"""Narrow evidence for foundation SAST review; never suppress scanner results.

Only the three structural observations below can be proved automatically.
External process execution stays pending for an individual owner decision.
Unknown findings, missing source and malformed reports fail closed.
"""
from __future__ import annotations

import ast
import hashlib
from pathlib import Path, PurePosixPath


PUBLIC_IAM_ROLES = frozenset((
    "roles/secretmanager.secretAccessor",
    "roles/secretmanager.secretVersionAdder",
))


def _site(node, issue):
    return (node.lineno == issue.get("line_number") == node.end_lineno
            and node.col_offset == issue.get("col_offset")
            and node.end_col_offset == issue.get("end_col_offset"))


def _proof(name, issue, tree):
    line, rule = issue.get("line_number"), issue.get("test_id")
    if rule == "B105" and name == "scripts/check_tf_int.py":
        for function in tree.body:
            if not isinstance(function, ast.FunctionDef) or function.name != "expected_iam_role":
                continue
            for node in ast.walk(function):
                if not isinstance(node, ast.Dict):
                    continue
                # Native B105 locates the sensitive-looking dictionary KEY,
                # and quotes its VALUE in issue_text. Bind both, never any
                # unrelated safe string on that line.
                for key, value in zip(node.keys, node.values):
                    if (isinstance(key, ast.Constant) and _site(key, issue)
                            and isinstance(value, ast.Constant) and value.value in PUBLIC_IAM_ROLES
                            and issue.get("issue_text") == "Possible hardcoded password: '" + value.value + "'"):
                        return "false_positive_proven", "Literal public IAM role identifier, not credential material."
    if rule == "B108" and name in {"scripts/tf_int_plan.py", "scripts/check_int_foundation.py"}:
        for node in ast.walk(tree):
            if not isinstance(node, ast.List):
                continue
            values = [item.value if isinstance(item, ast.Constant) else None for item in node.elts]
            if name == "scripts/tf_int_plan.py":
                pairs = {"--network": "none", "--cap-drop": "ALL", "--security-opt": "no-new-privileges", "--pull": "never"}
                isolated = all(values.count(flag) == 1 and values.index(flag) + 1 < len(values)
                               and values[values.index(flag) + 1] == expected for flag, expected in pairs.items())
                user_index = values.index("--user") + 1 if values.count("--user") == 1 else len(values)
                user_ok = user_index < len(values) and ast.unparse(node.elts[user_index]) == "uid + ':' + gid"
            else:
                flags = {"--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges", "--pull=never"}
                isolated = all(values.count(flag) == 1 for flag in flags)
                user_ok = sum(ast.unparse(item) == "'--user=' + uid + ':' + gid" for item in node.elts) == 1
                isolated = isolated and not any(isinstance(value, str) and value.startswith(("--network", "--cap-add", "--privileged"))
                                               and value != "--network=none" for value in values)
            conflicting = any(isinstance(value, str) and
                              (value.startswith(("--cap-add", "--privileged", "--user=", "--read-only="))
                               or value.startswith("--network=") and value != "--network=none") for value in values)
            if (values[:2] != ["docker", "run"] or not isolated or conflicting
                    or values.count("--read-only") != 1 or not user_ok):
                continue
            for previous, current in zip(node.elts, node.elts[1:]):
                if not (isinstance(previous, ast.Constant) and previous.value == "--tmpfs"
                        and isinstance(current, ast.Constant) and _site(current, issue)
                        and isinstance(current.value, str)):
                    continue
                parts = current.value.split(":", 1)
                mount = PurePosixPath(parts[0])
                if (len(parts) == 2 and mount.parts == ("/", "tmp")
                        and set(parts[1].split(",")) == {"rw", "nosuid", "nodev", "noexec", "size=128m"}):
                    return "false_positive_proven", "Per-container bounded tmpfs option, not a shared host temporary filename."
    if rule == "B404" and name == "scripts/int_release.py":
        attribute_nodes = [node for node in ast.walk(tree)
                      if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name)
                      and node.value.id == "subprocess"]
        attributes = [node.attr for node in attribute_nodes]
        imports = [node for node in ast.walk(tree) if isinstance(node, ast.Import)
                   and _site(node, issue) and any(alias.name == "subprocess" and alias.asname is None for alias in node.names)]
        aliases = [node for node in ast.walk(tree) if isinstance(node, ast.ImportFrom) and node.module == "subprocess"]
        names = [node for node in ast.walk(tree) if isinstance(node, ast.Name) and node.id == "subprocess"]
        # An identifier used as an argument/alias could escape the attribute-only check.
        parents = {child: parent for parent in ast.walk(tree) for child in ast.iter_child_nodes(parent)}
        def exception_type_only(node):
            parent = parents.get(node)
            if isinstance(parent, ast.Tuple):
                node, parent = parent, parents.get(parent)
            return isinstance(parent, ast.ExceptHandler) and parent.type is node
        if (len(imports) == 1 and attributes and set(attributes) == {"SubprocessError"} and not aliases
                and all(isinstance(node.ctx, ast.Load) for node in attribute_nodes)
                and all(exception_type_only(node) for node in attribute_nodes)
                and all(isinstance(parents.get(node), ast.Attribute) for node in names)):
            return "control_verified", "Import used only for the SubprocessError exception type; no process launch in this module."
    return "risk_pending", "Individual review required; no acceptance or general exception is recorded."


def evaluate(source_root, bandit_report):
    root = Path(source_root).resolve()
    output = {"schema": "clipforge-int-foundation-sast-review-1", "status": "blocked", "findings": [], "proofs": []}
    if (not isinstance(bandit_report, dict) or bandit_report.get("errors") != []
            or not isinstance(bandit_report.get("results"), list)
            or not isinstance(bandit_report.get("metrics"), dict)
            or bandit_report["metrics"].get("_totals", {}).get("loc", 0) <= 0
            or len(bandit_report["metrics"]) <= 1):
        output["error"] = "Missing or incomplete native Bandit report."
        return output
    for issue in bandit_report["results"]:
        if not isinstance(issue, dict):
            output["error"] = "Malformed native finding."
            return output
        name = str(issue.get("filename", "")).replace("\\", "/")
        # Scanner roots differ locally/in Actions; only an unambiguous source suffix is usable.
        segments = name.split("/")
        if "scripts" not in segments or segments.count("scripts") != 1:
            output["findings"].append({"rule": issue.get("test_id"), "disposition": "risk_pending", "reason": "Unknown source scope."})
            continue
        name = "/".join(segments[segments.index("scripts"):])
        target = root / name
        try:
            if not target.resolve().is_relative_to(root) or target.is_symlink():
                raise ValueError("Source boundary differs")
            raw = target.read_bytes()
            tree = ast.parse(raw)
            disposition, proof = _proof(name, issue, tree)
        except (OSError, SyntaxError, ValueError, TypeError):
            raw, disposition, proof = b"", "risk_pending", "Source unavailable or evidence does not match."
        record = {"resource": name, "line": issue.get("line_number"), "rule": issue.get("test_id"),
                  "severity": issue.get("issue_severity"), "source_sha256": hashlib.sha256(raw).hexdigest(),
                  "disposition": disposition, "reason": proof}
        output["findings"].append(record)
        if disposition != "risk_pending":
            output["proofs"].append(record.copy())
    if not any(row["disposition"] == "risk_pending" for row in output["findings"]):
        output["status"] = "classified_no_residual_findings"
    return output
