"""Real offline Gitleaks precision checks on disposable, synthetic source files.

This does not scan the checkout or use provider credentials. Both default and
configured detections must agree except for the one approved public DDL line.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import tempfile
import tomllib

try:
    from scripts import dev_local, prepare_ci_context as context
except ModuleNotFoundError:
    import dev_local
    import prepare_ci_context as context


ROOT = Path(__file__).resolve().parents[1]
SCANNER = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
POLICY_SHA256 = "877be9355eee66e958e1b453bb59c20302a8cd8bdcd8a7eadb791575483dd054"
CASE_IDS = ("approved", "same_file_other_secret", "changed_value", "other_path",
            "other_rule", "same_line_other_secret", "changed_identifier", "nested_path",
            "approved_after_prelude", "approved_full_file", "same_file_secret_before", "same_line_prefix")


def require(condition, message):
    if not condition:
        raise ValueError(message)


def record(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")


def finding_key(finding):
    return tuple(finding[key] for key in ("RuleID", "File", "StartLine", "EndLine", "StartColumn", "EndColumn"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--user", required=True)
    args = parser.parse_args(argv)
    config, scratch, report = map(lambda p: Path(os.path.abspath(p)), (args.config, args.scratch, args.report))
    summary = {"schema_version": 1, "status": "failed", "scanner_image": SCANNER,
               "policy_sha256": POLICY_SHA256, "cases": [], "synthetic_only": True,
               "external_network": False}
    try:
        require(re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", args.user), "Explicit non-root UID:GID required")
        require(not context._inside(scratch, ROOT) and not context._inside(ROOT, scratch), "Scratch must be outside checkout")
        context._check_components(config)
        policy = config.read_bytes()
        require(hashlib.sha256(policy).hexdigest() == POLICY_SHA256, "Policy bytes differ from the reviewed configuration")
        parsed = tomllib.loads(policy.decode("utf-8"))
        allow = parsed["rules"][0]["allowlists"][0]
        reference = ROOT / "tests/test_auth_recovery.py"
        context._check_components(reference)
        candidates = [line for line in reference.read_text(encoding="utf-8").splitlines()
                      if line.startswith("FROZEN_AUTH01_DDL_SHA256 = ")]
        require(len(candidates) == 1 and re.fullmatch(allow["regexes"][0], candidates[0]), "Approved assignment changed; review classification")
        approved = candidates[0]
        # These values are generated locally and never issued by any provider.
        canary = secrets.token_urlsafe(32)
        github_canary = "ghp_" + "".join(secrets.choice("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz") for _ in range(36))
        digest = approved.split("'")[1]
        changed = ("0" if digest[0] != "0" else "1") + digest[1:]
        synthetic = "service_api_key = '" + canary + "'"
        other_rule = "github_token = '" + github_canary + "'"
        default_path = "tests/test_auth_recovery.py"
        cases = [
            ("approved", default_path, approved + "\n"),
            ("same_file_other_secret", default_path, approved + "\n" + synthetic + "\n"),
            ("changed_value", default_path, approved.replace(digest, changed) + "\n"),
            ("other_path", "tests/copy_test_auth_recovery.py", approved + "\n"),
            ("other_rule", default_path, approved + "\n" + other_rule + "\n"),
            ("same_line_other_secret", default_path, approved + "; " + synthetic + "\n"),
            ("changed_identifier", default_path, approved.replace("FROZEN_AUTH01_DDL_SHA256", "FROZEN_AUTH01_DDL_SHA256_COPY") + "\n"),
            ("nested_path", "nested/tests/test_auth_recovery.py", approved + "\n"),
            ("approved_after_prelude", default_path, "# synthetic prelude\n" + approved + "\n# footer\n"),
            ("approved_full_file", default_path, reference.read_text(encoding="utf-8")),
            ("same_file_secret_before", default_path, synthetic + "\n" + approved + "\n"),
            ("same_line_prefix", default_path, synthetic + "; " + approved + "\n"),
        ]
        context._check_components(scratch)
        require(not scratch.exists(), "Use a new exclusive precision scratch directory")
        scratch.mkdir(mode=0o700)
        reports = report.parent / (report.stem + "-artifacts")
        reports.mkdir(parents=True)
        report.parent.mkdir(parents=True, exist_ok=True)
        endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
        client = scratch / "docker-config"
        client.mkdir(mode=0o700)
        docker = [dev_local.host_executable("docker"), "--config", str(client), "--host", endpoint]
        version_args = docker + ["run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--user", args.user,
                                 "--cap-drop", "ALL", "--security-opt", "no-new-privileges", SCANNER, "version"]
        version = subprocess.run(version_args, capture_output=True, timeout=60, check=True).stdout.decode("utf-8").strip()
        require(version.lstrip("v") == "8.30.1", "Scanner version mismatch")
        summary["scanner_version"] = "8.30.1"
        with tempfile.TemporaryDirectory(prefix="synthetic-", dir=scratch) as temporary:
            fixtures = Path(temporary)
            require(context._inside(fixtures.resolve(), scratch.resolve()), "Fixture cleanup boundary mismatch")
            for case_id, relative, text in cases:
                source = fixtures / case_id
                path = source / relative
                path.parent.mkdir(parents=True)
                path.write_text(text, encoding="utf-8", newline="\n")
                modes = {}
                for mode in ("default", "configured"):
                    output = reports / (case_id + "-" + mode)
                    output.mkdir()
                    arguments = docker + ["run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--user", args.user,
                        "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,nosuid,size=64m",
                        "--mount", f"type=bind,src={source},dst=/source,readonly",
                        "--mount", f"type=bind,src={config},dst=/policy/clipforge.toml,readonly",
                        "--mount", f"type=bind,src={output},dst=/reports", SCANNER, "dir", "/source", "--no-banner", "--redact=100",
                        "--ignore-gitleaks-allow", "--exit-code", "1", "--timeout", "60", "--report-format", "json",
                        "--report-path", "/reports/findings.json"]
                    if mode == "configured":
                        arguments += ["--config", "/policy/clipforge.toml"]
                    with (output / "stdout.log").open("xb") as stdout, (output / "stderr.log").open("xb") as stderr:
                        result = subprocess.run(arguments, stdout=stdout, stderr=stderr, timeout=90)
                    record(output / "execution.json", {"argv": arguments, "exit_code": result.returncode})
                    raw = json.loads((output / "findings.json").read_bytes())
                    require(type(raw) is list and result.returncode == int(bool(raw)), "Scanner error or incomplete precision evidence")
                    modes[mode] = (result.returncode, raw)
                baseline, configured = modes["default"][1], modes["configured"][1]
                require(baseline, "Negative fixture was not detected with default rules")
                approved_keys = [finding_key(f) for f in baseline
                    if f["RuleID"] == "generic-api-key" and f["File"] == "/source/" + default_path
                    and text.splitlines()[f["StartLine"] - 1] == approved]
                expected = Counter(finding_key(f) for f in baseline)
                expected.subtract(approved_keys)
                require(+expected == Counter(finding_key(f) for f in configured), "A detection outside the exact classification changed")
                if case_id in {"approved", "approved_after_prelude", "approved_full_file"}:
                    require(len(baseline) == 1 and not configured, "Approved checksum precision mismatch")
                else:
                    require(configured and modes["configured"][0] == 1, "Unclassified synthetic secret must remain blocking")
                if case_id in {"same_file_other_secret", "same_line_other_secret", "same_file_secret_before", "same_line_prefix"}:
                    require(any("service_api_key" in f["Match"] for f in configured), "Synthetic credential itself was not retained")
                if case_id == "other_rule":
                    require(any(f["RuleID"] == "github-pat" for f in configured), "A different default rule was not retained")
                summary["cases"].append({"id": case_id, "status": "passed", "default_exit": modes["default"][0],
                    "configured_exit": modes["configured"][0], "default_findings": len(baseline), "configured_findings": len(configured),
                    "removed_only_approved": True, "remaining_rules": sorted({f["RuleID"] for f in configured})})
        summary["status"] = "passed"
    except Exception as error:
        summary["error_type"] = type(error).__name__
    report.parent.mkdir(parents=True, exist_ok=True)
    record(report, summary)
    print(json.dumps({"status": summary["status"], "cases_completed": len(summary["cases"])}))
    return int(summary["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
