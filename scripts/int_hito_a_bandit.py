"""Evaluate the full native Bandit report under the temporary INT Hito A decision.

The policy is an exact multiset of findings, not a numeric ceiling.  Each
accepted finding is bound to its Bandit identity, the exact source span and the
complete current source file.  Any source change therefore requires a new
review even when Bandit would emit the same rule at the same statement.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re


SCHEMA = "clipforge-int-hito-a-bandit-acceptance-1"
RECEIPT_SCHEMA = "clipforge-int-hito-a-bandit-evaluation-1"
BASELINE_COMMIT = "cbc05133cd96bf3bd79991d8f2157775624c755f"
BANDIT_VERSION = "1.9.4"
WORKFLOW_REF = (
    "AldemaroCruz/ClipForge/.github/workflows/int-hito-a.yml"
    "@refs/heads/ci/bootstrap-sec03"
)
MAX_EXPIRY = datetime(2026, 12, 31, 23, 59, 59, tzinfo=timezone.utc)
METRIC_FIELDS = ("loc", "nosec", "skipped_tests") + tuple(
    f"{kind}.{level}" for kind in ("SEVERITY", "CONFIDENCE")
    for level in ("HIGH", "MEDIUM", "LOW", "UNDEFINED")
)
LEVELS = {"HIGH", "MEDIUM", "LOW", "UNDEFINED"}
FINDING_FIELDS = {
    "code", "col_offset", "end_col_offset", "filename", "issue_confidence",
    "issue_cwe", "issue_severity", "issue_text", "line_number", "line_range",
    "more_info", "test_id", "test_name",
}
ENTRY_FIELDS = {
    "path", "test_id", "severity", "confidence", "cwe", "context_sha256",
    "source_sha256", "line",
}
SHA256 = re.compile(r"[0-9a-f]{64}")
TEST_ID = re.compile(r"B[0-9]{3}")
HISTORICAL_CHANGED_FILES = [
    "scripts/check_int_demo_a.py",
    "scripts/int_demo_a_db_observe.py",
    "scripts/int_demo_a_native_publication.py",
    "scripts/int_demo_a_publication_host.py",
    "scripts/int_release.py",
    "scripts/int_release_image.py",
    "scripts/int_secrets.py",
]


class BanditPolicyError(ValueError):
    """Stable failure code without report or source contents."""


def require(condition, code):
    if not condition:
        raise BanditPolicyError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def _closed_json(path, maximum):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= maximum,
            "bandit_input_file")

    def pairs(rows):
        value = dict(rows)
        require(len(value) == len(rows), "bandit_duplicate_json_field")
        return value

    try:
        return json.loads(path.read_bytes(), object_pairs_hook=pairs)
    except (UnicodeError, ValueError, TypeError):
        raise BanditPolicyError("bandit_invalid_json") from None


def _source_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 4096 and "\x00" not in value,
            "bandit_source_path")
    name = value.replace("\\", "/")
    if name.startswith("/app/"):
        name = name[5:]
    elif name.startswith("./"):
        name = name[2:]
    elif not name.startswith(("app/", "scripts/")):
        matches = [position for marker in ("/app/", "/scripts/")
                   if (position := name.rfind(marker)) >= 0]
        require(matches, "bandit_source_path")
        name = name[max(matches) + 1:]
    path = PurePosixPath(name)
    require(path.as_posix() == name and path.suffix == ".py"
            and path.parts[0] in {"app", "scripts"}
            and all(part not in {"", ".", "..", "__pycache__"} for part in path.parts),
            "bandit_source_path")
    return name


def _regular_source(root, name):
    root = root.resolve()
    path = (root / PurePosixPath(name)).resolve()
    require(path.parent != root and root in path.parents and path.is_file() and not path.is_symlink()
            and path.stat().st_size <= 2 * 1024 * 1024, "bandit_source_file")
    raw = path.read_bytes()
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise BanditPolicyError("bandit_source_encoding") from None
    return raw, text.splitlines()


def _finding(row, root):
    require(isinstance(row, dict) and set(row) == FINDING_FIELDS, "bandit_finding_shape")
    name = _source_path(row.get("filename"))
    test_id = row.get("test_id")
    severity, confidence = row.get("issue_severity"), row.get("issue_confidence")
    cwe = row.get("issue_cwe")
    line, line_range = row.get("line_number"), row.get("line_range")
    require(isinstance(test_id, str) and TEST_ID.fullmatch(test_id)
            and severity in LEVELS and confidence in LEVELS
            and isinstance(cwe, dict) and set(cwe) == {"id", "link"}
            and type(cwe["id"]) is int and cwe["id"] > 0
            and isinstance(cwe["link"], str) and cwe["link"].startswith("https://cwe.mitre.org/")
            and type(line) is int and line > 0
            and isinstance(line_range, list) and line_range
            and all(type(item) is int and item > 0 for item in line_range)
            and line_range == list(range(min(line_range), max(line_range) + 1))
            and line in line_range
            and type(row.get("col_offset")) is int and row["col_offset"] >= 0
            and type(row.get("end_col_offset")) is int and row["end_col_offset"] >= 0
            and isinstance(row.get("code"), str) and len(row["code"].encode("utf-8")) <= 65536
            and isinstance(row.get("issue_text"), str) and 0 < len(row["issue_text"]) <= 2048
            and isinstance(row.get("test_name"), str) and 0 < len(row["test_name"]) <= 256
            and isinstance(row.get("more_info"), str)
            and row["more_info"].startswith("https://bandit.readthedocs.io/en/1.9.4/"),
            "bandit_finding_values")
    source, lines = _regular_source(root, name)
    first, last = min(line_range), max(line_range)
    require(last <= len(lines), "bandit_finding_lines")
    context = ("\n".join(lines[first - 1:last]) + "\n").encode("utf-8")
    key = (name, test_id, severity, confidence, cwe["id"], digest(context))
    return key, digest(source), line


def _metrics(report, root, findings):
    metrics = report.get("metrics")
    require(isinstance(metrics, dict) and "_totals" in metrics, "bandit_metrics_shape")
    normalized = {}
    for name, values in metrics.items():
        key = name if name == "_totals" else _source_path(name)
        require(key not in normalized and isinstance(values, dict)
                and set(values) == set(METRIC_FIELDS)
                and all(type(values[field]) is int and values[field] >= 0 for field in METRIC_FIELDS),
                "bandit_metrics_shape")
        normalized[key] = values
    expected = {
        path.relative_to(root).as_posix()
        for directory in (root / "app", root / "scripts")
        for path in directory.rglob("*.py")
        if path.is_file() and not path.is_symlink() and "__pycache__" not in path.parts
    }
    require(expected and set(normalized) == expected | {"_totals"},
            "bandit_source_inventory")
    totals = normalized["_totals"]
    require(totals["loc"] > 0
            and all(normalized[name]["nosec"] == 0
                    and normalized[name]["skipped_tests"] == 0 for name in expected)
            and all(totals[field] == sum(normalized[name][field] for name in expected)
                    for field in METRIC_FIELDS), "bandit_metrics_totals")
    for kind, position in (("SEVERITY", 2), ("CONFIDENCE", 3)):
        counts = Counter(key[position] for key, _source, _line in findings)
        require(all(totals[f"{kind}.{level}"] == counts[level] for level in LEVELS),
                "bandit_metrics_findings")
    return totals


def _instant(value, code):
    require(isinstance(value, str), code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise BanditPolicyError(code) from None
    require(parsed.tzinfo is not None, code)
    return parsed.astimezone(timezone.utc)


def _policy_entry(row, *, reviewed):
    wanted = ENTRY_FIELDS | ({"reason"} if reviewed else set())
    require(isinstance(row, dict) and set(row) == wanted, "bandit_policy_entry")
    name = _source_path(row.get("path"))
    require(TEST_ID.fullmatch(row.get("test_id", ""))
            and row.get("severity") in LEVELS and row.get("confidence") in LEVELS
            and type(row.get("cwe")) is int and row["cwe"] > 0
            and SHA256.fullmatch(row.get("context_sha256", ""))
            and SHA256.fullmatch(row.get("source_sha256", ""))
            and type(row.get("line")) is int and row["line"] > 0,
            "bandit_policy_entry")
    if reviewed:
        require(isinstance(row.get("reason"), str) and 20 <= len(row["reason"]) <= 500,
                "bandit_policy_reason")
    return (name, row["test_id"], row["severity"], row["confidence"],
            row["cwe"], row["context_sha256"]), row["source_sha256"]


def _load_policy(path, root, now):
    policy = _closed_json(path, 512 * 1024)
    fields = {
        "schema", "decision", "scope", "temporary", "valid_from_utc", "expires_utc",
        "baseline_commit", "baseline_summary", "reviewed_summary", "baseline_findings",
        "reviewed_additions", "historical_files_changed_outside_finding_span",
    }
    require(isinstance(policy, dict) and set(policy) == fields
            and policy.get("schema") == SCHEMA and policy.get("temporary") is True
            and policy.get("baseline_commit") == BASELINE_COMMIT
            and policy.get("scope") == {
                "environment": "int", "delivery": "int-hito-a",
                "workflow": ".github/workflows/int-hito-a.yml", "production": False,
            }
            and isinstance(policy.get("decision"), str) and 40 <= len(policy["decision"]) <= 1000,
            "bandit_policy_contract")
    start = _instant(policy["valid_from_utc"], "bandit_policy_time")
    expiry = _instant(policy["expires_utc"], "bandit_policy_time")
    require(start <= now < expiry <= MAX_EXPIRY and (expiry - start).days <= 45,
            "bandit_policy_expired")
    baseline = policy.get("baseline_summary")
    reviewed = policy.get("reviewed_summary")
    require(baseline == {
                "total": 142, "severity": {"LOW": 124, "MEDIUM": 18},
                "status": "accepted_historical_debt_not_remediated",
            }
            and reviewed == {
                "total": 12, "severity": {"LOW": 12},
                "rules": {"B105": 2, "B404": 3, "B603": 7},
                "status": "reviewed_and_accepted_for_int_hito_a",
            }, "bandit_policy_counts")
    baseline_rows = policy.get("baseline_findings")
    reviewed_rows = policy.get("reviewed_additions")
    require(isinstance(baseline_rows, list) and len(baseline_rows) == 142
            and isinstance(reviewed_rows, list) and len(reviewed_rows) == 12,
            "bandit_policy_counts")
    accepted = Counter()
    sources = {}
    for is_reviewed, rows in ((False, baseline_rows), (True, reviewed_rows)):
        for row in rows:
            key, source = _policy_entry(row, reviewed=is_reviewed)
            accepted[key] += 1
            prior = sources.setdefault(key[0], source)
            require(prior == source, "bandit_policy_source_conflict")
    baseline_levels = Counter(row["severity"] for row in baseline_rows)
    reviewed_levels = Counter(row["severity"] for row in reviewed_rows)
    reviewed_rules = Counter(row["test_id"] for row in reviewed_rows)
    require(baseline_levels == Counter({"LOW": 124, "MEDIUM": 18})
            and reviewed_levels == Counter({"LOW": 12})
            and reviewed_rules == Counter({"B603": 7, "B404": 3, "B105": 2})
            and not any(row["severity"] == "HIGH" for row in baseline_rows + reviewed_rows),
            "bandit_policy_counts")
    for name, expected in sources.items():
        actual, _lines = _regular_source(root, name)
        require(digest(actual) == expected, "bandit_accepted_source_changed")
    changed = policy.get("historical_files_changed_outside_finding_span")
    require(changed == HISTORICAL_CHANGED_FILES
            and all(_source_path(name) == name for name in changed),
            "bandit_historical_change_record")
    return policy, accepted


def _version(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 4096,
            "bandit_version_file")
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except UnicodeError:
        raise BanditPolicyError("bandit_version_file") from None
    require(len(lines) >= 2 and re.fullmatch(r"(?:bandit|__main__\.py) 1\.9\.4", lines[0])
            and lines[1].startswith("  python version = "), "bandit_version")
    return BANDIT_VERSION


def _context(environ):
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
        "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_JOB": "api",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_RUN_ATTEMPT": "1",
        "INT_BANDIT_POLICY_SCOPE": "int-hito-a",
    }
    require(all(environ.get(key) == value for key, value in expected.items())
            and re.fullmatch(r"[0-9a-f]{40}", environ.get("GITHUB_SHA", ""))
            and environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"),
            "bandit_int_context")


def evaluate(report_path, version_path, policy_path, *, root=None, environ=None, now=None):
    root = (root or Path(__file__).resolve().parents[1]).resolve()
    environ = os.environ if environ is None else environ
    now = datetime.now(timezone.utc) if now is None else now.astimezone(timezone.utc)
    _context(environ)
    version = _version(version_path)
    report = _closed_json(report_path, 16 * 1024 * 1024)
    require(isinstance(report, dict) and set(report) == {"errors", "generated_at", "metrics", "results"}
            and isinstance(report.get("errors"), list) and not report["errors"]
            and isinstance(report.get("results"), list), "bandit_report_shape")
    generated = _instant(report["generated_at"], "bandit_generated_at")
    require(generated <= now and now - generated < timedelta(hours=6), "bandit_generated_at")
    findings = [_finding(row, root) for row in report["results"]]
    totals = _metrics(report, root, findings)
    policy, accepted = _load_policy(policy_path, root, now)
    actual = Counter(key for key, _source, _line in findings)
    require(not any(key[2] == "HIGH" for key in actual), "bandit_high_finding")
    require(actual == accepted, "bandit_unreviewed_finding")
    severity = Counter(key[2] for key, _source, _line in findings)
    require(len(findings) == 154 and severity == Counter({"LOW": 136, "MEDIUM": 18})
            and totals["SEVERITY.HIGH"] == 0, "bandit_accepted_totals")
    policy_raw = policy_path.read_bytes()
    report_raw = report_path.read_bytes()
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "passed_with_int_exception",
        "scope": policy["scope"],
        "bandit_version": version,
        "baseline_commit": BASELINE_COMMIT,
        "baseline_findings": 142,
        "reviewed_additions": 12,
        "total_findings": 154,
        "severity": {"LOW": 136, "MEDIUM": 18, "HIGH": 0},
        "native_report_sha256": digest(report_raw),
        "policy_sha256": digest(policy_raw),
        "expires_utc": policy["expires_utc"],
        "production_exception": False,
    }


def _write_receipt(path, value):
    require(path.is_absolute() and not path.exists(), "bandit_receipt_path")
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(canonical(value) + b"\n")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("evaluate",))
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--version", type=Path, required=True)
    parser.add_argument("--policy", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = evaluate(args.report.resolve(), args.version.resolve(), args.policy.resolve())
        _write_receipt(args.receipt.resolve(), receipt)
        print(json.dumps({"status": receipt["status"], "total_findings": 154}, sort_keys=True))
        return 0
    except (BanditPolicyError, OSError, TypeError, KeyError) as error:
        code = str(error) if isinstance(error, BanditPolicyError) else "bandit_policy_failed"
        print(json.dumps({"status": "blocked", "failed_check": code}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
