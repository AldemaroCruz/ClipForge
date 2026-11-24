"""Evaluate the complete native Bandit report for the INT invitation beta."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

from .int_hito_a_bandit import (
    BanditPolicyError, _closed_json, _finding, _instant, _metrics, _policy_entry,
    _regular_source, _source_path, _version, _write_receipt, digest, require,
)


REFERENCE = "3caca7533844bdc43d7c0293a93a59c806d75b58"
SCHEMA = "clipforge-int-hito-b-bandit-review-1"
RECEIPT_SCHEMA = "clipforge-int-hito-b-bandit-evaluation-1"
WORKFLOW_REF = "AldemaroCruz/ClipForge/.github/workflows/int-hito-b.yml@refs/heads/ci/bootstrap-sec03"
BETA_SHARED_SOURCE = frozenset({"app/cloud/worker.py", "app/main.py", "app/media.py",
                               "app/media_child.py", "app/render.py"})


def reference_files(root):
    git = ("/usr/bin/git", "-c", f"safe.directory={root}", "ls-tree", "-rz", REFERENCE,
           "--", "app", "scripts")
    output = subprocess.run(git, cwd=root, check=True, capture_output=True, timeout=30).stdout
    records = {}
    for record in output.split(b"\x00"):
        if not record:
            continue
        metadata, filename = record.decode("utf-8").split("\t", 1)
        if filename.endswith(".py"):
            mode, kind, sha = metadata.split()
            filename = _source_path(filename)
            require(mode in {"100644", "100755"} and kind == "blob"
                    and re.fullmatch(r"[0-9a-f]{40}", sha) and filename not in records,
                    "bandit_beta_reference_sources")
            records[filename] = sha
    require(records and BETA_SHARED_SOURCE.issubset(records), "bandit_beta_reference_sources")
    return records


def source_identity(root, path):
    source, _ = _regular_source(root, path)
    source = source.replace(b"\r\n", b"\n")
    prefix = f"blob {len(source)}\0".encode("ascii")
    # Git object identity for scope comparison. SHA-256 binds review content.
    return hashlib.sha1(prefix + source, usedforsecurity=False).hexdigest(), digest(source)


def check_context(environ, local):
    if local:
        require(not environ.get("GITHUB_ACTIONS"), "bandit_beta_local_context")
        return None
    expected = {
        "GITHUB_ACTIONS": "true",
        "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
        "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": WORKFLOW_REF,
        "GITHUB_JOB": "api",
        "RUNNER_ENVIRONMENT": "github-hosted",
    }
    commit = environ.get("GITHUB_SHA", "")
    require(all(environ.get(name) == value for name, value in expected.items())
            and re.fullmatch(r"[0-9a-f]{40}", commit), "bandit_beta_int_context")
    return commit


def evaluate(report_path, version_path, policy_path, scanner_exit, *, root, local=False):
    commit = check_context(os.environ, local)
    version = _version(version_path)
    report = _closed_json(report_path, 16 * 1024 * 1024)
    require(isinstance(report, dict) and set(report) == {"errors", "generated_at", "metrics", "results"}
            and report.get("errors") == [] and isinstance(report.get("results"), list), "bandit_report_shape")
    require(scanner_exit == int(bool(report["results"])), "bandit_beta_scanner_exit")
    generated = _instant(report["generated_at"], "bandit_generated_at")
    now = datetime.now(timezone.utc)
    require(generated <= now and now - generated < timedelta(hours=6), "bandit_generated_at")
    findings = [_finding(row, root) for row in report["results"]]
    _metrics(report, root, findings)
    require(all(key[2] in {"LOW", "MEDIUM"} for key, _source, _line in findings), "bandit_beta_severity")

    policy = _closed_json(policy_path, 64 * 1024)
    require(isinstance(policy, dict) and set(policy) == {"schema", "scope", "reference", "reviewed"}
            and policy["schema"] == SCHEMA and policy["scope"] == "int-hito-b"
            and policy["reference"] == REFERENCE and isinstance(policy["reviewed"], list),
            "bandit_beta_policy_shape")
    reviewed = Counter()
    for entry in policy["reviewed"]:
        key, source = _policy_entry(entry, reviewed=True)
        require(key[2] in {"LOW", "MEDIUM"}, "bandit_beta_review_severity")
        reviewed[key, source, entry["line"]] += 1

    reference = reference_files(root)
    sources = {path: source_identity(root, path) for path in {key[0] for key, _, _ in findings}}
    actual = Counter()
    reviewed_severity = Counter()
    legacy = Counter()
    for key, _source, line in findings:
        path = key[0]
        git_sha, source_sha = sources[path]
        if path in BETA_SHARED_SOURCE or reference.get(path) != git_sha:
            actual[key, source_sha, line] += 1
            reviewed_severity[key[2]] += 1
        else:
            legacy[key[2]] += 1
    require(actual == reviewed, "bandit_beta_unreviewed_finding_or_stale_review")
    severity = Counter(key[2] for key, _source, _line in findings)
    return {
        "schema": RECEIPT_SCHEMA,
        "status": "local_review_passed" if local else "passed_int_beta_review",
        "scope": policy["scope"],
        "commit": commit,
        "reference": REFERENCE,
        "bandit_version": version,
        "total_findings": len(findings),
        "severity": {level: severity[level] for level in ("LOW", "MEDIUM", "HIGH")},
        "reviewed_int_beta": {level: reviewed_severity[level] for level in ("LOW", "MEDIUM")},
        "legacy_unchanged_outside_beta": {level: legacy[level] for level in ("LOW", "MEDIUM")},
        "native_report_sha256": digest(report_path.read_bytes()),
        "policy_sha256": digest(policy_path.read_bytes()),
        "production_exception": False,
        "hito_a_exception_used": False,
    }


def main(argv=None):
    root = Path(__file__).resolve().parents[1]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--version", required=True, type=Path)
    parser.add_argument("--scanner-exit", required=True, type=int)
    parser.add_argument("--policy", type=Path, default=root / "config/int-hito-b-bandit-review.json")
    parser.add_argument("--receipt", required=True, type=Path)
    parser.add_argument("--local", action="store_true")
    args = parser.parse_args(argv)
    try:
        receipt = evaluate(args.report, args.version, args.policy, args.scanner_exit, root=root, local=args.local)
        _write_receipt(args.receipt.absolute(), receipt)
        print(json.dumps(receipt, sort_keys=True))
        return 0
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        check = str(error) if isinstance(error, BanditPolicyError) else "bandit_beta_policy_failed"
        print(json.dumps({"status": "blocked", "failed_check": check}, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
