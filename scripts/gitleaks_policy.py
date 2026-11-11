"""Validate the reviewed source-scan policy and preserve scanner execution evidence."""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import tomllib

try:
    from scripts import prepare_ci_scan as scan
except ModuleNotFoundError:
    import prepare_ci_scan as scan


POLICY_SHA256 = "877be9355eee66e958e1b453bb59c20302a8cd8bdcd8a7eadb791575483dd054"
GITLEAKS_VERSION = "8.30.1"
GITLEAKS_IMAGE = "ghcr.io/gitleaks/gitleaks:v8.30.1@sha256:b109bc5f8f76a38196a3e413704fc5b9e3c32360bce4e4b603bd6f45b3721dbb"
EXECUTION_SCHEMA = "clipforge-gitleaks-execution-1"
EXECUTION_FIELDS = {"schema", "schema_version", "status", "raw_exit_code", "policy_sha256",
                    "source_manifest_sha256", "scanner_image", "scanner_version",
                    "raw_report_sha256", "findings_count", "errors"}
HEX = re.compile(r"[0-9a-f]{64}")
MAX_BYTES = 32 * 1024 * 1024


class PolicyError(ValueError):
    """The approved policy or its execution evidence does not match."""


def require(condition, message):
    if not condition:
        raise PolicyError(message)


def read_regular(path, limit=MAX_BYTES):
    path = Path(path)
    scan.context._check_components(path)
    before = scan.context._checked_stat(path)
    require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_size <= limit,
            "Expected a bounded regular evidence file without links")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        require(scan.context._identity(os.fstat(stream.fileno())) == scan.context._identity(before),
                "Evidence changed before reading")
        raw = stream.read(limit + 1)
        require(scan.context._identity(os.fstat(stream.fileno())) == scan.context._identity(before),
                "Evidence changed while reading")
    require(len(raw) <= limit, "Evidence exceeds its size bound")
    return raw


def validate_policy_structure(value):
    require(type(value) is dict and set(value) == {"title", "minVersion", "extend", "rules"},
            "Unexpected Gitleaks policy fields")
    require(type(value["title"]) is str and bool(value["title"].strip())
            and value["minVersion"] == "v" + GITLEAKS_VERSION, "Policy title/version mismatch")
    require(type(value["extend"]) is dict and value["extend"] == {"useDefault": True}
            and value["extend"]["useDefault"] is True, "Default Gitleaks rules must be retained")
    rules = value["rules"]
    require(type(rules) is list and len(rules) == 1 and type(rules[0]) is dict
            and set(rules[0]) == {"id", "allowlists"} and rules[0]["id"] == "generic-api-key",
            "Only the reviewed default-rule extension is permitted")
    lists = rules[0]["allowlists"]
    require(type(lists) is list and len(lists) == 1 and type(lists[0]) is dict
            and set(lists[0]) == {"description", "condition", "regexTarget", "paths", "regexes"},
            "Unexpected policy classification scope")
    item = lists[0]
    require(type(item["description"]) is str and bool(item["description"].strip())
            and item["condition"] == "AND" and item["regexTarget"] == "line"
            and item["paths"] == [r"^/source/tests/test_auth_recovery\.py$"],
            "Policy classification must bind the exact file and complete line")
    patterns = item["regexes"]
    require(type(patterns) is list and len(patterns) == 1 and type(patterns[0]) is str
            and re.fullmatch(r"\^\\n\?FROZEN_AUTH01_DDL_SHA256 = '[0-9a-f]{64}'\$", patterns[0]),
            "Policy must classify only one complete checksum assignment")


def _validate_policy_bytes(raw):
    require(hashlib.sha256(raw).hexdigest() == POLICY_SHA256, "Policy fingerprint differs from owner review")
    validate_policy_structure(tomllib.loads(raw.decode("utf-8")))
    return {"sha256": POLICY_SHA256, "bytes": len(raw), "defaults_retained": True}


def validate_policy(path):
    require(Path(path).name in {".gitleaks.toml", "gitleaks-policy.toml"}, "Unexpected policy filename")
    return _validate_policy_bytes(read_regular(path, 65536))


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON field")
        result[key] = value
    return result


def parse_json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: require(False, "Nonfinite JSON number"))


def validate_manifest_binding(raw, policy_bytes):
    value = parse_json(raw)
    require(type(value) is dict and value.get("schema") == scan.SCHEMA
            and type(value.get("files")) is list, "Source manifest schema mismatch")
    records = value["files"]
    require(all(type(row) is dict and set(row) == {"path", "bytes", "sha256"}
                and type(row["path"]) is str and type(row["bytes"]) is int and row["bytes"] >= 0
                and type(row["sha256"]) is str and HEX.fullmatch(row["sha256"]) for row in records),
            "Source manifest record is malformed")
    scan.validate_paths([row["path"] for row in records])
    policy = next((row for row in records if row["path"] == ".gitleaks.toml"), None)
    require(policy is not None and policy["sha256"] == POLICY_SHA256 and policy["bytes"] == policy_bytes,
            "Source manifest does not bind the approved policy")


def canonical_version(value):
    require(type(value) is str and re.fullmatch(r"(?:gitleaks(?: version)?\s+)?v?8\.30\.1", value.strip()),
            "Gitleaks version differs from the pinned scanner")
    return GITLEAKS_VERSION


def parse_findings(raw):
    result = parse_json(raw)
    require(type(result) is list and all(type(item) is dict for item in result), "Malformed raw Gitleaks report")
    return result


def execution_status(raw_exit, findings_count):
    require(type(raw_exit) is int and raw_exit in {0, 1}, "Gitleaks execution failed")
    require((raw_exit == 1) == (findings_count > 0), "Gitleaks exit contradicts its raw report")
    return "security_findings" if findings_count else "passed"


def validate_execution(report, *, policy_path, source_manifest_raw, raw_report, version_text):
    require(type(report) is dict and set(report) == EXECUTION_FIELDS, "Execution fields are missing or unexpected")
    require(report["schema"] == EXECUTION_SCHEMA and type(report["schema_version"]) is int
            and report["schema_version"] == 1 and report["errors"] == []
            and type(report["errors"]) is list, "Gitleaks execution contains errors")
    policy = validate_policy(policy_path)
    validate_manifest_binding(source_manifest_raw, policy["bytes"])
    require(report["policy_sha256"] == policy["sha256"]
            and report["source_manifest_sha256"] == hashlib.sha256(source_manifest_raw).hexdigest()
            and report["raw_report_sha256"] == hashlib.sha256(raw_report).hexdigest(),
            "Execution policy, source manifest or raw report hash mismatch")
    require(report["scanner_image"] == GITLEAKS_IMAGE
            and report["scanner_version"] == canonical_version(version_text), "Execution scanner identity mismatch")
    findings = parse_findings(raw_report)
    require(type(report["findings_count"]) is int and report["findings_count"] == len(findings),
            "Execution findings count is missing or incorrect")
    require(report["status"] == execution_status(report["raw_exit_code"], len(findings)),
            "Execution status contradicts scanner evidence")


def record_execution(*, config, source_manifest, raw_report, raw_exit, scanner_image, version_file,
                     policy_copy, output):
    report = {"schema": EXECUTION_SCHEMA, "schema_version": 1, "status": "error",
              "raw_exit_code": raw_exit, "policy_sha256": None, "source_manifest_sha256": None,
              "scanner_image": None, "scanner_version": None, "raw_report_sha256": None,
              "findings_count": None, "errors": []}
    stage = "policy"
    try:
        require(Path(config).name == ".gitleaks.toml", "Unexpected snapshot policy filename")
        policy_raw = read_regular(config, 65536)
        report["policy_sha256"] = hashlib.sha256(policy_raw).hexdigest()
        policy = _validate_policy_bytes(policy_raw)
        stage = "policy_copy"
        require(Path(policy_copy).name == "gitleaks-policy.toml", "Unexpected policy report filename")
        Path(policy_copy).parent.mkdir(parents=True, exist_ok=True)
        scan.context._check_components(Path(policy_copy).parent)
        with Path(policy_copy).open("xb") as stream:
            stream.write(policy_raw)
        stage = "source_manifest"
        manifest_raw = read_regular(source_manifest)
        report["source_manifest_sha256"] = hashlib.sha256(manifest_raw).hexdigest()
        validate_manifest_binding(manifest_raw, policy["bytes"])
        stage = "scanner_version"
        report["scanner_version"] = canonical_version(read_regular(version_file, 4096).decode("utf-8"))
        stage = "scanner_image"
        require(scanner_image == GITLEAKS_IMAGE, "Unexpected scanner image")
        report["scanner_image"] = scanner_image
        stage = "raw_report"
        raw = read_regular(raw_report)
        report["raw_report_sha256"] = hashlib.sha256(raw).hexdigest()
        findings = parse_findings(raw)
        report["findings_count"] = len(findings)
        stage = "scanner_exit"
        report["status"] = execution_status(raw_exit, len(findings))
    except (OSError, ValueError) as error:
        report["errors"].append({"stage": stage, "error_type": type(error).__name__})
    output = Path(output)
    output.parent.mkdir(parents=True, exist_ok=True)
    scan.context._check_components(output.parent)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    validation = commands.add_parser("validate")
    validation.add_argument("--config", type=Path, required=True)
    record = commands.add_parser("record")
    for name in ("config", "source-manifest", "raw-report", "version-file", "policy-copy", "output"):
        record.add_argument("--" + name, type=Path, required=True)
    record.add_argument("--exit-code", type=int, required=True)
    record.add_argument("--scanner-image", required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == "validate":
            print(json.dumps({"status": "passed", **validate_policy(args.config)}, sort_keys=True))
            return 0
        report = record_execution(config=args.config, source_manifest=args.source_manifest,
                                  raw_report=args.raw_report, raw_exit=args.exit_code,
                                  scanner_image=args.scanner_image, version_file=args.version_file,
                                  policy_copy=args.policy_copy, output=args.output)
        print(json.dumps({"status": report["status"], "raw_exit_code": report["raw_exit_code"]}))
        return 0 if report["status"] == "passed" else 1
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "error", "error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
