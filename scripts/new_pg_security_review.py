"""Review independently captured PG candidate evidence without changing CI gates."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path

try:
    from scripts import new_pg_security_inventory as candidate
    from scripts import validate_ci_reports as gates
except ModuleNotFoundError:
    import new_pg_security_inventory as candidate
    import validate_ci_reports as gates


def review(inventory, sbom, scan, execution):
    gates.require(inventory.get("schema") == candidate.SCHEMA and inventory.get("schema_version") == 1,
                  "Only the independent candidate schema is supported")
    image_id = inventory.get("image_id")
    gates.require(gates.IMAGE.fullmatch(image_id or "") and inventory.get("image_config_id") == image_id,
                  "Candidate image configuration identity mismatch")
    gates.require(inventory.get("source", {}).get("gosu_commit") == candidate.GOSU_COMMIT and
                  inventory["source"].get("gosu_module_version") == candidate.GOSU_MODULE_VERSION and
                  inventory["source"].get("go_toolchain") == candidate.GO_VERSION and
                  inventory["source"].get("zlib1g") == candidate.ZLIB_VERSION, "Candidate source proposal identity changed")
    expected = {}
    for target in inventory.get("targets", []):
        kind = target.get("Type")
        gates.require(kind in {"debian", "gobinary"} and kind not in expected and
                      target.get("Class") == gates.SCANNER_TARGETS[kind], "Incomplete or unexpected candidate inventory target")
        expected[kind] = gates.package_set(target.get("Packages"), kind)
    gates.require(set(expected) == {"debian", "gobinary"}, "Both actual Debian and Go package inventories are required")
    gates.require(len(expected["debian"]) == inventory.get("dpkg", {}).get("installed_package_count") and
                  ("zlib1g", candidate.ZLIB_VERSION) in expected["debian"], "Incomplete candidate installed-package count or zlib version")
    gosu = inventory.get("go_binaries", [])
    gates.require(len(gosu) == 1 and gosu[0].get("go_version") == candidate.GO_VERSION and
                  gosu[0].get("main_module", {}).get("Version") == candidate.GOSU_MODULE_VERSION and
                  gates.package_set(gosu[0].get("packages"), "gobinary") == expected["gobinary"], "Incomplete actual gosu module/toolchain inventory")
    # Reuse the existing completeness/security checks without altering any gate.
    gates.validate_sbom(sbom, image_id, expected)
    blocked = False
    try:
        gates.validate_trivy(scan, image_id, expected, inventory["os"])
    except gates.SecurityFinding:
        blocked = True
    findings = [{"target": target["Target"], "rule": item["VulnerabilityID"], "package": item["PkgName"],
                 "severity": item["Severity"], "installed": item.get("InstalledVersion"), "fixed": item.get("FixedVersion"),
                 "source": item.get("PrimaryURL")} for target in scan["Results"] for item in target.get("Vulnerabilities", [])]
    gates.require(execution.get("image_id") == image_id and execution.get("sbom_exit_code") == 0 and
                  execution.get("exit_code") == int(blocked) and bool(findings) == blocked,
                  "Scanner execution exit/status differs from the complete report")
    gates.require(inventory.get("scope", {}).get("database_started") is False and
                  inventory["scope"].get("database_data_read") is False and
                  inventory["scope"].get("credentials_used") is False,
                  "Candidate collection used forbidden database scope")
    return {"schema": "clipforge-postgres-security-proposal-review-1", "image_id": image_id,
            "image_reference": inventory["image_reference"], "base_image_reference": inventory["base_image_reference"],
            "candidate_security": "blocking_findings" if blocked else "complete_scan_without_high_critical",
            "package_counts": {kind: len(packages) for kind, packages in expected.items()},
            "severity_counts": {severity: sum(item["severity"] == severity for item in findings) for severity in ("CRITICAL", "HIGH")},
            "findings": findings, "source": inventory["source"],
            "ci_integration": "pending_producer_and_validator_review", "ci_approved": False,
            "scope": "this_independent_postgresql_test_candidate_only",
            "not_tested": ["existing_CI_image_selection", "existing_CI_inventory_contract", "existing_CI_validator_contract",
                           "PostgreSQL_lifecycle_with_this_candidate", "application_runtime", "browser_tools", "future_VM"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    parser.add_argument("--scan", type=Path, required=True)
    parser.add_argument("--execution", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        if args.output.exists():
            raise ValueError("Output must be new")
        paths = [args.inventory, args.sbom, args.scan, args.execution]
        values = [json.loads(path.read_text(encoding="utf-8-sig")) for path in paths]
        result = review(*values)
        result["evidence"] = [{"name": path.name, "bytes": path.stat().st_size,
                               "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for path in paths]
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2, sort_keys=True)
            stream.write("\n")
        print(json.dumps({"status": result["candidate_security"], "severity_counts": result["severity_counts"], "ci_approved": False}))
        return 1 if result["findings"] else 0
    except (ValueError, KeyError, TypeError, OSError):
        print(json.dumps({"status": "invalid_or_incomplete_evidence", "ci_approved": False}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
