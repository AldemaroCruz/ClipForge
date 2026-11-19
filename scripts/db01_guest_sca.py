"""Convert observed guest package metadata to a clearly scoped, third-party SBOM.

No dpkg database, source-package mapping, image, or package-selection state is
invented. Trivy's Debian source-name fallback limits the resulting scan.
This module performs local file conversion only, without process or network I/O.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import json
from pathlib import Path
import re
from urllib.parse import parse_qsl, quote, unquote, urlsplit

from scripts import int_guest_inventory_guest as guest

INVENTORY_SHA256 = "db74601986fc57b9d6f71d3e73c0cc7b456aead7350b134a75c7574a13d24c5d"
LIMITATIONS = [
    "Observed installed Debian binary-package metadata only; not a VM disk or filesystem scan.",
    "Source package names and versions were not collected and are not populated in this SBOM.",
    "Trivy 0.76.2 fills missing source names/versions from binary names/versions; Debian advisories use source packages, so detections can be missed or misattributed.",
    "No language-package, executable-file, repository-origin, runtime reachability, or full dpkg selection/error-state coverage is claimed.",
    "The running kernel and block-device metadata are observations, not a vulnerability assessment of those components.",
]
SOURCE_LIMITATIONS = [
    "Observed guest dpkg-query binary/source package identities and status fields only; not a disk/filesystem scan.",
    "Source fields are copied from the observation without deriving them from binary names or versions.",
    "Trivy-compatible source properties do not assert that Trivy generated this third-party SBOM.",
    "No language-package, file-integrity, repository-origin or runtime reachability assessment is claimed.",
    "The kernel and disk metadata remain observations, not full component vulnerability assessments.",
]
SOURCE_FIELDS = {"binary_name", "binary_version", "source_name", "source_version", "architecture", "status", "status_abbrev"}


class InvalidEvidence(ValueError):
    pass


def require(value, code):
    if not value:
        raise InvalidEvidence(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":")).encode("ascii") + b"\n"


def decode(raw, *, limit=2 * 1024 * 1024):
    require(type(limit) is int and 0 < limit <= 64 * 1024 * 1024 and isinstance(raw, bytes) and 0 < len(raw) <= limit, "bounded_inventory_required")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def prepare(raw, expected_sha256=INVENTORY_SHA256):
    require(isinstance(expected_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            and sha256(raw) == expected_sha256, "inventory_custody_mismatch")
    document = guest.validate_report(decode(raw))
    require(document["status"] == "inventory_complete" and document["exit_code"] == 0
            and document["safety"]["passed"] is True, "complete_safe_inventory_required")
    inventory = document["inventory"]
    release = inventory["os_release"]
    require(release.get("ID") == "debian" and release.get("VERSION_ID") == "13"
            and release.get("VERSION_CODENAME") == "trixie", "observed_debian13_required")
    components, identities = [], set()
    rows = inventory["packages"]
    require(rows and all(row[2] == "installed" for row in rows), "only_observed_installed_packages_supported")
    for binary_name, version, status, arch in rows:
        split = binary_name.split(":")
        require(len(split) == 1 or len(split) == 2 and split[1] == arch, "binary_name_architecture_mismatch")
        name = split[0]
        purl = "pkg:deb/debian/" + quote(name, safe="") + "@" + quote(version, safe="") + "?arch=" + quote(arch, safe="") + "&distro=debian-13"
        identity = (name, arch)
        require(identity not in identities, "duplicate_binary_package_identity")
        identities.add(identity)
        components.append({"type": "library", "bom-ref": purl, "name": name, "version": version, "purl": purl,
            "properties": [{"name": "clipforge:observed-binary-name", "value": binary_name},
                           {"name": "clipforge:observed-dpkg-status", "value": status},
                           {"name": "clipforge:source-package-fields", "value": "unobserved"}]})
    components.sort(key=lambda row: row["purl"])
    os_ref = "clipforge-observed-os-debian-13"
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "operating-system", "bom-ref": os_ref, "name": "debian", "version": "13"},
            "tools": {"components": [{"type": "application", "name": "clipforge-db01-guest-inventory-converter", "version": "1"}]},
            "properties": [{"name": "clipforge:inventory-sha256", "value": expected_sha256},
                           {"name": "clipforge:origin", "value": "read-only-guest-dpkg-query-metadata"},
                           {"name": "clipforge:source-fields-observed", "value": "false"}]},
        "components": components,
        "dependencies": [{"ref": os_ref, "dependsOn": [row["bom-ref"] for row in components]}]}
    sbom_raw = encoded(sbom)
    manifest = {"schema": "clipforge-db01-guest-sca-input-1", "inventory_sha256": expected_sha256,
        "inventory_bytes": len(raw), "sbom_sha256": sha256(sbom_raw), "sbom_bytes": len(sbom_raw),
        "observed_os_release": release, "observed_kernel": inventory["kernel"],
        "package_rows_observed": len(rows), "package_components": len(components),
        "observed_status_counts": dict(Counter(row[2] for row in rows)),
        "dpkg_database_reconstructed": False, "source_fields_observed": False,
        "generated_by_trivy": False, "complete_filesystem_sca": False, "limitations": LIMITATIONS}
    return sbom, manifest


def prepare_observation(raw, expected_sha256):
    """Convert only source/status fields actually obtained in the new RO capture."""
    require(isinstance(expected_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", expected_sha256)
            and sha256(raw) == expected_sha256, "observation_custody_mismatch")
    evidence = decode(raw)
    from scripts import int_guest_db_observe as observer
    try:
        proof = observer.disk_proof(evidence)
    except (ValueError, TypeError, KeyError, AttributeError):
        raise InvalidEvidence("invalid_disk_bound_guest_evidence") from None
    observation = evidence["guest"]
    require(isinstance(observation, dict) and observation.get("schema") == "clipforge-int-db01-observation-1", "source_observation_schema_required")
    base = guest.validate_report(observation.get("base_inventory"))
    require(base["status"] == "inventory_complete" and base["safety"]["passed"] is True, "complete_safe_inventory_required")
    inventory = base["inventory"]; release = inventory["os_release"]
    require(release.get("ID") == "debian" and release.get("VERSION_ID") == "13" and release.get("VERSION_CODENAME") == "trixie", "observed_debian13_required")
    rows = observation.get("packages_source")
    require(isinstance(rows, list) and 0 < len(rows) <= 16384, "source_package_rows_required")
    base_rows = {(row[0], row[1], row[3]): row[2] for row in inventory["packages"]}
    require(len(base_rows) == len(inventory["packages"]), "duplicate_base_package_identity")
    wanted = {"unknown": "u", "install": "i", "hold": "h", "deinstall": "r", "purge": "p"}
    current = {"not-installed": "n", "config-files": "c", "half-installed": "H", "unpacked": "U", "half-configured": "F", "triggers-awaited": "W", "triggers-pending": "t", "installed": "i"}
    components, observed, excluded = [], {}, []
    for row in rows:
        require(isinstance(row, dict) and set(row) == SOURCE_FIELDS and all(isinstance(value, str) for value in row.values()), "exact_observed_source_fields_required")
        name, version, arch = row["binary_name"], row["binary_version"], row["architecture"]
        guest.parse_packages((name + "\t" + version + "\tinstalled\t" + arch + "\n").encode())
        split = name.split(":")
        require(len(split) == 1 or len(split) == 2 and split[1] == arch, "binary_name_architecture_mismatch")
        identity = (name, version, arch)
        require(identity not in observed, "duplicate_observed_package_identity")
        parts = row["status"].split(" ")
        require(len(parts) == 3 and parts[0] in wanted and parts[1] in {"ok", "reinstreq"} and parts[2] in current
                and row["status_abbrev"] == wanted[parts[0]] + current[parts[2]] + (" " if parts[1] == "ok" else "R"), "observed_status_fields_disagree")
        require(identity in base_rows and parts[2] == base_rows[identity], "base_source_snapshot_mismatch")
        require(parts[1] == "ok" and parts[2] in {"installed", "not-installed", "config-files"}, "dpkg_error_or_partial_state_scan_blocked")
        observed[identity] = row
        require((not row["source_name"] or re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", row["source_name"]))
                and (not row["source_version"] or re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", row["source_version"])), "observed_source_identity_invalid")
        if parts[2] != "installed" or parts[1] != "ok":
            excluded.append({key: row[key] for key in ("binary_name", "binary_version", "architecture", "status", "status_abbrev")})
            continue
        require(row["source_name"] and row["source_version"], "missing_observed_source_fields_scan_blocked")
        binary = split[0]
        purl = "pkg:deb/debian/" + quote(binary, safe="") + "@" + quote(version, safe="") + "?arch=" + quote(arch, safe="") + "&distro=debian-13"
        components.append({"type": "library", "bom-ref": purl, "name": binary, "version": version, "purl": purl,
            "properties": [{"name": "clipforge:observed-binary-name", "value": name},
                           {"name": "clipforge:observed-dpkg-status", "value": row["status"]},
                           {"name": "clipforge:observed-dpkg-status-abbrev", "value": row["status_abbrev"]},
                           {"name": "clipforge:source-package-fields", "value": "observed"},
                           {"name": "aquasecurity:trivy:SrcName", "value": row["source_name"]},
                           {"name": "aquasecurity:trivy:SrcVersion", "value": row["source_version"]}]})
    require(set(observed) == set(base_rows), "base_source_package_coverage_mismatch")
    require(components, "installed_package_components_required")
    components.sort(key=lambda row: row["purl"])
    os_ref = "clipforge-observed-os-debian-13"
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
        "metadata": {"component": {"type": "operating-system", "bom-ref": os_ref, "name": "debian", "version": "13"},
            "tools": {"components": [{"type": "application", "name": "clipforge-db01-guest-inventory-converter", "version": "2"}]},
            "properties": [{"name": "clipforge:observation-sha256", "value": expected_sha256},
                           {"name": "clipforge:origin", "value": "read-only-guest-dpkg-query-binary-and-source-metadata"},
                           {"name": "clipforge:source-fields-observed", "value": "true"}]},
        "components": components, "dependencies": [{"ref": os_ref, "dependsOn": [row["bom-ref"] for row in components]}]}
    bom_raw = encoded(sbom)
    manifest = {"schema": "clipforge-db01-guest-sca-input-2", "inventory_sha256": expected_sha256,
        "evidence_sha256": expected_sha256, "evidence_bytes": len(raw), "guest_report_sha256": evidence["guest_report_sha256"],
        "disk_proof": proof, "sbom_sha256": sha256(bom_raw), "sbom_bytes": len(bom_raw),
        "base_inventory_canonical_sha256": sha256(encoded(base)), "observed_os_release": release, "observed_kernel": inventory["kernel"],
        "package_rows_observed": len(rows), "package_components": len(components), "source_fields_observed": True,
        "observed_status_counts": dict(Counter(row["status"] for row in rows)), "observed_status_abbrev_counts": dict(Counter(row["status_abbrev"] for row in rows)),
        "source_name_aliases_observed": sum(row["source_name"] != row["binary_name"].split(":")[0] for row in rows if row["source_name"]),
        "source_version_differences_observed": sum(row["source_version"] != row["binary_version"] for row in rows if row["source_version"]),
        "excluded_noninstalled_or_error_rows": excluded, "dpkg_database_reconstructed": False, "generated_by_trivy": False,
        "complete_filesystem_sca": False, "limitations": SOURCE_LIMITATIONS}
    return sbom, manifest


def observed_source_mapping(sbom, packages):
    expected = {}
    for component in sbom["components"]:
        properties = component.get("properties", [])
        require(len({row["name"] for row in properties}) == len(properties), "duplicate_sbom_source_property")
        props = {row["name"]: row["value"] for row in properties}
        require(props.get("aquasecurity:trivy:SrcName") and props.get("aquasecurity:trivy:SrcVersion"), "observed_sbom_source_fields_required")
        expected[package_identity(component["purl"])] = (props["aquasecurity:trivy:SrcName"], props["aquasecurity:trivy:SrcVersion"])
    for row in packages:
        identity = package_identity(row.get("Identifier", {}).get("PURL"))
        version = row.get("SrcVersion", "")
        release, epoch = row.get("SrcRelease", ""), row.get("SrcEpoch", 0)
        require(isinstance(version, str) and isinstance(release, str) and type(epoch) is int and epoch >= 0, "native_source_version_invalid")
        full = (str(epoch) + ":" if epoch else "") + version + ("-" + release if release else "")
        require(identity in expected and (row.get("SrcName"), full) == expected[identity], "scanner_source_mapping_mismatch")
    return len(expected)


def package_identity(value):
    """Compare parsed PURLs; Trivy normalizes harmless epoch/plus escaping."""
    require(isinstance(value, str) and len(value) <= 2048, "native_debian_purl_required")
    uri = urlsplit(value)
    require(uri.scheme == "pkg" and not uri.netloc and not uri.fragment
            and uri.path.startswith("deb/debian/") and uri.path.count("/") == 2
            and uri.path.count("@") == 1, "native_debian_purl_required")
    name, version = (unquote(part) for part in uri.path.removeprefix("deb/debian/").split("@"))
    fields = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
    require(len(fields) == 2 and {key for key, _ in fields} == {"arch", "distro"}, "native_purl_qualifiers_required")
    qualifiers = dict(fields)
    require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name) and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", version)
            and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", qualifiers["arch"])
            and qualifiers["distro"] == "debian-13", "native_purl_identity_invalid")
    return name, version, qualifiers["arch"], qualifiers["distro"]


def summarize(report, sbom, manifest):
    """Require native scanner coverage of each submitted PURL before counting."""
    require(isinstance(report, dict) and report.get("SchemaVersion") == 2
            and report.get("ArtifactType") == "cyclonedx", "native_cyclonedx_report_required")
    os = report.get("Metadata", {}).get("OS", {})
    require(os.get("Family") == "debian" and os.get("Name") == "13", "scanner_os_mismatch")
    results = report.get("Results")
    require(isinstance(results, list) and len(results) == 1 and results[0].get("Class") == "os-pkgs"
            and results[0].get("Type") == "debian", "single_debian_package_result_required")
    packages = results[0].get("Packages")
    require(isinstance(packages, list), "native_all_packages_required")
    expected = {package_identity(row["purl"]) for row in sbom["components"]}
    actual = [package_identity(row.get("Identifier", {}).get("PURL")) for row in packages]
    require(len(actual) == len(expected) and set(actual) == expected, "scanner_package_coverage_mismatch")
    source_observed = manifest.get("schema") == "clipforge-db01-guest-sca-input-2" and manifest.get("source_fields_observed") is True
    if source_observed:
        observed_source_mapping(sbom, packages)
    vulnerabilities = results[0].get("Vulnerabilities", [])
    require(isinstance(vulnerabilities, list), "native_vulnerability_array_required")
    severities = Counter()
    findings = []
    for row in vulnerabilities:
        severity = row.get("Severity")
        require(severity in {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
                and isinstance(row.get("VulnerabilityID"), str) and isinstance(row.get("PkgName"), str), "native_finding_fields_required")
        severities[severity] += 1
        findings.append({key: row.get(key) for key in ("VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Status", "Severity", "SeveritySource", "PrimaryURL", "DataSource")})
    return {"schema": "clipforge-db01-guest-sca-summary-2" if source_observed else "clipforge-db01-guest-sca-summary-1", "inventory_sha256": manifest["inventory_sha256"],
        "sbom_sha256": manifest["sbom_sha256"], "os_family": "debian", "os_version": "13",
        "packages_submitted": len(expected), "packages_recognized": len(actual),
        "finding_rows": len(findings), "unique_vulnerabilities": len({row["VulnerabilityID"] for row in findings}),
        "severity_counts": {key: severities[key] for key in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")},
        "findings": findings, "source_fields_observed": source_observed, "complete_filesystem_sca": False,
        "security_accepted": False, "limitations": SOURCE_LIMITATIONS if source_observed else LIMITATIONS}


def read_regular(path):
    require(path.is_file() and not path.is_symlink(), "regular_local_input_required")
    return path.read_bytes()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="operation", required=True)
    prep = sub.add_parser("prepare")
    prep.add_argument("--inventory", type=Path, required=True)
    prep.add_argument("--expected-sha256", default=INVENTORY_SHA256)
    prep.add_argument("--output-directory", type=Path, required=True)
    observed = sub.add_parser("prepare-observation")
    observed.add_argument("--inventory", type=Path, required=True)
    observed.add_argument("--expected-sha256", required=True)
    observed.add_argument("--output-directory", type=Path, required=True)
    summary = sub.add_parser("summarize")
    summary.add_argument("--report", type=Path, required=True)
    summary.add_argument("--sbom", type=Path, required=True)
    summary.add_argument("--manifest", type=Path, required=True)
    summary.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if args.operation in {"prepare", "prepare-observation"}:
        converter = prepare_observation if args.operation == "prepare-observation" else prepare
        bom, manifest = converter(read_regular(args.inventory), args.expected_sha256)
        require(args.output_directory.is_dir() and not args.output_directory.is_symlink(), "existing_output_directory_required")
        for name, value in (("guest-inventory.cdx.json", bom), ("guest-inventory-sca-input.json", manifest)):
            with (args.output_directory / name).open("xb") as stream:
                stream.write(encoded(value))
        print(json.dumps({"package_components": manifest["package_components"], "source_fields_observed": manifest["source_fields_observed"]}))
    else:
        sbom_raw, manifest_raw = read_regular(args.sbom), read_regular(args.manifest)
        manifest = decode(manifest_raw)
        require(sha256(sbom_raw) == manifest.get("sbom_sha256") and len(sbom_raw) == manifest.get("sbom_bytes"), "sbom_custody_mismatch")
        result = summarize(decode(read_regular(args.report), limit=64 * 1024 * 1024), decode(sbom_raw), manifest)
        with args.output.open("xb") as stream:
            stream.write(encoded(result))
        print(json.dumps({"packages_recognized": result["packages_recognized"], "severity_counts": result["severity_counts"]}))


if __name__ == "__main__":
    main()
