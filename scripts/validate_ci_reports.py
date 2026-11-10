"""Fail closed on incomplete CI evidence; never repair or rewrite reports."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime
import hashlib
import json
import math
from pathlib import Path
import re
from urllib.parse import parse_qs, unquote

try:
    from scripts import prepare_ci_context as context
    from scripts import prepare_ci_scan as scan
    from scripts.capture_ci_inventory import normalized_name
except ModuleNotFoundError:
    import prepare_ci_context as context
    import prepare_ci_scan as scan
    from capture_ci_inventory import normalized_name


class ValidationError(ValueError):
    """Missing, malformed, partial or policy-blocked evidence."""


CHECKS = {"isolated_environment", "ffmpeg", "ffprobe", "pip_check", "runtime",
          "media", "presentation", "branding", "test_inventory",
          "test_execution_completeness", "coverage"}
TARGETS = {"debian": "os-pkgs", "python-pkg": "lang-pkgs", "node-pkg": "lang-pkgs"}
METRICS = ("loc", "nosec", "skipped_tests") + tuple(
    f"{kind}.{level}" for kind in ("SEVERITY", "CONFIDENCE")
    for level in ("HIGH", "MEDIUM", "LOW", "UNDEFINED"))
SHA = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"sha256:[0-9a-f]{64}")


def require(condition, message):
    if not condition:
        raise ValidationError(message)


def obj(value, label):
    require(type(value) is dict, f"{label}: expected object")
    return value


def array(value, label, *, nonempty=False):
    require(type(value) is list and (value or not nonempty), f"{label}: expected {'nonempty ' if nonempty else ''}array")
    return value


def string(value, label):
    require(type(value) is str and bool(value.strip()), f"{label}: expected nonempty string")
    return value


def integer(value, label, *, positive=False):
    require(type(value) is int and value >= int(positive), f"{label}: expected {'positive' if positive else 'nonnegative'} integer")
    return value


def number(value, label):
    require(type(value) in (int, float) and math.isfinite(value) and value >= 0,
            f"{label}: expected finite nonnegative number")
    return value


def _pairs(pairs):
    result = {}
    for name, value in pairs:
        require(name not in result, f"Duplicate JSON key: {name}")
        result[name] = value
    return result


def load(path):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 100 * 1024 * 1024,
            f"Missing/unsafe/empty report: {path.name}")
    try:
        return json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=_pairs,
                          parse_constant=lambda value: require(False, f"Invalid JSON number: {value}"))
    except (UnicodeError, json.JSONDecodeError) as error:
        raise ValidationError(f"Invalid JSON: {path.name}") from error


def records(value, label):
    result = {}
    for row in array(value, label, nonempty=True):
        row = obj(row, label)
        name = string(row.get("path"), label + ".path")
        require(name not in result and "\\" not in name and not name.startswith("/")
                and all(part not in ("", ".", "..") for part in name.split("/")), f"{label}: invalid/duplicate path")
        integer(row.get("bytes"), label + ".bytes")
        require(type(row.get("sha256")) is str and SHA.fullmatch(row["sha256"]), f"{label}: invalid hash")
        result[name] = row
    return result


def validate_bandit(report, expected_sources, expected_locs=None):
    report = obj(report, "Bandit")
    require(not array(report.get("errors"), "Bandit.errors"), "Bandit scanner errors remain blocking")
    findings = array(report.get("results"), "Bandit.results")
    stamp = string(report.get("generated_at"), "Bandit.generated_at")
    try:
        require(datetime.fromisoformat(stamp.replace("Z", "+00:00")).tzinfo is not None,
                "Bandit timestamp needs timezone")
    except ValueError as error:
        raise ValidationError("Invalid Bandit timestamp") from error
    metrics = obj(report.get("metrics"), "Bandit.metrics")
    expected = {"/app/" + name for name in expected_sources}
    require(expected and set(metrics) == expected | {"_totals"}, "Bandit file inventory must equal all app/scripts Python sources")
    for name, values in metrics.items():
        values = obj(values, "Bandit metrics " + name)
        require(set(values) == set(METRICS), "Bandit metrics schema is incomplete/unsupported")
        for field in METRICS:
            integer(values[field], "Bandit " + field)
        require(values["skipped_tests"] == 0, "Bandit skipped tests remain blocking")
        require(values["nosec"] == 0, "Bandit suppression metrics contradict --ignore-nosec")
    totals = metrics["_totals"]
    require(totals["loc"] > 0, "Bandit must analyze nonzero lines")
    if expected_locs is not None:
        require(all(metrics["/app/" + name]["loc"] == count for name, count in expected_locs.items()),
                "Bandit per-file LOC differs from verified source (Bandit 1.9.4 counting rules)")
    for field in METRICS:
        require(totals[field] == sum(metrics[name][field] for name in expected), "Bandit metric totals do not match files")
    for kind, field in (("SEVERITY", "issue_severity"), ("CONFIDENCE", "issue_confidence")):
        counts = Counter()
        for item in findings:
            item = obj(item, "Bandit finding")
            require(item.get("filename") in expected, "Bandit finding is outside expected scope")
            integer(item.get("line_number"), "Bandit line", positive=True)
            require(item.get(field) in ("HIGH", "MEDIUM", "LOW", "UNDEFINED"), "Invalid Bandit finding level")
            counts[item[field]] += 1
        for level in ("HIGH", "MEDIUM", "LOW", "UNDEFINED"):
            require(totals[f"{kind}.{level}"] == counts[level], "Bandit findings and metrics disagree")
    require(not findings, "Static security findings remain blocking")


def package_set(packages, kind, *, trivy=False):
    result = set()
    for package in array(packages, kind + " packages", nonempty=True):
        package = obj(package, "package")
        name = string(package.get("Name"), "package.Name")
        version = string(package.get("Version"), "package.Version")
        if trivy and kind == "debian":
            epoch = integer(package.get("Epoch", 0), "package.Epoch")
            release = package.get("Release", "")
            require(type(release) is str, "package.Release: expected string")
            version = (f"{epoch}:" if epoch else "") + version + ("-" + release if release else "")
        key = (normalized_name(name) if kind == "python-pkg" else name, version)
        require(key not in result, "Duplicate package in " + kind)
        if trivy:
            purl = obj(package.get("Identifier"), "package.Identifier").get("PURL")
            require(purl_key(purl) == (kind, *key), "Package fields disagree with PURL")
        result.add(key)
    return result


def purl_key(purl):
    purl = string(purl, "package PURL")
    value = unquote(purl.split("?", 1)[0].split("#", 1)[0])
    require("@" in value and "/" in value, "Invalid PURL")
    name, version = value.rsplit("@", 1)
    head, name = name.split("/", 1)
    kind = {"pkg:deb": "debian", "pkg:pypi": "python-pkg", "pkg:npm": "node-pkg"}.get(head)
    require(kind is not None and version, "Unsupported/empty PURL")
    if kind == "debian":
        require(name.startswith("debian/"), "Non-Debian OS package")
        name = name.removeprefix("debian/")
        qualifiers = parse_qs(purl.partition("?")[2].split("#", 1)[0], keep_blank_values=True)
        if "epoch" in qualifiers:
            epoch = qualifiers["epoch"]
            require(len(epoch) == 1 and re.fullmatch(r"0|[1-9][0-9]*", epoch[0]), "Invalid Debian PURL epoch")
            if int(epoch[0]):
                require(":" not in version or version.startswith(epoch[0] + ":"), "Inconsistent Debian epoch")
                if ":" not in version:
                    version = epoch[0] + ":" + version
    return kind, normalized_name(name) if kind == "python-pkg" else name, version


def validate_inventory(inventory, image_id, sources):
    inventory = obj(inventory, "image inventory")
    require(type(inventory.get("schema_version")) is int and inventory["schema_version"] == 1
            and inventory.get("image_id") == image_id and inventory.get("source_root") == "/app",
            "Invalid independent image inventory identity/schema")
    require(records(inventory.get("python_sources"), "image sources") == sources,
            "Image Python source bytes/hashes differ from verified build context")
    os_info = obj(inventory.get("os"), "inventory OS")
    require(os_info.get("family") == "debian" and re.fullmatch(r"13(?:\.\d+)?", string(os_info.get("name"), "OS name")),
            "Expected Debian 13 candidate")
    targets = {}
    for target in array(inventory.get("targets"), "inventory targets", nonempty=True):
        target = obj(target, "inventory target")
        kind = string(target.get("Type"), "inventory target Type")
        require(kind in TARGETS and kind not in targets and target.get("Class") == TARGETS[kind], "Invalid/duplicate inventory target")
        targets[kind] = package_set(target.get("Packages"), kind)
    require(set(targets) == set(TARGETS), "Independent package inventory is incomplete")
    for kind, names in {
        "debian": {"ffmpeg", "libxml2", "zlib1g", "fonts-dejavu-core"},
        "python-pkg": {"fastapi", "starlette", "python-multipart", "faster-whisper", "av", "bandit", "coverage", "playwright", "pip"},
        "node-pkg": {"playwright-core"},
    }.items():
        require(names <= {name for name, _ in targets[kind]}, "Required candidate packages missing: " + kind)
    return targets, os_info


def validate_trivy(report, image_id, expected, os_info):
    report = obj(report, "Trivy")
    require(type(report.get("SchemaVersion")) is int and report["SchemaVersion"] == 2
            and report.get("ArtifactType") == "container_image", "Unsupported/incomplete Trivy schema")
    artifact = string(report.get("ArtifactName"), "Trivy.ArtifactName")
    metadata = obj(report.get("Metadata"), "Trivy.Metadata")
    require(metadata.get("ImageID") == image_id, "Trivy image identity mismatch")
    require(metadata.get("OS") == {"Family": os_info["family"], "Name": os_info["name"]}, "Trivy OS mismatch")
    require(not {"Errors", "Error", "errors", "error"} & report.keys(), "Unexpected Trivy scanner error field")
    targets = {}
    vulnerabilities = []
    for target in array(report.get("Results"), "Trivy.Results", nonempty=True):
        target = obj(target, "Trivy result")
        kind = string(target.get("Type"), "Trivy target Type")
        require(kind in expected and kind not in targets and target.get("Class") == TARGETS[kind], "Trivy target schema/coverage is incomplete")
        name = {"python-pkg": "Python", "node-pkg": "Node.js", "debian": f"{artifact} (debian {os_info['name']})"}[kind]
        require(target.get("Target") == name, "Unexpected Trivy target")
        require(not {"Errors", "Error", "errors", "error"} & target.keys(), "Unexpected Trivy target error field")
        targets[kind] = package_set(target.get("Packages"), kind, trivy=True)
        require(targets[kind] == expected[kind], "Trivy package inventory is partial or differs from image: " + kind)
        for finding in array(target.get("Vulnerabilities", []), "Trivy vulnerabilities"):
            finding = obj(finding, "Trivy vulnerability")
            string(finding.get("VulnerabilityID"), "vulnerability ID")
            string(finding.get("PkgName"), "vulnerability package")
            require(finding.get("Severity") in {"HIGH", "CRITICAL"}, "Unexpected/malformed vulnerability severity in mandatory gate")
            vulnerabilities.append(finding)
    require(set(targets) == set(expected), "Trivy is missing expected targets")
    require(not vulnerabilities, "HIGH/CRITICAL vulnerabilities remain blocking")


def validate_sbom(sbom, image_id, expected):
    sbom = obj(sbom, "SBOM")
    require(sbom.get("bomFormat") == "CycloneDX" and sbom.get("specVersion") == "1.7"
            and type(sbom.get("version")) is int and sbom["version"] > 0, "Expected complete CycloneDX 1.7 SBOM")
    properties = {}
    layer_ids = set()
    metadata = obj(sbom.get("metadata"), "SBOM metadata")
    component = obj(metadata.get("component"), "SBOM component")
    for prop in array(component.get("properties"), "SBOM properties", nonempty=True):
        prop = obj(prop, "SBOM property")
        name = string(prop.get("name"), "SBOM property name")
        value = string(prop.get("value"), "SBOM property value")
        if name == "aquasecurity:trivy:DiffID":
            require(IMAGE.fullmatch(value) and value not in layer_ids, "Invalid/duplicate SBOM layer ID")
            layer_ids.add(value)
            continue
        require(name not in properties, "Duplicate SBOM property")
        properties[name] = value
    require(properties.get("aquasecurity:trivy:ImageID") == image_id, "SBOM image mismatch")
    packages = set()
    for component in array(sbom.get("components"), "SBOM components", nonempty=True):
        component = obj(component, "SBOM package")
        name = string(component.get("name"), "SBOM package name")
        version = string(component.get("version"), "SBOM package version")
        if component.get("type") == "operating-system":
            continue
        require(component.get("type") == "library", "Unexpected/incomplete SBOM component type")
        key = purl_key(component.get("purl"))
        require((key[1], key[2]) == (normalized_name(name) if key[0] == "python-pkg" else name, version),
                "SBOM package fields disagree with PURL")
        require(key not in packages, "Duplicate SBOM package")
        packages.add(key)
    require(packages == {(kind, *key) for kind, items in expected.items() for key in items},
            "SBOM package inventory differs from independent image inventory")


def validate_tests(summary, measurement, expected_sources=None):
    summary = obj(summary, "test summary")
    require(type(summary.get("schema_version")) is int and summary["schema_version"] == 1,
            "Invalid test summary schema")
    require(summary.get("status") == summary.get("suite_status") == "passed"
            and type(summary.get("exit_code")) is int and summary["exit_code"] == 0, "Tests did not pass")
    counts = obj(summary.get("tests"), "test counts")
    integer(counts.get("tests_run"), "tests_run", positive=True)
    for name in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
        require(integer(counts.get(name), name) == 0, "Test failures/omissions")
    checks = array(summary.get("checks"), "checks", nonempty=True)
    require(all(type(c) is dict and c.get("status") == "passed" for c in checks), "Mandatory checks did not pass")
    names = [string(c.get("name"), "check name") for c in checks]
    require(len(set(names)) == len(names) and CHECKS <= set(names), "Incomplete/duplicate mandatory checks")
    for check in checks:
        require(not {"error", "errors", "error_type"} & check.keys(), "Test check contains error evidence")
        if check["name"] in {"pip_check", "runtime", "media", "presentation", "branding"}:
            require(type(check.get("returncode")) is int and check["returncode"] == 0, "Native/pip check return code must be integer zero")
    inventory = obj(summary.get("test_inventory"), "test inventory")
    ids = array(inventory.get("ids"), "test IDs", nonempty=True)
    require(all(type(name) is str and name.strip() for name in ids), "Malformed test IDs")
    for name in ("discovered", "unique"):
        require(integer(inventory.get(name), name, positive=True) == len(ids), "Incomplete test inventory")
    require(len(set(ids)) == len(ids) == counts["tests_run"] and inventory.get("duplicate_ids") == []
            and inventory.get("sha256_utf8_lf") == hashlib.sha256(("\n".join(sorted(ids)) + "\n").encode()).hexdigest(),
            "Discovered IDs must be unique, complete and fully executed")
    coverage = obj(summary.get("coverage"), "coverage summary")
    require(coverage.get("status") == "passed" and coverage.get("measured") is True
            and coverage.get("branch") is True and coverage.get("source") == ["app", "scripts"]
            and coverage.get("omit") == [], "Coverage measurement incomplete")
    measurement = obj(measurement, "coverage JSON")
    files = obj(measurement.get("files"), "coverage files")
    require(files, "Empty coverage scope")
    if expected_sources is not None:
        require(set(files) == set(expected_sources), "Coverage file scope differs from app/scripts sources")
    totals = obj(measurement.get("totals"), "coverage totals")
    statements = integer(totals.get("num_statements"), "coverage statements", positive=True)
    covered = integer(totals.get("covered_lines"), "covered lines")
    require(covered + integer(totals.get("missing_lines"), "missing lines") == statements
            and integer(totals.get("excluded_lines"), "excluded lines") == 0, "Invalid/incomplete line coverage")
    branches = integer(totals.get("num_branches"), "branches", positive=True)
    require(integer(totals.get("covered_branches"), "covered branches")
            + integer(totals.get("missing_branches"), "missing branches") == branches, "Invalid branch coverage")
    require(number(totals.get("percent_covered"), "percent coverage") <= 100, "Invalid coverage percentage")
    fields = ("covered_lines", "num_statements", "missing_lines", "excluded_lines",
              "num_branches", "covered_branches", "missing_branches")
    for name, file in files.items():
        file = obj(file, "coverage file " + name)
        values = obj(file.get("summary"), "file coverage summary")
        for field in fields:
            integer(values.get(field), "file coverage " + field)
        require(values["covered_lines"] + values["missing_lines"] == values["num_statements"]
                and values["covered_branches"] + values["missing_branches"] == values["num_branches"]
                and values["excluded_lines"] == 0, "Inconsistent file coverage")
    require(all(sum(file["summary"][field] for file in files.values()) == totals[field] for field in fields),
            "Coverage totals do not equal per-file measurements")
    combined = 100 * (covered + totals["covered_branches"]) / (statements + branches)
    require(math.isclose(totals["percent_covered"], combined, abs_tol=1e-9, rel_tol=1e-12)
            and math.isclose(number(coverage.get("percent_covered"), "summary percent"), combined,
                             abs_tol=1e-9, rel_tol=1e-12), "Coverage percentage contradicts measurement")


def validate_browser(report):
    report = obj(report, "browser")
    require(report.get("status") == "passed" and type(report.get("exit_code")) is int
            and report["exit_code"] == 0 and report.get("bridge_allowed") is False, "Browser failed or bridge enabled")
    require(integer(report.get("direct_http_scenarios_passed"), "HTTP count") == 5
            and integer(report.get("simulated_api_scenarios_passed"), "simulation count") == 1, "Incomplete browser transport coverage")
    checks = array(report.get("checks"), "browser checks", nonempty=True)
    require(all(type(item) is dict and item.get("status") == "passed"
                and not {"error", "errors", "error_type"} & item.keys() for item in checks), "Browser prerequisites failed/incomplete")
    require(len(checks) == 3 and {item.get("name") for item in checks} == {"ffmpeg", "ffprobe", "browser_toolchain"}, "Missing browser prerequisite")
    toolchain = obj(report.get("toolchain"), "browser toolchain")
    for key in ("playwright_version", "chromium_version", "chromium_revision", "system", "machine"):
        string(toolchain.get(key), "browser " + key)
    require(toolchain["system"] == "Linux" and toolchain["machine"] == "x86_64", "Unexpected browser platform")
    scenarios = {}
    for item in array(report.get("scenarios"), "browser scenarios", nonempty=True):
        item = obj(item, "browser scenario")
        name = string(item.get("name"), "browser scenario name")
        require(name not in scenarios, "Duplicate browser scenario")
        scenarios[name] = item
        require(item.get("script") == f"browser_{name}.py"
                and not {"error", "errors", "error_type"} & item.keys(), "Browser script mismatch or error evidence")
        require(item.get("status") == "passed" and type(item.get("returncode")) is int
                and item["returncode"] == 0 and item.get("timed_out") is False
                and item.get("bridge_detected") is False, "Browser scenario incomplete/failed")
        integer(item.get("reported_steps"), "browser steps", positive=True)
        require(item.get("transport") == ("simulated_fetch" if name == "smoke" else "direct_http"), "Browser transport mismatch")
    require(set(scenarios) == {"smoke", "workflow", "editorial", "delivery", "ai", "operations"}, "Missing browser scenario")


def validate_reports(reports: Path, source_context: Path) -> dict:
    errors = []
    def check(name, operation):
        try:
            operation()
        except (ValidationError, OSError, KeyError, TypeError, ValueError) as error:
            errors.append({"control": name, "message": str(error)})

    context.verify_context(source_context, reports / "context-manifest.json")
    manifest = load(reports / "context-manifest.json")
    sources = {name: record for name, record in records(manifest["files"], "context").items()
               if name.endswith(".py") and name.split("/")[0] in {"app", "scripts"}}
    require(sources, "Empty Python analysis scope")
    source_scan = obj(load(reports / "source-scan-manifest.json"), "source scan")
    require(source_scan.get("schema") == "clipforge-ci-source-scan-1", "Invalid secret-scan scope schema")
    tracked = records(source_scan.get("files"), "source scan files")
    scan.validate_paths(list(tracked))
    require(all(tracked.get(row["path"]) == row for row in manifest["files"]), "Secret-scan snapshot does not cover build sources exactly")
    check("tests_coverage", lambda: validate_tests(load(reports / "test-summary.json"), load(reports / "coverage/coverage.json"), sources))
    check("coverage_xml", lambda: require((reports / "coverage/coverage.xml").is_file()
                                         and (reports / "coverage/coverage.xml").stat().st_size > 0, "Missing/empty coverage XML"))
    check("browser", lambda: validate_browser(load(reports / "browser/browser-summary.json")))
    expected_locs = {name: sum(bool(line.strip()) and not line.strip().startswith(b"#")
                               for line in (source_context / name).read_bytes().split(b"\n")) for name in sources}
    check("bandit", lambda: validate_bandit(load(reports / "bandit.json"), sources, expected_locs))
    check("gitleaks", lambda: require(not array(load(reports / "gitleaks-source.json"), "Gitleaks"), "Secret findings remain blocking"))
    def actionlint():
        result = obj(load(reports / "actionlint-summary.json"), "actionlint")
        require(type(result.get("schema_version")) is int and result["schema_version"] == 1
                and result.get("version") == "1.7.12", "Actionlint version/schema mismatch")
        for name, expected in (("workflow_exit", 0), ("invalid_fixture_exit", 1)):
            require(type(result.get(name)) is int and result[name] == expected, "Actionlint contract failed")
        require(result.get("invalid_fixture_rejected") is True, "Actionlint invalid fixture was not rejected")
        workflow = tracked.get(".github/workflows/ci.yml")
        require(type(workflow) is dict and type(result.get("workflow_sha256")) is str
                and SHA.fullmatch(result["workflow_sha256"])
                and result["workflow_sha256"] == workflow["sha256"], "Linted workflow missing or differs from scanned sources")
        require("1.7.12" in (reports / "actionlint-version.txt").read_text(), "Missing actionlint version evidence")
    check("actionlint", actionlint)
    for prefix in ("", "browser-"):
        def image_checks(prefix=prefix):
            image_id = (reports / f"{prefix}image-id.txt").read_text().strip()
            require(IMAGE.fullmatch(image_id), "Invalid image ID")
            archive_hash = (reports / f"{prefix}image-archive.sha256").read_text().strip()
            require(SHA.fullmatch(archive_hash), "Missing/invalid archive hash")
            expected, os_info = validate_inventory(load(reports / f"{prefix}image-inventory.json"), image_id, sources)
            check(prefix + "sbom", lambda: validate_sbom(load(reports / f"{prefix}sbom.cdx.json"), image_id, expected))
            check(prefix + "trivy", lambda: validate_trivy(load(reports / f"{prefix}trivy-high-critical.json"), image_id, expected, os_info))
        check(prefix + "image_inventory", image_checks)
    def database():
        db = obj(load(reports / "trivy-db-metadata.json"), "Trivy DB")
        require(type(db.get("Version")) is int and db["Version"] == 2, "Invalid DB version")
        for name in ("UpdatedAt", "DownloadedAt", "NextUpdate"):
            stamp = datetime.fromisoformat(string(db.get(name), name).replace("Z", "+00:00"))
            require(stamp.tzinfo is not None, "DB timestamp lacks timezone")
        require(SHA.fullmatch((reports / "trivy-db.sha256").read_text().strip()), "Invalid DB hash")
    check("trivy_database", database)
    return {"schema_version": 1, "status": "failed" if errors else "passed", "errors": errors}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--context", type=Path, required=True)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        result = validate_reports(args.reports, args.context)
    except (ValidationError, OSError, ValueError, KeyError, TypeError) as error:
        result = {"schema_version": 1, "status": "failed", "errors": [{"control": "report_scope", "message": str(error)}]}
    if args.output:
        with args.output.open("x", encoding="utf-8", newline="\n") as stream:
            json.dump(result, stream, indent=2)
            stream.write("\n")
    print(json.dumps(result, sort_keys=True))
    return int(result["status"] != "passed")


if __name__ == "__main__":
    raise SystemExit(main())
