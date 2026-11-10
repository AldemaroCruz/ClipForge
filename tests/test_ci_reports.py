"""Fail-closed report contracts using COMPLETE, EXPLICITLY SYNTHETIC fixtures.

No scanner, application, package installation or live inventory is executed.
create_fixture() writes only into a caller-owned empty temporary directory and
returns (reports, source_context) for offline reproductions of the full gate.
The fixture's passing status is schema-test data, never real security evidence.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import copy
import hashlib
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from urllib.parse import quote

from scripts import capture_ci_inventory as capture
from scripts import prepare_ci_context as context
from scripts import prepare_ci_scan as scan
from scripts import validate_ci_reports as gate


SYNTHETIC = "SYNTHETIC FIXTURE ONLY: no scanner or real security acceptance"
IMAGE_ID = "sha256:" + "1" * 64
BROWSER_IMAGE_ID = "sha256:" + "2" * 64
PACKAGES = {
    "debian": [{"Name": name, "Version": "1.0-1"} for name in
               ("ffmpeg", "fonts-dejavu-core", "libxml2", "zlib1g")],
    "python-pkg": [{"Name": name, "Version": "1.0.0"} for name in (
        "av", "bandit", "coverage", "fastapi", "faster-whisper", "pip",
        "playwright", "python-multipart", "starlette",
    )],
    "node-pkg": [{"Name": "playwright-core", "Version": "1.0.0"}],
}
SCENARIOS = ("smoke", "workflow", "editorial", "delivery", "ai", "operations")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def purl(kind, package):
    head = {"debian": "pkg:deb/debian/", "python-pkg": "pkg:pypi/", "node-pkg": "pkg:npm/"}[kind]
    return head + package["Name"] + "@" + quote(package["Version"], safe=".+-")


def create_fixture(tmpRoot):
    """Create a complete synthetic dossier in an EMPTY disposable directory.

    Public reproduction helper: returns (reports: Path, context: Path).
    Context preparation and the permitted source snapshot run for real, over
    authored fixture sources. All purported tool findings/inventories are fake.
    """
    root = Path(tmpRoot)
    root.mkdir(parents=True, exist_ok=True)
    if any(root.iterdir()):
        raise ValueError("Synthetic report fixtures require an empty disposable root")
    source, prepared, reports = root / "source", root / "context", root / "reports"
    source.mkdir()
    for directory in context.DIRECTORIES:
        (source / directory).mkdir(parents=True, exist_ok=True)
    reports.mkdir()
    (reports / "SYNTHETIC-FIXTURE.txt").write_text(SYNTHETIC + "\n", encoding="utf-8")
    for relative in sorted(context.REQUIRED_FILES | {"app/fixture.py", "tests/test_fixture.py"}):
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text("FIXTURE_ONLY = 1\n" if target.suffix == ".py" else "# " + SYNTHETIC + "\n",
                          encoding="utf-8")
    workflow = source / ".github/workflows/ci.yml"
    workflow.parent.mkdir(parents=True)
    workflow.write_text("# " + SYNTHETIC + "\nname: synthetic\non: push\njobs: {}\n", encoding="utf-8")
    context.prepare_context(source, prepared, reports / "context-manifest.json")
    context_manifest = read_json(reports / "context-manifest.json")
    tracked = sorted([record["path"] for record in context_manifest["files"]] + [".github/workflows/ci.yml"])
    index = root / "tracked-fixture-paths.txt"
    index.write_bytes(("\0".join(tracked) + "\0").encode("utf-8"))
    scan.prepare_scan(source, index, root / "scan")
    source_scan = read_json(root / "scan" / scan.MANIFEST)
    write_json(reports / "source-scan-manifest.json", source_scan)
    workflow_sha = next(record["sha256"] for record in source_scan["files"]
                        if record["path"] == ".github/workflows/ci.yml")
    sources = [record for record in context_manifest["files"]
               if record["path"].endswith(".py") and record["path"].split("/")[0] in {"app", "scripts"}]
    metrics = {"/app/" + record["path"]: {name: (1 if name == "loc" else 0) for name in gate.METRICS}
               for record in sources}
    metrics["_totals"] = {name: sum(values[name] for values in metrics.values()) for name in gate.METRICS}
    write_json(reports / "bandit.json", {
        "synthetic_fixture": SYNTHETIC, "generated_at": "2026-11-10T00:00:00Z",
        "results": [], "errors": [], "metrics": metrics,
    })
    test_ids = ["synthetic_fixture.Contract.test_schema_only"]
    coverage_summary = {
        "status": "passed", "measured": True, "branch": True,
        "source": ["app", "scripts"], "omit": [], "percent_covered": 50.0, "threshold": None,
    }
    write_json(reports / "test-summary.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "status": "passed", "suite_status": "passed", "exit_code": 0,
        "tests": {"tests_run": 1, "failures": 0, "errors": 0, "skipped": 0,
                  "expected_failures": 0, "unexpected_successes": 0},
        "checks": [{"name": name, "status": "passed", **({"returncode": 0} if name in
                    {"pip_check", "runtime", "media", "presentation", "branding"} else {})}
                   for name in sorted(gate.CHECKS)],
        "test_inventory": {"ids": test_ids, "discovered": 1, "unique": 1, "duplicate_ids": [],
                           "sha256_utf8_lf": hashlib.sha256((test_ids[0] + "\n").encode()).hexdigest()},
        "coverage": coverage_summary,
    })
    coverage_files = {record["path"]: {"summary": {
        "num_statements": 2, "covered_lines": 1, "missing_lines": 1, "excluded_lines": 0,
        "num_branches": 2, "covered_branches": 1, "missing_branches": 1, "percent_covered": 50.0,
    }} for record in sources}
    write_json(reports / "coverage/coverage.json", {
        "synthetic_fixture": SYNTHETIC, "meta": {"version": "7.17.2", "branch_coverage": True},
        "files": coverage_files, "totals": {
            "num_statements": 2 * len(sources), "covered_lines": len(sources), "missing_lines": len(sources),
            "excluded_lines": 0, "num_branches": 2 * len(sources), "covered_branches": len(sources),
            "missing_branches": len(sources), "percent_covered": 50.0,
        },
    })
    (reports / "coverage/coverage.xml").write_text('<coverage version="SYNTHETIC-FIXTURE"/>\n', encoding="utf-8")
    write_json(reports / "browser/browser-summary.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "status": "passed", "exit_code": 0,
        "bridge_allowed": False, "direct_http_scenarios_passed": 5, "simulated_api_scenarios_passed": 1,
        "checks": [{"name": name, "status": "passed"} for name in ("ffmpeg", "ffprobe", "browser_toolchain")],
        "toolchain": {"playwright_version": "1.64.1", "chromium_version": "156.0.8078.4",
                      "chromium_revision": "1248", "system": "Linux", "machine": "x86_64"},
        "scenarios": [{"name": name, "script": "browser_" + name + ".py", "status": "passed",
                       "returncode": 0, "timed_out": False, "bridge_detected": False, "reported_steps": 1,
                       "transport": "simulated_fetch" if name == "smoke" else "direct_http"} for name in SCENARIOS],
    })
    write_json(reports / "gitleaks-source.json", [])
    write_json(reports / "actionlint-summary.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "version": "1.7.12",
        "workflow_exit": 0, "invalid_fixture_exit": 1, "invalid_fixture_rejected": True,
        "workflow_sha256": workflow_sha,
    })
    (reports / "actionlint-version.txt").write_text("actionlint 1.7.12 — " + SYNTHETIC + "\n", encoding="utf-8")
    for prefix, image_id in (("", IMAGE_ID), ("browser-", BROWSER_IMAGE_ID)):
        (reports / (prefix + "image-id.txt")).write_text(image_id + "\n", encoding="utf-8")
        (reports / (prefix + "image-archive.sha256")).write_text(("a" if not prefix else "b") * 64 + "\n", encoding="utf-8")
        inventory = {
            "synthetic_fixture": SYNTHETIC, "schema_version": 1, "image_id": image_id, "source_root": "/app",
            "os": {"family": "debian", "name": "13.7"}, "python_sources": sources,
            "targets": [{"Class": gate.TARGETS[kind], "Type": kind, "Packages": copy.deepcopy(packages)}
                        for kind, packages in PACKAGES.items()],
        }
        write_json(reports / (prefix + "image-inventory.json"), inventory)
        artifact = "synthetic-" + ("browser" if prefix else "ci") + "-fixture"
        targets = []
        components = []
        for kind, packages in PACKAGES.items():
            trivy_packages = []
            for package in packages:
                package_purl = purl(kind, package)
                item = {**package, "Identifier": {"PURL": package_purl}}
                if kind == "debian":
                    item.update(Version="1.0", Release="1", Epoch=0)
                trivy_packages.append(item)
                components.append({"type": "library", "name": package["Name"],
                                   "version": package["Version"], "purl": package_purl})
            targets.append({"Class": gate.TARGETS[kind], "Type": kind,
                            "Target": {"debian": artifact + " (debian 13.7)",
                                       "python-pkg": "Python", "node-pkg": "Node.js"}[kind],
                            "Packages": trivy_packages, "Vulnerabilities": []})
        write_json(reports / (prefix + "trivy-high-critical.json"), {
            "synthetic_fixture": SYNTHETIC, "SchemaVersion": 2, "ArtifactType": "container_image",
            "ArtifactName": artifact, "Metadata": {"ImageID": image_id, "OS": {"Family": "debian", "Name": "13.7"}},
            "Results": targets,
        })
        write_json(reports / (prefix + "sbom.cdx.json"), {
            "synthetic_fixture": SYNTHETIC, "bomFormat": "CycloneDX", "specVersion": "1.7", "version": 1,
            "metadata": {"component": {"type": "container", "name": artifact, "properties": [
                {"name": "aquasecurity:trivy:ImageID", "value": image_id},
            ]}}, "components": components,
        })
    write_json(reports / "trivy-db-metadata.json", {
        "synthetic_fixture": SYNTHETIC, "Version": 2, "UpdatedAt": "2026-11-10T00:00:00Z",
        "DownloadedAt": "2026-11-10T01:00:00Z", "NextUpdate": "2026-11-11T00:00:00Z",
    })
    (reports / "trivy-db.sha256").write_text("c" * 64 + "\n", encoding="utf-8")
    return reports, prepared


class CIReportContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-report-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.reports, self.context = create_fixture(self.root)
        manifest = read_json(self.reports / "context-manifest.json")
        self.sources = {record["path"]: record for record in manifest["files"]
                        if record["path"].endswith(".py") and record["path"].split("/")[0] in {"app", "scripts"}}
        self.expected, self.os_info = gate.validate_inventory(
            read_json(self.reports / "image-inventory.json"), IMAGE_ID, self.sources,
        )

    def rejects_report(self, relative, value, control):
        path = self.reports / relative
        original = path.read_bytes()
        try:
            write_json(path, value)
            result = gate.validate_reports(self.reports, self.context)
            self.assertEqual(result["status"], "failed", "Malformed synthetic evidence was accepted")
            self.assertTrue(any(error["control"] == control for error in result["errors"]), result)
        finally:
            path.write_bytes(original)

    def cli_result(self):
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = gate.main(["--reports", str(self.reports), "--context", str(self.context)])
        return exit_code, json.loads(output.getvalue())

    def test_complete_synthetic_fixture_passes_without_rewriting_evidence(self):
        before = {path.relative_to(self.reports).as_posix(): path.read_bytes()
                  for path in self.reports.rglob("*") if path.is_file()}
        self.assertEqual(gate.validate_reports(self.reports, self.context),
                         {"schema_version": 1, "status": "passed", "errors": []})
        after = {path.relative_to(self.reports).as_posix(): path.read_bytes()
                 for path in self.reports.rglob("*") if path.is_file()}
        self.assertEqual(after, before)

    def test_full_cli_exits_zero_only_for_complete_fixture(self):
        exit_code, result = self.cli_result()
        self.assertEqual(exit_code, 0)
        self.assertEqual(result["status"], "passed")
        write_json(self.reports / "bandit.json", {"results": [], "errors": []})
        exit_code, result = self.cli_result()
        self.assertEqual(exit_code, 1)
        self.assertEqual(result["status"], "failed")

    def test_bandit_empty_findings_without_metrics_is_rejected(self):
        report = read_json(self.reports / "bandit.json")
        del report["metrics"]
        self.assertEqual(report["results"], [])
        self.assertEqual(report["errors"], [])
        self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_zero_analyzed_lines_is_rejected(self):
        report = read_json(self.reports / "bandit.json")
        for values in report["metrics"].values():
            values["loc"] = 0
        self.rejects_report("bandit.json", report, "bandit")

    def test_trivy_placeholder_result_is_rejected_despite_correct_image_id(self):
        report = read_json(self.reports / "trivy-high-critical.json")
        report["Results"] = [{}]
        self.assertEqual(report["Metadata"]["ImageID"], IMAGE_ID)
        self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_bandit_metric_types_and_schema_fail_closed(self):
        original = read_json(self.reports / "bandit.json")
        source = next(name for name in original["metrics"] if name != "_totals")
        for value in (True, "1", 1.0, None, -1):
            with self.subTest(loc=value):
                report = copy.deepcopy(original)
                report["metrics"][source]["loc"] = value
                self.rejects_report("bandit.json", report, "bandit")
        report = copy.deepcopy(original)
        del report["metrics"][source]["CONFIDENCE.UNDEFINED"]
        self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_errors_and_skipped_tests_remain_blocking(self):
        original = read_json(self.reports / "bandit.json")
        for errors in ([{"filename": "/app/app/main.py", "reason": "synthetic parse error"}], {}, False, ""):
            with self.subTest(errors=errors):
                report = copy.deepcopy(original)
                report["errors"] = errors
                self.rejects_report("bandit.json", report, "bandit")
        report = copy.deepcopy(original)
        source = next(name for name in report["metrics"] if name != "_totals")
        report["metrics"][source]["skipped_tests"] = 1
        report["metrics"]["_totals"]["skipped_tests"] = 1
        self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_omitted_extra_or_zeroed_source_cannot_fake_scope(self):
        original = read_json(self.reports / "bandit.json")
        source = next(name for name in original["metrics"] if name != "_totals")
        report = copy.deepcopy(original)
        omitted = report["metrics"].pop(source)
        for field, count in omitted.items():
            report["metrics"]["_totals"][field] -= count
        self.rejects_report("bandit.json", report, "bandit")
        report = copy.deepcopy(original)
        report["metrics"]["/app/app/not-in-context.py"] = copy.deepcopy(report["metrics"][source])
        report["metrics"]["_totals"]["loc"] += 1
        self.rejects_report("bandit.json", report, "bandit")
        report = copy.deepcopy(original)
        report["metrics"][source]["loc"] = 0
        report["metrics"]["_totals"]["loc"] -= 1
        self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_metric_totals_must_equal_file_totals(self):
        report = read_json(self.reports / "bandit.json")
        report["metrics"]["_totals"]["loc"] += 1
        self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_findings_and_inconsistent_severity_counts_are_blocking(self):
        original = read_json(self.reports / "bandit.json")
        source = next(name for name in original["metrics"] if name != "_totals")
        for consistent in (False, True):
            with self.subTest(consistent=consistent):
                report = copy.deepcopy(original)
                report["results"] = [{"filename": source, "line_number": 1,
                                      "issue_severity": "LOW", "issue_confidence": "HIGH"}]
                if consistent:
                    for name in (source, "_totals"):
                        report["metrics"][name]["SEVERITY.LOW"] = 1
                        report["metrics"][name]["CONFIDENCE.HIGH"] = 1
                self.rejects_report("bandit.json", report, "bandit")

    def test_bandit_timestamp_requires_real_timezone_shape(self):
        original = read_json(self.reports / "bandit.json")
        for stamp in ("", None, True, "synthetic-not-a-date", "2026-11-10T00:00:00"):
            with self.subTest(stamp=stamp):
                report = copy.deepcopy(original)
                report["generated_at"] = stamp
                self.rejects_report("bandit.json", report, "bandit")

    def test_trivy_schema_and_image_identity_are_strict(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for value in (True, "2", None, 1):
            with self.subTest(schema=value):
                report = copy.deepcopy(original)
                report["SchemaVersion"] = value
                self.rejects_report("trivy-high-critical.json", report, "trivy")
        for field, value in (("ImageID", BROWSER_IMAGE_ID), ("OS", {"Family": "debian", "Name": "12"})):
            with self.subTest(metadata=field):
                report = copy.deepcopy(original)
                report["Metadata"][field] = value
                self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_trivy_requires_all_three_unique_exact_targets(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for index in range(3):
            with self.subTest(omitted=index):
                report = copy.deepcopy(original)
                del report["Results"][index]
                self.rejects_report("trivy-high-critical.json", report, "trivy")
        report = copy.deepcopy(original)
        report["Results"].append(copy.deepcopy(report["Results"][0]))
        self.rejects_report("trivy-high-critical.json", report, "trivy")
        for field in ("Target", "Type", "Class"):
            with self.subTest(target_field=field):
                report = copy.deepcopy(original)
                report["Results"][0][field] = "synthetic-wrong-target"
                self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_trivy_omitted_extra_or_duplicate_packages_are_rejected(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for index in range(3):
            with self.subTest(omitted_package=index):
                report = copy.deepcopy(original)
                report["Results"][index]["Packages"].pop()
                self.rejects_report("trivy-high-critical.json", report, "trivy")
        report = copy.deepcopy(original)
        report["Results"][1]["Packages"].append(copy.deepcopy(report["Results"][1]["Packages"][0]))
        self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_trivy_package_fields_must_agree_with_purl(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for field, value in (("Name", "other-package"), ("Version", True), ("Epoch", True), ("Release", False)):
            with self.subTest(package_field=field):
                report = copy.deepcopy(original)
                report["Results"][0]["Packages"][0][field] = value
                self.rejects_report("trivy-high-critical.json", report, "trivy")
        report = copy.deepcopy(original)
        report["Results"][0]["Packages"][0]["Identifier"]["PURL"] = "pkg:deb/ubuntu/ffmpeg@1.0-1"
        self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_trivy_error_fields_cannot_be_hidden_by_false_values(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for scope in ("report", "target"):
            for name in ("Error", "Errors", "error", "errors"):
                for value in (False, 0, {}, [], None, "", ["synthetic scanner error"]):
                    with self.subTest(scope=scope, name=name, value=value):
                        report = copy.deepcopy(original)
                        target = report if scope == "report" else report["Results"][0]
                        target[name] = value
                        self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_trivy_high_critical_or_malformed_findings_block(self):
        original = read_json(self.reports / "trivy-high-critical.json")
        for severity in ("HIGH", "CRITICAL", "LOW", True, None):
            with self.subTest(severity=severity):
                report = copy.deepcopy(original)
                report["Results"][0]["Vulnerabilities"] = [{
                    "VulnerabilityID": "CVE-2099-0001-SYNTHETIC", "PkgName": "ffmpeg", "Severity": severity,
                }]
                self.rejects_report("trivy-high-critical.json", report, "trivy")

    def test_independent_inventory_schema_identity_and_os_are_required(self):
        original = read_json(self.reports / "image-inventory.json")
        for field, value in (("schema_version", True), ("schema_version", "1"),
                             ("image_id", BROWSER_IMAGE_ID), ("source_root", "/other"),
                             ("os", {"family": "ubuntu", "name": "13.7"})):
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("image-inventory.json", report, "image_inventory")

    def test_independent_inventory_sources_and_required_packages_are_complete(self):
        original = read_json(self.reports / "image-inventory.json")
        report = copy.deepcopy(original)
        report["python_sources"][0]["sha256"] = "f" * 64
        self.rejects_report("image-inventory.json", report, "image_inventory")
        report = copy.deepcopy(original)
        report["python_sources"].pop()
        self.rejects_report("image-inventory.json", report, "image_inventory")
        for index in range(3):
            with self.subTest(required_package_target=index):
                report = copy.deepcopy(original)
                report["targets"][index]["Packages"].pop()
                self.rejects_report("image-inventory.json", report, "image_inventory")

    def test_sbom_package_inventory_cannot_be_omitted_or_duplicated(self):
        for prefix in ("", "browser-"):
            original = read_json(self.reports / (prefix + "sbom.cdx.json"))
            for operation in ("omit", "duplicate"):
                with self.subTest(prefix=prefix, operation=operation):
                    report = copy.deepcopy(original)
                    if operation == "omit":
                        report["components"].pop()
                    else:
                        report["components"].append(copy.deepcopy(report["components"][0]))
                    self.rejects_report(prefix + "sbom.cdx.json", report, prefix + "sbom")

    def test_sbom_identity_and_package_purl_are_bound_to_inventory(self):
        original = read_json(self.reports / "sbom.cdx.json")
        layered = copy.deepcopy(original)
        layered["metadata"]["component"]["properties"].extend([
            {"name": "aquasecurity:trivy:DiffID", "value": "sha256:" + "3" * 64},
            {"name": "aquasecurity:trivy:DiffID", "value": "sha256:" + "4" * 64},
        ])
        self.assertIsNone(gate.validate_sbom(layered, IMAGE_ID, self.expected))
        duplicated_layer = copy.deepcopy(layered)
        duplicated_layer["metadata"]["component"]["properties"].append(
            copy.deepcopy(duplicated_layer["metadata"]["component"]["properties"][-1]))
        self.rejects_report("sbom.cdx.json", duplicated_layer, "sbom")
        duplicated_image = copy.deepcopy(original)
        duplicated_image["metadata"]["component"]["properties"].append(
            copy.deepcopy(duplicated_image["metadata"]["component"]["properties"][0]))
        self.rejects_report("sbom.cdx.json", duplicated_image, "sbom")
        report = copy.deepcopy(original)
        report["metadata"]["component"]["properties"][0]["value"] = BROWSER_IMAGE_ID
        self.rejects_report("sbom.cdx.json", report, "sbom")
        report = copy.deepcopy(original)
        report["components"][0]["purl"] = "pkg:deb/debian/other@1.0-1"
        self.rejects_report("sbom.cdx.json", report, "sbom")

    def test_sbom_schema_and_component_fields_are_strict(self):
        original = read_json(self.reports / "sbom.cdx.json")
        for field, value in (("bomFormat", "SPDX"), ("specVersion", "1.0"), ("version", True), ("version", "1")):
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("sbom.cdx.json", report, "sbom")
        for field, value in (("name", "wrong"), ("version", "0.0.0"), ("type", "application"), ("type", None)):
            with self.subTest(component_field=field, value=value):
                report = copy.deepcopy(original)
                report["components"][0][field] = value
                self.rejects_report("sbom.cdx.json", report, "sbom")

    def test_test_counts_reject_bool_strings_failures_and_omissions(self):
        original = read_json(self.reports / "test-summary.json")
        for field in ("tests_run", "failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
            for value in (True, "0", None, -1):
                with self.subTest(field=field, value=value):
                    report = copy.deepcopy(original)
                    report["tests"][field] = value
                    self.rejects_report("test-summary.json", report, "tests_coverage")
        for field in ("failures", "errors", "skipped", "expected_failures", "unexpected_successes"):
            report = copy.deepcopy(original)
            report["tests"][field] = 1
            self.rejects_report("test-summary.json", report, "tests_coverage")

    def test_native_check_status_cannot_hide_nonzero_or_wrong_type_exit(self):
        original = read_json(self.reports / "test-summary.json")
        for name in ("pip_check", "runtime", "media", "presentation", "branding"):
            for value in (1, False, "0", None):
                with self.subTest(check=name, returncode=value):
                    report = copy.deepcopy(original)
                    next(item for item in report["checks"] if item["name"] == name)["returncode"] = value
                    self.rejects_report("test-summary.json", report, "tests_coverage")
        report = copy.deepcopy(original)
        report["checks"][0]["error_type"] = "SyntheticError"
        self.rejects_report("test-summary.json", report, "tests_coverage")
        report = copy.deepcopy(original)
        report["checks"].pop()
        self.rejects_report("test-summary.json", report, "tests_coverage")

    def test_test_ids_and_hash_must_match_the_executed_inventory(self):
        original = read_json(self.reports / "test-summary.json")
        for field, value in (("ids", []), ("unique", True), ("discovered", 2),
                             ("duplicate_ids", ["synthetic"]), ("sha256_utf8_lf", "f" * 64)):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report["test_inventory"][field] = value
                self.rejects_report("test-summary.json", report, "tests_coverage")

    def test_coverage_scope_counters_and_percentages_must_agree(self):
        original = read_json(self.reports / "coverage/coverage.json")
        report = copy.deepcopy(original)
        report["files"].pop(next(iter(report["files"])))
        self.rejects_report("coverage/coverage.json", report, "tests_coverage")
        for field, value in (("num_statements", True), ("covered_lines", 999), ("excluded_lines", 1),
                             ("covered_branches", "1"), ("percent_covered", 99.0)):
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report["totals"][field] = value
                self.rejects_report("coverage/coverage.json", report, "tests_coverage")
        report = copy.deepcopy(original)
        next(iter(report["files"].values()))["summary"]["covered_lines"] = 2
        self.rejects_report("coverage/coverage.json", report, "tests_coverage")

    def test_coverage_summary_cannot_claim_unmeasured_or_omitted_sources(self):
        original = read_json(self.reports / "test-summary.json")
        for field, value in (("measured", "true"), ("branch", 1), ("omit", ["scripts/*"]),
                             ("source", ["app"]), ("percent_covered", 99.0)):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report["coverage"][field] = value
                self.rejects_report("test-summary.json", report, "tests_coverage")

    def test_missing_or_empty_coverage_xml_is_rejected(self):
        path = self.reports / "coverage/coverage.xml"
        path.write_text("", encoding="utf-8")
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(error["control"] == "coverage_xml" for error in result["errors"]))
        path.unlink()
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")

    def test_browser_requires_six_completed_scenarios_and_separate_transports(self):
        original = read_json(self.reports / "browser/browser-summary.json")
        for field, value in (("bridge_allowed", True), ("exit_code", False), ("direct_http_scenarios_passed", "5")):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("browser/browser-summary.json", report, "browser")
        report = copy.deepcopy(original)
        report["scenarios"].pop()
        self.rejects_report("browser/browser-summary.json", report, "browser")
        for field, value in (("returncode", False), ("timed_out", True), ("bridge_detected", True),
                             ("reported_steps", 0), ("transport", "direct_http")):
            with self.subTest(scenario_field=field):
                report = copy.deepcopy(original)
                report["scenarios"][0][field] = value
                self.rejects_report("browser/browser-summary.json", report, "browser")

    def test_browser_prerequisites_and_toolchain_cannot_be_missing(self):
        original = read_json(self.reports / "browser/browser-summary.json")
        for field, value in (("checks", []), ("toolchain", {})):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("browser/browser-summary.json", report, "browser")
        report = copy.deepcopy(original)
        report["checks"][0]["error_type"] = "SyntheticLaunchError"
        self.rejects_report("browser/browser-summary.json", report, "browser")
        report = copy.deepcopy(original)
        report["toolchain"]["chromium_version"] = True
        self.rejects_report("browser/browser-summary.json", report, "browser")

    def test_browser_scenario_must_identify_the_expected_script(self):
        report = read_json(self.reports / "browser/browser-summary.json")
        report["scenarios"][0]["script"] = "different_synthetic_script.py"
        self.rejects_report("browser/browser-summary.json", report, "browser")

    def test_gitleaks_findings_and_non_array_results_are_rejected(self):
        for report in ({}, False, "", [{"Description": "SYNTHETIC secret finding, no secret value"}]):
            with self.subTest(report=report):
                self.rejects_report("gitleaks-source.json", report, "gitleaks")

    def test_actionlint_schema_exits_and_rejection_probe_are_strict(self):
        original = read_json(self.reports / "actionlint-summary.json")
        for field, value in (("schema_version", True), ("version", "other"), ("workflow_exit", False),
                             ("invalid_fixture_exit", "1"), ("invalid_fixture_rejected", 1),
                             ("workflow_sha256", "f" * 64)):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("actionlint-summary.json", report, "actionlint")

    def test_missing_workflow_record_and_null_hash_cannot_compare_equal(self):
        source_scan = read_json(self.reports / "source-scan-manifest.json")
        source_scan["files"] = [row for row in source_scan["files"] if row["path"] != ".github/workflows/ci.yml"]
        write_json(self.reports / "source-scan-manifest.json", source_scan)
        actionlint = read_json(self.reports / "actionlint-summary.json")
        actionlint["workflow_sha256"] = None
        write_json(self.reports / "actionlint-summary.json", actionlint)
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(error["control"] == "actionlint" for error in result["errors"]))

    def test_source_scan_must_cover_context_without_unsafe_paths(self):
        original = read_json(self.reports / "source-scan-manifest.json")
        for mutation in ("omit", "traversal"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "omit":
                    report["files"].pop(next(i for i, row in enumerate(report["files"]) if row["path"].startswith("app/")))
                else:
                    report["files"][0]["path"] = "../private-fixture.py"
                write_json(self.reports / "source-scan-manifest.json", report)
                exit_code, result = self.cli_result()
                self.assertEqual(exit_code, 1)
                self.assertEqual(result["status"], "failed")

    def test_context_hash_drift_is_rejected_without_repair(self):
        path = self.context / "app/main.py"
        changed = path.read_bytes() + b"# authored fixture drift\n"
        path.write_bytes(changed)
        exit_code, result = self.cli_result()
        self.assertEqual(exit_code, 1)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(path.read_bytes(), changed)

    def test_duplicate_json_keys_nonfinite_numbers_and_empty_reports_fail(self):
        for content in ('{"results": [], "results": []}', '{"value": NaN}', '{"value": Infinity}', ""):
            with self.subTest(content=content):
                path = self.root / "synthetic-invalid-report.json"
                path.write_text(content, encoding="utf-8")
                with self.assertRaises(gate.ValidationError):
                    gate.load(path)

    def test_database_version_timestamps_and_hash_are_required(self):
        original = read_json(self.reports / "trivy-db-metadata.json")
        for field, value in (("Version", True), ("Version", "2"), ("UpdatedAt", "2026-11-10T00:00:00"),
                             ("DownloadedAt", None), ("NextUpdate", "not-a-date")):
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("trivy-db-metadata.json", report, "trivy_database")
        (self.reports / "trivy-db.sha256").write_text("not-a-hash\n", encoding="utf-8")
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")

    def test_dpkg_parser_preserves_versions_and_skips_noninstalled_records(self):
        status = ("Package: zlib1g\nStatus: install ok installed\nVersion: 1:1.3-2\n"
                  "Description: fixture\n continuation is not a new field\n\n"
                  "Package: removed-fixture\nStatus: deinstall ok config-files\nVersion: 0.0\n\n"
                  "Package: ffmpeg\nStatus: install ok installed\nVersion: 7:7.1.5-0+deb13u1\n")
        self.assertEqual(capture.debian_packages(status), [
            {"Name": "ffmpeg", "Version": "7:7.1.5-0+deb13u1"},
            {"Name": "zlib1g", "Version": "1:1.3-2"},
        ])

    def test_capture_uses_only_supplied_fixtures_and_mocked_package_metadata(self):
        status = self.root / "synthetic-dpkg-status.txt"
        status.write_text("Package: ffmpeg\nStatus: install ok installed\nVersion: 1.0-1\n", encoding="utf-8")
        release = self.root / "synthetic-debian-version.txt"
        release.write_text("13.7\n", encoding="utf-8")
        node = self.root / "synthetic-playwright-package.json"
        write_json(node, {"name": "playwright-core", "version": "1.0.0"})
        distribution = SimpleNamespace(metadata={"Name": "Synthetic_Package"}, version="1.2.3")
        driver = SimpleNamespace(locate_file=lambda name: node)
        with patch.object(capture.importlib.metadata, "distributions", return_value=[distribution]) as packages, \
                patch.object(capture.importlib.metadata, "distribution", return_value=driver) as playwright:
            inventory = capture.capture(IMAGE_ID, root=self.context, status=status, release=release)
            packages.assert_called_once_with()
            playwright.assert_called_once_with("playwright")
        self.assertEqual(inventory["image_id"], IMAGE_ID)
        self.assertEqual(inventory["os"], {"family": "debian", "name": "13.7"})
        self.assertEqual(inventory["targets"][1]["Packages"], [{"Name": "synthetic-package", "Version": "1.2.3"}])
        self.assertEqual(inventory["targets"][2]["Packages"], [{"Name": "playwright-core", "Version": "1.0.0"}])
        self.assertEqual({row["path"]: row for row in inventory["python_sources"]}, self.sources)
        with patch.object(capture.importlib.metadata, "distributions") as packages:
            with self.assertRaises(ValueError):
                capture.capture("invalid-id", root=self.context, status=status, release=release)
            packages.assert_not_called()


if __name__ == "__main__":
    unittest.main()
