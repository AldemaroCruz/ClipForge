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
from scripts import gitleaks_policy as policy
try:  # CI discovery imports test modules directly; local module launches use the namespace package.
    from test_gitleaks_policy import fixture_policy_bytes
except ModuleNotFoundError:
    from tests.test_gitleaks_policy import fixture_policy_bytes


SYNTHETIC = "SYNTHETIC FIXTURE ONLY: no scanner or real security acceptance"
IMAGE_ID = "sha256:" + "1" * 64
BROWSER_IMAGE_ID = "sha256:" + "2" * 64
POSTGRES_IMAGE_ID = "sha256:" + "3" * 64
PACKAGES = {
    "debian": [{"Name": name, "Version": "1.0-1"} for name in
               ("ffmpeg", "fonts-dejavu-core", "libxml2", "zlib1g")],
    "python-pkg": [{"Name": name, "Version": "1.0.0"} for name in (
        "av", "bandit", "coverage", "fastapi", "faster-whisper", "pip",
        "playwright", "python-multipart", "starlette",
    )],
    "node-pkg": [{"Name": "playwright-core", "Version": "1.0.0"}],
}
POSTGRES_PACKAGES = {"debian": [
    {"Name": name, "Version": version, "Architecture": "amd64", "Source": name, "SourceVersion": version}
    for name, version in (("postgresql-18", "18.6-1.pgdg13+2"), ("libc6", "2.41-12"))
]}
GOSU_MODULES = [
    {"Name": "github.com/tianon/gosu", "Version": "v1.19.0", "Checksum": ""},
    {"Name": "github.com/moby/sys/user", "Version": "v0.1.0", "Checksum": "h1:" + "A" * 43 + "="},
    {"Name": "golang.org/x/sys", "Version": "v0.1.0", "Checksum": "h1:" + "B" * 43 + "="},
]
POSTGRES_PACKAGES["gobinary"] = [{"Name": item["Name"], "Version": item["Version"]} for item in GOSU_MODULES]
POSTGRES_PACKAGES["gobinary"].append({"Name": "stdlib", "Version": "v1.24.6"})
SCENARIOS = ("smoke", "workflow", "editorial", "delivery", "ai", "operations")
AUTH_SCENARIO_STEPS = ("login", "admin_create_user", "independent_sessions", "process_restart",
                       "password_revocation", "admin_deactivation", "logout_mobile")
RECOVERY_SCENARIO_STEPS = ("recovery_admin_reauthentication", "recovery_issue", "recovery_replace",
                           "recovery_process_restart", "recovery_consume", "recovery_session_revocation",
                           "recovery_single_use", "recovery_audit_privacy")


def write_json(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def purl(kind, package):
    head = {"debian": "pkg:deb/debian/", "python-pkg": "pkg:pypi/", "node-pkg": "pkg:npm/", "gobinary": "pkg:golang/"}[kind]
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
    (source / ".gitleaks.toml").write_bytes(fixture_policy_bytes())
    tracked = sorted([record["path"] for record in context_manifest["files"]]
                     + [".github/workflows/ci.yml", ".gitleaks.toml"])
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
    write_json(reports / "browser-auth/browser-auth-summary.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "status": "passed", "exit_code": 0,
        "timed_out": False, "script": "browser_auth.py", "transport": "direct_http", "postgresql": "real",
        "auth_mocked": False, "process_restart": True, "external_network": False,
        "image_id": BROWSER_IMAGE_ID, "postgres_image_id": POSTGRES_IMAGE_ID,
        "context_manifest_sha256": hashlib.sha256((reports / "context-manifest.json").read_bytes()).hexdigest(),
        "steps": 7, "details": [{"id": name, "status": "passed", "detail": SYNTHETIC + ": " + name}
                                 for name in AUTH_SCENARIO_STEPS],
    })
    # This strict-shape recovery report is schema-fixture data, not browser execution evidence.
    write_json(reports / "browser-auth-recovery/browser-auth-recovery-summary.json", {
        "schema_version": 1, "status": "passed", "exit_code": 0, "timed_out": False,
        "script": "browser_auth_recovery.py", "transport": "direct_http", "postgresql": "real",
        "auth_mocked": False, "process_restart": True, "external_network": False,
        "image_id": BROWSER_IMAGE_ID, "postgres_image_id": POSTGRES_IMAGE_ID,
        "context_manifest_sha256": hashlib.sha256((reports / "context-manifest.json").read_bytes()).hexdigest(),
        "toolchain": {"playwright_version": "1.64.1", "chromium_version": "156.0.8078.4",
                      "chromium_revision": "1248", "system": "Linux", "machine": "x86_64"},
        "steps": 8, "details": [{"id": name, "status": "passed"} for name in RECOVERY_SCENARIO_STEPS],
    })
    (reports / "browser-auth-recovery/FIXTURE-ONLY.txt").write_text(SYNTHETIC + "\n", encoding="utf-8")
    write_json(reports / "gitleaks-source.json", [])
    write_json(reports / "actionlint-summary.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "version": "1.7.12",
        "workflow_exit": 0, "invalid_fixture_exit": 1, "invalid_fixture_rejected": True,
        "workflow_sha256": workflow_sha,
    })
    (reports / "actionlint-version.txt").write_text("actionlint 1.7.12 — " + SYNTHETIC + "\n", encoding="utf-8")
    for prefix, image_id in (("", IMAGE_ID), ("browser-", BROWSER_IMAGE_ID), ("postgres-", POSTGRES_IMAGE_ID)):
        (reports / (prefix + "image-id.txt")).write_text(image_id + "\n", encoding="utf-8")
        (reports / (prefix + "image-archive.sha256")).write_text(("a" if not prefix else "b") * 64 + "\n", encoding="utf-8")
        inventory = {
            "synthetic_fixture": SYNTHETIC, "schema_version": 1, "image_id": image_id, "source_root": "/app",
            "os": {"family": "debian", "name": "13.7"}, "python_sources": sources,
            "targets": [{"Class": gate.TARGETS[kind], "Type": kind, "Packages": copy.deepcopy(packages)}
                        for kind, packages in PACKAGES.items()],
        }
        packages_by_kind = PACKAGES
        if prefix == "postgres-":
            packages_by_kind = POSTGRES_PACKAGES
            (reports / "postgres-image-ref.txt").write_text(gate.POSTGRES_IMAGE + "\n", encoding="utf-8")
            inventory = {
                "synthetic_fixture": SYNTHETIC, "schema_version": 1,
                "schema": "clipforge-postgres-image-inventory-1", "image_id": image_id, "image_config_id": image_id,
                "image_reference": gate.POSTGRES_IMAGE, "platform": {"os": "linux", "architecture": "amd64"},
                "os": {"family": "debian", "name": "13.7", "id": "debian", "version_id": "13"},
                "targets": [{"Class": "os-pkgs", "Type": "debian", "Packages": copy.deepcopy(POSTGRES_PACKAGES["debian"])},
                            {"Class": "lang-pkgs", "Type": "gobinary", "Target": "usr/local/bin/gosu",
                             "Packages": copy.deepcopy(POSTGRES_PACKAGES["gobinary"])}],
                "go_binaries": [{"path": "/usr/local/bin/gosu", "resolved_path": "/usr/local/bin/gosu",
                    "sha256": "7" * 64, "bytes": 100, "uid": 0, "gid": 0, "mode": "0o755",
                    "version": "1.19 (go1.24.6 on linux/amd64; gc)", "go_version": "go1.24.6",
                    "main_path": "github.com/tianon/gosu", "main_module": copy.deepcopy(GOSU_MODULES[0]),
                    "dependencies": copy.deepcopy(GOSU_MODULES[1:]), "build_settings": {"GOOS": "linux", "GOARCH": "amd64"},
                    "build_info_sha256": "8" * 64, "module_info_sha256": "9" * 64,
                    "packages": copy.deepcopy(POSTGRES_PACKAGES["gobinary"])}],
                "dpkg": {"status_path": "/var/lib/dpkg/status", "status_sha256": "d" * 64,
                         "status_bytes": 100, "installed_package_count": 2},
                "postgres": {"version": "postgres (PostgreSQL) 18.6 (Debian 18.6-1.pgdg13+2)",
                    "version_number": "18.6", "package_owned": True,
                    "package": {"Name": "postgresql-18", "Version": "18.6-1.pgdg13+2"},
                    "binary": {"path": "/usr/lib/postgresql/18/bin/postgres", "resolved_path": "/usr/lib/postgresql/18/bin/postgres",
                               "sha256": "e" * 64, "bytes": 100, "uid": 0, "gid": 0, "mode": "0o755"},
                    "package_file_list": {"path": "/var/lib/dpkg/info/postgresql-18.list", "sha256": "f" * 64, "bytes": 100}},
            }
        write_json(reports / (prefix + "image-inventory.json"), inventory)
        artifact = "synthetic-" + (prefix.rstrip("-") if prefix else "ci") + "-fixture"
        targets = []
        components = []
        for kind, packages in packages_by_kind.items():
            trivy_packages = []
            for package in packages:
                package_purl = purl(kind, package)
                item = {**package, "Identifier": {"PURL": package_purl}}
                if kind == "debian":
                    version, release = package["Version"].rsplit("-", 1)
                    item.update(Version=version, Release=release, Epoch=0)
                trivy_packages.append(item)
                components.append({"type": "library", "name": package["Name"],
                                   "version": package["Version"], "purl": package_purl})
            targets.append({"Class": gate.SCANNER_TARGETS[kind], "Type": kind,
                            "Target": {"debian": artifact + " (debian 13.7)",
                                       "python-pkg": "Python", "node-pkg": "Node.js", "gobinary": "usr/local/bin/gosu"}[kind],
                            "Packages": trivy_packages, "Vulnerabilities": []})
        write_json(reports / ("trivy-postgres.json" if prefix == "postgres-" else prefix + "trivy-high-critical.json"), {
            "synthetic_fixture": SYNTHETIC, "SchemaVersion": 2, "ArtifactType": "container_image",
            "ArtifactName": artifact, "Metadata": {"ImageID": image_id, "OS": {"Family": "debian", "Name": "13.7"}},
            "Results": targets,
        })
        if prefix == "postgres-":
            components.append({"type": "application", "name": "usr/local/bin/gosu", "bom-ref": "synthetic-gosu-target",
                               "properties": [{"name": "aquasecurity:trivy:Class", "value": "lang-pkgs"},
                                              {"name": "aquasecurity:trivy:Type", "value": "gobinary"}]})
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
    write_json(reports / "trivy-postgres-execution.json", {
        "synthetic_fixture": SYNTHETIC, "schema_version": 1, "image_id": POSTGRES_IMAGE_ID,
        "exit_code": 0, "sbom_exit_code": 0, "status": "passed",
    })
    run_key, nonce = "synthetic-workflow-run", "9" * 32
    prefix = "clipforge-ci-auth-" + hashlib.sha256(run_key.encode()).hexdigest()[:12] + "-" + nonce[:12]
    write_json(reports / "postgres-isolation.json", {
        "synthetic_fixture": SYNTHETIC, "schema": "clipforge-ci-postgres-isolation-1", "status": "passed",
        "run_key": run_key, "nonce": nonce, "prefix": prefix, "postgres_image_ref": gate.POSTGRES_IMAGE,
        "postgres_image_id": POSTGRES_IMAGE_ID, "ci_image_id": IMAGE_ID,
        "postgres": {"id": "4" * 64, "name": prefix + "-postgres", "published_ports": False},
        "network": {"id": "5" * 64, "name": prefix + "-network", "internal": True, "ipv6": False},
        "probe": {"status": "passed", "database": "reachable", "database_role": "clipforge_ci",
                  "superuser": False, "createdb": False, "uid_gid": "10001:10001",
                  "external_tcp_probes": [{"endpoint": ["1.1.1.1", 443], "connection": "blocked"},
                                          {"endpoint": ["8.8.8.8", 53], "connection": "blocked"}],
                  "default_ipv4_route": False, "no_new_privileges": True, "capabilities": "zero"},
        "checked_utc": "2026-11-10T00:00:00Z", "report": "synthetic-attempt/check",
    })
    write_json(reports / "postgres-cleanup.json", {
        "synthetic_fixture": SYNTHETIC, "schema": "clipforge-ci-postgres-cleanup-1", "status": "clean",
        "run_key": run_key, "nonce": nonce, "prefix": prefix, "ownership_verified": True,
        "containers_removed": [prefix + "-postgres", prefix + "-browser-auth-1234abcd"], "networks_removed": [prefix + "-network"],
        "private_files_removed": ["postgres-password", "database-password", "initialize.sql"],
        "remaining_container_ids": [], "remaining_network_ids": [], "private_files_remaining": [],
        "checked_utc": "2026-11-10T00:01:00Z", "report": "synthetic-attempt/cleanup",
    })
    (reports / "gitleaks-version.txt").write_text("8.30.1\n", encoding="utf-8")
    policy.record_execution(config=root / "scan/.gitleaks.toml",
        source_manifest=reports / "source-scan-manifest.json", raw_report=reports / "gitleaks-source.json",
        raw_exit=0, scanner_image=policy.GITLEAKS_IMAGE, version_file=reports / "gitleaks-version.txt",
        policy_copy=reports / "gitleaks-policy.toml", output=reports / "gitleaks-execution.json")
    precision_cases = [
        ("approved", 1, 0, []),
        ("same_file_other_secret", 2, 1, ["generic-api-key"]),
        ("changed_value", 1, 1, ["generic-api-key"]),
        ("other_path", 1, 1, ["generic-api-key"]),
        ("other_rule", 2, 1, ["github-pat"]),
        ("same_line_other_secret", 2, 2, ["generic-api-key"]),
        ("changed_identifier", 1, 1, ["generic-api-key"]),
        ("nested_path", 1, 1, ["generic-api-key"]),
        ("approved_after_prelude", 1, 0, []),
        ("approved_full_file", 1, 0, []),
        ("same_file_secret_before", 2, 1, ["generic-api-key"]),
        ("same_line_prefix", 2, 2, ["generic-api-key"]),
    ]
    write_json(reports / "gitleaks-precision.json", {
        "schema_version": 1, "status": "passed", "scanner_image": policy.GITLEAKS_IMAGE,
        "scanner_version": policy.GITLEAKS_VERSION, "policy_sha256": policy.POLICY_SHA256,
        "synthetic_only": True, "external_network": False,
        "cases": [{"id": name, "status": "passed", "default_exit": 1, "configured_exit": int(after > 0),
                   "default_findings": before, "configured_findings": after,
                   "removed_only_approved": True, "remaining_rules": rules}
                  for name, before, after, rules in precision_cases],
    })
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

    def test_postgres_inventory_accepts_its_own_complete_os_scope_without_application_packages(self):
        inventory = read_json(self.reports / "postgres-image-inventory.json")
        targets, os_info = gate.validate_postgres_inventory(inventory, POSTGRES_IMAGE_ID, gate.POSTGRES_IMAGE)
        self.assertEqual(set(targets), {"debian", "gobinary"})
        self.assertNotIn("ffmpeg", {name for name, _ in targets["debian"]})
        self.assertIsNone(gate.validate_trivy(read_json(self.reports / "trivy-postgres.json"),
                                             POSTGRES_IMAGE_ID, targets, os_info))
        self.assertIsNone(gate.validate_sbom(read_json(self.reports / "postgres-sbom.cdx.json"),
                                            POSTGRES_IMAGE_ID, targets))

    def test_postgres_reports_and_identity_files_are_mandatory(self):
        for relative, control in [("postgres-image-id.txt", "postgres_image_inventory"),
                                  ("postgres-image-ref.txt", "postgres_image_inventory"),
                                  ("postgres-image-archive.sha256", "postgres_image_inventory"),
                                  ("postgres-image-inventory.json", "postgres_image_inventory"),
                                  ("trivy-postgres-execution.json", "postgres_trivy_execution"),
                                  ("trivy-postgres.json", "postgres_trivy"),
                                  ("postgres-sbom.cdx.json", "postgres_sbom")]:
            path = self.reports / relative
            original = path.read_bytes()
            try:
                with self.subTest(report=relative):
                    path.unlink()
                    result = gate.validate_reports(self.reports, self.context)
                    self.assertEqual(result["status"], "failed")
                    self.assertTrue(any(error["control"] == control for error in result["errors"]), result)
            finally:
                path.write_bytes(original)

    def test_postgres_inventory_requires_pinned_identity_platform_and_complete_package_count(self):
        original = read_json(self.reports / "postgres-image-inventory.json")
        mutations = [("schema_version", True), ("schema", "unrelated"), ("image_id", IMAGE_ID),
                     ("image_config_id", IMAGE_ID), ("image_reference", "postgres:latest"),
                     ("platform", {"os": "linux", "architecture": "arm64"}),
                     ("os", {"family": "ubuntu", "id": "ubuntu", "version_id": "13", "name": "13.7"})]
        for field, value in mutations:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")
        for field, value in [("installed_package_count", 1), ("installed_package_count", True),
                             ("status_bytes", 0), ("status_sha256", "missing"), ("status_path", "/other")]:
            with self.subTest(dpkg_field=field):
                report = copy.deepcopy(original)
                report["dpkg"][field] = value
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")

    def test_postgres_inventory_cannot_hide_unowned_or_changed_runtime(self):
        original = read_json(self.reports / "postgres-image-inventory.json")
        for field, value in [("package_owned", False), ("package_owned", 1), ("version_number", "18.5"),
                             ("version", "postgres (PostgreSQL) 18.5"),
                             ("package", {"Name": "source-built-postgres", "Version": "18.6"})]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report["postgres"][field] = value
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")
        for field, value in [("path", "/tmp/postgres"), ("resolved_path", "/tmp/postgres"), ("sha256", None),
                             ("bytes", 0), ("uid", 1000), ("gid", True), ("mode", "0o777")]:
            with self.subTest(binary_field=field):
                report = copy.deepcopy(original)
                report["postgres"]["binary"][field] = value
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")
        report = copy.deepcopy(original)
        report["postgres"]["package_file_list"] = {}
        self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")

    def test_postgres_inventory_targets_cannot_omit_packages_or_invent_application_targets(self):
        original = read_json(self.reports / "postgres-image-inventory.json")
        for mutation in ("no-target", "duplicate-target", "python-target", "no-postgres-package", "partial-package"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "no-target":
                    report["targets"] = []
                elif mutation == "duplicate-target":
                    report["targets"].append(copy.deepcopy(report["targets"][0]))
                elif mutation == "python-target":
                    report["targets"][0]["Type"] = "python-pkg"
                elif mutation == "no-postgres-package":
                    report["targets"][0]["Packages"].pop(0)
                    report["dpkg"]["installed_package_count"] = 1
                else:
                    del report["targets"][0]["Packages"][0]["SourceVersion"]
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")

    def test_postgres_inventory_cannot_hide_bundled_gosu_main_dependencies_or_toolchain(self):
        original = read_json(self.reports / "postgres-image-inventory.json")
        for mutation in ("no-binary", "no-target", "no-dependency", "no-stdlib", "wrong-target"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "no-binary":
                    report["go_binaries"] = []
                elif mutation == "no-target":
                    report["targets"].pop()
                elif mutation == "no-dependency":
                    report["go_binaries"][0]["dependencies"].pop()
                elif mutation == "no-stdlib":
                    report["targets"][1]["Packages"].pop()
                else:
                    report["targets"][1]["Target"] = "unknown-gobinary"
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")

    def test_postgres_gosu_build_metadata_and_binary_identity_cannot_be_changed(self):
        original = read_json(self.reports / "postgres-image-inventory.json")
        for field, value in [("path", "/tmp/gosu"), ("resolved_path", "/tmp/gosu"), ("sha256", None),
                             ("uid", 1000), ("gid", True), ("mode", "0o777"), ("bytes", 0),
                             ("version", "1.18"), ("go_version", "go1.24.7"), ("build_info_sha256", None),
                             ("module_info_sha256", "invalid"), ("main_path", "unknown/module"),
                             ("build_settings", {"GOOS": "linux", "GOARCH": "arm64"})]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report["go_binaries"][0][field] = value
                self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")
        report = copy.deepcopy(original)
        report["go_binaries"][0]["dependencies"][0]["Checksum"] = ""
        self.rejects_report("postgres-image-inventory.json", report, "postgres_image_inventory")

    def test_postgres_trivy_must_cover_bundled_gosu_and_exact_go_versions(self):
        original = read_json(self.reports / "trivy-postgres.json")
        for mutation in ("no-target", "no-module", "version", "purl", "unexpected-target"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "no-target":
                    report["Results"].pop()
                elif mutation == "no-module":
                    report["Results"][1]["Packages"].pop()
                elif mutation == "version":
                    report["Results"][1]["Packages"][0]["Version"] = "v0.0.0"
                elif mutation == "purl":
                    report["Results"][1]["Packages"][0]["Identifier"]["PURL"] = "pkg:golang/other@v1.19.0"
                else:
                    report["Results"][1]["Target"] = "usr/local/bin/another-binary"
                self.rejects_report("trivy-postgres.json", report, "postgres_trivy")

    def test_postgres_sbom_must_cover_bundled_go_modules_and_toolchain(self):
        report = read_json(self.reports / "postgres-sbom.cdx.json")
        report["components"] = [item for item in report["components"] if not item.get("purl", "").startswith("pkg:golang/")]
        self.rejects_report("postgres-sbom.cdx.json", report, "postgres_sbom")

    def test_postgres_sbom_requires_unique_known_go_binary_target_and_all_module_libraries(self):
        original = read_json(self.reports / "postgres-sbom.cdx.json")
        for mutation in ("missing", "duplicate", "unknown", "invalid-class", "package-as-target"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                aggregate = report["components"][-1]
                if mutation == "missing":
                    report["components"].pop()
                elif mutation == "duplicate":
                    report["components"].append(copy.deepcopy(aggregate))
                elif mutation == "unknown":
                    aggregate["name"] = "usr/local/bin/uninventoried"
                elif mutation == "invalid-class":
                    aggregate["properties"][0]["value"] = "os-pkgs"
                else:
                    report["components"][0]["type"] = "application"
                self.rejects_report("postgres-sbom.cdx.json", report, "postgres_sbom")

    def test_postgres_trivy_requires_full_independent_scope_and_matching_image(self):
        original = read_json(self.reports / "trivy-postgres.json")
        for mutation in ("no-results", "missing-package", "duplicate-target", "wrong-image", "scanner-error"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "no-results":
                    report["Results"] = []
                elif mutation == "missing-package":
                    report["Results"][0]["Packages"].pop()
                elif mutation == "duplicate-target":
                    report["Results"].append(copy.deepcopy(report["Results"][0]))
                elif mutation == "wrong-image":
                    report["Metadata"]["ImageID"] = IMAGE_ID
                else:
                    report["Error"] = None
                self.rejects_report("trivy-postgres.json", report, "postgres_trivy")

    def test_postgres_sbom_and_high_critical_findings_remain_blocking(self):
        sbom = read_json(self.reports / "postgres-sbom.cdx.json")
        sbom["components"].pop()
        self.rejects_report("postgres-sbom.cdx.json", sbom, "postgres_sbom")
        original = read_json(self.reports / "trivy-postgres.json")
        for severity in ("HIGH", "CRITICAL"):
            with self.subTest(severity=severity):
                report = copy.deepcopy(original)
                report["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2099-0001-SYNTHETIC",
                                                          "PkgName": "postgresql-18", "Severity": severity}]
                self.rejects_report("trivy-postgres.json", report, "postgres_trivy")

    def test_postgres_scanner_execution_cannot_be_failed_or_contradict_its_report(self):
        original = read_json(self.reports / "trivy-postgres-execution.json")
        for field, value in [("schema_version", True), ("image_id", IMAGE_ID), ("exit_code", False),
                             ("exit_code", 2), ("exit_code", 1), ("status", "execution_failed"),
                             ("sbom_exit_code", 1), ("sbom_exit_code", False), ("errors", [])]:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("trivy-postgres-execution.json", report, "postgres_trivy_execution")
        report = copy.deepcopy(original)
        report.update(exit_code=1, status="security_findings")
        self.rejects_report("trivy-postgres-execution.json", report, "postgres_trivy_execution")

    def test_postgres_security_findings_and_execution_failures_have_distinct_categories(self):
        trivy = read_json(self.reports / "trivy-postgres.json")
        changed = copy.deepcopy(trivy)
        changed["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2099-0001-SYNTHETIC",
                                                    "PkgName": "postgresql-18", "Severity": "HIGH"}]
        write_json(self.reports / "trivy-postgres.json", changed)
        execution = read_json(self.reports / "trivy-postgres-execution.json")
        execution.update(exit_code=1, status="security_findings")
        write_json(self.reports / "trivy-postgres-execution.json", execution)
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertEqual([(item["control"], item["category"]) for item in result["errors"]],
                         [("postgres_trivy", "security_finding")])
        write_json(self.reports / "trivy-postgres.json", trivy)
        execution.update(exit_code=2, status="execution_failed")
        write_json(self.reports / "trivy-postgres-execution.json", execution)
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertEqual([(item["control"], item["category"]) for item in result["errors"]],
                         [("postgres_trivy_execution", "evidence_error")])

    def test_postgres_isolation_and_cleanup_evidence_are_mandatory(self):
        for relative, control in [("postgres-isolation.json", "postgres_isolation"),
                                  ("postgres-cleanup.json", "postgres_cleanup")]:
            path = self.reports / relative
            original = path.read_bytes()
            try:
                with self.subTest(report=relative):
                    path.unlink()
                    result = gate.validate_reports(self.reports, self.context)
                    self.assertEqual(result["status"], "failed")
                    self.assertTrue(any(error["control"] == control for error in result["errors"]), result)
            finally:
                path.write_bytes(original)

    def test_postgres_isolation_binds_own_resources_to_both_images_and_run(self):
        original = read_json(self.reports / "postgres-isolation.json")
        for field, value in [("status", "failed"), ("schema", "other"), ("run_key", "other-run"),
                             ("nonce", "7" * 32), ("prefix", "operational-service"),
                             ("postgres_image_ref", "postgres:latest"), ("ci_image_id", BROWSER_IMAGE_ID),
                             ("postgres_image_id", IMAGE_ID), ("checked_utc", "2026-11-10T00:00:00"), ("errors", [])]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("postgres-isolation.json", report, "postgres_isolation")
        for resource, field, value in [("postgres", "id", "unknown"), ("postgres", "name", "operational"),
                                       ("postgres", "published_ports", True), ("network", "internal", False),
                                       ("network", "internal", 1), ("network", "ipv6", True),
                                       ("network", "name", "other-network")]:
            with self.subTest(resource=resource, field=field):
                report = copy.deepcopy(original)
                report[resource][field] = value
                self.rejects_report("postgres-isolation.json", report, "postgres_isolation")

    def test_postgres_probe_requires_real_db_least_privilege_and_both_blocked_egress_checks(self):
        original = read_json(self.reports / "postgres-isolation.json")
        for field, value in [("status", "failed"), ("database", "unreachable"), ("database_role", "postgres"),
                             ("superuser", True), ("createdb", True), ("uid_gid", "0:0"),
                             ("default_ipv4_route", True), ("no_new_privileges", False), ("capabilities", "nonzero"),
                             ("external_tcp_probes", []), ("errors", [])]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report["probe"][field] = value
                self.rejects_report("postgres-isolation.json", report, "postgres_isolation")
        for mutation in ("reachable", "duplicate", "missing"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                probes = report["probe"]["external_tcp_probes"]
                if mutation == "reachable":
                    probes[0]["connection"] = "connected"
                elif mutation == "duplicate":
                    probes[1] = copy.deepcopy(probes[0])
                else:
                    probes.pop()
                self.rejects_report("postgres-isolation.json", report, "postgres_isolation")

    def test_postgres_cleanup_requires_same_run_subsequent_timestamp_and_no_remaining_resources(self):
        original = read_json(self.reports / "postgres-cleanup.json")
        for field, value in [("status", "failed"), ("ownership_verified", False), ("ownership_verified", 1),
                             ("run_key", "another-run"), ("checked_utc", "2026-11-09T00:00:00Z"),
                             ("remaining_container_ids", ["a" * 64]), ("remaining_network_ids", ["b" * 64]),
                             ("private_files_remaining", ["database-password"]),
                             ("containers_removed", ["operational-service"]), ("networks_removed", ["default"]),
                             ("private_files_removed", ["unrelated-file"]), ("errors", [])]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("postgres-cleanup.json", report, "postgres_cleanup")

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

    def test_auth_browser_report_is_mandatory(self):
        (self.reports / "browser-auth/browser-auth-summary.json").unlink()
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertTrue(any(error["control"] == "browser_auth" for error in result["errors"]))

    def test_auth_browser_rejects_failed_simulated_or_external_execution(self):
        original = read_json(self.reports / "browser-auth/browser-auth-summary.json")
        mutations = [("schema_version", True), ("status", "failed"), ("exit_code", 1), ("exit_code", False),
                     ("timed_out", True), ("script", "browser_smoke.py"), ("transport", "simulated_fetch"),
                     ("postgresql", "mocked"), ("auth_mocked", True), ("auth_mocked", 0),
                     ("process_restart", False), ("external_network", True), ("external_network", 0),
                     ("errors", [])]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("browser-auth/browser-auth-summary.json", report, "browser_auth")

    def test_auth_browser_requires_seven_unique_completed_detailed_steps(self):
        original = read_json(self.reports / "browser-auth/browser-auth-summary.json")
        for field, value in [("steps", 6), ("steps", True), ("details", []), ("details", None)]:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("browser-auth/browser-auth-summary.json", report, "browser_auth")
        for mutation in ("missing", "duplicate", "wrong", "failed", "empty", "repeated-detail", "error"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                steps = report["details"]
                if mutation == "missing":
                    steps.pop()
                elif mutation == "duplicate":
                    steps.append(copy.deepcopy(steps[0]))
                elif mutation == "wrong":
                    steps[0]["id"] = "unrelated"
                elif mutation == "failed":
                    steps[0]["status"] = "failed"
                elif mutation == "empty":
                    steps[0]["detail"] = " "
                elif mutation == "repeated-detail":
                    steps[0]["detail"] = steps[1]["detail"]
                else:
                    steps[0]["error"] = None
                self.rejects_report("browser-auth/browser-auth-summary.json", report, "browser_auth")

    def test_auth_browser_binds_both_images_and_exact_context_manifest(self):
        original = read_json(self.reports / "browser-auth/browser-auth-summary.json")
        for field, value in [("image_id", IMAGE_ID), ("postgres_image_id", IMAGE_ID),
                             ("context_manifest_sha256", "f" * 64), ("context_manifest_sha256", None)]:
            with self.subTest(field=field):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report("browser-auth/browser-auth-summary.json", report, "browser_auth")

    def test_auth_browser_does_not_replace_historical_scenarios(self):
        report = read_json(self.reports / "browser/browser-summary.json")
        report["scenarios"] = report["scenarios"][:-1]
        self.rejects_report("browser/browser-summary.json", report, "browser")

    def test_recovery_browser_report_is_independently_mandatory(self):
        (self.reports / "browser-auth-recovery/browser-auth-recovery-summary.json").unlink()
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual(result["status"], "failed")
        self.assertEqual([(error["control"], error["category"]) for error in result["errors"]],
                         [("browser_auth_recovery", "evidence_error")])

    def test_recovery_browser_requires_every_field_and_strict_public_types(self):
        path = "browser-auth-recovery/browser-auth-recovery-summary.json"
        original = read_json(self.reports / path)
        for field in original:
            with self.subTest(missing=field):
                report = copy.deepcopy(original)
                del report[field]
                self.rejects_report(path, report, "browser_auth_recovery")
        mutations = [("schema_version", True), ("status", "failed"), ("exit_code", 1), ("exit_code", False),
                     ("timed_out", True), ("timed_out", 0), ("script", "browser_auth.py"),
                     ("transport", "simulated_fetch"), ("postgresql", "mocked"),
                     ("process_restart", False), ("process_restart", 1), ("auth_mocked", True),
                     ("auth_mocked", 0), ("external_network", True), ("external_network", 0),
                     ("steps", 7), ("steps", True), ("details", []), ("details", None),
                     ("toolchain", False), ("errors", []), ("simulated", True),
                     ("synthetic_fixture", SYNTHETIC), ("recovery_code", "DO_NOT_EXPORT_FIXTURE")]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report(path, report, "browser_auth_recovery")

    def test_recovery_browser_requires_eight_unique_private_safe_step_records(self):
        path = "browser-auth-recovery/browser-auth-recovery-summary.json"
        original = read_json(self.reports / path)
        self.assertTrue(set(RECOVERY_SCENARIO_STEPS).isdisjoint(AUTH_SCENARIO_STEPS))
        for mutation in ("missing", "duplicate", "auth7", "failed", "extra", "wrongtype", "nondict"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                steps = report["details"]
                if mutation == "missing":
                    steps.pop()
                elif mutation == "duplicate":
                    steps.append(copy.deepcopy(steps[0]))
                elif mutation == "auth7":
                    steps[0]["id"] = AUTH_SCENARIO_STEPS[0]
                elif mutation == "failed":
                    steps[0]["status"] = "failed"
                elif mutation == "extra":
                    steps[0]["detail"] = "DO_NOT_EXPORT_FIXTURE"
                elif mutation == "wrongtype":
                    steps[0]["id"] = True
                else:
                    steps[0] = "not a step record"
                self.rejects_report(path, report, "browser_auth_recovery")

    def test_recovery_browser_binds_both_images_and_exact_context_manifest(self):
        path = "browser-auth-recovery/browser-auth-recovery-summary.json"
        original = read_json(self.reports / path)
        for field, value in [("image_id", IMAGE_ID), ("image_id", True),
                             ("postgres_image_id", IMAGE_ID), ("postgres_image_id", None),
                             ("context_manifest_sha256", "f" * 64), ("context_manifest_sha256", False)]:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report[field] = value
                self.rejects_report(path, report, "browser_auth_recovery")

    def test_recovery_browser_requires_complete_linux_toolchain_without_private_paths(self):
        path = "browser-auth-recovery/browser-auth-recovery-summary.json"
        original = read_json(self.reports / path)
        for field in original["toolchain"]:
            with self.subTest(missing=field):
                report = copy.deepcopy(original)
                del report["toolchain"][field]
                self.rejects_report(path, report, "browser_auth_recovery")
        for field, value in [("playwright_version", 1), ("chromium_version", " "),
                             ("system", "Windows"), ("machine", "arm64"),
                             ("executable", "/private/fixture/chromium")]:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original)
                report["toolchain"][field] = value
                self.rejects_report(path, report, "browser_auth_recovery")

    def test_recovery_browser_does_not_replace_auth7_or_historical_scenarios(self):
        for path, control in [("browser-auth/browser-auth-summary.json", "browser_auth"),
                              ("browser/browser-summary.json", "browser")]:
            with self.subTest(path=path):
                original = read_json(self.reports / path)
                (self.reports / path).unlink()
                try:
                    result = gate.validate_reports(self.reports, self.context)
                    self.assertEqual([(error["control"], error["category"]) for error in result["errors"]],
                                     [(control, "evidence_error")])
                finally:
                    write_json(self.reports / path, original)

    def test_gitleaks_findings_and_non_array_results_are_rejected(self):
        for report in ({}, False, "", [{"Description": "SYNTHETIC secret finding, no secret value"}]):
            with self.subTest(report=report):
                self.rejects_report("gitleaks-source.json", report, "gitleaks")

    def test_gitleaks_requires_separate_policy_execution_and_precision_evidence(self):
        self.assertFalse((self.context / ".gitleaks.toml").exists())
        self.assertEqual(policy.validate_policy(self.reports / "gitleaks-policy.toml")["sha256"], policy.POLICY_SHA256)
        for name, control in (("gitleaks-policy.toml", "gitleaks_execution"),
                              ("gitleaks-execution.json", "gitleaks_execution"),
                              ("gitleaks-version.txt", "gitleaks_execution"),
                              ("gitleaks-precision.json", "gitleaks_precision")):
            with self.subTest(name=name):
                raw = (self.reports / name).read_bytes()
                (self.reports / name).unlink()
                try:
                    result = gate.validate_reports(self.reports, self.context)
                    self.assertEqual([(error["control"], error["category"]) for error in result["errors"]],
                                     [(control, "evidence_error")])
                finally:
                    (self.reports / name).write_bytes(raw)

    def test_gitleaks_execution_rejects_missing_forged_or_wrong_typed_metadata(self):
        path = "gitleaks-execution.json"
        original = read_json(self.reports / path)
        for field in original:
            with self.subTest(missing=field):
                report = copy.deepcopy(original); del report[field]
                self.rejects_report(path, report, "gitleaks_execution")
        for field, value in [("schema_version", True), ("status", "error"), ("raw_exit_code", 1),
                             ("raw_exit_code", False), ("raw_exit_code", 125),
                             ("policy_sha256", "f" * 64), ("source_manifest_sha256", "f" * 64),
                             ("raw_report_sha256", "f" * 64), ("scanner_image", "latest"),
                             ("scanner_version", "8.30.0"), ("findings_count", False), ("errors", {})]:
            with self.subTest(field=field, value=value):
                report = copy.deepcopy(original); report[field] = value
                self.rejects_report(path, report, "gitleaks_execution")

    def test_gitleaks_modified_policy_flags_cannot_keep_passing_receipts(self):
        path = self.reports / "gitleaks-policy.toml"
        original = path.read_bytes()
        for modified in (original + b"\n", original.replace(b"useDefault = true", b"useDefault = false"),
                         original.replace(b'condition = "AND"', b'condition = "OR"')):
            with self.subTest(policy_hash=hashlib.sha256(modified).hexdigest()):
                path.write_bytes(modified)
                result = gate.validate_reports(self.reports, self.context)
                self.assertTrue(any(error["control"] == "gitleaks_execution"
                                    and error["category"] == "evidence_error" for error in result["errors"]))

    def test_gitleaks_unclassified_findings_stay_blocking_with_consistent_execution(self):
        write_json(self.reports / "gitleaks-source.json", [{"RuleID": "unclassified-fixture", "Secret": "REDACTED"}])
        execution = read_json(self.reports / "gitleaks-execution.json")
        execution.update(status="security_findings", raw_exit_code=1, findings_count=1,
                         raw_report_sha256=hashlib.sha256((self.reports / "gitleaks-source.json").read_bytes()).hexdigest())
        write_json(self.reports / "gitleaks-execution.json", execution)
        result = gate.validate_reports(self.reports, self.context)
        self.assertEqual([(error["control"], error["category"]) for error in result["errors"]],
                         [("gitleaks", "security_finding")])
        execution["raw_exit_code"] = 0
        write_json(self.reports / "gitleaks-execution.json", execution)
        result = gate.validate_reports(self.reports, self.context)
        self.assertTrue(any(error["control"] == "gitleaks_execution"
                            and error["category"] == "evidence_error" for error in result["errors"]))
        self.assertTrue(any(error["control"] == "gitleaks" and error["category"] == "security_finding"
                            for error in result["errors"]))

    def test_gitleaks_precision_rejects_missing_cases_wrong_identity_and_relaxed_results(self):
        path = "gitleaks-precision.json"
        original = read_json(self.reports / path)
        for field, value in [("schema_version", True), ("status", "failed"),
                             ("policy_sha256", "f" * 64), ("scanner_image", "latest"),
                             ("scanner_version", "8.30.0"), ("synthetic_only", False),
                             ("external_network", True), ("cases", [])]:
            with self.subTest(field=field):
                report = copy.deepcopy(original); report[field] = value
                self.rejects_report(path, report, "gitleaks_precision")
        for mutation in ("missing", "duplicate", "exit", "count", "classification", "other_rule", "boolean",
                         "old_first_line_only", "framing_drops_unrelated", "prefix_classified"):
            with self.subTest(mutation=mutation):
                report = copy.deepcopy(original)
                if mutation == "missing": report["cases"].pop()
                elif mutation == "duplicate": report["cases"].append(copy.deepcopy(report["cases"][0]))
                elif mutation == "exit": report["cases"][0]["configured_exit"] = 1
                elif mutation == "count": report["cases"][0]["configured_findings"] = 1
                elif mutation == "classification": report["cases"][0]["removed_only_approved"] = False
                elif mutation == "boolean": report["cases"][0]["default_exit"] = True
                elif mutation == "old_first_line_only": report["cases"] = report["cases"][:8]
                elif mutation == "framing_drops_unrelated":
                    next(c for c in report["cases"] if c["id"] == "same_file_secret_before")["configured_findings"] = 0
                elif mutation == "prefix_classified":
                    next(c for c in report["cases"] if c["id"] == "same_line_prefix")["configured_findings"] = 1
                else: next(c for c in report["cases"] if c["id"] == "other_rule")["remaining_rules"] = []
                self.rejects_report(path, report, "gitleaks_precision")

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

    def test_capture_keeps_cloud_package_and_media_child_hashes_for_both_images(self):
        cloud = self.context / "app/cloud"
        cloud.mkdir(parents=True, exist_ok=True)
        cloud_files = ("__init__.py", "config.py", "repository.py", "router.py", "storage.py", "dispatch.py",
                       "migrate.py", "bootstrap_admin.py", "worker.py")
        expected = dict(self.sources)
        for relative in ["app/cloud/" + name for name in cloud_files] + ["app/media_child.py"]:
            path = self.context / relative
            data = ("CAPTURE_SOURCE_FIXTURE = " + repr(relative) + "\n").encode()
            path.write_bytes(data)
            expected[relative] = {"path": relative, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()}
        nested = cloud / "unlisted"
        nested.mkdir()
        (nested / "excluded.py").write_text("UNLISTED_FIXTURE = True\n")
        (cloud / "excluded.json").write_text('{"fixture": true}')
        status, release, node = (self.root / name for name in ("capture-dpkg.txt", "capture-debian.txt", "capture-playwright.json"))
        status.write_text("\n\n".join("Package: " + package["Name"] + "\nStatus: install ok installed\nVersion: " + package["Version"]
                                     for package in PACKAGES["debian"]) + "\n")
        release.write_text("13.7\n")
        write_json(node, {"name": "playwright-core", "version": "1.0.0"})
        distributions = [SimpleNamespace(metadata={"Name": package["Name"]}, version=package["Version"])
                         for package in PACKAGES["python-pkg"]]
        driver = SimpleNamespace(locate_file=lambda name: node)
        for image_id in (IMAGE_ID, BROWSER_IMAGE_ID):
            with self.subTest(image_id=image_id), patch.object(capture.importlib.metadata, "distributions", return_value=distributions), \
                    patch.object(capture.importlib.metadata, "distribution", return_value=driver):
                inventory = capture.capture(image_id, root=self.context, status=status, release=release)
            self.assertEqual({row["path"]: row for row in inventory["python_sources"]}, expected)
            gate.validate_inventory(inventory, image_id, expected)
            incomplete = copy.deepcopy(inventory)
            incomplete["python_sources"] = [row for row in incomplete["python_sources"] if row["path"] != "app/cloud/__init__.py"]
            with self.assertRaises(gate.ValidationError):
                gate.validate_inventory(incomplete, image_id, expected)


if __name__ == "__main__":
    unittest.main()
