"""Exercise the credential-free APT observation, without native GitHub or cloud access."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import yaml

from scripts import int_demo_a_db_observe as observer


ROOT = Path(__file__).resolve().parents[1]


class AptRunnerObservationTests(unittest.TestCase):
    def test_workflow_prepares_exact_actions_without_federation_or_int(self):
        workflow = (ROOT / observer.WORKFLOW).read_text(encoding="utf-8")
        document = yaml.load(workflow, Loader=yaml.BaseLoader)
        self.assertEqual(set(document["on"]), {"workflow_dispatch"})
        jobs = document["jobs"]
        self.assertEqual(set(jobs), {observer.JOB})
        job = jobs[observer.JOB]
        self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(job["permissions"], {"contents": "read"})
        self.assertIn("github.event_name == 'workflow_dispatch'", job["if"])
        self.assertNotIn("environment", job)
        self.assertNotIn("secrets.", workflow)
        actions = {step["uses"]: step for step in job["steps"] if "uses" in step}
        self.assertEqual(set(actions), {ref for ref, _ in observer.db.ACTIONS.values()})
        self.assertEqual(actions[observer.db.ACTIONS["setup_gcloud"][0]]["with"], {"version": "582.0.0"})
        for name in ("download_artifact", "google_auth"):
            stage = actions[observer.db.ACTIONS[name][0]]
            self.assertEqual(stage["if"], "github.event_name == 'repository_dispatch'")
            self.assertNotIn("with", stage)

    def test_credentials_stop_before_ambient_reads(self):
        for key in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL", "GCP_ACCESS_TOKEN",
                    "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_OAUTH_ACCESS_TOKEN"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "admission_requires_no_secret_inputs|has_credentials"):
                observer.verify_context({key: "fixture"}, Path("not-used"))

    def test_stage_dpkg_records_native_release_bytes_and_only_selected_packages(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            host = work / "host"
            releases = {"etc/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n# native bytes\n',
                        "etc/lsb-release": b'DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=24.04\nDISTRIB_CODENAME=noble\n'}
            dpkg = "var/lib/dpkg/status"
            selected = b"Package: selected\nStatus: install ok installed\nArchitecture: amd64\nVersion: 1:1.2-3\n\n"
            ignored = selected.replace(b"Package: selected", b"Package: unrelated")
            for name, data in {**releases, dpkg: selected + ignored}.items():
                path = host / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(data)
            stage = work / "staged"
            identities = observer.stage_dpkg(stage, {"selected:amd64"}, host_root=host)
            self.assertEqual(set(identities), {*releases, dpkg})
            for name, original in {**releases, dpkg: selected}.items():
                self.assertEqual((stage / name).read_bytes(), original)
                self.assertEqual(identities[name], {"sha256": sha256(original).hexdigest(), "bytes": len(original)})
            lsb = host / "etc/lsb-release"
            lsb.unlink()
            with self.assertRaises(FileNotFoundError):
                observer.stage_dpkg(work / "missing", {"selected:amd64"}, host_root=host)
            lsb.write_bytes(b"DISTRIB_ID=Ubuntu\nDISTRIB_RELEASE=22.04\n")
            with self.assertRaisesRegex(ValueError, "apt_observation_os_identity_mismatch"):
                observer.stage_dpkg(work / "wrong", {"selected:amd64"}, host_root=host)

    def test_collect_records_exact_os_inputs_and_observation_scope(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            (work / "reports").mkdir()
            component_root = work / "components"
            paths = {}
            for role in observer.db.tool_names(observer.OPERATION):
                if role.startswith("action_"):
                    action = role.removeprefix("action_")
                    _, entries = observer.db.ACTIONS[action]
                    files = {leaf: component_root / role / leaf for leaf in ("action.yml", *entries)}
                else:
                    files = {"file": component_root / role}
                for path in files.values():
                    path.parent.mkdir(parents=True, exist_ok=True)
                    path.write_bytes(b"fixture")
                paths[role] = files
            inventory = [["ca-certificates", "1", "ca-certificates", "1"],
                         ["linux-image-7.0.0-1017-azure", "2", "linux-signed-azure-7.0", "2"],
                         ["linux-modules-7.0.0-1017-azure", "2", "linux-azure-7.0", "2"]]
            tools = dict.fromkeys(observer.db.tool_names(observer.OPERATION), "a" * 64)
            facts = {"tools": tools, "kernel": {"packages": inventory[1:]}}
            os_inputs = {name: {"sha256": character * 64, "bytes": index}
                         for index, (name, character) in enumerate((
                             ("etc/os-release", "b"), ("etc/lsb-release", "c"),
                             ("var/lib/dpkg/status", "d")), start=1)}
            with patch.object(observer, "verify_context", return_value=work), \
                    patch.object(observer.common, "package_inventory", return_value=inventory), \
                    patch.object(observer.db, "live_facts", return_value=(facts, "fixture-boot")), \
                    patch.object(observer.db, "runner_component_paths", return_value=paths), \
                    patch.object(observer.common, "file_identity", return_value={"sha256": "a" * 64, "bytes": 7}), \
                    patch.object(observer.common, "digest", return_value="a" * 64), \
                    patch.object(observer, "linked_libraries", return_value=([], [])), \
                    patch.object(observer, "local_command", return_value=(0, '{"node":"24"}')), \
                    patch.object(observer, "stage_dpkg", return_value=os_inputs), \
                    patch.object(observer, "stage_metadata", return_value={"package.json": "e" * 64}):
                observer.collect({"GITHUB_RUN_ID": "42", "GITHUB_SHA": "f" * 40}, work)
            scan_inputs = observer.read_json(work / "reports/scan-inputs.json")
            measured = observer.read_json(work / "reports/host-observed.json")
            self.assertEqual(scan_inputs["native_os_input_files"], os_inputs)
            self.assertEqual(measured["operation"], observer.OBSERVATION)
            self.assertEqual(measured["measurement_scope"], observer.OPERATION)
            self.assertEqual(measured["applicable_operations"], list(observer.APPLICABLE_OPERATIONS))

    def test_native_threshold_and_missing_application_report_remain_distinct(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            reports = work / "reports"
            reports.mkdir()
            package, version = "linux-modules-7.0.0-1014-aws", "7.0.0-1014.14~24.04.1"
            observed = {"run": "42", "commit": "a" * 40, "boot_id": "fixture",
                        "os_scan_packages": [[package, version, "linux-aws-7.0", version]],
                        "facts": {"kernel": {"packages": [[package, version, "linux-aws-7.0", version]]}}}
            result = {"PkgName": package, "InstalledVersion": version, "Severity": "HIGH",
                      "VulnerabilityID": "CVE-2026-90292", "FixedVersion": "7.0.0-1017.18~24.04.1"}
            native = {"SchemaVersion": 2, "Results": [{"Target": "fixture-os", "Vulnerabilities": [result],
                                                       "Packages": [{"Name": package, "Version": version}]}]}
            observer.write_json(reports / "host-observed.json", observed)
            observer.write_json(reports / "trivy-os.json", native)
            with patch.object(observer, "verify_context"):
                self.assertEqual(observer.summarize({}, work, "failure"), 1)
            summary = observer.read_json(reports / "host-result.json")
            self.assertFalse(summary["activation_authorized"])
            self.assertEqual(summary["status"], "host_rejected")
            self.assertEqual(summary["first_os_blocker"]["VulnerabilityID"], result["VulnerabilityID"])
            self.assertEqual(observer.read_json(reports / "trivy-os.json"), native)
            self.assertIn("native_scan_incomplete", summary["known_scope_gaps"])
            self.assertIn("native_os_identity_mismatch", summary["known_scope_gaps"])

    def test_clean_scans_remain_review_only(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            reports = work / "reports"
            reports.mkdir()
            package, version = "test-package:amd64", "1:1.2.3-1ubuntu2"
            observer.write_json(reports / "host-observed.json", {"run": "42", "commit": "a" * 40, "boot_id": "fixture",
                                "facts": {"kernel": {"packages": []}},
                                "os_scan_packages": [[package, version, "test-source", "1:1.2.3-1ubuntu1"]]})
            observer.write_json(reports / "trivy-db-receipt.json", {"test": True})
            native = {"SchemaVersion": 2, "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
                      "Results": [{"Target": "fixture", "Class": "os-pkgs", "Type": "ubuntu",
                                   "Packages": [{"Name": "test-package", "Arch": "amd64", "Version": "1.2.3",
                                                 "Epoch": 1, "Release": "1ubuntu2", "SrcName": "test-source",
                                                 "SrcVersion": "1.2.3", "SrcEpoch": 1, "SrcRelease": "1ubuntu1"}]}]}
            observer.write_json(reports / "trivy-os.json", native)
            observer.write_json(reports / "trivy-app-metadata.json", {
                "SchemaVersion": 2, "Results": [{"Target": "fixture-lock", "Class": "lang-pkgs", "Type": "npm",
                                                  "Packages": [{"Name": "fixture-library", "Version": "4.5.6"}]}]})
            with patch.object(observer, "verify_context"):
                self.assertEqual(observer.summarize({}, work, "success"), 0)
            summary = observer.read_json(reports / "host-result.json")
            self.assertEqual(summary["status"], "host_observed_review_required")
            self.assertFalse(summary["activation_authorized"])
            self.assertEqual(summary["operation"], observer.OBSERVATION)
            self.assertEqual(summary["measurement_scope"], observer.OPERATION)
            self.assertEqual(summary["applicable_operations"], list(observer.APPLICABLE_OPERATIONS))
            self.assertIn("owner_dispositions", summary["known_scope_gaps"])
            self.assertTrue(summary["native_os_coverage"]["inventory_match"])

            os_report = reports / "trivy-os.json"
            for label, modified in {
                "wrong_os": {**native, "Metadata": {"OS": {"Family": "none", "Name": ""}}},
                "missing_target": {**native, "Results": []},
                "wrong_type": {**native, "Results": [{**native["Results"][0], "Type": "debian"}]},
                "no_packages": {**native, "Results": [{**native["Results"][0], "Packages": []}]},
                "wrong_source": {**native, "Results": [{**native["Results"][0], "Packages": [
                    {**native["Results"][0]["Packages"][0], "SrcRelease": "1ubuntu9"}]}]},
                "wrong_arch": {**native, "Results": [{**native["Results"][0], "Packages": [
                    {**native["Results"][0]["Packages"][0], "Arch": "arm64"}]}]},
            }.items():
                with self.subTest(label=label):
                    os_report.write_text(json.dumps(modified), encoding="utf-8")
                    (reports / "host-result.json").unlink()
                    with patch.object(observer, "verify_context"):
                        self.assertEqual(observer.summarize({}, work, "success"), 1)
                    blocked = observer.read_json(reports / "host-result.json")
                    self.assertEqual(blocked["status"], "host_observation_blocked")
                    self.assertEqual(blocked["reason"], "native_scan_coverage_incomplete")

            os_report.unlink()
            (reports / "host-result.json").unlink()
            with patch.object(observer, "verify_context"):
                self.assertEqual(observer.summarize({}, work, "success"), 1)
            self.assertIn("trivy-os.json", observer.read_json(reports / "host-result.json")["known_scope_gaps"])

    def test_later_measurement_failure_keeps_the_host_projection(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            reports = work / "reports"
            reports.mkdir()
            measured = {"facts": {"tools": {name: "a" * 64 for name in observer.db.tool_names(observer.OPERATION)}}}
            observer.write_json(reports / "host-facts.json", measured)
            with patch.object(observer, "verify_context"):
                self.assertEqual(observer.summarize({}, work, "skipped"), 1)
            self.assertEqual(observer.read_json(reports / "host-facts.json"), measured)
            self.assertEqual(observer.read_json(reports / "host-result.json")["reason"], "dependency_measurement_missing")

    def test_database_receipt_binds_native_bytes_and_expires(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            cache = work / "cache/db"
            cache.mkdir(parents=True)
            (work / "reports").mkdir()
            raw = b"synthetic database"
            (cache / "trivy.db").write_bytes(raw)
            future = datetime.now(timezone.utc) + timedelta(hours=1)
            (cache / "metadata.json").write_text(json.dumps({"Version": 2, "NextUpdate": future.isoformat()}), encoding="utf-8")
            observer.database_receipt(work, "sha256:" + "b" * 64)
            report = observer.read_json(work / "reports/trivy-db-receipt.json")
            self.assertEqual(report["database"], {"sha256": sha256(raw).hexdigest(), "bytes": len(raw)})
            expired = future - timedelta(hours=2)
            (cache / "metadata.json").write_text(json.dumps({"Version": 2, "NextUpdate": expired.isoformat()}), encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "apt_observation_scanner_db_expired"):
                observer.database_receipt(work, "sha256:" + "b" * 64)


if __name__ == "__main__":
    unittest.main()
