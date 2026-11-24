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

    def test_clean_scans_remain_review_only(self):
        with tempfile.TemporaryDirectory() as scratch:
            work = Path(scratch)
            reports = work / "reports"
            reports.mkdir()
            package, version = "test-package", "1.2.3"
            observer.write_json(reports / "host-observed.json", {"run": "42", "commit": "a" * 40, "boot_id": "fixture",
                                "facts": {"kernel": {"packages": []}},
                                "os_scan_packages": [[package, version, package, version]]})
            observer.write_json(reports / "trivy-db-receipt.json", {"test": True})
            native = {"SchemaVersion": 2, "Results": [{"Target": "fixture", "Packages": [{"Name": package, "Version": version}]}]}
            for report in ("trivy-os.json", "trivy-app-metadata.json"):
                observer.write_json(reports / report, native)
            with patch.object(observer, "verify_context"):
                self.assertEqual(observer.summarize({}, work, "success"), 0)
            summary = observer.read_json(reports / "host-result.json")
            self.assertEqual(summary["status"], "host_observed_review_required")
            self.assertFalse(summary["activation_authorized"])
            self.assertIn("owner_dispositions", summary["known_scope_gaps"])

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
