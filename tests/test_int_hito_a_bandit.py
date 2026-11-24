from copy import deepcopy
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from scripts import int_hito_a_bandit as policy


NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


class HitoABanditPolicyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        snapshot = Path("/ci-results/hito-a-policy-fixture")
        cls.root = snapshot if snapshot.is_dir() else Path(__file__).resolve().parents[1]
        cls.temporary = tempfile.TemporaryDirectory(prefix="clipforge-hito-a-bandit-")
        cls.work = Path(cls.temporary.name)
        cls.native = cls.work / "bandit.json"
        result = subprocess.run(
            [sys.executable, "-B", "-m", "bandit", "-r", "app", "scripts",
             "--severity-level", "all", "--confidence-level", "all", "--ignore-nosec",
             "--format", "json", "--output", str(cls.native)],
            cwd=cls.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=60, check=False,
        )
        if result.returncode != 1:
            raise AssertionError("Bandit native finding exit was not retained")
        cls.report = json.loads(cls.native.read_text(encoding="utf-8"))
        cls.report["generated_at"] = "2026-11-25T11:59:00Z"
        version = subprocess.run(
            [sys.executable, "-B", "-m", "bandit", "--version"],
            cwd=cls.root, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, timeout=15, check=False,
        )
        if version.returncode != 0:
            raise AssertionError("Bandit version command failed")
        cls.version = cls.work / "bandit-version.txt"
        cls.version.write_bytes(version.stdout)
        cls.policy = cls.root / "config/int-hito-a-bandit-acceptance.json"
        cls.environ = {
            "GITHUB_ACTIONS": "true",
            "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
            "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
            "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_WORKFLOW_REF": policy.WORKFLOW_REF,
            "GITHUB_JOB": "api",
            "RUNNER_ENVIRONMENT": "github-hosted",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_SHA": "a" * 40,
            "INT_APPROVED_COMMIT": "a" * 40,
            "INT_BANDIT_POLICY_SCOPE": "int-hito-a",
        }

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def report_file(self, value):
        path = self.work / ("report-" + os.urandom(8).hex() + ".json")
        path.write_text(json.dumps(value), encoding="utf-8")
        return path

    def evaluate(self, report=None, *, version=None, policy_path=None, environ=None, now=NOW):
        value = deepcopy(self.report if report is None else report)
        return policy.evaluate(
            self.report_file(value), version or self.version,
            policy_path or self.policy, root=self.root,
            environ=self.environ if environ is None else environ, now=now,
        )

    def adjust_level(self, report, index, kind, replacement):
        finding = report["results"][index]
        field = "issue_" + kind.lower()
        previous = finding[field]
        finding[field] = replacement
        name = finding["filename"]
        report["metrics"][name][f"{kind}.{previous}"] -= 1
        report["metrics"][name][f"{kind}.{replacement}"] += 1
        report["metrics"]["_totals"][f"{kind}.{previous}"] -= 1
        report["metrics"]["_totals"][f"{kind}.{replacement}"] += 1

    def test_exact_historical_and_reviewed_multiset_passes_with_native_report_retained(self):
        receipt = self.evaluate()
        self.assertEqual(receipt["status"], "passed_with_int_exception")
        self.assertEqual(receipt["baseline_findings"], 142)
        self.assertEqual(receipt["reviewed_additions"], 12)
        self.assertEqual(receipt["total_findings"], 154)
        self.assertEqual(receipt["severity"], {"LOW": 136, "MEDIUM": 18, "HIGH": 0})
        self.assertFalse(receipt["production_exception"])

    def test_new_unreviewed_low_finding_is_blocked_by_identity_and_multiplicity(self):
        report = deepcopy(self.report)
        added = deepcopy(report["results"][0])
        report["results"].append(added)
        name = added["filename"]
        severity = added["issue_severity"]
        confidence = added["issue_confidence"]
        report["metrics"][name][f"SEVERITY.{severity}"] += 1
        report["metrics"][name][f"CONFIDENCE.{confidence}"] += 1
        report["metrics"]["_totals"][f"SEVERITY.{severity}"] += 1
        report["metrics"]["_totals"][f"CONFIDENCE.{confidence}"] += 1
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_unreviewed_finding"):
            self.evaluate(report)

    def test_malformed_native_json_is_blocked_without_a_receipt(self):
        malformed = self.work / ("malformed-" + os.urandom(8).hex() + ".json")
        malformed.write_text('{"errors":[]', encoding="utf-8")
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_invalid_json"):
            policy.evaluate(
                malformed, self.version, self.policy, root=self.root,
                environ=self.environ, now=NOW,
            )

    def test_new_medium_and_high_findings_remain_blocking(self):
        for level, code in (("MEDIUM", "bandit_unreviewed_finding"),
                            ("HIGH", "bandit_high_finding")):
            report = deepcopy(self.report)
            index = next(i for i, row in enumerate(report["results"])
                         if row["issue_severity"] == "LOW")
            self.adjust_level(report, index, "SEVERITY", level)
            with self.subTest(level=level), self.assertRaisesRegex(policy.BanditPolicyError, code):
                self.evaluate(report)

    def test_scanner_error_and_incomplete_inventory_are_blocked(self):
        errored = deepcopy(self.report)
        errored["errors"] = [{"filename": "withheld", "reason": "scanner error"}]
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_report_shape"):
            self.evaluate(errored)
        incomplete = deepcopy(self.report)
        name = next(name for name in incomplete["metrics"] if name != "_totals")
        del incomplete["metrics"][name]
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_source_inventory"):
            self.evaluate(incomplete)

    def test_wrong_scanner_version_and_expired_policy_are_blocked(self):
        version = self.work / ("wrong-version-" + os.urandom(4).hex() + ".txt")
        version.write_text("__main__.py 1.9.5\n  python version = fixture\n", encoding="utf-8")
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_version"):
            self.evaluate(version=version)
        expired = deepcopy(self.report)
        expired["generated_at"] = "2026-12-24T23:59:00Z"
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_policy_expired"):
            self.evaluate(expired, now=datetime(2026, 12, 25, tzinfo=timezone.utc))

    def test_source_change_requires_review_even_when_finding_identity_is_unchanged(self):
        value = json.loads(self.policy.read_text(encoding="utf-8"))
        target = value["baseline_findings"][0]["path"]
        for group in ("baseline_findings", "reviewed_additions"):
            for row in value[group]:
                if row["path"] == target:
                    row["source_sha256"] = "0" * 64
        changed = self.work / ("changed-policy-" + os.urandom(4).hex() + ".json")
        changed.write_text(json.dumps(value), encoding="utf-8")
        with self.assertRaisesRegex(policy.BanditPolicyError, "bandit_accepted_source_changed"):
            self.evaluate(policy_path=changed)

    def test_exception_cannot_be_used_by_production_or_another_workflow(self):
        for changed in (
            {**self.environ, "GITHUB_REF": "refs/heads/main"},
            {**self.environ, "GITHUB_WORKFLOW_REF":
                "AldemaroCruz/ClipForge/.github/workflows/prod.yml@refs/heads/main"},
            {**self.environ, "INT_BANDIT_POLICY_SCOPE": "prod"},
        ):
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    policy.BanditPolicyError, "bandit_int_context"):
                self.evaluate(environ=changed)


if __name__ == "__main__":
    unittest.main()
