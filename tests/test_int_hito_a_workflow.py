from pathlib import Path
import re
import unittest

import yaml


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/int-hito-a.yml"
LEGACY_MUTATORS = {
    "int-db01-noble-apply.yml",
    "int-db01-noble-bootstrap.yml",
    "int-db01-noble-intervention.yml",
    "int-db01-noble-jobs.yml",
    "int-demo-a-apply.yml",
    "int-demo-a-publish.yml",
    "int-demo-a-secrets.yml",
    "int-e2e-apply.yml",
    "int-e2e-bootstrap-db.yml",
    "int-e2e-jobs.yml",
    "int-e2e-runtime.yml",
    "int-e2e-secrets.yml",
    "int-foundation-close.yml",
    "int-foundation-recovery-apply.yml",
}


class HitoAWorkflowTests(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")
        self.value = yaml.load(self.source, Loader=yaml.BaseLoader)

    def test_exactly_three_standard_runner_jobs_and_one_protected_deploy(self):
        jobs = self.value["jobs"]
        self.assertEqual(set(jobs), {"frontend", "api", "deploy"})
        for job in jobs.values():
            self.assertEqual(job["runs-on"], "ubuntu-24.04")
        self.assertEqual(jobs["deploy"]["needs"], ["frontend", "api"])
        self.assertEqual(jobs["deploy"]["environment"], "int")
        self.assertNotIn("environment", jobs["frontend"])
        self.assertNotIn("environment", jobs["api"])
        self.assertEqual(jobs["deploy"]["permissions"]["id-token"], "write")
        self.assertNotIn("id-token", jobs["frontend"]["permissions"])
        self.assertNotIn("id-token", jobs["api"]["permissions"])

    def test_unprotected_jobs_have_no_int_credentials_and_api_owns_real_gates(self):
        jobs = self.value["jobs"]
        for name in ("frontend", "api"):
            rendered = yaml.dump(jobs[name])
            self.assertNotIn("secrets.", rendered)
            self.assertNotIn("GCP_WIF_PROVIDER", rendered)
            self.assertNotIn("google-github-actions/auth", rendered)
        api = yaml.dump(jobs["api"])
        for marker in ("scripts/ci_postgres.py migrate", "scripts/run_ci_tests.py",
                       "python -m bandit", "runtime-trivy.json", "runtime.oci.tar",
                       "--list-all-pkgs"):
            self.assertIn(marker, api)
        self.assertIn("python -B -m scripts.int_hito_a_scan verify", self.source)
        deploy = yaml.dump(jobs["deploy"])
        self.assertIn("google-github-actions/auth", deploy)
        self.assertIn("secrets.INT_BOOTSTRAP_ADMIN_JSON", deploy)
        self.assertNotIn("GH_TOKEN", deploy)
        self.assertIn("INT_IAP_ACCESS_TOKEN", deploy)
        self.assertNotIn("INT_IAP_ID_TOKEN", deploy)
        self.assertIn("api-demo-browser.json", deploy)
        self.assertIn("scripts/prepare_ci_scan.py", api)
        self.assertIn("gitleaks_policy.py record", api)
        self.assertRegex(api, r"moby/buildkit:v0\.35\.1@sha256:[a-f0-9]{64}")

    def test_one_candidate_is_reused_by_digest_for_service_jobs_and_acceptance(self):
        self.assertEqual(self.source.count("docker buildx build"), 1)
        self.assertIn("RUNTIME_IMAGE: ${{ needs.api.outputs.runtime_image }}", self.source)
        self.assertIn("python -B -m scripts.int_hito_a_delivery verify-artifact", self.source)
        self.assertIn("python -B -m scripts.int_hito_a_delivery replace", self.source)
        self.assertRegex(self.source, r"(?s)steps\.replace\.outcome != 'skipped'.*int_hito_a_delivery rollback")
        rollback = next(step for step in self.value["jobs"]["deploy"]["steps"]
                        if step.get("id") == "rollback_auth")
        self.assertEqual(rollback["with"]["service_account"], "${{ vars.GCP_TERRAFORM_SA }}")

    def test_bandit_keeps_native_results_and_uses_only_the_temporary_int_policy(self):
        jobs = self.value["jobs"]
        self.assertEqual(jobs["api"]["env"]["INT_BANDIT_POLICY_SCOPE"], "int-hito-a")
        self.assertNotIn("INT_BANDIT_POLICY_SCOPE", jobs["frontend"].get("env", {}))
        self.assertNotIn("INT_BANDIT_POLICY_SCOPE", jobs["deploy"].get("env", {}))
        steps = jobs["api"]["steps"]
        scan_index, scan = next((index, item) for index, item in enumerate(steps)
                                if item.get("id") == "bandit_scan")
        policy_index, policy = next((index, item) for index, item in enumerate(steps)
                                    if item.get("id") == "bandit_policy")
        self.assertLess(scan_index, policy_index)
        self.assertEqual(policy["if"],
                         "${{ !cancelled() && steps.bandit_scan.outcome == 'success' }}")

        scan_source = scan["run"]
        self.assertIn("python -m bandit -r /app/app /app/scripts", scan_source)
        self.assertIn("--severity-level all --confidence-level all --ignore-nosec", scan_source)
        self.assertIn("--format json --output /ci-results/bandit.json", scan_source)
        self.assertIn("bandit-version.txt", scan_source)
        self.assertEqual(scan_source.count("set +e"), 1)
        unguarded_start = scan_source.index("set +e")
        scanner_start = scan_source.index("docker run", unguarded_start)
        scanner_end = scan_source.index("scanner_exit=$?", scanner_start)
        self.assertEqual(scan_source[unguarded_start:scanner_end].count("docker run"), 1)
        self.assertIn("scanner_exit=$?\nset -e", scan_source)
        self.assertIn('0|1) ;;', scan_source)
        self.assertIn('*) exit "$scanner_exit" ;;', scan_source)
        self.assertIn('bandit-exit.txt', scan_source)
        self.assertLess(scanner_start, scanner_end)
        self.assertNotIn("scripts.int_hito_a_bandit evaluate", scan_source)
        self.assertNotIn("continue-on-error", yaml.dump(scan))
        self.assertNotIn("--exit-zero", scan_source)
        self.assertNotRegex(scan_source, r"(?:-s|--skip)\s+(?:B105|B404|B603)")

        policy_source = policy["run"]
        self.assertNotIn("python -m bandit -r", policy_source)
        self.assertIn("python -B -m scripts.int_hito_a_bandit evaluate", policy_source)
        self.assertIn("config/int-hito-a-bandit-acceptance.json", policy_source)
        self.assertIn('bandit-policy.json', policy_source)
        self.assertIn("Bandit evaluado con excepción INT", policy_source)
        for field in ("total_findings", "baseline_findings", "reviewed_additions"):
            self.assertIn(f"receipt['{field}']", policy_source)
        for level in ("LOW", "MEDIUM", "HIGH"):
            self.assertIn(f"severity['{level}']", policy_source)
        evaluator_start = policy_source.index("scripts.int_hito_a_bandit evaluate")
        receipt_start = policy_source.index("json.loads", evaluator_start)
        summary_start = policy_source.index("Bandit evaluado con excepción INT", receipt_start)
        self.assertLess(evaluator_start, receipt_start)
        self.assertLess(receipt_start, summary_start)
        self.assertNotIn("continue-on-error", yaml.dump(policy))

    def test_legacy_mutators_are_inert_and_cannot_be_manually_dispatched(self):
        directory = WORKFLOW.parent
        for name in sorted(LEGACY_MUTATORS):
            source = (directory / name).read_text(encoding="utf-8")
            workflow = yaml.load(source, Loader=yaml.BaseLoader)
            with self.subTest(name=name):
                self.assertIn("on:\n  workflow_call:", source)
                self.assertNotIn("on:\n  workflow_dispatch:", source)
                self.assertTrue(workflow["jobs"])
                for job in workflow["jobs"].values():
                    self.assertEqual(job.get("if"), "${{ false }}")

    def test_action_uses_are_immutable_commit_pins(self):
        uses = re.findall(r"(?m)^\s+uses:\s+([^\s#]+)", self.source)
        self.assertTrue(uses)
        for reference in uses:
            with self.subTest(reference=reference):
                self.assertRegex(reference, r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+@[a-f0-9]{40}$")


if __name__ == "__main__":
    unittest.main()
