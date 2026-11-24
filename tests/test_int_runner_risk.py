"""Closed-scope tests for the owner's GitHub-hosted INT runner acceptance."""

from hashlib import sha256
import unittest

from scripts import check_int_demo_a as gate
from scripts import int_noble_bootstrap_db as bootstrap
from scripts import int_runner_risk as risk
from scripts import prepare_ci_context as ci_context


class HostedRunnerRiskAcceptanceTests(unittest.TestCase):
    def test_versioned_policy_is_exact_and_digest_pinned(self):
        self.assertEqual(sha256(risk.CONFIG.read_bytes()).hexdigest(), risk.CONFIG_SHA256)
        self.assertEqual(risk.load(), risk.POLICY)
        self.assertEqual(risk.POLICY["scope"]["runner_label"], "ubuntu-24.04")
        self.assertEqual(risk.POLICY["scope"]["environment"], "int")
        self.assertFalse(risk.cross_job_identity_required())
        self.assertTrue(risk.POLICY["same_job_continuity_required"])

    def test_only_credential_runner_toolchain_vulnerabilities_are_informational(self):
        base = {"role": "credential_toolchain", "kind": "trivy_toolchain", "severity": "HIGH"}
        for changed, expected in (
            ({}, True),
            ({"severity": "CRITICAL"}, True),
            ({"severity": "UNKNOWN"}, False),
            ({"role": "artifact_builder"}, False),
            ({"kind": "trivy_oci"}, False),
        ):
            with self.subTest(changed=changed):
                self.assertIs(risk.informational_finding({**base, **changed}), expected)

    def test_duplicate_policy_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "runner_risk_duplicate_json_key"):
            risk.closed(b'{"schema":"one","schema":"two"}')

    def test_policy_sources_are_bound_to_every_legacy_credential_route(self):
        expected = {"scripts/int_runner_risk.py", "config/int-runner-risk-acceptance.json"}
        for sources in (gate.APT_PREFLIGHT_SOURCES, gate.PERSONAL_SQL_SOURCES,
                        gate.REQUIRED_BOOTSTRAP_SOURCES, gate.PUBLICATION_SOURCES,
                        gate.NATIVE_PUBLICATION_SOURCES, bootstrap.REQUIRED_SOURCES):
            with self.subTest(sources=sources):
                self.assertTrue(expected <= sources)
        self.assertIn("config/int-runner-risk-acceptance.json", ci_context.SUPPORT_FILES)


if __name__ == "__main__":
    unittest.main()
