from hashlib import sha256
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

from scripts import int_demo_a_publisher_lab as lab


class PublisherRehearsalEvidence(unittest.TestCase):
    def test_standard_preparation_job_has_no_federation_or_artifact_input(self):
        path = Path(lab.__file__).resolve().parents[1] / ".github/workflows/int-demo-a-wif-read.yml"
        workflow = path.read_text(encoding="utf-8")
        bootstrap, preparation = workflow.split("\n  docker-preparation-without-federation:\n", 1)
        self.assertIn("(inputs.observation == 'full' || inputs.observation == 'noble_policy')", bootstrap)
        self.assertIn("inputs.observation == 'docker_prepare'", preparation)
        self.assertIn("--profile evaluate", preparation)
        for excluded in ("id-token:", "environment:", "google-github-actions", "download-artifact", "GCP_ACCESS_TOKEN"):
            self.assertNotIn(excluded, preparation)

    def test_credentials_and_oidc_capability_each_block_the_lab(self):
        lab.credential_free({})
        for key in ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GCP_ACCESS_TOKEN",
                    "GOOGLE_APPLICATION_CREDENTIALS", "DOCKER_AUTH_CONFIG"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "credential_free_runner"):
                lab.credential_free({key: "fixture"})

    def test_lab_binds_the_complete_preparation_to_its_own_boot_and_run(self):
        observation = {"run": "82", "attempt": "1", "job": "fixture", "boot_id": "fixture-boot", "source_commit": "a" * 40}
        toolchain = {"schema": lab.identity.SCHEMA, "observation": observation}
        raw = json.dumps(toolchain).encode()
        preparation = {"schema": lab.preparation.SCHEMA, "profile": "evaluate", "status": "prepared_verified", "run": "82",
                       "attempt": "1", "commit": observation["source_commit"], "after": {"toolchain": toolchain},
                       "cloud_credentials_used": False, "oidc_job_capability": False}
        tool = {"manifest": "sha256:" + "c" * 64, "config": "sha256:" + "d" * 64}
        with patch.object(lab.identity, "projection_sha256", return_value="e" * 64):
            verified = lab.comparison_proof(toolchain, json.dumps(preparation).encode(), raw, tool)
            self.assertEqual(verified["boot_id"], observation["boot_id"])
            self.assertEqual(verified["docker_toolchain_sha256"], sha256(raw).hexdigest())
            self.assertEqual(verified["source_sha256"], sha256(Path(lab.__file__).read_bytes()).hexdigest())
            self.assertEqual(verified["images"], {name: list(values) for name, values in lab.publish.TARGETS.items()})
            with self.assertRaisesRegex(ValueError, "same_credential_free_preparation"):
                lab.comparison_proof(toolchain, json.dumps({**preparation, "run": "90"}).encode(), raw, tool)

    @unittest.skipUnless(os.name == "posix", "native laboratory process limits require POSIX")
    def test_native_error_and_output_limit_preserve_diagnostics(self):
        command = [sys.executable, "-c", "print('known fixture error'); raise SystemExit(7)"]
        with self.assertRaises(lab.LabFailure) as raised:
            lab.bounded(command, {}, "native_fixture")
        self.assertEqual(raised.exception.evidence["native_exit"], 7)
        self.assertIn("known fixture error", raised.exception.evidence["diagnostic"])
        excessive = [sys.executable, "-c", "print('x' * 100000)"]
        with self.assertRaises(lab.LabFailure) as raised:
            lab.bounded(excessive, {}, "native_output_fixture")
        self.assertEqual(raised.exception.evidence["output_bytes"], lab.BOUND)


if __name__ == "__main__":
    unittest.main()
