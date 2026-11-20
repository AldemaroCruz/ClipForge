"""Exercise the bounded kernel handoff without cloud or guest access."""
from pathlib import Path
import unittest
from unittest.mock import patch

from scripts import int_guest_inventory as transport
from scripts import int_noble_kernel_observation as observer


class KernelHandoffTests(unittest.TestCase):
    def test_accepts_only_its_own_first_attempt_on_the_protected_branch(self):
        env = {"RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_SHA": "a" * 40,
               "GUEST_APPROVED_COMMIT": "a" * 40,
               "GITHUB_WORKFLOW_REF": f"AldemaroCruz/ClipForge/{observer.WORKFLOW}@refs/heads/ci/bootstrap-sec03"}
        observer.check_hosted(env)
        for change in ({"GITHUB_RUN_ATTEMPT": "2"}, {"GUEST_APPROVED_COMMIT": "b" * 40},
                       {"GITHUB_WORKFLOW_REF": observer.first.OBSERVE_PATH}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "NOBLE_KERNEL_HOSTED_BOUNDARY"):
                observer.check_hosted({**env, **change})

    def test_handoff_is_bound_to_the_existing_successful_observation_and_creation(self):
        with (patch.object(observer.first, "checked_creation_runs") as creation,
              patch.object(observer.postverify, "verify_github_run") as observation):
            observer.verify_handoff("fixture")
        creation.assert_called_once_with(observer.ORIGINAL_APPLY, observer.CONTROLS, "fixture", observer.POSTVERIFY_RUN)
        observation.assert_called_once_with(observer.INITIAL_RUN, observer.CONTROLS, "fixture",
                                            observer.first.OBSERVE_PATH, "success")

    def test_pinned_input_and_preserved_incomplete_guest_result(self):
        summary = {"candidate": observer.PINNED_IDS}
        with (patch.object(observer.first, "creation_handoff", return_value=({}, summary)) as extract,
              patch.object(observer.first, "check_pin", return_value={}) as pin):
            self.assertEqual(observer.checked_inputs(b"summary", b"pin"), (summary, {}))
        extract.assert_called_once_with(b"summary", observer.SUMMARY_SHA, observer.CONTROLS, observer.ORIGINAL_APPLY,
                                        observer.POSTVERIFY_RUN)
        pin.assert_called_once_with(b"pin", observer.PIN_SHA, summary, observer.SUMMARY_SHA)
        with patch.object(observer.first, "creation_handoff", return_value=({}, {"candidate": {"instance_id": "wrong"}})):
            with self.assertRaisesRegex(ValueError, "NOBLE_KERNEL_SCOPE"):
                observer.checked_inputs(b"summary", b"pin")
        raw = transport.canonical({"schema": observer.probe.SCHEMA, "error": "NOBLE_KERNEL_PLATFORM"})
        with self.assertRaisesRegex(transport.Blocked, "NOBLE_KERNEL_PLATFORM"):
            observer.check_guest(raw, 2, "fixture")

    def test_kernel_receipt_requires_same_instance_and_boot_and_cannot_authorize(self):
        snapshot = {**observer.PINNED_IDS, "boot_timestamp": "fixture"}
        receipt = observer.link({}, snapshot, snapshot, b"payload", "a" * 40)
        self.assertIs(receipt["risk_accepted"], False)
        self.assertIs(receipt["runtime_authorized"], False)
        with self.assertRaisesRegex(ValueError, "NOBLE_KERNEL_CONTROL_PLANE_CHANGED"):
            observer.link({}, snapshot, {**snapshot, "boot_timestamp": "different"}, b"payload", "a" * 40)

    def test_workflow_requires_int_and_keeps_the_first_observation_closed(self):
        root = Path(__file__).resolve().parents[1]
        workflow = (root / observer.WORKFLOW).read_text(encoding="utf-8")
        self.assertIn("environment: int", workflow)
        self.assertIn("scripts.int_noble_kernel_observation run", workflow)
        self.assertIn("scripts.int_noble_kernel_observation cleanup", workflow)
        self.assertIn(f"{observer.CONTROLS}-{observer.POSTVERIFY_RUN}-1", workflow)
        self.assertNotIn("scripts.int_noble_first_observation run", workflow)
        self.assertNotIn("noble.cdx.json", workflow)


if __name__ == "__main__":
    unittest.main()
