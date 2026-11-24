"""Exercise the CLI invoked by Actions using authored, non-cloud controls."""
import contextlib
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_noble_bootstrap_db as launcher


class LauncherTests(unittest.TestCase):
    def setUp(self):
        temp = TemporaryDirectory(prefix="clipforge-noble-bootstrap-test-")
        self.addCleanup(temp.cleanup)
        self.temp = Path(temp.name)
        self.bundle = self.temp / "bundle"
        self.bundle.mkdir()
        self.env = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
                    "GITHUB_REF": "refs/heads/ci/bootstrap-sec03", "GITHUB_WORKFLOW_REF": f"AldemaroCruz/ClipForge/{launcher.WORKFLOW}@refs/heads/ci/bootstrap-sec03",
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "9999", "GITHUB_SHA": "a" * 40,
                    "INT_APPROVED_COMMIT": "a" * 40, "GCP_ACCESS_TOKEN": "fixture_token_not_used_by_tests",
                    "INT_NOBLE_PROTECTED_GATE_MODE": "global"}
        now = datetime.now(timezone.utc)
        self.proposal = {key: None for key in launcher.PROPOSAL_FIELDS}
        self.proposal.update(schema="clipforge-int-noble-bootstrap-proposal-2", status="authorized_single_guest_initialization",
                             execution_authorized=True, cloud_writes_authorized=True, VM_operations_authorized=True,
                             SQL_on_INT_authorized=True, risk_acceptance=False, target=launcher.TARGET.copy())
        self.decision = {"schema": "clipforge-db01-activation-decision-1", "status": "authorized_single_guest_initialization",
                         "owner": "admin@ixbalam.studio", "repository": self.env["GITHUB_REPOSITORY"], "branch": "ci/bootstrap-sec03",
                         "approved_commit": self.env["GITHUB_SHA"], "operation_id": "b" * 32,
                         "host_evidence_sha256": launcher.handoff.PIN_SHA, "baseline_evidence_sha256": launcher.BASELINE_SHA,
                         "baseline_run_id": launcher.BASELINE_RUN, "baseline_artifact_id": launcher.BASELINE_ARTIFACT,
                         "issued_utc": (now - timedelta(minutes=1)).isoformat(), "expires_utc": (now + timedelta(minutes=35)).isoformat(),
                         "confirmation": launcher.CONFIRMATION}
        (self.bundle / "review.json").write_bytes(b"{}")
        (self.bundle / "binding.json").write_bytes(b"{}")
        for kind in ("REVIEW", "BINDING"):
            self.env[f"INT_NOBLE_PROTECTED_{kind}_SHA256"] = launcher.transport.sha(b"{}")

    def cli(self, operation, *, damage=None):
        self.decision["proposal_sha256"] = self.save("proposal.json", self.proposal)
        digest = self.save("decision.json", self.decision)
        self.env["INT_NOBLE_PROTECTED_DECISION_SHA256"] = digest
        if damage:
            (self.bundle / damage).write_bytes(b"{}")
        with contextlib.redirect_stdout(io.StringIO()) as output:
            status = launcher.main([operation, "--bundle", str(self.bundle), "--decision-sha256", digest,
                                    "--review-sha256", self.env["INT_NOBLE_PROTECTED_REVIEW_SHA256"],
                                    "--binding-sha256", self.env["INT_NOBLE_PROTECTED_BINDING_SHA256"],
                                    "--workdir", str(self.temp / "work"), "--reports", str(self.temp / "reports")], env=self.env)
        return status, output.getvalue()

    def save(self, name, body):
        raw = launcher.transport.canonical(body)
        (self.bundle / name).write_bytes(raw)
        return launcher.transport.sha(raw)

    def test_actual_local_entrypoint_rejects_bad_digest_before_cloud_or_evidence_checker(self):
        with patch.object(launcher.transport, "_credential_document") as credential, patch.object(launcher.gate, "main") as gate:
            code, output = self.cli("local", damage="decision.json")
        self.assertEqual(code, 1)
        self.assertIn("noble_artifact_digest", output)
        credential.assert_not_called()
        gate.assert_not_called()

    def test_actual_local_entrypoint_rejects_debian_and_root_before_auth(self):
        for instance, disk in (("1670495097211408131", "6427691858848206684"), (launcher.payloads.INSTANCE, launcher.payloads.BOOT)):
            self.proposal["target"].update(instance_id=instance, disk_id=disk)
            with self.subTest(instance=instance, disk=disk), patch.object(launcher.transport, "_credential_document") as credential:
                code, output = self.cli("local")
            self.assertEqual(code, 1)
            self.assertIn("noble_bootstrap_exact_target", output)
            credential.assert_not_called()

    def test_local_rejects_gate_other_than_global_or_explicit_demo_a(self):
        control = launcher.ROOT / launcher.CONTROL
        raw = control.read_bytes()
        fixture = self.temp / launcher.CONTROL
        fixture.parent.mkdir()
        fixture.write_bytes(raw)
        self.proposal.update(controls=launcher.transport.sha(raw), gate="unknown")
        with patch.object(launcher, "ROOT", self.temp):
            code, output = self.cli("local")
        self.assertEqual(code, 1)
        self.assertIn("noble_bootstrap_exact_control_or_gate", output)

    def test_protected_job_does_not_switch_from_global_gate_without_separate_authority(self):
        with patch.object(launcher, "validate_local", return_value={"gate": "demo-a"}), patch.object(launcher.gate, "main") as gate:
            code, output = self.cli("protected-local")
        self.assertEqual(code, 1)
        self.assertIn("noble_independent_protected_input_digest", output)
        gate.assert_not_called()

    def test_secretless_admission_rejects_host_before_tls_and_guest(self):
        self.env.pop("GCP_ACCESS_TOKEN")
        with (patch.object(launcher, "validate_local", return_value={"gate": "global"}),
              patch.object(launcher.gate, "main", return_value=1) as gate,
              patch.object(launcher, "check_tls") as tls, patch.object(launcher, "launch") as launch):
            code, output = self.cli("protected-admit")
        self.assertEqual(code, 1)
        self.assertIn("noble_activation_evidence_blocked", output)
        self.assertIn("--match-credential-runner", gate.call_args.args[0])
        tls.assert_not_called()
        launch.assert_not_called()

    def test_admission_rejects_any_unexpected_secret_before_reading_bundle(self):
        self.env.pop("GCP_ACCESS_TOKEN")
        self.env["INT_PG_SERVER_KEY"] = "fixture-key"
        with patch.object(launcher, "validate_local") as decide:
            code, output = self.cli("protected-admit")
        self.assertEqual(code, 1)
        self.assertIn("db_runner_admission_requires_no_secret_inputs", output)
        self.assertNotIn("fixture-key", output)
        decide.assert_not_called()

    def test_cloud_discrepancy_at_actual_actions_run_stops_before_profile_or_ssh(self):
        ready = {"pin": {"control_plane": {"disk": launcher.payloads.DATA}}, "summary": {"candidate": {}}}
        (self.temp / "reports").mkdir()

        def already_valid(_env, bundle, _sha, *, root):
            return {**ready, "decision_raw": (bundle / "decision.json").read_bytes(), "gate": "global"}

        with (patch.object(launcher, "validate_local", side_effect=already_valid), patch.object(launcher.gate, "main", return_value=0),
              patch.object(launcher.transport, "_validate_paths", return_value=(self.temp, self.temp / "reports")),
              patch.object(launcher.transport, "_credential_document"), patch.object(launcher.transport, "validate_deploy_credentials") as auth,
              patch.object(launcher.first, "snapshot", return_value={"disk": launcher.payloads.BOOT}) as observed,
              patch.object(launcher, "NobleProcesses") as process, patch.object(launcher.transport.Client, "import_key") as key):
            code, output = self.cli("run")
        self.assertEqual(code, 1)
        self.assertIn("noble_current_disk_boot_or_metadata_changed", output)
        auth.assert_called_once()
        observed.assert_called_once()
        process.assert_not_called()
        key.assert_not_called()
        self.assertFalse((self.temp / "db01-journal.json").exists())
        report = json.loads((self.temp / "reports" / "db01-preflight-failure.json").read_bytes())
        self.assertEqual(report["error_code"], "noble_current_disk_boot_or_metadata_changed")

    def test_live_permission_errors_are_consolidated_before_os_login(self):
        decision = b"fixture bytes checked out of band"
        self.env["INT_NOBLE_PROTECTED_DECISION_SHA256"] = launcher.transport.sha(decision)
        ready = {"decision_raw": decision, "gate": "demo-a", "summary": {"candidate": {}}, "pin": {"control_plane": {}}, "deploy_policy": {}}
        policy_error = {"operation": "getIamPolicy", "resource": "account", "http_status": 403}
        with (patch.object(launcher.transport, "_credential_document"), patch.object(launcher.transport, "validate_deploy_credentials"),
              patch.object(launcher.first, "snapshot", return_value={}),
              patch.object(launcher.iam, "request_json", return_value={"permissions": []}) as evaluation,
              patch.object(launcher.release, "require_application_ci") as global_ci, patch.object(launcher.transport.Client, "profile") as profile):
            with self.assertRaises(launcher.transport.Failure) as failure:
                launcher.check_cloud(self.env, ready, policies=lambda *_: [policy_error])
        self.assertEqual(failure.exception.receipt["checks"], [
            policy_error,
            {"operation": "testIamPermissions", "resource": launcher.noble_policy.ACCOUNT, "missing_permissions": ["iam.serviceAccounts.actAs"], "http_status": 200},
        ])
        evaluation.assert_called_once_with(f"https://iam.googleapis.com/v1/{launcher.noble_policy.ACCOUNT}:testIamPermissions",
                                           self.env["GCP_ACCESS_TOKEN"], "POST", {"permissions": ["iam.serviceAccounts.actAs"]})
        global_ci.assert_not_called()
        profile.assert_not_called()

    def test_legacy_workflow_is_inert_before_any_oidc(self):
        workflow = (launcher.ROOT / launcher.WORKFLOW).read_text(encoding="utf-8")
        preview, protected = workflow.split("\n  protected-bootstrap:\n", 1)
        self.assertIn("-m scripts.int_noble_bootstrap_db local ", preview)
        self.assertNotIn("id-token:", preview)
        self.assertNotIn("google-github-actions/auth@", preview)
        self.assertIn("needs: local-preflight", protected)
        self.assertIn("if: ${{ false }}", protected)
        self.assertNotIn("needs.local-preflight.result == 'success'", protected)
        self.assertIn("environment: int", protected)
        order = ("protected-local --bundle", "google-github-actions/auth@", " cloud --bundle", " run --bundle")
        self.assertEqual(sorted(protected.index(marker) for marker in order), [protected.index(marker) for marker in order])
        config = json.loads((launcher.ROOT / launcher.CONTROL).read_bytes())
        self.assertFalse(config["activation_authorized"])
        self.assertEqual(config["application_ci_gate"], "global")

    def test_rendered_payloads_are_byte_exact_and_contain_only_noble_identity(self):
        raw = launcher.payloads.operator_bytes()
        scope = launcher.payloads.operator_contract(raw)
        self.assertEqual(scope.DISK_ID, launcher.payloads.DATA)
        self.assertEqual(str(scope.DEVICE), launcher.guest.BY_ID)
        self.assertIn(b"127.0.0.1/32 scram-sha-256", raw)
        self.assertNotIn(b"6427691858848206684", raw)
        stop = launcher.payloads.containment_bytes()
        self.assertIn(b"7382984635240536620", stop)
        self.assertNotIn(b"6427691858848206684", stop)


if __name__ == "__main__":
    unittest.main()
