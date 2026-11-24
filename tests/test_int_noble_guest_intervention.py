"""Directed, offline transport and native-receipt regressions for Noble."""

from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from scripts import int_demo_a_preflight as preflight
from scripts import int_noble_guest_intervention as intervention
from tests import test_int_noble_guest_intervention_kmod as kernels


apt, backend, kmod, transport = (intervention.apt, intervention.backend, intervention.kmod, intervention.transport)
COMMIT, DECISION = "b" * 40, "c" * 32
ACTOR = {"GITHUB_RUN_ID": "22", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": COMMIT, "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
         "GCP_ACCESS_TOKEN": "fixture-never-used-for-network", "INT_DEMO_A_PROTECTED_DECISION_SHA256": "a" * 64}
EXIT = {"process": "exited", "exit": 0, "stderr_markers": [], "unclassified_stderr_lines": 0}


def fixture(action="apt_upgrade"):
    snapshot = {"instance_id": apt.INSTANCE, "data_disk_id": apt.DATA_DISK, "boot_disk_id": apt.BOOT_DISK, "snapshot_sha256": "9" * 64}
    executable = apt.build_payload(intervention.ROOT / "scripts") if action == "apt_upgrade" else intervention.kmod_render.payload_bytes(intervention.ROOT / "scripts")
    decision = {"operation_id": DECISION, "control_commit": COMMIT,
                "issued_utc": (intervention.now_utc() - timedelta(minutes=1)).isoformat(),
                "expires_utc": (intervention.now_utc() + timedelta(minutes=30)).isoformat(),
                "inputs": {"action": action, "payload_sha256": transport.sha(executable), "snapshot_sha256": kmod.object_sha(snapshot),
                           "previous_kmod": None}}
    return {"decision": decision, "decision_raw": transport.canonical(decision), "snapshot": snapshot,
            "summary": {"candidate": {}}, "pin": {}, "executable": executable}


def apt_success(ready):
    raw, request = intervention.packet(ready)
    simulation = {"command": EXIT, "exact_upgrade": True, "action_count": 2}
    rest = "f" * 64
    fields = {"request_sha256": transport.sha(raw), "approved_commit": COMMIT, "owner_decision_sha256": request["owner_decision_sha256"],
              "simulation": simulation, "operation_id": request["operation_id"], "package_sha256": apt.DIGEST, "boot_id": apt.GUEST_BOOT}
    intent = {"schema": "clipforge-int-noble-apt-intent-1", **fields, "other_package_states_sha256": rest}
    postcheck = {"installed": apt.apt_checks.TARGET, "other_package_states_equal": True, "other_package_states_sha256": rest,
                 "dpkg_clean": True, "same_boot_and_kernel": True}
    receipt = {"schema": "clipforge-int-noble-apt-receipt-1", **fields, "status": "updated_exact_package", "launch_intent": True,
               "instance_id": apt.INSTANCE, "boot_disk_id": apt.BOOT_DISK, "data_disk_id": apt.DATA_DISK, "kernel": apt.RELEASE,
               "package": apt.apt_checks.PACKAGE, "signed_index_sha256": apt.SIGNED_INDEX, "download_verified": True, "temp_released": True,
               "install": {"tool": "dpkg", **EXIT}, "postcheck": postcheck, "intent_sha256": transport.sha(apt.canonical(intent) + b"\n")}
    return request, receipt


def reviewed_fixture(test, bundle):
    ready = fixture()
    snapshot = ready["snapshot"]
    decision = ready["decision"]
    decision.update(schema=preflight.SCHEMA, status="authorized_one_operation", owner="admin@ixbalam.studio",
                    repository=preflight.REPO, branch=preflight.BRANCH, environment="int", project=preflight.PROJECT,
                    operation=intervention.OPERATION, gate_mode="demo-a")
    env = {**ACTOR, "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_REF": "refs/heads/" + preflight.BRANCH,
           "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_WORKFLOW_REF": f"{preflight.REPO}/{intervention.WORKFLOW}@refs/heads/{preflight.BRANCH}",
           "INT_APPROVED_COMMIT": COMMIT, "ImageVersion": "20261116.133.1", "INT_DEMO_A_PROTECTED_GATE_MODE": "demo-a"}

    def store(path, value):
        raw = transport.canonical(value)
        path.write_bytes(raw)
        path.chmod(0o600)
        return transport.sha(raw)

    bundle.mkdir()
    summary, pin = {"candidate": {}}, {"control_plane": snapshot, "record": {"guest_boot_id": apt.GUEST_BOOT}}
    summary_sha = store(bundle / "summary.json", summary)
    pin_sha = store(bundle / "host-pin.json", pin)
    readiness = {"payload_sha256": intervention.READINESS_PAYLOAD, "control_plane": snapshot, "risk_accepted": False,
                 "runtime_authorized": False, "guest": {"release": apt.RELEASE, "package": {"installed": apt.apt_checks.CURRENT},
                                                        "exports": {"active_count": 0, "host_mount_namespace": True}}}
    readiness_sha = store(bundle / "apt-readiness.json", readiness)
    consumers_sha = store(bundle / "kernel-consumers.json", kernels.baseline(snapshot, kernels.observation()))
    policy_fixture = bundle / "policy-config.json"
    policy_fixture.write_bytes((intervention.ROOT / intervention.policies.CONFIG).read_bytes())
    policy_fixture.chmod(0o600)
    decision["inputs"].update(readiness_sha256=readiness_sha, consumer_inventory_sha256=consumers_sha,
                              policy_config_sha256=transport.sha(policy_fixture.read_bytes()),
                              deploy_policy_receipt_sha256=store(bundle / "deploy-policy-receipt.json", {}))
    review_sha = decision["review_sha256"] = store(bundle / "review.json", {"fixture": "security-review"})
    binding_sha = decision["binding_sha256"] = store(bundle / "binding.json", {"state_generation": backend.scope.STATE["generation"]})
    decision_sha = store(bundle / "decision.json", decision)
    env.update(INT_DEMO_A_PROTECTED_DECISION_SHA256=decision_sha, INT_NOBLE_INTERVENTION_REVIEW_SHA256=review_sha,
               INT_NOBLE_INTERVENTION_BINDING_SHA256=binding_sha)
    with (patch.multiple(intervention.handoff, SUMMARY_SHA=summary_sha, PIN_SHA=pin_sha),
          patch.object(intervention, "KMOD_INVENTORY", consumers_sha), patch.object(apt, "READINESS", readiness_sha),
          patch.object(intervention.handoff, "checked_inputs", return_value=(summary, pin)),
          patch.object(intervention.handoff, "check_guest", return_value=readiness["guest"]),
          patch.object(preflight.gate, "main", return_value=0) as local_gate,
          patch.object(intervention.gate, "verify_review", return_value=0) as protected_gate,
          patch.object(transport, "_local_bytes", (lambda path, _: path.read_bytes()) if os.name == "nt" else transport._local_bytes),
          patch.object(intervention.policies, "CONFIG", str(policy_fixture)),
          patch.object(intervention.policies, "expected_policy", return_value={"fixture": "full policy"})):
        result = intervention.validate_local(env, bundle, decision_sha, review_sha, binding_sha, protected=True)
    test.assertEqual(local_gate.call_args.args[0][-2:], ["--guest-action", "apt_upgrade"])
    test.assertEqual(protected_gate.call_args.kwargs["guest_action"], "apt_upgrade")
    return result, env, readiness_sha


class InterventionTests(unittest.TestCase):
    def test_apt_receipt_requires_exact_durable_intent_and_postcheck(self):
        ready = fixture()
        request, result = apt_success(ready)
        before = ready["snapshot"]
        self.assertEqual(intervention.check_success(apt.canonical(result), 0, before, before, ready, request), result)
        with self.assertRaisesRegex(ValueError, "intervention_apt_postcheck"):
            intervention.check_success(apt.canonical({**result, "intent_sha256": "e" * 64}), 0, before, before, ready, request)
        with self.assertRaisesRegex(ValueError, "intervention_native_exit_or_snapshot"):
            intervention.check_success(apt.canonical(result), 1, before, before, ready, request)

    def test_state_is_only_same_run_metadata_and_goes_stale(self):
        ready = fixture()
        expected = backend.binding(ACTOR, ready["decision"], ACTOR["INT_DEMO_A_PROTECTED_DECISION_SHA256"])
        bound = {**expected["state"], "size": str(expected["state"]["size"])}
        clock = datetime.now(timezone.utc)
        with patch.object(backend.jobs, "request_json", side_effect=[bound, None, bound]) as api:
            receipt = backend.observe("fixture", expected, opener=object(), clock=lambda: clock)
        self.assertEqual(api.call_count, 3)
        self.assertTrue(all(row.args[2] == "GET" and "alt=media" not in row.args[3] for row in api.call_args_list))
        self.assertTrue(api.call_args_list[1].kwargs["missing"])
        self.assertFalse(receipt["lock_acquired"])
        with self.assertRaisesRegex(ValueError, "intervention_backend_observation_expired"):
            backend.verify(receipt, expected, now=clock + timedelta(seconds=121))
        with patch.object(backend.jobs, "request_json", side_effect=[bound, ValueError("cloud_http_403")]), self.assertRaisesRegex(ValueError, "cloud_http_403"):
            backend.observe("fixture", expected, opener=object(), clock=lambda: clock)

    def test_transport_only_allows_one_bound_loader_invocation(self):
        work = Path(self.enterContext(TemporaryDirectory()))
        (work / "known_hosts").write_bytes(b"private pin fixture\n")
        runner = intervention.InterventionProcesses(work, "/fixture/gcloud", b"fixed-read", "fixture",
                                                      maximum_process_seconds=600, ssh_builder=intervention.first.ssh_builder(apt.INSTANCE))
        runner.username = "sa_fixture_deploy"
        public = b"approved source fixture"
        private = b"approved input fixture"
        def run(argv, raw, **kwargs):
            self.assertEqual(runner._kind(argv, raw), "ssh")
            self.assertEqual(argv[-1], intervention.kmod_contract.command(public, transport.sha(public)))
            with self.assertRaises(transport.Blocked):
                runner._kind(argv, b"different input")
            return 0, b"receipt", b""
        with patch.object(runner, "run", side_effect=run) as invoke:
            self.assertEqual(runner.invoke(15432, public, transport.sha(public), private), (0, b"receipt", b""))
            with self.assertRaisesRegex(ValueError, "already_used"):
                runner.invoke(15432, public, transport.sha(public), private)
        self.assertEqual(runner.payload, b"fixed-read")
        invoke.assert_called_once()

    def test_simulated_runner_observes_invokes_and_preserves_primary_failure(self):
        for exit_code, cleanup_status, expected_status in ((0, "own_key_removed", "completed_verified"),
                (255, "cleanup_unconfirmed_TTL_pending", "guest_outcome_unknown_reconcile")):
            with self.subTest(exit_code=exit_code), TemporaryDirectory() as scratch:
                work, reports = Path(scratch) / "work", Path(scratch) / "reports"
                work.mkdir()
                reports.mkdir()
                ready, env, readiness_sha = reviewed_fixture(self, Path(scratch) / "bundle")
                before = ready["snapshot"]
                with patch.object(apt, "READINESS", readiness_sha):
                    _, terminal = apt_success(ready)
                output = apt.canonical(terminal) if not exit_code else b"discarded unstructured output"
                client, cloud, processes = Mock(), Mock(), Mock()
                client.profile_name = "fixture-profile"
                processes.run.return_value = (0, b"precheck fixture", b"")
                processes.invoke.return_value = (exit_code, output, b"")
                make_custody = Mock(return_value=cloud)
                names = {intervention.INTENT: "fixture-intent", intervention.RESULT: "fixture-result"}
                reference = {"name": "fixture", "generation": "7", "size": 1, "sha256": "0" * 64}
                cloud.create.return_value = reference
                with (patch.object(intervention.first, "snapshot", return_value=before),
                      patch.object(intervention.custody, "producer_names", return_value=names),
                      patch.object(intervention.backend, "verify") as fresh,
                      patch.object(intervention.bootstrap, "proof", return_value=({}, {"guest_boot_id": apt.GUEST_BOOT, "disk_id": apt.DATA_DISK})),
                      patch.object(intervention.bootstrap, "token_margin"),
                      patch.object(apt, "READINESS", readiness_sha),
                      patch.object(intervention, "start_channel", return_value=processes),
                      patch.object(intervention, "open_channel", return_value=(15432, 100)),
                      patch.object(transport, "cleanup", return_value={"status": cleanup_status})):
                    result = intervention.launch(env, ready, {"fixture": True}, work, reports,
                                                 check_cloud=Mock(return_value=(before, client, {})), make_custody=make_custody)
                self.assertEqual(result["status"], expected_status, result)
                self.assertEqual(result["native_exit"], exit_code)
                self.assertEqual(fresh.call_count, 2)
                self.assertEqual([entry.args[0] for entry in cloud.create.call_args_list], list(names.values()))
                self.assertTrue(result["post_snapshot_unchanged"])
                self.assertEqual(result["result_reference"], reference)
                if exit_code:
                    self.assertEqual(result["error_code"], "intervention_native_failure_requires_reconciliation")
                    self.assertNotIn("guest_receipt", result)

    def test_workflow_initial_preflight_has_no_oidc_and_uses_private_backend_receipt(self):
        source = (intervention.ROOT / intervention.WORKFLOW).read_text(encoding="utf-8")
        preflight, deploy = source.split("\n  intervene:\n", 1)
        self.assertNotIn("id-token: write", preflight)
        observation, operator = deploy.split("      - name: Federate solely as the existing Deploy service account\n", 1)
        operator, followup = operator.split("      - name: Federate as Terraform solely for the post-SQL metadata observation\n", 1)
        metadata, retain = followup.split("      - name: Custody the personal SQL result with the original Deploy token\n", 1)
        self.assertNotIn("GCP_DEPLOY_SA", observation)
        self.assertNotIn("GCP_TERRAFORM_SA", operator)
        self.assertIn("create_credentials_file: false", observation)
        self.assertIn("export_environment_variables: false", observation)
        self.assertIn("${{ steps.backend-auth.outputs.access_token }}", observation)
        self.assertNotIn("steps.backend-auth.outputs.access_token", operator)
        self.assertIn("startsWith(inputs.operation, 'personal_')", metadata)
        self.assertIn("steps.post-backend-auth.outputs.access_token", metadata)
        self.assertNotIn("steps.auth.outputs.access_token", metadata)
        self.assertIn("GOOGLE_APPLICATION_CREDENTIALS: ''", metadata)
        self.assertIn("steps.auth.outputs.access_token", retain)
        self.assertNotIn("GCP_TERRAFORM_SA", retain)
        self.assertLess(deploy.index("protected-local"), deploy.index("google-github-actions/auth@"))
        self.assertEqual(len(re.findall(r"^    environment: int$", source, re.MULTILINE)), 1)


if __name__ == "__main__":
    unittest.main()
