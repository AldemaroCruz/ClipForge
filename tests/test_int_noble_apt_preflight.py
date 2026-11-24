"""Offline checks for the WIF-only preparation of a separate Noble APT attempt."""

from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from scripts import int_demo_a_db_runner as runner
from scripts import int_demo_a_preflight as shared
from scripts import int_noble_apt_preflight as preflight
from scripts import int_noble_guest_intervention as intervention
from tests.test_int_demo_a_db_runner import record as runner_record
from tests.test_int_noble_first_observation import summary_fixture


COMMIT = "a" * 40
DIGEST = "b" * 64
OPERATION_ID = "c" * 32
TOKEN = "synthetic-token-for-offline-apt-checks"
transport = intervention.transport
backend = intervention.backend


def workflow_steps(source):
    return re.split(r"(?m)^      - name: ", source)[1:]


def step(steps, label):
    matches = [item for item in steps if item.startswith(label + "\n")]
    if len(matches) != 1:
        raise AssertionError(f"Expected exactly one step named {label!r}; found {len(matches)}")
    return matches[0]


def approved_decision(inputs, **updates):
    now = datetime.now(timezone.utc)
    return {"schema": shared.SCHEMA, "status": "authorized_one_operation", "owner": "admin@ixbalam.studio",
            "repository": shared.REPO, "branch": shared.BRANCH, "environment": "int", "project": shared.PROJECT,
            "control_commit": COMMIT, "operation": "apt_preflight", "operation_id": OPERATION_ID,
            "issued_utc": (now - timedelta(minutes=1)).isoformat(), "expires_utc": (now + timedelta(minutes=5)).isoformat(),
            "gate_mode": "demo-a", "review_sha256": DIGEST, "binding_sha256": DIGEST, "inputs": inputs, **updates}


def hosted_env(decision_sha=DIGEST):
    return {"GITHUB_REPOSITORY": shared.REPO, "GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": "22", "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_ACTIONS": "true", "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_REF": "refs/heads/" + shared.BRANCH,
            "GITHUB_WORKFLOW_REF": f"{shared.REPO}/{intervention.WORKFLOW}@refs/heads/{shared.BRANCH}",
            "GITHUB_JOB": "intervene", "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24", "ImageVersion": "20261116.133.1",
            "INT_NOBLE_OPERATION": "apt_preflight", "INT_APPROVED_COMMIT": COMMIT, "GUEST_APPROVED_COMMIT": COMMIT,
            "GUEST_ENVIRONMENT": "int", "INT_DEMO_A_PROTECTED_DECISION_SHA256": decision_sha,
            "INT_DEMO_A_PROTECTED_GATE_MODE": "demo-a", "INT_NOBLE_INTERVENTION_REVIEW_SHA256": DIGEST,
            "INT_NOBLE_INTERVENTION_BINDING_SHA256": DIGEST, "GCP_PROJECT_ID": transport.PROJECT,
            "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1", "GCP_WIF_PROVIDER": transport.PROVIDER}


class NobleAptPreflight(unittest.TestCase):
    def block_mutations(self):
        forbidden = ((intervention, "launch"), (intervention, "packet"), (intervention, "start_channel"),
                     (intervention, "open_channel"), (intervention.InterventionProcesses, "invoke"),
                     (transport, "cleanup"), (transport.Client, "arm_key"), (transport.Client, "prepare_import"),
                     (transport.Client, "import_key"), (transport.Client, "delete_own_key"),
                     (intervention.custody.Custody, "create"), (intervention.custody.Custody, "create_bytes"))
        traps = [self.enterContext(patch.object(module, name, side_effect=AssertionError("mutation reached: " + name)))
                 for module, name in forbidden]
        for trap in traps:
            self.addCleanup(trap.assert_not_called)

    def test_read_only_cli_rejects_unknown_and_mutating_phases_before_authority(self):
        self.block_mutations()
        for phase in ("run", "cleanup", "apt_upgrade", "unknown-selector"):
            with (self.subTest(phase=phase), redirect_stderr(io.StringIO()),
                  patch.object(preflight, "validate_local") as validate, self.assertRaises(SystemExit) as stopped):
                preflight.main([phase], env=hosted_env())
            self.assertEqual(stopped.exception.code, 2)
            validate.assert_not_called()

    def command_fixture(self):
        root = Path(self.enterContext(TemporaryDirectory())).resolve()
        work = root / "clipforge-guest-inventory.fixture"
        reports = root / "clipforge-guest-report.fixture"
        local = root / "clipforge-noble-backend.abcdefgh"
        for directory in (work, reports, local):
            directory.mkdir(mode=0o700)
        receipt = local / "backend.json"
        argv = ["read", "--bundle", str(root), "--decision-sha256", DIGEST, "--review-sha256", DIGEST,
                "--binding-sha256", DIGEST, "--backend-observation", str(receipt)]
        env = {**hosted_env(), "GUEST_WORK": str(work), "GUEST_REPORTS": str(reports), "RUNNER_TEMP": str(root),
               "GCP_DEPLOY_SA": transport.DEPLOY, "GCP_ACCESS_TOKEN": TOKEN}
        decision = approved_decision({"action": "apt_preflight"})
        now = datetime.now(timezone.utc).isoformat()
        proof = {**backend.binding(env, decision, DIGEST), "started_utc": now, "lock_observed_utc": now, "completed_utc": now}
        receipt.write_bytes(transport.canonical(proof))
        receipt.chmod(0o600)
        if os.name == "nt":
            self.enterContext(patch.object(transport, "_validate_paths", return_value=(work, reports)))
        return root, env, reports, receipt, argv

    def test_read_dispatch_returns_only_the_preflight_receipt_and_has_no_mutation_path(self):
        self.block_mutations()
        _, env, reports, receipt, argv = self.command_fixture()
        ready = {"decision": approved_decision({"action": "apt_preflight"})}
        expected = {"schema": "clipforge-int-noble-apt-preflight-1", "status": "read_preflight_verified", "checks": [],
                    "runtime_authorized": False}
        with (patch.object(preflight, "validate_local", return_value=ready) as validate,
              patch.object(preflight, "read_deploy", return_value=expected) as read_deploy,
              patch.object(transport, "_local_bytes", side_effect=lambda file, _: file.read_bytes()),
              redirect_stdout(io.StringIO()) as printed):
            self.assertEqual(preflight.main(argv, env=env), 0)
        validate.assert_called_once()
        self.assertTrue(validate.call_args.kwargs["protected"])
        read_deploy.assert_called_once()
        self.assertEqual(read_deploy.call_args.args[:3], (env, ready, transport.decode(receipt.read_bytes())))
        self.assertNotIn(TOKEN, printed.getvalue())
        written = [transport.decode(item.read_bytes()) for item in reports.glob("*.json")]
        self.assertEqual(written, [expected])
        self.assertFalse(any(re.search(r"intent|intervention-result|cleanup", item.name) for item in reports.iterdir()))

    def test_read_dispatch_preserves_real_operation_and_resource_on_cloud_failure(self):
        self.block_mutations()
        _, env, reports, _, argv = self.command_fixture()
        resource = "projects/clipforgebeta2/zones/us-central1-a/instances/clipforge-int-db01-noble"
        denied = {"operation": "compute.snapshot.get", "resource": resource, "http_status": 403}
        ready = {"decision": approved_decision({"action": "apt_preflight"})}
        with (patch.object(preflight, "validate_local", return_value=ready),
              patch.object(preflight, "read_deploy", side_effect=transport.Failure("noble_compute_read_failed", denied)),
              patch.object(transport, "_local_bytes", side_effect=lambda file, _: file.read_bytes()),
              redirect_stdout(io.StringIO()) as printed):
            self.assertEqual(preflight.main(argv, env=env), 1)
        retained = printed.getvalue() + "".join(item.read_text(encoding="utf-8") for item in reports.glob("*.json"))
        self.assertIn(resource, retained)
        self.assertIn("compute.snapshot.get", retained)
        self.assertIn("403", retained)
        self.assertIn("noble_compute_read_failed", retained)
        self.assertNotIn(TOKEN, retained)

    def deployment_fixture(self):
        summary, reads = summary_fixture()
        snapshot = summary["control_plane"]
        policies = intervention.policies
        config = json.loads((intervention.ROOT / policies.CONFIG).read_bytes())
        transitions = {}
        for kind, role in config["read_roles"].items():
            before = config["prior"][kind]
            after = {**before, "etag": "preflight-" + kind,
                     "bindings": [*before["bindings"], {"role": role["name"], "members": [policies.PRINCIPAL]}]}
            transitions[kind] = {"role": role["name"], "role_definition": role["definition"], "before": before, "after": after}
        policy_receipt = {"schema": "clipforge-int-demo-a-noble-policy-receipt-2", "status": "applied_and_verified",
                          "approval_sha256": DIGEST, "policies": transitions}
        expected = policies.expected_policy(config, policy_receipt)
        decision = approved_decision({"action": "apt_preflight", "snapshot_sha256": intervention.kmod.object_sha(snapshot),
                                      "deploy_policy_receipt_sha256": transport.sha(transport.canonical(policy_receipt))})
        decision_raw = transport.canonical(decision)
        env = {**hosted_env(transport.sha(decision_raw)), "GCP_DEPLOY_SA": transport.DEPLOY, "GCP_ACCESS_TOKEN": TOKEN}
        state = backend.binding(env, decision, transport.sha(decision_raw))
        now = datetime.now(timezone.utc).isoformat()
        proof = {**state, "started_utc": now, "lock_observed_utc": now, "completed_utc": now}
        ready = {"decision": decision, "approval_sha256": transport.sha(decision_raw), "summary": summary, "snapshot": snapshot,
                 "pin": {"control_plane": snapshot}, "gate": "demo-a", "deploy_policy": expected}
        reader = Mock(side_effect=lambda url, token: {key: reads[key] for key in intervention.first.SNAPSHOT_ROUTES}[url])
        by_url = {url: kind for kind, (_, url, _) in policies.ROUTES.items()}
        policy_reader = Mock(side_effect=lambda url, token, method, payload: expected[by_url[url]])
        client = Mock(actor_verified=True, profile_name="users/fixture-deploy")
        client.profile.return_value = {"name": client.profile_name, "posixAccounts": [], "sshPublicKeys": {}}
        return env, ready, proof, reader, policy_reader, client

    @staticmethod
    def evaluation(probe, _token, principal):
        return {"operation": probe.operation, "resource": probe.resource, "method": probe.method, "principal": principal,
                "evidence": "evaluate", "http_status": 200, "result": "permission_indicated_by_evaluation",
                "write_executed": False, "permissions": list(probe.permissions),
                "permissions_indicated": list(probe.permissions), "permissions_not_confirmed": []}

    def test_deploy_checks_fixed_policies_and_permissions_without_ssh_or_writes(self):
        self.block_mutations()
        env, ready, proof, reader, policy_reader, client = self.deployment_fixture()
        evaluate = Mock(side_effect=self.evaluation)
        with (patch.object(transport, "_credential_document"), patch.object(transport, "validate_deploy_credentials") as identity):
            report = preflight.read_deploy(env, ready, proof, reader=reader, policy_reader=policy_reader,
                                          evaluate=evaluate, client_factory=Mock(return_value=client))
        identity.assert_called_once()
        self.assertEqual(report["schema"], "clipforge-int-noble-apt-preflight-1")
        self.assertEqual(report["status"], "read_preflight_verified")
        self.assertFalse(report.get("runtime_authorized", False))
        self.assertEqual({entry.args[0] for entry in reader.call_args_list}, set(intervention.first.SNAPSHOT_ROUTES))
        required = {url: (method, body) for method, url, body in intervention.policies.ROUTES.values()}
        self.assertEqual({entry.args[0]: entry.args[2:] for entry in policy_reader.call_args_list}, required)
        self.assertTrue(all(entry.args[1] == TOKEN for entry in policy_reader.call_args_list))
        indicated = {permission for entry in evaluate.call_args_list for permission in entry.args[0].permissions}
        self.assertTrue({"iam.serviceAccounts.actAs", "compute.instances.osAdminLogin"} <= indicated)
        self.assertTrue(all(entry.args[1:] == (TOKEN, transport.DEPLOY) for entry in evaluate.call_args_list))
        client.profile.assert_called_once()
        for command in ("arm_key", "prepare_import", "import_key", "delete_own_key"):
            getattr(client, command).assert_not_called()
        iap = [row for row in report["checks"] if row["operation"] == "evaluate:testIamPermissions" and
               "iap.tunnelInstances.accessViaIAP" in row["permissions"]]
        self.assertEqual(len(iap), 1)
        self.assertEqual(iap[0]["result"], "iap_permission_evaluated_tunnel_pending")
        self.assertEqual(iap[0]["condition_context"], "no_tunnel_port_evaluated_by_this_call")
        self.assertIn("conditioned_tcp_22_tunnel", report["pending"])
        self.assertIn("own_receipt_object_create_and_read", report["pending"])
        self.assertIn("secret_version_metadata_when_real_versions_exist", report["pending"])
        self.assertFalse(report["apt_authorized"])
        self.assertFalse(report["write_executed"])
        self.assertTrue(all(row["write_executed"] is False for row in report["checks"]))
        self.assertNotIn(TOKEN, json.dumps(report))

    def test_deploy_denied_policy_keeps_full_resource_and_actual_http_status(self):
        self.block_mutations()
        env, ready, proof, reader, policy_reader, client = self.deployment_fixture()
        account = intervention.policies.ACCOUNT
        account_url = intervention.policies.ROUTES["account"][1]
        response = policy_reader.side_effect

        def denied(url, token, method, payload):
            if url == account_url:
                raise intervention.policies.iam.CloudError(403)
            return response(url, token, method, payload)

        with (patch.object(transport, "_credential_document"), patch.object(transport, "validate_deploy_credentials")):
            report = preflight.read_deploy(env, ready, proof, reader=reader, policy_reader=denied,
                                          evaluate=self.evaluation, client_factory=Mock(return_value=client))
        self.assertEqual(report["status"], "blocked")
        self.assertTrue(any(row.get("resource") == account and row.get("http_status") == 403
                            and "getIamPolicy" in row.get("operation", "") for row in report["checks"]), report)

    def test_terraform_metadata_receipt_is_read_only_and_denial_binds_the_lock(self):
        decision = approved_decision({"action": "apt_preflight"})
        expected = backend.binding(hosted_env(), decision, DIGEST)
        state = {**expected["state"], "size": str(expected["state"]["size"])}
        with patch.object(backend.jobs, "request_json", side_effect=[state, None, state]) as api:
            proof = backend.observe(TOKEN, expected, opener=object())
        self.assertEqual(proof["identity"], backend.jobs.TERRAFORM)
        self.assertEqual(proof["lock"]["http_status"], 404)
        self.assertFalse(proof["state_content_read"])
        self.assertFalse(proof["lock_acquired"])
        self.assertEqual([entry.args[2] for entry in api.call_args_list], ["GET"] * 3)
        self.assertTrue(all("alt=media" not in entry.args[3] for entry in api.call_args_list))
        with (patch.object(backend.jobs, "request_json", side_effect=[state, ValueError("cloud_http_403")]) as blocked,
              self.assertRaises(transport.Failure) as stopped):
            backend.observe(TOKEN, expected, opener=object())
        self.assertEqual(blocked.call_count, 2)
        self.assertEqual(stopped.exception.receipt, {"operation": "storage.objects.get_metadata",
                         "resource": f"gs://{backend.scope.BUCKET}/{backend.jobs.LOCK_NAME}", "http_status": 403})

    def test_mixed_terraform_and_deploy_identity_never_reads_cloud(self):
        env, ready, proof, reader, policy_reader, _ = self.deployment_fixture()
        evaluate, client_factory = Mock(), Mock()
        with self.assertRaisesRegex(ValueError, "apt_preflight_deploy_scope"):
            preflight.read_deploy({**env, "GCP_TERRAFORM_SA": backend.jobs.TERRAFORM}, ready, proof,
                                  reader=reader, policy_reader=policy_reader, evaluate=evaluate, client_factory=client_factory)
        for remote in (reader, policy_reader, evaluate, client_factory):
            remote.assert_not_called()

    def test_installation_authority_cannot_substitute_for_read_decision(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        installation = approved_decision({"action": "apt_upgrade", "payload_sha256": DIGEST}, operation="guest_intervention")
        raw = transport.canonical(installation)
        decision = root / "decision.json"
        decision.write_bytes(raw)
        decision.chmod(0o600)
        digest = transport.sha(raw)
        with (patch.object(transport, "_local_bytes", side_effect=lambda file, _: file.read_bytes()),
              patch.object(shared.gate, "main") as gate,
              self.assertRaisesRegex(ValueError, "demo_a_closed_owner_decision")):
            preflight.validate_local(hosted_env(digest), root, digest, DIGEST, DIGEST, protected=True)
        gate.assert_not_called()

    def test_read_authority_matches_credential_runner_without_approval_for_apt_installation(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        config = (intervention.ROOT / intervention.policies.CONFIG).read_bytes()
        snapshot = {"instance_id": intervention.apt.INSTANCE, "data_disk_id": intervention.apt.DATA_DISK}
        deploy = {"schema": "synthetic receipt verified separately by expected_policy"}
        native = {"schema": "clipforge-int-demo-a-native-iam-receipt-1", "controls_commit": preflight.ORIGIN,
                  "deployment_phase": backend.scope.PROTECTED_RUNTIME, "backend_generation": backend.scope.STATE["generation"],
                  "noble_policies": deploy, "iap_policy": None, "protected_runtime_apply": None}

        def store(name, value):
            path = root / name
            raw = transport.canonical(value)
            path.write_bytes(raw)
            path.chmod(0o600)
            return transport.sha(raw)

        deploy_sha = store("deploy-policy-receipt.json", deploy)
        binding_sha = store("binding.json", {"operation": "apt_preflight", "state_generation": backend.scope.STATE["generation"]})
        review_sha = store("review.json", {"operation": "apt_preflight", "fixture": True})

        for producer, valid in ((preflight.ORIGIN, True), (COMMIT, False)):
            with self.subTest(producer=producer):
                native_sha = store("native-iam-receipt.json", {**native, "controls_commit": producer})
                inputs = {"action": "apt_preflight", "snapshot_sha256": transport.sha(transport.canonical(snapshot)),
                          "policy_config_sha256": transport.sha(config), "deploy_policy_receipt_sha256": deploy_sha,
                          "native_iam_receipt_sha256": native_sha}
                authority = approved_decision(inputs, review_sha256=review_sha, binding_sha256=binding_sha)
                decision_sha = store("decision.json", authority)
                env = {**hosted_env(decision_sha), "INT_NOBLE_INTERVENTION_REVIEW_SHA256": review_sha,
                       "INT_NOBLE_INTERVENTION_BINDING_SHA256": binding_sha}
                with (patch.multiple(preflight, DEPLOY_RECEIPT=deploy_sha, NATIVE_RECEIPT=native_sha),
                      patch.object(transport, "_local_bytes", side_effect=lambda file, _: file.read_bytes()),
                      patch.object(shared.gate, "main", return_value=0) as gate,
                      patch.object(intervention, "read", return_value=b"previous retained bytes"),
                      patch.object(preflight.handoff, "checked_inputs", return_value=({"candidate": {}}, {"control_plane": snapshot})),
                      patch.object(preflight.policies, "expected_policy", return_value={"fixture": "checked direct policies"})):
                    if valid:
                        checked = preflight.validate_local(env, root, decision_sha, review_sha, binding_sha, protected=True)
                        self.assertEqual(checked["decision"], authority)
                        self.assertEqual(checked["snapshot"], snapshot)
                        self.assertNotIn("executable", checked)
                    else:
                        with self.assertRaisesRegex(ValueError, "apt_preflight_original_iam_receipt_binding"):
                            preflight.validate_local(env, root, decision_sha, review_sha, binding_sha, protected=True)
                gate.assert_called_once()
                argv = gate.call_args.args[0]
                self.assertIn("--match-credential-runner", argv)
                self.assertEqual(argv[argv.index("--operation") + 1], "apt_preflight")
                self.assertNotIn("--guest-action", argv)

    def test_unknown_workflow_selector_cannot_start_review_or_admission(self):
        with (patch.object(shared, "local_decision") as decision,
              self.assertRaisesRegex(ValueError, "apt_preflight_exact_selector")):
            preflight.validate_local({**hosted_env(), "INT_NOBLE_OPERATION": "unexpected"}, Path("fixture"), DIGEST, DIGEST, DIGEST,
                                     protected=True)
        decision.assert_not_called()

    def test_deploy_admission_refuses_to_recreate_missing_checkpoint_without_credentials(self):
        root = Path(self.enterContext(TemporaryDirectory()))
        actual = runner_record("apt_preflight")
        same_boot = {"INT_DB_RUNNER_REQUIRE_EXISTING": "1"}
        with patch.object(runner, "observe", return_value=(root, actual)):
            runner.verify(actual["facts"], "apt_preflight", {}, {})
            runner.verify(actual["facts"], "apt_preflight", same_boot, {})
            checkpoint, = root.iterdir()
            checkpoint.unlink()
            with self.assertRaisesRegex(ValueError, "db_runner_missing_preauth_checkpoint"):
                runner.verify(actual["facts"], "apt_preflight", same_boot, {})
        self.assertEqual(list(root.iterdir()), [])

    def test_protected_workflow_keeps_both_host_fences_and_owns_a_distinct_read_step(self):
        source = (intervention.ROOT / intervention.WORKFLOW).read_text(encoding="utf-8")
        local, protected = source.split("\n  intervene:\n", 1)
        self.assertIn("on:\n  workflow_call:", local)
        self.assertNotIn("workflow_dispatch:", local)
        self.assertIn("if: ${{ false }}", local)
        self.assertIn('case "$INT_NOBLE_OPERATION" in', local)
        self.assertRegex(local, r"(?m)^ +\*\) exit 2 ;;")
        self.assertNotIn("id-token: write", local)
        self.assertRegex(protected, r"(?m)^    environment: int$")
        self.assertEqual(len(re.findall(r"(?m)^    environment: int$", source)), 1)
        steps = workflow_steps(protected)
        terraform = step(steps, "Federate as the existing Terraform identity for one metadata observation")
        deploy = step(steps, "Federate solely as the existing Deploy service account")
        initial = [item for item in steps if " protected-local --bundle " in item and "--backend-observation" not in item]
        switch = [item for item in steps if " protected-local --bundle " in item and "--backend-observation" in item]
        reads = [item for item in steps if " read --bundle " in item]
        self.assertEqual([len(initial), len(switch), len(reads)], [1, 1, 1])
        self.assertLess(steps.index(initial[0]), steps.index(terraform))
        self.assertLess(steps.index(terraform), steps.index(switch[0]))
        self.assertLess(steps.index(switch[0]), steps.index(deploy))
        self.assertLess(steps.index(deploy), steps.index(reads[0]))
        self.assertNotIn("INT_DB_RUNNER_REQUIRE_EXISTING", initial[0])
        self.assertRegex(switch[0], r"(?m)^ +INT_DB_RUNNER_REQUIRE_EXISTING: .*inputs\.operation == 'apt_preflight'.*'1'")
        self.assertRegex(reads[0], r"(?m)^        if: .*inputs\.operation == 'apt_preflight'")
        self.assertIn("steps.auth.outputs.access_token", reads[0])
        self.assertNotIn("steps.backend-auth.outputs.access_token", reads[0])
        self.assertNotIn("secrets.", reads[0])
        for command in ("run", "cleanup"):
            routes = [item for item in steps if re.search(rf'"\$OPERATOR_MODULE" {command}(?: |\n)', item)]
            self.assertEqual(len(routes), 1)
            self.assertRegex(routes[0], r"(?m)^        if: .*inputs\.operation != 'apt_preflight'")
