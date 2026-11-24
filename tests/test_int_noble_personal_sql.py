"""Directed fixtures for the new SQL/transport boundary."""

from datetime import datetime, timezone
from pathlib import Path
import stat
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch, Mock

from scripts import int_noble_personal_sql_guest as guest
from scripts import int_noble_personal_sql_contract as transport
from scripts import int_noble_personal_sql as workflow


SQL = transport.ROOT / "personal_sql"
BOOT = "12345678-1234-1234-1234-123456789abc"
COMMIT = "c" * 40
CA = "a" * 64
VERIFIER = "SCRAM-SHA-256$4096:" + "A" * 22 + "==$" + "B" * 43 + "=:" + "C" * 43 + "="
ACTIVE = {"login": True, "verifier_present": True, "scram": True, "connect": True, "view_usage": True,
          "sessions": 0, "view_select": guest.VIEWS, "activation_marker": None}
REVOKED = {"login": False, "verifier_present": False, "scram": False, "connect": False, "view_usage": False,
           "sessions": 0, "view_select": [], "activation_marker": None}


def intent_fixture(name, value):
    return {"name": name, "generation": "1795187957112199", "size": len(value), "sha256": transport.digest(value)}


def inputs():
    objects = {}
    registry = "2" * 64
    state = {"name": transport.STATE, "generation": "1795187957111160", "size": 183000, "current_lock_absent": True}
    success = "configured_guest_verified_external_acceptance_pending"
    checks = ("identity_verified", "mount_verified", "configuration_verified", "roles_verified",
              "local_tls_handshake_verified", "boot_persistence_configured")
    objects["bootstrap"] = {"schema": "clipforge-int-noble-bootstrap-result-1", "status": success,
                            "operation_id": "e" * 32, "phases": [{"phase": "postcheck", "status": "completed"}],
                            "guest_receipt": {"disk_id": guest.TARGET["data_disk_id"], "guest_boot_id": BOOT, "status": success,
                                              "phase": "guest_verified", "exit_code": 0, "operator_sha256": workflow.jobs.payloads.GUEST_SHA,
                                              "operation_id": "e" * 32, "checks": dict.fromkeys(checks, True)},
                            "ca_certificate_sha256": CA, "cleanup": {"status": "own_key_removed"}}
    pinned = lambda key: transport.digest(guest.canonical(objects[key]))
    objects["tls"] = {"status": "verified", "mode": "verify-full", "host": "10.80.1.3", "public_ca_sha256": CA,
                      "bootstrap_receipt_sha256": pinned("bootstrap")}
    objects["apply"] = {"schema": "clipforge-int-demo-a-result-2", "status": "applied_verified",
                        "phase": "apply", "controls_commit": COMMIT, "run": "1",
                        "plan_sha256": "7" * 64, "state_before_generation": "1795187957111158",
                        "deployment_phase": "human_access", "managed_count": 59,
                        "iap_verified": True, "firewall_verified": True, "bootstrap_receipt_sha256": pinned("bootstrap"),
                        "state_after": state, "publication_receipt_sha256": registry}
    refs = {key: pinned(key) for key in ("bootstrap", "tls", "apply")}
    for phase, job in transport.JOBS.items():
        name = transport.PREFIX + job
        row = {"schema": "clipforge-int-noble-job-result-1", "status": "execution_verified", "phase": phase, "action": "run",
               "job": name, "effect": transport.JOB_EFFECTS[phase], "execution": name + "/executions/" + job + "-placeholder",
               "receipts": dict(refs), "backend_observation": {"state": {key: state[key] for key in ("name", "generation", "size")}}}
        row["backend_observation_sha256"] = workflow.jobs.digest(workflow.jobs.canonical(row["backend_observation"]))
        if phase == "migrate":
            row["database_revisions"] = transport.REVISIONS
        if phase in {"app", "admin"}:
            row["receipts"]["migration"] = pinned("migrate")
        if phase == "admin":
            row["receipts"]["acceptance"] = pinned("app")
        objects[phase] = row
    return objects


class PersonalSql(unittest.TestCase):
    def setUp(self):
        self.assets = {key: (SQL / name).read_bytes() for key, (name, _) in transport.SQL_PINS.items()}
        self.executable = transport.payload(SQL)
        self.scope = {**guest.TARGET, "guest_boot_id": BOOT}
        self.artifacts = {key: guest.canonical(value) for key, value in inputs().items()}
        self.backend = {"name": transport.STATE, "generation": "1795187957111160", "current_lock_absent": True}
        self.now = datetime.fromisoformat("2026-11-23T19:30:00+00:00")
        self.key = "ssh-ed25519 fixture-key"
        self.fingerprint = "fixture-fingerprint"
        self.profile = "users/fixture"
        now_us = int(self.now.timestamp() * 1_000_000)
        self.origin = workflow.activation_origin(
            {"GITHUB_RUN_ID": "51", "GITHUB_RUN_ATTEMPT": "1"},
            {"import_attempted": True, "key_absent_before_import": True, "fingerprint": self.fingerprint,
             "profile_name": self.profile, "public_key": self.key, "created_us": now_us - 1_000_000,
             "expiration_us": now_us + 899_000_000}, "f" * 64)
        self.references = {}
        self.authority = {"schema": transport.AUTHORITY, **guest.TARGET, "action": "activate", "operation_id": "a" * 32,
                          "owner": "admin@ixbalam.studio", "owner_approval_ref": "fixture.local/owner", "approved_commit": COMMIT,
                          "valid_from": "2026-11-23T19:29:00+00:00", "expires": "2026-11-23T19:40:00+00:00",
                          "payload_sha256": transport.digest(self.executable), "snapshot_sha256": transport.digest(guest.canonical(self.scope)),
                          "evidence": {key: transport.digest(raw) for key, raw in self.artifacts.items()}}

    def admit(self, *, preserve_pins=False, backend=None, sha=None, commit=COMMIT, now=None, details=False):
        if not preserve_pins:
            self.authority["evidence"] = {key: transport.digest(raw) for key, raw in self.artifacts.items()}
        raw = guest.canonical(self.authority)
        result = transport.admission_details(raw, sha or transport.digest(raw), self.executable, self.artifacts,
                                              self.scope, backend or self.backend, commit, now or self.now,
                                              references=self.references)
        return result if details else result[0]

    def guest_activate(self, request):
        code, result = guest.main(guest.canonical({**guest.decode(request), "verifier": VERIFIER}),
                                  transport.digest(self.executable), self.assets,
                                  identity=lambda boot, ca: self.assertEqual((boot, ca), (BOOT, CA)),
                                  execute=lambda _: guest.canonical({**ACTIVE, "activation_marker": guest.activation_marker(guest.decode(request))}))
        self.assertEqual(code, 0)
        return result

    def test_live_scope_validates_pins_lock_generation_and_commit(self):
        self.assertEqual(guest.decode(self.admit())["boot_id"], BOOT)
        for options in ({"backend": {**self.backend, "current_lock_absent": False}},
                        {"backend": {**self.backend, "generation": "42"}},
                        {"sha": "7" * 64}, {"commit": "2" * 40},
                        {"now": datetime(2026, 11, 23, 19, 39, tzinfo=timezone.utc)}):
            with self.subTest(options=options), self.assertRaises(guest.Blocked):
                self.admit(**options)

    def test_ca_and_native_job_predecessor_order_are_required(self):
        original = self.artifacts.copy()
        for key, bad in (("tls", {"public_ca_sha256": "7" * 64}), ("migrate", {"database_revisions": []}),
                         ("admin", {"status": "rbac_failed"}), ("apply", {"managed_count": 58})):
            with self.subTest(key=key):
                self.artifacts = original.copy()
                self.artifacts[key] = guest.canonical({**guest.decode(original[key]), **bad})
                with self.assertRaises(guest.Blocked):
                    self.admit()

    def test_sql_has_one_transaction_and_exact_scope(self):
        request = guest.decode(self.admit())
        body = guest.prepare_sql({**request, "verifier": VERIFIER}, self.assets)
        self.assertEqual(body.count(b"BEGIN;"), 1)
        self.assertEqual(body.count(b"COMMIT;"), 1)
        self.assertIn(self.assets["acl"], body)
        self.assertIn(b"RESET ROLE", body)
        self.assertLess(body.index(b"unexpected_personal_sequence_or_function_acl"), body.index(b"ALTER ROLE aldemaro_int LOGIN"))
        self.assertLess(body.index(b"COMMENT ON ROLE aldemaro_int"), body.index(b"COMMIT;"))
        self.assertIn(b"CREATE VIEW clipforge_inspect.workspaces", body)

    def test_guest_compares_public_ca_bytes_after_boot_and_mount(self):
        dev = Mock()
        dev.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFLNK, st_uid=0)
        dev.stat.return_value = SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=42)
        mount = Mock()
        mount.stat.return_value = SimpleNamespace(st_dev=42)
        ca = Mock()
        ca.lstat.return_value = SimpleNamespace(st_mode=stat.S_IFREG, st_size=11)
        ca.read_bytes.return_value = b"test public"
        boot = Mock()
        boot.read_text.return_value = BOOT
        with patch.object(guest, "BY_ID", dev), patch.object(guest, "MOUNT", mount), patch.object(guest, "CA_FILE", ca), \
                patch.object(guest, "BOOT", boot), patch.object(guest.os, "geteuid", return_value=0, create=True), \
                patch.object(guest.os.path, "ismount", return_value=True):
            guest.check_target(BOOT, transport.digest(b"test public"))
            with self.assertRaisesRegex(guest.Blocked, "guest_noble_public_ca_changed"):
                guest.check_target(BOOT, CA)

    def test_activation_result_is_sanitized_and_intent_precedes_single_stdin(self):
        request = self.admit()
        events = []
        expected = guest.canonical(self.guest_activate(request))

        class Process:
            def invoke(self, port, executable, sha, packet):
                self_packet = guest.decode(packet)
                assert port == 22 and transport.digest(executable) == sha
                assert self_packet["verifier"] == VERIFIER
                events.append("ssh")
                return 0, expected, b"ignored"

        def record(name, raw):
            obj = guest.decode(raw)
            self.assertEqual(obj["status"], "intended_once")
            self.assertEqual(obj["origin"], self.origin)
            self.assertNotIn("verifier", obj)
            self.assertNotIn(VERIFIER.encode(), guest.canonical(obj))
            events.append("intent")
            return intent_fixture(name, raw)

        password = "synthetic_only-" * 3
        outcome = transport.protected_invocation(Process(), 22, self.executable, request, record, password,
                                                 render_verifier=lambda _: VERIFIER, origin=self.origin)
        self.assertEqual(events, ["intent", "ssh"])
        self.assertNotIn(VERIFIER.encode(), guest.canonical(outcome))
        self.assertNotIn(password.encode(), guest.canonical(outcome))
        with self.assertRaises(guest.Blocked):
            transport.verified_terminal(outcome, self.scope, self.scope, self.backend, {"status": "unconfirmed"})
        self.assertEqual(transport.verified_terminal(outcome, self.scope, self.scope, self.backend, {"status": "own_key_removed"})["status"],
                         "completed_verified")

    def test_failed_intent_and_native_uncertainty_do_not_repeat(self):
        request = self.admit()
        called = []

        class Failed:
            def invoke(self, *_):
                called.append(1)
                return 255, b"", b"private stderr"

        def before(*_):
            raise guest.Blocked("unconfirmed_create")

        password = "synthetic_only-" * 3
        for record in (before, lambda *_: None, intent_fixture):
            with self.assertRaises(guest.Blocked):
                transport.protected_invocation(Failed(), 22, self.executable, request, record, password,
                                               render_verifier=lambda _: VERIFIER, origin=self.origin)
        self.assertEqual(called, [1])

    def test_revoke_only_uses_verified_own_activation_and_zero_sessions(self):
        prior = self.guest_activate(self.admit())
        self.authority["action"] = "revoke"
        with self.assertRaisesRegex(guest.Blocked, "personal_predecessor_set"):
            self.admit()
        self.artifacts["activation"] = guest.canonical({"status": "completed_verified", "cleanup": "own_key_removed", "guest": prior})
        request = self.admit()
        sql = guest.prepare_sql(guest.decode(request), self.assets)
        self.assertIn(b"pg_terminate_backend", sql)
        self.assertLess(sql.index(b"personal_activation_marker_changed"), sql.index(b"ALTER ROLE aldemaro_int NOLOGIN"))
        self.assertLess(sql.index(b"COMMENT ON ROLE aldemaro_int IS NULL"), sql.index(b"COMMIT;"))
        for sessions, exit_code in ((1, 1), (0, 0)):
            code, result = guest.main(request, transport.digest(self.executable), self.assets, identity=lambda _boot, _ca: None,
                                      execute=lambda _: b"t\n" + guest.canonical({**REVOKED, "sessions": sessions}))
            self.assertEqual(code, exit_code, result)

    def test_observation_neither_writes_sql_nor_registers_mutation_intent(self):
        self.authority["action"] = "observe"
        request = self.admit()
        sql = guest.prepare_sql(guest.decode(request), self.assets)
        self.assertTrue(sql.startswith(b"BEGIN READ ONLY;\n"))
        self.assertNotIn(b"ALTER ROLE", sql)
        code, result = guest.main(request, transport.digest(self.executable), self.assets,
                                  identity=lambda *_: None, execute=lambda _: guest.canonical(ACTIVE))
        processes = Mock()
        processes.invoke.return_value = (code, guest.canonical(result), b"")
        create = Mock()
        outcome = transport.protected_invocation(processes, 22, self.executable, request, create)
        create.assert_not_called()
        self.assertIsNone(outcome["intent"])
        self.assertEqual(outcome["guest"]["status"], "observed")

    def add_artifact(self, key, name, value):
        raw = guest.canonical(value)
        self.artifacts[key] = raw
        self.references[key] = intent_fixture(name, raw)

    def lost_activation(self, partial_status):
        packet = self.admit()
        activation, scope = self.guest_activate(packet), guest.decode(packet)
        marker = activation["observation"]["activation_marker"]
        intent_name = f"{transport.PRIVATE_ROOT}{COMMIT}/decisions/{scope['operation_id']}/personal-sql-intent.json"
        self.add_artifact("activation_intent", intent_name, {**scope, "status": "intended_once", "origin": self.origin})
        if partial_status:
            intent = self.references["activation_intent"]
            partial = {"schema": transport.RESULT, "status": partial_status, "action": "activate",
                       "operation_id": scope["operation_id"], "run": self.origin["run"], "control_commit": COMMIT,
                       "request_sha256": transport.digest(packet), "sql_started": True, "retry_authorized": False,
                       "decision_sha256": self.origin["decision_sha256"], "intent": intent}
            if partial_status == "guest_cleanup_pending_reconcile":
                partial["outcome"] = {"guest": activation, "intent": intent}
            self.add_artifact("activation_partial", transport.receipt_name(COMMIT, self.origin["run"]), partial)
        self.authority.update(action="observe", operation_id="b" * 32)
        return marker

    def observe_and_finalize_recovery(self, request, recovery, marker):
        def read(sql):
            self.assertTrue(sql.startswith(b"BEGIN READ ONLY;"))
            self.assertNotIn(b"ALTER ROLE", sql)
            return guest.canonical({**ACTIVE, "activation_marker": marker})

        code, observation = guest.main(request, transport.digest(self.executable), self.assets, identity=lambda *_: None,
                                       execute=read)
        self.assertEqual(code, 0)
        processes = Mock()
        processes.invoke.return_value = (code, guest.canonical(observation), b"")
        create = Mock()
        outcome = transport.protected_invocation(processes, 22, self.executable, request, create)
        create.assert_not_called()
        env = {"GITHUB_RUN_ID": "52", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": COMMIT, "GCP_ACCESS_TOKEN": "fixture"}
        decision = {"operation_id": observation["operation_id"], "inputs": {"action": "observe"}}
        state = {key: value for key, value in {**self.backend, "size": 183000}.items() if key != "current_lock_absent"}
        ready = {"decision": decision, "request": request, "state": state, "references": self.references}
        binding = workflow.backend_binding(env, ready, "f" * 64, "after")
        proof = {**binding, **dict.fromkeys(("started_utc", "lock_observed_utc", "completed_utc"), self.now.isoformat())}
        draft = {"schema": workflow.SCHEMA, "status": "guest_verified_pending_backend", "action": "observe",
                 "decision_sha256": "f" * 64, "operation_id": observation["operation_id"], "retry_authorized": False,
                 "run": "52", "control_commit": COMMIT, "cleanup_status": "own_key_removed", "recovery": recovery,
                 "original_key_withdrawal": {**self.origin["key"], "status": transport.ABSENT}, "observed_utc": self.now.isoformat(),
                 "request_sha256": transport.digest(request), "outcome": outcome, "before": guest.TARGET, "after": guest.TARGET}
        cloud = Mock()
        written = {}

        def store(name, document):
            written["value"] = name, guest.decode(workflow.transport.canonical(document))
            return {"name": name}

        cloud.return_value.create.side_effect = store
        with (TemporaryDirectory() as path, patch.object(workflow.channel, "now_utc", return_value=self.now),
              patch.object(workflow.transport, "_credential_document", return_value={}),
              patch.object(workflow.transport, "validate_deploy_credentials")):
            root = Path(path)
            workflow.write_private(root / "personal-sql-pending.json", draft)
            workflow.finalize(env, ready, proof, binding, root, root, make_custody=cloud)
        return written["value"]

    def test_partial_activation_reconciles_without_replay_and_then_qualifies_revoke(self):
        for partial in (None, "guest_outcome_unknown_reconcile", "guest_cleanup_pending_reconcile"):
            with self.subTest(partial=partial):
                self.setUp()
                marker = self.lost_activation(partial)
                request, recovery = self.admit(details=True)
                name, observed = self.observe_and_finalize_recovery(request, recovery, marker)
                self.assertEqual(observed["status"], transport.RECOVERED)
                self.assertEqual(observed["guest"]["status"], "observed")
                self.assertIsNone(observed["intent"])
                self.assertEqual(observed["recovery"]["intent"], self.references["activation_intent"])
                self.authority.update(action="revoke", operation_id="d" * 32)
                self.add_artifact("activation_observation", name, observed)
                self.assertEqual(guest.decode(self.admit())["activation_marker"], marker)
                # An ordinary observer or a changed target cannot satisfy the evidence.
                self.add_artifact("activation_observation", name, {**observed, "status": "completed_verified"})
                with self.assertRaisesRegex(guest.Blocked, "personal_reconciled_activation_receipt"):
                    self.admit()
                observed["guest"]["boot_id"] = "12345678-1234-1234-1234-123456789000"
                self.add_artifact("activation_observation", name, observed)
                with self.assertRaisesRegex(guest.Blocked, "personal_reconciled_guest_receipt"):
                    self.admit()

    def test_reconciliation_rejects_partial_from_another_run(self):
        self.lost_activation("guest_outcome_unknown_reconcile")
        original = guest.decode(self.artifacts["activation_partial"])
        self.add_artifact("activation_partial", transport.receipt_name(COMMIT, "123"), {**original, "run": "123"})
        with self.assertRaisesRegex(guest.Blocked, "personal_partial_activation_result"):
            self.admit()

    def test_reconciliation_cannot_omit_retained_result_or_open_another_key(self):
        self.lost_activation(None)
        request, recovery = self.admit(details=True)
        env = {"GITHUB_RUN_ID": "52", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": COMMIT, "GCP_ACCESS_TOKEN": "fixture",
               "INT_DEMO_A_PROTECTED_DECISION_SHA256": "f" * 64}
        ready = {"request": request, "snapshot": self.scope, "decision": {}}
        cloud, start_channel, client = Mock(), Mock(), Mock()
        cloud.return_value.require_absent.side_effect = ValueError("demo_a_custody_existing_intent_requires_reconciliation")
        with (TemporaryDirectory() as path, patch.object(workflow, "native_readbacks", return_value=recovery),
              patch.object(workflow.backend, "verify"), patch.object(workflow.bootstrap, "check_window")):
            root = Path(path)
            with self.assertRaisesRegex(ValueError, "demo_a_custody_existing_intent_requires_reconciliation"):
                workflow.launch(env, ready, {}, {}, root, root, apply=b"fixture", make_custody=cloud,
                                check_cloud=Mock(return_value=(guest.TARGET, client, None)), start_channel=start_channel)
        cloud.assert_called_with("fixture", names=(recovery["original_result_name"],))
        cloud.return_value.require_absent.assert_called_once_with(recovery["original_result_name"])
        start_channel.assert_not_called()
        client.profile.assert_not_called()

    def test_original_key_withdrawal_requires_exact_live_profile(self):
        client = Mock()
        key = self.origin["key"]
        client.profile.return_value = {"name": self.profile, "sshPublicKeys": {"unrelated-fingerprint": {"key": "ssh-ed25519 unrelated"}}}
        self.assertEqual(workflow.verify_original_key_withdrawal(client, key), {**key, "status": transport.ABSENT})
        for fingerprint, value in ((self.fingerprint, "ssh-ed25519 unrelated"),
                                   ("unrelated-fingerprint", self.key + " reimported")):
            client.profile.return_value["sshPublicKeys"] = {fingerprint: {"key": value}}
            with self.assertRaisesRegex(ValueError, "personal_original_key_still_present"):
                workflow.verify_original_key_withdrawal(client, key)
        client.profile.return_value["name"] = "users/different"
        with self.assertRaisesRegex(ValueError, "personal_original_deploy_profile_changed"):
            workflow.verify_original_key_withdrawal(client, key)
        client.delete_key.assert_not_called()

    def test_workflow_checks_native_names_generations_and_exact_bytes(self):
        prefix = workflow.custody.PREFIX + COMMIT + "/1-1/"
        names = {"bootstrap": prefix + "noble-bootstrap.json",
                 "apply": workflow.plans.PREFIX + COMMIT + "/1-1/manifest.json",
                 **{phase: workflow.custody.job_names(phase, "run")["result"] for phase in transport.JOBS}}
        refs = {key: intent_fixture(name, self.artifacts[key]) for key, name in names.items()}
        selected = workflow.receipt_references(refs, "activate")
        self.assertEqual(selected, refs)
        cloud = Mock()
        cloud.fetch.side_effect = lambda ref: next(self.artifacts[key] for key, value in refs.items() if value == ref)
        request = self.admit()
        raw_authority = guest.canonical(self.authority)
        state = {key: value for key, value in {**self.backend, "size": 183000}.items() if key != "current_lock_absent"}
        ready = {"decision": {"inputs": {"authority_sha256": transport.digest(raw_authority)}}, "tls": self.artifacts["tls"],
                 "references": refs, "state": state, "request": request, "snapshot": self.scope,
                 "executable": self.executable, "authority": raw_authority,
                 "review_binding": {"state_generation": "1795187957111158", "post_apply_generation": state["generation"],
                                    "plan_sha256": "7" * 64}}
        with patch.object(workflow.channel, "now_utc", return_value=self.now):
            workflow.native_readbacks(ready, cloud, self.artifacts["apply"], {"GITHUB_SHA": COMMIT}, {"state": state})
            self.assertEqual(cloud.fetch.call_count, 4)
            with self.assertRaisesRegex(ValueError, "personal_native_receipt_reference"):
                workflow.receipt_references({**refs, "app": refs["admin"]}, "activate")
            with self.assertRaisesRegex(ValueError, "personal_phase_two_review_reconciliation"):
                workflow.native_readbacks(ready, cloud, self.artifacts["apply"] + b"\n", {"GITHUB_SHA": COMMIT}, {"state": state})
            cloud.fetch.side_effect = None
            cloud.fetch.return_value = self.artifacts["bootstrap"]
            with self.assertRaisesRegex(guest.Blocked, "personal_predecessor_digest"):
                workflow.native_readbacks(ready, cloud, self.artifacts["apply"], {"GITHUB_SHA": COMMIT}, {"state": state})

    def test_post_backend_proof_is_distinct_and_preserves_primary_scope(self):
        env = {"GITHUB_RUN_ID": "1", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": COMMIT}
        request = self.admit()
        selected = guest.decode(request)
        decision = {"operation_id": selected["operation_id"], "inputs": {"action": "activate"}}
        state = {**self.backend, "size": 183000}
        del state["current_lock_absent"]
        ready = {"decision": decision, "request": request, "state": state}
        before = workflow.backend_binding(env, ready, "f" * 64, "before")
        after = workflow.backend_binding(env, ready, "f" * 64, "after")
        ages = {key: self.now.isoformat() for key in ("started_utc", "lock_observed_utc", "completed_utc")}
        prior, final = {**before, **ages}, {**after, **ages}
        cloud = Mock()
        with (TemporaryDirectory() as path, patch.object(workflow.channel, "now_utc", return_value=self.now),
              patch.object(workflow.transport, "_credential_document", return_value={}),
              patch.object(workflow.transport, "validate_deploy_credentials")):
            root = Path(path)
            data = {"schema": workflow.SCHEMA, "status": "guest_verified_pending_backend", "action": "activate",
                    "decision_sha256": "f" * 64, "operation_id": selected["operation_id"],
                    "run": "1", "control_commit": COMMIT, "cleanup_status": "own_key_removed",
                    "request_sha256": transport.digest(request), "outcome": {"guest": self.guest_activate(request), "intent": {}},
                    "before": guest.TARGET, "after": guest.TARGET}
            workflow.write_private(root / "personal-sql-pending.json", data)
            with self.assertRaisesRegex(ValueError, "intervention_backend_binding_changed"):
                workflow.finalize(env, ready, prior, after, root, root, make_custody=cloud)
            cloud.assert_not_called()
            cloud.return_value.create.return_value = {"name": "fixture"}
            report = workflow.finalize({**env, "GCP_ACCESS_TOKEN": "synthetic_fixture"}, ready, final, after, root, root,
                                       make_custody=cloud)
            self.assertEqual(report["status"], "completed_verified")
            result_name, result = cloud.return_value.create.call_args.args
            self.assertTrue(result_name.endswith("/1-1/personal-sql-result.json"))
            self.assertNotIn("outcome", result)
            self.assertNotIn(b"authority_sha256", (root / "personal-sql-result.json").read_bytes())


if __name__ == "__main__":
    unittest.main()
