"""Local controller regressions. Cloud responses and owner receipts are synthetic."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
import tempfile
import unittest
from urllib.error import HTTPError
from urllib.parse import parse_qs, unquote, urlsplit
from unittest.mock import Mock, patch

from scripts import int_db01_noble_jobs as jobs


NOW = datetime(2026, 11, 20, 16, 30, tzinfo=timezone.utc)
SHA = "a" * 40
ENV = {"GITHUB_SHA": SHA, "INT_APPROVED_COMMIT": SHA, "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1"}
SOURCE = Path(jobs.client.__file__).read_bytes()
SOURCES = [{"path": path, "sha256": sha} for path, sha in sorted(jobs.client.NOBLE_SOURCES.items())]
PROTECTED_GENERATION = str(int(jobs.scope.STATE["generation"]) + 1)
FINAL_GENERATION = str(int(PROTECTED_GENERATION) + 1)


class NobleJobs(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()

    def write(self, name, value):
        raw = jobs.canonical(value)
        (self.root / (name + ".json")).write_bytes(raw)
        return jobs.digest(raw)

    def published(self, image, config, archive, layers):
        leaf = image.split("@")[0].rsplit("/", 1)[1]
        return {"status": "published_and_verified", "source_controls": SHA, "run": "1", "target": image,
                "manifest": image.split("@")[1], "config": config, "archive_sha256": archive, "layers": list(layers),
                "operation_id": "2" * 32, "owner_decision_sha256": "8" * 64,
                "intent": {"name": jobs.receipts.PREFIX + SHA + "/decisions/" + "2" * 32 + f"/publication-{leaf}-intent.json",
                           "sha256": "5" * 64, "generation": "7", "size": 42}, "publisher_digest": "sha256:" + "4" * 64}

    def bundle(self, action="create", phase="migrate", *, version="2", migration=True, tls_host="10.80.1.3", apply_secret_sha=None,
               layers=None, acceptance=True):
        refs = {}
        scope = jobs.client.NOBLE_SCOPE
        refs["bootstrap"] = self.write("bootstrap", {"schema": "clipforge-int-noble-bootstrap-result-1", "status": jobs.SUCCESS,
            "cleanup": {"status": "own_key_removed"}, "operation_id": "9" * 32, "phases": [{"phase": "postcheck", "status": "completed"}],
            "guest_receipt": {"status": jobs.SUCCESS, "exit_code": 0, "phase": "guest_verified", "disk_id": scope["data_disk_id"],
                "operation_id": "9" * 32, "operator_sha256": jobs.payloads.GUEST_SHA,
                "checks": dict.fromkeys(("identity_verified", "mount_verified", "configuration_verified", "roles_verified",
                                         "local_tls_handshake_verified", "boot_persistence_configured"), True)}})
        refs["publication"] = self.write("publication", self.published(jobs.client.NOBLE_IMAGE, jobs.CONFIG, jobs.ARCHIVE,
                                                                     jobs.LAYERS if layers is None else layers))
        runtime = None
        if phase == "admin":
            runtime = self.published(jobs.admin_image(), jobs.ADMIN_CONFIG, jobs.ADMIN_ARCHIVE, jobs.ADMIN_LAYERS)
            refs["runtime-publication"] = self.write("runtime-publication", runtime)
        refs["secrets"] = self.write("secrets", {"status": "published_and_verified", "source_controls": SHA, "run": "2",
            "bootstrap_receipt_sha256": refs["bootstrap"], "versions": {key: {"secret": target, "version": version}
                                                                        for key, target in jobs.TARGETS.items()}})
        def private_ref(run, receipt_sha, size=312):
            return {"name": f"{jobs.int_release.PREFIX}{SHA}/{run}-1/manifest.json", "generation": "16", "sha256": receipt_sha, "size": size}

        state = {**jobs.scope.STATE, "generation": PROTECTED_GENERATION, "serial": jobs.scope.STATE["serial"] + 1, "sha256": "4" * 64, "size": 99}
        common = {"schema": "clipforge-int-demo-a-result-2", "phase": "apply", "status": "applied_verified", "controls_commit": SHA,
                  "firewall_verified": True, "iap_verified": True, "run_service": {"uid": "clipforge-api-id", "generation": "1"},
                  "bootstrap_receipt_sha256": refs["bootstrap"], "secret_receipt_sha256": apply_secret_sha or refs["secrets"],
                  "publication_receipt_sha256": refs.get("runtime-publication", "c" * 64)}
        prior = {**common, "deployment_phase": jobs.scope.PROTECTED_RUNTIME, "run": "21", "managed_count": 58, "state_after": state,
                 "state_before_generation": jobs.scope.STATE["generation"], "plan_sha256": "6" * 64, "plan_manifest": private_ref("20", "3" * 64)}
        prior_sha = self.write("protected-runtime-apply", prior)
        refs["protected-runtime-apply"] = prior_sha
        apply = {**common, "deployment_phase": jobs.scope.HUMAN_ACCESS, "run": "31", "managed_count": 59,
                 "state_after": {**state, "generation": FINAL_GENERATION, "serial": state["serial"] + 1, "sha256": "5" * 64},
                 "state_before_generation": PROTECTED_GENERATION, "plan_sha256": "7" * 64, "plan_manifest": private_ref("30", "4" * 64),
                 "protected_runtime_apply": private_ref("21", prior_sha, len(jobs.canonical(prior))), "protected_runtime_receipt_sha256": prior_sha}
        refs["apply"] = self.write("apply", apply)
        refs["tls"] = self.write("tls", {"status": "verified", "bootstrap_receipt_sha256": refs["bootstrap"], "host": tls_host,
            "mode": "verify-full", "secret_version": version, "secret_receipt_sha256": refs["secrets"], "public_ca_sha256": "5" * 64})
        if phase in {"app", "admin"} and migration:
            refs["migration"] = self.write("migration", {"schema": "clipforge-int-noble-job-result-1", "status": "execution_verified",
                "action": "run", "phase": "migrate", "database_revisions": jobs.MIGRATION_REVISIONS, "receipts": dict(refs)})
        binding = {"target": "noble", "guest_receipt_sha256": jobs.client.NOBLE_GUEST_RECEIPT_SHA256,
                   "bootstrap_receipt_sha256": refs["bootstrap"]}
        versions = {key: version if version.isdecimal() else "2" for key in jobs.TARGETS if key != "bootstrap_admin"}
        if phase == "admin":
            result = {"schema": "clipforge-int-noble-job-result-1", "status": "execution_verified", "action": "run",
                      "phase": "app", "effect": "tls_and_dml_without_data_changes", "receipts": dict(refs)}
            if acceptance:
                refs["acceptance"] = self.write("acceptance", result)
            spec = jobs.validate_admin_predecessors({"runtime-publication": runtime, "apply": apply, "acceptance": result},
                                                   refs, {**versions, "bootstrap_admin": version})
        else:
            spec = jobs.client.job_spec(phase, jobs.client.NOBLE_IMAGE, versions, SOURCES, source=SOURCE, **binding)
        definition_sha = jobs.digest(jobs.canonical(spec))
        issued, expires = NOW.isoformat(), (NOW + timedelta(minutes=30)).isoformat()
        value = {"schema": "clipforge-int-noble-jobs-decision-1", "status": "authorized_exact_noble_job_operation", "owner": "admin@ixbalam.studio",
                 "source_controls": SHA, "action": action, "phase": phase, "operation_id": "1" * 32, "issued_utc": issued,
                 "expires_utc": expires, "receipts": refs, "definition_sha256": definition_sha, "gate": "global"}
        if action == "run" and phase != "admin":
            refs["created"] = self.write("created", {"schema": "clipforge-int-noble-job-result-1", "status": "created_verified",
                "action": "create", "phase": phase, "job": spec["name"], "definition_sha256": definition_sha, "receipts": dict(refs),
                "uid": "job-fixture", "generation": "1", "etag": "job-etag"})
            refs["client-decision"] = self.write("client-decision", {"schema": "clipforge-db01-client-decision-2",
                "status": "authorized_specific_job_execution", "owner": value["owner"], "job": spec["name"].rsplit("/", 1)[1],
                "phase": phase, "operation_id": value["operation_id"], "source_sha256": jobs.SOURCE_SHA256, "image": jobs.client.NOBLE_IMAGE,
                "secret_versions": versions, "app_sources": SOURCES, "target": scope, "guest_receipt_sha256": binding["guest_receipt_sha256"],
                "bootstrap_receipt_sha256": refs["bootstrap"], "issued_utc": issued, "expires_utc": expires})
        sha = self.write("decision", value)
        return sha

    def ready(self, action="create", phase="migrate", **changes):
        return jobs.decision_bundle(self.root, self.bundle(action, phase, **changes), ENV, action, phase, now=NOW)

    def actual(self, spec):
        return {**deepcopy(spec), "uid": "job-fixture", "etag": "job-etag", "generation": "1", "observedGeneration": "1",
                "terminalCondition": {"state": "CONDITION_SUCCEEDED"}}

    def execute(self, transport, ready):
        binding, proof = self.backend_proof(ready)
        with patch.object(jobs, "verify_live_scope"), patch.object(jobs, "verify_permissions"):
            return jobs.execute(transport, ready, proof, binding, notice=Mock(), wait=Mock(), clock=lambda: NOW)

    def backend_proof(self, ready=None):
        decision, _, _, _, applied = ready or self.ready()
        binding = jobs.backend_binding(ENV, decision, applied, "7" * 64)
        proof = {**binding, "lock_observed_utc": NOW.isoformat(), "completed_utc": NOW.isoformat(), "legacy_intent_http_status": 404}
        return binding, proof

    def http_error(self, status):
        error = HTTPError("https://storage.googleapis.com/", status, "fixture", {}, BytesIO())
        self.addCleanup(error.close)
        return error

    def test_terraform_observation_reads_exact_metadata_and_brackets_the_lock(self):
        binding, proof = self.backend_proof()
        state = {**binding["state"], "size": "99"}
        opener = Mock()
        opener.open.side_effect = [self.http_error(404), BytesIO(jobs.canonical(state)), self.http_error(404), BytesIO(jobs.canonical(state))]
        result = jobs.observe_backend("fake-terraform-token", binding, opener=opener, clock=lambda: NOW)
        self.assertEqual(result, proof)
        self.assertEqual([(call.args[0].method, unquote(urlsplit(call.args[0].full_url).path).rsplit("/o/", 1)[1],
                           parse_qs(urlsplit(call.args[0].full_url).query)) for call in opener.open.call_args_list], [
            ("GET", "private-plans/int/noble-jobs/migrate/create/intent.json", {"fields": ["name"]}),
            ("GET", jobs.STATE_NAME, {"fields": ["name,generation,size"]}),
            ("GET", jobs.LOCK_NAME, {"fields": ["name"]}),
            ("GET", jobs.STATE_NAME, {"fields": ["name,generation,size"]}),
        ])

    def test_backend_observation_blocks_legacy_intent_lock_and_generation_drift(self):
        binding, _ = self.backend_proof()
        state = {**binding["state"], "size": "99"}
        for changed in ("legacy", "lock", "generation", "forbidden_lock"):
            with self.subTest(changed=changed):
                responses = [None, state, None, state.copy()]
                if changed == "legacy":
                    responses[0] = {"name": "existing"}
                elif changed == "lock":
                    responses[2] = {"name": jobs.LOCK_NAME}
                elif changed == "generation":
                    responses[3]["generation"] = "100"
                else:
                    responses[2] = self.http_error(403)
                opener = Mock()
                opener.open.side_effect = [self.http_error(404) if value is None else
                                           BytesIO(jobs.canonical(value)) if isinstance(value, dict) else value for value in responses]
                with self.assertRaisesRegex(ValueError, "legacy_noble_job_intent|apply_backend_or_lock_changed|cloud_http_403"):
                    jobs.observe_backend("fake-terraform-token", binding, opener=opener, clock=lambda: NOW)

    def test_backend_proof_rejects_foreign_identity_execution_attempt_and_scope(self):
        binding, proof = self.backend_proof()
        for key, value in (("identity", jobs.DEPLOY), ("run", "124"), ("attempt", "2"), ("phase", "admin"),
                           ("operation_id", "4" * 32), ("controls_commit", "4" * 40), ("decision_sha256", "0" * 64),
                           ("apply_receipt_sha256", "0" * 64), ("state", {**proof["state"], "generation": "100"}),
                           ("lock", {**proof["lock"], "http_status": 200})):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "job_backend_observation_binding"):
                jobs.verify_backend_observation({**proof, key: value}, binding, now=NOW)
        with self.assertRaisesRegex(ValueError, "invalid_backend_observation_dispatch"):
            ready = self.ready()
            jobs.backend_binding({**ENV, "GITHUB_RUN_ATTEMPT": "2"}, ready[0], ready[4], "7" * 64)

    def test_stale_or_future_proof_stops_before_deploy_calls(self):
        ready = self.ready()
        binding, proof = self.backend_proof(ready)
        transport = Mock()
        for at in (NOW - timedelta(seconds=1), NOW + jobs.MAX_BACKEND_AGE + timedelta(seconds=1)):
            with self.subTest(at=at), self.assertRaisesRegex(ValueError, "job_backend_observation_expired_or_future"):
                jobs.execute(transport, ready, proof, binding, notice=Mock(), clock=lambda: at)
        self.assertFalse(transport.mock_calls)

    def test_expiry_after_intent_preserves_marker_and_blocks_run_post(self):
        ready = self.ready()
        binding, proof = self.backend_proof(ready)
        transport = Mock()
        transport.call.return_value = None
        notice = Mock()
        read_clock = Mock(side_effect=[NOW, NOW, NOW + jobs.MAX_BACKEND_AGE + timedelta(seconds=1)])
        with patch.object(jobs, "verify_live_scope"), patch.object(jobs, "verify_permissions"), \
                self.assertRaisesRegex(ValueError, "job_backend_observation_expired_or_future"):
            jobs.execute(transport, ready, proof, binding, notice=notice, clock=read_clock)
        transport.call.assert_called_once()
        transport.retain.assert_called_once()
        self.assertEqual(notice.call_args.args[0]["status"], "intent_recorded")

    def test_deploy_cannot_use_job_transport_for_backend_or_lock(self):
        transport = jobs.Transport("f" * 32, "migrate", "create")
        with patch.object(jobs, "request_json") as request:
            for path in (jobs.STATE_NAME, jobs.LOCK_NAME):
                with self.assertRaisesRegex(ValueError, "deploy_job_api_scope"):
                    transport.call("GET", f"https://storage.googleapis.com/storage/v1/b/{jobs.BUCKET}/o/{path}")
            request.assert_not_called()

    def test_workflow_serializes_with_state_and_keeps_credentials_in_separate_steps(self):
        workflow = (jobs.ROOT / jobs.WORKFLOW).read_text(encoding="utf-8")
        public, protected = workflow.split("  protected-operation:\n", 1)
        self.assertIn("group: clipforge-int-protected-operations", public)
        self.assertNotIn("id-token: write", public)
        self.assertIn("environment: int", protected)
        self.assertIn("group: clipforge-int-terraform-state", protected)
        tf_auth, deploy_auth = protected.split("      - name: Federate as existing Deploy", 1)
        self.assertIn("service_account: ${{ vars.GCP_TERRAFORM_SA }}", tf_auth)
        self.assertIn("GCP_ACCESS_TOKEN: ${{ steps.backend-auth.outputs.access_token }}", tf_auth)
        self.assertIn("service_account: ${{ vars.GCP_DEPLOY_SA }}", deploy_auth)
        self.assertIn("GCP_ACCESS_TOKEN: ${{ steps.auth.outputs.access_token }}", deploy_auth)
        self.assertNotIn("steps.backend-auth.outputs.access_token", deploy_auth)
        self.assertEqual(protected.count('--backend-observation "$INT_JOB_BACKEND_DIR/backend.json"'), 2)

    def test_exact_oci_and_three_versions_in_both_specs(self):
        for phase, account in jobs.client.ACCOUNTS.items():
            _, spec, _, _, _ = self.ready(phase=phase)
            task = spec["template"]["template"]
            container = task["containers"][0]
            self.assertEqual(task["serviceAccount"], account)
            self.assertEqual(task["maxRetries"], 0)
            self.assertEqual(container["image"], jobs.client.NOBLE_IMAGE)
            self.assertEqual(container["args"][-3:], [phase, "--target", "noble"])
            self.assertEqual([row["secret"]["items"][0]["version"] for row in task["volumes"]], ["2", "2"])
            self.assertIn({"name": "CLIPFORGE_DATABASE_SSL_MODE", "value": "verify-full"}, container["env"])

    def test_versions_receipts_and_tls_fail_closed(self):
        for changes, reason in (({"version": "latest"}, "secret_version_not_numeric"),
                                ({"apply_secret_sha": "0" * 64}, "demo_a_apply_firewall_not_verified"),
                                ({"layers": ["sha256:" + "0" * 64]}, "noble_client_publication_mismatch"),
                                ({"phase": "app", "migration": False}, "job_predecessor_set_mismatch"),
                                ({"tls_host": "10.80.1.2"}, "noble_ca_receipt_mismatch")):
            with self.subTest(changes=changes), self.assertRaisesRegex(ValueError, reason):
                self.ready(**changes)

    def test_requires_reconciled_final_apply_and_exact_protected_predecessor(self):
        decision, _, _, _, final = self.ready()
        prior = jobs.client.decode((self.root / "protected-runtime-apply.json").read_text(encoding="utf-8"))
        jobs.apply_receipt(final, prior, decision["receipts"])
        cases = (
            (prior, "demo_a_final_apply_chain_not_verified"),
            ({**final, "schema": "clipforge-int-demo-a-result-1"}, "demo_a_apply_firewall_not_verified"),
            ({**final, "managed_count": 58}, "demo_a_final_apply_chain_not_verified"),
            ({**final, "iap_verified": False}, "demo_a_apply_firewall_not_verified"),
            ({**final, "run_service": {**final["run_service"], "generation": "2"}}, "demo_a_apply_firewall_not_verified"),
            ({**final, "protected_runtime_receipt_sha256": "b" * 64}, "demo_a_final_apply_chain_not_verified"),
            ({**final, "protected_runtime_apply": {**final["protected_runtime_apply"], "name": final["plan_manifest"]["name"]}},
             "demo_a_final_apply_chain_not_verified"),
            ({**final, "state_before_generation": jobs.scope.STATE["generation"]}, "demo_a_final_apply_state_not_reconciled"),
            ({**final, "state_after": {**final["state_after"], "generation": PROTECTED_GENERATION}}, "demo_a_final_apply_state_not_reconciled"),
            ({**final, "state_after": {**final["state_after"], "current_lock_absent": False}}, "demo_a_final_apply_state_not_reconciled"),
        )
        for candidate, error in cases:
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                jobs.apply_receipt(candidate, prior, decision["receipts"])
        with self.assertRaisesRegex(ValueError, "demo_a_final_apply_chain_not_verified"):
            jobs.apply_receipt(final, {**prior, "different_receipt": True}, decision["receipts"])

    def test_backend_binding_uses_final_successor_and_real_phase_two_start(self):
        ready = self.ready()
        binding, _ = self.backend_proof(ready)
        self.assertEqual(binding["phase2_state_before_generation"], PROTECTED_GENERATION)
        self.assertEqual(binding["state"]["generation"], FINAL_GENERATION)
        self.assertEqual(binding["phase2_plan_sha256"], ready[4]["plan_sha256"])
        self.assertEqual(binding["protected_runtime_apply_sha256"], ready[0]["receipts"]["protected-runtime-apply"])

    def test_create_has_one_post_and_does_not_start_execution(self):
        ready = self.ready()
        spec = ready[1]
        transport = Mock()
        transport.call.side_effect = [None, {"name": jobs.LOCATION + "/operations/job-created", "done": True,
                                            "response": {"name": spec["name"], "uid": "job-fixture"}}, self.actual(spec)]
        result = self.execute(transport, ready)
        post = [call for call in transport.call.call_args_list if call.args[0] == "POST"]
        self.assertEqual(len(post), 1)
        self.assertTrue(post[0].args[1].endswith("/jobs?jobId=clipforge-int-db01-noble-migration"))
        self.assertNotIn("startExecutionToken", post[0].args[2])
        self.assertEqual(transport.retain.call_args_list[0].args[0], "intent")
        self.assertEqual(result["status"], "created_verified")

    def test_run_rechecks_etag_and_matches_exact_execution(self):
        ready = self.ready(action="run")
        spec, body = ready[1:3]
        task = deepcopy(spec["template"]["template"])
        task["containers"][0]["env"].extend(reversed(body["overrides"]["containerOverrides"][0]["env"]))
        name = spec["name"] + "/executions/one"
        transport = Mock()
        transport.call.side_effect = [self.actual(spec), {"name": jobs.LOCATION + "/operations/job-run", "done": True,
            "response": {"name": name, "uid": "execution-fixture"}}, {"name": name, "uid": "execution-fixture", "job": spec["name"],
            "taskCount": 1, "parallelism": 1, "succeededCount": 1, "completionTime": "fixture", "template": task},
            {**self.actual(spec), "executionCount": 1, "latestCreatedExecution": {"name": name}}]
        result = self.execute(transport, ready)
        post = transport.call.call_args_list[1]
        self.assertEqual(post.args[2], {"etag": "job-etag", **body})
        self.assertEqual(set(body["overrides"]["containerOverrides"][0]), {"name", "env"})
        self.assertEqual(result["database_revisions"], jobs.MIGRATION_REVISIONS)

    def test_drift_or_prior_execution_stops_before_intent(self):
        ready = self.ready(action="run")
        spec = ready[1]
        extra = self.actual(spec)
        extra["template"]["template"]["volumes"].append({"name": "foreign"})
        for actual in (extra, {**self.actual(spec), "executionCount": 1}, {**self.actual(spec), "etag": "changed"}):
            transport = Mock()
            transport.call.return_value = actual
            with self.assertRaises(ValueError):
                self.execute(transport, ready)
            transport.retain.assert_not_called()
            transport.call.assert_called_once()

    def test_indeterminate_post_is_never_repeated(self):
        ready = self.ready()
        transport = Mock()
        transport.call.side_effect = [None, TimeoutError()]
        with self.assertRaises(TimeoutError):
            self.execute(transport, ready)
        self.assertEqual([call.args[0] for call in transport.call.call_args_list], ["GET", "POST"])
        self.assertEqual(transport.retain.call_count, 1)

    def test_missing_run_with_overrides_is_reported(self):
        transport = Mock()
        transport.call.side_effect = [{"permissions": ["run.operations.get"]},
                                      {"permissions": ["run.jobs.get", "run.executions.get"]}]
        with self.assertRaisesRegex(ValueError, "permissions_missing_job:run.jobs.runWithOverrides"):
            jobs.verify_permissions(transport, "run", jobs.client.JOB_PATH + jobs.client.NOBLE_JOBS["migrate"], "migrate")

    def test_global_default_remains_blocking_and_protected_decision_is_independent(self):
        ready = self.ready()
        with patch.object(jobs.int_release, "require_application_ci", side_effect=ValueError) as check:
            with self.assertRaisesRegex(ValueError, "protected_noble_job_decision_or_gate_mismatch"):
                jobs.check_security(self.root, ready[0], ready[4], {}, "e" * 64, protected=True)
            check.assert_not_called()
            with self.assertRaisesRegex(ValueError, "existing_application_ci_blocks_noble_jobs"):
                jobs.check_security(self.root, ready[0], ready[4], {"INT_NOBLE_JOBS_PROTECTED_DECISION_SHA256": "e" * 64},
                                    "e" * 64, protected=True)
            check.assert_called_once()

    def test_alternate_gate_is_bound_to_protected_pins_and_apply(self):
        ready = self.ready()
        applied = ready[4]
        state_before, plan = applied["state_before_generation"], applied["plan_sha256"]
        binding = {"source_commit": SHA, "operation": "migration_job", "plan_sha256": plan,
                   "state_generation": state_before, "post_apply_generation": applied["state_after"]["generation"]}
        graph = {"entrypoint_sha256": jobs.digest((jobs.ROOT / jobs.WORKFLOW).read_bytes())}
        review = {"promotion_graph": {}, "subjects": {"migration_client": {"identity": jobs.client.NOBLE_IMAGE.split("@")[1]}}}
        refs = {"review": self.write("review", review), "binding": self.write("binding", binding), "apply": ready[0]["receipts"]["apply"]}
        decision = {**ready[0], "gate": "demo-a", "receipts": refs}
        protected = {"INT_NOBLE_JOBS_PROTECTED_GATE_MODE": "demo-a", "INT_NOBLE_JOBS_PROTECTED_DECISION_SHA256": "e" * 64,
                     "INT_NOBLE_JOBS_PROTECTED_REVIEW_SHA256": refs["review"], "INT_NOBLE_JOBS_PROTECTED_BINDING_SHA256": refs["binding"]}
        with patch.object(jobs.evidence_gate, "evidence", return_value=graph), patch.object(jobs.evidence_gate, "verify_review") as check:
            jobs.check_security(self.root, decision, applied, protected, "e" * 64, protected=True)
            check.assert_called_once()
            for env, state, error in (({}, applied, "protected_noble_job_decision_or_gate_mismatch"),
                                       ({**protected, "INT_NOBLE_JOBS_PROTECTED_REVIEW_SHA256": "1" * 64}, applied,
                                        "protected_noble_job_review_digests_mismatch"),
                                       (protected, {**applied, "plan_sha256": "12" * 32}, "job_gate_apply_binding_mismatch")):
                with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                    jobs.check_security(self.root, decision, state, env, "e" * 64, protected=True)
            refs["binding"] = self.write("binding", {**binding, "state_generation": jobs.scope.STATE["generation"]})
            protected["INT_NOBLE_JOBS_PROTECTED_BINDING_SHA256"] = refs["binding"]
            with self.assertRaisesRegex(ValueError, "job_gate_apply_binding_mismatch"):
                jobs.check_security(self.root, decision, applied, protected, "e" * 64, protected=True)

    def test_admin_phase_requires_two_predecessors_and_never_creates(self):
        with self.assertRaisesRegex(ValueError, "admin_job_requires_reviewed_terraform_creation"):
            jobs.decision_bundle(self.root, "x" * 64, ENV, "create", "admin", now=NOW)
        with self.assertRaisesRegex(ValueError, "job_predecessor_set_mismatch"):
            self.ready(action="run", phase="admin", acceptance=False)
        _, spec, body, created, _ = self.ready(action="run", phase="admin")
        self.assertEqual(spec["name"], jobs.ADMIN_JOB)
        task = spec["template"]["template"]
        self.assertEqual(task["serviceAccount"], jobs.client.ACCOUNTS["migrate"])
        self.assertEqual(task["containers"][0]["args"], ["-m", "app.cloud.bootstrap_admin"])
        self.assertEqual({row["name"] for row in task["volumes"]}, {"database", "admin", "postgres-ca"})
        self.assertEqual(body, {})
        self.assertIsNone(created)

    def test_admin_run_uses_etag_without_overrides_and_checks_only_attempt(self):
        ready = self.ready(action="run", phase="admin")
        spec = ready[1]
        name = spec["name"] + "/executions/one"
        transport = Mock()
        transport.call.side_effect = [self.actual(spec), {"name": jobs.LOCATION + "/operations/admin-run", "done": True,
            "response": {"name": name, "uid": "execution-fixture"}}, {"name": name, "uid": "execution-fixture", "job": spec["name"],
            "taskCount": 1, "parallelism": 1, "succeededCount": 1, "completionTime": "fixture", "template": spec["template"]["template"]},
            {**self.actual(spec), "executionCount": 1, "latestCreatedExecution": {"name": name}}]
        result = self.execute(transport, ready)
        self.assertEqual(transport.call.call_args_list[1].args, ("POST", jobs.RUN + jobs.ADMIN_JOB + ":run", {"etag": "job-etag"}))
        self.assertEqual(result["effect"], "one_time_first_administrator")


if __name__ == "__main__":
    unittest.main()
