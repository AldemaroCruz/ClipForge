from datetime import datetime, timedelta, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_demo_a_native as native


class ProtectedPlanTest(unittest.TestCase):
    def setUp(self):
        self.now = datetime.now(timezone.utc)
        directory = TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.root = Path(directory.name)
        self.commit = "a" * 40
        self.env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": native.REPOSITORY,
                    "GITHUB_REF": "refs/heads/" + native.BRANCH, "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "12",
                    "GITHUB_SHA": self.commit, "INT_APPROVED_COMMIT": self.commit,
                    "GITHUB_WORKFLOW_REF": f"{native.REPOSITORY}/{native.WORKFLOWS['plan']}@refs/heads/{native.BRANCH}",
                    "GCP_PROJECT_ID": "clipforgebeta2", "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1",
                    "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
                    "GCP_WIF_PROVIDER": "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
                    "TF_STATE_BUCKET": native.scope.BUCKET, "TF_STATE_PREFIX": "terraform/int"}
        source = b"review fixture\n"
        file_sha = native.custody.sha256(source)
        for name in native.SOURCES:
            path = self.root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(source)
        ref = {"name": f"private-plans/int/{self.commit}/12-1/int.json", "size": 10, "sha256": "b" * 64, "generation": "12"}
        evidence = {name: ref.copy() for name in native.NAMES}
        evidence[native.IAM_EVIDENCE] = ref.copy()
        evidence["postverify"] = native.POSTVERIFY.copy()
        deploy = f"{native.receipts.PREFIX}{self.commit}/12-1/"
        evidence["publish"]["name"] = deploy + "publication-runtime.json"
        evidence["versions"]["name"] = deploy + "secret-versions.json"
        evidence["bootstrap"]["name"] = deploy + "noble-bootstrap.json"
        self.decision = {"schema": "clipforge-int-demo-a-owner-decision-2", "phase": "plan",
                         "deployment_phase": native.scope.PROTECTED_RUNTIME, "owner": "admin@ixbalam.studio",
                         "decision_id": "7" * 30, "controls_commit": self.commit, "app_source": native.scope.SOURCE,
                         "image": native.scope.IMAGE, "state": native.scope.STATE, "sources": dict.fromkeys(native.SOURCES, file_sha),
                         "issued_utc": (self.now - timedelta(minutes=1)).isoformat(), "expires_utc": (self.now + timedelta(hours=1)).isoformat(),
                         "approvals": {"native_backend_lock": True, "private_immutable_custody": True, "apply_saved_plan": False},
                         "evidence": evidence, "publisher_digest": "sha256:" + "f" * 64, "gate": {"mode": "global"},
                         "publisher_controls": self.commit, "secret_controls": self.commit}
        hashes = patch.object(native, "NATIVE_HCL", dict.fromkeys(native.NATIVE_HCL, file_sha))
        stable = patch.object(native.writer, "verify_stable_reference")
        hashes.start()
        stable.start()
        self.addCleanup(hashes.stop)
        self.addCleanup(stable.stop)

    def validate(self):
        raw = native.custody.canonical(self.decision)
        sha = native.custody.sha256(raw)
        self.env["DECISION_SHA"] = sha
        self.env.setdefault("PROTECTED_DECISION_SHA", sha)
        return native.validate_local("plan", self.env, raw, root=self.root, now=self.now)

    def test_exact_preflight_and_changed_source_block_without_gcp(self):
        with patch.object(native, "get") as no_cloud:
            self.assertEqual(self.validate()["phase"], "plan")
            (self.root / native.MODULE / "runtime.tf").write_text("changed", encoding="utf-8")
            with self.assertRaisesRegex(ValueError, "changed_iac_source"):
                self.validate()
            no_cloud.assert_not_called()

    def test_materialization_uses_only_pinned_demo_overlays_in_private_scratch(self):
        historical = (native.MODULE / "runtime.tf").as_posix()
        overlay = native.OVERLAYS[historical]
        tested = b"reviewed demo runtime bytes\n"
        (self.root / overlay).write_bytes(tested)
        original = (self.root / historical).read_bytes()
        self.decision["sources"][overlay] = native.custody.sha256(tested)
        work = self.root / "owned-scratch"
        work.mkdir()
        staged = native.materialize_module(self.decision, work, root=self.root)
        self.assertEqual((staged / "runtime.tf").read_bytes(), tested)
        self.assertEqual((self.root / historical).read_bytes(), original)
        self.assertFalse((work / "module" / native.DEMO_MODULE).exists())
        for target, chosen in native.selected_sources(self.decision["sources"]).items():
            self.assertEqual(native.custody.sha256((work / "module" / target).read_bytes()), chosen["sha256"])
        (self.root / overlay).write_bytes(b"unreviewed runtime change")
        another = self.root / "another-scratch"
        another.mkdir()
        with self.assertRaisesRegex(ValueError, "changed_iac_source"):
            native.materialize_module(self.decision, another, root=self.root)

    def test_protected_decision_digest_is_independent_of_dispatch(self):
        self.env["PROTECTED_DECISION_SHA"] = "f" * 64
        with self.assertRaisesRegex(ValueError, "independently_pinned_owner_decision"):
            self.validate()

    def test_apply_approval_cannot_be_reused_for_plan(self):
        self.decision["approvals"]["apply_saved_plan"] = True
        with self.assertRaisesRegex(ValueError, "owner_scope_or_phase"):
            self.validate()

    def test_global_is_default_and_scoped_mode_is_not_a_dispatch_switch(self):
        with patch.object(native.custody, "require_application_ci") as ci:
            native.verify_activation_gate("plan", self.env, self.decision)
            ci.assert_called_once_with(self.env)
        self.decision["gate"] = {"mode": "demo-a"}
        with self.assertRaisesRegex(ValueError, "protected_gate_mode_changed"):
            native.verify_activation_gate("plan", self.env, self.decision)
        self.env["INT_DEMO_A_PROTECTED_GATE_MODE"] = "demo-a"
        with self.assertRaisesRegex(ValueError, "independent_demo_gate_approval_missing"):
            native.verify_activation_gate("plan", self.env, self.decision)

    def test_separately_approved_apply_gate_is_bound_to_binary(self):
        bundle = self.root / "clipforge-int-demo-a-review.fixture"
        bundle.mkdir()
        controller = self.root / "scripts/int_demo_a_native.py"
        controller.write_bytes(b"controller")
        binary_sha = "c" * 64
        binding = {**native.activation_gate.BOUNDARY, "source_commit": self.commit, "operation": "locked_plan_apply",
                   "state_generation": native.scope.STATE["generation"], "plan_sha256": binary_sha,
                   "apply_receipt_sha256": None, "post_apply_generation": None}
        good_review = {"promotion_graph": "graph", "subjects": {"api": {"identity": native.MANIFEST, "analyses": [
                      {"kind": "trivy_oci", "receipt": "receipt"}]}}}
        review_raw, binding_raw = (native.custody.canonical(item) for item in (good_review, binding))
        (bundle / "review.json").write_bytes(review_raw)
        (bundle / "binding.json").write_bytes(binding_raw)
        review_sha, binding_sha = map(native.custody.sha256, (review_raw, binding_raw))
        self.env.update(INT_DEMO_A_PROTECTED_GATE_MODE="demo-a", INT_DEMO_A_GATE_RUN="12", INT_DEMO_A_GATE_ARTIFACT="13",
                        INT_DEMO_A_PROTECTED_REVIEW_SHA=review_sha, INT_DEMO_A_PROTECTED_BINDING_SHA=binding_sha,
                        ImageOS="ubuntu24", ImageVersion="20261120.1", RUNNER_TEMP=str(self.root),
                        INT_DEMO_A_GATE_BUNDLE=str(bundle))
        self.decision["plan_binary_sha256"] = binary_sha
        self.decision["gate"] = {"mode": "demo-a", "run_id": "12", "artifact_id": "13", "runner_version": "20261120.1",
                                 "review_sha256": review_sha, "binding_sha256": binding_sha}
        evidence = {"graph": {"entrypoint_sha256": native.custody.sha256(controller.read_bytes())},
                    "receipt": {"scope": "scope"}, "scope": {"oci_config": native.CONFIG, "oci_diff_ids": native.LAYERS}}
        with patch.object(native.activation_gate, "verify_review") as check, \
                patch.object(native.activation_gate, "evidence", side_effect=lambda _, key: evidence[key]):
            native.verify_activation_gate("apply", self.env, self.decision, root=self.root)
            self.assertEqual(check.call_args.args[2], binding)
            self.decision["plan_binary_sha256"] = "a" * 64
            with self.assertRaisesRegex(ValueError, "exact_demo_gate_operation_binding"):
                native.verify_activation_gate("apply", self.env, self.decision, root=self.root)

    def test_one_shot_marker_precedes_native_plan(self):
        report = {}
        versions = dict.fromkeys(native.scope.SECRET_NAMES, "123")
        self.env["DECISION_SHA"] = "a" * 64
        with patch.object(native, "baseline_state", return_value=(native.scope.STATE, {})), patch.object(native, "init", return_value=["terraform"]), \
                patch.object(native, "store", side_effect=ValueError("marker_exists")) as marker, patch.object(native.driver, "run") as launch:
            with self.assertRaisesRegex(ValueError, "marker_exists"):
                native.plan(self.decision, self.env, self.root, versions, report, {"prior_apply": None})
        self.assertEqual(report["stage"], "claim_plan_once")
        self.assertIn("/" + self.decision["decision_id"] + "-1/foundation-state.json", marker.call_args.args[0])
        launch.assert_not_called()

    def test_native_reread_mismatch_prevents_apply_and_intent(self):
        with patch.object(native, "verified_plan", return_value=(b"binary", b"json", self.now + timedelta(hours=1))), \
                patch.object(native, "baseline_state", return_value=(native.scope.STATE, {})), patch.object(native, "init", return_value=["terraform"]), \
                patch.object(native.driver, "run", return_value=(0, b"changed")) as launch, patch.object(native, "store") as marker:
            with self.assertRaisesRegex(ValueError, "saved_binary_native_json_mismatch"):
                native.apply(self.decision, self.env, self.root, {}, {}, {"prior_apply": None})
        self.assertEqual(launch.call_count, 1)
        self.assertEqual(launch.call_args.args[0][1], "show")
        marker.assert_not_called()

    def test_iac_requires_specific_current_decision_for_each_native_failure(self):
        base_file = (native.MODULE / "runtime.tf").as_posix()
        overlay_file = native.OVERLAYS[base_file]
        self.decision["sources"][overlay_file] = "b" * 64
        status = {"ID": "GCP-0033", "Status": "FAIL", "Severity": "LOW", "CauseMetadata": {
                  "Resource": "google_compute_instance.postgres", "StartLine": 1, "EndLine": 2}}
        raw = native.custody.canonical({"ArtifactType": "filesystem", "Trivy": {"Version": "0.76.2"}, "Results": [
               {"Class": "config", "Type": "terraform", "Target": "runtime.tf", "MisconfSummary": {"Failures": 1}, "Misconfigurations": [status]}]})
        digest = native.custody.sha256(raw)
        review = {"schema": "clipforge-int-demo-a-iac-review-1", "status": "reviewed", "controls_commit": self.commit,
                  "sources": self.decision["sources"], "selected_sources": native.selected_sources(self.decision["sources"]),
                  "native_report_sha256": digest, "native_report": {"sha256": digest},
                  "unresolved_count": 0, "expires_utc": self.decision["expires_utc"], "decisions": []}
        with self.assertRaisesRegex(ValueError, "unresolved_native_iac_finding"):
            native.verify_iac(review, raw, self.decision, now=self.now)
        row = {"id": "GCP-0033", "severity": "LOW", "target": "runtime.tf", "resource": status["CauseMetadata"]["Resource"],
               "start_line": 1, "end_line": 2, "native_report_sha256": digest, "source_sha256": self.decision["sources"][base_file],
               "expires_utc": self.decision["expires_utc"], "responsible": "fixture", "control": "fixture", "evidence": "fixture",
               "status": "control_verified"}
        review["decisions"] = [row]
        with self.assertRaisesRegex(ValueError, "independent_iac_finding_decision"):
            native.verify_iac(review, raw, self.decision, now=self.now)
        row["source_sha256"] = self.decision["sources"][overlay_file]
        native.verify_iac(review, raw, self.decision, now=self.now)
        row["expires_utc"] = self.decision["issued_utc"]
        with self.assertRaisesRegex(ValueError, "independent_iac_finding_decision"):
            native.verify_iac(review, raw, self.decision, now=self.now)

    def test_publisher_and_secret_intents_use_shared_custody_and_exact_operations(self):
        base = f"{native.receipts.PREFIX}{self.commit}"
        records = {}

        def prepared(leaf, operation, body):
            path = f"{base}/decisions/{operation}/{leaf}"
            raw = native.custody.canonical(body)
            records[path] = raw
            return {"name": path, "generation": "12", "sha256": native.custody.sha256(raw), "size": len(raw)}

        approved = {"owner_decision_sha256": "f" * 64}
        publication = {"target": native.scope.IMAGE, "run": "12", "source_controls": self.commit,
                       "manifest": native.MANIFEST, "config": native.CONFIG, "archive_sha256": native.ARCHIVE,
                       "layers": native.LAYERS, "publisher_digest": "sha256:" + "1" * 64, "operation_id": "a" * 32, **approved}
        publication["intent"] = prepared("publication-runtime-intent.json", "a" * 32,
                                         {**publication, **approved, "status": "copy_intended"})
        source = {"source_controls": self.commit, "run": "13", "bootstrap_receipt_sha256": "2" * 64,
                  "bootstrap_run": "11", "bootstrap_artifact": "14", "ca_certificate_sha256": "3" * 64,
                  "operation_id": "b" * 32, **approved}
        secrets = {**source, "intents": {key: prepared(f"secret-{key}-intent.json", "b" * 32,
                   {**source, **approved, "status": "secret_version_intended", "secret": name})
                   for key, name in native.scope.SECRET_NAMES.items()}}
        with patch.object(native, "read_reference", side_effect=lambda ref: records[ref["name"]]) as read:
            native.verify_producer_intents(self.decision, publication, secrets)
            self.assertEqual(read.call_count, 5)
            publication["manifest"] = "sha256:" + "4" * 64
            with self.assertRaisesRegex(ValueError, "producer_intent_contents"):
                native.verify_producer_intents(self.decision, publication, secrets)
            publication["manifest"] = native.MANIFEST
            slot = "bootstrap_admin"
            secrets["intents"][slot] = prepared(f"secret-{slot}-intent.json", "c" * 32,
                    {**source, **approved, "status": "secret_version_intended", "secret": native.scope.SECRET_NAMES[slot]})
            with self.assertRaisesRegex(ValueError, "producer_intent_scope"):
                native.verify_producer_intents(self.decision, publication, secrets)

    def test_deploy_reference_reader_does_not_reuse_terraform_plan_transport(self):
        review = self.decision["evidence"]["publish"]
        with patch.dict(native.os.environ, {"GCP_ACCESS_TOKEN": "e" * 32}), \
                patch.object(native.receipts.Custody, "fetch", return_value=b"producer receipt") as fetch, \
                patch.object(native.custody, "fetch_verified") as legacy:
            self.assertEqual(native.read_reference(review), b"producer receipt")
            fetch.assert_called_once_with(review)
            legacy.assert_not_called()
            with self.assertRaises(ValueError):
                native.reference({**review, "name": review["name"].replace(native.receipts.PREFIX, native.custody.PREFIX)})

    def test_second_phase_local_guard_requires_explicit_new_backend_and_receipt(self):
        self.decision["deployment_phase"] = native.scope.HUMAN_ACCESS
        with self.assertRaisesRegex(ValueError, "second_phase_requires_new_backend_generation"):
            self.validate()
        state = native.scope.STATE
        self.decision["state"] = {**state, "generation": str(int(state["generation"]) + 1)}
        self.env.pop("PROTECTED_DECISION_SHA")
        with self.assertRaisesRegex(ValueError, "required_source_evidence"):
            self.validate()
        self.decision["evidence"][native.PROTECTED_APPLY] = {**self.decision["evidence"][native.IAM_EVIDENCE],
            "name": f"{native.custody.PREFIX}{self.commit}/13-1/manifest.json"}
        self.env.pop("PROTECTED_DECISION_SHA")
        self.assertEqual(self.validate()["deployment_phase"], native.scope.HUMAN_ACCESS)

    def test_attributed_iam_preserves_full_policies_and_only_named_bindings(self):
        both = native.SECRET_POLICY_NAMES
        resources = {*both, "other"}
        before = {"version": 3, "etag": "old", "bindings": [{"role": "roles/example.viewer", "members": ["user:member"]}]}
        after = {**before, "etag": "new", "bindings": [*before["bindings"],
                 {"role": native.VERSION_ROLE, "members": [native.writer.iam.MEMBER]}]}
        chosen = {target: [] for target in resources}
        for path in native.scope.SECRET_IAM_ETAG_ADDRESSES:
            needle = "bootstrap-admin" if "bootstrap_admin" in path else "postgres-ca"
            target = next(item for item in both if item.endswith(needle))
            chosen[target].append({"address": path})
        profile = {"roles": {}, "policies": {target: {"state_etags": rows} for target, rows in chosen.items()}}
        proof = {"policies": {target: {"after": before} for target in resources}}
        evidence = {"schema": "clipforge-int-demo-a-native-iam-receipt-1", "controls_commit": self.commit,
                    "deployment_phase": native.scope.PROTECTED_RUNTIME, "backend_generation": self.decision["state"]["generation"],
                    "read_receipt": native.writer.READ_RECEIPT, "protected_runtime_apply": None, "iap_policy": None,
                    "noble_policies": {"fixture": "exact Noble receipt"},
                    "secret_policies": {target: {"before": before, "after": after} for target in both}}
        actual = {**dict.fromkeys(both, after), "other": before}
        noble_etags = dict.fromkeys(native.scope.NOBLE_IAM_ETAG_ADDRESSES.values(), {"before": "a", "after": "b"})
        bootstrap = {"noble_iam_receipt_sha256": "c" * 64}
        with patch.object(native.writer, "verify_roles"), patch.object(native, "verify_role"), \
                patch.object(native, "noble_iam_etags", return_value=noble_etags) as verify_noble, \
                patch.object(native.writer.iam, "get_policy", side_effect=lambda target, *_: actual[target]):
            transitions, iap = native.verify_native_iam(self.decision, evidence, profile, proof, None, bootstrap, "fixture")
            self.assertEqual(set(transitions), native.scope.IAM_ETAG_ADDRESSES)
            verify_noble.assert_called_once_with(evidence["noble_policies"], bootstrap, "fixture")
            self.assertIsNone(iap)
            actual["other"] = {**before, "etag": "foreign"}
            with self.assertRaisesRegex(ValueError, "unaffected_stable_read_policy_changed"):
                native.verify_native_iam(self.decision, evidence, profile, proof, None, bootstrap, "fixture")

    def test_noble_policy_etags_are_bound_to_bootstrap_and_all_direct_policy_reads(self):
        config_value = {"schema": "clipforge-int-demo-a-noble-policy-1", "project": native.scope.PROJECT,
                        "principal": native.noble_policy.PRINCIPAL, "read_roles": {}, "prior": {},
                        "ownership": "external_additive_binding", "authorized": False}
        policies = {}
        for target, (name, mode, permission) in native.noble_policy.ROLES.items():
            role = native.IAM_ROLE_PREFIX + name
            definition = {"title": "Fixture", "description": "Fixture", "stage": "GA", "includedPermissions": [permission]}
            before = {"version": 3, "etag": "before-" + target,
                      "bindings": [{"role": "roles/viewer", "members": ["user:before@example.invalid"]}]}
            after = {**before, "etag": "after-" + target, "bindings": [
                *before["bindings"], {"role": role, "members": [native.noble_policy.PRINCIPAL]}]}
            config_value["read_roles"][target] = {"name": role, "mode": mode, "definition": definition}
            config_value["prior"][target] = before
            policies[target] = {"before": before, "after": after, "role": role, "role_definition": definition}
        receipt = {"schema": "clipforge-int-demo-a-noble-policy-receipt-2", "status": "applied_and_verified",
                   "approval_sha256": "a" * 64, "policies": policies}
        config = self.root / native.noble_policy.CONFIG
        config.parent.mkdir(exist_ok=True)
        config.write_bytes(native.custody.canonical(config_value))
        bootstrap = {"noble_iam_receipt_sha256": native.custody.sha256(native.custody.canonical(receipt))}
        after = {target: pair["after"] for target, pair in policies.items()}
        responses = {route[1]: after[target] for target, route in native.noble_policy.ROUTES.items()}
        role_lookups = {f"https://iam.googleapis.com/v1/{row['role']}": {"name": row["role"], **row["role_definition"]}
                        for row in policies.values()}

        def read(url, token, method, body):
            self.assertIn((method, url, body), native.noble_policy.ROUTES.values())
            return responses[url]

        with patch.object(native.writer.iam, "request_json", side_effect=read) as direct, \
                patch.object(native, "get", side_effect=lambda url, _: role_lookups[url]) as definitions:
            self.assertEqual(native.noble_iam_etags(receipt, bootstrap, "fixture", root=self.root), {
                address: {"before": native.writer.iam.digest("before-" + target), "after": native.writer.iam.digest("after-" + target)}
                for target, address in native.scope.NOBLE_IAM_ETAG_ADDRESSES.items()
            })
            self.assertEqual((direct.call_count, definitions.call_count), (3, 3))
            url = native.noble_policy.ROUTES["tunnel"][1]
            responses[url] = {**responses[url], "etag": "unexpected"}
            with self.assertRaisesRegex(ValueError, "noble_iam_policy_read_or_etag_changed"):
                native.noble_iam_etags(receipt, bootstrap, "fixture", root=self.root)
            with self.assertRaisesRegex(ValueError, "exact_bootstrap_noble_iam_receipt"):
                native.noble_iam_etags(receipt, {}, "fixture", root=self.root)

    def test_saved_backend_must_have_all_nine_attributable_iam_etags(self):
        attrs = {path: {} for path in native.scope.baseline()}
        old = "reviewed-old-etag"
        for path in native.scope.IAM_ETAG_ADDRESSES:
            attrs[path]["etag"] = old
        cloud = {"prior_apply": None, "etags": {path: {"before": native.writer.iam.digest(old)}
                    for path in native.scope.IAM_ETAG_ADDRESSES}}
        with patch.object(native, "state_binding", return_value=(native.scope.STATE, attrs)), \
                patch.object(native.scope, "check_pinned_vm"):
            native.baseline_state(self.decision, cloud)
            row = attrs[native.scope.NOBLE_IAM_ETAG_ADDRESSES["tunnel"]]
            del row["etag"]
            with self.assertRaisesRegex(ValueError, "native_backend_iam_etags_not_attributable"):
                native.baseline_state(self.decision, cloud)
            row["etag"] = "other-etag"
            with self.assertRaisesRegex(ValueError, "native_backend_iam_etags_not_attributable"):
                native.baseline_state(self.decision, cloud)

    def test_noble_etag_postcheck_rejects_other_state_attributes(self):
        path = native.scope.NOBLE_IAM_ETAG_ADDRESSES["instance"]
        before = {path: {"etag": "old", "role": "original"}}
        after = {path: {"etag": "new", "role": "original"}}
        etags = {"etags": {path: {"after": native.writer.iam.digest("new")}}}
        native.preserved_resources(before, after, etags)
        after[path]["role"] = "unrelated"
        with self.assertRaisesRegex(ValueError, "apply_iam_etag_unreconciled"):
            native.preserved_resources(before, after, etags)

    def test_live_protected_service_checks_real_run_invoker_policy_contract(self):
        service = {"name": f"projects/{native.scope.PROJECT}/locations/{native.scope.REGION}/services/{native.API}",
                   "uid": "fixture-service", "generation": "2", "iapEnabled": True, "invokerIamDisabled": False}
        policy = {"version": 1, "etag": "fixture-etag", "bindings": [
            {"role": "roles/run.invoker", "members": [native.IAP_AGENT]}]}
        with patch.object(native, "get", side_effect=[service, policy]) as read, \
                patch.object(native, "read_iap_policy") as web:
            self.assertEqual(native.verify_live_iap(native.scope.PROTECTED_RUNTIME, None, "fixture"),
                             {"uid": "fixture-service", "generation": "2"})
            self.assertTrue(read.call_args_list[0].args[0].startswith(native.RUN_API + "?fields="))
            self.assertEqual(read.call_args_list[1].args[0], native.RUN_API + ":getIamPolicy?options.requestedPolicyVersion=3")
            web.assert_not_called()
        policy["bindings"][0]["members"].append("allUsers")
        with patch.object(native, "get", side_effect=[service, policy]):
            with self.assertRaisesRegex(ValueError, "live_run_invoker_policy_changed"):
                native.verify_live_iap(native.scope.PROTECTED_RUNTIME, None, "fixture")


if __name__ == "__main__":
    unittest.main()
