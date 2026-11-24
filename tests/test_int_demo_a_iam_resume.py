"""Exercise continuation of a reconciled IAM attempt without network calls."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from scripts import int_demo_a_iam as delta
from scripts import int_demo_a_iam_resume as resume


ORIGINAL_COMMIT = resume.ORIGINAL_COMMIT
CONTROLS_COMMIT = "b" * 40
ORIGINAL_ID = resume.ORIGINAL_ID
CONTINUATION_ID = "d" * 32
TOKEN = "local-token-placeholder"
ACCOUNT, INSTANCE, TUNNEL = (delta.NOBLE[name] for name in ("account", "instance", "tunnel"))
ROLE_PREFIX = f"projects/{delta.PROJECT}/roles/"
DEPLOY = delta.noble.PRINCIPAL
TERRAFORM = f"serviceAccount:clipforge-terraform-int@{delta.PROJECT}.iam.gserviceaccount.com"
GRANTABLE = "https://iam.googleapis.com/v1/roles:queryGrantableRoles"
GRANTABLE_INSTANCE = ("//compute.googleapis.com/projects/clipforgebeta2/zones/us-central1-a/"
                      "instances/7365414160255801909")
CONDITION = {"title": "int_demo_a_deploy_receipts_v1",
             "expression": "resource.type == 'storage.googleapis.com/Object' && "
                           "resource.name.startsWith('projects/_/buckets/clipforgebeta2-tfstate-int/"
                           "objects/private-deploy/int/demo-a/v1/')"}


def fixture_profile():
    account_role = "clipforgeIntReadPostgresPolicy_20261118T180000Z"
    instance_role = "clipforgeIntDemoANobleInstancePolicyRead"
    tunnel_role = "clipforgeIntNobleIapPolicyRead"
    receipt_role = "clipforgeIntDemoADeployReceiptObjects"
    secret_role = "clipforgeIntDemoASecretVersionMetadata"
    specs = {
        account_role: ("reuse", ["iam.serviceAccounts.getIamPolicy"]),
        instance_role: ("create", ["compute.instances.getIamPolicy"]),
        tunnel_role: ("reuse", ["iap.tunnelInstances.getIamPolicy"]),
        receipt_role: ("create", ["storage.objects.create", "storage.objects.get"]),
        secret_role: ("create", ["secretmanager.versions.get"]),
    }
    roles = {ROLE_PREFIX + role: {"mode": mode, "definition": {
        "title": "Synthetic " + role, "description": "Synthetic definition", "stage": "GA",
        "includedPermissions": permissions,
    }} for role, (mode, permissions) in specs.items()}
    rows = [(ACCOUNT, account_role, DEPLOY), (INSTANCE, instance_role, DEPLOY),
            (TUNNEL, tunnel_role, DEPLOY), (delta.BUCKET, receipt_role, DEPLOY),
            *((name, secret_role, TERRAFORM) for name in delta.SECRETS)]
    before_bootstrap = []
    for index, (resource, role, principal) in enumerate(rows):
        before = {"etag": f"baseline-{index}", "version": 3,
                  "bindings": [{"role": "roles/viewer", "members": ["user:synthetic@example.test"]}],
                  "auditConfigs": [{"service": "example.googleapis.com", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]}
        binding = {"role": ROLE_PREFIX + role, "members": [principal]}
        if resource == delta.BUCKET:
            before.update(kind="storage#policy", resourceId=delta.BUCKET)
            binding["condition"] = dict(CONDITION)
        before_bootstrap.append({"resource": resource, "before": before, "add_binding": binding})
    return {"schema": "clipforge-int-demo-a-iam-proposal-1", "project": delta.PROJECT,
            "before_bootstrap": before_bootstrap, "roles": roles}


def observation(resource, change, live, classification):
    binding = change["binding"]
    return {"resource": resource, "role": binding["role"], "principal": binding["members"][0],
            "condition": binding.get("condition"), "observed": classification,
            "baseline_etag": change["before"]["etag"], "live_etag": live["etag"],
            "live_policy_sha256": delta.iam.digest(live)}


def fixture_prior(profile):
    changes = delta.targets(profile, "before_bootstrap")
    account = changes[ACCOUNT]
    verified_account = {"before": account["before"], "after": {**account["requested"], "etag": "verified-account"}}
    role_specs = delta.roles_for(changes)
    created = [name for name, spec in role_specs.items() if spec["mode"] == "create"]
    original = {"schema": delta.RESULT_SCHEMA, "status": "indeterminate_reconciliation_required",
                "controls_commit": ORIGINAL_COMMIT, "approval_sha256": "e" * 64,
                "phase": "before_bootstrap", "operation": "apply", "roles_created": created,
                "policies": {ACCOUNT: verified_account}, "pending": {"operation": "setIamPolicy", "resource": INSTANCE},
                "primary_error": "http_400"}
    reconciliation = {
        "operation_id": ORIGINAL_ID, "commit": ORIGINAL_COMMIT,
        "approval_sha256_canonical": original["approval_sha256"],
        "status": original["status"], "pending": original["pending"], "primary_error": original["primary_error"],
        "files": {"result.json": {"sha256": resume.ORIGINAL_RESULT, "bytes": len(delta.iam.custody.canonical(original))}},
        "reconciled_roles": [{"name": name, "expected_mode": spec["mode"],
                              "journal_verified": name in created, "observed": "exact_present"}
                             for name, spec in role_specs.items()],
        "reconciled_policies": [
            observation(resource, change, verified_account["after"], "exact_requested_delta_with_verified_journal")
            if resource == ACCOUNT else observation(resource, change, change["before"], "exact_baseline")
            for resource, change in changes.items()
        ],
    }
    return original, reconciliation


def fixture_authority(reconciliation):
    now = datetime.now(timezone.utc)
    return {"schema": resume.SCHEMA, "operation": "continue",
            "phase": "before_bootstrap", "operation_id": CONTINUATION_ID, "controls_commit": CONTROLS_COMMIT,
            "owner": delta.iam.ADMIN, "profile_sha256": delta.PROFILE_SHA,
            "original_operation_id": ORIGINAL_ID, "original_commit": ORIGINAL_COMMIT,
            "original_result_sha256": reconciliation["files"]["result.json"]["sha256"],
            "reconciliation_sha256": delta.iam.digest(reconciliation),
            "approval_ref": "Synthetic continuation approval", "controller_sha256": "f" * 64,
            "valid_from": (now - timedelta(minutes=1)).isoformat(), "expires_at": (now + timedelta(minutes=5)).isoformat()}


class CloudFixture:
    def __init__(self, profile, original):
        self.changes = delta.targets(profile, "before_bootstrap")
        self.policies = {resource: deepcopy(change["before"]) for resource, change in self.changes.items()}
        self.policies[ACCOUNT] = deepcopy(original["policies"][ACCOUNT]["after"])
        self.roles = {name: {"name": name, **spec["definition"]} for name, spec in profile["roles"].items()}
        self.calls = []
        self.error = None
        self.apply_before_error = False
        self.grantable = True
        self.grantable_after_first_page = False
        self.read_routes = {url: delta.NOBLE[name] for name, (_, url, _) in delta.noble.ROUTES.items()}
        self.read_routes[delta.STORAGE + "/iam?optionsRequestedPolicyVersion=3"] = delta.BUCKET
        for name in delta.SECRETS:
            url = f"https://secretmanager.googleapis.com/v1/{name}:getIamPolicy?options.requestedPolicyVersion=3"
            self.read_routes[url] = name
        self.write_routes = {
            f"https://iam.googleapis.com/v1/{ACCOUNT}:setIamPolicy": ACCOUNT,
            delta.noble.ROUTES["instance"][1].split("/getIamPolicy", 1)[0] + "/setIamPolicy": INSTANCE,
            f"https://iap.googleapis.com/v1/{TUNNEL}:setIamPolicy": TUNNEL,
            delta.STORAGE + "/iam": delta.BUCKET,
            **{f"https://secretmanager.googleapis.com/v1/{name}:setIamPolicy": name for name in delta.SECRETS},
        }

    @property
    def writes(self):
        return [target for operation, target in self.calls if operation == "write"]

    def requested_policy_present(self, resource):
        self.policies[resource] = {**deepcopy(self.changes[resource]["requested"]), "etag": "present-before-continuation"}

    def __call__(self, url, token, method="GET", body=None, **options):
        assert token == TOKEN
        if url == GRANTABLE:
            self.calls.append(("grantable", deepcopy(body)))
            assert method == "POST" and body["fullResourceName"] == GRANTABLE_INSTANCE
            if self.grantable_after_first_page and not body.get("pageToken"):
                return {"roles": [{"name": "roles/viewer"}], "nextPageToken": "fixture-page-two"}
            if self.grantable_after_first_page:
                assert body["pageToken"] == "fixture-page-two"
            role = self.changes[INSTANCE]["binding"]["role"]
            return {"roles": [{"name": role}] if self.grantable else [{"name": "roles/viewer"}]}
        if url in self.read_routes:
            target = self.read_routes[url]
            self.calls.append(("policy", target))
            observed = deepcopy(self.policies[target])
            if target == delta.BUCKET:
                observed.update(kind="storage#policy", resourceId=target)
            return observed
        if url in self.write_routes:
            target = self.write_routes[url]
            self.calls.append(("write", target))
            assert target != ACCOUNT, "The prior account binding is a read-only gate"
            assert method == ("PUT" if target == delta.BUCKET else "POST")
            if self.error and not self.apply_before_error:
                raise self.error
            policy = body if target == delta.BUCKET else body["policy"]
            assert policy["etag"] == self.policies[target]["etag"]
            assert delta.iam.semantic(policy) == delta.iam.semantic(self.changes[target]["requested"])
            policy = {**deepcopy(policy), "etag": f"verified-{len(self.writes)}"}
            self.policies[target] = policy
            if self.error:
                raise self.error
            response = deepcopy(policy)
            if target == delta.BUCKET:
                response.update(kind="storage#policy", resourceId=target)
            return response
        if url.startswith("https://iam.googleapis.com/v1/" + ROLE_PREFIX):
            assert method == "GET" and body is None
            role = url.removeprefix("https://iam.googleapis.com/v1/")
            self.calls.append(("role", role))
            return deepcopy(self.roles[role])
        if url.startswith(f"https://iam.googleapis.com/v1/projects/{delta.PROJECT}/serviceAccounts/"):
            assert method == "GET" and body is None
            email = url.rsplit("/", 1)[1]
            return {"email": email, "projectId": delta.PROJECT, "disabled": False}
        if url.startswith(delta.STORAGE + "?fields="):
            assert method == "GET" and body is None
            return {"name": delta.receipts.BUCKET, "projectNumber": "816643438938",
                    "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}}}
        raise AssertionError((method, url, options))


class ResumeIamTests(unittest.TestCase):
    def setUp(self):
        self.profile = fixture_profile()
        self.original, self.reconciliation = fixture_prior(self.profile)
        self.authority = fixture_authority(self.reconciliation)
        self.cloud = CloudFixture(self.profile, self.original)
        self.work = TemporaryDirectory()
        self.addCleanup(self.work.cleanup)
        self.journal = Path(self.work.name) / CONTINUATION_ID
        self.journal.mkdir()

    def continue_once(self):
        return resume.continue_changes(self.profile, self.original, self.reconciliation, self.authority, TOKEN,
                                       self.journal, request=self.cloud, enforce_time=lambda _: None)

    def test_success_writes_only_the_five_verified_policies(self):
        original = deepcopy(self.original)
        report = self.continue_once()
        self.assertEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [resource for resource in self.cloud.changes if resource != ACCOUNT])
        first_write = next(i for i, (operation, _) in enumerate(self.cloud.calls) if operation == "write")
        before = self.cloud.calls[:first_write]
        self.assertEqual({key for operation, key in before if operation == "role"}, set(self.cloud.roles))
        self.assertEqual({key for operation, key in before if operation == "policy"}, set(self.cloud.changes))
        self.assertTrue(any(operation == "grantable" for operation, _ in before))
        grantability = json.loads((self.journal / "compute-grantable.json").read_bytes())
        self.assertEqual(grantability["resource"], GRANTABLE_INSTANCE)
        self.assertEqual(grantability["matching_role"]["name"], self.cloud.changes[INSTANCE]["binding"]["role"])
        self.assertEqual(report["policy_actions"], {target: "preserved_original" if target == ACCOUNT else "written_and_verified"
                                                   for target in self.cloud.changes})
        self.assertEqual(self.original, original)
        self.assertEqual(self.cloud.policies[ACCOUNT], self.original["policies"][ACCOUNT]["after"])
        self.assertEqual(self.cloud.policies[delta.BUCKET]["auditConfigs"],
                         self.cloud.changes[delta.BUCKET]["before"]["auditConfigs"])

    def test_complete_result_preserves_the_consumers_receipt_contracts(self):
        report = self.continue_once()
        self.assertEqual(report["status"], "applied_and_verified")
        source = {"operation_id": ORIGINAL_ID, "controls_commit": ORIGINAL_COMMIT,
                  "result_sha256": self.authority["original_result_sha256"],
                  "reconciliation_sha256": self.authority["reconciliation_sha256"]}
        delta.keep_receipt(self.journal / "result.json", report)
        references = resume.keep_final_receipts(self.journal, report, self.cloud.changes, self.authority, source)
        for name, reference in references.items():
            raw = (self.journal / name).read_bytes()
            self.assertEqual(reference, {"bytes": len(raw), "sha256": delta.sha(raw)})
        deploy = json.loads((self.journal / "deploy-policy-receipt.json").read_bytes())
        native = json.loads((self.journal / "native-iam-receipt.json").read_bytes())
        continuation = json.loads((self.journal / "continuation-receipt.json").read_bytes())
        self.assertEqual(continuation["original"], source)
        self.assertEqual(continuation["operation_id"], CONTINUATION_ID)
        self.assertEqual(continuation["final_etags"], {name: policy["etag"] for name, policy in self.cloud.policies.items()})
        self.assertEqual(set(deploy["policies"]), set(delta.NOBLE))
        self.assertEqual(deploy["policies"]["account"]["after"], self.original["policies"][ACCOUNT]["after"])
        self.assertEqual(native["controls_commit"], CONTROLS_COMMIT)
        self.assertEqual(native["noble_policies"], deploy)
        self.assertEqual(set(native["secret_policies"]), set(delta.SECRETS))
        self.assertIsNone(native["iap_policy"])

    def test_exact_binding_already_present_is_read_and_never_rewritten(self):
        self.cloud.requested_policy_present(delta.BUCKET)
        report = self.continue_once()
        self.assertEqual(report["status"], "applied_and_verified")
        self.assertEqual(len(self.cloud.writes), 4)
        self.assertNotIn(delta.BUCKET, self.cloud.writes)
        self.assertEqual(report["policy_actions"][delta.BUCKET], "already_exact")
        self.assertEqual(report["policies"][delta.BUCKET]["after"], self.cloud.policies[delta.BUCKET])

    def test_foreign_policy_drift_blocks_before_any_mutation(self):
        name = delta.SECRETS[-1]
        current = self.cloud.policies[name]
        current["bindings"].append({"role": "roles/editor", "members": ["user:external@example.test"]})
        current["etag"] = "new-external-etag"
        report = self.continue_once()
        self.assertNotEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [])

    def test_account_etag_drift_blocks_even_when_approved_binding_survives(self):
        self.cloud.policies[ACCOUNT]["etag"] = "unknown-account-etag"
        report = self.continue_once()
        self.assertNotEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [])

    def test_bad_original_policy_reference_blocks_before_cloud_reads(self):
        self.reconciliation["reconciled_policies"][-1]["live_policy_sha256"] = "0" * 64
        report = self.continue_once()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["primary_error"], "resume_original_policy_readback_changed")
        self.assertEqual(self.cloud.calls, [])

    def test_own_role_is_checked_for_eligibility_not_just_definition(self):
        self.cloud.grantable = False
        report = self.continue_once()
        self.assertNotEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [])
        self.assertTrue(any(operation == "grantable" for operation, _ in self.cloud.calls))

    def test_grantability_can_be_proved_on_later_page(self):
        self.cloud.grantable_after_first_page = True
        report = self.continue_once()
        self.assertEqual(report["status"], "applied_and_verified")
        self.assertEqual(len(self.cloud.writes), 5)
        self.assertTrue(any(operation == "grantable" and details.get("pageToken") == "fixture-page-two"
                            for operation, details in self.cloud.calls))

    def test_timeout_after_policy_effect_reconciles_by_read_and_stops(self):
        self.cloud.error = TimeoutError("synthetic journal transport timeout")
        self.cloud.apply_before_error = True
        report = self.continue_once()
        self.assertNotEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [INSTANCE])
        sent = self.cloud.calls.index(("write", INSTANCE))
        self.assertIn(("policy", INSTANCE), self.cloud.calls[sent + 1:])
        self.assertTrue(any("intent" in item.name for item in self.journal.iterdir()))

    def test_explicit_rejection_does_not_retry_and_keeps_safe_error_proof(self):
        message = "Synthetic resource rejected the binding."
        self.cloud.error = delta.iam.CloudError(400, diagnostic={"status": "INVALID_ARGUMENT", "message": message})
        report = self.continue_once()
        self.assertEqual(report["status"], "rejected_reconciled")
        self.assertEqual(report["primary_error"], "http_400")
        self.assertEqual(self.cloud.writes, [INSTANCE])
        self.assertIn(message, json.dumps(report))
        self.assertEqual(self.cloud.policies[INSTANCE], self.cloud.changes[INSTANCE]["before"])

    def test_role_definition_drift_cannot_reach_a_policy_write(self):
        name = self.cloud.changes[INSTANCE]["binding"]["role"]
        self.cloud.roles[name]["includedPermissions"] = ["compute.instances.setIamPolicy"]
        report = self.continue_once()
        self.assertNotEqual(report["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [])

    def test_consumed_journal_blocks_on_reentry_before_any_policy_write(self):
        self.assertEqual(self.continue_once()["status"], "applied_and_verified")
        self.cloud = CloudFixture(self.profile, self.original)
        try:
            result = self.continue_once()
        except FileExistsError:
            pass
        else:
            self.assertNotEqual(result["status"], "applied_and_verified")
        self.assertEqual(self.cloud.writes, [])

    def test_authority_rejects_original_id_and_mismatched_controller_hash(self):
        controller_sha = self.authority["controller_sha256"]
        self.assertEqual(resume.validate_authority(self.authority, CONTROLS_COMMIT, controller_sha), self.authority)
        for mutation in ({"operation_id": ORIGINAL_ID}, {"controller_sha256": "0" * 64}):
            with self.subTest(mutation=mutation), self.assertRaisesRegex(ValueError, "resume_exact_authority_required"):
                resume.validate_authority({**self.authority, **mutation}, CONTROLS_COMMIT, controller_sha)

    def test_archived_journal_has_to_match_all_original_custody_references(self):
        origin = Path(self.work.name) / "original"
        archived = origin / ORIGINAL_ID
        archived.mkdir(parents=True)
        approver = {"operation_id": ORIGINAL_ID, "controls_commit": ORIGINAL_COMMIT}
        self.original["approval_sha256"] = delta.iam.digest(approver)
        self.reconciliation.update(custody=str(archived), approval_sha256_canonical=self.original["approval_sha256"])
        documents = {"result.json": self.original,
                     "initial.json": {"authority": approver, "policies": self.cloud.changes},
                     "policy-0.response.json": self.original["policies"][ACCOUNT]["after"]}
        for index, name in enumerate(self.original["roles_created"]):
            documents[f"role-{index}.intent.json"] = {"operation": "createRole", "resource": name}
        for index, name in enumerate((ACCOUNT, INSTANCE)):
            documents[f"policy-{index}.intent.json"] = {"operation": "setIamPolicy", "resource": name, **self.cloud.changes[name]}
        references = {}
        for name, document in documents.items():
            path = archived / name
            delta.keep_receipt(path, document)
            raw = path.read_bytes()
            references[name] = {"sha256": delta.sha(raw), "bytes": len(raw)}
        self.reconciliation["files"] = references
        delta.keep_receipt(origin / "owner-decision.json", approver)
        delta.keep_receipt(origin / "profile.json", self.profile)
        reconciliation_path = origin / "reconciliation.json"
        delta.keep_receipt(reconciliation_path, self.reconciliation)
        authority = {**self.authority, "original_result_sha256": references["result.json"]["sha256"],
                     "reconciliation_sha256": delta.sha(reconciliation_path.read_bytes())}
        with (patch.object(resume, "ORIGINAL_RESULT", authority["original_result_sha256"]),
              patch.object(delta, "load_profile", return_value=self.profile)):
            original, reconciliation, source = resume.history(self.profile, origin, authority)
            self.assertEqual((original, reconciliation), (self.original, self.reconciliation))
            self.assertEqual(source["receipts"], references)
            path = archived / "policy-1.intent.json"
            path.write_bytes(path.read_bytes() + b"\n")
            with self.assertRaisesRegex(ValueError, "resume_original_journal_bytes_changed"):
                resume.history(self.profile, origin, authority)


class RejectionDiagnosticTests(unittest.TestCase):
    def test_opt_in_preserves_a_bounded_sanitized_google_message(self):
        url = delta.noble.ROUTES["instance"][1]
        message = f"Role not recognized. Token {TOKEN}.\n" + "detail " * 130
        payload = json.dumps({"error": {"status": "INVALID_ARGUMENT", "message": message,
                                         "details": [{"private": "fixture detail must be omitted"}]}}).encode()
        response = HTTPError(url, 400, "Fixture rejection", {}, BytesIO(payload))
        opener = Mock()
        opener.open.side_effect = response
        with patch.object(delta.iam, "build_opener", return_value=opener):
            with self.assertRaises(delta.iam.CloudError) as caught:
                delta.iam.request_json(url, TOKEN, retain_error=True)
        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic["status"], "INVALID_ARGUMENT")
        self.assertTrue(diagnostic["message"].startswith("Role not recognized."))
        self.assertNotIn(TOKEN, json.dumps(diagnostic))
        self.assertNotIn("fixture detail must be omitted", json.dumps(diagnostic))
        self.assertNotIn("\n", diagnostic["message"])
        self.assertLessEqual(len(diagnostic["message"]), 700)

    def test_existing_transport_still_discards_the_error_body_by_default(self):
        url = delta.noble.ROUTES["instance"][1]
        stream = Mock()
        response = HTTPError(url, 403, "Fixture rejection", {}, stream)
        opener = Mock()
        opener.open.side_effect = response
        with patch.object(delta.iam, "build_opener", return_value=opener):
            with self.assertRaises(delta.iam.CloudError) as caught:
                delta.iam.request_json(url, TOKEN)
        self.assertIsNone(caught.exception.diagnostic)
        stream.read.assert_not_called()


if __name__ == "__main__":
    unittest.main()
