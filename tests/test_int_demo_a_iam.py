"""Exercise the scoped administrative delta without a cloud client or live policy."""

from copy import deepcopy
from datetime import datetime, timedelta, timezone
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock
from urllib.parse import parse_qs, unquote, urlsplit

from scripts import int_demo_a_iam as delta


COMMIT = "a" * 40
RESOURCE = delta.NOBLE["account"]
ROLE = "projects/clipforgebeta2/roles/clipforgeIntReadPostgresPolicy_20261118T180000Z"
RECIPIENT = delta.noble.PRINCIPAL
DEFINITION = {"title": "fixture", "description": "fixture", "stage": "GA", "includedPermissions": ["iam.serviceAccounts.getIamPolicy"]}
BASE = {"version": 3, "etag": "before", "bindings": [{"role": "roles/iam.serviceAccountUser", "members": [RECIPIENT]}],
        "auditConfigs": [{"service": "example.googleapis.com", "auditLogConfigs": [{"logType": "ADMIN_READ"}]}]}
ADDITION = {"role": ROLE, "members": [RECIPIENT]}
TOKEN = "local-token-placeholder"


def changes():
    return {RESOURCE: {"before": deepcopy(BASE), "requested": delta.policy({**BASE, "bindings": [*BASE["bindings"], ADDITION]}),
                       "roles": {"mode": "reuse", "definition": DEFINITION}, "binding": ADDITION}}


def approved(operation="apply", **extra):
    now = datetime.now(timezone.utc)
    return {"schema": delta.APPROVAL_SCHEMA, "operation": operation, "operation_id": "b" * 32, "phase": "before_bootstrap",
            "controls_commit": COMMIT, "profile_sha256": delta.PROFILE_SHA, "owner": delta.iam.ADMIN,
            "approval_ref": "synthetic unit test", "valid_from": (now - timedelta(minutes=1)).isoformat(),
            "expires_at": (now + timedelta(minutes=5)).isoformat(), "protected_apply": None, "iap_before": None,
            "prerequisites_sha256": None, "withdraw_from": None, **extra}


class CloudFixture:
    def __init__(self):
        self.policy = deepcopy(BASE)
        self.calls = []
        self.error = None

    def __call__(self, url, token, method="GET", body=None):
        self.calls.append((url, method, deepcopy(body)))
        if url.endswith(RECIPIENT.removeprefix("serviceAccount:")):
            return {"projectId": delta.PROJECT, "email": RECIPIENT.removeprefix("serviceAccount:")}
        if url.endswith(ROLE):
            return {"name": ROLE, **DEFINITION}
        if ":getIamPolicy?options.requestedPolicyVersion=3" in url and method == "POST" and body is None:
            return deepcopy(self.policy)
        if url.endswith(RESOURCE + ":setIamPolicy") and method == "POST":
            if self.error:
                raise self.error
            assert body["updateMask"] == "bindings,etag" and body["policy"]["etag"] == self.policy["etag"]
            self.policy = {**body["policy"], "etag": self.policy["etag"] + "-new"}
            return deepcopy(self.policy)
        raise AssertionError((method, url))


class ScopedIamTests(unittest.TestCase):
    def test_apply_captures_cas_and_complete_policy_before_and_after(self):
        cloud = CloudFixture()
        with TemporaryDirectory() as work:
            directory = Path(work)
            result = delta.run_changes(changes(), approved(), TOKEN, directory, request=cloud)
            self.assertTrue((directory / "policy-0.intent.json").is_file())
            self.assertTrue((directory / "policy-0.response.json").is_file())
        self.assertEqual(result["status"], "applied_and_verified")
        self.assertEqual(result["policies"][RESOURCE], {"before": BASE, "after": cloud.policy})
        self.assertEqual(cloud.policy["auditConfigs"], BASE["auditConfigs"])
        self.assertEqual(len([url for url, _, _ in cloud.calls if ":setIamPolicy" in url]), 1)

    def test_preexisting_drift_blocks_before_writes(self):
        cloud = CloudFixture()
        cloud.policy["etag"] = "different"
        with TemporaryDirectory() as work:
            result = delta.run_changes(changes(), approved(), TOKEN, Path(work), request=cloud)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["checks"], [{"operation": "getIamPolicy", "resource": RESOURCE, "reason": "full_policy_or_etag_drift"}])
        self.assertFalse(any(":setIamPolicy" in url for url, _, _ in cloud.calls))

    def test_unknown_mutation_preserves_intent_and_refuses_automatic_withdraw(self):
        cloud = CloudFixture()
        cloud.error = TimeoutError()
        with TemporaryDirectory() as work:
            directory = Path(work)
            result = delta.run_changes(changes(), approved(), TOKEN, directory, request=cloud)
            self.assertTrue((directory / "policy-0.intent.json").is_file())
            self.assertFalse((directory / "policy-0.response.json").exists())
        self.assertEqual(result["status"], "indeterminate_reconciliation_required")
        self.assertEqual(result["primary_error"], "TimeoutError")
        decision = approved("withdraw", withdraw_from=delta.iam.digest(result))
        with self.assertRaisesRegex(ValueError, "iam_withdraw_source_unreconciled"):
            delta.withdraw_changes(changes(), decision, result)

    def test_malformed_mutation_reply_keeps_primary_failure_and_cas_intent(self):
        cloud = CloudFixture()

        def broken_reply(url, token, method="GET", body=None):
            reply = cloud(url, token, method, body)
            return [] if ":setIamPolicy" in url else reply

        with TemporaryDirectory() as work:
            directory = Path(work)
            report = delta.run_changes(changes(), approved(), TOKEN, directory, request=broken_reply)
            self.assertTrue((directory / "policy-0.intent.json").is_file())
            self.assertTrue((directory / "policy-0.response.json").is_file())
        self.assertEqual(report["status"], "indeterminate_reconciliation_required")
        self.assertEqual(report["primary_error"], "unexpected_iam_write_response")

    def test_verified_withdraw_requires_current_etag_and_restores_exact_binding_set(self):
        cloud = CloudFixture()
        with TemporaryDirectory() as before, TemporaryDirectory() as after:
            result = delta.run_changes(changes(), approved(), TOKEN, Path(before), request=cloud)
            decision = approved("withdraw", withdraw_from=delta.iam.digest(result))
            withdraw = delta.withdraw_changes(changes(), decision, result)
            report = delta.run_changes(withdraw, decision, TOKEN, Path(after), request=cloud)
        self.assertEqual(report["status"], "withdrawn_and_verified")
        self.assertEqual(delta.iam.semantic(cloud.policy), delta.iam.semantic(BASE))
        cloud.policy["etag"] = "external-change"
        self.assertEqual(delta.preflight(withdraw, TOKEN, cloud, withdrawing=True)[0]["reason"], "full_policy_or_etag_drift")

    def test_storage_and_iap_keep_their_transport_contracts(self):
        cloud = Mock(return_value={**BASE, "kind": "storage#policy", "resourceId": delta.BUCKET})
        delta.read_policy(delta.BUCKET, TOKEN, cloud)
        cloud.assert_called_once_with(delta.STORAGE + "/iam?optionsRequestedPolicyVersion=3", TOKEN, "GET", None)
        delta.write_policy(delta.BUCKET, BASE, TOKEN, cloud)
        self.assertEqual(cloud.call_args.args, (delta.STORAGE + "/iam", TOKEN, "PUT", BASE))
        delta.write_policy(delta.IAP, BASE, TOKEN, cloud)
        self.assertEqual(cloud.call_args.args, (delta.native.IAP_API + ":setIamPolicy", TOKEN, "POST", {"policy": BASE}))
        delta.write_policy(delta.NOBLE["instance"], BASE, TOKEN, cloud)
        self.assertTrue(cloud.call_args.args[0].endswith("clipforge-int-db01-noble/setIamPolicy"))

    def test_secret_manager_reads_version_three_in_query_with_empty_body(self):
        cloud = Mock(return_value=BASE)
        for resource in delta.SECRETS:
            url = f"https://secretmanager.googleapis.com/v1/{resource}:getIamPolicy?options.requestedPolicyVersion=3"
            self.assertEqual(delta.read_policy(resource, TOKEN, cloud), BASE)
            self.assertEqual(cloud.call_args.args, (url, TOKEN, "GET", None))

    def test_private_manifest_read_binds_explicit_identity_and_actual_generation(self):
        raw = b'{"manifest":"fixture"}'
        reference = {"name": f"private-plans/int/{COMMIT}/123456-1/manifest.json", "generation": "24",
                     "size": len(raw), "sha256": delta.sha(raw)}
        opener = Mock()
        opener.open.return_value = BytesIO(raw)
        self.assertEqual(delta.fetch_protected_manifest(reference, TOKEN, opener=opener), raw)
        request = opener.open.call_args.args[0]
        url = urlsplit(request.full_url)
        self.assertEqual((request.get_method(), request.get_header("Authorization"), url.scheme, url.hostname),
                         ("GET", "Bearer " + TOKEN, "https", "storage.googleapis.com"))
        self.assertTrue(unquote(url.path).endswith("/o/" + reference["name"]))
        self.assertEqual(parse_qs(url.query), {"alt": ["media"], "generation": ["24"], "ifGenerationMatch": ["24"]})
        opener.open.return_value = BytesIO(raw + b"\n")
        with self.assertRaisesRegex(ValueError, "iam_protected_manifest_bytes_changed"):
            delta.fetch_protected_manifest(reference, TOKEN, opener=opener)

    def test_for_phase_two_exact_native_apply_and_live_iap_identity_are_required(self):
        deployment = delta.scope
        service = {"uid": "service-fixture", "generation": "1"}
        state = {**deployment.STATE, "generation": str(int(deployment.STATE["generation"]) + 1),
                 "serial": deployment.STATE["serial"] + 1, "sha256": "c" * 64}
        prior = {"schema": "clipforge-int-demo-a-result-2", "phase": "apply", "run": "123456", "controls_commit": COMMIT,
                 "deployment_phase": deployment.PROTECTED_RUNTIME, "status": "applied_verified", "managed_count": 58,
                 "iap_verified": True, "firewall_verified": True, "state_before_generation": deployment.STATE["generation"],
                 "plan_sha256": "d" * 64, "state_after": state, "run_service": service}
        raw = delta.iam.custody.canonical(prior)
        ref = {"name": f"private-plans/int/{COMMIT}/123456-1/manifest.json", "generation": "12", "size": len(raw),
               "sha256": delta.sha(raw)}
        run = {"id": 123456, "run_attempt": 1, "status": "completed", "conclusion": "success", "head_sha": COMMIT,
               "head_branch": delta.native.BRANCH, "event": "workflow_dispatch", "path": delta.native.WORKFLOWS["apply"]}
        self.assertEqual(delta.verify_protected_service(COMMIT, ref, raw, TOKEN, lambda _: run, lambda *_: service), prior)
        with self.assertRaisesRegex(ValueError, "iam_protected_service_identity_changed"):
            delta.verify_protected_service(COMMIT, ref, raw, TOKEN, lambda _: run, lambda *_: {**service, "generation": "2"})
        with self.assertRaisesRegex(ValueError, "iam_protected_apply_run_changed"):
            delta.verify_protected_service(COMMIT, ref, raw, TOKEN, lambda _: {**run, "conclusion": "failure"}, lambda *_: service)

    def test_authority_rejects_out_of_phase_fields_and_expired_decision(self):
        self.assertEqual(delta.authority(approved(), COMMIT, "apply")["controls_commit"], COMMIT)
        with self.assertRaisesRegex(ValueError, "iam_authority_phase_binding"):
            delta.authority(approved(prerequisites_sha256="e" * 64), COMMIT, "apply")
        with self.assertRaisesRegex(ValueError, "iam_decision_not_current"):
            delta.authority(approved(expires_at="2000-01-01T00:00:00+00:00"), COMMIT, "apply")

    def test_guest_custody_allowlist_preserves_operation_bound_names(self):
        env = {"GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "1"}
        names = delta.receipts.producer_names(env, "guest_intervention", "b" * 32)
        self.assertEqual(set(names), {"noble-intervention-intent.json", "noble-intervention-result.json"})
        self.assertTrue(all(delta.receipts.NAME.fullmatch(value) for value in names.values()))
        self.assertIsNone(delta.receipts.NAME.fullmatch(names["noble-intervention-result.json"].replace("123456-1", "123456-2")))


if __name__ == "__main__":
    unittest.main()
