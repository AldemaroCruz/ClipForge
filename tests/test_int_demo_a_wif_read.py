from io import BytesIO
import json
import unittest
from unittest.mock import Mock
from urllib.error import HTTPError
from urllib.parse import parse_qs, urlsplit

from scripts import int_demo_a_wif_read as wif


class Response(BytesIO):
    def __init__(self, value, headers=None):
        super().__init__(json.dumps(value).encode())
        self.status = 200
        self.headers = headers or {}


class WifReadTests(unittest.TestCase):
    def test_narrow_noble_policy_followup_uses_only_the_two_omitted_requests(self):
        compute, tunnel = wif.noble_policy_probes()
        self.assertEqual((compute.method, compute.body), ("GET", None))
        self.assertTrue(compute.url.endswith("/instances/clipforge-int-db01-noble/getIamPolicy?optionsRequestedPolicyVersion=3"))
        self.assertEqual((tunnel.method, tunnel.body), ("POST", {"options": {"requestedPolicyVersion": 3}}))
        self.assertTrue(tunnel.url.endswith("/instances/7365414160255801909:getIamPolicy"))
        opener = Mock()
        opener.open.return_value = Response({"etag": "fixture=", "bindings": []})
        row = wif.observe(tunnel, "fixture", wif.SA["deploy"], opener=opener)
        self.assertEqual((row["result"], row["policy_etag"], len(row["policy_sha256"])), ("policy_read_wif", "fixture=", 64))

    def probe(self, identity, permission, operation_prefix, resource):
        return next(p for p in wif.probes(identity) if permission in p.permissions and p.operation.startswith(operation_prefix)
                    and resource in p.resource)

    def test_service_specific_read_and_evaluate_transports(self):
        secret = self.probe("deploy", "secretmanager.secrets.getIamPolicy", "policy:", "clipforge-int-postgres-ca")
        self.assertEqual((secret.method, secret.body), ("GET", None))
        self.assertTrue(secret.url.endswith(":getIamPolicy?options.requestedPolicyVersion=3"))
        account = self.probe("terraform", "iam.serviceAccounts.getIamPolicy", "policy:", "clipforge-api-int")
        self.assertEqual((account.method, account.body), ("POST", None))
        self.assertTrue(account.url.endswith(":getIamPolicy?options.requestedPolicyVersion=3"))
        storage = self.probe("deploy", "storage.objects.create", "evaluate:", "buckets/")
        self.assertEqual((storage.method, storage.body), ("GET", None))
        self.assertTrue(urlsplit(storage.url).path.endswith("/iam/testPermissions"))
        self.assertEqual(parse_qs(urlsplit(storage.url).query)["permissions"], ["storage.objects.get", "storage.objects.create"])
        iap = self.probe("terraform", "iap.webServices.getIamPolicy", "policy:", "clipforge-int-api")
        self.assertEqual(iap.body, {"options": {"requestedPolicyVersion": 3}})

    def test_no_mutating_or_secret_payload_request_is_present(self):
        for identity in ("terraform", "deploy"):
            queries = list(wif.probes(identity))
            self.assertTrue(queries)
            for operation in queries:
                self.assertIn(operation.method, ("GET", "POST"))
                self.assertNotIn("run.jobs.delete", operation.permissions)
                suffix = urlsplit(operation.url).path
                self.assertNotRegex(suffix, r":(?:access|addVersion|run|setIamPolicy)$|^/upload/|/versions/")
                if operation.method == "POST":
                    self.assertRegex(suffix, r"(?::getIamPolicy|[:/]testIamPermissions)$")
        self.assertEqual(set(wif.JOBS), {"clipforge-int-bootstrap", "clipforge-int-db01-noble-migration", "clipforge-int-db01-noble-acceptance"})

    def test_local_source_guard_can_run_before_int_approval_or_oidc(self):
        approved = "a" * 40
        env = {"GITHUB_REPOSITORY": wif.REPO, "GITHUB_REF": wif.REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_WORKFLOW_REF": f"{wif.REPO}/{wif.WORKFLOW}@{wif.REF}", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_ACTIONS": "true",
               "GITHUB_SHA": approved, "INT_APPROVED_COMMIT": approved, "GITHUB_RUN_ID": "100"}
        wif.hosted_context(env)
        with self.assertRaisesRegex(ValueError, "fixed_wif_identity_and_provider"):
            wif.preflight("terraform", env)
        env["INT_APPROVED_COMMIT"] = "b" * 40
        with self.assertRaisesRegex(ValueError, "exact_dispatch_source"):
            wif.hosted_context(env)

    def test_empty_evaluation_is_not_permission_and_denial_does_not_echo_body(self):
        storage = self.probe("deploy", "storage.objects.create", "evaluate:", "buckets/")
        opener = Mock()
        opener.open.return_value = Response({})
        row = wif.observe(storage, "fixture", wif.SA["deploy"], opener=opener)
        self.assertEqual(row["result"], "no_permission_confirmed_by_evaluation")
        self.assertEqual(row["permissions_indicated"], [])
        self.assertIn("storage.objects.create", row["permissions_not_confirmed"])
        self.assertFalse(row["write_executed"])
        opener.open.side_effect = HTTPError(storage.url, 403, "private server message", {}, BytesIO(b"private server body"))
        row = wif.observe(storage, "fixture", wif.SA["deploy"], opener=opener)
        self.assertEqual(row["result"], "denied")
        self.assertEqual(row["failure_scope"], "this_request_only")
        self.assertNotIn("private server", json.dumps(row))
        opener.open.side_effect = HTTPError(storage.url, 404, "private server message", {}, BytesIO(b"private server body"))
        self.assertEqual(wif.observe(storage, "fixture", wif.SA["deploy"], opener=opener)["result"], "not_found_or_not_visible")

    def test_policy_result_is_scoped_to_the_actual_principal(self):
        secret = self.probe("deploy", "secretmanager.secrets.getIamPolicy", "policy:", "clipforge-int-postgres-ca")
        opener = Mock()
        opener.open.return_value = Response({"bindings": [
            {"role": "roles/secretmanager.secretVersionAdder", "members": ["serviceAccount:" + wif.SA["deploy"]], "condition": {"expression": "private"}},
            {"role": "roles/owner", "members": ["user:private@example.invalid"]}]})
        row = wif.observe(secret, "fixture", wif.SA["deploy"], opener=opener)
        self.assertEqual(row["direct_policy_roles"], [{"role": "roles/secretmanager.secretVersionAdder", "conditional": True}])
        self.assertNotIn("private", json.dumps(row))
        self.assertNotIn("permissions_indicated", row)

    def test_live_job_reads_validate_exact_identity_and_404_stays_open(self):
        target = self.probe("terraform", "run.jobs.get", "read:", "clipforge-int-bootstrap")
        self.assertEqual(parse_qs(urlsplit(target.url).query)["fields"], ["name,uid,generation"])
        opener = Mock()
        job_name = target.resource.replace(wif.PROJECT, wif.NUMBER, 1)
        uid = "d5a9a174-5add-46ce-bac7-0e5251badf4a"
        opener.open.return_value = Response({"name": job_name, "unexpected": "private", "uid": uid, "generation": "5"})
        row = wif.observe(target, "fixture", wif.SA["terraform"], opener=opener)
        self.assertEqual(row["result"], "read_verified_wif")
        self.assertEqual((row["job_present"], row["uid"], row["generation"]), (True, uid, "5"))
        self.assertNotIn("private", json.dumps(row))
        opener.open.return_value = Response({"name": job_name})
        row = wif.observe(target, "fixture", wif.SA["terraform"], opener=opener)
        self.assertTrue(row["job_present"])
        self.assertNotIn("uid", row)
        self.assertNotIn("generation", row)
        opener.open.return_value = Response({"name": job_name, "generation": "9223372036854775808"})
        self.assertEqual(wif.observe(target, "fixture", wif.SA["terraform"], opener=opener)["result"], "indeterminate_response")
        opener.open.return_value = Response({"name": target.resource + "-other"})
        self.assertEqual(wif.observe(target, "fixture", wif.SA["terraform"], opener=opener)["result"], "indeterminate_response")


if __name__ == "__main__":
    unittest.main()
