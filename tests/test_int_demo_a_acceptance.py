from contextlib import redirect_stdout
from datetime import datetime, timezone
import io
import json
import os
from pathlib import Path
from types import MappingProxyType
from types import SimpleNamespace
import tempfile
import unittest
from urllib.parse import urlsplit

from scripts import int_hito_a_acceptance as acceptance


COMMIT = "a" * 40
DIGEST = "b" * 64
IMAGE = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + DIGEST
GCP_TOKEN = "gcp-private-token-" + "g" * 32
IAP_TOKEN = "iap-private-token-" + "i" * 32
ADMIN_PASSWORD = "admin-private-password-123456789"
ADMIN = "hito_a_admin"
ADMIN_ID = "1" * 32
ACCOUNT_ID = "2" * 32
NOW = datetime(2026, 11, 24, 18, 0, tzinfo=timezone.utc)


def response(status, value=b"", headers=None):
    if isinstance(value, (dict, list)):
        value = json.dumps(value).encode()
        headers = {"content-type": "application/json", **(headers or {})}
    return acceptance.Response(status, {key.lower(): item for key, item in (headers or {}).items()}, value)


def revision_resource(name):
    return f"{acceptance.SERVICE_RESOURCE}/revisions/{name}"


class CloudHTTP:
    def __init__(self, revision, *, image=IMAGE, traffic=None, public=False, owner=True):
        self.revision = revision
        self.image = image
        self.traffic = traffic or [{"revision": revision_resource(revision), "percent": 100}]
        self.public = public
        self.owner = owner
        self.reported_uri = acceptance.ORIGIN
        self.reported_urls = []
        self.reported_revision_service = acceptance.SERVICE_RESOURCE
        self.calls = []

    def request(self, method, url, **kwargs):
        self.calls.append((method, url, kwargs))
        service = acceptance.RUN_API + acceptance.SERVICE_RESOURCE
        if method == "GET" and url == service:
            return response(200, {
                "name": acceptance.SERVICE_RESOURCE,
                "uid": "service-uid-fixture",
                "generation": "17",
                "observedGeneration": "17",
                "reconciling": False,
                "terminalCondition": {"state": "CONDITION_SUCCEEDED"},
                "iapEnabled": True,
                "invokerIamDisabled": False,
                "uri": self.reported_uri,
                "urls": self.reported_urls,
                "latestReadyRevision": revision_resource(self.revision),
                "latestCreatedRevision": revision_resource(self.revision),
                "template": {"containers": [{"image": self.image}]},
                "trafficStatuses": self.traffic,
            })
        if method == "GET" and url == acceptance.RUN_API + revision_resource(self.revision):
            return response(200, {
                "name": revision_resource(self.revision),
                "service": self.reported_revision_service,
                "reconciling": False,
                "conditions": [{"type": "Ready", "state": "CONDITION_SUCCEEDED"}],
                "containers": [{"image": self.image}],
                "logUri": "https://console.cloud.google.com/logs/viewer?project=clipforgebeta2",
            })
        if method == "GET" and url.endswith(":getIamPolicy?options.requestedPolicyVersion=3"):
            members = [acceptance.IAP_AGENT]
            if self.public:
                members.append("allUsers")
            return response(200, {"bindings": [{"role": "roles/run.invoker", "members": members}]})
        if method == "POST" and url == acceptance.IAP_API + acceptance.IAP_RESOURCE + ":getIamPolicy":
            members = [acceptance.OWNER_MEMBER] if self.owner else ["user:other@example.test"]
            return response(200, {"bindings": [{"role": "roles/iap.httpsResourceAccessor", "members": members}]})
        raise AssertionError((method, url))


class CloudRunURLTests(unittest.TestCase):
    def test_catalog_authorizes_the_fixed_origin_for_the_exact_service(self):
        cloud = CloudHTTP("clipforge-int-api-00001-2pp")
        cloud.reported_uri = "https://clipforge-int-api-fixture-uc.a.run.app"
        cloud.reported_urls = [cloud.reported_uri, acceptance.ORIGIN]
        cloud.reported_revision_service = acceptance.SERVICE
        self.assertEqual(acceptance.inspect_cloud(cloud, IMAGE)["uri"], acceptance.ORIGIN)
        cloud.reported_urls = [cloud.reported_uri]
        with self.assertRaisesRegex(acceptance.AcceptanceError, "cloud_service_uri"):
            acceptance.inspect_cloud(cloud, IMAGE)


class DeniedHTTP:
    def __init__(self, *, allow=False):
        self.allow = allow
        self.calls = 0

    def request(self, method, url, **kwargs):
        self.calls += 1
        if self.allow:
            return response(200, {"status": "ok", "profile": "int-demo-a"})
        return response(302, b"", {"location": "https://accounts.google.com/o/oauth2/auth"})


class Backend:
    def __init__(self):
        self.users = {
            ADMIN: {"id": ADMIN_ID, "username": ADMIN, "password": ADMIN_PASSWORD,
                    "is_admin": True, "is_active": True, "permissions": ["users:manage"]}
        }
        self.created_posts = 0

    def session(self, token):
        if token != IAP_TOKEN:
            raise AssertionError("wrong authored IAP token")
        return SessionHTTP(self)


class SessionHTTP:
    def __init__(self, backend):
        self.backend = backend
        self.user = None
        self.csrf = None

    def request(self, method, url, *, headers=None, body=None, maximum=None):
        del maximum
        path = urlsplit(url).path
        query = urlsplit(url).query
        if method == "GET" and path == "/health":
            return response(200, {"status": "ok", "profile": "int-demo-a"})
        if method == "GET" and path == "/environment":
            return response(200, {"environment": "INT", "revision": COMMIT})
        if method == "GET" and path == "/login":
            return response(200, b'<form id="login-form"></form><script src="/static/auth.js"></script>',
                            {"content-type": "text/html"})
        if method == "GET" and path == "/auth/csrf":
            self.csrf = "csrf-authored-fixture-" + "x" * 24
            return response(200, {"csrf_token": self.csrf})
        if method == "POST" and path == "/auth/login":
            user = self.backend.users.get(body.get("username"))
            if user is None or body.get("password") != user["password"] or not user["is_active"]:
                return response(401, {"detail": "Usuario o contraseña incorrectos."})
            if headers.get("X-CSRF-Token") != self.csrf:
                return response(403, {"detail": "La verificación CSRF falló."})
            self.user = user
            self.csrf = "csrf-session-fixture-" + "y" * 24
            public = {key: value for key, value in user.items() if key != "password"}
            return response(200, {"user": public, "csrf_token": self.csrf})
        if method == "GET" and path == "/account":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            return response(200, b'<section id="users-panel"></section><section id="audit-panel"></section><button data-auth-logout></button>',
                            {"content-type": "text/html"})
        if method == "POST" and path == "/auth/users":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            if not self.user["is_admin"]:
                return response(403, {"detail": "Se requiere el permiso users:manage."})
            self.backend.created_posts += 1
            user = {"id": ACCOUNT_ID, "username": body["username"], "password": body["password"],
                    "is_admin": False, "is_active": True, "permissions": []}
            self.backend.users[user["username"]] = user
            return response(201, {"user": {key: value for key, value in user.items() if key != "password"}})
        if method == "GET" and path == "/auth/users":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            if not self.user["is_admin"]:
                return response(403, {"detail": "Se requiere el permiso users:manage."})
            return response(200, {"users": [{key: value for key, value in user.items() if key != "password"}
                                             for user in self.backend.users.values()]})
        if method == "GET" and path == "/auth/admin/audit":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            if not self.user["is_admin"]:
                return response(403, {"detail": "Se requiere el permiso users:manage."})
            target = next((user for user in self.backend.users.values() if not user["is_admin"]), None)
            item = {"actor_id": ADMIN_ID, "target_id": target["id"], "action": "user.created",
                    "created_at": "2026-11-24T18:00:00Z", "result": "success",
                    "correlation_id": "00000000-0000-4000-8000-000000000001"}
            self.last_audit_query = query
            return response(200, {"items": [item], "page": 1, "page_size": 100, "total": 1})
        if method == "GET" and path == "/auth/me":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            return response(200, {"user": {key: value for key, value in self.user.items() if key != "password"}})
        if method == "POST" and path == "/auth/logout":
            if self.user is None:
                return response(401, {"detail": "Inicia sesión"})
            if headers.get("X-CSRF-Token") != self.csrf:
                return response(403, {"detail": "La verificación CSRF falló."})
            self.user = None
            return response(200, {"status": "logged_out"})
        raise AssertionError((method, path, body))


class FailingCreateBackend(Backend):
    def session(self, token):
        session = super().session(token)
        original = session.request

        def request(method, url, **kwargs):
            if method == "POST" and urlsplit(url).path == "/auth/users":
                self.created_posts += 1
                return response(503, {"detail": "Unavailable"})
            return original(method, url, **kwargs)
        session.request = request
        return session


class AcceptanceTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-int-demo-a-acceptance-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.gcp = self.write("gcp-token", GCP_TOKEN)
        self.iap = self.write("iap-token", IAP_TOKEN)
        self.admin = self.write("admin.json", json.dumps({"username": ADMIN, "password": ADMIN_PASSWORD}))
        self.state = self.root / "state.json"
        self.backend = Backend()

    def write(self, name, value):
        path = self.root / name
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            stream.write(value)
            stream.write("\n")
        return path

    def args(self, operation, report, *, image=IMAGE):
        return SimpleNamespace(operation=operation, expected_commit=COMMIT, expected_image=image,
                               gcp_token_file=self.gcp, iap_token_file=self.iap,
                               admin_credentials_file=self.admin, state=self.state, report=self.root / report)

    def execute(self, operation, revision, report, *, backend=None, cloud=None, denial=None):
        output = io.StringIO()
        backend = backend or self.backend
        cloud = cloud or CloudHTTP(revision)
        denial = denial or DeniedHTTP()
        with redirect_stdout(output):
            code = acceptance.run_cli(self.args(operation, report), cloud_http=cloud,
                                      session_factory=backend.session, unauth_http=denial,
                                      clock=lambda: NOW)
        return code, json.loads((self.root / report).read_text()), output.getvalue(), cloud

    def test_prepare_and_verify_real_contract_with_sanitized_receipts(self):
        code, prepared, output, _ = self.execute("prepare", "clipforge-int-api-00001-abc", "prepare.json")
        self.assertEqual(code, 0)
        self.assertEqual(prepared["status"], "prepared_for_revision_replacement")
        self.assertEqual(prepared["service"]["digest"], DIGEST)
        self.assertEqual(prepared["service"]["traffic"], [{"revision": "clipforge-int-api-00001-abc", "percent": 100}])
        self.assertTrue(self.state.is_file())
        state = json.loads(self.state.read_text())
        self.assertEqual(self.backend.created_posts, 1)
        self.assertEqual(state["account"]["id"], ACCOUNT_ID)
        code, verified, verify_output, _ = self.execute("verify", "clipforge-int-api-00002-def", "verify.json")
        self.assertEqual(code, 0)
        self.assertEqual(verified["status"], "passed")
        self.assertEqual(verified["persistence"], {
            "prepared": True, "revision_replaced": True, "verified": True,
            "before_revision": "clipforge-int-api-00001-abc", "after_revision": "clipforge-int-api-00002-def",
        })
        self.assertTrue(verified["account"]["persisted"])
        material = json.dumps(prepared) + json.dumps(verified) + output + verify_output
        for secret in (GCP_TOKEN, IAP_TOKEN, ADMIN_PASSWORD, state["account"]["password"], state["account"]["username"]):
            self.assertNotIn(secret, material)
        self.assertEqual(verified["audit_receipt"]["credentials_present"], False)

    def test_delivery_entrypoint_interface_returns_only_sanitized_dicts(self):
        environ = {"GCP_ACCESS_TOKEN": GCP_TOKEN, "INT_IAP_ACCESS_TOKEN": IAP_TOKEN,
                   "INT_BOOTSTRAP_ADMIN": json.dumps({"username": ADMIN, "password": ADMIN_PASSWORD})}
        state = {"operation": "prepare", "expected_commit": COMMIT, "expected_image": IMAGE,
                 "expected_digest": "sha256:" + DIGEST, "private_state_path": str(self.state)}
        prepared = acceptance.run(MappingProxyType(environ), MappingProxyType(state),
                                  cloud_http=CloudHTTP("clipforge-int-api-00001-abc"),
                                  session_factory=self.backend.session, unauth_http=DeniedHTTP(), clock=lambda: NOW)
        self.assertEqual(prepared["status"], "prepared_for_revision_replacement")
        state["operation"] = "verify"
        verified = acceptance.run(environ, state, cloud_http=CloudHTTP("clipforge-int-api-00002-def"),
                                  session_factory=self.backend.session, unauth_http=DeniedHTTP(), clock=lambda: NOW)
        self.assertEqual(verified["status"], "passed")
        private = json.loads(self.state.read_text())
        material = json.dumps(prepared) + json.dumps(verified)
        for secret in (GCP_TOKEN, IAP_TOKEN, ADMIN_PASSWORD, private["account"]["password"], private["account"]["username"]):
            self.assertNotIn(secret, material)

    def test_short_traffic_revision_is_normalized_to_the_service_resource(self):
        revision = "clipforge-int-api-00001-abc"
        cloud = CloudHTTP(revision, traffic=[{"revision": revision, "percent": 100}])
        code, report, _, _ = self.execute("prepare", "unused", "prepare.json", cloud=cloud)
        self.assertEqual(code, 0)
        self.assertEqual(report["service"]["revision"], revision)

    def test_verify_rejects_same_revision_before_application_requests(self):
        self.execute("prepare", "clipforge-int-api-00001-abc", "prepare.json")
        calls = []
        def forbidden(token):
            calls.append(token)
            self.fail("application acceptance must not run without replacement")
        output = io.StringIO()
        with redirect_stdout(output):
            code = acceptance.run_cli(self.args("verify", "verify.json"),
                cloud_http=CloudHTTP("clipforge-int-api-00001-abc"), session_factory=forbidden,
                unauth_http=DeniedHTTP(), clock=lambda: NOW)
        report = json.loads((self.root / "verify.json").read_text())
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "cloud_revision_was_not_replaced")
        self.assertEqual(calls, [])

    def test_verify_rejects_private_state_from_another_commit(self):
        self.execute("prepare", "clipforge-int-api-00001-abc", "prepare.json")
        state = json.loads(self.state.read_text())
        state["before"]["commit"] = "c" * 40
        self.state.write_text(json.dumps(state), encoding="utf-8")
        calls = []

        def forbidden(token):
            calls.append(token)
            self.fail("application acceptance must not run with stale private state")

        output = io.StringIO()
        with redirect_stdout(output):
            code = acceptance.run_cli(
                self.args("verify", "verify.json"),
                cloud_http=CloudHTTP("clipforge-int-api-00002-def"),
                session_factory=forbidden,
                unauth_http=DeniedHTTP(),
                clock=lambda: NOW,
            )
        report = json.loads((self.root / "verify.json").read_text())
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "acceptance_state_commit_mismatch")
        self.assertEqual(calls, [])

    def test_public_invoker_and_missing_owner_binding_fail_closed(self):
        for index, cloud in enumerate((CloudHTTP("clipforge-int-api-00001-abc", public=True),
                                       CloudHTTP("clipforge-int-api-00001-abc", owner=False))):
            with self.subTest(index=index):
                args = self.args("prepare", f"blocked-{index}.json")
                with redirect_stdout(io.StringIO()):
                    code = acceptance.run_cli(args, cloud_http=cloud, session_factory=self.backend.session,
                                              unauth_http=DeniedHTTP(), clock=lambda: NOW)
                report = json.loads(args.report.read_text())
                self.assertEqual(code, 1)
                self.assertIn(report["failed_check"], {"cloud_run_policy_public", "cloud_iap_owner_access"})
                self.assertFalse(self.state.exists())

    def test_successful_unauthenticated_request_is_not_iap_evidence(self):
        code, report, _, _ = self.execute("prepare", "clipforge-int-api-00001-abc", "blocked.json",
                                          denial=DeniedHTTP(allow=True))
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "iap_unauthenticated_request_not_rejected")
        self.assertFalse(self.state.exists())

    def test_split_traffic_fails_before_creating_account(self):
        other = revision_resource("clipforge-int-api-00000-old")
        cloud = CloudHTTP("clipforge-int-api-00001-abc", traffic=[
            {"revision": revision_resource("clipforge-int-api-00001-abc"), "percent": 50},
            {"revision": other, "percent": 50},
        ])
        code, report, _, _ = self.execute("prepare", "unused", "blocked.json", cloud=cloud)
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "cloud_traffic_not_single_ready_revision")
        self.assertEqual(self.backend.created_posts, 0)

    def test_account_creation_is_never_retried(self):
        backend = FailingCreateBackend()
        code, report, _, _ = self.execute("prepare", "clipforge-int-api-00001-abc", "blocked.json", backend=backend)
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "application_create_user")
        self.assertEqual(backend.created_posts, 1)
        self.assertFalse(self.state.exists())

    def test_missing_persistent_account_blocks_after_revision_change(self):
        self.execute("prepare", "clipforge-int-api-00001-abc", "prepare.json")
        state = json.loads(self.state.read_text())
        self.backend.users.pop(state["account"]["username"])
        code, report, output, _ = self.execute("verify", "clipforge-int-api-00002-def", "verify.json")
        self.assertEqual(code, 1)
        self.assertEqual(report["failed_check"], "application_login")
        self.assertNotIn(state["account"]["password"], json.dumps(report) + output)

    def test_cli_exposes_only_secret_file_inputs(self):
        help_text = acceptance.parser().format_help()
        for direct in ("--gcp-token ", "--iap-token ", "--admin-password", "--password"):
            self.assertNotIn(direct, help_text)
        for safe in ("--gcp-token-file", "--iap-token-file", "--admin-credentials-file", "--state", "--report"):
            self.assertIn(safe, help_text)


if __name__ == "__main__":
    unittest.main()
