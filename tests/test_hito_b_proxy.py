"""Exercise the public relay and private ASGI boundaries without calling GCP."""
from contextlib import nullcontext
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi.testclient import TestClient
from requests.structures import CaseInsensitiveDict

from app import auth, int_beta, int_beta_proxy as proxy


JOB_ID = "b" * 32
CLIP_PATH = f"/jobs/{JOB_ID}/clips/clip_01.mp4"


class PublicProxyTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(proxy.app, base_url=proxy.PUBLIC_ORIGIN)
        self.addCleanup(self.client.close)
        self.upstream = Mock()
        connection = patch.object(proxy, "session", return_value=self.upstream)
        self.connection = connection.start()
        self.addCleanup(connection.stop)
        identity = patch.object(proxy.identity, "token", return_value="server.identity.fixture")
        self.identity = identity.start()
        self.addCleanup(identity.stop)
        self.response = Mock(status_code=200, headers=CaseInsensitiveDict(), raw=Mock())
        self.response.raw.headers.getlist.return_value = []
        self.response.iter_content.return_value = iter([b"response from private API"])
        self.upstream.request.return_value = self.response

    def test_rejects_noncanonical_host_and_cross_origin_mutations_before_upstream(self):
        rejected = (
            ("GET", "/login", {"Host": "unapproved.invalid"}, 421),
            ("GET", "/login", [("Host", proxy.PUBLIC_HOST), ("Host", "unapproved.invalid")], 421),
            ("POST", "/beta/uploads", {}, 403),
            ("POST", "/beta/uploads", {"Origin": "https://unapproved.invalid"}, 403),
            ("POST", "/beta/uploads", {"Origin": proxy.PUBLIC_ORIGIN, "Sec-Fetch-Site": "cross-site"}, 403),
            ("GET", "/jobs", {}, 404),
            ("POST", "/jobs", {"Origin": proxy.PUBLIC_ORIGIN}, 404),
            ("POST", f"/jobs/{JOB_ID}/drafts", {"Origin": proxy.PUBLIC_ORIGIN}, 404),
            ("GET", "/beta/feedback", {}, 404),
            ("GET", "/beta/admin/feedback", {}, 404),
            ("POST", "/beta/feedback", {"Origin": proxy.PUBLIC_ORIGIN}, 404),
        )
        for method, path, headers, expected in rejected:
            with self.subTest(method=method, path=path, headers=headers):
                self.assertEqual(self.client.request(method, path, headers=headers).status_code, expected)
        self.connection.assert_not_called()
        self.identity.assert_not_called()

    def test_uses_fixed_upstream_and_replaces_browser_supplied_identity_headers(self):
        self.response.headers.update({"Content-Type": "application/json", "X-Private-Header": "internal"})
        self.response.raw.headers.getlist.return_value = ["sample=value; Secure; HttpOnly; SameSite=Strict"]
        result = self.client.post("/beta/uploads?limit=5&limit=10", json={"filename": "fixture.mp4"}, headers={
            "Origin": proxy.PUBLIC_ORIGIN,
            "Cookie": "sample=fixture",
            "X-CSRF-Token": "browser-csrf",
            "Authorization": "Bearer browser-controlled",
            "X-Serverless-Authorization": "Bearer browser-controlled",
            proxy.PROXY_ORIGIN_HEADER: "https://unapproved.invalid",
            "X-Forwarded-Host": "unapproved.invalid",
            "X-Forwarded-Proto": "http",
            "X-Forwarded-For": "192.0.2.10",
        })
        self.assertEqual(result.status_code, 200)
        self.identity.assert_called_once_with()
        args, outbound = self.upstream.request.call_args
        self.assertEqual(args, ("POST", proxy.API_ORIGIN + "/beta/uploads"))
        self.assertEqual(outbound["params"], [("limit", "5"), ("limit", "10")])
        self.assertFalse(outbound["allow_redirects"])
        headers = CaseInsensitiveDict(outbound["headers"])
        self.assertEqual(headers["X-Serverless-Authorization"], "Bearer server.identity.fixture")
        self.assertEqual(headers[proxy.PROXY_ORIGIN_HEADER], proxy.PUBLIC_ORIGIN)
        self.assertEqual(headers["origin"], proxy.PUBLIC_ORIGIN)
        self.assertEqual(headers["cookie"], "sample=fixture")
        self.assertEqual(headers["x-csrf-token"], "browser-csrf")
        for forbidden in ("authorization", "host", "x-forwarded-host", "x-forwarded-proto", "x-forwarded-for"):
            self.assertNotIn(forbidden, headers)
        self.assertNotIn("X-Private-Header", result.headers)
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertEqual(result.headers.get_list("set-cookie"), self.response.raw.headers.getlist.return_value)

    def test_relays_single_clip_range_and_partial_response(self):
        self.response.status_code = 206
        self.response.headers.update({"Accept-Ranges": "bytes", "Content-Range": "bytes 10-19/50"})
        self.response.iter_content.return_value = iter([b"0123456789"])
        result = self.client.get(CLIP_PATH, headers={"Range": "bytes=10-19"})
        self.assertEqual((result.status_code, result.content), (206, b"0123456789"))
        self.assertEqual(result.headers["content-range"], "bytes 10-19/50")
        self.assertEqual(CaseInsensitiveDict(self.upstream.request.call_args.kwargs["headers"])["Range"],
                         "bytes=10-19")
        result = self.client.head(CLIP_PATH, headers={"Range": "bytes=10-19"})
        self.assertEqual((result.status_code, result.content), (206, b""))

    def test_blocks_malformed_clip_ranges_and_drops_nonclip_range(self):
        for headers in ({"Range": "bytes=0-1,4-9"}, {"Range": "items=0-1"},
                        [("Range", "bytes=0-1"), ("Range", "bytes=4-9")]):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.get(CLIP_PATH, headers=headers).status_code, 416)
        self.upstream.request.assert_not_called()
        result = self.client.get("/beta/limits", headers={"Range": "bytes=0-1"})
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("Range", CaseInsensitiveDict(self.upstream.request.call_args.kwargs["headers"]))


class PrivateApiBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(int_beta.app, base_url=proxy.API_ORIGIN)
        self.addCleanup(self.client.close)

    def test_denies_missing_forged_and_duplicate_origin_marker(self):
        for headers in ({}, {proxy.PROXY_ORIGIN_HEADER: "https://unapproved.invalid"},
                        [(proxy.PROXY_ORIGIN_HEADER, proxy.PUBLIC_ORIGIN)] * 2):
            with self.subTest(headers=headers):
                self.assertEqual(self.client.get("/environment", headers=headers).status_code, 403)

    def test_rewrites_trusted_origin_and_enforces_session_csrf_and_beta_routes(self):
        session_token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        principal = auth.Principal("a" * 32, "member_fixture", False, True, "c" * 32)
        session = SimpleNamespace(csrf_hash=auth.token_hash(csrf))

        def fixture_session(database, token):
            return (session, None, principal) if token == session_token else None

        headers = {proxy.PROXY_ORIGIN_HEADER: proxy.PUBLIC_ORIGIN, "Origin": proxy.PUBLIC_ORIGIN}
        config = auth.Settings(proxy.PUBLIC_ORIGIN, secure=True, ttl_seconds=3600)
        database = Mock()
        database.execute.return_value.scalar_one_or_none.return_value = None
        with (
            patch.object(auth, "settings", return_value=config),
            patch.object(auth, "_http_storage", side_effect=lambda: nullcontext(database)),
            patch.object(auth, "_session", side_effect=fixture_session),
        ):
            self.assertEqual(self.client.post("/beta/uploads", headers=headers, json={}).status_code, 401)
            headers["Cookie"] = f"{auth.SESSION_COOKIE}={session_token}"
            self.assertEqual(self.client.post("/beta/uploads", headers=headers, json={}).status_code, 403)
            headers["X-CSRF-Token"] = csrf
            self.assertEqual(self.client.post("/beta/uploads", headers={**headers, "Origin": proxy.API_ORIGIN},
                                              json={}).status_code, 403)
            self.assertEqual(self.client.post("/beta/uploads", headers=headers, json={}).status_code, 422)
            self.assertEqual(self.client.post("/jobs", headers=headers, json={}).status_code, 404)
            self.assertEqual(self.client.get("/beta/feedback", headers=headers).status_code, 404)
            self.assertEqual(self.client.post("/beta/feedback", headers=headers, json={}).status_code, 404)
            self.assertEqual(self.client.get("/beta/admin/feedback", headers=headers).status_code, 404)
            self.assertEqual(self.client.post(f"/jobs/{JOB_ID}/editor/range", headers=headers,
                                              json={}).status_code, 404)
            self.assertEqual(self.client.post(f"/jobs/{JOB_ID}/exports/{'a' * 32}/retry", headers=headers,
                                              json={}).status_code, 404)
            self.assertEqual(self.client.get(f"/jobs/{JOB_ID}/source", headers=headers).status_code, 404)
