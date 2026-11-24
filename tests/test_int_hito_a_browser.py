from datetime import datetime, timezone
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.parse import urlsplit

from scripts import int_hito_a_acceptance as api_acceptance
from scripts import int_hito_a_browser as browser_acceptance


COMMIT = "a" * 40
DIGEST = "b" * 64
OLD_REVISION = "clipforge-int-api-00001-old"
NEW_REVISION = "clipforge-int-api-00002-new"
IAP_TOKEN = "iap-browser-private-token-" + "i" * 32
ADMIN = {"username": "hito_a_admin", "password": "admin-browser-private-password"}
ACCOUNT = {
    "id": "2" * 32,
    "username": "qa_hito_a_" + "3" * 20,
    "password": "account-browser-private-password-123",
}
NOW = datetime(2026, 11, 24, 20, 0, tzinfo=timezone.utc)


class FakeResponse:
    def __init__(self, url, status, content_type):
        self.url = url
        self.status = status
        self.headers = {"content-type": content_type}


class FakeRequest:
    def __init__(self, url):
        self.url = url
        self.headers = {"accept": "text/html"}


class FakeRoute:
    def __init__(self):
        self.aborted = False
        self.continued = False
        self.headers = None

    def abort(self, _reason):
        self.aborted = True

    def continue_(self, *, headers):
        self.continued = True
        self.headers = headers


class FakeLocator:
    def __init__(self, page, selector):
        self.page = page
        self.selector = selector

    def fill(self, value):
        self.page.fields[self.selector] = value

    def click(self):
        self.page.click(self.selector)


class FakePage:
    def __init__(self, context):
        self.context = context
        self.backend = context.backend
        self.handlers = {}
        self.fields = {}
        self.identity = None
        self.url = "about:blank"

    def on(self, event, callback):
        self.handlers.setdefault(event, []).append(callback)

    def emit(self, event, value):
        for callback in self.handlers.get(event, []):
            callback(value)

    def load_assets(self):
        for path, kind in browser_acceptance.EXPECTED_ASSETS.items():
            if (path in self.backend.missing_assets
                    or path in self.backend.missing_assets_by_context[self.context.label]):
                continue
            url = browser_acceptance.ORIGIN + path
            if not self.context.fetch(url):
                self.emit("requestfailed", FakeRequest(url))
                continue
            content_type = "text/css; charset=utf-8" if kind == "css" else "text/javascript; charset=utf-8"
            self.emit("response", FakeResponse(url, 200, content_type))

    def goto(self, url, **_kwargs):
        self.backend.visited[self.context.label].append(urlsplit(url).path)
        if not self.context.fetch(url):
            self.emit("requestfailed", FakeRequest(url))
            return None
        path = urlsplit(url).path
        if path == "/account" and self.identity is None:
            self.context.fetch(browser_acceptance.ORIGIN + "/login")
            self.url = browser_acceptance.ORIGIN + "/login"
        else:
            self.url = browser_acceptance.ORIGIN + path
        self.load_assets()
        if self.backend.external_request and not self.backend.external_emitted:
            self.backend.external_emitted = True
            request = FakeRequest("https://example.invalid/tracker.js")
            if not self.context.fetch(request.url):
                self.emit("requestfailed", request)
        if self.backend.console_error:
            self.emit("console", SimpleNamespace(type="error"))
        if self.backend.page_error:
            self.emit("pageerror", RuntimeError("private page failure"))
        return FakeResponse(self.url, 200, "text/html")

    def wait_for_selector(self, selector, **_kwargs):
        if selector != "#login-form" or urlsplit(self.url).path != "/login":
            raise AssertionError("login form not visible")

    def locator(self, selector):
        return FakeLocator(self, selector)

    def click(self, selector):
        if selector == '#login-form button[type="submit"]':
            username = self.fields.get("#username")
            password = self.fields.get("#password")
            if (username, password) == (ADMIN["username"], ADMIN["password"]):
                self.identity = {"username": username, "is_admin": True}
            elif (username, password) == (ACCOUNT["username"], ACCOUNT["password"]):
                self.identity = {"username": username, "is_admin": False}
            else:
                raise AssertionError("unexpected credentials")
            self.context.fetch(browser_acceptance.ORIGIN + "/")
            self.url = browser_acceptance.ORIGIN + "/"
            self.load_assets()
            return
        if selector == "[data-auth-logout]":
            if self.identity is None:
                raise AssertionError("logout without identity")
            self.identity = None
            self.context.fetch(browser_acceptance.ORIGIN + "/login")
            self.url = browser_acceptance.ORIGIN + "/login"
            self.load_assets()
            return
        raise AssertionError(selector)

    def wait_for_url(self, expected, **_kwargs):
        if self.url != expected:
            raise AssertionError((self.url, expected))

    def wait_for_function(self, _expression, *, arg=None, timeout):
        if self.identity is None or (arg is not None and not arg) or timeout != browser_acceptance.TIMEOUT_MS:
            raise AssertionError("dynamic UI was not ready")

    def evaluate(self, _expression):
        if urlsplit(self.url).path != "/account":
            raise AssertionError("account UI was not opened explicitly")
        if self.identity["is_admin"]:
            return {
                "username": self.identity["username"],
                "role": "Administrador de usuarios",
                "usersVisible": True,
                "auditVisible": True,
                "recoveryVisible": True,
                "users": "Cuenta " + ACCOUNT["username"],
                "audit": "Cuenta creada " + ACCOUNT["id"],
            }
        return {
            "username": self.identity["username"],
            "role": "Usuario",
            "usersHidden": True,
            "auditHidden": True,
            "recoveryHidden": True,
        }


class FakeContext:
    def __init__(self, backend, label):
        self.backend = backend
        self.label = label
        self.route_handler = None

    def route(self, pattern, handler):
        if pattern != "**/*":
            raise AssertionError(pattern)
        self.route_handler = handler

    def fetch(self, url):
        route = FakeRoute()
        self.route_handler(route, FakeRequest(url))
        if route.aborted:
            self.backend.aborted_urls.append(url)
            return False
        if not route.continued:
            raise AssertionError("request was neither continued nor aborted")
        self.backend.continued_headers.append((url, route.headers))
        return True

    def new_page(self):
        return FakePage(self)

    def close(self):
        self.backend.closed_contexts += 1


class FakeBrowser:
    def __init__(self, backend):
        self.backend = backend
        self.version = backend.browser_version

    def new_context(self, **kwargs):
        self.backend.context_options.append(kwargs)
        label = "admin" if len(self.backend.context_options) == 1 else "ordinary"
        return FakeContext(self.backend, label)

    def close(self):
        self.backend.browser_closed = True


class FakeChromium:
    def __init__(self, backend):
        self.backend = backend

    def launch(self, **kwargs):
        self.backend.launch_options = kwargs
        return FakeBrowser(self.backend)


class FakeManager:
    def __init__(self, backend):
        self.playwright = SimpleNamespace(chromium=FakeChromium(backend))

    def __enter__(self):
        return self.playwright

    def __exit__(self, *_args):
        return False


class FakeBackend:
    def __init__(self):
        self.browser_version = "140.0.7339.16"
        self.missing_assets = set()
        self.missing_assets_by_context = {"admin": set(), "ordinary": set()}
        self.console_error = False
        self.page_error = False
        self.external_request = False
        self.external_emitted = False
        self.aborted_urls = []
        self.continued_headers = []
        self.context_options = []
        self.visited = {"admin": [], "ordinary": []}
        self.closed_contexts = 0
        self.browser_closed = False
        self.launch_options = None

    def factory(self):
        return FakeManager(self)


class HitoABrowserTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-hito-a-browser-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name).resolve()
        self.browser = self.root / "chromium"
        self.browser.write_bytes(b"fixture executable")
        self.private = self.root / "acceptance-private.json"
        private_state = {
            "schema": api_acceptance.STATE_SCHEMA,
            "origin": api_acceptance.ORIGIN,
            "created_utc": "2026-11-24T19:55:00Z",
            "before": {"revision": OLD_REVISION, "digest": DIGEST, "commit": COMMIT},
            "account": dict(ACCOUNT),
        }
        descriptor = os.open(self.private, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(json.dumps(private_state).encode("utf-8"))
        self.environ = {
            "INT_IAP_ACCESS_TOKEN": IAP_TOKEN,
            "INT_BOOTSTRAP_ADMIN": json.dumps(ADMIN),
        }
        self.state = {
            "expected_commit": COMMIT,
            "expected_revision": NEW_REVISION,
            "expected_digest": "sha256:" + DIGEST,
            "private_state_path": str(self.private),
        }
        self.backend = FakeBackend()

    def run_acceptance(self, **overrides):
        options = {
            "playwright_factory": self.backend.factory,
            "browser_resolver": lambda _env: self.browser,
            "version_getter": lambda _package: browser_acceptance.PLAYWRIGHT_VERSION,
            "clock": lambda: NOW,
        }
        options.update(overrides)
        return browser_acceptance.run(self.environ, self.state, **options)

    def test_real_browser_contract_passes_and_receipt_is_sanitized(self):
        report = self.run_acceptance()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["revision"], NEW_REVISION)
        self.assertEqual(report["assets"], {
            "css": ["/static/account.css"],
            "javascript": ["/static/account.js", "/static/auth.js"],
            "contexts_verified": 2,
        })
        self.assertEqual(report["errors"], {"page": 0, "console": 0, "request": 0, "observer": 0})
        self.assertEqual(self.backend.closed_contexts, 2)
        self.assertTrue(self.backend.browser_closed)
        self.assertEqual(len(self.backend.context_options), 2)
        self.assertIn("/account", self.backend.visited["admin"])
        self.assertIn("/account", self.backend.visited["ordinary"])
        self.assertTrue(self.backend.continued_headers)
        for url, headers in self.backend.continued_headers:
            self.assertTrue(url.startswith(browser_acceptance.ORIGIN + "/"))
            self.assertEqual(headers["Authorization"], "Bearer " + IAP_TOKEN)
        material = json.dumps(report)
        for private in (
            IAP_TOKEN, ADMIN["username"], ADMIN["password"], ACCOUNT["id"],
            ACCOUNT["username"], ACCOUNT["password"], str(self.private),
        ):
            self.assertNotIn(private, material)

    def test_playwright_and_chromium_receive_no_protected_process_environment(self):
        protected = {name: "private-" + name.lower()
                     for name in browser_acceptance.SENSITIVE_PROCESS_ENV}
        with mock.patch.dict(os.environ, {**protected, "PATH": "safe-path"}, clear=True):
            report = self.run_acceptance()
            self.assertEqual(report["status"], "passed")
            self.assertTrue(all(name not in os.environ for name in protected))
        self.assertEqual(self.backend.launch_options["env"], {"PATH": "safe-path"})
        self.assertFalse(set(self.backend.launch_options["env"]) & set(protected))

    def test_console_and_page_errors_fail_closed_without_error_text(self):
        for kind in ("console_error", "page_error"):
            with self.subTest(kind=kind):
                self.backend = FakeBackend()
                setattr(self.backend, kind, True)
                report = self.run_acceptance()
                self.assertEqual(report["status"], "blocked")
                self.assertEqual(report["failed_check"],
                                 "browser_console_error" if kind == "console_error" else "browser_page_error")
                self.assertNotIn("private page failure", json.dumps(report))

    def test_missing_javascript_fails_closed(self):
        self.backend.missing_assets_by_context["ordinary"].add("/static/auth.js")
        report = self.run_acceptance()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["failed_check"], "browser_assets_missing")

    def test_external_request_is_aborted_before_iap_header_can_be_added(self):
        self.backend.external_request = True
        report = self.run_acceptance()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["failed_check"], "browser_external_request")
        self.assertEqual(self.backend.aborted_urls, ["https://example.invalid/tracker.js"])
        self.assertFalse(any(url.startswith("https://example.invalid/")
                             for url, _headers in self.backend.continued_headers))

    def test_same_revision_is_rejected_before_browser_launch(self):
        self.state["expected_revision"] = OLD_REVISION
        report = self.run_acceptance()
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["failed_check"], "browser_revision_not_replaced")
        self.assertIsNone(self.backend.launch_options)

    def test_wrong_playwright_version_is_rejected_before_browser_launch(self):
        report = self.run_acceptance(version_getter=lambda _package: "1.64.0")
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["failed_check"], "playwright_version")
        self.assertIsNone(self.backend.launch_options)

    def test_exception_messages_and_private_state_never_enter_blocked_receipt(self):
        def fail(_factory, _executable, inputs):
            raise RuntimeError("failure with " + inputs["account"]["password"])

        report = self.run_acceptance(executor=fail)
        self.assertEqual(report["status"], "blocked")
        self.assertEqual(report["error_type"], "RuntimeError")
        self.assertNotIn(ACCOUNT["password"], json.dumps(report))
        self.assertNotIn(str(self.private), json.dumps(report))


if __name__ == "__main__":
    unittest.main()
