"""Real post-replacement browser acceptance for the protected INT Hito A UI.

The browser uses the preinstalled hosted-runner Chrome/Chromium selected by the
delivery job.  IAP credentials are injected only into requests for the fixed
INT origin; redirects or subresources for any other origin are blocked before
credentials can be attached.  No screenshots, traces, HAR files, storage
state, response bodies or exception messages are retained.
"""
from __future__ import annotations

from collections.abc import Mapping
from datetime import datetime, timezone
import importlib.metadata
import json
import os
from pathlib import Path
import re
import shutil
from urllib.parse import urlsplit

from scripts import int_hito_a_acceptance as api_acceptance


SCHEMA = "clipforge-int-hito-a-browser-acceptance-1"
PLAYWRIGHT_VERSION = "1.64.1"
ORIGIN = api_acceptance.ORIGIN
EXPECTED_ASSETS = {
    "/static/account.css": "css",
    "/static/account.js": "javascript",
    "/static/auth.js": "javascript",
}
BROWSER_NAMES = ("google-chrome", "google-chrome-stable", "chromium", "chromium-browser")
TIMEOUT_MS = 30_000
SAFE_BROWSER_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9 ._()+-]{0,127}")
SENSITIVE_PROCESS_ENV = {
    "GCP_ACCESS_TOKEN", "INT_IAP_ACCESS_TOKEN", "INT_DEMO_A_IAP_TOKEN",
    "INT_BOOTSTRAP_ADMIN", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH",
    "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
    "ACTIONS_ID_TOKEN_REQUEST_URL",
}
BROWSER_ENV_ALLOWLIST = {
    "HOME", "PATH", "LANG", "LC_ALL", "TZ", "TMPDIR", "XDG_RUNTIME_DIR",
    "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "SSL_CERT_FILE", "SSL_CERT_DIR",
}


class BrowserAcceptanceError(RuntimeError):
    """Credential-free, stable browser acceptance failure code."""


def require(condition, code):
    if not condition:
        raise BrowserAcceptanceError(code)


def utc_now():
    return datetime.now(timezone.utc)


def utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def record(report, name):
    require(name not in {row["id"] for row in report["checks"]}, "duplicate_browser_check")
    report["checks"].append({"id": name, "status": "passed"})


def resolve_browser(environ):
    authored = environ.get("INT_HITO_A_BROWSER_EXECUTABLE", "")
    if authored:
        require(isinstance(authored, str) and "\x00" not in authored and Path(authored).is_absolute(),
                "browser_executable_path")
        candidate = Path(authored).resolve()
    else:
        found = next((shutil.which(name) for name in BROWSER_NAMES if shutil.which(name)), None)
        require(found is not None, "preinstalled_browser_missing")
        candidate = Path(found).resolve()
    require(candidate.is_absolute() and candidate.is_file(), "preinstalled_browser_missing")
    return candidate


def _playwright_factory():
    from playwright.sync_api import sync_playwright
    return sync_playwright()


def _admin(environ):
    try:
        value = json.loads(environ.get("INT_BOOTSTRAP_ADMIN", ""))
    except (TypeError, ValueError):
        raise BrowserAcceptanceError("browser_admin_environment") from None
    try:
        return api_acceptance.validate_admin(value)
    except api_acceptance.AcceptanceError:
        raise BrowserAcceptanceError("browser_admin_environment") from None


def _token(environ):
    value = environ.get("INT_IAP_ACCESS_TOKEN") or environ.get("INT_DEMO_A_IAP_TOKEN")
    try:
        return api_acceptance.validate_token(value)
    except api_acceptance.AcceptanceError:
        raise BrowserAcceptanceError("browser_iap_token") from None


def _private_inputs(environ, state):
    require(isinstance(environ, Mapping) and isinstance(state, Mapping), "browser_call_shape")
    commit = state.get("expected_commit")
    revision = state.get("expected_revision")
    raw_digest = state.get("expected_digest")
    require(isinstance(commit, str) and api_acceptance.SHA40.fullmatch(commit), "browser_expected_commit")
    require(isinstance(revision, str) and api_acceptance.REVISION.fullmatch(revision)
            and revision.startswith(api_acceptance.SERVICE + "-"), "browser_expected_revision")
    require(isinstance(raw_digest, str), "browser_expected_digest")
    digest = raw_digest.removeprefix("sha256:")
    require(api_acceptance.SHA256.fullmatch(digest), "browser_expected_digest")
    try:
        private_path = Path(state.get("private_state_path", ""))
    except TypeError:
        raise BrowserAcceptanceError("browser_private_state_path") from None
    require(private_path.is_absolute(), "browser_private_state_path")
    try:
        private, _ = api_acceptance.load_state(private_path)
    except api_acceptance.AcceptanceError:
        raise BrowserAcceptanceError("browser_private_state") from None
    before, account = private["before"], private["account"]
    require(before["commit"] == commit, "browser_private_state_commit")
    require(before["digest"] == digest, "browser_private_state_digest")
    require(before["revision"] != revision, "browser_revision_not_replaced")
    return {
        "commit": commit,
        "revision": revision,
        "digest": digest,
        "private_path": str(private_path),
        "account": account,
        "admin": _admin(environ),
        "iap_token": _token(environ),
    }


def _scrub_process_environment():
    for name in SENSITIVE_PROCESS_ENV:
        os.environ.pop(name, None)
    return {name: value for name, value in os.environ.items()
            if name in BROWSER_ENV_ALLOWLIST and isinstance(value, str) and "\x00" not in value}


def _same_origin(url):
    parsed = urlsplit(url)
    return (parsed.scheme == "https" and parsed.hostname == urlsplit(ORIGIN).hostname
            and (parsed.port or 443) == 443 and not parsed.username and not parsed.password)


def _route_iap(token, external_requests, continued_requests):
    def handler(route, request):
        if not _same_origin(request.url):
            external_requests.append(request.url)
            route.abort("blockedbyclient")
            return
        headers = {key: value for key, value in request.headers.items() if key.lower() != "authorization"}
        headers["Authorization"] = "Bearer " + token
        route.continue_(headers=headers)
        continued_requests.append("authorized")
    return handler


def _observe_page(page, label, assets, page_errors, console_errors, request_failures,
                  observer_errors, intentionally_blocked):
    def response_observer(response):
        try:
            path = urlsplit(response.url).path
            if path not in EXPECTED_ASSETS:
                return
            headers = response.headers
            assets[label][path] = {
                "status": response.status,
                "content_type": headers.get("content-type", "").split(";", 1)[0].strip().lower(),
            }
        except Exception:
            observer_errors.append("response")

    def console_observer(message):
        try:
            if message.type == "error":
                console_errors.append("console")
        except Exception:
            observer_errors.append("console")

    page.on("response", response_observer)
    page.on("pageerror", lambda _error: page_errors.append("page"))
    page.on("console", console_observer)
    def request_failed(request):
        try:
            if request.url not in intentionally_blocked:
                request_failures.append("request")
        except Exception:
            observer_errors.append("request")

    page.on("requestfailed", request_failed)


def _login(page, username, password, expected_commit):
    page.goto(ORIGIN + "/login", wait_until="networkidle", timeout=TIMEOUT_MS)
    page.wait_for_selector("#login-form", state="visible", timeout=TIMEOUT_MS)
    page.locator("#username").fill(username)
    page.locator("#password").fill(password)
    page.locator('#login-form button[type="submit"]').click()
    page.wait_for_url(ORIGIN + "/", wait_until="networkidle", timeout=TIMEOUT_MS)
    page.wait_for_function(
        """([username, commit]) => {
          const user = document.querySelector('[data-auth-user]');
          const badge = document.querySelector('#environment-badge');
          return user?.textContent === username && badge?.title === commit;
        }""",
        arg=[username, expected_commit], timeout=TIMEOUT_MS,
    )


def _logout_and_prove_revocation(page):
    page.locator("[data-auth-logout]").click()
    page.wait_for_url(ORIGIN + "/login", wait_until="networkidle", timeout=TIMEOUT_MS)
    page.goto(ORIGIN + "/account", wait_until="networkidle", timeout=TIMEOUT_MS)
    require(page.url == ORIGIN + "/login", "browser_logout_session_active")


def _admin_snapshot(page, account):
    page.wait_for_function(
        """([username, accountId]) => {
          const users = document.querySelector('#user-list')?.textContent || '';
          const audit = document.querySelector('#audit-list')?.textContent || '';
          return users.includes(username) && audit.includes(accountId) && audit.includes('Cuenta creada');
        }""",
        arg=[account["username"], account["id"]], timeout=TIMEOUT_MS,
    )
    return page.evaluate(
        """() => ({
          username: document.querySelector('[data-auth-user]')?.textContent || '',
          role: document.querySelector('#account-role')?.textContent || '',
          usersVisible: !document.querySelector('#users-panel')?.hidden,
          auditVisible: !document.querySelector('#audit-panel')?.hidden,
          recoveryVisible: !document.querySelector('#recovery-panel')?.hidden,
          users: document.querySelector('#user-list')?.textContent || '',
          audit: document.querySelector('#audit-list')?.textContent || ''
        })"""
    )


def _ordinary_snapshot(page):
    page.wait_for_function(
        """() => document.querySelector('#account-role')?.textContent === 'Usuario'""",
        timeout=TIMEOUT_MS,
    )
    return page.evaluate(
        """() => ({
          username: document.querySelector('[data-auth-user]')?.textContent || '',
          role: document.querySelector('#account-role')?.textContent || '',
          usersHidden: Boolean(document.querySelector('#users-panel')?.hidden),
          auditHidden: Boolean(document.querySelector('#audit-panel')?.hidden),
          recoveryHidden: Boolean(document.querySelector('#recovery-panel')?.hidden)
        })"""
    )


def _asset_contract(assets):
    require(set(assets) == {"admin", "ordinary"}, "browser_asset_contexts")
    for observed in assets.values():
        require(set(observed) == set(EXPECTED_ASSETS), "browser_assets_missing")
        for path, kind in EXPECTED_ASSETS.items():
            row = observed[path]
            require(row["status"] == 200, "browser_asset_status")
            if kind == "css":
                require(row["content_type"] == "text/css", "browser_asset_content_type")
            else:
                require(row["content_type"] in {
                    "application/javascript", "application/x-javascript", "text/javascript"
                }, "browser_asset_content_type")


def execute_browser(factory, executable, inputs):
    assets = {"admin": {}, "ordinary": {}}
    page_errors, console_errors, request_failures = [], [], []
    external_requests, continued_requests, observer_errors = [], [], []
    browser = None
    with factory() as playwright:
        browser = playwright.chromium.launch(
            executable_path=str(executable), headless=True,
            args=["--disable-dev-shm-usage"],
            env=inputs["browser_env"],
        )
        try:
            version = str(browser.version)
            require(SAFE_BROWSER_VERSION.fullmatch(version), "browser_version_value")
            for label, credential, is_admin in (
                ("admin", inputs["admin"], True),
                ("ordinary", inputs["account"], False),
            ):
                context = browser.new_context(
                    viewport={"width": 1280, "height": 960},
                    java_script_enabled=True, accept_downloads=False,
                    ignore_https_errors=False, service_workers="block",
                )
                try:
                    context.route("**/*", _route_iap(
                        inputs["iap_token"], external_requests, continued_requests
                    ))
                    page = context.new_page()
                    _observe_page(page, label, assets, page_errors, console_errors,
                                  request_failures, observer_errors, external_requests)
                    _login(page, credential["username"], credential["password"], inputs["commit"])
                    page.goto(ORIGIN + "/account", wait_until="networkidle", timeout=TIMEOUT_MS)
                    page.wait_for_url(ORIGIN + "/account", wait_until="networkidle", timeout=TIMEOUT_MS)
                    if is_admin:
                        snapshot = _admin_snapshot(page, inputs["account"])
                        require(snapshot.get("username") == credential["username"]
                                and snapshot.get("role") == "Administrador de usuarios"
                                and snapshot.get("usersVisible") is True
                                and snapshot.get("auditVisible") is True
                                and snapshot.get("recoveryVisible") is True
                                and inputs["account"]["username"] in snapshot.get("users", "")
                                and inputs["account"]["id"] in snapshot.get("audit", "")
                                and "Cuenta creada" in snapshot.get("audit", ""),
                                "browser_admin_ui_contract")
                    else:
                        snapshot = _ordinary_snapshot(page)
                        require(snapshot == {
                            "username": credential["username"], "role": "Usuario",
                            "usersHidden": True, "auditHidden": True, "recoveryHidden": True,
                        }, "browser_ordinary_ui_contract")
                    _logout_and_prove_revocation(page)
                finally:
                    context.close()
        finally:
            if browser is not None:
                browser.close()
    _asset_contract(assets)
    require(continued_requests, "browser_iap_not_exercised")
    require(not external_requests, "browser_external_request")
    require(not observer_errors, "browser_observer_error")
    require(not request_failures, "browser_request_failed")
    require(not page_errors, "browser_page_error")
    require(not console_errors, "browser_console_error")
    return {
        "browser_version": version,
        "assets": {
            "css": [path for path, kind in sorted(EXPECTED_ASSETS.items()) if kind == "css"],
            "javascript": [path for path, kind in sorted(EXPECTED_ASSETS.items()) if kind == "javascript"],
            "contexts_verified": 2,
        },
        "errors": {"page": 0, "console": 0, "request": 0, "observer": 0},
        "iap": {"bearer_scoped_to_origin": True, "external_requests": 0},
        "admin_ui": {"login": True, "users": True, "audit": True, "logout": True},
        "persistent_account_ui": {"login": True, "admin_panels_hidden": True, "logout": True},
    }


def _secret_free(report, inputs):
    raw = canonical(report)
    exact_values = (
        inputs["private_path"], inputs["admin"]["username"], inputs["admin"]["password"],
        inputs["account"]["id"], inputs["account"]["username"], inputs["account"]["password"],
        inputs["iap_token"],
    )
    for value in exact_values:
        encoded = canonical(value)
        require(encoded not in raw, "browser_receipt_contains_private_value")
    for value in (inputs["admin"]["password"], inputs["account"]["password"], inputs["iap_token"]):
        require(value.encode("utf-8") not in raw, "browser_receipt_contains_credential")


def run(environ, state, *, playwright_factory=None, browser_resolver=resolve_browser,
        version_getter=importlib.metadata.version, executor=execute_browser, clock=utc_now):
    """Execute the real post-replacement browser acceptance and return a safe receipt.

    ``state`` requires ``expected_commit``, ``expected_revision``,
    ``expected_digest`` and the absolute ``private_state_path`` created by API
    acceptance. Secrets are read only from the supplied environment and that
    private file. They are never returned.
    """
    report = {
        "schema": SCHEMA, "operation": "post_replacement_browser",
        "status": "blocked", "stage": "input_validation",
        "started_utc": utc(clock()), "checks": [],
    }
    inputs = None
    try:
        inputs = _private_inputs(environ, state)
        inputs["browser_env"] = _scrub_process_environment()
        report.update(controls_commit=inputs["commit"], origin=ORIGIN,
                      revision=inputs["revision"], digest=inputs["digest"])
        record(report, "private_persistence_state_bound")
        report["stage"] = "browser_toolchain"
        version = version_getter("playwright")
        require(version == PLAYWRIGHT_VERSION, "playwright_version")
        executable = browser_resolver(environ)
        require(isinstance(executable, Path) and executable.is_absolute() and executable.is_file(),
                "preinstalled_browser_missing")
        report["toolchain"] = {
            "playwright_version": version,
            "browser_family": "chromium",
            "preinstalled_browser": True,
        }
        record(report, "pinned_playwright_preinstalled_browser")
        report["stage"] = "browser_acceptance"
        factory = playwright_factory or _playwright_factory
        evidence = executor(factory, executable, inputs)
        require(isinstance(evidence, dict), "browser_evidence_shape")
        report.update(evidence)
        for check in (
            "iap_scoped_css_javascript_loaded",
            "admin_ui_login_users_audit_logout",
            "persistent_account_ui_login_logout",
            "zero_page_console_request_errors",
        ):
            record(report, check)
        report["persistence"] = {"revision_replaced": True, "account_verified": True}
        report["credentials_present"] = False
        report["status"] = "passed"
        report["stage"] = "complete"
    except Exception as error:
        report["status"] = "blocked"
        report["error_type"] = type(error).__name__
        if isinstance(error, BrowserAcceptanceError):
            report["failed_check"] = str(error)
    report["finished_utc"] = utc(clock())
    if inputs is not None:
        _secret_free(report, inputs)
    return report
