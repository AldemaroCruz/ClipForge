"""Remote Hito A acceptance for the protected INT Cloud Run account demo.

The executor is deliberately split in two. ``prepare`` creates one synthetic
ordinary account and writes its high-entropy credential only to a private local
state file. Infrastructure then replaces the Cloud Run revision. ``verify``
requires a different ready revision and proves that the account, audit event and
authorization boundaries survived. Neither phase mutates infrastructure or
prints credentials, cookies, bearer tokens, response bodies or request headers.
"""
from __future__ import annotations

import argparse
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import re
import secrets
import stat
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode, urlsplit
from urllib.request import HTTPCookieProcessor, HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROJECT = "clipforgebeta2"
PROJECT_NUMBER = "816643438938"
REGION = "us-central1"
SERVICE = "clipforge-int-api"
ORIGIN = f"https://{SERVICE}-{PROJECT_NUMBER}.{REGION}.run.app"
SERVICE_RESOURCE = f"projects/{PROJECT}/locations/{REGION}/services/{SERVICE}"
RUN_API = "https://run.googleapis.com/v2/"
IAP_API = "https://iap.googleapis.com/v1/"
IAP_RESOURCE = f"projects/{PROJECT_NUMBER}/iap_web/cloud_run-{REGION}/services/{SERVICE}"
IAP_AGENT = f"serviceAccount:service-{PROJECT_NUMBER}@gcp-sa-iap.iam.gserviceaccount.com"
OWNER_MEMBER = "user:admin@ixbalam.studio"
IMAGE = re.compile(
    r"us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/runtime@sha256:([a-f0-9]{64})"
)
SHA40 = re.compile(r"[a-f0-9]{40}")
SHA256 = re.compile(r"[a-f0-9]{64}")
ID = re.compile(r"[a-f0-9]{32}")
REVISION = re.compile(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?")
USERNAME = re.compile(r"qa_hito_a_[a-f0-9]{20}")
STATE_SCHEMA = "clipforge-int-demo-a-acceptance-state-1"
REPORT_SCHEMA = "clipforge-int-demo-a-acceptance-1"
MAX_HTTP = 2 * 1024 * 1024
MAX_SECRET = 16 * 1024
AUDIT_FIELDS = {"actor_id", "target_id", "action", "created_at", "result", "correlation_id"}


class AcceptanceError(RuntimeError):
    """Fixed, credential-free acceptance failure code."""


def require(condition, code):
    if not condition:
        raise AcceptanceError(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def digest(value):
    return hashlib.sha256(value).hexdigest()


def utc_now():
    return datetime.now(timezone.utc)


def utc(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def private_file(path, *, must_exist=True):
    path = Path(path)
    if must_exist:
        require(path.is_absolute() and path.exists() and not path.is_symlink(), "private_file_missing_or_unsafe")
        info = path.stat()
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= MAX_SECRET, "private_file_shape")
        if os.name == "posix":
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "private_file_permissions")
    else:
        require(path.is_absolute() and path.parent.is_dir() and not path.exists(), "new_private_file_required")
    return path


def read_private(path, maximum=MAX_SECRET):
    path = private_file(path)
    raw = path.read_bytes()
    require(0 < len(raw) <= maximum, "private_file_size")
    return raw


def read_token(path):
    try:
        value = read_private(path).decode("ascii").strip()
    except (UnicodeDecodeError, OSError):
        raise AcceptanceError("credential_file_unreadable") from None
    require(20 <= len(value) <= MAX_SECRET and not any(character.isspace() for character in value),
            "credential_file_value")
    return value


def validate_token(value):
    require(isinstance(value, str) and 20 <= len(value) <= MAX_SECRET
            and not any(character.isspace() for character in value), "credential_value")
    return value


def validate_admin(value):
    require(type(value) is dict and set(value) == {"username", "password"}, "admin_credential_fields")
    require(isinstance(value["username"], str) and 1 <= len(value["username"]) <= 64
            and isinstance(value["password"], str) and 12 <= len(value["password"]) <= 128,
            "admin_credential_values")
    return value


def read_admin(path):
    try:
        value = json.loads(read_private(path, 8192))
    except (ValueError, OSError):
        raise AcceptanceError("admin_credential_file_invalid") from None
    return validate_admin(value)


def environment_credentials(environ):
    gcp = validate_token(environ.get("GCP_ACCESS_TOKEN"))
    iap = validate_token(environ.get("INT_IAP_ACCESS_TOKEN") or environ.get("INT_DEMO_A_IAP_TOKEN"))
    try:
        admin = json.loads(environ.get("INT_BOOTSTRAP_ADMIN", ""))
    except ValueError:
        raise AcceptanceError("admin_credential_environment_invalid") from None
    return gcp, iap, validate_admin(admin)


def write_new(path, value):
    path = private_file(path, must_exist=False)
    raw = json.dumps(value, indent=2, sort_keys=True, ensure_ascii=False).encode("utf-8") + b"\n"
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return raw


def load_state(path):
    raw = read_private(path)
    try:
        value = json.loads(raw)
    except ValueError:
        raise AcceptanceError("acceptance_state_invalid") from None
    require(type(value) is dict and set(value) == {"schema", "origin", "created_utc", "before", "account"}
            and value["schema"] == STATE_SCHEMA and value["origin"] == ORIGIN, "acceptance_state_fields")
    before, account = value["before"], value["account"]
    require(type(before) is dict and set(before) == {"revision", "digest", "commit"}
            and REVISION.fullmatch(before["revision"] or "") and SHA256.fullmatch(before["digest"] or "")
            and SHA40.fullmatch(before["commit"] or ""), "acceptance_state_revision")
    require(type(account) is dict and set(account) == {"id", "username", "password"}
            and ID.fullmatch(account["id"] or "") and USERNAME.fullmatch(account["username"] or "")
            and isinstance(account["password"], str) and 24 <= len(account["password"]) <= 128,
            "acceptance_state_account")
    try:
        created = datetime.fromisoformat(value["created_utc"].replace("Z", "+00:00"))
    except (AttributeError, ValueError):
        raise AcceptanceError("acceptance_state_time") from None
    require(created.tzinfo is not None, "acceptance_state_time")
    return value, raw


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, newurl):
        return None


@dataclass(frozen=True)
class Response:
    status: int
    headers: dict[str, str]
    body: bytes


class HTTP:
    """Bounded HTTP transport with isolated cookies and no implicit redirects."""

    def __init__(self, bearer=None, *, timeout=30):
        self.bearer = bearer
        self.timeout = timeout
        self.cookies = http.cookiejar.CookieJar()
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(self.cookies), NoRedirect())

    def request(self, method, url, *, headers=None, body=None, maximum=MAX_HTTP):
        fields = {"Accept": "application/json"}
        if self.bearer is not None:
            fields["Authorization"] = "Bearer " + self.bearer
        for key, value in (headers or {}).items():
            require(key.lower() != "authorization", "authorization_header_override")
            fields[key] = value
        payload = body
        if isinstance(body, (dict, list)):
            payload = canonical(body)
            fields["Content-Type"] = "application/json"
        try:
            response = self.opener.open(Request(url, data=payload, headers=fields, method=method), timeout=self.timeout)
        except HTTPError as error:
            response = error
        except (OSError, URLError):
            raise AcceptanceError("http_transport_failed") from None
        try:
            raw = response.read(maximum + 1)
            result = Response(int(response.status), {key.lower(): value for key, value in response.headers.items()}, raw)
        except OSError:
            raise AcceptanceError("http_response_failed") from None
        finally:
            response.close()
        require(len(result.body) <= maximum, "http_response_too_large")
        return result


def json_body(response, expected, code):
    require(response.status == expected, code)
    try:
        value = json.loads(response.body)
    except (UnicodeDecodeError, ValueError):
        raise AcceptanceError(code + "_json") from None
    require(type(value) is dict, code + "_shape")
    return value


def normalized_resource(value):
    prefix = f"projects/{PROJECT_NUMBER}/"
    return f"projects/{PROJECT}/" + value[len(prefix):] if isinstance(value, str) and value.startswith(prefix) else value


def ready(value):
    terminal = value.get("terminalCondition")
    if isinstance(terminal, dict) and terminal.get("state") == "CONDITION_SUCCEEDED":
        return True
    return any(isinstance(row, dict) and row.get("type") == "Ready" and row.get("state") == "CONDITION_SUCCEEDED"
               for row in value.get("conditions", []))


def revision_leaf(value):
    if isinstance(value, str) and REVISION.fullmatch(value):
        return value, f"{SERVICE_RESOURCE}/revisions/{value}"
    value = normalized_resource(value)
    prefix = f"{SERVICE_RESOURCE}/revisions/"
    require(isinstance(value, str) and value.startswith(prefix), "cloud_revision_resource")
    leaf = value.removeprefix(prefix)
    require(REVISION.fullmatch(leaf or ""), "cloud_revision_name")
    return leaf, value


def validate_log_uri(value):
    parsed = urlsplit(value or "")
    require(parsed.scheme == "https" and parsed.hostname == "console.cloud.google.com"
            and not parsed.username and not parsed.password and len(value) <= 4096, "cloud_revision_log_uri")
    return value


def policy_bindings(value, code):
    bindings = value.get("bindings", [])
    require(isinstance(bindings, list) and all(isinstance(row, dict) for row in bindings), code)
    for row in bindings:
        require(isinstance(row.get("role"), str) and isinstance(row.get("members"), list)
                and all(isinstance(member, str) for member in row["members"]), code)
        require(not ({"allUsers", "allAuthenticatedUsers"} & set(row["members"])), code + "_public")
    return bindings


def inspect_cloud(http, expected_image):
    match = IMAGE.fullmatch(expected_image or "")
    require(match is not None, "expected_runtime_image")
    service_url = RUN_API + SERVICE_RESOURCE
    service = json_body(http.request("GET", service_url), 200, "cloud_service_read")
    require(normalized_resource(service.get("name")) == SERVICE_RESOURCE and service.get("uid")
            and str(service.get("generation", "")).isdecimal()
            and service.get("observedGeneration") is not None
            and str(service["observedGeneration"]) == str(service["generation"])
            and service.get("reconciling", False) is False and ready(service), "cloud_service_not_ready")
    require(service.get("iapEnabled") is True and service.get("invokerIamDisabled", False) is False,
            "cloud_service_iap")
    urls = service.get("urls", [])
    require(isinstance(urls, list) and all(isinstance(url, str) for url in urls)
            and (service.get("uri") == ORIGIN or ORIGIN in urls), "cloud_service_uri")
    latest, revision_resource = revision_leaf(service.get("latestReadyRevision"))
    created, _ = revision_leaf(service.get("latestCreatedRevision"))
    require(created == latest, "cloud_revision_pending")
    template = service.get("template")
    require(isinstance(template, dict) and isinstance(template.get("containers"), list)
            and len(template["containers"]) == 1 and template["containers"][0].get("image") == expected_image,
            "cloud_service_image")

    revision = json_body(http.request("GET", RUN_API + revision_resource), 200, "cloud_revision_read")
    require(normalized_resource(revision.get("name")) == revision_resource
            and normalized_resource(revision.get("service")) in {SERVICE, SERVICE_RESOURCE}
            and revision.get("reconciling", False) is False and ready(revision), "cloud_revision_not_ready")
    containers = revision.get("containers")
    require(isinstance(containers, list) and len(containers) == 1 and isinstance(containers[0], dict),
            "cloud_revision_container")
    require(containers[0].get("image") == expected_image, "cloud_revision_digest")

    statuses = service.get("trafficStatuses")
    require(isinstance(statuses, list) and all(isinstance(row, dict) for row in statuses), "cloud_traffic_shape")
    active = []
    for row in statuses:
        percent = row.get("percent", 0)
        require(type(percent) is int and 0 <= percent <= 100, "cloud_traffic_percent")
        if percent:
            leaf, _ = revision_leaf(row.get("revision"))
            active.append({"revision": leaf, "percent": percent, **({"tag": row["tag"]} if row.get("tag") else {})})
    require(active == [{"revision": latest, "percent": 100}], "cloud_traffic_not_single_ready_revision")

    run_policy = json_body(http.request("GET", service_url + ":getIamPolicy?options.requestedPolicyVersion=3"),
                           200, "cloud_run_policy_read")
    bindings = policy_bindings(run_policy, "cloud_run_policy")
    invokers = [row for row in bindings if row["role"] == "roles/run.invoker"]
    require(len(invokers) == 1 and set(invokers[0]["members"]) == {IAP_AGENT} and not invokers[0].get("condition"),
            "cloud_run_iap_invoker")

    iap_policy = json_body(http.request("POST", IAP_API + IAP_RESOURCE + ":getIamPolicy",
                                        body={"options": {"requestedPolicyVersion": 3}}),
                           200, "cloud_iap_policy_read")
    access = [row for row in policy_bindings(iap_policy, "cloud_iap_policy")
              if row["role"] == "roles/iap.httpsResourceAccessor"]
    require(any(OWNER_MEMBER in row["members"] and not row.get("condition") for row in access),
            "cloud_iap_owner_access")
    return {
        "uri": ORIGIN,
        "service_uid": service["uid"],
        "service_generation": str(service["generation"]),
        "revision": latest,
        "image": expected_image,
        "digest": match.group(1),
        "traffic": active,
        "platform_log_uri": validate_log_uri(revision.get("logUri")),
        "iap_enabled": True,
        "owner_member": OWNER_MEMBER,
    }


def verify_iap_denial(http):
    response = http.request("GET", ORIGIN + "/health", headers={"Accept": "text/html"})
    generated = response.headers.get("x-goog-iap-generated-response", "").lower() == "true"
    location = urlsplit(response.headers.get("location", ""))
    redirected = response.status in {302, 303} and location.scheme == "https" and location.hostname == "accounts.google.com"
    denied = response.status in {401, 403} and generated
    require(redirected or denied, "iap_unauthenticated_request_not_rejected")
    return response.status


class Application:
    def __init__(self, http):
        self.http = http
        self.csrf = None

    def request(self, method, path, *, body=None, expected=200, code="application_request", csrf=False,
                accept="application/json"):
        require(isinstance(path, str) and path.startswith("/") and not path.startswith("//"), "application_path")
        headers = {"Origin": ORIGIN, "Accept": accept}
        if csrf:
            require(isinstance(self.csrf, str), "application_csrf_missing")
            headers["X-CSRF-Token"] = self.csrf
        response = self.http.request(method, ORIGIN + path, headers=headers, body=body)
        require(response.status == expected, code)
        return response

    def json(self, method, path, *, body=None, expected=200, code="application_json", csrf=False):
        response = self.request(method, path, body=body, expected=expected, code=code, csrf=csrf)
        try:
            value = json.loads(response.body)
        except (UnicodeDecodeError, ValueError):
            raise AcceptanceError(code + "_json") from None
        require(type(value) is dict, code + "_shape")
        return value, response.body

    def login(self, username, password, *, admin=None):
        challenge, _ = self.json("GET", "/auth/csrf", code="application_csrf")
        token = challenge.get("csrf_token")
        require(isinstance(token, str) and 20 <= len(token) <= 256 and not any(c.isspace() for c in token),
                "application_csrf_value")
        self.csrf = token
        value, raw = self.json("POST", "/auth/login", body={"username": username, "password": password},
                               code="application_login", csrf=True)
        require(password.encode("utf-8") not in raw, "application_login_exposed_password")
        user, token = value.get("user"), value.get("csrf_token")
        require(isinstance(user, dict) and ID.fullmatch(user.get("id", ""))
                and user.get("username") == username and isinstance(token, str), "application_login_identity")
        if admin is not None:
            require(user.get("is_admin") is admin, "application_login_role")
        self.csrf = token
        return user

    def logout(self):
        value, _ = self.json("POST", "/auth/logout", body={}, code="application_logout", csrf=True)
        require(value == {"status": "logged_out"}, "application_logout_result")


def safe_audit(value, account_id, secrets_to_hide):
    require(set(value) == {"items", "page", "page_size", "total"} and isinstance(value["items"], list),
            "application_audit_shape")
    for item in value["items"]:
        require(isinstance(item, dict) and set(item) == AUDIT_FIELDS, "application_audit_fields")
    matches = [item for item in value["items"] if item["target_id"] == account_id
               and item["action"] == "user.created" and item["result"] == "success"]
    require(len(matches) == 1, "application_audit_creation_missing")
    raw = canonical(value)
    require(all(secret.encode("utf-8") not in raw for secret in secrets_to_hide if secret),
            "application_audit_contains_secret")
    return {"action": "user.created", "result": "success", "target_id": account_id,
            "fields": sorted(AUDIT_FIELDS), "credentials_present": False}


def public_application_checks(client, expected_commit):
    health, _ = client.json("GET", "/health", code="application_health")
    require(health == {"status": "ok", "profile": "int-demo-a"}, "application_health_value")
    environment, _ = client.json("GET", "/environment", code="application_environment")
    require(environment == {"environment": "INT", "revision": expected_commit}, "application_environment_value")
    page = client.request("GET", "/login", code="application_login_page", accept="text/html")
    require(b'id="login-form"' in page.body and b"/static/auth.js" in page.body,
            "application_login_frontend")


def account_frontend(client):
    page = client.request("GET", "/account", code="application_account_page", accept="text/html")
    require(all(marker in page.body for marker in (b'id="users-panel"', b'id="audit-panel"', b"data-auth-logout")),
            "application_account_frontend")


def account_list(client, account_id, username):
    value, _ = client.json("GET", "/auth/users", code="application_user_list")
    users = value.get("users")
    require(isinstance(users, list) and any(isinstance(row, dict) and row.get("id") == account_id
            and row.get("username") == username and row.get("is_admin") is False and row.get("is_active") is True
            for row in users), "application_created_account_not_listed")


def unauthorized_checks(client):
    client.json("GET", "/auth/users", expected=403, code="application_ordinary_list_not_rejected")
    client.json("POST", "/auth/users", body={"username": "qa_hito_a_forbidden", "password": secrets.token_urlsafe(32)},
                expected=403, code="application_ordinary_create_not_rejected", csrf=True)
    client.json("GET", "/auth/admin/audit", expected=403, code="application_ordinary_audit_not_rejected")


def audit_check(admin, account_id, secrets_to_hide):
    query = urlencode({"page": "1", "page_size": "100", "action": "user.created",
                       "target_id": account_id, "result": "success"})
    value, _ = admin.json("GET", "/auth/admin/audit?" + query, code="application_audit")
    return safe_audit(value, account_id, secrets_to_hide)


def logout_check(client):
    client.logout()
    client.json("GET", "/auth/me", expected=401, code="application_logout_session_active")


def new_session(factory, token):
    return Application(factory(token) if factory is not None else HTTP(token))


def record(report, step):
    require(step not in {row["id"] for row in report["steps"]}, "duplicate_acceptance_step")
    report["steps"].append({"id": step, "status": "passed"})


def prepare(args, report, *, credentials=None, cloud_http=None, session_factory=None, unauth_http=None,
            clock=utc_now):
    if credentials is None:
        gcp_token, iap_token = read_token(args.gcp_token_file), read_token(args.iap_token_file)
        admin_credential = read_admin(args.admin_credentials_file)
    else:
        gcp_token, iap_token, admin_credential = credentials
    report["stage"] = "cloud_identity"
    cloud = inspect_cloud(cloud_http or HTTP(gcp_token), args.expected_image)
    report["service"] = cloud
    record(report, "cloud_ready_revision_digest_traffic")
    report["stage"] = "iap_boundary"
    denied = verify_iap_denial(unauth_http or HTTP())
    report["iap"] = {"protected": True, "unauthenticated_status": denied,
                     "authorized_identity_used": True, "owner_member_verified": True}
    record(report, "https_iap_unauthorized_rejection")

    report["stage"] = "application_public"
    admin = new_session(session_factory, iap_token)
    public_application_checks(admin, args.expected_commit)
    admin_user = admin.login(admin_credential["username"], admin_credential["password"], admin=True)
    require("users:manage" in admin_user.get("permissions", []), "application_admin_permission")
    account_frontend(admin)
    record(report, "frontend_health_environment_admin_login")

    report["stage"] = "create_synthetic_account"
    username, password = "qa_hito_a_" + secrets.token_hex(10), secrets.token_urlsafe(32)
    created, raw = admin.json("POST", "/auth/users", body={"username": username, "password": password},
                              expected=201, code="application_create_user", csrf=True)
    require(password.encode("utf-8") not in raw, "application_create_exposed_password")
    user = created.get("user")
    require(isinstance(user, dict) and ID.fullmatch(user.get("id", "")) and user.get("username") == username
            and user.get("is_admin") is False and user.get("is_active") is True, "application_created_user_identity")
    state = {"schema": STATE_SCHEMA, "origin": ORIGIN, "created_utc": utc(clock()),
             "before": {"revision": cloud["revision"], "digest": cloud["digest"], "commit": args.expected_commit},
             "account": {"id": user["id"], "username": username, "password": password}}
    state_raw = write_new(args.state, state)
    report["state_sha256"] = digest(state_raw)
    report["account"] = {"id": user["id"], "created": True, "listed": False}
    account_list(admin, user["id"], username)
    report["account"]["listed"] = True
    audit = audit_check(admin, user["id"], (password, admin_credential["password"], gcp_token, iap_token))
    report["audit_receipt"] = audit
    record(report, "admin_create_list_and_secret_free_audit")

    report["stage"] = "ordinary_account_boundary"
    ordinary = new_session(session_factory, iap_token)
    ordinary_user = ordinary.login(username, password, admin=False)
    require(ordinary_user["id"] == user["id"], "application_ordinary_identity")
    me, _ = ordinary.json("GET", "/auth/me", code="application_ordinary_me")
    require(me.get("user", {}).get("id") == user["id"], "application_ordinary_me_identity")
    unauthorized_checks(ordinary)
    logout_check(ordinary)
    logout_check(admin)
    record(report, "ordinary_rejections_and_logout")
    report["application"] = {"environment": "INT", "commit": args.expected_commit,
                             "health": "ok", "profile": "int-demo-a"}
    report["persistence"] = {"prepared": True, "revision_replaced": False, "verified": False}
    report["status"] = "prepared_for_revision_replacement"
    report["stage"] = "complete"
    return (gcp_token, iap_token, admin_credential["password"], password)


def verify(args, report, *, credentials=None, cloud_http=None, session_factory=None, unauth_http=None,
           clock=utc_now):
    del clock  # The state timestamp is validated on read; verification records its own report time.
    if credentials is None:
        gcp_token, iap_token = read_token(args.gcp_token_file), read_token(args.iap_token_file)
        admin_credential = read_admin(args.admin_credentials_file)
    else:
        gcp_token, iap_token, admin_credential = credentials
    state, state_raw = load_state(args.state)
    account, before = state["account"], state["before"]
    expected_digest = IMAGE.fullmatch(args.expected_image or "")
    require(expected_digest is not None and before["commit"] == args.expected_commit,
            "acceptance_state_commit_mismatch")
    require(before["digest"] == expected_digest.group(1), "acceptance_state_digest_mismatch")
    report["state_sha256"] = digest(state_raw)
    report["stage"] = "replacement_revision"
    cloud = inspect_cloud(cloud_http or HTTP(gcp_token), args.expected_image)
    require(cloud["revision"] != before["revision"], "cloud_revision_was_not_replaced")
    report["service"] = cloud
    report["previous"] = before
    record(report, "replacement_revision_ready_digest_traffic")
    report["stage"] = "iap_boundary"
    denied = verify_iap_denial(unauth_http or HTTP())
    report["iap"] = {"protected": True, "unauthenticated_status": denied,
                     "authorized_identity_used": True, "owner_member_verified": True}
    record(report, "https_iap_unauthorized_rejection")

    report["stage"] = "persistent_account"
    ordinary = new_session(session_factory, iap_token)
    public_application_checks(ordinary, args.expected_commit)
    ordinary_user = ordinary.login(account["username"], account["password"], admin=False)
    require(ordinary_user["id"] == account["id"], "persistent_account_identity")
    unauthorized_checks(ordinary)
    record(report, "persistent_account_login_and_rejections")

    admin = new_session(session_factory, iap_token)
    admin_user = admin.login(admin_credential["username"], admin_credential["password"], admin=True)
    require("users:manage" in admin_user.get("permissions", []), "application_admin_permission")
    account_frontend(admin)
    account_list(admin, account["id"], account["username"])
    report["audit_receipt"] = audit_check(
        admin, account["id"], (account["password"], admin_credential["password"], gcp_token, iap_token)
    )
    record(report, "persistent_admin_list_and_secret_free_audit")
    logout_check(ordinary)
    logout_check(admin)
    record(report, "post_replacement_logout")
    report["account"] = {"id": account["id"], "created": True, "listed": True, "persisted": True}
    report["application"] = {"environment": "INT", "commit": args.expected_commit,
                             "health": "ok", "profile": "int-demo-a"}
    report["persistence"] = {"prepared": True, "revision_replaced": True, "verified": True,
                             "before_revision": before["revision"], "after_revision": cloud["revision"]}
    report["status"] = "passed"
    report["stage"] = "complete"
    return (gcp_token, iap_token, admin_credential["password"], account["password"])


def validate_public_inputs(args):
    require(SHA40.fullmatch(args.expected_commit or "") is not None, "expected_commit")
    require(IMAGE.fullmatch(args.expected_image or "") is not None, "expected_runtime_image")
    for value in (args.gcp_token_file, args.iap_token_file, args.admin_credentials_file, args.state, args.report):
        require(Path(value).is_absolute(), "absolute_private_paths_required")
    private_file(args.report, must_exist=False)
    if args.operation == "prepare":
        private_file(args.state, must_exist=False)
    else:
        private_file(args.state)


def secret_free(report, secret_values):
    raw = canonical(report)
    require(all(not value or value.encode("utf-8") not in raw for value in secret_values), "acceptance_receipt_contains_secret")


def base_report(operation, commit, clock):
    return {"schema": REPORT_SCHEMA, "operation": operation, "status": "blocked",
            "stage": "input_validation", "started_utc": utc(clock()), "steps": [],
            "controls_commit": commit}


def run(environ, state, *, cloud_http=None, session_factory=None, unauth_http=None, clock=utc_now):
    """Run one acceptance phase for the protected deployment entrypoint.

    ``state`` contains only orchestration metadata: ``operation``,
    ``expected_commit``, ``expected_image`` and an absolute
    ``private_state_path``. Secrets are accepted only from the supplied
    environment mapping. The returned dictionary is safe to retain as an
    artifact; the private state file is not.
    """
    require(isinstance(environ, Mapping) and isinstance(state, Mapping), "acceptance_call_shape")
    operation = state.get("operation")
    commit, image = state.get("expected_commit"), state.get("expected_image")
    report = base_report(operation, commit, clock)
    secret_values = []
    try:
        require(operation in {"prepare", "verify"}, "acceptance_operation")
        require(SHA40.fullmatch(commit or "") is not None, "expected_commit")
        image_match = IMAGE.fullmatch(image or "")
        require(image_match is not None, "expected_runtime_image")
        if state.get("expected_digest") is not None:
            require(state["expected_digest"] in {image_match.group(1), "sha256:" + image_match.group(1)},
                    "expected_digest_mismatch")
        state_path = Path(state.get("private_state_path", ""))
        require(state_path.is_absolute(), "absolute_private_paths_required")
        if operation == "prepare":
            private_file(state_path, must_exist=False)
        else:
            private_file(state_path)
        credentials = environment_credentials(environ)
        secret_values = [credentials[0], credentials[1], credentials[2]["password"]]
        args = argparse.Namespace(operation=operation, expected_commit=commit, expected_image=image, state=state_path)
        if operation == "prepare":
            returned = prepare(args, report, credentials=credentials, cloud_http=cloud_http,
                               session_factory=session_factory, unauth_http=unauth_http, clock=clock)
        else:
            returned = verify(args, report, credentials=credentials, cloud_http=cloud_http,
                              session_factory=session_factory, unauth_http=unauth_http, clock=clock)
        secret_values.extend(returned)
    except Exception as error:
        report["status"] = "blocked"
        report["error_type"] = type(error).__name__
        if isinstance(error, AcceptanceError):
            report["failed_check"] = str(error)
    report["finished_utc"] = utc(clock())
    secret_free(report, secret_values)
    return report


def run_cli(args, *, cloud_http=None, session_factory=None, unauth_http=None, clock=utc_now):
    started = clock()
    report = {"schema": REPORT_SCHEMA, "operation": args.operation, "status": "blocked",
              "stage": "input_validation", "started_utc": utc(started), "steps": [],
              "controls_commit": args.expected_commit}
    secret_values = []
    try:
        validate_public_inputs(args)
        if args.operation == "prepare":
            secret_values = list(prepare(args, report, cloud_http=cloud_http, session_factory=session_factory,
                                         unauth_http=unauth_http, clock=clock))
        else:
            secret_values = list(verify(args, report, cloud_http=cloud_http, session_factory=session_factory,
                                        unauth_http=unauth_http, clock=clock))
    except Exception as error:
        report["status"] = "blocked"
        report["error_type"] = type(error).__name__
        if isinstance(error, AcceptanceError):
            report["failed_check"] = str(error)
    report["finished_utc"] = utc(clock())
    try:
        secret_free(report, secret_values)
        write_new(args.report, report)
    except Exception:
        print(json.dumps({"status": "blocked", "phase": args.operation, "receipt": "unavailable"}, sort_keys=True))
        return 1
    print(json.dumps({"status": report["status"], "phase": args.operation, "receipt": "sanitized"}, sort_keys=True))
    return 0 if report["status"] in {"prepared_for_revision_replacement", "passed"} else 1


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    value.add_argument("operation", choices=("prepare", "verify"))
    value.add_argument("--expected-commit", required=True)
    value.add_argument("--expected-image", required=True)
    value.add_argument("--gcp-token-file", type=Path, required=True)
    value.add_argument("--iap-token-file", type=Path, required=True)
    value.add_argument("--admin-credentials-file", type=Path, required=True)
    value.add_argument("--state", type=Path, required=True)
    value.add_argument("--report", type=Path, required=True)
    return value


def main(argv=None):
    os.umask(0o077)
    return run_cli(parser().parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
