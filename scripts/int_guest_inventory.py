"""Protected INT inventory transport: WIF Deploy, pinned host, own OS Login key.

No VM, metadata, IAM, Terraform or database mutation route exists here. The only
cloud writes import and remove this execution's own expiring SSH public key.
Raw process output and credential documents never enter public reports.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import socket
import stat
import subprocess
import sys
import time
import threading
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from scripts import int_vm_hostkey as host
from scripts import int_vm_hostkey_guest as host_guest

ROOT = Path(__file__).resolve().parents[1]
DEPLOY = "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
PROVIDER = "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github"
PROJECT, ZONE, VM_NAME = "clipforgebeta2", "us-central1-a", "clipforge-int-base-postgres"
OPERATOR_SHA = "90f47688e1b53e173dfd9105d2861235b99caae59c84fce6c8205e9601ec9dd9"
HOST_GUEST_SHA = "a8211bbfbe29f0694f633b403fbe41e08ef6dfbc8abb9705f56e1f8e13ea10ad"
PROPOSAL_SHA = "62d8a1049a78f355c0aab234389b680183f39eb651c2c08bb601190e28cbed5e"
PUBLISHER_SHA = "0529b95de129932593856a3a4c8c7f9a047054743ffe00fd8dbfade37122ab8f"
HOST_EVIDENCE_SHA = "1963b5e52a4606a6f0b6560dcd0ab1356e36f4ec0764b4c4fc05ee99d12229a4"
# Public integrity digest of the owner decision document.
OWNER_DECISION_SHA256 = "956984c5fd9aa7b0ea0c128b0f46e24a8f1e55643edc69ff5b5895db92763ee6"
DEPLOY_UNIQUE_ID = "101402373862758071342"
STARTUP_SHA = "a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255"
KEY_TTL_SECONDS = 900
MAX_JSON = 2 * 1024 * 1024
REMOTE_COMMAND = "/usr/bin/sudo -n /usr/bin/python3 -I -"
BASE = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
VM_URL = BASE + "instances/" + VM_NAME
BOOT_URL = BASE + "disks/clipforge-int-base-postgres"
DATA_URL = BASE + "disks/clipforge-int-base-postgres-data"
OSLOGIN_USER = "https://oslogin.googleapis.com/v1/users/" + DEPLOY_UNIQUE_ID
PROFILE_URL = OSLOGIN_USER + "/loginProfile?projectId=clipforgebeta2"
IMPORT_URL = OSLOGIN_USER + ":importSshPublicKey?projectId=clipforgebeta2"


class Blocked(ValueError):
    """Fixed codes only; no token, raw stderr, policy or guest environment."""


class Failure(Blocked):
    def __init__(self, code, receipt):
        self.receipt = receipt
        super().__init__(code)


def require(ok, code):
    if not ok:
        raise Blocked(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value
    require(isinstance(raw, (bytes, str)) and 0 < len(raw) <= MAX_JSON, "bounded_json_required")
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError):
        raise Blocked("invalid_private_json") from None


def validate_hostkey_bundle(raw, expected_sha):
    require(expected_sha == HOST_EVIDENCE_SHA and sha(raw) == expected_sha, "host_evidence_digest")
    value = decode(raw)
    fields = {"schema", "original_proposal_sha256", "operator_sha256", "guest_source_sha256", "publisher_sha256", "identity",
              "initial_last_start_timestamp", "observed_last_start_timestamp", "hostkey_record", "journal", "restore",
              "known_hosts_sha256", "restored_startup_sha256", "authorization"}
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == "clipforge-int-guest-hostkey-evidence-1"
            and value["original_proposal_sha256"] == PROPOSAL_SHA and value["operator_sha256"] == OPERATOR_SHA
            and value["guest_source_sha256"] == HOST_GUEST_SHA and value["publisher_sha256"] == PUBLISHER_SHA
            and value["restored_startup_sha256"] == STARTUP_SHA and value["identity"] == host.IDENTITY, "host_evidence_source_or_identity")
    require(sha((ROOT / "scripts/int_vm_hostkey.py").read_bytes()) == OPERATOR_SHA
            and sha((ROOT / "scripts/int_vm_hostkey_guest.py").read_bytes()) == HOST_GUEST_SHA, "frozen_host_operator_changed")
    journal = value["journal"]
    require(set(journal) == {"sha256", "phase"} and journal["phase"] == "complete"
            and re.fullmatch(r"[a-f0-9]{64}", journal["sha256"]), "host_journal_incomplete")
    restore = value["restore"]
    require(set(restore) == {"type", "request_id", "operation", "done_success"} and restore["type"] == "setMetadata"
            and restore["done_success"] is True and re.fullmatch(r"[a-f0-9-]{36}", restore["request_id"]), "host_restore_not_confirmed")
    operation = restore["operation"]
    require(set(operation) == {"name", "id", "status"} and operation["status"] == "DONE"
            and re.fullmatch(r"[A-Za-z0-9_-]+", operation["name"]) and re.fullmatch(r"[1-9][0-9]*", operation["id"]), "host_restore_operation")
    record = value["hostkey_record"]
    require(isinstance(record, dict), "host_record_required")
    template = (ROOT / "scripts/int_vm_hostkey_guest.py").read_bytes()
    require(sha(host.render(template, record.get("nonce", ""))) == PUBLISHER_SHA, "host_nonce_not_bound_to_publisher")
    core = {"nonce": record.get("nonce"), "guest_source_sha256": HOST_GUEST_SHA, "publisher_sha256": PUBLISHER_SHA}
    host.record_contract(record, core)
    require(host.instant(value["observed_last_start_timestamp"]) > host.instant(value["initial_last_start_timestamp"]), "host_boot_not_new")
    known = (VM_NAME + "." + host.IDENTITY["instance_id"] + " " + record["public_key"] + "\n").encode("ascii")
    require(sha(known) == value["known_hosts_sha256"], "host_known_hosts_digest")
    authorization = value["authorization"]
    require(set(authorization) == {"sha256", "approved_at", "expires_at", "completed_utc"}
            and authorization["sha256"] == OWNER_DECISION_SHA256
            and host.instant(authorization["approved_at"]) == host.instant("2026-11-18T21:22:08Z")
            and host.instant(authorization["expires_at"]) == host.instant("2026-11-18T22:22:08Z")
            and host.instant(authorization["approved_at"]) <= host.instant(authorization["completed_utc"]) < host.instant(authorization["expires_at"]),
            "host_intervention_not_completed_in_authorized_window")
    return {**value, "known_hosts": known, "evidence_sha256": expected_sha}


def validate_deploy_credentials(env, document):
    expected_env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                    "GCP_PROJECT_ID": PROJECT, "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1",
                    "GCP_DEPLOY_SA": DEPLOY, "GCP_WIF_PROVIDER": PROVIDER, "GUEST_ENVIRONMENT": "int", "GITHUB_EVENT_NAME": "workflow_dispatch"}
    require(all(env.get(key) == value for key, value in expected_env.items()), "workflow_or_deploy_boundary")
    require(re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", "")) and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ATTEMPT", ""))
            and env.get("GUEST_APPROVED_COMMIT") == env["GITHUB_SHA"], "workflow_identity")
    forbidden = {"GOOGLE_CREDENTIALS", "GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON", "GOOGLE_OAUTH_ACCESS_TOKEN",
                 "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN",
                 "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_LOGIN_CONFIG_FILE", "CLOUDSDK_CORE_ACCOUNT"}
    require(not any(env.get(key) for key in forbidden) and not any(key.startswith(("TF_VAR_", "TF_LOG", "TF_CLI_ARGS")) for key in env), "ambient_authentication_override")
    if env.get("CLOUDSDK_CONFIG"):
        temporary = Path(env.get("RUNNER_TEMP", ""))
        work = Path(env.get("GUEST_WORK", ""))
        sdk = Path(env["CLOUDSDK_CONFIG"])
        require(temporary.is_absolute() and work.is_absolute() and sdk.is_absolute()
                and work.parent == temporary.resolve() and work.name.startswith("clipforge-guest-inventory.")
                and sdk == work / "gcloud" and not work.is_symlink() and not sdk.is_symlink()
                and (not sdk.exists() or sdk.is_dir()), "unreviewed_sdk_configuration_directory")
    path = Path(env.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    require(path.is_absolute() and path.name.startswith("gha-creds-") and path.suffix == ".json", "gha_adc_path")
    require(all(not env.get(key) or Path(env[key]).resolve() == path.resolve() for key in ("GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")), "gha_adc_alias")
    require(isinstance(document, dict) and document.get("type") == "external_account"
            and document.get("audience") == "//iam.googleapis.com/" + PROVIDER
            and document.get("token_url") == "https://sts.googleapis.com/v1/token"
            and document.get("service_account_impersonation_url") == "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + DEPLOY + ":generateAccessToken"
            and not {"private_key", "private_key_id", "client_secret"}.intersection(document)
            and isinstance(document.get("credential_source"), dict) and "executable" not in document["credential_source"], "adc_not_exact_deploy_wif")
    return {"source": "external_account_WIF", "configured_service_account": DEPLOY, "provider": PROVIDER,
            "permanent_key_absent": True, "configured_identity_is_effective_identity": False}


def validate_compute_snapshot(vm, boot, data, pin):
    host.identity(vm, boot, data)
    metadata = host.metadata_items(vm.get("metadata", {}))
    require(vm.get("status") == "RUNNING" and vm.get("lastStartTimestamp") == pin["observed_last_start_timestamp"]
            and sha(metadata.get("startup-script", "").encode()) == STARTUP_SHA
            and not host.HOOKS.intersection(metadata) and "enable-guest-attributes" not in metadata, "current_vm_boot_or_startup_changed")
    selected = {key: vm.get(key) for key in ("id", "name", "creationTimestamp", "lastStartTimestamp", "status", "machineType",
                "deletionProtection", "canIpForward", "networkInterfaces", "disks", "metadata", "serviceAccounts", "shieldedInstanceConfig")}
    return {"instance_id": host.IDENTITY["instance_id"], "boot_timestamp": vm["lastStartTimestamp"],
            "configuration_sha256": sha(canonical(selected)), "disk_metadata_sha256": sha(canonical([boot, data])), "startup_restored": True}


def find_own_key(profile, public_key, expiration_us):
    keys = profile.get("sshPublicKeys", {})
    require(isinstance(keys, dict), "oslogin_key_map")
    found = []
    for fingerprint, value in keys.items():
        if isinstance(value, dict) and value.get("key", "").strip() == public_key:
            require(re.fullmatch(r"[A-Za-z0-9_:+/=-]{16,128}", fingerprint)
                    and value.get("fingerprint", fingerprint) == fingerprint
                    and str(value.get("expirationTimeUsec")) == str(expiration_us), "own_oslogin_key_metadata_changed")
            found.append(fingerprint)
    require(len(found) <= 1, "own_oslogin_key_ambiguous")
    return found[0] if found else None


def key_preexists(profile, public_key):
    keys = profile.get("sshPublicKeys", {})
    require(isinstance(keys, dict), "oslogin_key_map")
    return any(isinstance(value, dict) and isinstance(value.get("key"), str)
               and value["key"].split()[:2] == public_key.split() for value in keys.values())


def validate_import_response(value, public_key, expiration_us):
    profile = value.get("loginProfile", {})
    validate_deploy_profile(profile)
    fingerprint = find_own_key(profile, public_key, expiration_us)
    require(fingerprint is not None, "import_did_not_confirm_own_key")
    accounts = profile.get("posixAccounts", [])
    require(isinstance(accounts, list), "oslogin_posix_accounts")
    eligible = [row for row in accounts if row.get("operatingSystemType", "LINUX") in {"LINUX", "OPERATING_SYSTEM_TYPE_UNSPECIFIED"}]
    primary = [row for row in eligible if row.get("primary") is True]
    chosen = primary if primary else eligible
    require(len(chosen) == 1, "oslogin_username_ambiguous")
    username = chosen[0].get("username", "")
    require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", username) and username != "root"
            and re.fullmatch(r"[1-9][0-9]*", str(chosen[0].get("uid", ""))), "oslogin_username_or_uid")
    return {"fingerprint": fingerprint, "username": username}


def validate_deploy_profile(profile):
    require(isinstance(DEPLOY_UNIQUE_ID, str) and re.fullmatch(r"[1-9][0-9]{5,30}", DEPLOY_UNIQUE_ID), "deploy_unique_id_not_materialized")
    require(isinstance(profile, dict) and profile.get("name") in {DEPLOY_UNIQUE_ID, "users/" + DEPLOY_UNIQUE_ID}, "effective_oslogin_actor_not_deploy")
    return {"verified_profile_account": DEPLOY, "oslogin_unique_id": DEPLOY_UNIQUE_ID,
            "observed_by": "canonical_OSLogin_loginProfile", "OAuth_token_subject_introspected": False}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("cloud_redirect_forbidden")


class Client:
    def __init__(self, token_provider):
        self.token_provider = token_provider
        self.key, self.expiration_us, self.fingerprint = None, None, None
        self.import_attempted = False
        self.actor_verified = False
        self.key_absent_before_import = False
        self._delete_authorization = None

    def arm_key(self, public_key, expiration_us, *, now=None):
        canonical_key, _ = host_guest.public_key(public_key.encode("ascii"))
        at = now if now is not None else time.time()
        require(canonical_key == public_key and type(expiration_us) is int and int(at * 1000000) < expiration_us <= int((at + KEY_TTL_SECONDS) * 1000000), "ssh_key_or_ttl")
        require(self.key is None, "ssh_key_already_armed")
        self.key, self.expiration_us = public_key, expiration_us

    def request(self, method, url, payload=None):
        importing = method == "POST" and url == IMPORT_URL and self.actor_verified and self.key_absent_before_import and self.key is not None and payload == {"key": self.key, "expirationTimeUsec": str(self.expiration_us)} and not self.import_attempted
        deleting = method == "DELETE" and self.actor_verified and self.key_absent_before_import and self.key is not None and self.fingerprint is not None and url == OSLOGIN_USER + "/sshPublicKeys/" + quote(self.fingerprint, safe="") and payload is None and self._delete_authorization == (self.key, self.expiration_us, self.fingerprint)
        require((method == "GET" and url in {VM_URL, BOOT_URL, DATA_URL, PROFILE_URL} and payload is None)
                or importing or deleting, "cloud_capability_denied_before_token")
        if importing:
            self.import_attempted = True
        if deleting:
            self._delete_authorization = None
        token = self.token_provider()
        require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "short_lived_deploy_token_required")
        request = Request(url, method=method, data=canonical(payload) if payload is not None else None,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                   "X-Goog-Request-Reason": "ClipForge INT readonly guest inventory"})
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=30) as response:
                raw = response.read(MAX_JSON + 1)
            return decode(raw)
        except HTTPError as error:
            raw = error.read(16384)
            permission_allowlist = {"compute.instances.get", "compute.disks.get", "compute.projects.get", "compute.instances.osLogin",
                "compute.instances.osAdminLogin", "iap.tunnelInstances.accessViaIAP", "iam.serviceAccounts.actAs",
                "iam.serviceAccounts.getAccessToken", "oslogin.users.getLoginProfile", "oslogin.users.importSshPublicKey",
                "oslogin.users.deleteSshPublicKey", "serviceusage.services.use"}
            text = raw.decode("utf-8", errors="replace")
            reasons = []
            try:
                details = decode(raw).get("error", {}).get("details", [])
                reasons = sorted({row["reason"] for row in details if isinstance(row, dict) and isinstance(row.get("reason"), str)
                                  and re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", row["reason"])})[:5]
            except (ValueError, AttributeError):
                pass
            resource = "Deploy_OSLogin_profile" if url.startswith(OSLOGIN_USER) else url.rsplit("/", 1)[-1]
            raise Failure("cloud_http_" + str(error.code), {"operation": method + " " + ("OSLogin" if url.startswith(OSLOGIN_USER) else "ComputeGET"),
                "resource": resource, "http_status": error.code, "permissions": sorted(value for value in permission_allowlist if value in text),
                "error_info_reasons": reasons, "response_body_withheld": True}) from None

    def profile(self):
        value = self.request("GET", PROFILE_URL)
        validate_deploy_profile(value)
        self.actor_verified = True
        return value

    def import_key(self):
        if not self.key_absent_before_import:
            self.prepare_import()
        value = self.request("POST", IMPORT_URL, {"key": self.key, "expirationTimeUsec": str(self.expiration_us)})
        own = validate_import_response(value, self.key, self.expiration_us)
        self.fingerprint = own["fingerprint"]
        return own

    def prepare_import(self):
        require(self.key is not None and not self.import_attempted, "new_key_import_only")
        require(not key_preexists(self.profile(), self.key), "preexisting_oslogin_key_not_owned")
        self.key_absent_before_import = True

    def delete_own_key(self, fingerprint):
        require(self.key_absent_before_import and self.key is not None and fingerprint == self.fingerprint and fingerprint is not None, "delete_only_confirmed_own_fingerprint")
        require(find_own_key(self.profile(), self.key, self.expiration_us) == fingerprint, "own_key_not_confirmed_before_delete")
        self._delete_authorization = (self.key, self.expiration_us, fingerprint)
        self.request("DELETE", OSLOGIN_USER + "/sshPublicKeys/" + quote(fingerprint, safe=""))
        require(find_own_key(self.profile(), self.key, self.expiration_us) is None, "own_key_still_present")
        return {"removed_exact_own_key": True}


def parse_inventory(raw, exit_code):
    from scripts import int_guest_inventory_guest as payload
    value = payload.validate_report(decode(raw))
    require(exit_code == value["exit_code"] and exit_code in {0, 2, 3}, "guest_exit_code_or_report_mismatch")
    return value


def ssh_command(work, username, port):
    require(re.fullmatch(r"[a-z_][a-z0-9_-]{0,63}", username or "") and username != "root"
            and type(port) is int and 1 <= port <= 65535, "ssh_login_or_port")
    return ["/usr/bin/ssh", "-F", "/dev/null", *host.ssh_options(work / "known_hosts"),
            "-oIdentitiesOnly=yes", "-oIdentityAgent=none", "-oPreferredAuthentications=publickey",
            "-oPubkeyAuthentication=yes", "-oGSSAPIAuthentication=no", "-oNumberOfPasswordPrompts=0",
            "-oCheckHostIP=no", "-oClearAllForwardings=yes", "-oPermitLocalCommand=no",
            "-oConnectTimeout=20", "-oConnectionAttempts=1", "-oServerAliveInterval=10", "-oServerAliveCountMax=2",
            "-T", "-p", str(port), "-i", str(work / "id_ed25519"), "-l", username, "127.0.0.1", REMOTE_COMMAND]


def tunnel_command(gcloud, port):
    require(Path(gcloud).is_absolute() and type(port) is int and 1 <= port <= 65535, "tunnel_program_or_port")
    return [gcloud, "compute", "start-iap-tunnel", VM_NAME, "22", "--project=" + PROJECT, "--zone=" + ZONE,
            "--account=" + DEPLOY, "--local-host-port=127.0.0.1:" + str(port), "--quiet", "--verbosity=error"]


def _process_ticks(pid):
    require(type(pid) is int and pid > 1, "owned_process_pid")
    raw = Path("/proc/" + str(pid) + "/stat").read_text(encoding="ascii")
    return raw.rsplit(") ", 1)[1].split()[19]


def process_diagnostic(raw):
    messages, unclassified = [], 0
    phrases = ("Permission denied (publickey)", "Permission denied", "permission denied", "Host key verification failed",
               "REMOTE HOST IDENTIFICATION HAS CHANGED", "Connection refused", "Connection timed out", "not authorized",
               "not authorised", "a password is required", "a terminal is required", "not allowed to execute", "command not found")
    permissions = ("iap.tunnelInstances.accessViaIAP", "compute.instances.get", "compute.instances.osLogin",
                   "compute.instances.osAdminLogin", "iam.serviceAccounts.actAs", "serviceusage.services.use")
    for line in raw.decode("utf-8", errors="replace").splitlines():
        if re.search(r"(?i)bearer|ya29\.|eyJ|private.?key|access.?token|credential|password=", line):
            unclassified += 1
            continue
        found = [phrase for phrase in (*phrases, *permissions) if phrase in line]
        if found:
            messages.extend(phrase for phrase in found if phrase not in messages)
        elif line.strip():
            unclassified += 1
    return {"stderr_bytes": len(raw), "stderr_sha256": sha(raw), "messages": messages[:8], "unclassified_lines": unclassified}


class ProcessRunner:
    """Only fixed SSH/keygen/tunnel commands, bounded pipes and own sessions."""
    def __init__(self, work, gcloud, payload, run_tag, journal_callback=None):
        self.work, self.gcloud, self.payload, self.run_tag = Path(work), gcloud, payload, run_tag
        self.journal_callback = journal_callback or (lambda row: None)
        self.owned = []
        self.username = None
        self.tunnel_errors = threading.Event()
        self.tunnel_stderr = bytearray()

    def keygen_command(self):
        return ["/usr/bin/ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", self.run_tag, "-f", str(self.work / "id_ed25519")]

    def _kind(self, argv, input_data):
        if argv == self.keygen_command() and input_data is None:
            return "keygen"
        if argv == [self.gcloud, "version", "--format=json"] and input_data is None:
            return "sdk_version"
        if self.username is not None and input_data == self.payload:
            try:
                port = int(argv[argv.index("-p") + 1])
            except (ValueError, IndexError, TypeError):
                raise Blocked("unreviewed_local_process") from None
            if argv == ssh_command(self.work, self.username, port):
                return "ssh"
        raise Blocked("unreviewed_local_process")

    def _start(self, argv, kind):
        if kind == "tunnel":
            ports = [arg.split(":")[-1] for arg in argv if isinstance(arg, str) and arg.startswith("--local-host-port=127.0.0.1:")]
            require(len(ports) == 1 and ports[0].isdigit() and argv == tunnel_command(self.gcloud, int(ports[0])), "unreviewed_tunnel_process")
        else:
            require(self._kind(argv, self.payload if kind == "ssh" else None) == kind, "unreviewed_local_process")
        process = subprocess.Popen(argv, stdin=subprocess.PIPE if kind == "ssh" else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True, bufsize=0)
        self.owned.append(process)
        try:
            ticks = _process_ticks(process.pid)
        except (FileNotFoundError, ProcessLookupError):
            require(process.poll() is not None, "unregistered_local_process")
        else:
            self.journal_callback({"pid": process.pid, "start_ticks": ticks, "kind": kind})
        return process

    def stop(self, process):
        require(any(process is own for own in self.owned), "foreign_process_cleanup_forbidden")
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
                process.wait(timeout=3)
        else:
            process.wait(timeout=1)

    def run(self, argv, input_data=None, *, timeout=30, stdout_limit=16384, stderr_limit=8192):
        kind = self._kind(argv, input_data)
        require(type(timeout) in {int, float} and 0 < timeout <= 180
                and 0 < stdout_limit <= MAX_JSON and 0 < stderr_limit <= 8192, "local_process_bounds")
        process = self._start(argv, kind)
        output, errors = bytearray(), bytearray()
        selector = selectors.DefaultSelector()
        try:
            for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ, label)
            offset = 0
            if input_data is not None:
                os.set_blocking(process.stdin.fileno(), False)
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            end = time.monotonic() + timeout
            while selector.get_map():
                require(time.monotonic() < end, "local_process_timeout")
                require(not self.tunnel_errors.is_set(), "tunnel_output_limit")
                for key, _ in selector.select(timeout=min(0.2, max(0.01, end-time.monotonic()))):
                    if key.data == "stdin":
                        try:
                            offset += os.write(key.fileobj.fileno(), input_data[offset:offset + 65536])
                        except BrokenPipeError:
                            offset = len(input_data)
                        if offset == len(input_data):
                            selector.unregister(key.fileobj); key.fileobj.close()
                        continue
                    raw = os.read(key.fileobj.fileno(), 65536)
                    if not raw:
                        selector.unregister(key.fileobj); key.fileobj.close(); continue
                    target, bound = (output, stdout_limit) if key.data == "stdout" else (errors, stderr_limit)
                    require(len(target) + len(raw) <= bound, "local_process_output_limit")
                    target.extend(raw)
            code = process.wait(timeout=max(0.01, end-time.monotonic()))
            return code, bytes(output), bytes(errors)
        finally:
            selector.close()
            self.stop(process)
            for stream in (process.stdin, process.stdout, process.stderr):
                if stream is not None and not stream.closed:
                    stream.close()

    def start_tunnel(self, port):
        argv = tunnel_command(self.gcloud, port)
        process = self._start(argv, "tunnel")
        def drain(stream, limit, save=False):
            size = 0
            try:
                while True:
                    raw = stream.read(4096)
                    if not raw:
                        return
                    size += len(raw)
                    if size > limit:
                        self.tunnel_errors.set(); return
                    if save:
                        self.tunnel_stderr.extend(raw)
            finally:
                stream.close()
        for stream, bound in ((process.stdout, 16384), (process.stderr, 8192)):
            threading.Thread(target=drain, args=(stream, bound, stream is process.stderr), daemon=True).start()
        end = time.monotonic() + 30
        while time.monotonic() < end:
            if process.poll() is not None or self.tunnel_errors.is_set():
                raise Failure("iap_tunnel_failed", process_diagnostic(bytes(self.tunnel_stderr)))
            try:
                with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                    return process
            except OSError:
                time.sleep(0.2)
        raise Blocked("iap_tunnel_timeout")

    def close(self):
        for process in reversed(self.owned):
            self.stop(process)


def _local_bytes(path, limit=MAX_JSON):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and info.st_nlink == 1
            and 0 < info.st_size <= limit and not info.st_mode & 0o022, "unsafe_local_evidence_file")
    raw = path.read_bytes()
    require(len(raw) == info.st_size, "local_evidence_changed")
    return raw


def _save_journal(work, value):
    path = work / "cleanup-journal.json"
    pending = work / "cleanup-journal.next.json"
    require(not pending.exists() and not pending.is_symlink() and (not path.exists() or not path.is_symlink()), "cleanup_journal_collision")
    with pending.open("xb") as stream:
        os.chmod(pending, 0o600)
        stream.write(canonical(value))
        stream.flush(); os.fsync(stream.fileno())
    os.replace(pending, path)


def _validate_paths(env, workdir, reports):
    require(sys.platform == "linux", "hosted_linux_runner_required")
    require(Path(env.get("RUNNER_TEMP", "")).is_absolute(), "explicit_runner_temporary_directory_required")
    temporary = Path(env["RUNNER_TEMP"]).resolve()
    work, output = Path(workdir).absolute(), Path(reports).absolute()
    require(temporary.is_absolute() and work.parent == temporary and output.parent == temporary
            and work.name.startswith("clipforge-guest-inventory.") and output.name.startswith("clipforge-guest-report.") and work != output
            and not work.is_symlink() and not output.is_symlink(), "dedicated_runner_scratch_required")
    require(not env.get("GUEST_WORK") or Path(env["GUEST_WORK"]) == work, "guest_work_argument_mismatch")
    for path in (work, output):
        if not path.exists():
            path.mkdir(mode=0o700)
        info = path.stat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and not info.st_mode & 0o077, "private_runner_directory_required")
    return work, output


def readinesscheck(host_evidence_raw, host_evidence_sha, payload_sha, *, environ=None, credential_document=None):
    pin = validate_hostkey_bundle(host_evidence_raw, host_evidence_sha)
    raw = _local_bytes(ROOT / "scripts/int_guest_inventory_guest.py", 131072)
    require(re.fullmatch(r"[a-f0-9]{64}", payload_sha or "") and sha(raw) == payload_sha, "inventory_payload_source_digest")
    credentials = None
    if environ is not None:
        credentials = validate_deploy_credentials(environ, credential_document)
    return {"pin": pin, "payload": raw, "payload_sha256": payload_sha, "credential_selection": credentials}


def _credential_document(env):
    path = Path(env.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    require(path.is_absolute() and path.name.startswith("gha-creds-") and path.suffix == ".json", "gha_adc_path")
    return decode(_local_bytes(path, 65536))


def _write_report(reports, name, value):
    require(name in {"guest-summary.json", "inventory.json", "cleanup.json"}, "report_filename")
    path = reports / name
    require(not path.is_symlink(), "report_symlink")
    path.write_bytes(canonical(value) + b"\n")


def _cleanup_process(row):
    require(set(row) == {"pid", "start_ticks", "kind"} and type(row["pid"]) is int and row["pid"] > 1
            and re.fullmatch(r"[0-9]+", row["start_ticks"]) and row["kind"] in {"keygen", "sdk_version", "tunnel", "ssh"}, "cleanup_process_descriptor")
    pid = row["pid"]
    def own():
        return (_process_ticks(pid) == row["start_ticks"] and os.getpgid(pid) == pid and os.getsid(pid) == pid
                and Path("/proc/" + str(pid)).stat().st_uid == os.getuid())
    try:
        if not own():
            return "foreign_or_reused_pid_not_touched"
        os.killpg(pid, signal.SIGTERM)
        end = time.monotonic() + 2
        while time.monotonic() < end:
            try:
                if not own():
                    return "own_process_no_longer_active"
            except (FileNotFoundError, ProcessLookupError):
                return "own_process_gone"
            time.sleep(0.1)
        if own():
            os.killpg(pid, signal.SIGKILL)
        return "own_process_group_stopped"
    except (FileNotFoundError, ProcessLookupError):
        return "own_process_gone"


def cleanup(*, environ, workdir, reports, client=None):
    work, output = _validate_paths(environ, workdir, reports)
    path = work / "cleanup-journal.json"
    result = {"schema": "clipforge-int-guest-cleanup-1", "status": "no_registered_key", "own_processes": [], "private_files_removed": []}
    if not path.exists():
        _write_report(output, "cleanup.json", result)
        return result
    journal = decode(_local_bytes(path, 65536))
    fields = {"schema", "repository", "run_id", "run_attempt", "commit", "public_key", "created_us", "expiration_us", "fingerprint", "import_attempted", "key_absent_before_import", "processes"}
    require(set(journal) == fields and journal["schema"] == "clipforge-int-guest-cleanup-journal-1"
            and journal["repository"] == "AldemaroCruz/ClipForge" and journal["run_id"] == environ.get("GITHUB_RUN_ID")
            and journal["run_attempt"] == environ.get("GITHUB_RUN_ATTEMPT") and journal["commit"] == environ.get("GITHUB_SHA")
            and isinstance(journal["processes"], list) and len(journal["processes"]) <= 4, "cleanup_journal_scope")
    for row in journal["processes"]:
        result["own_processes"].append(_cleanup_process(row))
    try:
        if journal["import_attempted"]:
            require(journal["key_absent_before_import"] is True, "cleanup_must_not_touch_preexisting_key")
            validate_deploy_credentials(environ, _credential_document(environ))
            public_key, _ = host_guest.public_key(journal["public_key"].encode("ascii"))
            require(public_key == journal["public_key"] and type(journal["created_us"]) is int and type(journal["expiration_us"]) is int
                    and 0 < journal["expiration_us"] - journal["created_us"] <= KEY_TTL_SECONDS * 1000000, "cleanup_key_ttl_or_source")
            client = client or Client(lambda: environ.get("GCP_ACCESS_TOKEN", ""))
            if client.key is None:
                client.arm_key(public_key, journal["expiration_us"], now=journal["created_us"] / 1000000)
                client.import_attempted = True  # Cleanup can never import or renew a key.
            client.key_absent_before_import = True
            require(client.key == public_key and client.expiration_us == journal["expiration_us"], "cleanup_client_key_changed")
            profile = client.profile()
            observed = find_own_key(profile, public_key, journal["expiration_us"])
            if observed is None:
                result["status"] = "key_already_absent" if journal["fingerprint"] is not None else "import_outcome_unknown_TTL_pending"
            else:
                require(journal["fingerprint"] in {None, observed}, "cleanup_fingerprint_changed")
                client.fingerprint = observed
                client.delete_own_key(observed)
                result.update(status="own_key_removed", fingerprint_sha256=sha(observed.encode()))
    except Exception as error:
        result.update(status="cleanup_unconfirmed_TTL_pending", error_code=str(error) if isinstance(error, Blocked) else "cleanup_transport_error_withheld")
        if isinstance(error, Failure):
            result["failure"] = error.receipt
    finally:
        for name in ("id_ed25519", "id_ed25519.pub", "known_hosts"):
            item = work / name
            if item.exists():
                require(not item.is_symlink() and stat.S_ISREG(item.lstat().st_mode) and item.parent == work, "unsafe_private_key_cleanup_target")
                item.unlink()
                result["private_files_removed"].append(name)
    _write_report(output, "cleanup.json", result)
    return result


def run(*, environ, workdir, reports, host_evidence_raw, host_evidence_sha, payload_sha, client=None, processes=None):
    ready = readinesscheck(host_evidence_raw, host_evidence_sha, payload_sha, environ=environ, credential_document=_credential_document(environ))
    work, output = _validate_paths(environ, workdir, reports)
    require(not (work / "cleanup-journal.json").exists()
            and all(path.name == "host.json" or (path.name == "gcloud" and path.is_dir() and not path.is_symlink()) for path in work.iterdir()), "new_inventory_work_directory_required")
    client = client or Client(lambda: environ.get("GCP_ACCESS_TOKEN", ""))
    pin = ready["pin"]
    journal = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": environ["GITHUB_REPOSITORY"],
               "run_id": environ["GITHUB_RUN_ID"], "run_attempt": environ["GITHUB_RUN_ATTEMPT"], "commit": environ["GITHUB_SHA"],
               "public_key": None, "created_us": None, "expiration_us": None, "fingerprint": None,
               "import_attempted": False, "key_absent_before_import": False, "processes": []}
    _save_journal(work, journal)
    summary = {"schema": "clipforge-int-guest-inventory-run-1", "status": "blocked", "host_evidence_sha256": host_evidence_sha,
               "host_fingerprint": pin["hostkey_record"]["fingerprint"], "payload_sha256": payload_sha,
               "credential_selection": ready["credential_selection"], "runtime_authorized": False, "database_initialized": False}
    previous_signals = {}
    try:
        def interrupted(signum, frame):
            raise Blocked("runner_interrupted_cleanup_required")
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_signals[number] = signal.signal(number, interrupted)
        before = validate_compute_snapshot(client.request("GET", VM_URL), client.request("GET", BOOT_URL), client.request("GET", DATA_URL), pin)
        profile = client.profile()
        summary["oslogin_profile_identity"] = validate_deploy_profile(profile)
        program = shutil.which("gcloud")
        require(program and Path(program).is_absolute() and Path(program).name == "gcloud", "official_gcloud_sdk_required")
        def record_process(row):
            journal["processes"].append(row)
            _save_journal(work, journal)
        processes = processes or ProcessRunner(work, program, ready["payload"], "clipforge-int-guest-" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"], record_process)
        code, raw, stderr = processes.run([program, "version", "--format=json"])
        require(code == 0 and decode(raw).get("Google Cloud SDK") == "582.0.0", "cloud_sdk_version_mismatch")
        code, raw, stderr = processes.run(processes.keygen_command())
        require(code == 0 and not (work / "id_ed25519").is_symlink(), "ephemeral_key_generation_failed")
        require(stat.S_IMODE((work / "id_ed25519").stat().st_mode) == 0o600, "ephemeral_private_key_mode")
        public_key, _ = host_guest.public_key(_local_bytes(work / "id_ed25519.pub", 1024))
        created = int(time.time() * 1000000)
        expiration = created + KEY_TTL_SECONDS * 1000000
        journal.update(public_key=public_key, created_us=created, expiration_us=expiration)
        client.arm_key(public_key, expiration)
        client.prepare_import()
        journal.update(import_attempted=True, key_absent_before_import=True)
        _save_journal(work, journal)  # Before the sole import; unknown responses are never replayed.
        own = client.import_key()
        journal["fingerprint"] = own["fingerprint"]
        _save_journal(work, journal)
        known = work / "known_hosts"
        with known.open("xb") as stream:
            os.chmod(known, 0o400)
            stream.write(pin["known_hosts"])
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0))
            port = reserved.getsockname()[1]
        processes.username = own["username"]
        processes.start_tunnel(port)
        code, raw, stderr = processes.run(ssh_command(work, own["username"], port), ready["payload"], timeout=180, stdout_limit=MAX_JSON)
        summary["ssh_diagnostic"] = process_diagnostic(stderr)
        if code not in {0, 2, 3}:
            raise Failure("ssh_or_sudo_failed", {"exit_code": code, **process_diagnostic(stderr)})
        inventory = parse_inventory(raw, code)
        after = validate_compute_snapshot(client.request("GET", VM_URL), client.request("GET", BOOT_URL), client.request("GET", DATA_URL), pin)
        require(before == after and _local_bytes(known, 1024) == pin["known_hosts"], "vm_or_pin_changed_during_inventory")
        _write_report(output, "inventory.json", inventory)
        summary.update(status=inventory["status"], guest_exit_code=code, unchanged_compute_snapshot=before)
    except BaseException as error:
        summary.update(status="blocked", error_code=str(error) if isinstance(error, Blocked) else "runner_failure_details_withheld")
        if isinstance(error, Failure):
            summary["failure"] = error.receipt
    finally:
        try:
            if processes is not None:
                try:
                    processes.close()
                except Exception:
                    summary.update(status="blocked", local_process_cleanup_error="own_process_cleanup_unconfirmed")
        finally:
            try:
                summary["cleanup"] = cleanup(environ=environ, workdir=work, reports=output, client=client)
            finally:
                for number, previous in previous_signals.items():
                    signal.signal(number, previous)
    if summary["cleanup"]["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"}:
        summary["status"] = "blocked_cleanup_unconfirmed"
    _write_report(output, "guest-summary.json", summary)
    (output / "guest-summary.md").write_text("# INT guest inventory\n\nStatus: " + summary["status"]
        + "\n\nRead-only guest inspection. No database, guest bootstrap or runtime deployment is approved.\n", encoding="utf-8")
    return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "run", "cleanup"))
    parser.add_argument("--host-evidence", type=Path)
    parser.add_argument("--host-evidence-sha")
    parser.add_argument("--payload-sha")
    parser.add_argument("--workdir", type=Path, required=True)
    parser.add_argument("--reports", type=Path, required=True)
    args = parser.parse_args()
    if args.operation == "cleanup":
        result = cleanup(environ=os.environ, workdir=args.workdir, reports=args.reports)
        print(json.dumps(result))
        return 0 if result["status"] in {"own_key_removed", "key_already_absent", "no_registered_key"} else 1
    require(args.host_evidence is not None and args.host_evidence_sha and args.payload_sha, "explicit_host_and_payload_binding_required")
    raw = _local_bytes(args.host_evidence, 65536)
    if args.operation == "check":
        readinesscheck(raw, args.host_evidence_sha, args.payload_sha, environ=os.environ, credential_document=_credential_document(os.environ))
        print("Exact host evidence, source and Deploy WIF selection verified locally; no SSH or cloud calls.")
        return 0
    result = run(environ=os.environ, workdir=args.workdir, reports=args.reports, host_evidence_raw=raw,
                 host_evidence_sha=args.host_evidence_sha, payload_sha=args.payload_sha)
    print(json.dumps({"status": result["status"], "runtime_authorized": False}))
    return 0 if result["status"] == "inventory_complete" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Blocked as error:
        print(json.dumps({"status": "blocked", "code": str(error)}), file=sys.stderr)
        raise SystemExit(1)
