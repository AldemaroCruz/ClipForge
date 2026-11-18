"""Proposed, owner-gated host-key recovery. Default check is offline; no SSH.

Cloud reads use the usual active human gcloud account. Every cloud write needs
an externally reviewed authorization JSON and its separately supplied SHA256.
Unknown operations preserve the publisher; there is no automatic rollback,
second reboot cycle, IAM mutation, state access, key generation or SQL.
"""
import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from urllib.parse import urlencode
import uuid

try:
    from scripts import int_vm_hostkey_guest as guest
except ModuleNotFoundError:
    import int_vm_hostkey_guest as guest

ROOT = Path(__file__).resolve().parent.parent
GUEST = ROOT / "scripts/int_vm_hostkey_guest.py"
STARTUP = ROOT / "infra/gcp/int-base/postgres-install.sh"
STARTUP_SHA = "a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255"
OWNER = "admin@ixbalam.studio"
VM = "/compute/v1/projects/clipforgebeta2/zones/us-central1-a/instances/clipforge-int-base-postgres"
PROJECT = "/compute/v1/projects/clipforgebeta2"
ZONE = "/compute/v1/projects/clipforgebeta2/zones/us-central1-a"
IDENTITY = {**guest.IDENTITY, "creation_timestamp": "2026-11-17T16:31:41.095-08:00",
            "compute_project_id": "4183880808888199084",
            "boot_disk_id": "2158164599035219715", "data_disk_id": "6427691858848206684",
            "image_id": "5913446147369107523"}
SCHEMA = "clipforge-int-hostkey-proposal-1"
JOURNAL = "clipforge-int-hostkey-journal-1"
AUTHORIZATION = "clipforge-int-hostkey-owner-authorization-1"
SECURITY = {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE",
            "disable-legacy-endpoints": "TRUE", "serial-port-enable": "FALSE"}
HOOKS = {"startup-script-url", "shutdown-script", "shutdown-script-url"}
LIMIT = 2 * 1024 * 1024


class Blocked(ValueError):
    """Fixed diagnostic codes only; never include HTTP bodies or credentials."""


def require(ok, code):
    if not ok:
        raise Blocked(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    require(len(raw) <= LIMIT, "json_size")
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (UnicodeError, json.JSONDecodeError) as error:
        raise Blocked("invalid_json") from error


def instant(value):
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
        require(result.utcoffset() is not None, "timestamp_timezone")
        return result.astimezone(timezone.utc)
    except (ValueError, AttributeError) as error:
        raise Blocked("invalid_timestamp") from error


def read_file(path, limit=LIMIT):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and not path.is_symlink()
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and info.st_nlink == 1 and 0 < info.st_size <= limit, "unsafe_local_file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    after = path.lstat()
    require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
            == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
            and len(raw) == info.st_size, "local_file_changed")
    return raw


def windows_private(path):
    """Check existing Windows ACL using native APIs; no ACL modification."""
    import ctypes
    from ctypes import wintypes
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    get_security = advapi.GetNamedSecurityInfoW
    get_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD,
                             ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_void_p), ctypes.c_void_p,
                             ctypes.POINTER(ctypes.c_void_p)]
    get_security.restype = wintypes.DWORD
    descriptor, owner, dacl = ctypes.c_void_p(), ctypes.c_void_p(), ctypes.c_void_p()
    require(get_security(str(path), 1, 5, ctypes.byref(owner), None,
                         ctypes.byref(dacl), None, ctypes.byref(descriptor)) == 0 and dacl.value,
            "private_acl_unavailable")
    sid_string = advapi.ConvertSidToStringSidW
    sid_string.argtypes = [ctypes.c_void_p, ctypes.POINTER(wintypes.LPWSTR)]
    sid_string.restype = wintypes.BOOL
    kernel.LocalFree.argtypes = [ctypes.c_void_p]
    kernel.LocalFree.restype = ctypes.c_void_p
    get_ace = advapi.GetAce
    get_ace.argtypes = [ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(ctypes.c_void_p)]
    get_ace.restype = wintypes.BOOL
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.OpenProcessToken.restype = wintypes.BOOL
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p,
                                           wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    advapi.GetTokenInformation.restype = wintypes.BOOL

    def sid(ptr):
        text = wintypes.LPWSTR()
        require(sid_string(ptr, ctypes.byref(text)), "private_acl_sid")
        try:
            return text.value
        finally:
            kernel.LocalFree(ctypes.cast(text, ctypes.c_void_p))
    try:
        handle, size = wintypes.HANDLE(), wintypes.DWORD()
        require(advapi.OpenProcessToken(kernel.GetCurrentProcess(), 8, ctypes.byref(handle)), "private_acl_current_user")
        try:
            advapi.GetTokenInformation(handle, 1, None, 0, ctypes.byref(size))
            require(0 < size.value <= 65536, "private_acl_current_user")
            buffer = ctypes.create_string_buffer(size.value)
            require(advapi.GetTokenInformation(handle, 1, buffer, size.value, ctypes.byref(size)), "private_acl_current_user")
            current = sid(ctypes.c_void_p.from_buffer(buffer))
        finally:
            kernel.CloseHandle(handle)
        allowed = {current, "S-1-5-18", "S-1-5-32-544"}
        require(sid(owner) in allowed, "private_acl_owner")
        header = ctypes.string_at(dacl, 8)
        count = int.from_bytes(header[4:6], "little")
        require(count > 0, "private_acl_empty")
        for index in range(count):
            ace = ctypes.c_void_p()
            require(get_ace(dacl, index, ctypes.byref(ace)), "private_acl_ace")
            raw = ctypes.string_at(ace, 8)
            # Only ordinary allow/deny ACEs are supported. Unknown ACL semantics
            # fail closed; no broad group or inherited public allow is accepted.
            require(raw[0] in {0, 1}, "private_acl_unsupported")
            if raw[0] == 0 and int.from_bytes(raw[4:8], "little"):
                require(sid(ctypes.c_void_p(ace.value + 8)) in allowed, "private_acl_broad")
    finally:
        kernel.LocalFree(descriptor)


def private_directory(path, create=False):
    path = Path(os.path.abspath(path))
    require(path != ROOT and ROOT not in path.parents, "scratch_inside_source_tree")
    for component in (path, *path.parents):
        if component.exists():
            info = component.lstat()
            require(not component.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400,
                    "private_path_reparse")
    if create and not path.exists():
        require(path.parent.is_dir(), "private_parent_missing")
        # Windows creation inherits the parent's already-private DACL.
        if os.name == "nt":
            windows_private(path.parent)
        path.mkdir(mode=0o700)
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode), "private_directory_type")
    if os.name == "nt":
        windows_private(path)
    else:
        require(info.st_uid == os.getuid() and not info.st_mode & 0o077, "private_directory_permissions")
    return path


def create_file(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


@contextmanager
def local_lock(work):
    path = work / "operator.lock"
    try:
        create_file(path, b"0")
    except FileExistsError:
        require(read_file(path, 1) == b"0", "operator_lock_content")
    stream = path.open("r+b")
    try:
        if os.name == "nt":
            import msvcrt
            msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(stream.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
        yield
    finally:
        stream.close()  # Kernel lock releases even after process interruption.


def sources():
    operator = read_file(Path(__file__), 131072)
    template = read_file(GUEST, 65536)
    startup = read_file(STARTUP, 65536)
    require(b"\r" not in operator and b"\r" not in template and sha(startup) == STARTUP_SHA, "source_bytes")
    return {"operator_sha256": sha(operator), "guest_source_sha256": sha(template)}, template, startup.decode("utf-8")


def render(template, nonce):
    require(re.fullmatch(r"[a-f0-9]{64}", nonce) and template.count(b"\nBINDING = None\n") == 1, "publisher_render")
    binding = {**guest.IDENTITY, "nonce": nonce, "guest_source_sha256": sha(template)}
    return template.replace(b"\nBINDING = None\n", b"\nBINDING = " + canonical(binding) + b"\n")


def metadata_items(metadata):
    require(isinstance(metadata, dict) and isinstance(metadata.get("items", []), list), "metadata_shape")
    result = {}
    for item in metadata.get("items", []):
        require(isinstance(item, dict) and set(item) == {"key", "value"}
                and isinstance(item["key"], str) and isinstance(item["value"], str)
                and item["key"] not in result, "metadata_item")
        result[item["key"]] = item["value"]
    return result


def resource_path(value):
    require(isinstance(value, str), "resource_link")
    for host in ("https://www.googleapis.com", "https://compute.googleapis.com"):
        if value.startswith(host + "/compute/v1/"):
            return value[len(host):]
    raise Blocked("resource_link")


def identity(vm, boot, data):
    require(vm.get("name") == "clipforge-int-base-postgres" and str(vm.get("id")) == IDENTITY["instance_id"]
            and vm.get("creationTimestamp") == IDENTITY["creation_timestamp"]
            and resource_path(vm.get("selfLink")) == VM and resource_path(vm.get("zone")) == ZONE,
            "vm_identity")
    disks = vm.get("disks", [])
    require(len(disks) == 2 and sum(disk.get("boot") is True for disk in disks) == 1, "vm_disk_count")
    expected = {True: ZONE + "/disks/clipforge-int-base-postgres",
                False: ZONE + "/disks/clipforge-int-base-postgres-data"}
    for disk in disks:
        require(disk.get("boot") in {True, False} and resource_path(disk.get("source")) == expected[disk["boot"]]
                and disk.get("autoDelete") is False, "vm_disk_attachment")
    for disk, disk_id, name in ((boot, IDENTITY["boot_disk_id"], "clipforge-int-base-postgres"),
                                (data, IDENTITY["data_disk_id"], "clipforge-int-base-postgres-data")):
        require(str(disk.get("id")) == disk_id and disk.get("name") == name and disk.get("status") == "READY"
                and resource_path(disk.get("selfLink")) == ZONE + "/disks/" + name
                and [resource_path(user) for user in disk.get("users", [])] == [VM], "disk_identity")
    require(str(boot.get("sourceImageId")) == IDENTITY["image_id"], "boot_image_identity")
    nics = vm.get("networkInterfaces", [])
    require(len(nics) == 1 and nics[0].get("networkIP") == "10.80.1.2"
            and not nics[0].get("accessConfigs") and not nics[0].get("ipv6AccessConfigs"), "vm_private_network")
    for key, value in SECURITY.items():
        require(metadata_items(vm.get("metadata", {})).get(key, "").upper() == value, "vm_security_metadata")
    instant(vm.get("lastStartTimestamp", ""))


def metadata_flags(own, inherited):
    return {"instance": {key + "_present": key in own for key in sorted(HOOKS | {"enable-guest-attributes"})},
            "project": {key + "_present": key in inherited for key in sorted(HOOKS | {"enable-guest-attributes", "startup-script"})},
            "security_metadata_exact": True}


def snapshot(api, hooks=True, audit=None):
    vm, project = api.request("GET", VM), api.request("GET", PROJECT)
    boot = api.request("GET", ZONE + "/disks/clipforge-int-base-postgres")
    data = api.request("GET", ZONE + "/disks/clipforge-int-base-postgres-data")
    identity(vm, boot, data)
    require(str(project.get("id")) == IDENTITY["compute_project_id"]
            and project.get("name") == IDENTITY["project"]
            and resource_path(project.get("selfLink")) == PROJECT, "project_identity")
    own = metadata_items(vm.get("metadata", {}))
    inherited = metadata_items(project.get("commonInstanceMetadata", {}))
    if hooks:
        require(not HOOKS.intersection(own) and not (HOOKS | {"startup-script"}).intersection(inherited), "startup_or_shutdown_hook")
        require("enable-guest-attributes" not in own and "enable-guest-attributes" not in inherited, "guest_attributes_changed")
        if audit is not None:
            audit.update(metadata_flags(own, inherited))
    require(isinstance(vm["metadata"].get("fingerprint"), str) and vm["metadata"]["fingerprint"], "metadata_fingerprint")
    return vm, own


class GcloudUser:
    def __init__(self):
        prohibited = ("GOOGLE_APPLICATION_CREDENTIALS", "CLOUDSDK_CONFIG", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
                      "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN",
                      "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_LOGIN_CONFIG_FILE", "CLOUDSDK_CORE_ACCOUNT")
        require(not any(os.environ.get(name) for name in prohibited), "authentication_override")
        self.program = shutil.which("gcloud")
        require(self.program and Path(self.program).is_absolute(), "gcloud_unavailable")
        require(self.run("config", "get-value", "core/account") == OWNER, "usual_user_account")
        for prop in ("auth/impersonate_service_account", "auth/credential_file_override", "auth/access_token_file"):
            require(self.run("config", "get-value", prop) in {"", "(unset)"}, "authentication_override")
        self.token = self.run("auth", "print-access-token")
        require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", self.token), "oauth_token_format")

    def run(self, *args):
        result = subprocess.run([self.program, *args, "--quiet"], stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=60, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 16384, "gcloud_user_authentication")
        return result.stdout.decode("ascii").strip()


class Compute:
    def __init__(self, token, approved=None):
        self.token = token
        self.approved = approved

    def request(self, method, path, payload=None):
        base, _, query = path.partition("?")
        allowed_get = base in {VM, PROJECT, ZONE + "/disks/clipforge-int-base-postgres",
                               ZONE + "/disks/clipforge-int-base-postgres-data", VM + "/serialPort"}
        allowed_get = allowed_get or bool(re.fullmatch(re.escape(ZONE) + r"/operations/[A-Za-z0-9_-]+", base))
        require((method == "GET" and allowed_get and payload is None)
                or (method == "POST" and base in {VM + "/setMetadata", VM + "/stop", VM + "/start"}), "http_scope")
        require(not query or (method == "GET" and base == VM + "/serialPort" and re.fullmatch(r"port=1&start=[0-9]+", query))
                or (method == "POST" and re.fullmatch(r"requestId=[a-f0-9-]{36}", query)), "http_query")
        if method == "POST":
            require(isinstance(self.approved, dict) and self.approved.get("schema") == AUTHORIZATION
                    and self.approved.get("decision") == "authorize_hostkey_recovery_once"
                    and self.approved.get("proposal", {}).get("identity") == IDENTITY
                    and instant(self.approved.get("approved_at")) <= datetime.now(timezone.utc)
                    < instant(self.approved.get("expires_at")), "cloud_write_not_authorized")
        connection = http.client.HTTPSConnection("compute.googleapis.com", timeout=30)
        try:
            connection.request(method, path, body=canonical(payload) if payload is not None else None,
                               headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json"})
            response = connection.getresponse()
            require(response.status == 200, "compute_http_" + str(response.status))
            raw = response.read(LIMIT + 1)
            value = strict_json(raw)
            require(isinstance(value, dict), "compute_response")
            return value
        except (OSError, http.client.HTTPException) as error:
            raise Blocked("compute_transport_unknown") from error
        finally:
            connection.close()


def inspect(api, work, nonce):
    hashes, template, original = sources()
    audit = {}
    vm, own = snapshot(api, audit=audit)
    require(vm.get("status") == "RUNNING" and own.get("startup-script") == original, "original_startup_or_status")
    publisher = render(template, nonce)
    proposal = {"schema": SCHEMA, "identity": IDENTITY, **hashes, "nonce": nonce,
                "publisher_sha256": sha(publisher), "startup_original_sha256": STARTUP_SHA,
                "initial_metadata_sha256": sha(canonical(own)), "metadata_checks": audit,
                "initial_last_start_timestamp": vm["lastStartTimestamp"], "operator_account": OWNER,
                "workdir": str(work), "allowed_actions": ["publish-hostkey-once", "restore-own-startup"]}
    create_file(work / "publisher.py", publisher)
    create_file(work / "proposal.json", canonical(proposal))
    create_file(work / "journal.json", canonical({"schema": JOURNAL, "proposal_sha256": sha(canonical(proposal)),
                "nonce": nonce, "phase": "prepared", "operations": {}, "original_startup": original}))
    return proposal


def authorization(raw, expected_sha, proposal, now):
    require(re.fullmatch(r"[a-f0-9]{64}", expected_sha) and sha(raw) == expected_sha, "authorization_sha256")
    value = strict_json(raw)
    expected = {"schema", "decision", "authorized_by", "authorization_id", "approved_at", "expires_at", "proposal"}
    require(isinstance(value, dict) and set(value) == expected and value["schema"] == AUTHORIZATION
            and value["decision"] == "authorize_hostkey_recovery_once" and value["authorized_by"] == OWNER
            and re.fullmatch(r"[A-Za-z0-9_-]{8,100}", value["authorization_id"])
            and value["proposal"] == proposal, "owner_authorization")
    approved, expires = instant(value["approved_at"]), instant(value["expires_at"])
    require(approved <= now < expires and timedelta(0) < expires - approved <= timedelta(hours=2), "authorization_window")
    return value


def load(work):
    proposal = strict_json(read_file(work / "proposal.json"))
    journal = strict_json(read_file(work / "journal.json"))
    hashes, template, original = sources()
    expected = {"schema", "identity", "operator_sha256", "guest_source_sha256", "nonce", "publisher_sha256",
                "startup_original_sha256", "initial_last_start_timestamp", "operator_account", "workdir", "allowed_actions",
                "initial_metadata_sha256", "metadata_checks"}
    require(isinstance(proposal, dict) and set(proposal) == expected and proposal["schema"] == SCHEMA
            and proposal["identity"] == IDENTITY and proposal["operator_account"] == OWNER
            and proposal["workdir"] == str(work) and all(proposal.get(key) == value for key, value in hashes.items())
            and proposal["startup_original_sha256"] == STARTUP_SHA
            and re.fullmatch(r"[a-f0-9]{64}", proposal["initial_metadata_sha256"])
            and proposal["metadata_checks"] == metadata_flags({}, {})
            and proposal["allowed_actions"] == ["publish-hostkey-once", "restore-own-startup"], "proposal_contract")
    publisher = render(template, proposal["nonce"])
    require(read_file(work / "publisher.py", 65536) == publisher and sha(publisher) == proposal["publisher_sha256"], "publisher_changed")
    require(journal.get("schema") == JOURNAL and journal.get("nonce") == proposal["nonce"]
            and journal.get("proposal_sha256") == sha(canonical(proposal)) and journal.get("original_startup") == original
            and isinstance(journal.get("operations"), dict), "journal_binding")
    instant(proposal["initial_last_start_timestamp"])
    return proposal, journal, publisher.decode("ascii")


def record_contract(value, proposal):
    fields = {"schema", *guest.IDENTITY, "nonce", "guest_source_sha256", "script_sha256", "public_key", "fingerprint"}
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == "clipforge-int-hostkey-record-1"
            and all(value.get(key) == expected for key, expected in guest.IDENTITY.items())
            and value["nonce"] == proposal["nonce"] and value["guest_source_sha256"] == proposal["guest_source_sha256"]
            and value["script_sha256"] == proposal["publisher_sha256"], "serial_record_binding")
    key, fingerprint = guest.public_key(value["public_key"].encode("ascii"))
    require(key == value["public_key"] and fingerprint == value["fingerprint"], "serial_record_key")
    return value


def serial_records(raw, proposal):
    require(isinstance(raw, str) and len(raw.encode("utf-8")) <= LIMIT, "serial_size")
    found = []
    for line in raw.splitlines(keepends=True):
        if guest.MARKER in line:
            if not line.endswith(("\n", "\r")):
                continue  # A bounded serial GET may end part-way through write().
            body = line.split(guest.MARKER, 1)[1]
            require(len(body) <= 2048, "serial_record_size")
            value = strict_json(body.encode("utf-8"))
            # Other intervention markers cannot establish this intervention's pin.
            if isinstance(value, dict) and value.get("nonce") == proposal["nonce"]:
                found.append(record_contract(value, proposal))
    require(len(found) <= 1, "serial_duplicate_record")
    return found


def ssh_options(known_hosts):
    require(known_hosts.is_file(), "known_hosts_missing")
    alias = "clipforge-int-base-postgres." + IDENTITY["instance_id"]
    return ["-oHostKeyAlias=" + alias, "-oStrictHostKeyChecking=yes", "-oUserKnownHostsFile=" + str(known_hosts),
            "-oGlobalKnownHostsFile=/dev/null", "-oHostKeyAlgorithms=ssh-ed25519", "-oUpdateHostKeys=no",
            "-oBatchMode=yes", "-oPasswordAuthentication=no", "-oKbdInteractiveAuthentication=no", "-oForwardAgent=no"]


class Recovery:
    def __init__(self, api, work, proposal, journal, publisher, *, clock=time.monotonic, sleep=time.sleep, timeout=180):
        self.api, self.work, self.proposal, self.journal, self.publisher = api, work, proposal, journal, publisher
        self.clock, self.sleep, self.timeout = clock, sleep, timeout
        require(0 < timeout <= 600, "operation_timeout_bound")

    def save(self):
        path = self.work / "journal.json"
        current = strict_json(read_file(path))
        require(current.get("schema") == JOURNAL and current.get("nonce") == self.proposal["nonce"], "journal_replaced")
        temporary = self.work / ("journal-" + uuid.uuid4().hex + ".tmp")
        create_file(temporary, canonical(self.journal))
        os.replace(temporary, path)

    def operation(self, value, intent, pinned=None):
        require(isinstance(value, dict) and re.fullmatch(r"[A-Za-z0-9_-]+", value.get("name", ""))
                and re.fullmatch(r"[1-9][0-9]*", str(value.get("id", "")))
                and str(value.get("targetId")) == IDENTITY["instance_id"] and resource_path(value.get("targetLink")) == VM
                and value.get("operationType") == intent["type"] and value.get("clientOperationId") == intent["request_id"]
                and resource_path(value.get("zone")) == ZONE and value.get("status") in {"PENDING", "RUNNING", "DONE"},
                "operation_identity")
        require(pinned is None or (value["name"], str(value["id"])) == (pinned["name"], pinned["id"]), "operation_changed")
        return {"name": value["name"], "id": str(value["id"]), "status": value["status"]}

    def poll(self, key, operation_name=None):
        intent = self.journal["operations"][key]
        pinned = intent.get("operation")
        require(pinned or operation_name, "operation_name_unknown_preserve_publisher")
        name = pinned["name"] if pinned else operation_name
        require(re.fullmatch(r"[A-Za-z0-9_-]+", name), "operation_name")
        until = self.clock() + self.timeout
        while self.clock() < until:
            value = self.api.request("GET", ZONE + "/operations/" + name)
            observed = self.operation(value, intent, pinned)
            if pinned is None:
                pinned = observed
            intent["operation"] = observed
            self.save()
            if observed["status"] == "DONE":
                require(not value.get("error") and not value.get("httpErrorStatusCode"), "operation_failed")
                intent["done_success"] = True
                self.save()
                return
            self.sleep(2)
        raise Blocked("operation_timeout_preserve_publisher")

    def mutate(self, key, kind, payload=None):
        require(key not in self.journal["operations"], "mutation_already_attempted")
        intent = {"type": kind, "request_id": str(uuid.uuid5(uuid.NAMESPACE_URL, self.proposal["nonce"] + ":" + key))}
        self.journal["operations"][key] = intent
        self.journal["phase"] = key + "_requested"
        self.save()  # Persist intent before sending; unknown outcomes never replay.
        value = self.api.request("POST", VM + "/" + kind + "?" + urlencode({"requestId": intent["request_id"]}), payload)
        intent["operation"] = self.operation(value, intent)
        self.save()
        self.poll(key)

    def own_current(self, hooks=True):
        vm, own = snapshot(self.api, hooks)
        require(own.get("startup-script") == self.publisher and sha(own["startup-script"].encode("ascii"))
                == self.proposal["publisher_sha256"], "current_startup_not_own_publisher")
        return vm, own

    def new_running_boot(self, vm):
        require(vm.get("status") == "RUNNING"
                and instant(vm["lastStartTimestamp"]) > instant(self.proposal["initial_last_start_timestamp"]),
                "new_running_boot_unconfirmed")
        observed = self.journal.get("observed_last_start_timestamp")
        require(observed is None or observed == vm["lastStartTimestamp"], "boot_changed_during_recovery")
        if observed is None:
            self.journal["observed_last_start_timestamp"] = vm["lastStartTimestamp"]
            self.save()

    def publication(self):
        until = self.clock() + self.timeout
        while self.clock() < until:
            vm, _ = self.own_current()
            self.new_running_boot(vm)
            # Re-read the bounded serial buffer: a partial final line must not
            # advance beyond the marker and lose its remaining bytes.
            response = self.api.request("GET", VM + "/serialPort?port=1&start=0")
            require(re.fullmatch(r"[0-9]+", str(response.get("start", "")))
                    and int(response["start"]) == 0, "serial_buffer_truncated_or_start_unknown")
            require(re.fullmatch(r"[0-9]+", str(response.get("next", "")))
                    and int(response["next"]) >= 0, "serial_cursor")
            records = serial_records(response.get("contents", ""), self.proposal)
            if records:
                vm, _ = self.own_current()
                self.new_running_boot(vm)
                self.journal["hostkey_record"] = records[0]
                self.journal["phase"] = "key_verified"
                self.save()
                return
            self.sleep(2)
        raise Blocked("publication_timeout_preserve_publisher")

    def restore(self, before_cycle=False):
        vm, own = self.own_current()
        if before_cycle:
            require("stop" not in self.journal["operations"] and "start" not in self.journal["operations"]
                    and vm.get("status") == "RUNNING"
                    and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"], "precycle_restore_unsafe")
        else:
            require(self.journal["operations"].get("start", {}).get("done_success") is True, "start_not_completed")
            record_contract(self.journal.get("hostkey_record"), self.proposal)
            self.new_running_boot(vm)
        # Copy CURRENT items, replacing only our exact publisher. Fresh metadata
        # fingerprint provides CAS; a changed startup is never overwritten.
        items = [{"key": item["key"], "value": self.journal["original_startup"] if item["key"] == "startup-script" else item["value"]}
                 for item in vm["metadata"].get("items", [])]
        require(own.get("startup-script") == self.publisher, "restore_ownership")
        self.mutate("restore", "setMetadata", {"fingerprint": vm["metadata"]["fingerprint"], "items": items})
        self.finish(before_cycle)

    def finish(self, before_cycle=False):
        vm, own = snapshot(self.api)
        require(own.get("startup-script") == self.journal["original_startup"], "restore_not_observed")
        require(self.journal["operations"].get("restore", {}).get("done_success") is True, "restore_operation_unconfirmed")
        if not before_cycle:
            self.new_running_boot(vm)
            record = record_contract(self.journal.get("hostkey_record"), self.proposal)
            line = ("clipforge-int-base-postgres." + IDENTITY["instance_id"] + " " + record["public_key"] + "\n").encode("ascii")
            path = self.work / "known_hosts"
            if path.exists():
                require(read_file(path, 1024) == line, "known_hosts_changed")
            else:
                create_file(path, line)
            self.journal["phase"] = "complete"
        else:
            require(vm.get("status") == "RUNNING"
                    and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"],
                    "precycle_restore_final_boot_unconfirmed")
            self.journal["phase"] = "restored_before_cycle_no_pin"
        self.save()

    def execute(self):
        require(self.journal["phase"] == "prepared" and not self.journal["operations"], "no_execute_replay")
        vm, own = snapshot(self.api)
        require(vm.get("status") == "RUNNING" and own.get("startup-script") == self.journal["original_startup"]
                and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"]
                and sha(canonical(own)) == self.proposal["initial_metadata_sha256"], "prepared_snapshot_changed")
        items = [{"key": item["key"], "value": self.publisher if item["key"] == "startup-script" else item["value"]}
                 for item in vm["metadata"].get("items", [])]
        self.mutate("install", "setMetadata", {"fingerprint": vm["metadata"]["fingerprint"], "items": items})
        vm, _ = self.own_current()
        require(vm.get("status") == "RUNNING"
                and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"],
                "precycle_boot_changed_preserve_publisher")
        self.journal["phase"] = "publisher_installed"
        self.save()
        self.mutate("stop", "stop")
        vm, _ = self.own_current()
        require(vm.get("status") == "TERMINATED"
                and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"],
                "stop_not_observed_or_boot_changed_preserve_publisher")
        self.mutate("start", "start")
        self.publication()
        self.restore()

    def recover(self, operation_name=None):
        """Reads/polls or restores our metadata; never installs/stops/starts."""
        operations = self.journal["operations"]
        if self.journal["phase"] in {"complete", "restored_before_cycle_no_pin"}:
            vm, own = snapshot(self.api)
            require(own.get("startup-script") == self.journal["original_startup"], "completed_startup_changed")
            if self.journal["phase"] == "complete":
                self.new_running_boot(vm)
            else:
                require(vm.get("status") == "RUNNING"
                        and vm["lastStartTimestamp"] == self.proposal["initial_last_start_timestamp"], "completed_boot_changed")
            return
        if "restore" in operations:
            if not operations["restore"].get("done_success"):
                self.poll("restore", operation_name)
            self.finish("start" not in operations and "stop" not in operations)
            return
        if "start" in operations:
            if not operations["start"].get("done_success"):
                self.poll("start", operation_name)
            self.publication()
            self.restore()
            return
        require("stop" not in operations, "stopped_or_stop_unknown_preserve_publisher")
        require("install" in operations, "no_installation_to_recover")
        if not operations["install"].get("done_success"):
            self.poll("install", operation_name)
        self.restore(before_cycle=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", nargs="?", choices=("check", "inspect", "execute", "recover"), default="check")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--authorization", type=Path)
    parser.add_argument("--authorization-sha256")
    parser.add_argument("--operation-name", help="Exact existing operation for an unknown response; GET validates request/target/type/ID")
    args = parser.parse_args(argv)
    hashes, _, _ = sources()
    if args.action == "check" and args.workdir is None:
        print(json.dumps({"status": "offline_check_only", **hashes, "identity": IDENTITY}, sort_keys=True))
        return
    require(args.workdir is not None, "private_workdir_required")
    work = private_directory(args.workdir, create=args.action == "inspect")
    with local_lock(work):
        if args.action == "inspect":
            require(args.authorization is None and args.authorization_sha256 is None, "inspect_no_authorization")
            result = inspect(Compute(GcloudUser().token), work, os.urandom(32).hex())
            print(json.dumps({"status": "inspection_only_no_cloud_writes", "proposal_sha256": sha(canonical(result)), **hashes}, sort_keys=True))
            return
        proposal, journal, publisher = load(work)
        if args.action == "check":
            print(json.dumps({"status": "offline_proposal_check_only", "phase": journal["phase"], **hashes}, sort_keys=True))
            return
        require(args.authorization is not None and args.authorization_sha256 is not None, "future_owner_authorization_required")
        require(args.authorization.name == "owner-authorization.json"
                and args.authorization.parent.resolve() == work, "authorization_private_location")
        approved = authorization(read_file(args.authorization, 65536), args.authorization_sha256, proposal, datetime.now(timezone.utc))
        engine = Recovery(Compute(GcloudUser().token, approved), work, proposal, journal, publisher)
        journal.setdefault("authorizations", []).append({"sha256": args.authorization_sha256,
                    "authorization_id": approved["authorization_id"], "approved_at": approved["approved_at"],
                    "expires_at": approved["expires_at"], "action": args.action})
        engine.save()
        try:
            if args.action == "execute":
                require(args.operation_name is None, "execute_operation_override")
                engine.execute()
            else:
                engine.recover(args.operation_name)
        except Exception:
            # The durable intent/operation journal remains authoritative. Never
            # restore the PostgreSQL startup or reboot as an exception handler.
            raise
        print(json.dumps({"status": journal["phase"], "instance_id": IDENTITY["instance_id"],
                          "fingerprint": journal.get("hostkey_record", {}).get("fingerprint")}, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        code = str(error) if isinstance(error, Blocked) else "operator_blocked_private_diagnostic_required"
        print(json.dumps({"status": "blocked", "code": code}), file=sys.stderr)
        raise SystemExit(1)
