"""One-shot DB-01 guest operator. Protected JSON stdin; no automatic recovery.

The caller verifies public source, GCP proof and explicit activation. This guest
independently checks local identity/storage/TLS and journals every mutation.
Existing filesystems, clusters and partial operations are never adopted.
"""
from __future__ import annotations

import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import os
from pathlib import Path
try:
    import pwd
except ImportError:
    pwd = None
import re
import selectors
import signal
import stat
import subprocess
import sys
import tempfile
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

DEVICE = "/dev/disk/by-id/google-clipforge-pg-data"
MOUNT = Path("/var/lib/clipforge-postgres/data")
ROOT = Path("/var/lib/clipforge-postgres")
JOURNAL_DIR = ROOT / "db01"
CONFIG = Path("/etc/postgresql/17/main")
FSTAB = Path("/etc/fstab")
DISK_ID = "6427691858848206684"
INSTANCE_ID = "1670495097211408131"
SIZE_BYTES = 21474836480
MIN_TLS_SECONDS = 604800
TOTAL_SECONDS = 540  # Parent SSH reserves sixty seconds to receive the receipt.
INPUT_LIMIT = OUTPUT_LIMIT = 65536
ERROR_LIMIT = 8192
ENV = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_PAGER": "/bin/false", "PAGER": "/bin/false"}
SECRET_KEYS = {"app_password", "migrator_password", "server_cert", "server_key", "ca_cert"}
PROOF_KEYS = {"project_id", "project_number", "zone", "instance_id", "boot_timestamp", "disk_id", "disk_name", "device_name", "size_bytes", "disk_type", "interface", "index", "mode", "boot", "auto_delete", "observed_utc", "guest_major_minor", "guest_serial", "guest_by_id", "guest_read_receipt_sha256", "guest_read_source_sha256", "guest_boot_id"}
INPUT_KEYS = {"schema", "operation_id", "approved_commit", "proposal_sha256", "operator_sha256", "confirmation", "disk_proof", "secrets"}
FLAGS = {"runtime_authorized": False, "external_client_acceptance": False, "migrations_applied": False, "administrator_bootstrapped": False, "restore_verified": False, "security_accepted": False}
CHECK_KEYS = {"identity_verified", "disk_blank_verified", "tls_inputs_verified", "mount_verified", "parent_traversal_verified", "configuration_verified", "roles_verified", "local_tls_handshake_verified", "boot_persistence_configured"}
OP_KEYS = {"operation", "exit_code", "status", "duration_ms", "stdout_bytes", "stderr_bytes", "messages", "unclassified_stderr_lines"}
OPS = {"unit_files", "unit_state", "processes", "tcp", "unix", "clusters", "packages", "locale", "lsblk", "udev", "wipefs", "mounts", "tls_chain", "tls_leaf_lifetime", "tls_ca_lifetime", "tls_ip", "tls_cert_public", "tls_key_public", "mkfs", "filesystem_uuid", "mount", "mounted", "cluster_create", "unmask", "start", "sql_roles", "sql_database", "sql_grants", "sql_config", "sql_role_check", "service_active", "tls_handshake", "enable", "enabled"}
PHRASES = ("Permission denied", "Operation not permitted", "No such file or directory", "certificate has expired", "certificate verify failed", "IP address mismatch", "unable to get local issuer certificate", "Failed to start", "already exists", "Connection refused", "No space left on device")
BINARIES = ("/usr/bin/systemctl", "/usr/bin/ps", "/usr/bin/ss", "/usr/bin/pg_lsclusters", "/usr/bin/dpkg-query", "/usr/bin/locale",
            "/usr/bin/lsblk", "/usr/bin/udevadm", "/usr/sbin/wipefs", "/usr/bin/findmnt", "/usr/bin/openssl",
            "/usr/sbin/mkfs.ext4", "/usr/sbin/blkid", "/usr/bin/mount", "/usr/bin/pg_createcluster",
            "/usr/sbin/runuser", "/usr/lib/postgresql/17/bin/psql")
DISK_OPS = ["mounts", "lsblk", "udev", "wipefs"]
SUCCESS_OPERATIONS = (["unit_files", "unit_state", "processes", "tcp", "unix", "clusters", "packages", "locale"]
                      + DISK_OPS + ["tls_chain", "tls_leaf_lifetime", "tls_ca_lifetime", "tls_ip", "tls_cert_public", "tls_key_public"]
                      + DISK_OPS + DISK_OPS + ["mkfs", "filesystem_uuid", "mount", "mounted", "mounted", "cluster_create",
                         "unmask", "start", "sql_roles", "sql_database", "sql_grants", "mounted", "sql_config",
                         "sql_role_check", "service_active", "clusters", "tls_handshake", "enable", "enabled"])


class Blocked(ValueError):
    """Fixed codes only; no protected values."""


class NativeFailure(Blocked):
    pass


def require(ok, code):
    if not ok:
        raise Blocked(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def utc():
    return datetime.now(timezone.utc).isoformat()


def instant(value):
    require(isinstance(value, str) and len(value) <= 64, "invalid_timestamp")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise Blocked("invalid_timestamp") from None
    require(result.tzinfo is not None, "timezone_required")
    return result


def decode(raw):
    def pairs(rows):
        result = {}
        for key, value in rows:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    require(isinstance(raw, bytes) and 0 < len(raw) <= INPUT_LIMIT, "bounded_input_required")
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise Blocked("invalid_input_json") from None


def scram(password):
    require(isinstance(password, str) and 32 <= len(password) <= 4096 and password.isascii()
            and all(33 <= ord(char) <= 126 for char in password), "invalid_protected_password")
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored = hashlib.sha256(client).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")
    return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(stored) + ":" + b64(server)


def validate_secrets(value):
    require(isinstance(value, dict) and set(value) == SECRET_KEYS, "closed_protected_inputs_required")
    scram(value["app_password"])
    scram(value["migrator_password"])
    require(value["app_password"] != value["migrator_password"], "database_passwords_must_differ")
    for key in ("ca_cert", "server_cert", "server_key"):
        text = value[key]
        kind = "PRIVATE KEY" if key == "server_key" else "CERTIFICATE"
        require(isinstance(text, str) and text.isascii() and 1 <= len(text) <= 8192
                and text.startswith("-----BEGIN " + kind + "-----\n")
                and text.rstrip().endswith("-----END " + kind + "-----")
                and "\x00" not in text, "invalid_protected_tls_input")
        require(key == "server_key" or "PRIVATE KEY" not in text, "private_key_in_certificate_input")


def validate_input(value, source_sha, *, now=None):
    require(isinstance(value, dict) and set(value) == INPUT_KEYS and value["schema"] == "clipforge-db01-bootstrap-input-1", "closed_bootstrap_input_required")
    require(isinstance(value["operation_id"], str) and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]), "invalid_operation_id")
    for key, width in (("approved_commit", 40), ("proposal_sha256", 64), ("operator_sha256", 64)):
        require(isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{" + str(width) + "}", value[key]), "invalid_source_binding")
    require(value["operator_sha256"] == source_sha, "operator_source_digest_mismatch")
    require(value["confirmation"] == "INITIALIZE_NEW_DISK_" + DISK_ID, "explicit_disk_confirmation_required")
    proof = value["disk_proof"]
    require(isinstance(proof, dict) and set(proof) == PROOF_KEYS, "closed_disk_proof_required")
    expected = {"project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a", "instance_id": INSTANCE_ID,
                "disk_id": DISK_ID, "disk_name": "clipforge-int-base-postgres-data", "device_name": "clipforge-pg-data",
                "size_bytes": SIZE_BYTES, "disk_type": "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard", "interface": "SCSI", "index": 1,
                "mode": "READ_WRITE", "guest_by_id": DEVICE}
    require(all(proof.get(key) == item and type(proof.get(key)) is type(item) for key, item in expected.items())
            and proof["boot"] is False and proof["auto_delete"] is False, "exact_target_identity_required")
    require(isinstance(proof["guest_major_minor"], str) and re.fullmatch(r"[0-9]+:[0-9]+", proof["guest_major_minor"])
            and isinstance(proof["guest_serial"], str) and 0 < len(proof["guest_serial"]) <= 128
            and all(32 <= ord(char) <= 126 for char in proof["guest_serial"])
            and isinstance(proof["guest_boot_id"], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", proof["guest_boot_id"]), "observed_guest_identity_required")
    for key in ("guest_read_receipt_sha256", "guest_read_source_sha256"):
        require(isinstance(proof[key], str) and re.fullmatch(r"[a-f0-9]{64}", proof[key]), "observed_guest_provenance_required")
    observed = instant(proof["observed_utc"])
    at = now or datetime.now(timezone.utc)
    require(0 <= (at - observed).total_seconds() <= 300 and instant(proof["boot_timestamp"]) <= observed, "disk_proof_expired_or_future")
    validate_secrets(value["secrets"])
    return value


def blank_disk_contract(disk_id, confirmation, signatures, block_info):
    require(isinstance(disk_id, str) and re.fullmatch(r"[1-9][0-9]*", disk_id)
            and confirmation == "INITIALIZE_NEW_DISK_" + disk_id, "explicit_disk_confirmation_required")
    require(signatures == [], "disk_signatures_present")
    rows = block_info.get("blockdevices", [])
    require(len(rows) == 1 and rows[0].get("type") == "disk" and not rows[0].get("fstype")
            and not rows[0].get("children") and not any(rows[0].get("mountpoints") or []), "existing_disk_structure_or_mount")


def _regular(path, *, owners=(0,), maximum=65536):
    info = Path(path).lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o022
            and info.st_nlink == 1 and info.st_size <= maximum, "unsafe_regular_file")
    return info


def _parents(path, *, owners=(0,)):
    for parent in reversed(Path(path).parents):
        info = parent.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o022, "unsafe_parent_directory")


def read_bytes(path, limit=65536, *, owners=(0,)):
    _parents(path, owners=owners)
    _regular(path, owners=owners, maximum=limit)
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "file_limit")
    return raw


def _fsync_dir(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def parent_permissions(info, postgres_gid):
    require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == postgres_gid
            and stat.S_IMODE(info.st_mode) == 0o710, "postgres_parent_permissions_mismatch")
    return {"uid": info.st_uid, "gid": info.st_gid, "mode": "0710"}


def postgres_account():
    require(pwd is not None, "postgres_os_account_unavailable")
    account = pwd.getpwnam("postgres")
    require(type(account.pw_uid) is int and account.pw_uid > 0
            and type(account.pw_gid) is int and account.pw_gid > 0, "postgres_must_be_unprivileged_os_account")
    return account


def require_utf8_locale(raw):
    require(isinstance(raw, bytes), "invalid_locale_query")
    locales = raw.decode("ascii").splitlines()
    require(any(item in {"C.utf8", "C.UTF-8"} for item in locales), "required_utf8_locale_unavailable")


def atomic_file(path, raw, *, expected=None, uid=0, gid=0, mode=0o600, owners=(0,)):
    path = Path(path)
    _parents(path, owners=owners)
    if expected is None:
        require(not os.path.lexists(path), "destination_already_exists")
    else:
        require(read_bytes(path, owners=owners) == expected, "file_changed_concurrently")
    temp = path.with_name("." + path.name + ".db01-" + os.urandom(8).hex())
    try:
        descriptor = os.open(temp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, mode)
        with os.fdopen(descriptor, "wb") as stream:
            os.fchown(stream.fileno(), uid, gid)
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        require((expected is None and not os.path.lexists(path))
                or expected is not None and read_bytes(path, owners=owners) == expected, "file_changed_concurrently")
        os.replace(temp, path)
        _fsync_dir(path.parent)
    finally:
        if os.path.lexists(temp):
            temp.unlink()


def _trusted_binary(path):
    require(path.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/postgresql/17/bin/")), "fixed_binary_required")
    real = os.path.realpath(path)
    _parents(real)
    info = _regular(real, maximum=64 * 1024 * 1024)
    require(info.st_mode & 0o111, "executable_required")


def native(operation, argv, payload, timeout):
    require(operation in OPS and isinstance(argv, list) and all(isinstance(arg, str) for arg in argv), "unknown_native_operation")
    _trusted_binary(argv[0])
    started = time.monotonic()
    process = subprocess.Popen(argv, stdin=subprocess.PIPE if payload is not None else subprocess.DEVNULL,
                               stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=ENV, start_new_session=True, bufsize=0)
    output, errors = bytearray(), bytearray()
    selector = selectors.DefaultSelector()
    status, code = "ok", None
    try:
        for stream, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ, label)
        offset = 0
        if payload is not None:
            os.set_blocking(process.stdin.fileno(), False)
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        while selector.get_map():
            if time.monotonic() - started >= timeout:
                status = "timeout"
                break
            for key, _ in selector.select(0.1):
                if key.data == "stdin":
                    try:
                        offset += os.write(key.fileobj.fileno(), payload[offset:offset + 16384])
                    except BrokenPipeError:
                        offset = len(payload)
                    if offset == len(payload):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), 8192)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                    continue
                target, cap = (output, OUTPUT_LIMIT) if key.data == "stdout" else (errors, ERROR_LIMIT)
                if len(target) + len(chunk) > cap:
                    target.extend(chunk[:max(0, cap - len(target))])
                    status = "stdout_limit" if key.data == "stdout" else "stderr_limit"
                    break
                target.extend(chunk)
            if status != "ok":
                break
        if status == "ok":
            code = process.wait(timeout=max(0.01, timeout - (time.monotonic() - started)))
            if code != 0:
                status = "nonzero_exit"
    except subprocess.TimeoutExpired:
        status = "timeout"
    finally:
        selector.close()
        if process.poll() is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        process.wait(timeout=5)
        if code is None:
            code = process.returncode
        for stream in (process.stdin, process.stdout, process.stderr):
            if stream is not None and not stream.closed:
                stream.close()
    lines = errors.decode("utf-8", "replace").splitlines()
    messages = sorted({phrase for line in lines for phrase in PHRASES if phrase.lower() in line.lower()})
    row = {"operation": operation, "exit_code": code, "status": status,
           "duration_ms": int((time.monotonic() - started) * 1000), "stdout_bytes": len(output), "stderr_bytes": len(errors),
           "messages": messages, "unclassified_stderr_lines": sum(not any(p.lower() in line.lower() for p in PHRASES) for line in lines if line.strip())}
    return bytes(output), row


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise Blocked("metadata_redirect_forbidden")


def metadata_identity():
    result = {}
    for key, route in (("instance_id", "instance/id"), ("project_id", "project/project-id"),
                       ("project_number", "project/numeric-project-id"), ("zone", "instance/zone")):
        request = Request("http://169.254.169.254/computeMetadata/v1/" + route, headers={"Metadata-Flavor": "Google"})
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=3) as response:
            require(response.headers.get("Metadata-Flavor") == "Google", "metadata_origin_required")
            raw = response.read(1025)
        require(len(raw) <= 1024, "metadata_limit")
        result[key] = raw.decode("ascii").strip()
    result["zone"] = result["zone"].rsplit("/", 1)[-1]
    return result


class Operator:
    def __init__(self, value, source_sha, *, runner=native, identity_reader=metadata_identity, clock=time.monotonic, now=None):
        self.value, self.source_sha = value, source_sha
        self.runner, self.identity_reader, self.clock = runner, identity_reader, clock
        self.now = now or (lambda: datetime.now(timezone.utc))
        self.deadline = clock() + TOTAL_SECONDS
        self.journal_raw = None
        self.filesystem_uuid = None
        self.fstab_preimage = None
        self.expected_files = {}
        self.receipt = {"schema": "clipforge-db01-bootstrap-receipt-1", "status": "blocked", "exit_code": 2,
                        "operation_id": None, "approved_commit": None, "proposal_sha256": None, "operator_sha256": source_sha,
                        "disk_id": DISK_ID, "guest_boot_id": None, "disk_proof_sha256": None, "guest_read_receipt_sha256": None,
                        "guest_read_source_sha256": None, "phase": "input", "started_utc": utc(), "finished_utc": None,
                        "journal_path": None, "journal_sha256": None, "filesystem_uuid": None, "fstab_before_sha256": None,
                        "fstab_after_sha256": None, "effective_config_sha256": None,
                        "parent_permissions_before": None, "parent_permissions_after": None,
                        "checks": {key: False for key in CHECK_KEYS}, "native_operations": [], "error_code": None, "journal_error_code": None, "flags": dict(FLAGS)}

    def call(self, operation, argv, payload=None, timeout=120):
        remaining = self.deadline - self.clock()
        require(remaining > 0, "operation_time_budget")
        try:
            raw, row = self.runner(operation, argv, payload, min(timeout, remaining))
        except Blocked:
            raise
        except (OSError, ValueError, subprocess.SubprocessError):
            row = {"operation": operation, "exit_code": None, "status": "spawn_error", "duration_ms": 0,
                   "stdout_bytes": 0, "stderr_bytes": 0, "messages": [], "unclassified_stderr_lines": 0}
            self.receipt["native_operations"].append(row)
            self.save()
            raise NativeFailure("native_" + operation + "_spawn_error") from None
        require(isinstance(raw, bytes) and len(raw) <= OUTPUT_LIMIT and set(row) == OP_KEYS, "invalid_native_result")
        self.receipt["native_operations"].append(row)
        self.save()
        if row["status"] != "ok" or type(row["exit_code"]) is not int or row["exit_code"] != 0:
            raise NativeFailure("native_" + operation + "_" + row["status"])
        return raw

    def save(self):
        if self.journal_raw is not None:
            # The journal never hashes itself; receipt hash refers to its bytes.
            journal = {key: value for key, value in self.receipt.items() if key != "journal_sha256"}
            raw = canonical(journal) + b"\n"
            atomic_file(JOURNAL_DIR / "operation.json", raw, expected=self.journal_raw)
            self.journal_raw = raw
            self.receipt["journal_sha256"] = digest(raw)

    def phase(self, name):
        self.receipt["phase"] = name
        self.save()

    def journal(self):
        require(not os.path.lexists(JOURNAL_DIR), "prior_operation_blocks_retry")
        JOURNAL_DIR.mkdir(mode=0o700)
        _fsync_dir(ROOT)
        self.receipt["journal_path"] = str(JOURNAL_DIR / "operation.json")
        self.receipt["phase"] = "journal_created"
        journal = {key: value for key, value in self.receipt.items() if key != "journal_sha256"}
        raw = canonical(journal) + b"\n"
        atomic_file(JOURNAL_DIR / "operation.json", raw)
        self.journal_raw = raw
        self.receipt["journal_sha256"] = digest(raw)

    def identity(self):
        proof = self.value["disk_proof"]
        expected = {key: proof[key] for key in ("instance_id", "project_id", "project_number", "zone")}
        require(self.identity_reader() == expected, "guest_metadata_identity_mismatch")
        boot = read_bytes("/proc/sys/kernel/random/boot_id", 128).decode("ascii").strip()
        require(boot == proof["guest_boot_id"], "guest_boot_changed")
        self.receipt["checks"]["identity_verified"] = True

    def safety(self):
        postgres = postgres_account()
        for program in BINARIES:
            _trusted_binary(program)
        units = self.call("unit_files", ["/usr/bin/systemctl", "list-unit-files", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "postgresql*"])
        rows = [line.split() for line in units.decode("ascii").splitlines() if line.strip()]
        require(len(rows) == 2 and all(len(r) in {2, 3} for r in rows)
                and {r[0] for r in rows} == {"postgresql.service", "postgresql@.service"}
                and all(r[1] == "masked" for r in rows), "postgres_units_not_masked")
        state = self.call("unit_state", ["/usr/bin/systemctl", "show", "postgresql.service", "--no-pager", "--property=Type,ActiveState,SubState,LoadState,UnitFileState"])
        values = {}
        for line in state.decode("ascii").splitlines():
            require("=" in line, "invalid_postgres_unit_state")
            key, value = line.split("=", 1)
            require(key not in values, "invalid_postgres_unit_state")
            values[key] = value
        require(set(values) == {"Type", "LoadState", "ActiveState", "SubState", "UnitFileState"}
                and values["LoadState"] == "masked" and values["UnitFileState"] == "masked"
                and values["ActiveState"] == "inactive" and values["SubState"] == "dead"
                and values["Type"] in {"", "oneshot", "forking", "simple", "notify", "exec"}, "postgres_unit_active_or_unknown")
        names = self.call("processes", ["/usr/bin/ps", "-eo", "comm="]).decode("ascii").split()
        require(names and not any(name.lower().startswith(("postgres", "postmaster")) or name.lower() in {"pg_ctl", "pg_ctlcluster", "initdb", "pg_createcluster"} for name in names), "postgres_process_present")
        tcp = self.call("tcp", ["/usr/bin/ss", "--no-header", "--listening", "--tcp", "--numeric"])
        for line in tcp.decode("ascii").splitlines():
            parts = line.split()
            require(len(parts) >= 5 and parts[0] == "LISTEN" and ":" in parts[3]
                    and parts[3].rsplit(":", 1)[1].isdigit(), "invalid_socket_query")
            require(parts[3].rsplit(":", 1)[1] != "5432", "postgres_listener_present")
        unix = self.call("unix", ["/usr/bin/ss", "--no-header", "--listening", "--unix", "--numeric"])
        for line in unix.decode("ascii").splitlines():
            parts = line.split()
            require(len(parts) >= 5 and parts[0] in {"u_str", "u_dgr", "u_seq"}
                    and parts[1] in {"LISTEN", "UNCONN"}, "invalid_unix_socket_query")
        require(b".s.PGSQL.5432" not in unix, "postgres_unix_listener_present")
        require(not self.call("clusters", ["/usr/bin/pg_lsclusters", "--no-header"]).strip(), "existing_cluster_blocks_initialization")
        packages = self.call("packages", ["/usr/bin/dpkg-query", "--show", "--showformat=" + "$" + "{binary:Package}\t" + "$" + "{Version}\t" + "$" + "{db:Status-Status}\n", "postgresql-17", "postgresql-client-17"])
        require(sorted(line.split("\t") for line in packages.decode("ascii").splitlines()) == [["postgresql-17", "17.12-0+deb13u1", "installed"], ["postgresql-client-17", "17.12-0+deb13u1", "installed"]], "postgres_package_version_mismatch")
        require_utf8_locale(self.call("locale", ["/usr/bin/locale", "-a"]))
        for path in (Path("/etc/postgresql"), Path("/var/lib/postgresql")):
            if os.path.lexists(path):
                info = path.lstat()
                require(stat.S_ISDIR(info.st_mode) and info.st_uid in {0, postgres.pw_uid}
                        and not info.st_mode & 0o022 and not any(path.iterdir()), "existing_postgres_files")
        _parents(ROOT)
        info = ROOT.lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and info.st_gid == 0 and stat.S_IMODE(info.st_mode) == 0o700, "unsafe_bootstrap_root")
        require(not os.path.lexists(MOUNT) and not os.path.lexists(CONFIG) and not os.path.lexists(JOURNAL_DIR), "prior_installation_or_operation")
        require({path.name for path in ROOT.iterdir()} == {"package-provenance.txt"}, "unexpected_bootstrap_root_files")
        _regular(ROOT / "package-provenance.txt")

    def fstab_preflight(self):
        raw = read_bytes(FSTAB)
        require(b"\x00" not in raw, "invalid_fstab")
        for line in raw.decode("utf-8").splitlines():
            fields = line.split()
            require(not fields or fields[0].startswith("#") or len(fields) >= 2 and fields[1] != str(MOUNT)
                    and fields[0] != DEVICE, "fstab_target_already_present")
        self.fstab_preimage = raw

    def disk(self):
        proof = self.value["disk_proof"]
        require(0 <= (self.now() - instant(proof["observed_utc"])).total_seconds() <= 300, "disk_proof_expired_or_future")
        for parent in (Path("/dev"), Path("/dev/disk"), Path("/dev/disk/by-id")):
            info = parent.lstat()
            require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "unsafe_device_parent")
        link = Path(DEVICE).lstat()
        require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0, "unsafe_by_id_link")
        info = Path(DEVICE).stat()
        require(stat.S_ISBLK(info.st_mode), "by_id_not_block_device")
        number = str(os.major(info.st_rdev)) + ":" + str(os.minor(info.st_rdev))
        require(number == proof["guest_major_minor"], "device_major_minor_changed")
        kernel = Path("/sys/dev/block") / number
        def meta(path, cap):
            with path.open("rb") as stream:
                raw = stream.read(cap + 1)
            require(len(raw) <= cap, "sysfs_metadata_limit")
            return raw.decode("ascii").strip()
        sectors = meta(kernel / "size", 32)
        try:
            serial = meta(kernel / "device/serial", 128)
        except FileNotFoundError:
            serial = None
        require(sectors.isdigit() and int(sectors) * 512 == SIZE_BYTES, "device_serial_or_size_changed")
        with os.scandir(kernel / "holders") as entries:
            require(next(entries, None) is None, "device_has_holders")
        mounts = json.loads(self.call("mounts", ["/usr/bin/findmnt", "--json", "--output", "TARGET,MAJ:MIN"]))
        flattened = []
        def visit(rows, depth=0):
            require(isinstance(rows, list) and depth < 16, "invalid_mount_metadata")
            for row in rows:
                require(isinstance(row, dict) and len(flattened) < 512 and isinstance(row.get("target"), str)
                        and isinstance(row.get("maj:min"), str) and re.fullmatch(r"[0-9]+:[0-9]+", row["maj:min"]), "invalid_mount_metadata")
                flattened.append(row)
                visit(row.get("children", []), depth + 1)
        visit(mounts.get("filesystems"))
        roots = [row for row in flattened if row["target"] == "/"]
        require(len(roots) == 1 and all(row["maj:min"] != number and row["target"] != str(MOUNT) for row in flattened), "device_mounted_or_root_unknown")
        root_path = os.path.realpath("/sys/dev/block/" + roots[0]["maj:min"])
        target_path = os.path.realpath(kernel)
        require(root_path != target_path and not root_path.startswith(target_path + "/"), "root_disk_forbidden")
        block = json.loads(self.call("lsblk", ["/usr/bin/lsblk", "--json", "--bytes", "--output", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MAJ:MIN,SERIAL", DEVICE]))
        udev = {}
        for line in self.call("udev", ["/usr/bin/udevadm", "info", "--query=property", "--name", DEVICE]).decode("ascii").splitlines():
            require("=" in line, "invalid_udev_metadata")
            key, item = line.split("=", 1)
            require(key not in udev, "duplicate_udev_property")
            udev[key] = item
        signatures = json.loads(self.call("wipefs", ["/usr/sbin/wipefs", "--json", "--no-act", DEVICE]))
        require(set(signatures) == {"signatures"}, "invalid_signature_query")
        blank_disk_contract(DISK_ID, self.value["confirmation"], signatures["signatures"], block)
        row = block["blockdevices"][0]
        require(type(row.get("size")) is int and row["size"] == SIZE_BYTES and row.get("maj:min") == number
                and row.get("kname") == Path(os.path.realpath(DEVICE)).name, "block_metadata_identity_mismatch")
        observed = [item for item in (serial, row.get("serial"), udev.get("ID_SERIAL_SHORT")) if item is not None and item != ""]
        require(observed and all(isinstance(item, str) and item == proof["guest_serial"] for item in observed), "device_serial_or_size_changed")
        current = Path(DEVICE).stat()
        require(stat.S_ISBLK(current.st_mode) and current.st_rdev == info.st_rdev, "device_changed_during_read")
        self.receipt["checks"]["disk_blank_verified"] = True

    def tls(self):
        secrets = self.value["secrets"]
        with tempfile.TemporaryDirectory(prefix="db01-tls-", dir=ROOT) as directory:
            os.chmod(directory, 0o700)
            root = Path(directory)
            for name, key in (("server.crt", "server_cert"), ("server.key", "server_key"), ("root.crt", "ca_cert")):
                atomic_file(root / name, secrets[key].encode("ascii"))
            self.call("tls_chain", ["/usr/bin/openssl", "verify", "-purpose", "sslserver", "-CAfile", str(root / "root.crt"), str(root / "server.crt")])
            for operation, name in (("tls_leaf_lifetime", "server.crt"), ("tls_ca_lifetime", "root.crt")):
                self.call(operation, ["/usr/bin/openssl", "x509", "-in", str(root / name), "-noout", "-checkend", str(MIN_TLS_SECONDS)])
            self.call("tls_ip", ["/usr/bin/openssl", "x509", "-in", str(root / "server.crt"), "-noout", "-checkip", "10.80.1.2"])
            cert = self.call("tls_cert_public", ["/usr/bin/openssl", "x509", "-in", str(root / "server.crt"), "-pubkey", "-noout"])
            key = self.call("tls_key_public", ["/usr/bin/openssl", "pkey", "-in", str(root / "server.key"), "-pubout"])
            require(cert == key and cert, "tls_key_pair_mismatch")
        self.receipt["checks"]["tls_inputs_verified"] = True

    def mount(self):
        self.identity()
        self.disk()
        require(self.fstab_preimage is not None and read_bytes(FSTAB) == self.fstab_preimage, "fstab_changed_before_format")
        atomic_file(JOURNAL_DIR / "fstab.before", self.fstab_preimage)
        self.receipt["fstab_before_sha256"] = digest(self.fstab_preimage)
        self.phase("mkfs_intent")
        self.call("mkfs", ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", DEVICE])
        self.phase("mkfs_completed")
        uuid = self.call("filesystem_uuid", ["/usr/sbin/blkid", "-s", "UUID", "-o", "value", DEVICE]).decode("ascii").strip()
        require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", uuid), "invalid_filesystem_uuid")
        self.filesystem_uuid = uuid
        self.receipt["filesystem_uuid"] = uuid
        before = read_bytes(FSTAB)
        require(before == self.fstab_preimage, "fstab_changed_after_format")
        for line in before.decode("utf-8").splitlines():
            fields = line.split()
            require(not fields or fields[0].startswith("#") or len(fields) >= 2 and fields[1] != str(MOUNT)
                    and fields[0] not in {DEVICE, "UUID=" + uuid}, "fstab_target_already_present")
        line = "UUID=" + uuid + " " + str(MOUNT) + " ext4 defaults,nodev,nosuid,noexec 0 2\n"
        after = before + (b"" if before.endswith(b"\n") else b"\n") + line.encode("ascii")
        self.receipt.update(fstab_before_sha256=digest(before), fstab_after_sha256=digest(after))
        self.phase("fstab_intent")
        info = FSTAB.lstat()
        atomic_file(FSTAB, after, expected=before, uid=info.st_uid, gid=info.st_gid, mode=stat.S_IMODE(info.st_mode))
        self.phase("fstab_completed")
        self.phase("mount_intent")
        require(not os.path.lexists(MOUNT), "mountpoint_appeared")
        MOUNT.mkdir(mode=0o700)
        _fsync_dir(ROOT)
        self.call("mount", ["/usr/bin/mount", str(MOUNT)])
        self.verify_mount()
        self.phase("mount_completed")

    def verify_mount(self):
        data = json.loads(self.call("mounted", ["/usr/bin/findmnt", "--json", "--target", str(MOUNT), "--output", "UUID,SOURCE,TARGET,FSTYPE,OPTIONS,MAJ:MIN"]))
        rows = data.get("filesystems", [])
        require(len(rows) == 1, "mount_not_unique")
        row = rows[0]
        options = set(row.get("options", "").split(","))
        require(row.get("uuid") == self.filesystem_uuid and row.get("target") == str(MOUNT)
                and row.get("fstype") == "ext4" and row.get("maj:min") == self.value["disk_proof"]["guest_major_minor"]
                and {"rw", "nodev", "nosuid", "noexec"} <= options and "ro" not in options, "mounted_device_or_options_mismatch")
        source = row.get("source", "")
        require(isinstance(source, str) and source.startswith("/dev/")
                and Path(source).stat().st_rdev == Path(DEVICE).stat().st_rdev, "mounted_source_mismatch")
        self.receipt["checks"]["mount_verified"] = True

    def configure(self):
        postgres = postgres_account()
        before = ROOT.lstat()
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == 0 and before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == 0o700, "bootstrap_parent_changed_before_traversal")
        self.receipt["parent_permissions_before"] = {"uid": 0, "gid": 0, "mode": "0700"}
        self.phase("root_permissions_intent")
        os.chown(ROOT, 0, postgres.pw_gid)
        os.chmod(ROOT, 0o710)
        _fsync_dir(ROOT)
        self.receipt["parent_permissions_after"] = parent_permissions(ROOT.lstat(), postgres.pw_gid)
        self.receipt["checks"]["parent_traversal_verified"] = True
        self.phase("root_permissions_configured")
        self.phase("cluster_intent")
        self.verify_mount()
        os.chown(MOUNT, postgres.pw_uid, postgres.pw_gid)
        os.chmod(MOUNT, 0o700)
        self.call("cluster_create", ["/usr/bin/pg_createcluster", "17", "main", "--datadir", str(MOUNT / "pgdata"), "--start-conf=manual", "--encoding=UTF8", "--locale=C.UTF-8"])
        owners = (0, postgres.pw_uid)
        for name, key in (("server.crt", "server_cert"), ("server.key", "server_key"), ("root.crt", "ca_cert")):
            atomic_file(CONFIG / name, self.value["secrets"][key].encode("ascii"), uid=postgres.pw_uid, gid=postgres.pw_gid, owners=owners)
        settings = ("\nlisten_addresses='10.80.1.2'\nport=5432\nssl=on\nssl_cert_file='/etc/postgresql/17/main/server.crt'\n"
                    "ssl_key_file='/etc/postgresql/17/main/server.key'\nssl_ca_file='/etc/postgresql/17/main/root.crt'\n"
                    "ssl_min_protocol_version='TLSv1.2'\npassword_encryption='scram-sha-256'\n")
        path = CONFIG / "postgresql.conf"
        original = read_bytes(path, owners=owners)
        atomic_file(path, original + settings.encode(), expected=original, uid=postgres.pw_uid, gid=postgres.pw_gid, mode=0o600, owners=owners)
        hba = ("local all postgres peer\nhostssl clipforge clipforge_app 10.80.0.0/26 scram-sha-256\n"
               "hostssl clipforge clipforge_migrator 10.80.0.0/26 scram-sha-256\n").encode()
        path = CONFIG / "pg_hba.conf"
        atomic_file(path, hba, expected=read_bytes(path, owners=owners), uid=postgres.pw_uid, gid=postgres.pw_gid, mode=0o600, owners=owners)
        self.expected_files = {CONFIG / "postgresql.conf": original + settings.encode(), CONFIG / "pg_hba.conf": hba}
        self.expected_files.update({CONFIG / name: self.value["secrets"][key].encode("ascii")
                                   for name, key in (("server.crt", "server_cert"), ("server.key", "server_key"), ("root.crt", "ca_cert"))})
        self.receipt["effective_config_sha256"] = digest(canonical({"postgresql_conf": digest(original + settings.encode()), "pg_hba_conf": digest(hba)}))
        self.phase("cluster_configured")
        self.phase("service_start_intent")
        self.call("unmask", ["/usr/bin/systemctl", "unmask", "postgresql.service", "postgresql@.service"])
        self.call("start", ["/usr/bin/systemctl", "start", "postgresql@17-main.service"])
        self.phase("service_started")

    def sql(self, operation, database, statement):
        return self.call(operation, ["/usr/sbin/runuser", "-u", "postgres", "--", "/usr/lib/postgresql/17/bin/psql", "-X", "-qAt", "--set=ON_ERROR_STOP=1", "--dbname=" + database], statement.encode("utf-8"))

    def roles(self):
        self.phase("roles_intent")
        app, migrate = scram(self.value["secrets"]["app_password"]), scram(self.value["secrets"]["migrator_password"])
        self.sql("sql_roles", "postgres", "SET log_statement='none'; SET log_min_error_statement='panic'; BEGIN; "
                 "CREATE ROLE clipforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + app + "'; "
                 "CREATE ROLE clipforge_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '" + migrate + "'; COMMIT;")
        self.phase("roles_created")
        self.phase("database_intent")
        self.sql("sql_database", "postgres", "CREATE DATABASE clipforge OWNER clipforge_migrator;")
        self.phase("database_created")
        self.phase("grants_intent")
        self.sql("sql_grants", "clipforge", "BEGIN; REVOKE ALL ON DATABASE clipforge FROM PUBLIC; GRANT CONNECT ON DATABASE clipforge TO clipforge_app; "
                 "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO clipforge_app; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO clipforge_app; "
                 "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO clipforge_app; COMMIT;")
        self.phase("grants_completed")

    def postchecks(self):
        self.phase("postchecks")
        self.verify_mount()
        config = json.loads(self.sql("sql_config", "clipforge", "SELECT json_build_object('version',current_setting('server_version_num'),'data_directory',current_setting('data_directory'),"
                "'listen',current_setting('listen_addresses'),'port',current_setting('port'),'ssl',current_setting('ssl'),'ssl_min',current_setting('ssl_min_protocol_version'),"
                "'password_encryption',current_setting('password_encryption'),'cert',current_setting('ssl_cert_file'),'key',current_setting('ssl_key_file'),'ca',current_setting('ssl_ca_file'),"
                "'encoding',current_setting('server_encoding'),'lc_collate',(SELECT datcollate FROM pg_database WHERE datname=current_database()),"
                "'lc_ctype',(SELECT datctype FROM pg_database WHERE datname=current_database()),"
                "'config_errors',(SELECT count(*) FROM pg_file_settings WHERE error IS NOT NULL),'hba_errors',(SELECT count(*) FROM pg_hba_file_rules WHERE error IS NOT NULL));"))
        require(canonical(config) == canonical({"version": "170012", "data_directory": str(MOUNT / "pgdata"), "listen": "10.80.1.2", "port": "5432", "ssl": "on", "ssl_min": "TLSv1.2",
                           "password_encryption": "scram-sha-256", "cert": str(CONFIG / "server.crt"), "key": str(CONFIG / "server.key"), "ca": str(CONFIG / "root.crt"),
                           "encoding": "UTF8", "lc_collate": "C.UTF-8", "lc_ctype": "C.UTF-8", "config_errors": 0, "hba_errors": 0}), "effective_postgres_configuration_mismatch")
        postgres = postgres_account()
        require(parent_permissions(ROOT.lstat(), postgres.pw_gid) == self.receipt["parent_permissions_after"], "postgres_parent_changed")
        require(self.expected_files and all(read_bytes(path, owners=(0, postgres.pw_uid)) == raw
                for path, raw in self.expected_files.items()), "postgres_config_files_changed")
        self.receipt["checks"]["configuration_verified"] = True
        roles = json.loads(self.sql("sql_role_check", "clipforge", "SELECT json_build_object('roles',(SELECT json_agg(json_build_object('name',rolname,'login',rolcanlogin,'super',rolsuper,'createdb',rolcreatedb,'createrole',rolcreaterole,'replication',rolreplication,'bypassrls',rolbypassrls,'scram',rolpassword LIKE 'SCRAM-SHA-256$%') ORDER BY rolname) FROM pg_authid WHERE rolname IN ('clipforge_app','clipforge_migrator')),"
                "'owner',(SELECT pg_get_userbyid(datdba) FROM pg_database WHERE datname='clipforge'),'app_connect',has_database_privilege('clipforge_app','clipforge','CONNECT'),'app_db_create',has_database_privilege('clipforge_app','clipforge','CREATE'),"
                "'app_temp',has_database_privilege('clipforge_app','clipforge','TEMP'),'app_schema_use',has_schema_privilege('clipforge_app','public','USAGE'),'app_schema_create',has_schema_privilege('clipforge_app','public','CREATE'),"
                "'migrator_schema_create',has_schema_privilege('clipforge_migrator','public','CREATE'),'memberships',(SELECT count(*) FROM pg_auth_members WHERE member IN (SELECT oid FROM pg_roles WHERE rolname IN ('clipforge_app','clipforge_migrator'))),"
                "'defaults',(SELECT json_agg(json_build_object('kind',kind,'privileges',privileges) ORDER BY kind) FROM (SELECT d.defaclobjtype::text AS kind,array_agg(a.privilege_type ORDER BY a.privilege_type) AS privileges FROM pg_default_acl d CROSS JOIN LATERAL aclexplode(d.defaclacl) a WHERE d.defaclrole='clipforge_migrator'::regrole AND d.defaclnamespace='public'::regnamespace AND a.grantee='clipforge_app'::regrole GROUP BY d.defaclobjtype) q));"))
        expected_roles = [{"name": name, "login": True, "super": False, "createdb": False, "createrole": False, "replication": False, "bypassrls": False, "scram": True} for name in ("clipforge_app", "clipforge_migrator")]
        require(canonical(roles) == canonical({"roles": expected_roles, "owner": "clipforge_migrator", "app_connect": True, "app_db_create": False, "app_temp": False, "app_schema_use": True,
                          "app_schema_create": False, "migrator_schema_create": True, "memberships": 0,
                          "defaults": [{"kind": "S", "privileges": ["SELECT", "USAGE"]}, {"kind": "r", "privileges": ["DELETE", "INSERT", "SELECT", "UPDATE"]}]}), "database_role_boundaries_mismatch")
        self.receipt["checks"]["roles_verified"] = True
        require(self.call("service_active", ["/usr/bin/systemctl", "is-active", "postgresql@17-main.service"]).strip() == b"active", "cluster_not_active")
        rows = self.call("clusters", ["/usr/bin/pg_lsclusters", "--no-header"]).decode("ascii").splitlines()
        require(len(rows) == 1 and rows[0].split()[:6] == ["17", "main", "5432", "online", "postgres", str(MOUNT / "pgdata")], "cluster_identity_mismatch")
        self.call("tls_handshake", ["/usr/bin/openssl", "s_client", "-brief", "-starttls", "postgres", "-connect", "10.80.1.2:5432", "-CAfile", str(CONFIG / "root.crt"), "-verify_return_error", "-verify_ip", "10.80.1.2", "-tls1_2"], b"", timeout=15)
        self.receipt["checks"]["local_tls_handshake_verified"] = True
        self.phase("enable_intent")
        path = CONFIG / "start.conf"
        atomic_file(path, b"auto\n", expected=read_bytes(path, owners=(0, postgres.pw_uid)), uid=postgres.pw_uid, gid=postgres.pw_gid, mode=0o600, owners=(0, postgres.pw_uid))
        self.call("enable", ["/usr/bin/systemctl", "enable", "postgresql.service"])
        require(self.call("enabled", ["/usr/bin/systemctl", "is-enabled", "postgresql.service"]).strip() == b"enabled", "boot_service_not_enabled")
        self.receipt["checks"]["boot_persistence_configured"] = True
        self.phase("guest_verified")

    def run(self):
        try:
            require(sys.platform == "linux" and hasattr(os, "geteuid") and os.geteuid() == 0, "linux_root_required")
            validate_input(self.value, self.source_sha, now=self.now())
            self.receipt.update({key: self.value[key] for key in ("operation_id", "approved_commit", "proposal_sha256", "operator_sha256")})
            self.receipt["guest_boot_id"] = self.value["disk_proof"]["guest_boot_id"]
            self.receipt["disk_proof_sha256"] = digest(canonical(self.value["disk_proof"]))
            for key in ("guest_read_receipt_sha256", "guest_read_source_sha256"):
                self.receipt[key] = self.value["disk_proof"][key]
            self.phase("preflight")
            self.identity()
            self.safety()
            self.disk()
            self.tls()
            self.fstab_preflight()
            self.identity()
            self.disk()
            self.journal()
            self.mount()
            self.configure()
            self.roles()
            self.postchecks()
            self.receipt.update(status="configured_guest_verified_external_acceptance_pending", exit_code=0)
        except BaseException as error:
            partial = self.journal_raw is not None or os.path.lexists(JOURNAL_DIR)
            self.receipt.update(status="partial_preserved" if partial else "blocked", exit_code=3 if partial else 2,
                                error_code=str(error) if isinstance(error, Blocked) else "guest_operation_failed_details_withheld")
        finally:
            self.receipt["finished_utc"] = utc()
            try:
                self.save()
            except (OSError, ValueError):
                self.receipt.update(status="partial_preserved", exit_code=3, journal_error_code="journal_update_unconfirmed")
                if self.receipt["error_code"] is None:
                    self.receipt["error_code"] = "journal_update_unconfirmed"
        validate_receipt(self.receipt)
        return self.receipt


def validate_receipt(value):
    fields = {"schema", "status", "exit_code", "operation_id", "approved_commit", "proposal_sha256", "operator_sha256", "disk_id", "guest_boot_id", "disk_proof_sha256", "guest_read_receipt_sha256", "guest_read_source_sha256", "phase", "started_utc", "finished_utc", "journal_path", "journal_sha256", "filesystem_uuid", "fstab_before_sha256", "fstab_after_sha256", "effective_config_sha256", "parent_permissions_before", "parent_permissions_after", "checks", "native_operations", "error_code", "journal_error_code", "flags"}
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == "clipforge-db01-bootstrap-receipt-1", "invalid_guest_receipt")
    statuses = {"configured_guest_verified_external_acceptance_pending": 0, "blocked": 2, "partial_preserved": 3}
    require(value["status"] in statuses and type(value["exit_code"]) is int and value["exit_code"] == statuses[value["status"]]
            and value["disk_id"] == DISK_ID and value["flags"] == FLAGS
            and all(type(item) is bool for item in value["flags"].values()), "invalid_guest_receipt_status")
    require(isinstance(value["checks"], dict) and set(value["checks"]) == CHECK_KEYS and all(type(item) is bool for item in value["checks"].values()), "invalid_guest_receipt_checks")
    require(isinstance(value["native_operations"], list) and len(value["native_operations"]) <= 100, "invalid_guest_receipt_native_operations")
    for row in value["native_operations"]:
        require(isinstance(row, dict) and set(row) == OP_KEYS and row["operation"] in OPS
                and row["status"] in {"ok", "nonzero_exit", "timeout", "stdout_limit", "stderr_limit", "spawn_error"}
                and (row["exit_code"] is None or type(row["exit_code"]) is int)
                and all(type(row[key]) is int and row[key] >= 0 for key in ("duration_ms", "stdout_bytes", "stderr_bytes", "unclassified_stderr_lines"))
                and row["stdout_bytes"] <= OUTPUT_LIMIT and row["stderr_bytes"] <= ERROR_LIMIT
                and isinstance(row["messages"], list) and len(row["messages"]) <= len(PHRASES)
                and all(item in PHRASES for item in row["messages"]), "invalid_guest_native_receipt")
        require((row["status"] != "ok" or type(row["exit_code"]) is int and row["exit_code"] == 0)
                and (row["status"] != "nonzero_exit" or type(row["exit_code"]) is int and row["exit_code"] != 0)
                and (row["status"] != "spawn_error" or row["exit_code"] is None), "inconsistent_native_exit")
    for key, width in (("operation_id", 32), ("approved_commit", 40), ("proposal_sha256", 64), ("operator_sha256", 64), ("disk_proof_sha256", 64), ("guest_read_receipt_sha256", 64), ("guest_read_source_sha256", 64), ("journal_sha256", 64), ("fstab_before_sha256", 64), ("fstab_after_sha256", 64), ("effective_config_sha256", 64)):
        require(value[key] is None or isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{" + str(width) + "}", value[key]), "invalid_guest_receipt_digest")
    for key in ("guest_boot_id", "filesystem_uuid"):
        require(value[key] is None or isinstance(value[key], str) and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value[key]), "invalid_guest_receipt_uuid")
    require(isinstance(value["phase"], str) and re.fullmatch(r"[a-z_]{1,40}", value["phase"])
            and (value["error_code"] is None or isinstance(value["error_code"], str) and re.fullmatch(r"[a-z0-9_]{1,100}", value["error_code"]))
            and value["journal_path"] in {None, str(JOURNAL_DIR / "operation.json")}, "invalid_guest_receipt_metadata")
    require(instant(value["started_utc"]) <= instant(value["finished_utc"]), "invalid_guest_receipt_time")
    require(value["journal_error_code"] in {None, "journal_update_unconfirmed"}, "invalid_guest_journal_error")
    require(value["parent_permissions_before"] is None or value["parent_permissions_before"] == {"uid": 0, "gid": 0, "mode": "0700"}
            and type(value["parent_permissions_before"]["uid"]) is int and type(value["parent_permissions_before"]["gid"]) is int, "invalid_parent_preimage")
    if value["parent_permissions_after"] is not None:
        row = value["parent_permissions_after"]
        require(isinstance(row, dict) and set(row) == {"uid", "gid", "mode"} and type(row["uid"]) is int and row["uid"] == 0
                and type(row["gid"]) is int and row["gid"] > 0 and row["mode"] == "0710", "invalid_parent_successor")
    if value["exit_code"] == 0:
        require(all(value["checks"].values()) and value["phase"] == "guest_verified" and value["error_code"] is None and value["journal_error_code"] is None
                and all(value[key] is not None for key in ("operation_id", "approved_commit", "proposal_sha256", "operator_sha256", "guest_boot_id", "disk_proof_sha256", "guest_read_receipt_sha256", "guest_read_source_sha256", "journal_path", "filesystem_uuid", "journal_sha256", "fstab_before_sha256", "fstab_after_sha256", "effective_config_sha256", "parent_permissions_before", "parent_permissions_after"))
                and [row["operation"] for row in value["native_operations"]] == SUCCESS_OPERATIONS
                and all(row["status"] == "ok" and type(row["exit_code"]) is int and row["exit_code"] == 0 for row in value["native_operations"]), "incomplete_guest_success_receipt")
    require(len(canonical(value)) + 1 <= OUTPUT_LIMIT, "guest_receipt_limit")
    return value


def initialize(value, disk_id=None, confirmation=None, *, source_sha=None, **kwargs):
    if disk_id is not None:
        require(disk_id == DISK_ID and confirmation == "INITIALIZE_NEW_DISK_" + DISK_ID, "explicit_disk_confirmation_required")
    source = source_sha or globals().get("DB01_OPERATOR_SHA256")
    require(isinstance(source, str) and re.fullmatch(r"[a-f0-9]{64}", source), "verified_public_source_required")
    return Operator(value, source, **kwargs).run()


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    source = globals().get("DB01_OPERATOR_SHA256")
    if source is None and "__file__" in globals():
        source = digest(Path(__file__).read_bytes())
    operator = Operator({}, source)
    previous_alarm = None
    previous_signals = {}
    try:
        require(not args, "arguments_forbidden")
        if sys.platform == "linux":
            def expired(signum, frame):
                raise Blocked("operation_time_budget")
            previous_alarm = signal.signal(signal.SIGALRM, expired)
            signal.alarm(TOTAL_SECONDS)
            def interrupted(signum, frame):
                raise Blocked("operator_interrupted")
            for number in (signal.SIGTERM, signal.SIGINT):
                previous_signals[number] = signal.signal(number, interrupted)
        operator.value = decode(sys.stdin.buffer.read(INPUT_LIMIT + 1))
        receipt = operator.run()
    except BaseException as error:
        operator.receipt.update(error_code=str(error) if isinstance(error, Blocked) else "guest_input_failed_details_withheld", finished_utc=utc())
        receipt = validate_receipt(operator.receipt)
    finally:
        if previous_alarm is not None:
            signal.alarm(0)
            signal.signal(signal.SIGALRM, previous_alarm)
        for number, previous in previous_signals.items():
            signal.signal(number, previous)
    sys.stdout.buffer.write(canonical(receipt) + b"\n")
    return receipt["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
