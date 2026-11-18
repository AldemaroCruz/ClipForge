"""Bounded, fixed read-only guest inventory; never initializes PostgreSQL.

Execute this standalone file with Python 3 on Linux. No arguments, environment
values, SQL, package changes or database-file reads are supported. stdout is a
closed JSON report. Bounded command stderr belongs only to the caller's private
stderr channel, and is represented in JSON by lengths/hashes, never its text.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import os
import re
import selectors
import shlex
import signal
import stat
import subprocess
import sys
import time


SCHEMA = "clipforge-int-guest-inventory-1"
TOTAL_SECONDS = 120
COMMAND_SECONDS = 15
PACKAGE_LIMIT = 1024 * 1024
TOTAL_OUTPUT_LIMIT = 2 * 1024 * 1024
STDERR_LIMIT = 8192
COMMANDS = {
    "unit_files": ("/usr/bin/systemctl", "list-unit-files", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "postgresql*"),
    "unit_state": ("/usr/bin/systemctl", "show", "postgresql.service", "--no-pager", "--property=Type,ActiveState,SubState,LoadState,UnitFileState"),
    "units": ("/usr/bin/systemctl", "list-units", "--all", "--type=service", "--no-legend", "--no-pager", "--plain", "--full", "postgresql*"),
    "processes": ("/usr/bin/ps", "-eo", "comm="),
    "tcp": ("/usr/bin/ss", "--no-header", "--listening", "--tcp", "--numeric"),
    "unix": ("/usr/bin/ss", "--no-header", "--listening", "--unix", "--numeric"),
    "clusters": ("/usr/bin/pg_lsclusters", "--no-header"),
    "kernel": ("/usr/bin/uname", "--kernel-release", "--machine"),
    "packages": ("/usr/bin/dpkg-query", "--show", "--showformat=${binary:Package}\t${Version}\t${db:Status-Status}\t${Architecture}\n"),
    "blockdevices": ("/usr/bin/lsblk", "--json", "--bytes", "--output", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS"),
    "mounts": ("/usr/bin/findmnt", "--json", "--output", "TARGET,SOURCE,FSTYPE"),
}
SAFETY_COMMANDS = ("unit_files", "unit_state", "units", "processes", "tcp", "unix", "clusters")
INVENTORY_COMMANDS = ("kernel", "packages", "blockdevices", "mounts")
PATHS = ("/etc/postgresql", "/var/lib/postgresql", "/var/lib/clipforge-postgres")
OS_KEYS = frozenset(("ID", "NAME", "PRETTY_NAME", "VERSION_ID", "VERSION_CODENAME"))
PROCESS_STATUSES = frozenset(("ok", "nonzero_exit", "timeout", "stdout_limit", "stderr_limit", "spawn_error", "unsafe_binary", "budget_exhausted"))
DPKG_STATUSES = frozenset(("not-installed", "config-files", "half-installed", "unpacked", "half-configured", "triggers-awaited", "triggers-pending", "installed"))
REASONS = frozenset(("SAFE_AND_COMPLETE", "UNSUPPORTED_PLATFORM", "ARGUMENTS_FORBIDDEN", "QUERY_FAILED", "QUERY_INVALID", "POSTGRES_UNMASKED", "POSTGRES_ACTIVE", "POSTGRES_PROCESS", "TCP_5432_PRESENT", "UNIX_5432_PRESENT", "CLUSTER_PRESENT", "PATHS_UNSAFE", "TIME_BUDGET", "OS_RELEASE_INVALID", "INVENTORY_INVALID", "REPORT_LIMIT"))
ERROR_CODES = frozenset(name.upper() for name in PROCESS_STATUSES)
STDERR_PHRASES = ("Permission denied", "Operation not permitted", "No such file or directory", "Failed to connect to bus",
                  "Host is down", "Connection refused", "Connection timed out", "Access denied", "Unknown option",
                  "unrecognized option", "invalid option", "command not found", "could not be found",
                  "No packages found matching", "Failed to list unit files", "Failed to list units")
STDERR_PATTERN = re.compile("|".join(re.escape(phrase) for phrase in STDERR_PHRASES), re.IGNORECASE)
UNIT_PROPERTIES = {"Type": {"simple", "exec", "forking", "oneshot", "dbus", "notify", "notify-reload", "idle"},
                   "ActiveState": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
                   "SubState": {"dead", "running", "exited", "failed", "start", "start-pre", "start-post", "stop", "stop-sigterm", "stop-sigkill", "stop-post", "final-sigterm", "final-sigkill", "auto-restart", "cleaning", "condition", "reload", "reload-signal", "reload-notify", "stop-watchdog", "final-watchdog"},
                   "LoadState": {"loaded", "not-found", "bad-setting", "error", "merged", "masked"},
                   "UnitFileState": {"masked", "masked-runtime", "enabled", "enabled-runtime", "disabled", "static", "indirect", "generated", "transient", "bad", "linked", "linked-runtime", "alias"}}
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C", "SYSTEMD_COLORS": "0", "SYSTEMD_PAGER": "/bin/false", "PAGER": "/bin/false"}


class InventoryError(ValueError):
    """A fixed code only; no private command output or file content."""


def require(condition, code):
    if not condition:
        raise InventoryError(code)


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sanitized_stderr(raw):
    """Retain only real fixed diagnostic phrases; never paths, args or values."""
    messages, unclassified = [], 0
    for line in raw.decode("utf-8", errors="replace").splitlines():
        found = [match.group(0) for match in STDERR_PATTERN.finditer(line)]
        if line.strip() and not found:
            unclassified += 1
        for phrase in found:
            if phrase not in messages and len(messages) < 16:
                messages.append(phrase)
    return {"messages": messages, "unclassified_lines": unclassified}


@dataclass(frozen=True)
class CommandResult:
    exit_code: int | None
    stdout: bytes = b""
    stderr: bytes = b""
    duration_ms: int = 0
    status: str = "ok"
    error_code: str | None = None


def _trusted_regular(path):
    info = os.lstat(path)
    require(stat.S_ISREG(info.st_mode) and info.st_uid == 0
            and not info.st_mode & (stat.S_ISUID | stat.S_ISGID | 0o022), "UNTRUSTED_FILE")
    return info


def _safe_parents(path):
    parent = os.path.dirname(path)
    while parent:
        info = os.lstat(parent)
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "PATHS_UNSAFE")
        if parent == "/":
            break
        parent = os.path.dirname(parent)


def _kill(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=1)
    except subprocess.TimeoutExpired:
        pass


def run_fixed(key, *, timeout_seconds, stdout_limit, stderr_limit, deadline, clock):
    """Drain both pipes while running; limits never rely on unbounded capture."""
    started = clock()
    require(key in COMMANDS and 0 < stdout_limit <= TOTAL_OUTPUT_LIMIT and 0 <= stderr_limit <= STDERR_LIMIT, "COMMAND_CONTRACT")
    finish = min(deadline - 1, started + min(timeout_seconds, COMMAND_SECONDS))
    if finish <= started:
        return CommandResult(None, status="budget_exhausted", error_code="BUDGET_EXHAUSTED")
    try:
        _trusted_regular(COMMANDS[key][0])
    except (OSError, InventoryError):
        return CommandResult(None, status="unsafe_binary", error_code="UNSAFE_BINARY")
    try:
        process = subprocess.Popen(COMMANDS[key], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, env=ENVIRONMENT, start_new_session=True)
    except OSError:
        return CommandResult(None, status="spawn_error", error_code="SPAWN_ERROR")
    streams = selectors.DefaultSelector()
    out, err, failure = bytearray(), bytearray(), None
    for pipe, label in ((process.stdout, "stdout"), (process.stderr, "stderr")):
        os.set_blocking(pipe.fileno(), False)
        streams.register(pipe, selectors.EVENT_READ, label)
    try:
        while streams.get_map():
            remaining = finish - clock()
            if remaining <= 0:
                failure = "timeout"
                break
            for item, _event in streams.select(min(remaining, 0.25)):
                target, maximum = (out, stdout_limit) if item.data == "stdout" else (err, stderr_limit)
                try:
                    chunk = os.read(item.fileobj.fileno(), min(65536, maximum - len(target) + 1))
                except BlockingIOError:
                    continue
                if not chunk:
                    streams.unregister(item.fileobj)
                    continue
                available = maximum - len(target)
                target.extend(chunk[:available])
                if len(chunk) > available:
                    failure = item.data + "_limit"
                    break
            if failure:
                break
        if failure:
            _kill(process)
        else:
            try:
                process.wait(timeout=max(0.001, min(1, finish - clock())))
            except subprocess.TimeoutExpired:
                failure = "timeout"
                _kill(process)
    finally:
        streams.close()
        process.stdout.close()
        process.stderr.close()
        if process.poll() is None:
            _kill(process)
    status = failure or ("ok" if process.returncode == 0 else "nonzero_exit")
    return CommandResult(process.returncode, bytes(out), bytes(err), max(0, int((clock() - started) * 1000)),
                         status, None if status == "ok" else status.upper())


def _text(raw):
    value = raw.decode("utf-8", errors="strict")
    require(not any(ord(char) < 32 and char not in "\n\t\r" for char in value), "QUERY_INVALID")
    return value


def parse_unit_files(raw):
    rows = []
    for line in _text(raw).splitlines():
        parts = line.split()
        require(len(parts) in {2, 3} and parts[0] in {"postgresql.service", "postgresql@.service"}, "QUERY_INVALID")
        rows.append({"name": parts[0], "state": parts[1]})
    require(len(rows) == 2 and {row["name"] for row in rows} == {"postgresql.service", "postgresql@.service"}, "QUERY_INVALID")
    require(all(row["state"] == "masked" for row in rows), "POSTGRES_UNMASKED")
    return rows


def parse_units(raw):
    rows = []
    for line in _text(raw).splitlines():
        parts = line.split()
        require(len(parts) >= 4 and parts[0].startswith("postgresql"), "QUERY_INVALID")
        require(parts[0] == "postgresql.service" and parts[1] in {"loaded", "masked"}
                and parts[2] == "inactive" and parts[3] == "dead", "POSTGRES_ACTIVE")
        rows.append({"name": parts[0], "load": parts[1], "active": parts[2], "sub": parts[3]})
    require(len(rows) <= 1, "QUERY_INVALID")
    return rows


def parse_unit_state(raw):
    values = {}
    for line in _text(raw).splitlines():
        require("=" in line, "QUERY_INVALID")
        key, value = line.split("=", 1)
        require(key in UNIT_PROPERTIES and key not in values and value in UNIT_PROPERTIES[key], "QUERY_INVALID")
        values[key] = value
    require(set(values) == set(UNIT_PROPERTIES), "QUERY_INVALID")
    return values


def parse_processes(raw):
    names = [line.strip() for line in _text(raw).splitlines() if line.strip()]
    require(names and all(len(name) <= 64 and not any(char.isspace() for char in name) for name in names), "QUERY_INVALID")
    require(not any(name.lower().startswith(("postgres", "postmaster")) or name.lower() in
                    {"pg_ctl", "pg_ctlcluster", "pg_createcluster", "pg_dropcluster", "initdb"} for name in names), "POSTGRES_PROCESS")
    return 0


def parse_tcp(raw):
    for line in _text(raw).splitlines():
        parts = line.split()
        require(len(parts) >= 5 and parts[0] == "LISTEN" and parts[1].isdigit() and parts[2].isdigit()
                and ":" in parts[3] and parts[3].rsplit(":", 1)[1].isdigit(), "QUERY_INVALID")
        require(parts[3].rsplit(":", 1)[1] != "5432", "TCP_5432_PRESENT")
    return 0


def parse_unix(raw):
    text = _text(raw)
    require(not re.search(r"\.s\.PGSQL\.5432(?:\D|$)", text), "UNIX_5432_PRESENT")
    for line in text.splitlines():
        parts = line.split()
        require(len(parts) >= 6 and parts[0] in {"u_str", "u_dgr", "u_seq"}
                and parts[1] in {"LISTEN", "UNCONN"} and parts[2].isdigit() and parts[3].isdigit(), "QUERY_INVALID")
    return 0


def parse_clusters(raw):
    require(not _text(raw).strip(), "CLUSTER_PRESENT")
    return 0


def inspect_paths(*, deadline, clock):
    rows = []
    for path in PATHS:
        require(clock() < deadline, "TIME_BUDGET")
        _safe_parents(path)
        try:
            info = os.lstat(path)
        except FileNotFoundError:
            require(path != PATHS[-1], "PATHS_UNSAFE")
            rows.append({"path": path, "exists": False, "uid": None, "gid": None, "mode": None,
                         "entries_count": 0, "provenance_metadata_only": False, "known_shell_dotfiles": [],
                         "empty_version_dirs": [], "absent_version_dirs": ["17", "18"]})
            continue
        require(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode), "PATHS_UNSAFE")
        entries = []
        with os.scandir(path) as stream:
            for entry in stream:
                require(clock() < deadline and len(entries) < 16, "PATHS_UNSAFE")
                entries.append(entry)
        provenance, dotfiles, versions = False, [], []
        if path == PATHS[-1]:
            require({entry.name for entry in entries} == {"package-provenance.txt"}, "PATHS_UNSAFE")
            item = entries[0].stat(follow_symlinks=False)
            require(stat.S_ISREG(item.st_mode) and item.st_uid == 0 and not item.st_mode & 0o022
                    and 0 < item.st_size <= 65536, "PATHS_UNSAFE")
            provenance = True
        else:
            for entry in entries:
                require(clock() < deadline, "TIME_BUDGET")
                item = entry.stat(follow_symlinks=False)
                if entry.name in {"17", "18"}:
                    require(stat.S_ISDIR(item.st_mode), "PATHS_UNSAFE")
                    with os.scandir(entry.path) as children:
                        require(next(children, None) is None, "PATHS_UNSAFE")
                    versions.append(entry.name)
                elif path == "/var/lib/postgresql" and entry.name in {".bashrc", ".profile", ".bash_logout"}:
                    require(stat.S_ISREG(item.st_mode) and not item.st_mode & 0o022 and item.st_nlink == 1,
                            "PATHS_UNSAFE")
                    dotfiles.append(entry.name)
                else:
                    # Includes cluster names, PG_VERSION/base/global/pg_wal,
                    # unregistered data and unrelated user files. No content read.
                    raise InventoryError("PATHS_UNSAFE")
        rows.append({"path": path, "exists": True, "uid": info.st_uid, "gid": info.st_gid, "mode": oct(stat.S_IMODE(info.st_mode)),
                     "entries_count": len(entries), "provenance_metadata_only": provenance,
                     "known_shell_dotfiles": sorted(dotfiles), "empty_version_dirs": sorted(versions),
                     "absent_version_dirs": sorted({"17", "18"} - set(versions)) if path != PATHS[-1] else []})
    return rows


def parse_os_release(raw):
    values = {}
    for line in _text(raw).splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        require("=" in line, "OS_RELEASE_INVALID")
        key, value = line.split("=", 1)
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key), "OS_RELEASE_INVALID")
        parts = shlex.split(value, comments=False, posix=True)
        require(len(parts) == 1 and len(parts[0]) <= 256, "OS_RELEASE_INVALID")
        if key in OS_KEYS:
            require(key not in values, "OS_RELEASE_INVALID")
            values[key] = parts[0]
    require(values.get("ID") == "debian" and values.get("VERSION_CODENAME") == "trixie", "OS_RELEASE_INVALID")
    return values


def read_os_release(*, deadline, clock):
    require(clock() < deadline, "TIME_BUDGET")
    path = os.path.realpath("/etc/os-release")
    require(path in {"/etc/os-release", "/usr/lib/os-release"}, "OS_RELEASE_INVALID")
    _safe_parents(path)
    _trusted_regular(path)
    with open(path, "rb") as stream:
        raw = stream.read(65537)
    require(len(raw) <= 65536 and clock() < deadline, "OS_RELEASE_INVALID")
    return parse_os_release(raw)


def parse_packages(raw):
    rows, names = [], set()
    for line in _text(raw).splitlines():
        parts = line.split("\t")
        require(len(parts) == 4 and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", parts[0])
                and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", parts[1]) and parts[2] in DPKG_STATUSES
                and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", parts[3]) and parts[0] not in names, "INVENTORY_INVALID")
        names.add(parts[0]); rows.append(parts)
    require(rows and len(rows) <= 16384, "INVENTORY_INVALID")
    selected = {name: next((row for row in rows if row[0].split(":", 1)[0] == name), None)
                for name in ("postgresql-17", "postgresql-client-17", "postgresql-18", "postgresql-client-18")}
    return rows, selected


def _json(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            require(key not in value, "INVENTORY_INVALID")
            value[key] = item
        return value
    return json.loads(_text(raw), object_pairs_hook=pairs)


def parse_devices(raw):
    value = _json(raw)
    require(isinstance(value, dict) and set(value) == {"blockdevices"} and isinstance(value["blockdevices"], list)
            and value["blockdevices"], "INVENTORY_INVALID")
    count = 0
    def visit(row, depth=0):
        nonlocal count
        count += 1
        require(count <= 128 and depth <= 8 and isinstance(row, dict)
                and set(row) <= {"name", "kname", "type", "size", "fstype", "mountpoints", "children"}
                and {"name", "kname", "type", "size", "fstype", "mountpoints"} <= set(row), "INVENTORY_INVALID")
        require(all(isinstance(row[key], str) and re.fullmatch(r"[A-Za-z0-9_.:+-]{1,128}", row[key]) for key in ("name", "kname", "type"))
                and type(row["size"]) is int and row["size"] >= 0
                and (row["fstype"] is None or isinstance(row["fstype"], str) and re.fullmatch(r"[A-Za-z0-9_.+-]{1,64}", row["fstype"]))
                and isinstance(row["mountpoints"], list) and len(row["mountpoints"]) <= 16
                and all(item is None or isinstance(item, str) and len(item) <= 512 and not any(ord(char) < 32 for char in item) for item in row["mountpoints"]), "INVENTORY_INVALID")
        children = row.get("children", [])
        require(isinstance(children, list), "INVENTORY_INVALID")
        for child in children: visit(child, depth + 1)
    for row in value["blockdevices"]: visit(row)
    return value["blockdevices"]


def parse_mounts(raw):
    value = _json(raw)
    require(isinstance(value, dict) and set(value) == {"filesystems"} and isinstance(value["filesystems"], list)
            and value["filesystems"], "INVENTORY_INVALID")
    count = 0
    def visit(row, depth=0):
        nonlocal count
        count += 1
        require(count <= 512 and depth <= 16 and isinstance(row, dict)
                and set(row) <= {"target", "source", "fstype", "children"}
                and {"target", "source", "fstype"} <= set(row), "INVENTORY_INVALID")
        require(all(isinstance(row[key], str) and 0 < len(row[key]) <= 512 and not any(ord(char) < 32 for char in row[key])
                    for key in ("target", "source", "fstype")), "INVENTORY_INVALID")
        require("://" not in row["source"] and "@" not in row["source"] and not re.search(r"(?i)password|credential|token=|secret=", row["source"]), "INVENTORY_INVALID")
        require(isinstance(row.get("children", []), list), "INVENTORY_INVALID")
        for child in row.get("children", []): visit(child, depth + 1)
    for row in value["filesystems"]: visit(row)
    return value["filesystems"]


def collect(*, runner=None, metadata_reader=None, release_reader=None, clock=None, stderr_sink=None):
    clock = clock or time.monotonic
    runner, metadata_reader, release_reader = runner or run_fixed, metadata_reader or inspect_paths, release_reader or read_os_release
    started = clock(); deadline = started + TOTAL_SECONDS
    report = {"schema": SCHEMA, "status": "safety_stop", "exit_code": 2, "reason": "QUERY_FAILED",
              "safety": {"passed": False, "unit_files": None, "unit_state": None, "units": None, "postgres_processes": None, "tcp_5432_listeners": None,
                         "unix_5432_listeners": None, "clusters": None, "paths": None},
              "inventory": None, "commands": [], "timing": {"duration_ms": 0, "limit_seconds": TOTAL_SECONDS},
              "stderr": {"bytes": 0, "sha256": digest(b""), "truncated": False}}
    stderr, stdout_bytes = bytearray(), 0
    def finish(status, reason):
        report.update(status=status, exit_code={"safety_stop": 2, "inventory_incomplete": 3, "inventory_complete": 0}[status], reason=reason)
        report["timing"]["duration_ms"] = max(0, int((clock() - started) * 1000))
        report["stderr"].update(bytes=len(stderr), sha256=digest(stderr))
        if len(encoded(report)) + 1 > TOTAL_OUTPUT_LIMIT:
            report.update(status="inventory_incomplete" if report["safety"]["passed"] else "safety_stop",
                          exit_code=3 if report["safety"]["passed"] else 2, reason="REPORT_LIMIT", inventory=None)
        return report
    def query(key):
        nonlocal stdout_bytes
        remaining = TOTAL_OUTPUT_LIMIT - stdout_bytes
        require(remaining > 0 and clock() < deadline - 1, "TIME_BUDGET")
        stdout_limit = min(PACKAGE_LIMIT if key == "packages" else 262144, remaining)
        result = runner(key, timeout_seconds=COMMAND_SECONDS, stdout_limit=min(PACKAGE_LIMIT if key == "packages" else 262144, remaining),
                        stderr_limit=STDERR_LIMIT - len(stderr), deadline=deadline, clock=clock)
        require(isinstance(result, CommandResult) and result.status in PROCESS_STATUSES and isinstance(result.stdout, bytes)
                and isinstance(result.stderr, bytes) and (result.exit_code is None or type(result.exit_code) is int)
                and type(result.duration_ms) is int and result.duration_ms >= 0, "QUERY_INVALID")
        require(len(result.stdout) <= stdout_limit, "QUERY_INVALID")
        stdout_bytes += len(result.stdout)
        require(stdout_bytes <= TOTAL_OUTPUT_LIMIT and len(stderr) + len(result.stderr) <= STDERR_LIMIT, "QUERY_INVALID")
        stderr.extend(result.stderr)
        if stderr_sink is not None:
            stderr_sink.write(result.stderr); stderr_sink.flush()
        report["stderr"]["truncated"] |= result.status == "stderr_limit"
        report["commands"].append({"key": key, "exit_code": result.exit_code, "duration_ms": result.duration_ms,
                                   "status": result.status, "error_code": result.error_code, "stdout_bytes": len(result.stdout),
                                   "stdout_sha256": digest(result.stdout), "stderr_bytes": len(result.stderr), "stderr_sha256": digest(result.stderr),
                                   "stderr_diagnostic": sanitized_stderr(result.stderr)})
        require(clock() < deadline, "TIME_BUDGET")
        require(result.status == "ok" and result.exit_code == 0, "QUERY_FAILED")
        return result.stdout
    try:
        parsers = (("unit_files", "unit_files", parse_unit_files), ("units", "units", parse_units),
                   ("processes", "postgres_processes", parse_processes), ("tcp", "tcp_5432_listeners", parse_tcp),
                   ("unix", "unix_5432_listeners", parse_unix), ("clusters", "clusters", parse_clusters))
        for key, field, parser in parsers:
            report["safety"][field] = parser(query(key))
            if key == "unit_files":
                report["safety"]["unit_state"] = parse_unit_state(query("unit_state"))
                current = report["safety"]["unit_state"]
                require(current["LoadState"] in {"loaded", "masked"} and current["UnitFileState"] == "masked"
                        and current["ActiveState"] == "inactive" and current["SubState"] == "dead", "POSTGRES_ACTIVE")
        report["safety"]["paths"] = metadata_reader(deadline=deadline, clock=clock)
        require(clock() < deadline, "TIME_BUDGET")
        report["safety"]["passed"] = True
    except (OSError, ValueError, TypeError, UnicodeError):
        error = sys.exc_info()[1]
        return finish("safety_stop", str(error) if str(error) in REASONS else "PATHS_UNSAFE" if isinstance(error, OSError) else "QUERY_INVALID")
    try:
        release = release_reader(deadline=deadline, clock=clock)
        require(isinstance(release, dict) and release.get("ID") == "debian" and release.get("VERSION_CODENAME") == "trixie", "OS_RELEASE_INVALID")
        kernel = _text(query("kernel")).split()
        require(len(kernel) == 2 and all(re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", item) for item in kernel), "INVENTORY_INVALID")
        packages, selected = parse_packages(query("packages"))
        devices = parse_devices(query("blockdevices"))
        mounts = parse_mounts(query("mounts"))
        report["inventory"] = {"os_release": release, "kernel": {"release": kernel[0], "machine": kernel[1]},
                               "postgresql_packages": selected, "packages": packages, "blockdevices": devices, "mounts": mounts}
        return finish("inventory_complete", "SAFE_AND_COMPLETE")
    except (OSError, ValueError, TypeError, UnicodeError):
        error = sys.exc_info()[1]
        return finish("inventory_incomplete", str(error) if str(error) in REASONS else "INVENTORY_INVALID")


def validate_report(value):
    require(isinstance(value, dict) and set(value) == {"schema", "status", "exit_code", "reason", "safety", "inventory", "commands", "timing", "stderr"}
            and value["schema"] == SCHEMA and value["status"] in {"inventory_complete", "inventory_incomplete", "safety_stop"}
            and type(value["exit_code"]) is int and value["exit_code"] == {"inventory_complete": 0, "inventory_incomplete": 3, "safety_stop": 2}[value["status"]]
            and value["reason"] in REASONS, "REPORT_INVALID")
    safety = value["safety"]
    require(isinstance(safety, dict) and set(safety) == {"passed", "unit_files", "unit_state", "units", "postgres_processes", "tcp_5432_listeners", "unix_5432_listeners", "clusters", "paths"}
            and type(safety["passed"]) is bool, "REPORT_INVALID")
    if safety["unit_files"] is not None:
        require(isinstance(safety["unit_files"], list) and all(isinstance(row, dict) and set(row) == {"name", "state"} for row in safety["unit_files"]), "REPORT_INVALID")
        parse_unit_files("\n".join(row["name"] + " " + row["state"] for row in safety["unit_files"]).encode())
    if safety["unit_state"] is not None:
        require(isinstance(safety["unit_state"], dict), "REPORT_INVALID")
        parse_unit_state("\n".join(key + "=" + value for key, value in safety["unit_state"].items()).encode())
    if safety["units"] is not None:
        require(isinstance(safety["units"], list) and all(isinstance(row, dict) and set(row) == {"name", "load", "active", "sub"} for row in safety["units"]), "REPORT_INVALID")
        parse_units("\n".join(" ".join(row[key] for key in ("name", "load", "active", "sub")) for row in safety["units"]).encode())
    for field in ("postgres_processes", "tcp_5432_listeners", "unix_5432_listeners", "clusters"):
        require(safety[field] is None or type(safety[field]) is int and safety[field] == 0, "REPORT_INVALID")
    fields = {"key", "exit_code", "duration_ms", "status", "error_code", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256", "stderr_diagnostic"}
    require(isinstance(value["commands"], list) and len(value["commands"]) <= len(COMMANDS), "REPORT_INVALID")
    keys = []
    for row in value["commands"]:
        require(isinstance(row, dict) and set(row) == fields and row["key"] in COMMANDS and row["key"] not in keys
                and row["status"] in PROCESS_STATUSES and (row["exit_code"] is None or type(row["exit_code"]) is int)
                and type(row["duration_ms"]) is int and row["duration_ms"] >= 0
                and type(row["stdout_bytes"]) is int and 0 <= row["stdout_bytes"] <= (PACKAGE_LIMIT if row["key"] == "packages" else 262144)
                and type(row["stderr_bytes"]) is int and 0 <= row["stderr_bytes"] <= STDERR_LIMIT
                and all(re.fullmatch(r"[a-f0-9]{64}", row[key]) for key in ("stdout_sha256", "stderr_sha256"))
                and (row["error_code"] is None or row["error_code"] in ERROR_CODES), "REPORT_INVALID")
        require((row["status"] == "ok" and row["exit_code"] == 0 and row["error_code"] is None)
                or (row["status"] != "ok" and row["error_code"] == row["status"].upper()
                    and (row["status"] != "nonzero_exit" or type(row["exit_code"]) is int and row["exit_code"] != 0)
                    and (row["status"] not in {"spawn_error", "unsafe_binary", "budget_exhausted"} or row["exit_code"] is None)), "REPORT_INVALID")
        diagnostic = row["stderr_diagnostic"]
        require(isinstance(diagnostic, dict) and set(diagnostic) == {"messages", "unclassified_lines"}
                and isinstance(diagnostic["messages"], list) and len(diagnostic["messages"]) <= 16
                and all(isinstance(phrase, str) and STDERR_PATTERN.fullmatch(phrase) for phrase in diagnostic["messages"])
                and type(diagnostic["unclassified_lines"]) is int and 0 <= diagnostic["unclassified_lines"] <= STDERR_LIMIT,
                "REPORT_INVALID")
        keys.append(row["key"])
    require(keys == list(COMMANDS)[:len(keys)] and sum(row["stdout_bytes"] for row in value["commands"]) <= TOTAL_OUTPUT_LIMIT
            and sum(row["stderr_bytes"] for row in value["commands"]) <= STDERR_LIMIT, "REPORT_INVALID")
    require(set(value["timing"]) == {"duration_ms", "limit_seconds"} and value["timing"]["limit_seconds"] == TOTAL_SECONDS
            and type(value["timing"]["duration_ms"]) is int and value["timing"]["duration_ms"] >= 0
            and set(value["stderr"]) == {"bytes", "sha256", "truncated"} and type(value["stderr"]["bytes"]) is int
            and value["stderr"]["bytes"] == sum(row["stderr_bytes"] for row in value["commands"])
            and re.fullmatch(r"[a-f0-9]{64}", value["stderr"]["sha256"]) and type(value["stderr"]["truncated"]) is bool, "REPORT_INVALID")
    if safety["passed"]:
        require(keys[:len(SAFETY_COMMANDS)] == list(SAFETY_COMMANDS)
                and all(row["status"] == "ok" and row["exit_code"] == 0 for row in value["commands"][:len(SAFETY_COMMANDS)])
                and all(safety[field] == 0 for field in ("postgres_processes", "tcp_5432_listeners", "unix_5432_listeners", "clusters")), "REPORT_INVALID")
        require(safety["unit_files"] is not None and safety["unit_state"] is not None and safety["units"] is not None
                and safety["unit_state"]["LoadState"] in {"loaded", "masked"} and safety["unit_state"]["UnitFileState"] == "masked"
                and safety["unit_state"]["ActiveState"] == "inactive" and safety["unit_state"]["SubState"] == "dead", "REPORT_INVALID")
    if safety["paths"] is not None:
        require(isinstance(safety["paths"], list) and len(safety["paths"]) == 3, "REPORT_INVALID")
        for row, path in zip(safety["paths"], PATHS):
            require(set(row) == {"path", "exists", "uid", "gid", "mode", "entries_count", "provenance_metadata_only", "known_shell_dotfiles", "empty_version_dirs", "absent_version_dirs"} and row["path"] == path
                    and type(row["exists"]) is bool and type(row["entries_count"]) is int and row["entries_count"] >= 0
                    and ((row["exists"] and all(type(row[key]) is int and row[key] >= 0 for key in ("uid", "gid"))
                          and isinstance(row["mode"], str) and re.fullmatch(r"0o[0-7]{3,4}", row["mode"]))
                         or (not row["exists"] and row["uid"] is None and row["gid"] is None and row["mode"] is None
                             and row["entries_count"] == 0 and row["known_shell_dotfiles"] == row["empty_version_dirs"] == []))
                    and isinstance(row["known_shell_dotfiles"], list) and len(set(row["known_shell_dotfiles"])) == len(row["known_shell_dotfiles"])
                    and set(row["known_shell_dotfiles"]) <= ({".bashrc", ".profile", ".bash_logout"} if path == "/var/lib/postgresql" else set())
                    and isinstance(row["empty_version_dirs"], list) and len(set(row["empty_version_dirs"])) == len(row["empty_version_dirs"])
                    and set(row["empty_version_dirs"]) <= ({"17", "18"} if path != PATHS[-1] else set())
                    and row["absent_version_dirs"] == (sorted({"17", "18"} - set(row["empty_version_dirs"])) if path != PATHS[-1] else [])
                    and row["entries_count"] == (1 if path == PATHS[-1] else len(row["known_shell_dotfiles"]) + len(row["empty_version_dirs"]))
                    and row["provenance_metadata_only"] is (path == PATHS[-1])
                    and (path != PATHS[-1] or row["exists"] is True), "REPORT_INVALID")
    if safety["passed"]:
        require(safety["paths"] is not None, "REPORT_INVALID")
    if value["status"] == "inventory_complete":
        require(safety["passed"] and keys == list(COMMANDS) and value["reason"] == "SAFE_AND_COMPLETE"
                and value["timing"]["duration_ms"] <= TOTAL_SECONDS * 1000
                and all(row["status"] == "ok" and row["exit_code"] == 0 and row["duration_ms"] <= COMMAND_SECONDS * 1000
                        for row in value["commands"]), "REPORT_INVALID")
        inventory = value["inventory"]
        require(isinstance(inventory, dict) and set(inventory) == {"os_release", "kernel", "postgresql_packages", "packages", "blockdevices", "mounts"}
                and isinstance(inventory["os_release"], dict) and set(inventory["os_release"]) <= OS_KEYS
                and inventory["os_release"].get("ID") == "debian" and inventory["os_release"].get("VERSION_CODENAME") == "trixie"
                and all(isinstance(item, str) and len(item) <= 256 for item in inventory["os_release"].values())
                and set(inventory["kernel"]) == {"release", "machine"}
                and all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9._+-]{1,128}", item) for item in inventory["kernel"].values()), "REPORT_INVALID")
        packages, selected = parse_packages("\n".join("\t".join(row) for row in inventory["packages"]).encode())
        require(packages == inventory["packages"] and selected == inventory["postgresql_packages"], "REPORT_INVALID")
        parse_devices(encoded({"blockdevices": inventory["blockdevices"]}))
        parse_mounts(encoded({"filesystems": inventory["mounts"]}))
    else:
        require(value["inventory"] is None and value["reason"] != "SAFE_AND_COMPLETE"
                and (safety["passed"] is (value["status"] == "inventory_incomplete")), "REPORT_INVALID")
    require(len(encoded(value)) + 1 <= TOTAL_OUTPUT_LIMIT, "REPORT_INVALID")
    return value


def main():
    if len(sys.argv) != 1 or not sys.platform.startswith("linux"):
        report = collect(runner=lambda *_args, **_kwargs: CommandResult(None, status="spawn_error", error_code="SPAWN_ERROR"))
        report["reason"] = "ARGUMENTS_FORBIDDEN" if len(sys.argv) != 1 else "UNSUPPORTED_PLATFORM"
    else:
        def deadline_reached(_signum, _frame):
            raise InventoryError("TIME_BUDGET")
        previous = signal.signal(signal.SIGALRM, deadline_reached)
        signal.setitimer(signal.ITIMER_REAL, TOTAL_SECONDS)
        try:
            report = collect(stderr_sink=sys.stderr.buffer)
        finally:
            signal.setitimer(signal.ITIMER_REAL, 0)
            signal.signal(signal.SIGALRM, previous)
    validate_report(report)
    sys.stdout.buffer.write(encoded(report) + b"\n")
    sys.stdout.buffer.flush()
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
