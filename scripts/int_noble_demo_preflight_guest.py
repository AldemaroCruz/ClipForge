"""Read confined Noble demo prerequisites without touching the services."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import selectors
import subprocess
import sys
import time

if "_noble_kernel_reads" not in globals():
    from scripts import int_noble_kernel_guest as _noble_kernel_reads

kernel = _noble_kernel_reads
SCHEMA = "clipforge-int-noble-demo-preflight-2"
MAX_OUTPUT = 32768
PACKAGE = "linux-tools-common"
CURRENT = "6.8.0-149.149"
TARGET = "6.8.0-151.151"
HUMAN = "admin_ixbalam_studio"
SAMPLES = ("35.235.240.1", "35.235.255.254")
APT_NO_CACHE = ["-o", "Dir::Cache::pkgcache=", "-o", "Dir::Cache::srcpkgcache="]
VERSION = re.compile(r"[0-9A-Za-z.:+~-]{1,64}")
APT_ERRORS = {
    "target_version_not_found": r"^E: Version '6\.8\.0-151\.151' for 'linux-tools-common' was not found$",
    "target_package_not_found": r"^E: Unable to locate package linux-tools-common$",
    "broken_dependencies": r"^E: (?:Unable to correct problems, you have held broken packages\.|Unmet dependencies\..*)$",
    "removal_required": r"^E: Packages need to be removed but remove is disabled\.$",
    "apt_lock_or_permission": r"^[EW]: (?:Could not get lock|Unable to acquire.+lock|Could not open lock file).*$",
    "apt_lists_invalid": r"^[EW]: (?:The package lists or status file could not be parsed|Encountered a section with no Package: header|Problem with MergeList).*$",
    "apt_config_or_source_unavailable": r"^[EW]: (?:Unable to read|Could not open file|Malformed entry|The list of sources could not be read).*$",
    "apt_temp_unavailable": r"^E: (?:Unable to mkstemp|Could not create temporary file).*$",
}
SSH_ERRORS = {
    "host_key_unavailable": r"^(?:Unable to load host key: .*|sshd: no hostkeys available -- exiting\.)$",
    "privilege_separation_unavailable": r"^Missing privilege separation directory: .+$",
    "configuration_unavailable": r"^.*(?:Permission denied|No such file or directory).*$",
    "test_connection_option_rejected": r"^Config test connection parameter \(-C\) provided without test mode \(-T\)$",
    "human_user_unresolved": r"^.*(?:Can't match group|Invalid user|invalid user).*$",
}
PROCESS_STATUS = {"exited", "timeout", "output_limit", "start_error"}


def run_diagnostic(argv, *, budget=8, limit=32768, environment=None):
    """Return raw streams to the caller only, retaining the exit or bounded failure."""
    end = time.monotonic() + budget
    output = {"stdout": bytearray(), "stderr": bytearray()}
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                              cwd="/", env=environment or kernel.ENVIRONMENT) as process:
            try:
                with selectors.DefaultSelector() as incoming:
                    incoming.register(process.stdout, selectors.EVENT_READ, "stdout")
                    incoming.register(process.stderr, selectors.EVENT_READ, "stderr")
                    while incoming.get_map():
                        ready = incoming.select(max(0, end - time.monotonic()))
                        if not ready:
                            return "timeout", None, "", ""
                        for key, _ in ready:
                            data = os.read(key.fd, 8192)
                            if not data:
                                incoming.unregister(key.fileobj)
                                continue
                            output[key.data].extend(data)
                            if sum(map(len, output.values())) > limit:
                                return "output_limit", None, "", ""
                        if time.monotonic() >= end:
                            return "timeout", None, "", ""
                code = process.wait(timeout=max(0, end - time.monotonic()))
                return "exited", code, output["stdout"].decode("ascii", errors="replace"), output["stderr"].decode("ascii", errors="replace")
            finally:
                if process.poll() is None:
                    process.kill()
    except subprocess.TimeoutExpired:
        return "timeout", None, "", ""
    except OSError:
        return "start_error", None, "", ""


def sanitized(result, rules):
    status, code, _, stderr = result
    found = set()
    unclassified = 0
    for line in stderr.splitlines():
        if not line.strip():
            continue
        categories = {tag for tag, pattern in rules.items() if re.fullmatch(pattern, line)}
        found.update(categories)
        if not categories:
            unclassified += 1
    return {"process": status, "exit": code, "stderr_markers": sorted(found),
            "unclassified_stderr_lines": unclassified}


def nfs_exports():
    first = os.stat("/proc/1/ns/mnt")
    current = os.stat("/proc/self/ns/mnt")
    host_mount_namespace = (first.st_dev, first.st_ino) == (current.st_dev, current.st_ino)
    virtual_filesystems = kernel.read("/proc/filesystems", 65536).splitlines()
    registered = any(line.split()[-1:] == ["nfsd"] for line in virtual_filesystems)
    loaded = "nfsd" in kernel.module_loaded_names() or kernel.sysfs_module("nfsd")
    mounts = kernel.filesystem_counts()["nfsd"]
    try:
        active = kernel.active_exports()
        state = "table_read"
    except FileNotFoundError:
        inactive = host_mount_namespace and not registered and not loaded and mounts == 0
        state = "server_unregistered_in_host_mount_namespace" if inactive else "table_absent_capacity_undetermined"
        active = 0 if inactive else None
    except (OSError, ValueError):
        state, active = "table_unavailable", None
    return {"host_mount_namespace": host_mount_namespace, "registered_filesystem": registered, "module_loaded": loaded,
            "nfsd_mounts": mounts, "active_count": active, "state": state,
            "configured_count": kernel.optional(kernel.configured_exports)}


def forwarding(address):
    context = f"user={HUMAN},host={address},addr={address},laddr=10.80.1.3,lport=22"
    result = run_diagnostic(["/usr/sbin/sshd", "-T", "-C", context], limit=16384)
    report = {"command": sanitized(result, SSH_ERRORS), "state": "command_failed", "allowtcpforwarding": None,
              "disableforwarding": None, "loopback_5432_allowed": None, "usedns": None}
    if result[1] != 0:
        return report
    fields = [line.split(None, 1) for line in result[2].splitlines()]
    keys = {"allowtcpforwarding", "disableforwarding", "permitopen", "usedns"}
    selected = [field for field in fields if len(field) == 2 and field[0] in keys]
    rows = dict(selected)
    forwarding = rows.get("allowtcpforwarding")
    disabled = rows.get("disableforwarding")
    permitted = rows.get("permitopen", "").split()
    usedns = rows.get("usedns")
    if (len(selected) != len(keys) or set(rows) != keys or forwarding not in {"yes", "no", "all", "local", "remote"}
            or disabled not in {"yes", "no"} or usedns not in {"yes", "no"} or not permitted):
        report["state"] = "unexpected_output"
        return report
    target_allowed = any(rule in {"any", "127.0.0.1:5432", "127.0.0.1:*", "*:5432", "*:*"} for rule in permitted)
    report.update(state="evaluated", allowtcpforwarding=forwarding, disableforwarding=disabled == "yes",
                  loopback_5432_allowed=target_allowed, usedns=usedns == "yes")
    return report


def upgrade(result, installed):
    _, code, output, _ = result
    changes = [line for line in output.splitlines() if line.startswith(("Inst ", "Remv ", "Conf ", "Purg "))]
    install = re.compile(r"Inst linux-tools-common \[6\.8\.0-149\.149\] \(6\.8\.0-151\.151(?: |\)).*")
    configure = re.compile(r"Conf linux-tools-common \(6\.8\.0-151\.151(?: |\)).*")
    summary = r"^1 upgraded, 0 newly installed, 0 to remove and [0-9]+ not upgraded\.$"
    exact = (code == 0 and installed == CURRENT and len(changes) == 2 and install.fullmatch(changes[0]) is not None
             and configure.fullmatch(changes[1]) is not None and re.search(summary, output, re.M) is not None)
    return {"command": sanitized(result, APT_ERRORS), "exact_upgrade": exact, "action_count": len(changes)}


def package_scope():
    dpkg = run_diagnostic(["/usr/bin/dpkg-query", "-W", "-f=${Version}\\t${db:Status-Status}\\n", PACKAGE], limit=2048)
    fields = dpkg[2].strip().split("\t")
    installed = fields[0] if dpkg[1] == 0 and len(fields) == 2 and VERSION.fullmatch(fields[0]) and fields[1] == "installed" else None
    policy = run_diagnostic(["/usr/bin/apt-cache", *APT_NO_CACHE, "policy", PACKAGE], budget=12)
    candidate = re.search(r"^  Candidate: ([A-Za-z0-9.:+~-]{1,64})$", policy[2], re.M) if policy[1] == 0 else None
    present = bool(re.search(r"^\s+(?:\*\*\* )?6\.8\.0-151\.151 +[0-9-]+$", policy[2], re.M)) if policy[1] == 0 else None
    original = run_diagnostic(["/usr/bin/apt-get", *APT_NO_CACHE, "-s", "--no-download", "--only-upgrade", "install",
                               PACKAGE + "=" + TARGET], budget=12)
    return {"installed": installed, "requested": TARGET, "dpkg": sanitized(dpkg, APT_ERRORS), "apt_index_candidate": candidate[1] if candidate else None,
            "apt_index_target_present": present, "apt_index": sanitized(policy, APT_ERRORS),
            "original_simulation": upgrade(original, installed)}


def grub_scope():
    path = Path("/boot/grub/grub.cfg")
    report = {"uefi": Path("/sys/firmware/efi").is_dir(), "cfg_sha256": None, "cfg_syntax": None,
              "grubenv_read": False, "next_entry_set": None, "saved_entry_set": None,
              "next_entry_clear_declared": None, "grubenv_regular_1024": None, "grubenv_fs": None,
              "grubenv_no_abstraction": None}
    if path.is_file():
        with path.open("rb") as stream:
            content = stream.read(1048577)
        if len(content) <= 1048576:
            report["cfg_sha256"] = sha256(content).hexdigest()
            clear_once = rb'set default="\$\{next_entry\}"\n[ \t]*set next_entry=\n[ \t]*save_env next_entry\n'
            report["next_entry_clear_declared"] = re.search(clear_once, content) is not None
        check, _ = kernel.run(["/usr/bin/grub-script-check", str(path)], budget=4, limit=2048)
        if check is not None:
            report["cfg_syntax"] = check == 0
    env = Path("/boot/grub/grubenv")
    if env.is_file():
        report["grubenv_regular_1024"] = not env.is_symlink() and env.stat().st_size == 1024
        status, fstype = kernel.run(["/usr/bin/findmnt", "-n", "-o", "FSTYPE", "-T", str(env)], limit=512)
        if status == 0 and re.fullmatch(r"[a-z][a-z0-9_]{0,31}", fstype.strip()):
            report["grubenv_fs"] = fstype.strip()
        status, abstraction = kernel.run(["/usr/sbin/grub-probe", "--target=abstraction", str(env)], limit=4096)
        if status == 0:
            report["grubenv_no_abstraction"] = not abstraction.strip()
    status, raw = kernel.run(["/usr/bin/grub-editenv", str(env), "list"], limit=4096)
    if status == 0:
        fields = dict(row.split("=", 1) for row in raw.splitlines() if "=" in row)
        report.update(grubenv_read=True, next_entry_set=bool(fields.get("next_entry")), saved_entry_set=bool(fields.get("saved_entry")))
    return report


def collect():
    boot, release = kernel.identity()
    user = run_diagnostic(["/usr/bin/getent", "passwd", HUMAN], limit=2048)
    nss = {"command": sanitized(user, SSH_ERRORS),
           "resolved": len(user[2].splitlines()) == 1 and user[2].startswith(HUMAN + ":") if user[1] == 0 else None}
    report = {"schema": SCHEMA, "boot_id": boot, "release": release, "exports": kernel.optional(nfs_exports),
              "ssh_human_nss": nss, "ssh_samples": {address: forwarding(address) for address in SAMPLES},
              "package": package_scope(), "grub": kernel.optional(grub_scope)}
    if kernel.identity() != (boot, release):
        raise ValueError("guest_changed")
    return report


def nullable(value, expected_type):
    if value is not None and type(value) is not expected_type:
        raise ValueError("preflight_field_type")


def check_diagnostic(value, rules):
    fields = kernel.object_with(value, ("process", "exit", "stderr_markers", "unclassified_stderr_lines"))
    if fields["process"] not in PROCESS_STATUS:
        raise ValueError("invalid_diagnostic_process")
    code = fields["exit"]
    if (fields["process"] == "exited" and (type(code) is not int or not -127 <= code <= 255)
            or fields["process"] != "exited" and code is not None):
        raise ValueError("invalid_diagnostic_exit")
    tags = fields["stderr_markers"]
    if (not isinstance(tags, list) or len(tags) > len(rules) or any(type(tag) is not str or tag not in rules for tag in tags)
            or tags != sorted(set(tags))):
        raise ValueError("invalid_diagnostic_markers")
    kernel.count(fields["unclassified_stderr_lines"])


def check_upgrade(value, installed):
    fields = kernel.object_with(value, ("command", "exact_upgrade", "action_count"))
    check_diagnostic(fields["command"], APT_ERRORS)
    kernel.count(fields["action_count"])
    if type(fields["exact_upgrade"]) is not bool or (fields["exact_upgrade"] and
            (fields["command"]["exit"], fields["action_count"], installed) != (0, 2, CURRENT)):
        raise ValueError("invalid_package_transition")


def check_package(value):
    pkg = kernel.object_with(value, ("installed", "requested", "dpkg", "apt_index_candidate", "apt_index_target_present",
                                     "apt_index", "original_simulation"))
    for field in ("installed", "apt_index_candidate"):
        nullable(pkg[field], str)
        if pkg[field] is not None and not VERSION.fullmatch(pkg[field]):
            raise ValueError("invalid_package_version")
    if pkg["requested"] != TARGET:
        raise ValueError("invalid_package_target")
    check_diagnostic(pkg["dpkg"], APT_ERRORS)
    check_diagnostic(pkg["apt_index"], APT_ERRORS)
    nullable(pkg["apt_index_target_present"], bool)
    if (pkg["apt_index"]["exit"] == 0) != (pkg["apt_index_target_present"] is not None):
        raise ValueError("invalid_apt_index_result")
    check_upgrade(pkg["original_simulation"], pkg["installed"])


def validate(raw, expected_boot_id):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_OUTPUT:
        raise ValueError("demo_preflight_report_size")

    def object_pairs(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate_preflight_field")
        return result

    value = kernel.object_with(json.loads(raw.decode("ascii"), object_pairs_hook=object_pairs),
                               ("schema", "boot_id", "release", "exports", "ssh_human_nss", "ssh_samples", "package", "grub"))
    if value["schema"] != SCHEMA or not kernel.BOOT_ID.fullmatch(expected_boot_id) or value["boot_id"] != expected_boot_id:
        raise ValueError("demo_preflight_boot")
    if not isinstance(value["release"], str) or not kernel.RELEASE.fullmatch(value["release"]):
        raise ValueError("demo_preflight_release")
    if value["exports"] is not None:
        fields = kernel.object_with(value["exports"], ("host_mount_namespace", "registered_filesystem", "module_loaded",
                                                      "nfsd_mounts", "active_count", "configured_count", "state"))
        if any(type(fields[key]) is not bool for key in ("host_mount_namespace", "registered_filesystem", "module_loaded")):
            raise ValueError("demo_preflight_export_flags")
        for key in ("nfsd_mounts", "active_count", "configured_count"):
            if fields[key] is not None:
                kernel.count(fields[key])
        if fields["state"] not in {"table_read", "server_unregistered_in_host_mount_namespace",
                                    "table_absent_capacity_undetermined", "table_unavailable"}:
            raise ValueError("demo_preflight_export_status")
        if fields["state"] == "server_unregistered_in_host_mount_namespace" and (
                not fields["host_mount_namespace"] or fields["registered_filesystem"] or fields["module_loaded"]
                or fields["nfsd_mounts"] != 0 or fields["active_count"] != 0):
            raise ValueError("demo_preflight_export_absence_unproven")
    nss = kernel.object_with(value["ssh_human_nss"], ("command", "resolved"))
    check_diagnostic(nss["command"], SSH_ERRORS)
    nullable(nss["resolved"], bool)
    for row in kernel.object_with(value["ssh_samples"], SAMPLES).values():
        ssh = kernel.object_with(row, ("command", "state", "allowtcpforwarding", "disableforwarding",
                                       "loopback_5432_allowed", "usedns"))
        check_diagnostic(ssh["command"], SSH_ERRORS)
        if ssh["state"] == "evaluated":
            if (ssh["command"]["exit"] != 0 or ssh["allowtcpforwarding"] not in {"yes", "no", "all", "local", "remote"}
                    or any(type(ssh[key]) is not bool for key in ("disableforwarding", "loopback_5432_allowed", "usedns"))):
                raise ValueError("demo_preflight_ssh_fields")
        elif (ssh["state"] not in {"command_failed", "unexpected_output"}
              or (ssh["state"] == "command_failed") != (ssh["command"]["exit"] != 0)
              or any(ssh[key] is not None for key in ("allowtcpforwarding", "disableforwarding", "loopback_5432_allowed", "usedns"))):
            raise ValueError("demo_preflight_ssh_fields")
    check_package(value["package"])
    if value["grub"] is not None:
        flags = kernel.object_with(value["grub"], ("uefi", "cfg_sha256", "cfg_syntax", "grubenv_read", "next_entry_set", "saved_entry_set",
                                                  "next_entry_clear_declared", "grubenv_regular_1024", "grubenv_fs", "grubenv_no_abstraction"))
        for key in ("uefi", "cfg_syntax", "grubenv_read", "next_entry_set", "saved_entry_set", "next_entry_clear_declared",
                    "grubenv_regular_1024", "grubenv_no_abstraction"):
            nullable(flags[key], bool)
        if flags["cfg_sha256"] is not None and not re.fullmatch(r"[a-f0-9]{64}", flags["cfg_sha256"]):
            raise ValueError("demo_preflight_grub_hash")
        if flags["grubenv_fs"] is not None and not re.fullmatch(r"[a-z][a-z0-9_]{0,31}", flags["grubenv_fs"]):
            raise ValueError("demo_preflight_grub_fs")
    return value


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("unexpected_arguments")
        report = collect()
        raw = json.dumps(report, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        validate(raw, report["boot_id"])
        print(raw.decode("ascii"))
        return 0
    except (OSError, ValueError, UnicodeError):
        print(json.dumps({"schema": SCHEMA, "error": "NOBLE_DEMO_GUEST_PRECONDITION"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
