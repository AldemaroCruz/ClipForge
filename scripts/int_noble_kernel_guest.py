"""Read-only evidence for the three kernel subsystems on the Noble INT guest."""
from __future__ import annotations

from collections import Counter
import json
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time


SCHEMA = "clipforge-int-noble-kernel-observation-1"
MAX_OUTPUT = 131072
MODULES = ("xen_netback", "ceph", "nfsd")
UNIT_NAMES = ("xencommons.service", "xenstored.service", "ceph.target", "ceph-mon.target",
              "ceph-osd.target", "ceph-mds.target", "nfs-server.service", "nfs-kernel-server.service",
              "nfs-mountd.service", "rpcbind.service", "rpcbind.socket")
FILESYSTEMS = ("ceph", "fuse.ceph", "nfs", "nfs4", "nfsd", "rpc_pipefs")
PORTS = (111, 2049, 3300, 6789)
MODLOAD_DIRS = ("/etc/modules-load.d", "/run/modules-load.d", "/usr/local/lib/modules-load.d",
                "/usr/lib/modules-load.d", "/lib/modules-load.d")
AUTO_DIRECTIVES = ("blacklist", "aliases", "dependencies", "options", "remove_directives")
VIRT = ("none", "kvm", "qemu", "xen", "amazon", "google", "microsoft", "vmware", "other")
UNIT_STATES = {
    "load": {"loaded", "not-found", "bad-setting", "error", "merged", "masked"},
    "active": {"active", "reloading", "inactive", "failed", "activating", "deactivating", "maintenance", "refreshing"},
    "file": {"enabled", "enabled-runtime", "linked", "linked-runtime", "alias", "masked", "masked-runtime",
             "static", "disabled", "indirect", "generated", "transient", "bad", "absent"},
}
LIMITATIONS = (
    "runtime_snapshot_only",
    "namespace_of_observer",
    "cannot_prove_future_exposure_or_patch",
    "ceph_userspace_clients_not_inspected",
    "no_initramfs_or_kernel_command_line_config_read",
    "autoload_counts_are_direct_declarations_only",
    "exports_scope_counts_only",
)
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
RELEASE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-gcp")
ENVIRONMENT = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"}


def read(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    if len(raw) > limit:
        raise ValueError("read_limit")
    return raw.decode("ascii")


def run(argv, budget=4, limit=131072):
    """Use fixed argv, discard stderr and cap stdout and elapsed time."""
    end = time.monotonic() + budget
    try:
        with subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                              stderr=subprocess.DEVNULL, cwd="/", env=ENVIRONMENT) as process:
            try:
                result = bytearray()
                with selectors.DefaultSelector() as incoming:
                    incoming.register(process.stdout, selectors.EVENT_READ)
                    while incoming.select(max(0, end - time.monotonic())):
                        part = os.read(process.stdout.fileno(), min(8192, limit + 1 - len(result)))
                        if not part:
                            return process.wait(timeout=max(0, end - time.monotonic())), result.decode("ascii")
                        result.extend(part)
                        if len(result) > limit or time.monotonic() >= end:
                            break
            finally:
                if process.poll() is None:
                    process.kill()
    except (OSError, UnicodeError, subprocess.TimeoutExpired):
        pass
    return None, ""


def optional(probe, default=None):
    try:
        return probe()
    except (OSError, UnicodeError, ValueError):
        return default


def commands_output(argv, **limits):
    code, raw = run(argv, **limits)
    if code != 0:
        raise ValueError("query_failed")
    return raw


def virtualization():
    code, raw = run(["/usr/bin/systemd-detect-virt", "--vm"])
    value = raw.strip()
    if code == 1 and value == "none":
        return "none"
    if code == 0 and re.fullmatch(r"[a-z][a-z0-9-]{0,30}", value):
        return value if value in VIRT[:-1] and value != "none" else "other"
    return None


def module_loaded_names():
    names = set()
    for row in read("/proc/modules", 262144).splitlines():
        fields = row.split()
        if len(fields) < 6 or not re.fullmatch(r"[A-Za-z0-9_-]+", fields[0]):
            raise ValueError("proc_modules_shape")
        names.add(fields[0].replace("-", "_"))
    return names


def sysfs_module(module):
    try:
        return stat.S_ISDIR(Path("/sys/module", module).lstat().st_mode)
    except FileNotFoundError:
        if Path("/sys/module").is_dir():
            return False
        raise


def module_disk(release, module):
    code, raw = run(["/usr/sbin/modinfo", "-k", release, "-F", "filename", module])
    disk = raw.strip()
    if code == 0 and disk == "(builtin)":
        return "builtin"
    roots = ("/lib/modules/" + release + "/", "/usr/lib/modules/" + release + "/")
    if code == 0 and "\n" not in disk and disk.startswith(roots) and re.fullmatch(r"[A-Za-z0-9_.+-]+\.ko(?:\.(?:gz|xz|zst))?", Path(disk).name):
        return "module_file" if Path(disk).is_file() else None
    # kmod rc=1 also covers read or index failures, so it cannot establish absence.
    return None


def module_report(release):
    names = optional(module_loaded_names)
    return {module: {"loaded": None if names is None else module in names,
                     "sysfs": optional(lambda: sysfs_module(module)), "disk": module_disk(release, module)}
            for module in MODULES}


def unit(name):
    raw = commands_output(["/usr/bin/systemctl", "show", "--no-pager", "--property=LoadState,ActiveState,UnitFileState", name], limit=2048)
    fields = {}
    mapping = {"LoadState": "load", "ActiveState": "active", "UnitFileState": "file"}
    for row in raw.splitlines():
        key, separator, value = row.partition("=")
        if not separator or key not in mapping or mapping[key] in fields:
            raise ValueError("unit_shape")
        fields[mapping[key]] = value
    if fields.get("load") == "not-found" and not fields.get("file"):
        fields["file"] = "absent"
    if fields.keys() != UNIT_STATES.keys() or any(fields[key] not in states for key, states in UNIT_STATES.items()):
        raise ValueError("unit_state_unknown")
    return fields


def filesystem_counts():
    raw = commands_output(["/usr/bin/findmnt", "--kernel", "--raw", "--noheadings", "--output", "FSTYPE"])
    counts = Counter(raw.splitlines())
    if not counts or any(not re.fullmatch(r"[A-Za-z0-9_.-]+", name) for name in counts):
        raise ValueError("findmnt_shape")
    return {type_: counts[type_] for type_ in FILESYSTEMS}


def directory_files(directory, suffix):
    try:
        with os.scandir(directory) as rows:
            files = []
            for entry in rows:
                if entry.name.endswith(suffix):
                    files.append(Path(entry.path))
                    if len(files) > 128:
                        raise ValueError("directory_limit")
            return sorted(files)
    except FileNotFoundError:
        return []


def nofollow_text(path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return ""
    if stat.S_ISLNK(info.st_mode) and path.resolve() == Path("/dev/null"):
        return ""
    if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
        raise ValueError("untrusted_config_mode")
    return read(path, 32768)


def config_rows(raw):
    return [line.split("#", 1)[0].strip() for line in raw.splitlines() if line.split("#", 1)[0].strip()]


def configured_exports():
    files = [Path("/etc/exports"), *directory_files("/etc/exports.d", ".exports")]
    return sum(len(config_rows(nofollow_text(path))) for path in files)


def active_exports():
    # The kernel virtual file can be absent or unreadable to an OS Login user.
    raw = read("/proc/fs/nfsd/exports", 131072)
    if not raw.startswith("# Version "):
        raise ValueError("kernel_export_shape")
    return len(config_rows(raw))


def port_counts(path, tcp):
    raw = read(path, 262144)
    first, *rows = raw.splitlines()
    if "local_address" not in first or not ("rem_address" in first or "remote_address" in first):
        raise ValueError("socket_table_shape")
    found = Counter()
    for row in rows:
        fields = row.split()
        if len(fields) < 4 or not re.fullmatch(r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", fields[1]):
            raise ValueError("socket_row_shape")
        port = int(fields[1].rsplit(":", 1)[1], 16)
        if port in PORTS and ((tcp and fields[3] == "0A") or (not tcp and fields[3] == "07")):
            found[port] += 1
    return {str(port): found[port] for port in PORTS}


def configured_module_loads():
    selected = {}
    for directory in MODLOAD_DIRS:
        for path in directory_files(directory, ".conf"):
            selected.setdefault(path.name, path)
    legacy = Path("/etc/modules")
    # On Ubuntu the vendor's modules-load.d link may name the same file.
    if any(path.is_symlink() and path.resolve() == legacy for path in selected.values()):
        selected = {name: path for name, path in selected.items() if not (path.is_symlink() and path.resolve() == legacy)}
    found = Counter(line.replace("-", "_") for path in [*selected.values(), legacy] for line in config_rows(nofollow_text(path)))
    return {module: found[module] for module in MODULES}


def modprobe_config():
    # --showconfig shows the effective kmod declarations without loading modules or running install commands.
    raw = commands_output(["/usr/sbin/modprobe", "--showconfig"], limit=4 * 1024 * 1024)
    result = {name: {field: 0 for field in AUTO_DIRECTIVES} | {"install": "default"} for name in MODULES}
    for row in config_rows(raw):
        directive, *parts = row.split()
        if not parts:
            continue
        name = parts[0].replace("-", "_")
        if directive == "alias" and len(parts) >= 2 and parts[1].replace("-", "_") in result:
            result[parts[1].replace("-", "_")]["aliases"] += 1
        elif directive in ("softdep", "weakdep"):
            for relevant in set(part.replace("-", "_") for part in parts) & result.keys():
                result[relevant]["dependencies"] += 1
        elif name in result and directive in ("blacklist", "options", "remove"):
            result[name]["remove_directives" if directive == "remove" else directive] += 1
        elif name in result and directive == "install":
            label = "deny" if parts[1:] in (["/bin/false"], ["/usr/bin/false"]) else "other"
            current = result[name]["install"]
            result[name]["install"] = label if current in ("default", label) else "other"
    return result


def identity():
    os_rows = dict(line.split("=", 1) for line in read("/etc/os-release", 4096).splitlines() if "=" in line)
    boot = read("/proc/sys/kernel/random/boot_id", 64).strip()
    system, _, release, _, machine = os.uname()
    if (os_rows.get("ID", "").strip('"') != "ubuntu" or os_rows.get("VERSION_ID", "").strip('"') != "24.04"
            or system != "Linux" or machine != "x86_64" or not RELEASE.fullmatch(release) or not BOOT_ID.fullmatch(boot)):
        raise ValueError("unsupported_guest")
    return boot, release


def collect():
    boot, release = identity()
    report = {"schema": SCHEMA, "boot_id": boot, "release": release, "virtualization": virtualization(),
              "modules": module_report(release), "units": {name: optional(lambda: unit(name)) for name in UNIT_NAMES},
              "mounts": optional(filesystem_counts), "exports": {"active": optional(active_exports),
                                                                "configured": optional(configured_exports)},
              "listeners": {kind: optional(lambda: port_counts("/proc/net/" + kind, kind.startswith("tcp")))
                            for kind in ("tcp", "tcp6", "udp", "udp6")},
              "autoload": {"modules_load": optional(configured_module_loads), "modprobe": optional(modprobe_config)},
              "limitations": list(LIMITATIONS)}
    if identity() != (boot, release):
        raise ValueError("identity_changed")
    return report


def object_with(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise ValueError("unexpected_fields")
    return value


def count(value):
    if type(value) is not int or not 0 <= value <= 262144:
        raise ValueError("invalid_count")


def counts(value, keys):
    if value is not None:
        for item in object_with(value, keys).values():
            count(item)


def validate(raw, expected_boot_id):
    """Validate only a sanitized success from the authenticated expected boot."""
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_OUTPUT:
        raise ValueError("invalid_payload_size")

    def unique(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate_field")
        return result

    try:
        decoded = json.loads(raw.decode("ascii"), object_pairs_hook=unique)
    except RecursionError as exc:
        raise ValueError("observation_nesting") from exc
    value = object_with(decoded, ("schema", "boot_id", "release", "virtualization", "modules", "units", "mounts",
                                  "exports", "listeners", "autoload", "limitations"))
    if (value["schema"] != SCHEMA or type(expected_boot_id) is not str or not BOOT_ID.fullmatch(expected_boot_id)
            or value["boot_id"] != expected_boot_id or type(value["release"]) is not str
            or not RELEASE.fullmatch(value["release"]) or value["virtualization"] not in (*VIRT, None)
            or value["limitations"] != list(LIMITATIONS)):
        raise ValueError("invalid_identity_or_scope")
    for item in object_with(value["modules"], MODULES).values():
        fields = object_with(item, ("loaded", "sysfs", "disk"))
        if any(x is not None and type(x) is not bool for x in (fields["loaded"], fields["sysfs"])) or fields["disk"] not in ("builtin", "module_file", None):
            raise ValueError("invalid_module_result")
    for item in object_with(value["units"], UNIT_NAMES).values():
        if item is not None:
            fields = object_with(item, UNIT_STATES)
            if any(type(fields[key]) is not str or fields[key] not in states for key, states in UNIT_STATES.items()):
                raise ValueError("invalid_unit_result")
    counts(value["mounts"], FILESYSTEMS)
    for item in object_with(value["exports"], ("active", "configured")).values():
        if item is not None:
            count(item)
    for item in object_with(value["listeners"], ("tcp", "tcp6", "udp", "udp6")).values():
        counts(item, map(str, PORTS))
    auto = object_with(value["autoload"], ("modules_load", "modprobe"))
    counts(auto["modules_load"], MODULES)
    if auto["modprobe"] is not None:
        for item in object_with(auto["modprobe"], MODULES).values():
            fields = object_with(item, (*AUTO_DIRECTIVES, "install"))
            if fields["install"] not in ("default", "deny", "other"):
                raise ValueError("invalid_install_class")
            for key in AUTO_DIRECTIVES:
                count(fields[key])
    return value


def main():
    try:
        if len(sys.argv) != 1:
            raise ValueError("unexpected_argument")
        result = collect()
        raw = json.dumps(result, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")
        validate(raw, result["boot_id"])
        print(raw.decode("ascii"))
        return 0
    except (OSError, ValueError, UnicodeError):
        print(json.dumps({"schema": SCHEMA, "error": "identity_or_protocol_unavailable"}))
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
