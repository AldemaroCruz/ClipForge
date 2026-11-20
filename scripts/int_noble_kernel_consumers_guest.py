"""Observe the Noble kernel consumers and kmod resolution without loading modules."""

import hashlib
import json
import os
from pathlib import Path
import re
import stat

try:
    import _clipforge_noble_kernel_reads as kernel
except ModuleNotFoundError:
    from scripts import int_noble_kernel_guest as kernel


SCHEMA = "clipforge-int-noble-kernel-consumers-1"
MAX_OUTPUT = kernel.MAX_OUTPUT
PRIVATE_IP = "10.80.1.3"
BY_ID = "/dev/disk/by-id/google-clipforge-noble-pg-data"
PG_MOUNT = "/var/lib/clipforge-postgres/data"
CEPH_FILESYSTEMS = {"ceph", "fuse.ceph"}
CEPH_PACKAGES = ("ceph-common", "ceph-fuse", "libcephfs2", "rbd-nbd")
CEPH_PORTS = {3300, 6789}
CEPH_COMM = {"ceph", "ceph-fuse", "ceph-mon", "ceph-mgr", "ceph-mds", "ceph-osd", "mount.ceph", "rbd-nbd"}
DRIVERS = {"gve", "virtio_net", "xen_netfront", "hv_netvsc", "ena", "e1000", "e1000e", "other"}
PROBE_STATES = {"deny_install", "would_insert", "no_action_reported", "other", "failed"}
KMOD_RULE = Path("/etc/modprobe.d/98-clipforge-int-noble-kernel.conf")
KMOD_SHA256 = "4bf91a0780473f141bef96afec377c7f7d627fc4b207137544b7dd4bee034784"
LIMITATIONS = (
    "runtime_snapshot_and_pid1_namespaces_only",
    "ceph_sockets_count_only_canonical_remote_ports",
    "ceph_package_presence_is_not_current_use",
    "kmod_dry_run_does_not_cover_direct_privileged_load_or_early_boot",
    "initramfs_contents_not_read",
)


def nic_driver():
    raw = kernel.commands_output(["/usr/sbin/ip", "-j", "address", "show", "to", PRIVATE_IP + "/32"], limit=32768)
    devices = [row["ifname"] for row in json.loads(raw) if any(item.get("local") == PRIVATE_IP
               for item in row.get("addr_info", []))]
    if len(devices) != 1 or not re.fullmatch(r"[A-Za-z0-9_.-]{1,15}", devices[0]):
        raise ValueError("private_nic_indeterminate")
    driver = Path(os.readlink(Path("/sys/class/net", devices[0], "device/driver"))).name.replace("-", "_")
    return driver if driver in DRIVERS else "other"


def xen_backend_vifs():
    devices = Path("/sys/bus/xen-backend/devices")
    try:
        with os.scandir(devices) as entries:
            return sum(row.name.startswith("vif-") for row in entries)
    except FileNotFoundError:
        if Path("/sys/bus").is_dir():
            return 0
        raise


def storage_mounts():
    rows = []
    for line in kernel.read("/proc/1/mountinfo", 262144).splitlines():
        before, separator, after = line.partition(" - ")
        left, right = before.split(), after.split()
        if not separator or len(left) < 6 or len(right) < 3 or not re.fullmatch(r"[0-9]+:[0-9]+", left[2]):
            raise ValueError("host_mountinfo_shape")
        rows.append((left[2], left[4], right[0]))
    if not rows:
        raise ValueError("empty_host_mountinfo")
    return rows


def data_disk_relation(mounts):
    if mounts is None:
        return None
    disk = Path(BY_ID).stat()
    if not stat.S_ISBLK(disk.st_mode):
        raise ValueError("unexpected_data_device")
    number = f"{os.major(disk.st_rdev)}:{os.minor(disk.st_rdev)}"
    matches = [(device, fstype) for device, target, fstype in mounts if target == PG_MOUNT]
    if len(matches) > 1:
        raise ValueError("stacked_data_mounts")
    if not matches:
        return "mounted_elsewhere" if any(row[0] == number for row in mounts) else "expected_device_unmounted"
    return "expected_ext4_device" if matches[0] == (number, "ext4") else "unexpected_data_mount"


def ceph_configured_mounts():
    raw = kernel.commands_output(["/usr/bin/findmnt", "--fstab", "--noheadings", "--raw", "--output", "FSTYPE"],
                                 limit=16384)
    if any(not re.fullmatch(r"[A-Za-z0-9_.-]+", row) for row in raw.splitlines()):
        raise ValueError("fstab_type_shape")
    return sum(row in CEPH_FILESYSTEMS for row in raw.splitlines())


def ceph_packages():
    raw = kernel.commands_output(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\t${db:Status-Status}\n"], limit=131072)
    if not raw.strip():
        raise ValueError("empty_dpkg_inventory")
    result = {name: False for name in CEPH_PACKAGES}
    for row in raw.splitlines():
        package, status = row.split("\t")
        name = package.split(":", 1)[0]
        if name in result:
            result[name] |= status == "installed"
    return result


def ceph_processes():
    count = 0
    with os.scandir("/proc") as rows:
        for index, row in enumerate(rows):
            if index >= 4096:
                raise ValueError("pid_observation_limit")
            if row.name.isdecimal():
                try:
                    count += int(kernel.read(Path(row.path, "comm"), 256).rstrip("\n") in CEPH_COMM)
                except FileNotFoundError:
                    continue
    return count


def ceph_remote_sockets():
    count = 0
    for protocol in ("tcp", "tcp6"):
        header, *rows = kernel.read("/proc/1/net/" + protocol, 262144).splitlines()
        if "local_address" not in header or not ("rem_address" in header or "remote_address" in header):
            raise ValueError("socket_table_shape")
        for row in rows:
            fields = row.split()
            if len(fields) < 4 or not re.fullmatch(r"[0-9A-Fa-f]+:[0-9A-Fa-f]{4}", fields[2]):
                raise ValueError("socket_row_shape")
            count += int(fields[3] in {"01", "02"} and int(fields[2].rsplit(":", 1)[1], 16) in CEPH_PORTS)
    return count


def modules_disabled():
    value = kernel.read("/proc/sys/kernel/modules_disabled", 32).strip()
    if value not in {"0", "1"}:
        raise ValueError("modules_disabled_shape")
    return value == "1"


def module_helper():
    value = kernel.read("/proc/sys/kernel/modprobe", 4096).strip()
    if value in {"/sbin/modprobe", "/usr/sbin/modprobe"}:
        return "standard"
    return "other" if value else "disabled"


def kmod_rule_state():
    try:
        info = KMOD_RULE.lstat()
    except FileNotFoundError:
        return "absent"
    if (not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_gid != 0
            or stat.S_IMODE(info.st_mode) != 0o644):
        return "different"
    raw = kernel.read(KMOD_RULE, 4096)
    return "reviewed" if hashlib.sha256(raw.encode("ascii")).hexdigest() == KMOD_SHA256 else "different"


def boot_blacklist():
    tokens = kernel.read("/proc/cmdline", 16384).split()
    if "--" in tokens:
        tokens = tokens[:tokens.index("--")]
    parameters = [item.split("=", 1)[-1] for item in tokens if item.startswith("module_blacklist=")]
    if len(parameters) > 1 or any(not re.fullmatch(r"[A-Za-z0-9_,-]+", item) for item in parameters):
        raise ValueError("kernel_blacklist_indeterminate")
    blocked = parameters[0].replace("-", "_").split(",") if parameters else []
    return {module: module in blocked for module in kernel.MODULES}


def dry_run(name, *, blacklist=False):
    command = ["/usr/sbin/modprobe", "--dry-run", "--verbose"]
    if blacklist:
        command.append("--use-blacklist")
    code, raw = kernel.run([*command, "--", name], limit=16384)
    if code != 0:
        return "failed"
    lines = [row.split() for row in raw.splitlines() if row.strip()]
    if not lines:
        return "no_action_reported"
    if lines in ([["install", "/bin/false"]], [["install", "/usr/bin/false"]]):
        return "deny_install"
    return "would_insert" if all(row[0] == "insmod" for row in lines) else "other"


def module_aliases(release, module):
    raw = kernel.commands_output(["/usr/sbin/modinfo", "-k", release, "-F", "alias", module], limit=4096)
    aliases = raw.splitlines()
    # Accept literal aliases only. A wildcard would require a separately reviewed concrete query.
    if len(aliases) > 8 or any(not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_:.+-]{0,127}", item) for item in aliases):
        raise ValueError("unsupported_module_aliases")
    return [dry_run(alias, blacklist=True) for alias in aliases]


def collect():
    baseline = kernel.collect()
    boot, release = baseline["boot_id"], baseline["release"]
    mounts = kernel.optional(storage_mounts)
    report = {"schema": SCHEMA, "kernel": baseline, "xen": {"private_nic_driver": kernel.optional(nic_driver),
              "backend_vifs": kernel.optional(xen_backend_vifs)}, "ceph": {
                  "pid1_mounts": None if mounts is None else sum(row[2] in CEPH_FILESYSTEMS for row in mounts),
                  "fstab_mounts": kernel.optional(ceph_configured_mounts),
                  "packages": kernel.optional(ceph_packages), "named_processes": kernel.optional(ceph_processes),
                  "pid1_canonical_remote_sockets": kernel.optional(ceph_remote_sockets),
                  "data_disk_relation": kernel.optional(lambda: data_disk_relation(mounts))},
              "kmod": {"modules_disabled": kernel.optional(modules_disabled), "helper": kernel.optional(module_helper),
                       "scope_rule": kernel.optional(kmod_rule_state),
                       "boot_blacklist": kernel.optional(boot_blacklist),
                       "dry_run": {module: {"direct": dry_run(module),
                                            "aliases": kernel.optional(lambda: module_aliases(release, module))}
                                   for module in kernel.MODULES}}, "limitations": list(LIMITATIONS)}
    if kernel.identity() != (boot, release):
        raise ValueError("identity_changed")
    return report


def unique_pairs(pairs):
    row = dict(pairs)
    if len(row) != len(pairs):
        raise ValueError("duplicate_consumer_field")
    return row


def validate(raw, expected_boot_id):
    if len(raw) > MAX_OUTPUT:
        raise ValueError("consumer_report_size")
    row = kernel.object_with(json.loads(raw, object_pairs_hook=unique_pairs), ("schema", "kernel", "xen", "ceph", "kmod", "limitations"))
    if row["schema"] != SCHEMA or row["limitations"] != list(LIMITATIONS):
        raise ValueError("consumer_report_scope")
    kernel.validate(json.dumps(row["kernel"]).encode("ascii"), expected_boot_id)
    xen = kernel.object_with(row["xen"], ("private_nic_driver", "backend_vifs"))
    ceph = kernel.object_with(row["ceph"], ("pid1_mounts", "fstab_mounts", "packages", "named_processes",
                                              "pid1_canonical_remote_sockets", "data_disk_relation"))
    kmod = kernel.object_with(row["kmod"], ("modules_disabled", "helper", "scope_rule", "boot_blacklist", "dry_run"))
    if xen["private_nic_driver"] not in {None, *DRIVERS} or ceph["data_disk_relation"] not in {
            None, "expected_device_unmounted", "mounted_elsewhere", "expected_ext4_device", "unexpected_data_mount"}:
        raise ValueError("invalid_consumer_device_state")
    for value in (xen["backend_vifs"], ceph["pid1_mounts"], ceph["fstab_mounts"], ceph["named_processes"],
                  ceph["pid1_canonical_remote_sockets"]):
        if value is not None:
            kernel.count(value)
    if ceph["packages"] is not None:
        packages = kernel.object_with(ceph["packages"], CEPH_PACKAGES)
        if any(type(value) is not bool for value in packages.values()):
            raise ValueError("invalid_package_state")
    if kmod["boot_blacklist"] is not None:
        blacklist = kernel.object_with(kmod["boot_blacklist"], kernel.MODULES)
        if any(type(value) is not bool for value in blacklist.values()):
            raise ValueError("invalid_kernel_blacklist_state")
    if (kmod["modules_disabled"] is not None and type(kmod["modules_disabled"]) is not bool
            or kmod["helper"] not in {None, "standard", "disabled", "other"}
            or kmod["scope_rule"] not in {None, "absent", "different", "reviewed"}):
        raise ValueError("invalid_consumer_state")
    for probe in kernel.object_with(kmod["dry_run"], kernel.MODULES).values():
        kernel.object_with(probe, ("direct", "aliases"))
        aliases = probe["aliases"]
        if probe["direct"] not in PROBE_STATES or (aliases is not None and (
                type(aliases) is not list or len(aliases) > 8 or any(alias not in PROBE_STATES for alias in aliases))):
            raise ValueError("invalid_dry_run_state")
    return row


if __name__ == "__main__":
    try:
        print(json.dumps(collect(), sort_keys=True, separators=(",", ":")))
    except (OSError, UnicodeError, ValueError, KeyError):
        print(json.dumps({"schema": SCHEMA, "error": "NOBLE_KERNEL_CONSUMERS_CONTEXT"}))
        raise SystemExit(2)
