"""Read confined Noble demo prerequisites without touching the services."""
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import sys

if "_noble_kernel_reads" not in globals():
    from scripts import int_noble_kernel_guest as _noble_kernel_reads

kernel = _noble_kernel_reads
SCHEMA = "clipforge-int-noble-demo-preflight-1"
MAX_OUTPUT = 32768
PACKAGE = "linux-tools-common"
CURRENT = "6.8.0-149.149"
TARGET = "6.8.0-151.151"
HUMAN = "admin_ixbalam_studio"
SAMPLES = ("35.235.240.1", "35.235.255.254")


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
    raw = kernel.commands_output(["/usr/sbin/sshd", "-T", "-C", context], limit=16384)
    rows = dict(line.split(None, 1) for line in raw.splitlines() if " " in line)
    forwarding = rows.get("allowtcpforwarding")
    disabled = rows.get("disableforwarding")
    permitted = rows.get("permitopen", "").split()
    if forwarding not in {"yes", "no", "all", "local", "remote"} or disabled not in {"yes", "no"} or not permitted:
        raise ValueError("sshd_forwarding_fields")
    target_allowed = any(rule in {"any", "127.0.0.1:5432", "127.0.0.1:*", "*:5432", "*:*"} for rule in permitted)
    return {"local_forwarding": forwarding in {"yes", "all", "local"} and disabled == "no", "loopback_5432_allowed": target_allowed}


def package_scope():
    raw = kernel.commands_output(["/usr/bin/dpkg-query", "-W", "-f=${Version}\\t${db:Status-Status}\\n", PACKAGE], limit=1024)
    fields = raw.strip().split("\t")
    if len(fields) != 2 or not re.fullmatch(r"[0-9A-Za-z.:+~-]{1,64}", fields[0]) or fields[1] != "installed":
        raise ValueError("dpkg_scope")
    code, plan = kernel.run(["/usr/bin/apt-get", "-s", "--no-download", "--only-upgrade", "install", PACKAGE + "=" + TARGET],
                            budget=12, limit=16384)
    changes = []
    for line in plan.splitlines():
        if line.startswith(("Inst ", "Remv ")):
            changes.append(line)
    expected = re.compile(r"Inst linux-tools-common \[6\.8\.0-149\.149\] \(6\.8\.0-151\.151(?: |\)).*")
    exact = code == 0 and fields[0] == CURRENT and len(changes) == 1 and expected.fullmatch(changes[0]) is not None
    return {"installed": fields[0], "requested": TARGET, "simulate_exit": code, "single_upgrade": exact, "changes": len(changes)}


def grub_scope():
    path = Path("/boot/grub/grub.cfg")
    report = {"uefi": Path("/sys/firmware/efi").is_dir(), "cfg_sha256": None, "cfg_syntax": None,
              "grubenv_read": False, "next_entry_set": None, "saved_entry_set": None}
    if path.is_file():
        with path.open("rb") as stream:
            content = stream.read(1048577)
        if len(content) <= 1048576:
            report["cfg_sha256"] = sha256(content).hexdigest()
        check, _ = kernel.run(["/usr/bin/grub-script-check", str(path)], budget=4, limit=2048)
        if check is not None:
            report["cfg_syntax"] = check == 0
    status, raw = kernel.run(["/usr/bin/grub-editenv", "/boot/grub/grubenv", "list"], limit=4096)
    if status == 0:
        fields = dict(row.split("=", 1) for row in raw.splitlines() if "=" in row)
        report.update(grubenv_read=True, next_entry_set=bool(fields.get("next_entry")), saved_entry_set=bool(fields.get("saved_entry")))
    return report


def collect():
    boot, release = kernel.identity()
    report = {"schema": SCHEMA, "boot_id": boot, "release": release, "exports": kernel.optional(nfs_exports),
              "ssh_samples": {address: kernel.optional(lambda: forwarding(address)) for address in SAMPLES},
              "package": kernel.optional(package_scope), "grub": kernel.optional(grub_scope)}
    if kernel.identity() != (boot, release):
        raise ValueError("guest_changed")
    return report


def nullable(value, expected_type):
    if value is not None and type(value) is not expected_type:
        raise ValueError("preflight_field_type")


def validate(raw, expected_boot_id):
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_OUTPUT:
        raise ValueError("demo_preflight_report_size")

    def object_pairs(pairs):
        result = dict(pairs)
        if len(result) != len(pairs):
            raise ValueError("duplicate_preflight_field")
        return result

    value = kernel.object_with(json.loads(raw.decode("ascii"), object_pairs_hook=object_pairs),
                               ("schema", "boot_id", "release", "exports", "ssh_samples", "package", "grub"))
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
    for row in kernel.object_with(value["ssh_samples"], SAMPLES).values():
        if row is not None and any(type(x) is not bool for x in
                                   kernel.object_with(row, ("local_forwarding", "loopback_5432_allowed")).values()):
            raise ValueError("demo_preflight_ssh_fields")
    if value["package"] is not None:
        pkg = kernel.object_with(value["package"], ("installed", "requested", "simulate_exit", "single_upgrade", "changes"))
        if not re.fullmatch(r"[0-9A-Za-z.:+~-]{1,64}", pkg["installed"]) or pkg["requested"] != TARGET or type(pkg["single_upgrade"]) is not bool:
            raise ValueError("demo_preflight_apt_fields")
        nullable(pkg["simulate_exit"], int)
        kernel.count(pkg["changes"])
        if pkg["single_upgrade"] and (pkg["installed"], pkg["changes"], pkg["simulate_exit"]) != (CURRENT, 1, 0):
            raise ValueError("demo_preflight_apt_scope")
    if value["grub"] is not None:
        flags = kernel.object_with(value["grub"], ("uefi", "cfg_sha256", "cfg_syntax", "grubenv_read", "next_entry_set", "saved_entry_set"))
        for key in ("uefi", "cfg_syntax", "grubenv_read", "next_entry_set", "saved_entry_set"):
            nullable(flags[key], bool)
        if flags["cfg_sha256"] is not None and not re.fullmatch(r"[a-f0-9]{64}", flags["cfg_sha256"]):
            raise ValueError("demo_preflight_grub_hash")
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
