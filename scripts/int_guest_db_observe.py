"""Fixed, bounded DB-01 disk/package observations; never writes guest data.

The hosted GUEST transport embeds the unchanged baseline inventory module before
this source. Local imports are only for pure validation/tests, never remote code.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

if "__clipforge_readonly_base__" in globals():
    g = globals()["__clipforge_readonly_base__"]
else:
    from scripts import int_guest_inventory_guest as g

SCHEMA = "clipforge-int-db01-observation-1"
EVIDENCE_SCHEMA = "clipforge-int-db01-evidence-1"
DEVICE = "/dev/disk/by-id/google-clipforge-pg-data"
SIZE = 21474836480
FIELDS = ("binary_name", "binary_version", "source_name", "source_version", "architecture", "status", "status_abbrev")
EXTRA = {
    "packages_source": ("/usr/bin/dpkg-query", "--show", "--showformat=${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${Architecture}\t${Status}\t${db:Status-Abbrev}\n"),
    "disk_lsblk": ("/usr/bin/lsblk", "--json", "--bytes", "--output", "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MAJ:MIN,SERIAL", DEVICE),
    "disk_signatures": ("/usr/sbin/wipefs", "--json", "--no-act", DEVICE),
    "disk_udev": ("/usr/bin/udevadm", "info", "--query=property", "--name=" + DEVICE),
}
UDEV = {"DEVNAME", "DEVPATH", "DEVTYPE", "MAJOR", "MINOR", "ID_BUS", "ID_MODEL", "ID_MODEL_ENC", "ID_SERIAL", "ID_SERIAL_SHORT", "ID_VENDOR", "ID_WWN", "ID_PATH"}
WANT = {"unknown": "u", "install": "i", "hold": "h", "deinstall": "r", "purge": "p"}
STATE = {"not-installed": "n", "config-files": "c", "half-installed": "H", "unpacked": "U", "half-configured": "F", "triggers-awaited": "W", "triggers-pending": "t", "installed": "i"}
ERROR = {"ok": " ", "reinstreq": "R"}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def parse_packages(raw):
    rows, names = [], set()
    for line in raw.decode("utf-8").splitlines():
        parts = line.split("\t")
        require(len(parts) == 7, "PACKAGE_COLUMNS")
        row = dict(zip(FIELDS, parts))
        require(re.fullmatch(r"[a-z0-9][a-z0-9+.-]*(?::[a-z0-9][a-z0-9-]*)?", row["binary_name"])
                and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", row["binary_version"])
                and re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", row["architecture"]), "PACKAGE_IDENTITY")
        require((row["source_name"] == row["source_version"] == "") or
                re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", row["source_name"])
                and re.fullmatch(r"[A-Za-z0-9.+:~_-]{1,256}", row["source_version"]), "PACKAGE_SOURCE")
        status = row["status"].split(" ")
        require(len(status) == 3 and status[0] in WANT and status[1] in ERROR and status[2] in STATE, "PACKAGE_STATUS")
        require(row["status_abbrev"] == WANT[status[0]] + STATE[status[2]] + ERROR[status[1]], "PACKAGE_STATUS_ABBREVIATION")
        require(row["binary_name"] not in names and len(rows) < 16384, "PACKAGE_DUPLICATE_OR_LIMIT")
        names.add(row["binary_name"]); rows.append(row)
    require(rows, "PACKAGE_EMPTY")
    return rows


def _metadata(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "METADATA_BOUND")
    value = raw.decode("ascii").strip()
    require(value and not re.search(r"[\x00-\x1f\x7f]", value), "METADATA_TEXT")
    return value


def read_disk_metadata():
    for path in ("/dev", "/dev/disk", "/dev/disk/by-id"):
        info = Path(path).lstat()
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and not info.st_mode & 0o022, "DEVICE_PARENT")
    link = Path(DEVICE).lstat()
    require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0, "DEVICE_LINK")
    device = str(Path(DEVICE).resolve(strict=True)); info = os.stat(DEVICE)
    require(re.fullmatch(r"/dev/[a-zA-Z0-9_-]{1,64}", device) and stat.S_ISBLK(info.st_mode), "DEVICE_BLOCK")
    number = str(os.major(info.st_rdev)) + ":" + str(os.minor(info.st_rdev))
    sysfs = Path("/sys/dev/block") / number
    require(sysfs.is_dir(), "DEVICE_SYSFS")
    holders = sorted(path.name for path in (sysfs / "holders").iterdir())
    require(len(holders) <= 32 and all(re.fullmatch(r"[a-zA-Z0-9_-]{1,64}", item) for item in holders), "HOLDERS_BOUND")
    root = os.stat("/").st_dev
    root_number = str(os.major(root)) + ":" + str(os.minor(root))
    try:
        serial = _metadata(sysfs / "device/serial", 256)
    except FileNotFoundError:
        serial = None  # Some SCSI drivers expose serial only through udev/lsblk.
    return {"by_id": DEVICE, "device": device, "major_minor": number, "sysfs": str(sysfs.resolve(strict=True)),
            "serial": serial, "size_sectors": _metadata(sysfs / "size", 32),
            "holders": holders, "root_major_minor": root_number,
            "root_sysfs": str((Path("/sys/dev/block") / root_number).resolve(strict=True))}


def parse_udev(raw):
    values = {}
    for line in raw.decode("ascii").splitlines():
        require("=" in line and len(line) <= 4096, "UDEV_LINE")
        key, value = line.split("=", 1)
        if key in UDEV:
            require(key not in values and len(value) <= 1024 and not re.search(r"[\x00-\x1f\x7f]", value), "UDEV_VALUE")
            values[key] = value
    return values


def validate_disk(disk):
    require(isinstance(disk, dict) and set(disk) == {"before", "after", "lsblk", "signatures", "udev", "identity_confirmed"}, "DISK_FIELDS")
    before = disk["before"]
    require(isinstance(before, dict) and set(before) == {"by_id", "device", "major_minor", "sysfs", "serial", "size_sectors", "holders", "root_major_minor", "root_sysfs"}
            and before == disk["after"], "DISK_CHANGED")
    require(before["by_id"] == DEVICE and re.fullmatch(r"/dev/[a-zA-Z0-9_-]{1,64}", before["device"])
            and re.fullmatch(r"[0-9]+:[0-9]+", before["major_minor"]) and re.fullmatch(r"[0-9]+:[0-9]+", before["root_major_minor"]), "DISK_IDENTITY")
    require(all(isinstance(before[key], str) and before[key].startswith("/sys/devices/") and ".." not in before[key].split("/") and len(before[key]) <= 1024 for key in ("sysfs", "root_sysfs")), "DISK_SYSFS_PATH")
    require(before["major_minor"] != before["root_major_minor"] and before["root_sysfs"] != before["sysfs"]
            and not before["root_sysfs"].startswith(before["sysfs"] + "/"), "ROOT_DISK")
    require((before["serial"] is None or isinstance(before["serial"], str) and 0 < len(before["serial"]) <= 256 and not re.search(r"[\x00-\x1f\x7f]", before["serial"]))
            and before["size_sectors"].isdigit() and int(before["size_sectors"]) * 512 == SIZE and before["holders"] == [], "DISK_SIZE_SERIAL_HOLDERS")
    require(isinstance(disk["lsblk"], dict) and set(disk["lsblk"]) == {"blockdevices"}, "LSBLK_FIELDS")
    rows = disk["lsblk"]["blockdevices"]
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), "LSBLK_DEVICE")
    row = rows[0]
    require(set(row) <= {"name", "kname", "type", "size", "fstype", "mountpoints", "maj:min", "serial", "children"}
            and {"name", "kname", "type", "size", "fstype", "mountpoints", "maj:min", "serial"} <= set(row), "LSBLK_FIELDS")
    require("/dev/" + row["kname"] == before["device"] and row["name"] == row["kname"]
            and row["maj:min"] == before["major_minor"] and row["type"] == "disk" and type(row["size"]) is int
            and row["size"] == SIZE and row["fstype"] is None and not row.get("children")
            and isinstance(row["mountpoints"], list) and not any(row["mountpoints"]), "DISK_IN_USE")
    require(isinstance(disk["signatures"], dict) and set(disk["signatures"]) == {"signatures"} and disk["signatures"]["signatures"] == [], "DISK_SIGNATURES")
    udev = disk["udev"]
    require(isinstance(udev, dict) and set(udev) <= UDEV and all(isinstance(v, str) and len(v) <= 1024 for v in udev.values())
            and udev.get("DEVNAME") == before["device"] and udev.get("DEVTYPE") == "disk"
            and udev.get("MAJOR", "") + ":" + udev.get("MINOR", "") == before["major_minor"], "UDEV_DISCORDANCE")
    serials = [value for value in (before["serial"], row["serial"], udev.get("ID_SERIAL_SHORT")) if value is not None and value != ""]
    require(serials and all(isinstance(value, str) and 0 < len(value) <= 256 and not re.search(r"[\x00-\x1f\x7f]", value) for value in serials)
            and len(set(serials)) == 1, "SERIAL_DISCORDANCE")
    require(disk["identity_confirmed"] is True, "DISK_IDENTITY_UNCONFIRMED")
    return disk


def collect(*, base_runner=None, runner=None, disk_reader=None, boot_reader=None, clock=None, base_metadata_reader=None, base_release_reader=None):
    clock = clock or g.time.monotonic; start = clock(); deadline = start + 120
    baseline = g.collect(runner=base_runner, metadata_reader=base_metadata_reader, release_reader=base_release_reader, clock=clock)
    report = {"schema": SCHEMA, "status": "observation_blocked", "exit_code": 2,
              "observed_utc": datetime.now(timezone.utc).isoformat(), "guest_boot_id": None,
              "base_inventory": baseline, "disk": None, "packages_source": None, "commands": [],
              "error_code": None, "read_only": True}
    if baseline["status"] != "inventory_complete":
        report["error_code"] = "BASELINE_UNSAFE_OR_INCOMPLETE"; return report
    saved = dict(g.COMMANDS)
    try:
        g.COMMANDS.update(EXTRA)
        def query(key):
            require(clock() < deadline - 1, "TOTAL_TIME")
            result = (runner or g.run_fixed)(key, timeout_seconds=15, stdout_limit=1048576, stderr_limit=8192, deadline=deadline, clock=clock)
            report["commands"].append({"key": key, "status": result.status, "exit_code": result.exit_code,
                "stdout_bytes": len(result.stdout), "stdout_sha256": sha(result.stdout), "stderr_bytes": len(result.stderr),
                "stderr_sha256": sha(result.stderr), "stderr_diagnostic": g.sanitized_stderr(result.stderr), "duration_ms": result.duration_ms})
            require(result.status == "ok" and result.exit_code == 0 and len(result.stdout) <= 1048576 and len(result.stderr) <= 8192, "READ_QUERY_FAILED")
            return result.stdout
        report["packages_source"] = parse_packages(query("packages_source"))
        expected = sorted(baseline["inventory"]["packages"])
        actual = sorted([row["binary_name"], row["binary_version"], row["status"].split(" ")[-1], row["architecture"]] for row in report["packages_source"])
        require(actual == expected, "PACKAGES_CHANGED_DURING_CAPTURE")
        report["guest_boot_id"] = (boot_reader or (lambda: _metadata("/proc/sys/kernel/random/boot_id", 64)))()
        require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", report["guest_boot_id"]), "BOOT_ID")
        read = disk_reader or read_disk_metadata
        before = read()
        disk = {"before": before, "after": None, "lsblk": g._json(query("disk_lsblk")),
                "signatures": g._json(query("disk_signatures")), "udev": parse_udev(query("disk_udev")), "identity_confirmed": True}
        disk["after"] = read(); validate_disk(disk)
        report["disk"] = disk
        require(clock() < deadline and (boot_reader or (lambda: _metadata("/proc/sys/kernel/random/boot_id", 64)))() == report["guest_boot_id"], "BOOT_OR_TIME_CHANGED")
        report.update(status="observation_complete", exit_code=0)
    except (ValueError, OSError, TypeError, UnicodeError, KeyError) as error:
        code = str(error)
        report["error_code"] = code if re.fullmatch(r"[A-Z_]{3,80}", code) else "READ_OBSERVATION_FAILED"
    finally:
        g.COMMANDS.clear(); g.COMMANDS.update(saved)
    return report


def validate_report(value):
    require(isinstance(value, dict) and set(value) == {"schema", "status", "exit_code", "observed_utc", "guest_boot_id", "base_inventory", "disk", "packages_source", "commands", "error_code", "read_only"}
            and value["schema"] == SCHEMA and value["read_only"] is True, "OBSERVATION_FIELDS")
    require(value["status"] in {"observation_complete", "observation_blocked"} and type(value["exit_code"]) is int
            and value["exit_code"] == (0 if value["status"] == "observation_complete" else 2), "OBSERVATION_STATUS")
    require(isinstance(value["observed_utc"], str) and len(value["observed_utc"]) <= 40
            and datetime.fromisoformat(value["observed_utc"]).utcoffset().total_seconds() == 0, "OBSERVATION_TIME")
    g.validate_report(value["base_inventory"])
    rows = value["packages_source"]
    if rows is not None:
        require(isinstance(rows, list) and all(isinstance(row, dict) and set(row) == set(FIELDS) and all(isinstance(v, str) for v in row.values()) for row in rows), "PACKAGE_FIELDS")
        require(parse_packages(("\n".join("\t".join(row[key] for key in FIELDS) for row in rows) + "\n").encode()) == rows, "PACKAGE_REPORT")
    require(isinstance(value["commands"], list) and len(value["commands"]) <= len(EXTRA), "OBSERVATION_COMMANDS")
    keys = []
    for row in value["commands"]:
        require(isinstance(row, dict) and set(row) == {"key", "status", "exit_code", "stdout_bytes", "stdout_sha256", "stderr_bytes", "stderr_sha256", "stderr_diagnostic", "duration_ms"}
                and row["key"] in EXTRA and row["key"] not in keys and row["status"] in g.PROCESS_STATUSES
                and (row["exit_code"] is None or type(row["exit_code"]) is int), "OBSERVATION_COMMAND")
        for field, bound in (("stdout_bytes", 1048576), ("stderr_bytes", 8192), ("duration_ms", 15000)):
            require(type(row[field]) is int and 0 <= row[field] <= bound, "OBSERVATION_BOUNDS")
        require(all(isinstance(row[field], str) and re.fullmatch(r"[a-f0-9]{64}", row[field]) for field in ("stdout_sha256", "stderr_sha256"))
                and isinstance(row["stderr_diagnostic"], dict) and set(row["stderr_diagnostic"]) == {"messages", "unclassified_lines"}, "OBSERVATION_DIAGNOSTIC")
        diagnostic = row["stderr_diagnostic"]
        require(isinstance(diagnostic["messages"], list) and len(diagnostic["messages"]) <= 16
                and all(isinstance(item, str) and g.STDERR_PATTERN.fullmatch(item) for item in diagnostic["messages"])
                and type(diagnostic["unclassified_lines"]) is int and 0 <= diagnostic["unclassified_lines"] <= 8192, "OBSERVATION_DIAGNOSTIC")
        keys.append(row["key"])
    if value["status"] == "observation_complete":
        require(value["error_code"] is None and value["base_inventory"]["status"] == "inventory_complete"
                and keys == list(EXTRA) and all(row["status"] == "ok" and row["exit_code"] == 0 for row in value["commands"])
                and re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", value["guest_boot_id"] or ""), "OBSERVATION_INCOMPLETE")
        validate_disk(value["disk"])
        expected = sorted(value["base_inventory"]["inventory"]["packages"])
        require(sorted([row["binary_name"], row["binary_version"], row["status"].split(" ")[-1], row["architecture"]] for row in rows) == expected, "PACKAGE_SNAPSHOT_MISMATCH")
    else:
        require(isinstance(value["error_code"], str) and re.fullmatch(r"[A-Z_]{3,80}", value["error_code"]), "OBSERVATION_ERROR")
    require(len(g.encoded(value)) <= g.TOTAL_OUTPUT_LIMIT, "OBSERVATION_SIZE")
    return value


def make_evidence(report, vm, boot, data, *, observed_utc, commit, payload_sha256):
    validate_report(report)
    from scripts import int_guest_inventory as transport
    transport.host.identity(vm, boot, data)
    attachment = next(row for row in vm["disks"] if row.get("deviceName") == "clipforge-pg-data")
    require(re.fullmatch(r"[a-f0-9]{40}", commit) and re.fullmatch(r"[a-f0-9]{64}", payload_sha256), "SOURCE_BINDING")
    return {"schema": EVIDENCE_SCHEMA, "guest": report, "guest_report_sha256": sha(g.encoded(report) + b"\n"),
            "control_plane": {"project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a",
                "instance_id": str(vm["id"]), "boot_timestamp": vm["lastStartTimestamp"], "disk_id": str(data["id"]),
                "disk_name": data["name"], "disk_type": data["type"], "size_bytes": int(data["sizeGb"]) * 1073741824,
                "attachment": {key: attachment.get(key) for key in ("deviceName", "source", "interface", "index", "mode", "boot", "autoDelete")},
                "observed_utc": observed_utc}, "source": {"commit": commit, "payload_sha256": payload_sha256}}


def disk_proof(evidence):
    require(isinstance(evidence, dict) and set(evidence) == {"schema", "guest", "guest_report_sha256", "control_plane", "source"}
            and evidence["schema"] == EVIDENCE_SCHEMA, "EVIDENCE_FIELDS")
    guest = validate_report(evidence["guest"])
    require(guest["status"] == "observation_complete" and sha(g.encoded(guest) + b"\n") == evidence["guest_report_sha256"], "GUEST_RECEIPT_INTEGRITY")
    cp, source = evidence["control_plane"], evidence["source"]
    require(isinstance(cp, dict) and set(cp) == {"project_id", "project_number", "zone", "instance_id", "boot_timestamp", "disk_id", "disk_name", "disk_type", "size_bytes", "attachment", "observed_utc"}
            and cp["project_id"] == "clipforgebeta2" and cp["project_number"] == "816643438938"
            and cp["zone"] == "us-central1-a" and cp["instance_id"] == "1670495097211408131" and cp["disk_id"] == "6427691858848206684"
            and cp["disk_name"] == "clipforge-int-base-postgres-data" and cp["size_bytes"] == SIZE
            and cp["disk_type"] == "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard", "CONTROL_PLANE_DISK")
    a = cp["attachment"]
    require(isinstance(cp["boot_timestamp"], str) and datetime.fromisoformat(cp["boot_timestamp"]).utcoffset() is not None
            and isinstance(cp["observed_utc"], str) and datetime.fromisoformat(cp["observed_utc"]).utcoffset().total_seconds() == 0, "CONTROL_PLANE_TIME")
    require(a == {"deviceName": "clipforge-pg-data", "source": "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/disks/clipforge-int-base-postgres-data", "interface": "SCSI", "index": 1, "mode": "READ_WRITE", "boot": False, "autoDelete": False}, "CONTROL_PLANE_ATTACHMENT")
    require(type(a["index"]) is int and type(a["boot"]) is bool and type(a["autoDelete"]) is bool, "CONTROL_PLANE_ATTACHMENT_TYPES")
    require(isinstance(source, dict) and set(source) == {"commit", "payload_sha256"}
            and re.fullmatch(r"[a-f0-9]{40}", source["commit"]) and re.fullmatch(r"[a-f0-9]{64}", source["payload_sha256"]), "SOURCE_BINDING")
    d = guest["disk"]["before"]
    serial = next(value for value in (d["serial"], guest["disk"]["lsblk"]["blockdevices"][0]["serial"], guest["disk"]["udev"].get("ID_SERIAL_SHORT")) if value)
    return {"project_id": cp["project_id"], "project_number": cp["project_number"], "zone": cp["zone"], "instance_id": cp["instance_id"],
            "boot_timestamp": cp["boot_timestamp"], "guest_boot_id": guest["guest_boot_id"], "disk_id": cp["disk_id"], "disk_name": cp["disk_name"],
            "disk_type": cp["disk_type"], "device_name": a["deviceName"], "size_bytes": SIZE, "interface": a["interface"], "index": a["index"],
            "mode": a["mode"], "boot": a["boot"], "auto_delete": a["autoDelete"], "observed_utc": guest["observed_utc"],
            "guest_major_minor": d["major_minor"], "guest_serial": serial, "guest_by_id": DEVICE,
            "guest_read_receipt_sha256": sha(g.encoded(evidence) + b"\n"), "guest_read_source_sha256": source["payload_sha256"]}


def main():
    require(sys.platform.startswith("linux") and len(sys.argv) == 1, "PLATFORM_OR_ARGUMENTS")
    def expired(_signum, _frame):
        raise ValueError("TOTAL_TIME")
    previous = g.signal.signal(g.signal.SIGALRM, expired); g.signal.setitimer(g.signal.ITIMER_REAL, 120)
    try:
        report = collect()
    finally:
        g.signal.setitimer(g.signal.ITIMER_REAL, 0); g.signal.signal(g.signal.SIGALRM, previous)
    validate_report(report); sys.stdout.buffer.write(g.encoded(report) + b"\n"); sys.stdout.buffer.flush()
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
