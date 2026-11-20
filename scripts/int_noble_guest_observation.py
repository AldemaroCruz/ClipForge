"""Render and validate the read-only Noble GUEST payload from frozen controls."""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from pathlib import Path
import re

from scripts import int_noble_hostkey as host


ROOT = Path(__file__).resolve().parents[1]
SOURCES = {
    "int_guest_inventory_guest.py": "46c5c59346198436cd6c7d7b71d50eadc77b9a1004656b581b19d97fa15c2663",
    "int_guest_db_observe.py": "9ace0c89fb084693acae3ad64a9e20343853b18df9348f108a7caef5eb79d0bd",
}
DEVICE_NAME = "clipforge-noble-pg-data"
BY_ID = "/dev/disk/by-id/google-" + DEVICE_NAME
SIZE_BYTES = 20 * 1024 ** 3
SCHEMA = "clipforge-int-db01-noble-observation-1"
MAX_OUTPUT = 2 * 1024 ** 2
PROJECT_PATH = "projects/" + host.PROJECT
ZONE_PATH = PROJECT_PATH + "/zones/" + host.ZONE
INSTANCE_PATH = ZONE_PATH + "/instances/" + host.INSTANCE
NETWORK_PATH = PROJECT_PATH + "/global/networks/clipforge-int-base"
SUBNET_PATH = PROJECT_PATH + "/regions/us-central1/subnetworks/clipforge-int-base-postgres"
PRIVATE_IP = "10.80.1.3"
GUEST_EMAIL = "clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
SCOPE = "https://www.googleapis.com/auth/userinfo.email"
IMAGE_PATH = "projects/ubuntu-os-cloud/global/images/"
IMAGE_NAME_PATTERN = r"ubuntu-2404-noble-amd64-v[0-9]{8}[a-z]?"
BOOT_DISK = host.INSTANCE + "-boot"
DATA_DISK = host.INSTANCE + "-data"
SECURITY_METADATA = {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE",
                     "disable-legacy-endpoints": "TRUE", "serial-port-enable": "FALSE"}
SHIELDED = {"enableSecureBoot": True, "enableVtpm": True, "enableIntegrityMonitoring": True}
LEGACY_IDS = {"1670495097211408131", "2158164599035219715", "6427691858848206684"}
PACKAGE_VERSIONS = {
    "postgresql-17": "17.12-1.pgdg24.04+1",
    "postgresql-client-17": "17.12-1.pgdg24.04+1",
    "postgresql-common": "297.pgdg24.04+1",
    "postgresql-client-common": "297.pgdg24.04+1",
    "libpq5": "18.7-1.pgdg24.04+2",
    "libxml2": "2.9.14+dfsg-1.3ubuntu3.10",
}
require = host.require


def link_is(value, expected):
    return value in {"https://www.googleapis.com/compute/v1/" + expected,
                     "https://compute.googleapis.com/compute/v1/" + expected}


def timestamp(value):
    require(isinstance(value, str) and len(value) <= 48, "NOBLE_OBSERVER_TIMESTAMP")
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(parsed.utcoffset() is not None, "NOBLE_OBSERVER_TIMESTAMP")
    return parsed


def metadata_map(metadata):
    require(isinstance(metadata, dict) and isinstance(metadata.get("items", []), list), "NOBLE_OBSERVER_METADATA")
    rows = metadata.get("items", [])
    require(len(rows) <= 64 and all(isinstance(row, dict) and set(row) == {"key", "value"}
            and isinstance(row["key"], str) and isinstance(row["value"], str) for row in rows), "NOBLE_OBSERVER_METADATA")
    result = {row["key"]: row["value"] for row in rows}
    require(len(result) == len(rows), "NOBLE_OBSERVER_METADATA_DUPLICATE")
    return result


def control_snapshot(vm, boot, data, project, approved):
    """Validate exact Compute GETs against reviewed plan and post-create identities."""
    ids = {"instance_id", "boot_disk_id", "data_disk_id", "image_id"}
    fields = ids | {"image_name", "startup_sha256", "creation_timestamp", "first_boot_timestamp"}
    require(isinstance(approved, dict) and set(approved) == fields
            and all(isinstance(approved[key], str) and re.fullmatch(host.NUMBER, approved[key]) for key in ids)
            and len({approved[key] for key in ids}) == len(ids) and not LEGACY_IDS.intersection(approved.values())
            and re.fullmatch(IMAGE_NAME_PATTERN, approved["image_name"])
            and re.fullmatch(host.HEX, approved["startup_sha256"]), "NOBLE_OBSERVER_APPROVED_TARGET")
    require(vm["name"] == host.INSTANCE and str(vm["id"]) == approved["instance_id"]
            and link_is(vm["selfLink"], INSTANCE_PATH) and vm["status"] == "RUNNING"
            and link_is(vm["zone"], ZONE_PATH) and link_is(vm["machineType"], ZONE_PATH + "/machineTypes/e2-small")
            and vm["deletionProtection"] is True and vm["canIpForward"] is False
            and vm["shieldedInstanceConfig"] == SHIELDED, "NOBLE_OBSERVER_VM")
    require(vm["creationTimestamp"] == approved["creation_timestamp"]
            and vm["lastStartTimestamp"] == approved["first_boot_timestamp"]
            and timestamp(vm["lastStartTimestamp"]) >= timestamp(vm["creationTimestamp"]), "NOBLE_OBSERVER_FIRST_BOOT")
    interfaces = vm["networkInterfaces"]
    require(len(interfaces) == 1 and interfaces[0]["networkIP"] == PRIVATE_IP
            and link_is(interfaces[0]["network"], NETWORK_PATH) and link_is(interfaces[0]["subnetwork"], SUBNET_PATH)
            and interfaces[0].get("stackType", "IPV4_ONLY") == "IPV4_ONLY"
            and not any(interfaces[0].get(key) for key in ("accessConfigs", "ipv6AccessConfigs", "ipv6Address", "aliasIpRanges"))
            and vm["serviceAccounts"] == [{"email": GUEST_EMAIL, "scopes": [SCOPE]}], "NOBLE_OBSERVER_NETWORK_OR_SA")
    fingerprint = vm["metadata"].get("fingerprint")
    require(isinstance(fingerprint, str) and 0 < len(fingerprint) <= 256, "NOBLE_OBSERVER_METADATA_FINGERPRINT")
    own = metadata_map(vm["metadata"])
    inherited = metadata_map(project["commonInstanceMetadata"])
    require(project["name"] == host.PROJECT and str(project["id"]) == host.PROJECT_NUMBER
            and set(own) == set(SECURITY_METADATA) | {"startup-script"}
            and all(own[key] == value for key, value in SECURITY_METADATA.items())
            and host.sha(own["startup-script"].encode("utf-8")) == approved["startup_sha256"]
            and not any(key.startswith(("startup-script", "shutdown-script")) for key in inherited)
            and inherited.get("enable-guest-attributes", "FALSE").upper() == "FALSE", "NOBLE_OBSERVER_STARTUP_OR_METADATA")
    attachments = vm["disks"]
    require(len(attachments) == 2 and [item["index"] for item in attachments] == [0, 1]
            and all(type(item["index"]) is int for item in attachments), "NOBLE_OBSERVER_ATTACHMENTS")
    for position, disk, name, id_key, device, size in (
        (0, boot, BOOT_DISK, "boot_disk_id", "clipforge-noble-pg-boot", 10),
        (1, data, DATA_DISK, "data_disk_id", DEVICE_NAME, 20),
    ):
        attachment = attachments[position]
        path = ZONE_PATH + "/disks/" + name
        require(disk["name"] == name and str(disk["id"]) == approved[id_key] and disk["status"] == "READY"
                and link_is(disk["selfLink"], path) and link_is(disk["zone"], ZONE_PATH)
                and link_is(disk["type"], ZONE_PATH + "/diskTypes/pd-standard") and str(disk["sizeGb"]) == str(size)
                and len(disk["users"]) == 1 and link_is(disk["users"][0], INSTANCE_PATH)
                and link_is(attachment["source"], path) and attachment["deviceName"] == device
                and attachment["boot"] is (position == 0) and attachment["autoDelete"] is False
                and attachment["interface"] == "SCSI" and attachment["mode"] == "READ_WRITE", "NOBLE_OBSERVER_DISK")
    require(str(boot["sourceImageId"]) == approved["image_id"]
            and link_is(boot["sourceImage"], IMAGE_PATH + approved["image_name"])
            and not any(data.get(key) for key in ("sourceImage", "sourceImageId", "sourceSnapshot", "sourceSnapshotId",
                                                   "sourceDisk", "sourceDiskId", "sourceStorageObject")), "NOBLE_OBSERVER_IMAGE_OR_DATA_SOURCE")
    # Keep no raw Compute metadata in the receipt. The digest detects concurrent
    # changes to approved/effective metadata during the serial and SSH intervals.
    selected = {"approved": approved, "own_metadata": own, "inherited_metadata": inherited,
                "fingerprint": fingerprint, "attachments": attachments, "interfaces": interfaces}
    snapshot = json.dumps(selected, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    return {"instance_id": approved["instance_id"], "boot_disk_id": approved["boot_disk_id"],
            "data_disk_id": approved["data_disk_id"], "boot_timestamp": approved["first_boot_timestamp"],
            "attachment_device": DEVICE_NAME, "attachment_size_bytes": SIZE_BYTES,
            "attachment_interface": "SCSI", "attachment_index": 1, "attachment_mode": "READ_WRITE",
            "attachment_boot": False, "attachment_auto_delete": False, "snapshot_sha256": host.sha(snapshot)}


def host_receipt(serial, *, before, after, nonce, publisher_sha256):
    """Extract only the first-boot host record between matching Compute GETs."""
    require(before == after and isinstance(before, dict) and re.fullmatch(host.HEX, before["snapshot_sha256"]),
            "NOBLE_OBSERVER_CONTROL_PLANE_CHANGED")
    record = host.serial_record(serial, instance_id=before["instance_id"], nonce=nonce,
                                publisher_sha256=publisher_sha256)
    return {"schema": "clipforge-int-noble-hostkey-evidence-1", "control_plane": before, "record": record,
            "known_hosts_line": host.INSTANCE + "." + before["instance_id"] + " " + record["public_key"] + "\n"}


def checked_source(name):
    raw = (ROOT / "scripts" / name).read_bytes()
    require(hashlib.sha256(raw).hexdigest() == SOURCES[name], "NOBLE_OBSERVER_LEGACY_BYTES_CHANGED")
    return raw


def replace_exact(raw, before, after, count):
    require(raw.count(before) == count, "NOBLE_OBSERVER_LEGACY_SHAPE_CHANGED")
    return raw.replace(before, after)


def payload_bytes():
    base = checked_source("int_guest_inventory_guest.py")
    base = replace_exact(base, b'"debian"', b'"ubuntu"', 3)
    base = replace_exact(base, b'"trixie"', b'"noble"', 3)
    observer = checked_source("int_guest_db_observe.py")
    # Legacy control-plane and standalone entry points are strictly Debian.
    require(observer.count(b"\ndef make_evidence(") == 1, "NOBLE_OBSERVER_LEGACY_SHAPE_CHANGED")
    observer = observer.split(b"\ndef make_evidence(", 1)[0]
    observer = replace_exact(observer, b"/dev/disk/by-id/google-clipforge-pg-data", BY_ID.encode("ascii"), 1)
    observer = replace_exact(observer, b"clipforge-int-db01-observation-1", SCHEMA.encode("ascii"), 1)
    prefix = (
        "import signal, sys, types\n"
        "def guest_module(name, raw, **attrs):\n"
        "    module = types.ModuleType(name)\n"
        "    module.__dict__.update(attrs)\n"
        "    sys.modules[name] = module\n"
        "    try:\n"
        "        exec(compile(raw, name, 'exec'), module.__dict__)\n"
        "    finally:\n"
        "        del sys.modules[name]\n"
        "    return module\n"
        f"base = guest_module('_clipforge_noble_base', {base!r})\n"
        f"observer = guest_module('_clipforge_noble_observer', {observer!r}, __clipforge_readonly_base__=base)\n"
        "def expired(_number, _frame):\n"
        "    raise ValueError('TOTAL_TIME')\n"
        "if __name__ == '__main__':\n"
        "    if not sys.platform.startswith('linux') or len(sys.argv) != 1:\n"
        "        raise SystemExit('NOBLE_GUEST_PLATFORM_OR_ARGUMENTS')\n"
        "    previous = signal.signal(signal.SIGALRM, expired)\n"
        "    signal.setitimer(signal.ITIMER_REAL, 120)\n"
        "    try:\n"
        "        report = observer.collect()\n"
        "    finally:\n"
        "        signal.setitimer(signal.ITIMER_REAL, 0)\n"
        "        signal.signal(signal.SIGALRM, previous)\n"
        "    observer.validate_report(report)\n"
        "    sys.stdout.buffer.write(base.encoded(report) + b'\\n')\n"
        "    sys.stdout.buffer.flush()\n"
        "    raise SystemExit(report['exit_code'])\n"
    )
    return prefix.encode("ascii")


def validate_guest(raw, exit_code, *, host_record, expected_payload_sha256):
    """Validate a bounded result associated with this exact boot and SSH payload."""
    payload = payload_bytes()
    require(host.sha(payload) == expected_payload_sha256 and type(exit_code) is int
            and isinstance(raw, bytes) and len(raw) <= MAX_OUTPUT, "NOBLE_OBSERVER_PAYLOAD_OR_OUTPUT")
    scope = {"__name__": "_clipforge_noble_validation"}
    exec(compile(payload, "noble_readonly_payload", "exec"), scope)
    report = scope["observer"].validate_report(host.closed_json(raw))
    require(report["exit_code"] == exit_code, "NOBLE_OBSERVER_EXIT_MISMATCH")
    if exit_code != 0:
        return report
    inventory = report["base_inventory"]["inventory"]
    require(inventory["os_release"]["VERSION_ID"] == "24.04" and inventory["kernel"]["machine"] == "x86_64"
            and report["guest_boot_id"] == host_record["guest_boot_id"], "NOBLE_OBSERVER_RELEASE_OR_BOOT")
    selected = {}
    for row in report["packages_source"]:
        name = row["binary_name"].split(":", 1)[0]
        if name in PACKAGE_VERSIONS:
            require(name not in selected, "NOBLE_OBSERVER_PACKAGE_AMBIGUOUS")
            selected[name] = row["binary_version"]
            require(row["status_abbrev"] == "ii " and row["architecture"] in {"amd64", "all"},
                    "NOBLE_OBSERVER_PACKAGE_STATUS")
        elif re.fullmatch(r"postgresql-(?:client-)?[0-9]+", name):
            raise ValueError("NOBLE_OBSERVER_UNEXPECTED_POSTGRES_MAJOR")
    require(selected == PACKAGE_VERSIONS, "NOBLE_OBSERVER_PACKAGE_CHANGED")
    disk = report["disk"]
    row = disk["lsblk"]["blockdevices"][0]
    serials = [value for value in (disk["before"]["serial"], row["serial"], disk["udev"].get("ID_SERIAL_SHORT")) if value]
    require(disk["before"]["by_id"] == BY_ID and row["size"] == SIZE_BYTES
            and serials and all(value == DEVICE_NAME for value in serials), "NOBLE_OBSERVER_ATTACHMENT_SERIAL")
    return report


def linked_observation(raw, exit_code, *, before, after, pin_receipt, workflow_commit, expected_payload_sha256):
    """Bind the sanitized, separately checked Compute attachment to the guest."""
    fields = {"instance_id", "boot_disk_id", "data_disk_id", "boot_timestamp", "attachment_device",
              "attachment_size_bytes", "attachment_interface", "attachment_index", "attachment_mode",
              "attachment_boot", "attachment_auto_delete", "snapshot_sha256"}
    require(isinstance(before, dict) and set(before) == fields and before == after
            and len({before[key] for key in ("instance_id", "boot_disk_id", "data_disk_id")}) == 3
            and all(re.fullmatch(host.NUMBER, before[key]) for key in ("instance_id", "boot_disk_id", "data_disk_id"))
            and re.fullmatch(host.HEX, before["snapshot_sha256"]), "NOBLE_OBSERVER_CONTROL_PLANE_CHANGED")
    require(isinstance(pin_receipt, dict) and pin_receipt.get("schema") == "clipforge-int-noble-hostkey-evidence-1"
            and pin_receipt.get("control_plane") == before, "NOBLE_OBSERVER_HOST_RECEIPT_CHANGED")
    record = pin_receipt["record"]
    report = validate_guest(raw, exit_code, host_record=record, expected_payload_sha256=expected_payload_sha256)
    require(before["instance_id"] == record["instance_id"] and report["status"] == "observation_complete"
            and before["attachment_device"] == DEVICE_NAME and before["attachment_size_bytes"] == SIZE_BYTES
            and before["attachment_interface"] == "SCSI" and type(before["attachment_index"]) is int
            and before["attachment_index"] == 1 and before["attachment_mode"] == "READ_WRITE"
            and before["attachment_boot"] is False and before["attachment_auto_delete"] is False,
            "NOBLE_OBSERVER_ATTACHMENT_OR_HOST")
    require(re.fullmatch(r"[0-9a-f]{40}", workflow_commit) and host.sha(payload_bytes()) == expected_payload_sha256,
            "NOBLE_OBSERVER_SOURCE_BINDING")
    principal = {"project": host.PROJECT, "project_number": host.PROJECT_NUMBER, "zone": host.ZONE, "name": host.INSTANCE}
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii") + b"\n"
    return {"schema": "clipforge-int-db01-noble-evidence-1", "target": principal, "control_plane": before,
            "guest": report, "guest_sha256": host.sha(canonical), "payload_sha256": expected_payload_sha256,
            "workflow_commit": workflow_commit, "read_only": True, "runtime_authorized": False}
