"""Read-only DB-01 Noble state probe for the protected Hito A delivery.

This module is sent as public source through IAP/SSH and runs with sudo.  It
never accepts input, never reads PostgreSQL rows, and emits only the minimum
disk/service metadata needed to choose between first initialization and an
already configured database.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


INSTANCE_ID = "7365414160255801909"
PROJECT_ID = "clipforgebeta2"
PROJECT_NUMBER = "816643438938"
ZONE = "us-central1-a"
DEVICE = Path("/dev/disk/by-id/google-clipforge-noble-pg-data")
JOURNAL = Path("/var/lib/clipforge-postgres/db01/operation.json")
MOUNT = Path("/var/lib/clipforge-postgres/data")
CA = Path("/etc/postgresql/17/main/root.crt")
MAX_OUTPUT = 65536


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("metadata_redirect")


def require(condition, code):
    if not condition:
        raise ValueError(code)


def metadata(route):
    request = Request(
        "http://169.254.169.254/computeMetadata/v1/" + route,
        headers={"Metadata-Flavor": "Google"},
    )
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=3) as response:
        require(response.headers.get("Metadata-Flavor") == "Google", "metadata_origin")
        raw = response.read(1025)
    require(0 < len(raw) <= 1024, "metadata_bound")
    return raw.decode("ascii").strip()


def fixed(command, limit=65536):
    result = subprocess.run(
        command,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        timeout=15,
        check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    require(result.returncode == 0 and len(result.stdout) <= limit and len(result.stderr) <= 8192,
            "probe_command_failed")
    return result.stdout


def regular_bytes(path, limit, *, owners=(0,)):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_uid in owners and not info.st_mode & 0o022
            and info.st_size <= limit, "unsafe_probe_file")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "probe_file_bound")
    return raw


def disk_metadata():
    link = DEVICE.lstat()
    require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0, "disk_link")
    target = DEVICE.resolve(strict=True)
    info = target.stat()
    require(stat.S_ISBLK(info.st_mode), "disk_block")
    major_minor = f"{os.major(info.st_rdev)}:{os.minor(info.st_rdev)}"
    lsblk = json.loads(fixed([
        "/usr/bin/lsblk", "--json", "--bytes", "--output",
        "NAME,KNAME,TYPE,SIZE,FSTYPE,MOUNTPOINTS,MAJ:MIN,SERIAL", str(DEVICE),
    ]))
    signatures = json.loads(fixed(["/usr/sbin/wipefs", "--json", "--no-act", str(DEVICE)]))
    rows = lsblk.get("blockdevices", [])
    require(len(rows) == 1 and rows[0].get("maj:min") == major_minor and rows[0].get("type") == "disk"
            and rows[0].get("size") == 20 * 1024 ** 3, "disk_identity")
    row = rows[0]
    mounts = row.get("mountpoints")
    require(isinstance(mounts, list)
            and all(path is None or isinstance(path, str) and path for path in mounts),
            "disk_mountpoints")
    return {
        "major_minor": major_minor,
        "serial": row.get("serial") or "clipforge-noble-pg-data",
        "fstype": row.get("fstype"),
        "mountpoints": [path for path in mounts if path is not None],
        "signature_count": len(signatures.get("signatures", [])),
    }


def collect():
    identity = {
        "instance_id": metadata("instance/id"),
        "project_id": metadata("project/project-id"),
        "project_number": metadata("project/numeric-project-id"),
        "zone": metadata("instance/zone").rsplit("/", 1)[-1],
    }
    require(identity == {"instance_id": INSTANCE_ID, "project_id": PROJECT_ID,
                         "project_number": PROJECT_NUMBER, "zone": ZONE}, "guest_identity")
    boot_id = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require(re.fullmatch(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}", boot_id), "boot_id")
    disk = disk_metadata()
    journal_status = None
    if JOURNAL.exists():
        journal = json.loads(regular_bytes(JOURNAL, 65536))
        journal_status = journal.get("status")
    active = subprocess.run(
        ["/usr/bin/systemctl", "is-active", "postgresql@17-main.service"],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
        timeout=10, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    ).stdout.decode("ascii", "replace").strip()
    blank = (journal_status is None and disk["fstype"] is None and not disk["mountpoints"]
             and disk["signature_count"] == 0 and not MOUNT.exists())
    configured = (journal_status == "configured_guest_verified_external_acceptance_pending"
                  and active == "active" and disk["fstype"] == "ext4" and str(MOUNT) in disk["mountpoints"])
    require(blank or configured, "database_state_requires_manual_reconciliation")
    ca_sha = None
    if configured:
        from pwd import getpwnam

        ca_sha = hashlib.sha256(regular_bytes(CA, 8192, owners=(0, getpwnam("postgres").pw_uid))).hexdigest()
    return {
        "schema": "clipforge-int-hito-a-db-probe-1",
        "state": "blank" if blank else "configured",
        "identity": identity,
        "boot_id": boot_id,
        "observed_utc": datetime.now(timezone.utc).isoformat(),
        "disk": disk,
        "journal_status": journal_status,
        "postgres_active": active == "active",
        "ca_sha256": ca_sha,
        "read_only": True,
    }


def main():
    try:
        require(sys.platform.startswith("linux") and len(sys.argv) == 1, "probe_invocation")
        value = collect()
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")
        require(len(raw) <= MAX_OUTPUT, "probe_output_bound")
        sys.stdout.buffer.write(raw + b"\n")
        return 0
    except Exception:
        print('{"schema":"clipforge-int-hito-a-db-probe-1","state":"blocked"}')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
