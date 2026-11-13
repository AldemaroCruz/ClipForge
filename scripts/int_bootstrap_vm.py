"""Future, explicitly approved initialization of a NEW private INT PostgreSQL disk.

Run as root on the new VM through protected IAP SSH, with secrets on stdin only.
No existing filesystem/cluster is adopted, formatted, repaired or rotated. A failed
partial initialization stops subsequent attempts for individual review.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import subprocess
import sys

DEVICE = "/dev/disk/by-id/google-clipforge-pg-data"
MOUNT = Path("/var/lib/clipforge-postgres/data")


def require(ok, message):
    if not ok:
        raise ValueError(message)


def blank_disk_contract(disk_id, confirmation, signatures, block_info):
    require(bool(re.fullmatch(r"[1-9][0-9]*", disk_id)) and confirmation == "INITIALIZE_NEW_DISK_" + disk_id,
            "Explicit confirmation of this newly reviewed disk ID is required")
    require(signatures == [], "Existing disk signatures require review; formatting is forbidden")
    rows = block_info.get("blockdevices", [])
    require(len(rows) == 1 and rows[0].get("type") == "disk" and not rows[0].get("fstype")
            and not rows[0].get("children") and not any(rows[0].get("mountpoints") or []),
            "Existing partitions, filesystems or mounts require review")


def command(args, *, payload=None, user=None):
    if user:
        args = ["runuser", "-u", user, "--", *args]
    result = subprocess.run(args, input=payload, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                            timeout=120, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536, "Protected VM command failed; inspect privately without secret logging")
    return result.stdout


def scram(password):
    require(isinstance(password, str) and 32 <= len(password) <= 4096 and password.isascii()
            and all(33 <= ord(ch) <= 126 for ch in password), "Protected database passwords require explicit graphic ASCII input; no SASLprep ambiguity")
    salt = os.urandom(16)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored = hashlib.sha256(client).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    b64 = lambda value: base64.b64encode(value).decode("ascii")
    return "SCRAM-SHA-256$4096:" + b64(salt) + "$" + b64(stored) + ":" + b64(server)


def validate_secrets(value):
    require(isinstance(value, dict) and set(value) == {"app_password", "migrator_password", "server_cert", "server_key", "ca_cert"}, "Exact protected inputs required")
    scram(value["app_password"])
    scram(value["migrator_password"])
    for key in ("ca_cert", "server_cert"):
        require(value[key].startswith("-----BEGIN CERTIFICATE-----\n") and len(value[key]) <= 8192, "Invalid protected TLS certificate")
    require(value["server_key"].startswith("-----BEGIN PRIVATE KEY-----\n") and len(value["server_key"]) <= 8192,
            "Invalid protected TLS server key")


def initialize(value, disk_id, confirmation):
    require(hasattr(os, "geteuid") and os.geteuid() == 0, "Initialization runs only as VM root via protected IAP")
    validate_secrets(value)
    require(Path(DEVICE).is_block_device() and not MOUNT.exists()
            and not Path("/etc/postgresql/17/main").exists(), "Existing installation requires review")
    signatures = json.loads(command(["wipefs", "--json", "--no-act", DEVICE])).get("signatures")
    info = json.loads(command(["lsblk", "--json", "--output", "NAME,TYPE,FSTYPE,MOUNTPOINTS", DEVICE]))
    blank_disk_contract(disk_id, confirmation, signatures, info)
    # Explicit one-time formatting only after the checked dispatch confirmation;
    # never called by startup, Terraform, plan, deploy, or an automatic retry.
    command(["mkfs.ext4", "-L", "clipforge-int-pg", DEVICE])
    uuid = command(["blkid", "-s", "UUID", "-o", "value", DEVICE]).decode().strip()
    require(bool(re.fullmatch(r"[a-f0-9-]{36}", uuid)), "Unexpected new filesystem UUID")
    MOUNT.mkdir(mode=0o700)
    with Path("/etc/fstab").open("a") as stream:
        stream.write("\nUUID=" + uuid + " " + str(MOUNT) + " ext4 defaults,nodev,nosuid,noexec 0 2\n")
    command(["mount", str(MOUNT)])
    marker = {"project": "clipforgebeta2", "disk_id": disk_id, "filesystem_uuid": uuid,
              "state": "initializing", "credential_values": "never recorded"}
    (MOUNT / "clipforge-int-owner.json").write_text(json.dumps(marker) + "\n")
    command(["chown", "postgres:postgres", str(MOUNT)])
    command(["pg_createcluster", "17", "main", "--datadir", str(MOUNT / "pgdata"), "--start-conf=manual"])
    config = Path("/etc/postgresql/17/main")
    for name, key in (("server.crt", "server_cert"), ("server.key", "server_key"), ("root.crt", "ca_cert")):
        target = config / name
        with target.open("xb") as stream:
            stream.write(value[key].encode())
        target.chmod(0o600)
        command(["chown", "postgres:postgres", str(target)])
    command(["openssl", "verify", "-CAfile", str(config / "root.crt"), str(config / "server.crt")])
    command(["openssl", "x509", "-in", str(config / "server.crt"), "-noout", "-checkip", "10.80.1.2"])
    cert_pub = command(["openssl", "x509", "-in", str(config / "server.crt"), "-pubkey", "-noout"])
    key_pub = command(["openssl", "pkey", "-in", str(config / "server.key"), "-pubout"])
    require(cert_pub == key_pub, "TLS certificate and server key differ")
    with (config / "postgresql.conf").open("a") as stream:
        stream.write("\nlisten_addresses='10.80.1.2'\nssl=on\nssl_cert_file='/etc/postgresql/17/main/server.crt'\nssl_key_file='/etc/postgresql/17/main/server.key'\nssl_ca_file='/etc/postgresql/17/main/root.crt'\nssl_min_protocol_version='TLSv1.2'\npassword_encryption='scram-sha-256'\n")
    (config / "pg_hba.conf").write_text("local all postgres peer\n"
        "hostssl clipforge clipforge_app 10.80.0.0/26 scram-sha-256\n"
        "hostssl clipforge clipforge_migrator 10.80.0.0/26 scram-sha-256\n")
    command(["systemctl", "unmask", "postgresql.service", "postgresql@.service"])
    command(["systemctl", "start", "postgresql@17-main"])
    app, migrate = scram(value["app_password"]), scram(value["migrator_password"])
    sql = ("SET log_statement='none'; SET log_min_error_statement='panic';\n"
           "CREATE ROLE clipforge_app LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + app + "';\n"
           "CREATE ROLE clipforge_migrator LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD '" + migrate + "';\n"
           "CREATE DATABASE clipforge OWNER clipforge_migrator;\n")
    command(["psql", "-X", "-q", "--set=ON_ERROR_STOP=1", "--dbname=postgres"], payload=sql.encode(), user="postgres")
    grants = ("REVOKE ALL ON DATABASE clipforge FROM PUBLIC; GRANT CONNECT ON DATABASE clipforge TO clipforge_app;\n"
              "REVOKE CREATE ON SCHEMA public FROM PUBLIC; GRANT USAGE ON SCHEMA public TO clipforge_app;\n"
              "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO clipforge_app;\n"
              "ALTER DEFAULT PRIVILEGES FOR ROLE clipforge_migrator IN SCHEMA public GRANT USAGE,SELECT ON SEQUENCES TO clipforge_app;\n")
    command(["psql", "-X", "-q", "--set=ON_ERROR_STOP=1", "--dbname=clipforge"], payload=grants.encode(), user="postgres")
    marker["state"] = "initialized_requires_migration_and_restore_acceptance"
    (config / "start.conf").write_text("auto\n")
    command(["systemctl", "enable", "postgresql.service"])
    (MOUNT / "clipforge-int-owner.json").write_text(json.dumps(marker) + "\n")
    print("New INT database initialized with SCRAM, retained data disk and verified TLS. Migration/restore acceptance remains required.")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--disk-id", required=True)
    parser.add_argument("--confirmation", required=True)
    args = parser.parse_args(argv)
    os.umask(0o077)
    raw = sys.stdin.buffer.read(32769)
    require(len(raw) <= 32768, "Protected bootstrap input exceeds bound")
    initialize(json.loads(raw), args.disk_id, args.confirmation)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("Protected database initialization stopped. Preserve disk and inspect privately; no automatic retry or repair.", file=sys.stderr)
        raise SystemExit(1)
