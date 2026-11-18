#!/usr/bin/python3
"""One-purpose startup publisher. Rendered binding required; never runs on import."""
import base64
import hashlib
import http.client
import json
import os
import re
import stat
import sys

BINDING = None
MARKER = "CLIPFORGE_HOSTKEY_V1 "
IDENTITY = {"project": "clipforgebeta2", "project_number": "816643438938",
            "zone": "us-central1-a", "instance_id": "1670495097211408131"}


def require(value, code):
    if not value:
        raise ValueError(code)


def public_key(raw):
    """Accept a bounded existing .pub, returning a comment-free canonical key."""
    require(isinstance(raw, bytes) and 0 < len(raw) <= 1024, "public_key_size")
    value = raw.decode("ascii").strip()
    require("\n" not in value and "\r" not in value, "public_key_lines")
    parts = value.split()
    require(len(parts) >= 2 and parts[0] == "ssh-ed25519", "public_key_type")
    blob = base64.b64decode(parts[1], validate=True)
    require(base64.b64encode(blob).decode("ascii") == parts[1]
            and len(blob) == 51 and blob[:19] == b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20", "public_key_blob")
    fingerprint = "SHA256:" + base64.b64encode(hashlib.sha256(blob).digest()).decode("ascii").rstrip("=")
    return "ssh-ed25519 " + parts[1], fingerprint


def trusted(info, directory=False):
    require((stat.S_ISDIR(info.st_mode) if directory else stat.S_ISREG(info.st_mode))
            and info.st_uid == 0 and not info.st_mode & 0o022, "untrusted_public_path")
    if not directory:
        require(info.st_nlink == 1, "public_file_hardlink")


def read_public_key():
    """Open /, etc, ssh and the .pub with no symlink traversal on Linux."""
    opened = []
    try:
        directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        opened.append(directory)
        trusted(os.fstat(directory), True)
        for name in ("etc", "ssh"):
            directory = os.open(name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory)
            opened.append(directory)
            trusted(os.fstat(directory), True)
        fd = os.open("ssh_host_ed25519_key.pub", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
        opened.append(fd)
        before = os.fstat(fd)
        trusted(before)
        require(0 < before.st_size <= 1024, "public_key_size")
        raw = os.read(fd, 1025)
        after = os.fstat(fd)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns)
                == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns, after.st_ctime_ns)
                and len(raw) == before.st_size, "public_key_changed")
        return raw
    finally:
        for fd in reversed(opened):
            os.close(fd)


def own_source():
    fd = os.open(__file__, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        trusted(info)
        require(0 < info.st_size <= 65536, "publisher_size")
        raw = os.read(fd, 65537)
        require(len(raw) == info.st_size and b"\r" not in raw, "publisher_bytes")
        return raw
    finally:
        os.close(fd)


def metadata(path):
    require(path in {"project/project-id", "project/numeric-project-id", "instance/zone", "instance/id"}, "metadata_path")
    connection = http.client.HTTPConnection("169.254.169.254", timeout=5)
    try:
        connection.request("GET", "/computeMetadata/v1/" + path, headers={"Metadata-Flavor": "Google"})
        response = connection.getresponse()
        require(response.status == 200 and response.getheader("Metadata-Flavor") == "Google", "metadata_response")
        raw = response.read(1025)
        require(len(raw) <= 1024, "metadata_size")
        return raw.decode("ascii")
    finally:
        connection.close()


def binding_contract(binding):
    require(isinstance(binding, dict) and set(binding) == set(IDENTITY) | {"nonce", "guest_source_sha256"}
            and all(binding.get(key) == value for key, value in IDENTITY.items())
            and re.fullmatch(r"[a-f0-9]{64}", binding.get("nonce", ""))
            and re.fullmatch(r"[a-f0-9]{64}", binding.get("guest_source_sha256", "")), "publisher_binding")


def record(binding, raw_key, source, reader=metadata):
    binding_contract(binding)
    require(reader("project/project-id") == IDENTITY["project"]
            and reader("project/numeric-project-id") == IDENTITY["project_number"]
            and reader("instance/id") == IDENTITY["instance_id"]
            and reader("instance/zone") == "projects/816643438938/zones/us-central1-a", "metadata_identity")
    key, fingerprint = public_key(raw_key)
    return {"schema": "clipforge-int-hostkey-record-1", **binding,
            "script_sha256": hashlib.sha256(source).hexdigest(), "public_key": key, "fingerprint": fingerprint}


def write_serial(value):
    payload = (MARKER + json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(payload) <= 2048, "serial_size")
    fd = os.open("/dev/ttyS0", os.O_WRONLY | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        require(stat.S_ISCHR(info.st_mode) and info.st_uid == 0
                and (os.major(info.st_rdev), os.minor(info.st_rdev)) == (4, 64), "serial_device")
        require(os.write(fd, payload) == len(payload), "serial_short_write")
    finally:
        os.close(fd)


def main():
    require(sys.platform == "linux" and os.geteuid() == 0, "publisher_platform")
    binding_contract(BINDING)
    write_serial(record(BINDING, read_public_key(), own_source()))


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("CLIPFORGE_HOSTKEY_BLOCKED", file=sys.stderr)
        raise SystemExit(1)
