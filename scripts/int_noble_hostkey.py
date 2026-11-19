"""Publish the existing Noble Ed25519 public key and verify its serial record."""
from __future__ import annotations

import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import sys
import time


PROJECT = "clipforgebeta2"
PROJECT_NUMBER = "816643438938"
ZONE = "us-central1-a"
INSTANCE = "clipforge-int-db01-noble"
MARKER = "CLIPFORGE_HOSTKEY_V1 "
SCHEMA = "clipforge-int-noble-hostkey-record-1"
HEX = r"[0-9a-f]{64}"
NUMBER = r"[1-9][0-9]{0,19}"
BOOT = r"[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}"
LEGACY_SHA256 = "a8211bbfbe29f0694f633b403fbe41e08ef6dfbc8abb9705f56e1f8e13ea10ad"
IDENTITY = {"project": PROJECT, "project_number": PROJECT_NUMBER, "zone": ZONE, "instance_name": INSTANCE}
RECORD_FIELDS = set(IDENTITY) | {"schema", "nonce", "instance_id", "guest_boot_id", "script_sha256",
                                 "publisher_dependency_sha256", "public_key", "fingerprint"}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def closed_json(raw):
    def no_duplicates(pairs):
        parsed = dict(pairs)
        require(len(parsed) == len(pairs), "NOBLE_HOSTKEY_DUPLICATE_FIELD")
        return parsed

    return json.loads(raw, object_pairs_hook=no_duplicates)


def record(nonce, source, *, instance_id, guest_boot_id, public_key, parse_public_key):
    require(isinstance(nonce, str) and re.fullmatch(HEX, nonce) and re.fullmatch(NUMBER, instance_id)
            and re.fullmatch(BOOT, guest_boot_id) and 0 < len(source) <= 65536, "NOBLE_HOSTKEY_BINDING")
    key, fingerprint = parse_public_key(public_key)
    return {"schema": SCHEMA, **IDENTITY, "nonce": nonce, "instance_id": instance_id,
            "guest_boot_id": guest_boot_id, "script_sha256": sha(source),
            "publisher_dependency_sha256": LEGACY_SHA256, "public_key": key, "fingerprint": fingerprint}


def instance_name():
    connection = http.client.HTTPConnection("169.254.169.254", timeout=5)
    try:
        connection.request("GET", "/computeMetadata/v1/instance/name", headers={"Metadata-Flavor": "Google"})
        response = connection.getresponse()
        require(response.status == 200 and response.getheader("Metadata-Flavor") == "Google", "NOBLE_HOSTKEY_METADATA")
        return response.read(1025).decode("ascii")
    finally:
        connection.close()


def publish(nonce, source, legacy):
    """Called only from the reviewed initial startup. The legacy source is hash-checked by the loader."""
    require(sys.platform == "linux" and os.geteuid() == 0 and re.fullmatch(HEX, nonce), "NOBLE_HOSTKEY_PLATFORM")
    metadata = legacy["metadata"]
    require(metadata("project/project-id") == PROJECT and metadata("project/numeric-project-id") == PROJECT_NUMBER
            and metadata("instance/zone") == "projects/" + PROJECT_NUMBER + "/zones/" + ZONE
            and instance_name() == INSTANCE, "NOBLE_HOSTKEY_IDENTITY")
    instance_id = metadata("instance/id")
    with Path("/proc/sys/kernel/random/boot_id").open("rb") as stream:
        guest_boot_id = stream.read(64).decode("ascii").strip()
    deadline = time.monotonic() + 30
    while True:
        try:
            key = legacy["read_public_key"]()
            break
        except FileNotFoundError:
            require(time.monotonic() < deadline, "NOBLE_HOSTKEY_PUBLIC_KEY_ABSENT")
            time.sleep(1)
    value = record(nonce, source, instance_id=instance_id, guest_boot_id=guest_boot_id,
                   public_key=key, parse_public_key=legacy["public_key"])
    legacy["write_serial"](value)


def serial_record(response, *, instance_id, nonce, publisher_sha256):
    from scripts.int_vm_hostkey_guest import public_key

    def cursor(value):
        return type(value) is int and 0 <= value <= 2 ** 63 - 1 or (
            isinstance(value, str) and re.fullmatch(r"0|[1-9][0-9]{0,18}", value) and int(value) <= 2 ** 63 - 1)

    require(isinstance(response, dict) and cursor(response.get("start")) and int(response["start"]) == 0
            and cursor(response.get("next")) and int(response["next"]) > 0, "NOBLE_SERIAL_TRUNCATED_OR_UNKNOWN")
    contents = response.get("contents")
    require(isinstance(contents, str) and len(contents.encode("utf-8")) <= 2 * 1024 * 1024
            and re.fullmatch(NUMBER, instance_id) and re.fullmatch(HEX, nonce)
            and re.fullmatch(HEX, publisher_sha256), "NOBLE_SERIAL_BINDING")
    matching = [line for line in contents.splitlines(keepends=True) if line.startswith(MARKER)]
    require(len(matching) == 1 and matching[0].endswith("\n") and len(matching[0]) <= 2048, "NOBLE_SERIAL_RECORD_NOT_UNIQUE_COMPLETE")
    found = closed_json(matching[0][len(MARKER):].strip())
    require(isinstance(found, dict) and set(found) == RECORD_FIELDS, "NOBLE_SERIAL_RECORD_FIELDS")
    require(isinstance(found["guest_boot_id"], str) and isinstance(found["public_key"], str), "NOBLE_SERIAL_RECORD_TYPES")
    expected = {"schema": SCHEMA, **IDENTITY, "nonce": nonce, "instance_id": instance_id,
                "script_sha256": publisher_sha256, "publisher_dependency_sha256": LEGACY_SHA256}
    require(all(found[key] == value for key, value in expected.items())
            and re.fullmatch(BOOT, found["guest_boot_id"]), "NOBLE_SERIAL_RECORD_BINDING")
    key, fingerprint = public_key(found["public_key"].encode("ascii"))
    require(found["public_key"] == key and found["fingerprint"] == fingerprint, "NOBLE_SERIAL_RECORD_KEY")
    return found
