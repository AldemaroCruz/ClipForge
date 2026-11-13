"""Independent proposal inventory; deliberately not a replacement for CI gates.

The candidate keeps the reviewed PostgreSQL base and records its real rebuilt
gosu module version. No database is started, no data/credentials are mounted.
Existing CI producers and validators keep their original identity contracts.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import signal
import tempfile
import threading
import uuid

try:
    from scripts import capture_postgres_inventory as original
except ModuleNotFoundError:
    import capture_postgres_inventory as original

SCHEMA = "clipforge-postgres-security-proposal-inventory-1"
GOSU_COMMIT = "29b939aa5bd4dc588af765b8248f6e39150d2565"
GOSU_MODULE_VERSION = "v0.0.0-20261025094355-29b939aa5bd4"
GO_VERSION = "go1.27.4"
ZLIB_VERSION = "1:1.3.dfsg+really1.3.1-1+deb13u1"
SOURCE_MODULE_CHECKSUM = "h1:1SHWv8GcArm5ipwzlVf6Xp4e9mAvzBVlfrkxJTCh4jc="
require = original.require


def parse_candidate(raw, *, image_id, image_reference):
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", image_id), "Expected immutable candidate configuration ID")
    require(re.fullmatch(r"clipforge-pg-security:[a-z0-9][a-z0-9._-]{0,80}", image_reference), "Expected an explicitly named independent candidate")
    parts = original.parse_sections(raw)
    packages = original.parse_packages(parts["dpkg-status"])
    os_info = original.parse_os_release(parts["os-release"], parts["debian-version"])
    postgres = next(item for item in packages if item["Name"] == original.POSTGRES_PACKAGE)
    require(re.fullmatch(r"18\.6-[0-9A-Za-z.+:~\-]+", postgres["Version"]), "PostgreSQL base version changed")
    pg_version = parts["postgres-version"].decode("ascii").strip()
    require(pg_version == "postgres (PostgreSQL) 18.6 (Debian " + postgres["Version"] + ")", "PostgreSQL runtime/package mismatch")
    binary = base64.b64decode(parts["gosu-binary"], validate=True)
    go = original.parse_go_build_info(binary)
    require(go["go_version"] == GO_VERSION, "Candidate Go toolchain differs from proposal")
    require(go["main_module"] == {"Name": "github.com/tianon/gosu", "Version": GOSU_MODULE_VERSION,
                                  "Checksum": SOURCE_MODULE_CHECKSUM}, "Actual gosu source module identity differs from proposal")
    require({(item["Name"], item["Version"]) for item in go["dependencies"]} == {
        ("github.com/moby/sys/user", "v0.4.1"), ("golang.org/x/sys", "v0.1.0")}, "Candidate dependency inventory changed")
    gosu_version = parts["gosu-version"].decode("ascii").strip()
    require(gosu_version == "1.20 (" + GO_VERSION + " on linux/amd64; gc)", "gosu runtime/build metadata mismatch")
    binaries = {}
    for label, path in (("postgres", original.POSTGRES_BINARY), ("gosu", original.GOSU_BINARY)):
        require(parts[label + "-resolved"].decode("ascii").strip() == path, "Unexpected executable resolution")
        matched = re.fullmatch(r"0 0 755 ([1-9][0-9]*) regular file", parts[label + "-stat"].decode("ascii").strip())
        require(matched is not None, "Executable must be root-owned regular 0755")
        digest = re.fullmatch(r"([a-f0-9]{64})  " + re.escape(path), parts[label + "-sha256"].decode("ascii").strip())
        require(digest is not None, "Missing executable hash")
        binaries[label] = {"path": path, "resolved_path": path, "sha256": digest[1], "bytes": int(matched[1]), "uid": 0, "gid": 0, "mode": "0o755"}
    require(len(binary) == binaries["gosu"]["bytes"] and hashlib.sha256(binary).hexdigest() == binaries["gosu"]["sha256"], "Captured gosu hash/size mismatch")
    require(parts["postgres-owner"].decode("ascii").strip() == original.POSTGRES_PACKAGE + ": " + original.POSTGRES_BINARY, "PostgreSQL package ownership changed")
    pg_files = parts["postgres-file-list"].decode("utf-8").splitlines()
    require(original.POSTGRES_BINARY in pg_files and len(pg_files) == len(set(pg_files)) and all(item.startswith("/") and ".." not in item.split("/") for item in pg_files), "PostgreSQL package file inventory invalid")
    zlib = next((item for item in packages if item["Name"] == "zlib1g"), None)
    require(zlib is not None and zlib["Version"] == ZLIB_VERSION, "Required zlib security version is absent")
    gosu = {**binaries["gosu"], "version": gosu_version, **go}
    return {"schema": SCHEMA, "schema_version": 1, "image_id": image_id, "image_config_id": image_id,
            "image_reference": image_reference, "base_image_reference": original.POSTGRES_IMAGE,
            "platform": {"os": "linux", "architecture": "amd64"}, "os": os_info,
            "targets": [{"Class": "os-pkgs", "Type": "debian", "Packages": packages},
                        {"Class": "lang-pkgs", "Type": "gobinary", "Target": "usr/local/bin/gosu", "Packages": go["packages"]}],
            "go_binaries": [gosu], "postgres": {"version": pg_version, "version_number": "18.6", "binary": binaries["postgres"], "package": postgres, "package_owned": True,
                "package_file_list": {"sha256": hashlib.sha256(parts["postgres-file-list"]).hexdigest(), "bytes": len(parts["postgres-file-list"])}},
            "dpkg": {"status_sha256": hashlib.sha256(parts["dpkg-status"]).hexdigest(), "status_bytes": len(parts["dpkg-status"]), "installed_package_count": len(packages)},
            "source": {"gosu_commit": GOSU_COMMIT, "gosu_module_version": GOSU_MODULE_VERSION, "go_toolchain": GO_VERSION, "zlib1g": ZLIB_VERSION},
            "scope": {"installed_dpkg_packages": "complete", "go_binaries": [original.GOSU_BINARY], "database_started": False, "database_data_read": False,
                      "credentials_used": False, "network": "none", "ci_integration": "pending_producer_and_validator_review", "vm_or_application_result": False},
            "probe_stdout_sha256": hashlib.sha256(raw).hexdigest(), "probe_script_sha256": hashlib.sha256(original.PROBE.encode()).hexdigest()}


def capture(image_reference, image_id, output, runner=original._execute):
    output = Path(output)
    require(not output.exists(), "Inventory output must be new")
    artifacts = output.with_name(output.stem + ".capture")
    require(not artifacts.exists(), "Capture directory must be new")
    artifacts.mkdir(parents=True)
    nonce = uuid.uuid4().hex
    container = "clipforge-ci-pg-security-" + nonce[:20]
    with tempfile.TemporaryDirectory(prefix="clipforge-pg-security-docker-") as docker_config:
        engine = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
        prefix = [original.host_executable("docker"), "--config", docker_config, "--host", engine]
        identity_format = '{{.Id}}|{{.Os}}|{{.Architecture}}|{{json .RootFS.Layers}}'
        identity = runner(prefix + ["image", "inspect", "--format", identity_format, image_reference], artifacts, "candidate-identity").decode().strip().split("|", 3)
        base = runner(prefix + ["image", "inspect", "--format", identity_format, original.POSTGRES_IMAGE], artifacts, "base-identity").decode().strip().split("|", 3)
        require(identity[:3] == [image_id, "linux", "amd64"] and base[1:3] == ["linux", "amd64"], "Candidate or base platform/identity mismatch")
        layers, base_layers = json.loads(identity[3]), json.loads(base[3])
        require(layers[:len(base_layers)] == base_layers and len(layers) > len(base_layers), "Candidate does not preserve the reviewed PostgreSQL base layers")
        argv = prefix + ["run", "--rm", "--pull", "never", "--platform", "linux/amd64", "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                         "--user", "65534:65534", "--name", container, "--label", "clipforge.inventory.probe=" + nonce,
                         "--tmpfs", "/var/lib/postgresql:ro,nosuid,nodev,size=1m", "--entrypoint", "/bin/sh", image_id, "-ec", original.PROBE]
        handle_signal = threading.current_thread() is threading.main_thread()
        previous_handler = signal.signal(signal.SIGTERM, original._cancel_capture) if handle_signal else None
        try:
            raw = runner(argv, artifacts, "package-probe")
        finally:
            if handle_signal:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                original._cleanup_probe(prefix, container, nonce, artifacts, runner)
            finally:
                if handle_signal:
                    signal.signal(signal.SIGTERM, previous_handler)
    inventory = parse_candidate(raw, image_id=image_id, image_reference=image_reference)
    inventory["capture"] = {"captured_utc": datetime.now(timezone.utc).isoformat(), "container_name": container, "probe_identity": nonce}
    inventory["base_config_id"] = base[0]
    inventory["layers"] = {"candidate": layers, "base": base_layers, "base_prefix_preserved": True}
    dockerfile = Path(__file__).resolve().parents[1] / "config" / "postgres-ci-security.Dockerfile"
    inventory["source"]["dockerfile_sha256"] = hashlib.sha256(dockerfile.read_bytes()).hexdigest()
    original._write_json(output, inventory)
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = capture(args.image, args.image_id, args.output)
        print(json.dumps({"status": "captured_independent_proposal", "image_id": result["image_id"], "installed_packages": result["dpkg"]["installed_package_count"], "ci_integration": "pending"}))
        return 0
    except (original.InventoryError, OSError, ValueError, KeyError, UnicodeError):
        print(json.dumps({"status": "failed", "message": "Candidate inventory failed; preserve this attempt. Existing CI contracts unchanged."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
