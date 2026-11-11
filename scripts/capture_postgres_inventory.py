"""Independently inventory the pinned PostgreSQL image without starting a DB.

Host stdlib only. Docker uses a reviewed absolute executable, fresh empty
configuration and the local engine. The fixed probe has no network, database
credentials, host mounts or database data; it never runs the image entrypoint.
This inventories installed content, not scanner coverage or vulnerability fixes.
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
import shlex
import signal
import struct
import subprocess
import sys
import tempfile
import threading
import uuid

try:
    from scripts.dev_local import POSTGRES_IMAGE, host_executable
except ModuleNotFoundError:
    from dev_local import POSTGRES_IMAGE, host_executable


SCHEMA = "clipforge-postgres-image-inventory-1"
POSTGRES_BINARY = "/usr/lib/postgresql/18/bin/postgres"
POSTGRES_PACKAGE = "postgresql-18"
POSTGRES_FILE_LIST = "/var/lib/dpkg/info/postgresql-18.list"
GOSU_BINARY = "/usr/local/bin/gosu"
MAX_CAPTURE_BYTES = 16 * 1024 * 1024
SECTIONS = ("os-release", "debian-version", "dpkg-status", "postgres-version",
            "postgres-resolved", "postgres-stat", "postgres-sha256", "postgres-owner",
            "postgres-file-list", "gosu-version", "gosu-resolved", "gosu-stat", "gosu-sha256",
            "gosu-binary", "end")
MARKER = b"\x1eCLIPFORGE-PG-INVENTORY:"

# Fixed code, never formatted from image metadata or command-line arguments.
# The initial LF after every section is a framing byte, not part of the file.
PROBE = r"""set -eu
printf '\036CLIPFORGE-PG-INVENTORY:os-release\n'
/bin/cat /etc/os-release
printf '\n\036CLIPFORGE-PG-INVENTORY:debian-version\n'
/bin/cat /etc/debian_version
printf '\n\036CLIPFORGE-PG-INVENTORY:dpkg-status\n'
/bin/cat /var/lib/dpkg/status
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-version\n'
/usr/lib/postgresql/18/bin/postgres --version
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-resolved\n'
/usr/bin/readlink -f /usr/lib/postgresql/18/bin/postgres
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-stat\n'
/usr/bin/stat -c '%u %g %a %s %F' /usr/lib/postgresql/18/bin/postgres
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-sha256\n'
/usr/bin/sha256sum /usr/lib/postgresql/18/bin/postgres
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-owner\n'
/usr/bin/dpkg-query -S /usr/lib/postgresql/18/bin/postgres
printf '\n\036CLIPFORGE-PG-INVENTORY:postgres-file-list\n'
/bin/cat /var/lib/dpkg/info/postgresql-18.list
printf '\n\036CLIPFORGE-PG-INVENTORY:gosu-version\n'
/usr/local/bin/gosu --version
printf '\n\036CLIPFORGE-PG-INVENTORY:gosu-resolved\n'
/usr/bin/readlink -f /usr/local/bin/gosu
printf '\n\036CLIPFORGE-PG-INVENTORY:gosu-stat\n'
/usr/bin/stat -c '%u %g %a %s %F' /usr/local/bin/gosu
printf '\n\036CLIPFORGE-PG-INVENTORY:gosu-sha256\n'
/usr/bin/sha256sum /usr/local/bin/gosu
printf '\n\036CLIPFORGE-PG-INVENTORY:gosu-binary\n'
/usr/bin/base64 -w0 /usr/local/bin/gosu
printf '\n\036CLIPFORGE-PG-INVENTORY:end\n'
"""


class InventoryError(ValueError):
    """Image identity, probe output or required inventory scope is invalid."""


def require(condition, message):
    if not condition:
        raise InventoryError(message)


def _sha(data):
    return hashlib.sha256(data).hexdigest()


def parse_sections(raw: bytes) -> dict[str, bytes]:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_CAPTURE_BYTES, "Invalid probe output size")
    parts = raw.split(MARKER)
    require(parts[0] == b"" and len(parts) == len(SECTIONS) + 1, "Incomplete/extra probe sections")
    result = {}
    for expected, part in zip(SECTIONS, parts[1:]):
        name, separator, payload = part.partition(b"\n")
        require(separator and name.decode("ascii", errors="replace") == expected, "Unexpected probe section order")
        if expected == "end":
            require(payload == b"", "Unexpected trailing probe output")
        else:
            require(payload.endswith(b"\n"), "Missing probe frame delimiter")
            result[expected] = payload[:-1]
    return result


def parse_os_release(raw: bytes, debian_version: bytes) -> dict:
    try:
        fields = {}
        for line in raw.decode("utf-8").splitlines():
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            key, separator, value = line.partition("=")
            require(separator and re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and key not in fields,
                    "Malformed/duplicate OS identity field")
            words = shlex.split(value, comments=False, posix=True)
            require(len(words) == 1, "Malformed OS identity value")
            fields[key] = words[0]
        name = debian_version.decode("ascii").strip()
    except (UnicodeError, ValueError) as error:
        raise InventoryError("Invalid OS identity document") from error
    require(fields.get("ID") == "debian" and fields.get("VERSION_ID") == "13"
            and re.fullmatch(r"13(?:\.[0-9]+)*", name), "Expected pinned Debian 13 PostgreSQL image")
    return {"family": "debian", "name": name, "id": fields["ID"], "version_id": fields["VERSION_ID"]}


def parse_packages(raw: bytes) -> list[dict]:
    try:
        status = raw.decode("utf-8")
    except UnicodeError as error:
        raise InventoryError("Invalid dpkg status encoding") from error
    packages = []
    names = set()
    for paragraph in status.strip().split("\n\n"):
        fields = {}
        previous = None
        for line in paragraph.splitlines():
            if line[:1].isspace():
                require(previous is not None, "Unexpected dpkg field continuation")
                fields[previous] += "\n" + line[1:]
            elif line:
                key, separator, value = line.partition(":")
                require(separator and re.fullmatch(r"[A-Za-z][A-Za-z0-9-]*", key)
                        and key not in fields, "Malformed/duplicate dpkg field")
                fields[key] = value.lstrip(" ")
                previous = key
        require(fields.get("Package"), "Dpkg record missing package name")
        status_parts = fields.get("Status", "").split()
        require(len(status_parts) == 3 and status_parts[0] in {"unknown", "install", "hold", "deinstall", "purge"}
                and status_parts[1] == "ok" and status_parts[2] in {"installed", "config-files", "not-installed"},
                "Missing, broken or incomplete dpkg package status")
        if status_parts[2] != "installed":
            continue
        name, version, architecture = (fields.get(key) for key in ("Package", "Version", "Architecture"))
        require(type(name) is str and re.fullmatch(r"[a-z0-9][a-z0-9+.-]*", name), "Invalid installed package name")
        require(type(version) is str and re.fullmatch(r"[0-9A-Za-z.+:~\-]+", version), "Missing/invalid installed package version")
        require(architecture in {"amd64", "all"}, "Unexpected installed package architecture")
        require(name not in names, "Duplicate installed package")
        names.add(name)
        source = re.fullmatch(r"([a-z0-9][a-z0-9+.-]*)(?: \(([0-9A-Za-z.+:~\-]+)\))?", fields.get("Source", name))
        require(source is not None, "Invalid installed package source/version")
        packages.append({"Name": name, "Version": version, "Architecture": architecture,
                         "Source": source[1], "SourceVersion": source[2] or version})
    require(bool(packages), "Installed package inventory is empty")
    require(any(item["Name"] == POSTGRES_PACKAGE for item in packages), "PostgreSQL package missing from complete inventory")
    return sorted(packages, key=lambda item: (item["Name"], item["Version"]))


def parse_go_build_info(binary: bytes) -> dict:
    """Read the pinned ELF64/Go>=1.18 inline format, independently of Trivy.

    Format reference: go.dev/src/debug/buildinfo/buildinfo.go and
    go.dev/src/runtime/debug/mod.go. Unsupported formats fail; no dependency
    is guessed from strings, executable versions or scanner findings.
    """
    require(type(binary) is bytes and 64 <= len(binary) <= 8 * 1024 * 1024, "Invalid Go executable size")
    header = struct.unpack_from("<16sHHIQQQIHHHHHH", binary)
    require(header[0][:7] == b"\x7fELF\x02\x01\x01" and header[1] in {2, 3}
            and header[2] == 62 and header[3] == 1 and header[8] == 64,
            "Expected Linux amd64 ELF64 little-endian executable")
    table, width, count, names_index = header[6], header[11], header[12], header[13]
    require(width == 64 and 1 <= count <= 4096 and names_index < count and table + width * count <= len(binary),
            "Invalid ELF section table")
    sections = [struct.unpack_from("<IIQQQQIIQQ", binary, table + index * width) for index in range(count)]
    names_section = sections[names_index]
    require(names_section[1] == 3 and names_section[4] + names_section[5] <= len(binary), "Invalid ELF section name table")
    names = binary[names_section[4]:names_section[4] + names_section[5]]
    matches = []
    for section in sections:
        require(section[0] < len(names), "Invalid ELF section name offset")
        end = names.find(b"\0", section[0])
        require(end >= 0, "Unterminated ELF section name")
        if names[section[0]:end] == b".go.buildinfo":
            require(section[4] % 16 == 0 and 32 <= section[5] <= 128 * 1024
                    and section[4] + section[5] <= len(binary), "Invalid Go build-info section")
            matches.append(binary[section[4]:section[4] + section[5]])
    require(len(matches) == 1, "Exactly one Go build-info section is required")
    info = matches[0]
    require(info[:14] == b"\xff Go buildinf:" and info[14:16] == b"\x08\x02", "Unsupported Go build-info header")

    def read_string(offset):
        length = 0
        for index in range(10):
            require(offset < len(info), "Truncated Go string length")
            value = info[offset]
            offset += 1
            length |= (value & 0x7f) << (7 * index)
            if value < 128:
                require(length <= 65536 and offset + length <= len(info), "Truncated/oversized Go string")
                return info[offset:offset + length], offset + length
        raise InventoryError("Invalid Go string length")

    raw_version, offset = read_string(32)
    framed_modules, _ = read_string(offset)
    require(re.fullmatch(rb"go[0-9]+\.[0-9]+\.[0-9]+", raw_version), "Unsupported Go toolchain version")
    require(framed_modules.startswith(bytes.fromhex("3077af0c9274080241e1c107e6d618e6"))
            and framed_modules.endswith(bytes.fromhex("f932433186182072008242104116d8f2"))
            and framed_modules[-17:-16] == b"\n", "Invalid Go module-info frame")
    module_text = framed_modules[16:-16].decode("utf-8")
    main, path, dependencies, settings = None, None, [], {}
    module_names = set()
    for line in module_text.splitlines():
        parts = line.split("\t")
        if parts[0] == "path":
            require(len(parts) == 2 and path is None and parts[1], "Invalid/duplicate Go main path")
            path = parts[1]
        elif parts[0] in {"mod", "dep"}:
            require(len(parts) in {3, 4} and re.fullmatch(r"[A-Za-z0-9_./!~+\-]+", parts[1])
                    and re.fullmatch(r"v[0-9]+\.[0-9]+\.[0-9]+(?:[+\-][A-Za-z0-9.\-]+)?", parts[2]),
                    "Missing/invalid Go module identity")
            require(parts[1] not in module_names, "Duplicate Go module")
            module_names.add(parts[1])
            checksum = parts[3] if len(parts) == 4 else ""
            require(not checksum or re.fullmatch(r"h1:[A-Za-z0-9+/]{43}=", checksum), "Invalid Go module checksum")
            item = {"Name": parts[1], "Version": parts[2], "Checksum": checksum}
            if parts[0] == "mod":
                require(main is None, "Duplicate Go main module")
                main = item
            else:
                dependencies.append(item)
        elif parts[0] == "build":
            require(len(parts) == 2 and "=" in parts[1], "Malformed Go build setting")
            key, value = parts[1].split("=", 1)
            require(key and key not in settings, "Duplicate Go build setting")
            settings[key] = value
        else:
            # Replaced or development modules need explicit producer review.
            raise InventoryError("Unsupported Go module-info record")
    require(main is not None and path == "github.com/tianon/gosu" and main["Name"] == path,
            "Expected actual gosu main module")
    require(settings.get("GOOS") == "linux" and settings.get("GOARCH") == "amd64", "Go build platform differs from image")
    version = raw_version.decode("ascii")
    packages = [{"Name": item["Name"], "Version": item["Version"]} for item in [main, *dependencies]]
    packages.append({"Name": "stdlib", "Version": "v" + version.removeprefix("go")})
    return {"go_version": version, "main_path": path, "main_module": main,
            "dependencies": dependencies, "build_settings": settings,
            "build_info_sha256": _sha(info), "module_info_sha256": _sha(framed_modules),
            "packages": sorted(packages, key=lambda item: (item["Name"], item["Version"]))}


def parse_gosu(sections):
    try:
        binary = base64.b64decode(sections["gosu-binary"], validate=True)
        version = sections["gosu-version"].decode("ascii").strip()
        resolved = sections["gosu-resolved"].decode("ascii").strip()
        metadata = sections["gosu-stat"].decode("ascii").strip()
        digest_line = sections["gosu-sha256"].decode("ascii").strip()
    except (ValueError, UnicodeError) as error:
        raise InventoryError("Invalid gosu executable capture") from error
    require(resolved == GOSU_BINARY, "Unexpected gosu executable resolution")
    matched = re.fullmatch(r"0 0 ([0-7]{3,4}) ([1-9][0-9]*) regular file", metadata)
    require(matched is not None, "gosu must be a root-owned regular file")
    mode = int(matched[1], 8)
    require(mode & 0o111 and not mode & 0o7022 and len(binary) == int(matched[2]), "Unsafe/mismatched gosu executable")
    digest = _sha(binary)
    require(digest_line == digest + "  " + GOSU_BINARY, "gosu binary and reported hash differ")
    go = parse_go_build_info(binary)
    require(version == "1.19 (" + go["go_version"] + " on linux/amd64; gc)", "gosu runtime/build metadata mismatch")
    return {"path": GOSU_BINARY, "resolved_path": resolved, "sha256": digest, "bytes": len(binary),
            "uid": 0, "gid": 0, "mode": oct(mode), "version": version, **go}


def parse_probe(raw: bytes, *, image_id: str, image_reference: str) -> dict:
    require(image_reference == POSTGRES_IMAGE, "Only the reviewed pinned PostgreSQL image is permitted")
    require(type(image_id) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "Expected verified image configuration ID")
    sections = parse_sections(raw)
    os_info = parse_os_release(sections["os-release"], sections["debian-version"])
    packages = parse_packages(sections["dpkg-status"])
    gosu = parse_gosu(sections)
    package = next(item for item in packages if item["Name"] == POSTGRES_PACKAGE)
    require(re.fullmatch(r"18\.6-[0-9A-Za-z.+:~\-]+", package["Version"]), "Installed PostgreSQL version differs from reviewed image")
    try:
        version = sections["postgres-version"].decode("ascii").strip()
        resolved = sections["postgres-resolved"].decode("ascii").strip()
        metadata = sections["postgres-stat"].decode("ascii").strip()
        digest_line = sections["postgres-sha256"].decode("ascii").strip()
        owner = sections["postgres-owner"].decode("ascii").strip()
        file_list = sections["postgres-file-list"].decode("utf-8").splitlines()
    except UnicodeError as error:
        raise InventoryError("Invalid PostgreSQL binary metadata encoding") from error
    require(version == "postgres (PostgreSQL) 18.6 (Debian " + package["Version"] + ")", "Runtime and packaged PostgreSQL versions differ")
    require(resolved == POSTGRES_BINARY, "Unexpected PostgreSQL executable resolution")
    matched = re.fullmatch(r"(0) (0) ([0-7]{3,4}) ([1-9][0-9]*) regular file", metadata)
    require(matched is not None, "PostgreSQL executable must be a root-owned regular file")
    mode = int(matched[3], 8)
    require(mode & 0o111 and not mode & 0o7022, "Unsafe PostgreSQL executable mode")
    digest = re.fullmatch(r"([0-9a-f]{64})  " + re.escape(POSTGRES_BINARY), digest_line)
    require(digest is not None, "Missing/invalid PostgreSQL executable hash")
    require(owner == POSTGRES_PACKAGE + ": " + POSTGRES_BINARY and POSTGRES_BINARY in file_list,
            "PostgreSQL executable is not owned by the inventoried package")
    require(file_list and len(file_list) == len(set(file_list)) and
            all(line.startswith("/") and ".." not in line.split("/") for line in file_list),
            "Invalid/duplicate package file-list entries")
    return {
        "schema": SCHEMA, "schema_version": 1, "image_id": image_id, "image_config_id": image_id,
        "image_reference": image_reference, "platform": {"os": "linux", "architecture": "amd64"},
        "os": os_info,
        "targets": [{"Class": "os-pkgs", "Type": "debian", "Packages": packages},
                    {"Class": "lang-pkgs", "Type": "gobinary", "Target": GOSU_BINARY.lstrip("/"), "Packages": gosu["packages"]}],
        "go_binaries": [gosu],
        "dpkg": {"status_path": "/var/lib/dpkg/status", "status_sha256": _sha(sections["dpkg-status"]),
                 "status_bytes": len(sections["dpkg-status"]), "installed_package_count": len(packages)},
        "postgres": {"version": version, "version_number": "18.6",
                     "binary": {"path": POSTGRES_BINARY, "resolved_path": resolved,
                                "sha256": digest[1], "bytes": int(matched[4]),
                                "uid": 0, "gid": 0, "mode": oct(mode)},
                     "package": {"Name": package["Name"], "Version": package["Version"]},
                     "package_file_list": {"path": POSTGRES_FILE_LIST,
                                           "sha256": _sha(sections["postgres-file-list"]),
                                           "bytes": len(sections["postgres-file-list"])},
                     "package_owned": True},
        "scope": {"installed_dpkg_packages": "complete", "postgres_runtime_binary": "verified",
                  "go_binaries": [GOSU_BINARY], "invented_language_targets": False, "network": "none", "database_started": False,
                  "database_data_read": False, "credentials_used": False,
                  "limitation": "Content/ownership inventory does not prove scanner coverage or absence of vulnerabilities."},
        "probe_stdout_sha256": _sha(raw), "probe_script_sha256": _sha(PROBE.encode("utf-8")),
    }


def _write_json(path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def _execute(argv, directory, label, *, timeout=45):
    started = datetime.now(timezone.utc).isoformat()
    error = None
    exit_code = None
    interrupted = None
    stdout_path, stderr_path = (directory / (label + suffix) for suffix in (".stdout.log", ".stderr.log"))
    with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
        try:
            process = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, check=False)
            exit_code = process.returncode
        except (OSError, subprocess.TimeoutExpired) as failure:
            error = type(failure).__name__
        except KeyboardInterrupt as failure:
            error = type(failure).__name__
            interrupted = failure
    _write_json(directory / (label + "-execution.json"), {
        "argv": argv, "exit_code": exit_code, "error_type": error,
        "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(),
        "stdout_bytes": stdout_path.stat().st_size, "stderr_bytes": stderr_path.stat().st_size,
    })
    if interrupted is not None:
        raise interrupted
    require(error is None and exit_code == 0, label + " failed; preserve this attempt and inspect its exclusively named probe before retrying")
    require(stdout_path.stat().st_size <= MAX_CAPTURE_BYTES and stderr_path.stat().st_size <= MAX_CAPTURE_BYTES,
            "Probe output exceeded its size limit")
    require(stderr_path.stat().st_size == 0, "Probe diagnostic output requires review")
    return stdout_path.read_bytes()


def _cleanup_probe(prefix, container_name, probe_identity, artifacts, runner):
    """Remove only a probe whose full ID, exact name and random label agree."""
    raw = runner(prefix + ["container", "ls", "--all", "--no-trunc",
                 "--filter", "label=clipforge.inventory.probe=" + probe_identity,
                 "--filter", "name=^/" + container_name + "$", "--format", "{{.ID}}"],
                 artifacts, "probe-cleanup-list")
    identifiers = raw.decode("ascii").splitlines()
    require(len(identifiers) <= 1, "Ambiguous inventory probe cleanup; no resource removed")
    if not identifiers:
        return
    identifier = identifiers[0]
    require(re.fullmatch(r"[0-9a-f]{64}", identifier), "Invalid cleanup container ID")
    identity = runner(prefix + ["container", "inspect", "--format",
        '{{.Id}}|{{.Name}}|{{index .Config.Labels "clipforge.inventory.probe"}}', identifier],
        artifacts, "probe-cleanup-identity").decode("ascii").strip()
    require(identity == identifier + "|/" + container_name + "|" + probe_identity,
            "Inventory probe cleanup identity mismatch; no resource removed")
    runner(prefix + ["container", "rm", "--force", identifier], artifacts, "probe-cleanup-remove")


def _cancel_capture(signum, frame):
    raise KeyboardInterrupt("Inventory capture cancelled")


def capture(image_reference, image_id, container_name, *, artifacts, runner=_execute):
    require(image_reference == POSTGRES_IMAGE, "Only the reviewed pinned PostgreSQL image is permitted")
    require(type(image_id) is str and re.fullmatch(r"sha256:[0-9a-f]{64}", image_id), "A verified PostgreSQL image ID is required")
    require(re.fullmatch(r"clipforge-ci-pg-inventory-[a-z0-9][a-z0-9-]{0,80}", container_name),
            "Use an exclusively named CI PostgreSQL inventory container")
    artifacts = Path(artifacts)
    require(not artifacts.exists(), "An inventory attempt needs a new artifact directory")
    artifacts.mkdir(parents=True)
    docker = host_executable("docker")
    probe_identity = uuid.uuid4().hex
    with tempfile.TemporaryDirectory(prefix="clipforge-pg-inventory-docker-") as configuration:
        engine = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
        prefix = [docker, "--config", configuration, "--host", engine]
        raw_identity = runner(prefix + ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", image_reference],
                              artifacts, "image-identity")
        require(raw_identity.decode("ascii").strip() == image_id + "|linux|amd64", "Image reference/configuration/platform mismatch")
        argv = prefix + ["run", "--rm", "--pull", "never", "--platform", "linux/amd64",
                         "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                         "--user", "65534:65534", "--name", container_name,
                         "--label", "clipforge.inventory.probe=" + probe_identity,
                         "--tmpfs", "/var/lib/postgresql:ro,nosuid,nodev,size=1m", "--entrypoint", "/bin/sh",
                         image_id, "-ec", PROBE]
        _write_json(artifacts / "probe-identity.json", {"container_name": container_name,
                    "probe_identity": probe_identity, "image_id": image_id})
        previous_handler = None
        handle_signal = threading.current_thread() is threading.main_thread()
        if handle_signal:
            previous_handler = signal.signal(signal.SIGTERM, _cancel_capture)
        try:
            raw = runner(argv, artifacts, "package-probe")
        finally:
            if handle_signal:
                signal.signal(signal.SIGTERM, signal.SIG_IGN)
            try:
                _cleanup_probe(prefix, container_name, probe_identity, artifacts, runner)
            finally:
                if handle_signal:
                    signal.signal(signal.SIGTERM, previous_handler)
    inventory = parse_probe(raw, image_id=image_id, image_reference=image_reference)
    inventory["capture"] = {"container_name": container_name, "probe_identity": probe_identity,
                            "captured_utc": datetime.now(timezone.utc).isoformat()}
    return inventory


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", required=True)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--container-name", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    artifacts = args.output.with_name(args.output.stem + ".capture")
    try:
        require(not args.output.exists(), "The inventory output must be new")
        result = capture(args.image, args.image_id, args.container_name, artifacts=artifacts)
        _write_json(args.output, result)
    except (InventoryError, OSError, UnicodeError, ValueError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__,
                          "message": "PostgreSQL inventory failed; preserve the attempt artifacts. No valid inventory was written."}), file=sys.stderr)
        return 130 if isinstance(error, KeyboardInterrupt) else 1
    print(json.dumps({"status": "captured", "image_id": result["image_id"],
                      "installed_packages": result["dpkg"]["installed_package_count"], "output": str(args.output)}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
