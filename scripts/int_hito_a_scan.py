"""Closed security validator for the exact Hito A INT runtime candidate.

The validator never trusts a scanner-generated package count as an inventory.
It derives the final dpkg and Python package sets directly from the verified OCI
layers, then requires Trivy JSON and CycloneDX to describe exactly those sets.
The OCI manifest, config, compressed layers and uncompressed diff IDs are all
verified before reports are considered.  The Trivy database file and metadata
are hashed and must be fresh for the report timestamp.

This module does not scan the GitHub-hosted runner.  The accepted hosted-runner
risk therefore cannot change the application-image thresholds enforced here.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timedelta, timezone
from email import policy
from email.parser import BytesParser
import gzip
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import tarfile
from urllib.parse import parse_qs, unquote


SCHEMA = "clipforge-int-hito-a-scan-receipt-1"
TRIVY_VERSION = "0.76.2"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
HEX64 = re.compile(r"[a-f0-9]{64}")
TARGETS = {("os-pkgs", "ubuntu"), ("lang-pkgs", "python-pkg")}
SEVERITIES = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
BLOCKING = {"UNKNOWN", "HIGH", "CRITICAL"}
LAYER_MEDIA_TYPES = {
    "application/vnd.oci.image.layer.v1.tar",
    "application/vnd.oci.image.layer.v1.tar+gzip",
    "application/vnd.docker.image.rootfs.diff.tar",
    "application/vnd.docker.image.rootfs.diff.tar.gzip",
}
MANIFEST_MEDIA_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}
CONFIG_MEDIA_TYPES = {
    "application/vnd.oci.image.config.v1+json",
    "application/vnd.docker.container.image.v1+json",
}
MAX_ARCHIVE = 4 * 1024 * 1024 * 1024
MAX_LAYER = 1024 * 1024 * 1024
MAX_JSON = 64 * 1024 * 1024
MAX_CONFIG = 4 * 1024 * 1024
MAX_METADATA = 2 * 1024 * 1024
MAX_STATUS = 16 * 1024 * 1024
MAX_LAYER_ENTRIES = 1_000_000
MEDIA_PYTHON = {"av", "ctranslate2", "faster-whisper", "onnxruntime"}
MEDIA_DEBIAN = {"ffmpeg"}
MEDIA_DEBIAN_PREFIXES = ("libavcodec", "libavdevice", "libavfilter", "libavformat", "libavutil",
                         "libpostproc", "libswresample", "libswscale")


class ScanBlocked(ValueError):
    """A fixed, non-sensitive validation failure code."""


def require(condition, code):
    if not condition:
        raise ScanBlocked(code)


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def no_duplicate_keys(pairs):
    value = {}
    for key, item in pairs:
        require(key not in value, "duplicate_json_key")
        value[key] = item
    return value


def json_bytes(raw, code):
    require(isinstance(raw, bytes) and 0 < len(raw) <= MAX_JSON, code + "_size")
    try:
        return json.loads(raw, object_pairs_hook=no_duplicate_keys)
    except ScanBlocked:
        raise
    except (UnicodeError, ValueError):
        raise ScanBlocked(code + "_json") from None


def regular_file(path, maximum, code):
    path = Path(path)
    require(path.is_absolute() and path.exists() and not path.is_symlink(), code + "_path")
    info = path.stat()
    require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum, code + "_shape")
    return path


def hash_file(path):
    digest = hashlib.sha256()
    size = 0
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def load_json(path, maximum, code):
    path = regular_file(path, maximum, code)
    return json_bytes(path.read_bytes(), code)


def normalized_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 400, "package_name")
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_time(value, code):
    require(isinstance(value, str) and 10 <= len(value) <= 64, code)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        raise ScanBlocked(code) from None
    require(parsed.tzinfo is not None, code)
    return parsed.astimezone(timezone.utc)


def normalize_tar_name(name):
    require(isinstance(name, str) and 0 < len(name) <= 1024 and "\\" not in name and "\0" not in name,
            "unsafe_tar_path")
    while name.startswith("./"):
        name = name[2:]
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and all(part not in {"", ".", ".."} for part in path.parts),
            "unsafe_tar_path")
    return path.as_posix()


def tar_members(archive):
    result = {}
    for member in archive.getmembers():
        name = normalize_tar_name(member.name)
        if member.isdir():
            continue
        require(member.isfile() and name not in result, "oci_archive_member")
        result[name] = member
    return result


def read_member(archive, members, name, maximum, code):
    member = members.get(name)
    require(member is not None and member.isfile() and 0 < member.size <= maximum, code + "_member")
    stream = archive.extractfile(member)
    require(stream is not None, code + "_member")
    raw = stream.read(maximum + 1)
    require(len(raw) == member.size and len(raw) <= maximum, code + "_size")
    return raw


def descriptor(value, media_types, maximum, code):
    require(isinstance(value, dict) and value.get("mediaType") in media_types
            and DIGEST.fullmatch(value.get("digest", ""))
            and type(value.get("size")) is int and 0 < value["size"] <= maximum, code)
    return value


def read_descriptor(archive, members, value, maximum, code):
    name = "blobs/sha256/" + value["digest"].removeprefix("sha256:")
    raw = read_member(archive, members, name, maximum, code)
    require(len(raw) == value["size"] and "sha256:" + hashlib.sha256(raw).hexdigest() == value["digest"],
            code + "_digest")
    return raw, name


def relevant_file(path):
    if path in {"etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status"}:
        return True
    parent, leaf = PurePosixPath(path).parent.name, PurePosixPath(path).name
    return ((parent.endswith(".dist-info") and leaf == "METADATA")
            or (parent.endswith(".egg-info") and leaf == "PKG-INFO")
            or leaf.endswith(".egg-info"))


def forbidden_path(path):
    parts = PurePosixPath(path).parts
    lowered = tuple(part.lower() for part in parts)
    leaf = lowered[-1]
    module = None
    for marker in ("site-packages", "dist-packages"):
        if marker in lowered and lowered.index(marker) + 1 < len(lowered):
            module = normalized_name(lowered[lowered.index(marker) + 1].split(".", 1)[0])
            break
    return (leaf in {"ffmpeg", "ffprobe", "node", "nodejs", "npm", "npx", "corepack",
                     "package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}
            or "node_modules" in lowered or module in MEDIA_PYTHON
            or (".so" in leaf and leaf.startswith(MEDIA_DEBIAN_PREFIXES)))


class LayerState:
    def __init__(self):
        self.files = {}
        self.forbidden = set()

    def remove(self, target, *, children=True):
        if target == "" and children:
            self.files.clear()
            self.forbidden.clear()
            return
        prefix = target.rstrip("/") + "/"
        self.files = {name: raw for name, raw in self.files.items()
                      if name != target and (not children or not name.startswith(prefix))}
        self.forbidden = {name for name in self.forbidden
                          if name != target and (not children or not name.startswith(prefix))}

    def apply(self, layer, member):
        if member.isdir() and member.name in {".", "./"}:
            return
        path = normalize_tar_name(member.name)
        leaf = PurePosixPath(path).name
        parent = PurePosixPath(path).parent.as_posix()
        if leaf == ".wh..wh..opq":
            require(member.size == 0, "invalid_opaque_whiteout")
            prefix = "" if parent == "." else parent
            self.remove(prefix, children=True)
            return
        if leaf.startswith(".wh."):
            require(member.size == 0 and len(leaf) > 4, "invalid_whiteout")
            target = leaf[4:] if parent == "." else parent + "/" + leaf[4:]
            self.remove(target, children=True)
            return
        if relevant_file(path):
            self.files.pop(path, None)
            if member.isfile():
                maximum = MAX_STATUS if path == "var/lib/dpkg/status" else MAX_METADATA
                require(0 < member.size <= maximum, "inventory_file_size")
                stream = layer.extractfile(member)
                require(stream is not None, "inventory_file_read")
                raw = stream.read(maximum + 1)
                require(len(raw) == member.size and len(raw) <= maximum, "inventory_file_read")
                self.files[path] = raw
        if forbidden_path(path) and (not member.isdir()
                                     or "node_modules" in {part.lower() for part in PurePosixPath(path).parts}):
            self.forbidden.add(path)


class HashingReader:
    def __init__(self, stream):
        self.stream = stream
        self.digest = hashlib.sha256()

    def read(self, size=-1):
        raw = self.stream.read(size)
        self.digest.update(raw)
        return raw


def hash_stream(stream, maximum, code):
    digest = hashlib.sha256()
    size = 0
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        size += len(block)
        require(size <= maximum, code + "_size")
        digest.update(block)
    return digest.hexdigest(), size


def apply_layer(archive, member, layer_descriptor, expected_diff_id, state):
    stream = archive.extractfile(member)
    require(stream is not None, "layer_read")
    compressed_hash, compressed_size = hash_stream(stream, MAX_LAYER, "layer")
    require(compressed_size == layer_descriptor["size"]
            and "sha256:" + compressed_hash == layer_descriptor["digest"], "layer_digest")

    stream = archive.extractfile(member)
    require(stream is not None, "layer_read")
    media_type = layer_descriptor["mediaType"]
    decoded = gzip.GzipFile(fileobj=stream, mode="rb") if media_type.endswith(("+gzip", ".gzip")) else stream
    reader = HashingReader(decoded)
    count = 0
    try:
        with tarfile.open(fileobj=reader, mode="r|") as layer:
            for entry in layer:
                count += 1
                require(count <= MAX_LAYER_ENTRIES, "layer_entry_bound")
                state.apply(layer, entry)
        for _ in iter(lambda: reader.read(1024 * 1024), b""):
            pass
    except (OSError, tarfile.TarError):
        raise ScanBlocked("layer_tar_invalid") from None
    finally:
        if decoded is not stream:
            decoded.close()
        stream.close()
    require("sha256:" + reader.digest.hexdigest() == expected_diff_id, "layer_diff_id")


def parse_os_release(raw):
    values = {}
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ScanBlocked("os_release_encoding") from None
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        require("=" in line, "os_release_line")
        key, value = line.split("=", 1)
        require(re.fullmatch(r"[A-Z][A-Z0-9_]*", key) and key not in values, "os_release_key")
        if len(value) >= 2 and value[0] == value[-1] and value[0] in {'"', "'"}:
            value = value[1:-1]
        require("\n" not in value and "\r" not in value, "os_release_value")
        values[key] = value
    require(values.get("ID") == "ubuntu" and values.get("VERSION_ID") == "24.04", "demo_os_profile")
    return {"family": "ubuntu", "version": "24.04"}


def debian_packages(raw):
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        raise ScanBlocked("dpkg_status_encoding") from None
    result = set()
    for paragraph in re.split(r"\n\s*\n", text.strip()):
        fields = {}
        for line in paragraph.splitlines():
            if not line or line[0].isspace() or ":" not in line:
                continue
            key, value = line.split(":", 1)
            if key in {"Package", "Version", "Status"}:
                require(key not in fields, "dpkg_duplicate_field")
                fields[key] = value.strip()
        if fields.get("Status") == "install ok installed":
            name, version = fields.get("Package"), fields.get("Version")
            require(isinstance(name, str) and isinstance(version, str)
                    and 0 < len(name) <= 400 and 0 < len(version) <= 400, "dpkg_package_identity")
            require((name, version) not in result, "dpkg_duplicate_package")
            result.add((name, version))
    require(result, "dpkg_inventory_empty")
    return result


def python_packages(files):
    result = set()
    for path, raw in files.items():
        if path in {"etc/os-release", "usr/lib/os-release", "var/lib/dpkg/status"}:
            continue
        try:
            message = BytesParser(policy=policy.compat32).parsebytes(raw, headersonly=True)
        except (UnicodeError, ValueError):
            raise ScanBlocked("python_metadata_invalid") from None
        names, versions = message.get_all("Name", []), message.get_all("Version", [])
        require(len(names) == len(versions) == 1, "python_metadata_identity")
        name, version = normalized_name(names[0]), versions[0].strip()
        require(0 < len(version) <= 400, "python_metadata_identity")
        require((name, version) not in result, "python_duplicate_package")
        result.add((name, version))
    require(result, "python_inventory_empty")
    return result


def inventory_from_layers(state):
    os_raw = state.files.get("etc/os-release") or state.files.get("usr/lib/os-release")
    require(os_raw is not None, "os_release_missing")
    require("var/lib/dpkg/status" in state.files, "dpkg_status_missing")
    os_identity = parse_os_release(os_raw)
    packages = {
        ("os-pkgs", "ubuntu"): debian_packages(state.files["var/lib/dpkg/status"]),
        ("lang-pkgs", "python-pkg"): python_packages(state.files),
    }
    os_names = {name for name, _ in packages[("os-pkgs", "ubuntu")]}
    py_names = {name for name, _ in packages[("lang-pkgs", "python-pkg")]}
    require(not state.forbidden, "demo_forbidden_executable_or_node_metadata")
    require(not (MEDIA_DEBIAN & os_names)
            and not any(name.startswith(MEDIA_DEBIAN_PREFIXES) for name in os_names), "demo_media_os_package")
    require(not (MEDIA_PYTHON & py_names), "demo_media_python_package")
    require(not ({"nodejs", "npm"} & os_names), "demo_node_package")
    return os_identity, packages


def verify_oci(path, expected_manifest):
    path = regular_file(path, MAX_ARCHIVE, "oci_archive")
    require(DIGEST.fullmatch(expected_manifest or ""), "expected_manifest_digest")
    try:
        archive = tarfile.open(path, "r:*")
    except tarfile.TarError:
        raise ScanBlocked("oci_archive_tar") from None
    with archive:
        members = tar_members(archive)
        layout = json_bytes(read_member(archive, members, "oci-layout", 4096, "oci_layout"), "oci_layout")
        require(layout == {"imageLayoutVersion": "1.0.0"}, "oci_layout_contract")
        index = json_bytes(read_member(archive, members, "index.json", 1024 * 1024, "oci_index"), "oci_index")
        manifests = index.get("manifests") if isinstance(index, dict) else None
        require(index.get("schemaVersion") == 2 and isinstance(manifests, list) and len(manifests) == 1,
                "oci_single_manifest")
        manifest_descriptor = descriptor(manifests[0], MANIFEST_MEDIA_TYPES, MAX_CONFIG, "oci_manifest_descriptor")
        require(manifest_descriptor["digest"] == expected_manifest, "oci_expected_manifest")
        manifest_raw, manifest_name = read_descriptor(
            archive, members, manifest_descriptor, MAX_CONFIG, "oci_manifest"
        )
        manifest = json_bytes(manifest_raw, "oci_manifest")
        require(isinstance(manifest, dict) and manifest.get("schemaVersion") == 2
                and manifest.get("mediaType") in MANIFEST_MEDIA_TYPES, "oci_manifest_contract")
        config_descriptor = descriptor(manifest.get("config"), CONFIG_MEDIA_TYPES, MAX_CONFIG,
                                       "oci_config_descriptor")
        config_raw, config_name = read_descriptor(archive, members, config_descriptor, MAX_CONFIG, "oci_config")
        config = json_bytes(config_raw, "oci_config")
        layers = manifest.get("layers")
        require(isinstance(layers, list) and layers, "oci_layers")
        layers = [descriptor(row, LAYER_MEDIA_TYPES, MAX_LAYER, "oci_layer_descriptor") for row in layers]
        require(len({row["digest"] for row in layers}) == len(layers), "oci_duplicate_layer")
        rootfs = config.get("rootfs") if isinstance(config, dict) else None
        diff_ids = rootfs.get("diff_ids") if isinstance(rootfs, dict) else None
        require(config.get("architecture") == "amd64" and config.get("os") == "linux"
                and rootfs.get("type") == "layers" and isinstance(diff_ids, list)
                and len(diff_ids) == len(layers) and all(DIGEST.fullmatch(row or "") for row in diff_ids),
                "oci_config_rootfs")
        history = config.get("history", [])
        require(isinstance(history, list) and all(isinstance(row, dict) for row in history)
                and sum(not row.get("empty_layer", False) for row in history) == len(layers),
                "oci_history_layers")
        config_values = config.get("config", {})
        require(isinstance(config_values, dict) and config_values.get("User") == "10001:10001"
                and config_values.get("WorkingDir") == "/app", "demo_runtime_config")
        env = config_values.get("Env", [])
        require(isinstance(env, list) and "CLIPFORGE_RUNTIME_PROFILE=int-demo-a" in env,
                "demo_runtime_environment")

        expected_files = {"oci-layout", "index.json", manifest_name, config_name}
        state = LayerState()
        layer_receipts = []
        for row, diff_id in zip(layers, diff_ids, strict=True):
            name = "blobs/sha256/" + row["digest"].removeprefix("sha256:")
            member = members.get(name)
            require(member is not None and member.isfile() and member.size == row["size"], "oci_layer_member")
            expected_files.add(name)
            apply_layer(archive, member, row, diff_id, state)
            layer_receipts.append({"digest": row["digest"], "size": row["size"], "diff_id": diff_id})
        require(set(members) == expected_files, "oci_unreferenced_file")
        os_identity, packages = inventory_from_layers(state)
        return {
            "manifest_digest": expected_manifest,
            "config_digest": config_descriptor["digest"],
            "config": config,
            "diff_ids": diff_ids,
            "layers": layer_receipts,
            "os": os_identity,
            "packages": packages,
        }


def complete_debian_version(package):
    name, version = package.get("Name"), package.get("Version")
    require(isinstance(name, str) and isinstance(version, str) and name and version, "trivy_package_identity")
    epoch, release = package.get("Epoch", 0), package.get("Release", "")
    require(type(epoch) is int and epoch >= 0 and isinstance(release, str), "trivy_debian_version")
    if release:
        version += "-" + release
    if epoch:
        require(":" not in version, "trivy_debian_epoch")
        version = str(epoch) + ":" + version
    if package.get("ID"):
        require(package["ID"] == name + "@" + version, "trivy_package_id")
    return name, version


def purl_identity(value, kind):
    require(isinstance(value, str) and 0 < len(value) <= 4096 and "#" not in value, "package_purl")
    if kind == "ubuntu":
        prefix = "pkg:deb/ubuntu/"
    else:
        prefix = "pkg:pypi/"
    require(value.startswith(prefix), "package_purl_ecosystem")
    body, query = (value.split("?", 1) + [""])[:2]
    identity = body[len(prefix):]
    require("@" in identity, "package_purl_version")
    name, version = (unquote(part) for part in identity.rsplit("@", 1))
    qualifiers = parse_qs(query, strict_parsing=True) if query else {}
    if "epoch" in qualifiers:
        epoch = qualifiers["epoch"]
        require(kind == "ubuntu" and len(epoch) == 1 and re.fullmatch(r"[1-9][0-9]*", epoch[0])
                and ":" not in version, "package_purl_epoch")
        version = epoch[0] + ":" + version
    return (normalized_name(name) if kind == "python-pkg" else name, version)


def trivy_package(package, kind):
    require(isinstance(package, dict), "trivy_package")
    if kind == "ubuntu":
        identity = complete_debian_version(package)
    else:
        name, version = package.get("Name"), package.get("Version")
        require(isinstance(name, str) and isinstance(version, str) and name and version,
                "trivy_package_identity")
        identity = normalized_name(name), version
    purl = package.get("Identifier", {}).get("PURL") if isinstance(package.get("Identifier"), dict) else None
    require(purl_identity(purl, kind) == identity, "trivy_package_purl_mismatch")
    return identity


def verify_trivy(report, oci, at):
    require(isinstance(report, dict) and report.get("SchemaVersion") == 2
            and report.get("Trivy", {}).get("Version") == TRIVY_VERSION
            and report.get("ArtifactType") in {"container_image", "oci"}, "trivy_report_identity")
    created = parse_time(report.get("CreatedAt"), "trivy_created_at")
    require(created <= at + timedelta(minutes=5) and at - created <= timedelta(hours=2),
            "trivy_report_freshness")
    metadata = report.get("Metadata")
    require(isinstance(metadata, dict) and metadata.get("ImageID") == oci["config_digest"]
            and metadata.get("DiffIDs") == oci["diff_ids"]
            and metadata.get("ImageConfig") == oci["config"], "trivy_oci_identity")
    os_metadata = metadata.get("OS", {})
    require(isinstance(os_metadata, dict) and os_metadata.get("Family") == "ubuntu"
            and str(os_metadata.get("Name", "")).startswith("24.04"), "trivy_os_identity")

    groups = {key: set() for key in TARGETS}
    target_packages = {}
    findings = Counter({severity: 0 for severity in sorted(SEVERITIES)})
    results = report.get("Results")
    require(isinstance(results, list) and results, "trivy_results")
    for target in results:
        require(isinstance(target, dict), "trivy_target")
        key = target.get("Class"), target.get("Type")
        name = target.get("Target")
        require(key in TARGETS and isinstance(name, str) and name and name not in target_packages,
                "trivy_target_scope")
        packages = target.get("Packages")
        require(isinstance(packages, list) and packages, "trivy_target_packages")
        current = set()
        for package in packages:
            identity = trivy_package(package, key[1])
            require(identity not in current and identity not in groups[key], "trivy_duplicate_package")
            current.add(identity)
            groups[key].add(identity)
        target_packages[name] = (key, current)
        vulnerabilities = target.get("Vulnerabilities") or []
        require(isinstance(vulnerabilities, list), "trivy_vulnerabilities")
        for row in vulnerabilities:
            require(isinstance(row, dict) and row.get("Severity") in SEVERITIES
                    and isinstance(row.get("VulnerabilityID"), str) and row["VulnerabilityID"]
                    and isinstance(row.get("Fingerprint"), str) and row["Fingerprint"],
                    "trivy_finding")
            package_purl = row.get("PkgIdentifier", {}).get("PURL") if isinstance(row.get("PkgIdentifier"), dict) else None
            identity = purl_identity(package_purl, key[1])
            finding_name = normalized_name(row.get("PkgName")) if key[1] == "python-pkg" else row.get("PkgName")
            require(identity in current and finding_name == identity[0]
                    and row.get("InstalledVersion") == identity[1],
                    "trivy_finding_package")
            findings[row["Severity"]] += 1
    require(set(key for key, rows in groups.items() if rows) == TARGETS, "trivy_target_types")
    require(groups == oci["packages"], "trivy_inventory_mismatch")
    require(not any(findings[severity] for severity in BLOCKING), "trivy_blocking_finding")
    return created, groups, dict(findings), len(results)


def verify_sbom(sbom, oci, expected_packages, trivy_created):
    require(isinstance(sbom, dict) and sbom.get("bomFormat") == "CycloneDX"
            and str(sbom.get("specVersion", "")) in {"1.5", "1.6", "1.7"}, "sbom_identity")
    timestamp = parse_time(sbom.get("metadata", {}).get("timestamp"), "sbom_timestamp")
    require(abs((timestamp - trivy_created).total_seconds()) <= 10 * 60, "sbom_report_time")
    metadata = sbom.get("metadata", {})
    tools = metadata.get("tools", {}) if isinstance(metadata, dict) else {}
    tool_components = tools.get("components", []) if isinstance(tools, dict) else []
    trivy_tools = [row for row in tool_components if isinstance(row, dict) and row.get("name") == "trivy"]
    require(len(trivy_tools) == 1 and trivy_tools[0].get("group") == "aquasecurity"
            and trivy_tools[0].get("version") == TRIVY_VERSION, "sbom_tool_identity")
    root = metadata.get("component", {}) if isinstance(metadata, dict) else {}
    require(isinstance(root, dict) and root.get("type") == "container", "sbom_root_component")
    properties = root.get("properties", [])
    require(isinstance(properties, list), "sbom_properties")
    image_ids = [row.get("value") for row in properties
                 if isinstance(row, dict) and row.get("name") == "aquasecurity:trivy:ImageID"]
    diff_ids = [row.get("value") for row in properties
                if isinstance(row, dict) and row.get("name") == "aquasecurity:trivy:DiffID"]
    require(image_ids == [oci["config_digest"]] and sorted(diff_ids) == sorted(oci["diff_ids"]),
            "sbom_oci_identity")

    groups = {key: set() for key in TARGETS}
    systems = []
    refs = set()
    components = sbom.get("components")
    require(isinstance(components, list) and components, "sbom_components")
    for component in components:
        require(isinstance(component, dict), "sbom_component")
        reference = component.get("bom-ref")
        require(isinstance(reference, str) and reference and reference not in refs, "sbom_component_reference")
        refs.add(reference)
        if component.get("type") == "operating-system":
            systems.append((component.get("name"), component.get("version")))
            continue
        purl = component.get("purl")
        if isinstance(purl, str) and purl.startswith("pkg:deb/ubuntu/"):
            key = "os-pkgs", "ubuntu"
        elif isinstance(purl, str) and purl.startswith("pkg:pypi/"):
            key = "lang-pkgs", "python-pkg"
        else:
            raise ScanBlocked("sbom_uninventoried_component")
        identity = purl_identity(purl, key[1])
        component_name = normalized_name(component.get("name")) if key[1] == "python-pkg" else component.get("name")
        require(identity == (component_name, component.get("version")) and identity not in groups[key],
                "sbom_component_identity")
        groups[key].add(identity)
    require(systems == [("ubuntu", "24.04")] and groups == expected_packages,
            "sbom_inventory_mismatch")
    return groups, len(components)


def verify_database(path, metadata_path, created, at):
    path = regular_file(path, 2 * 1024 * 1024 * 1024, "trivy_db")
    metadata_path = regular_file(metadata_path, 64 * 1024, "trivy_db_metadata")
    metadata = json_bytes(metadata_path.read_bytes(), "trivy_db_metadata")
    require(isinstance(metadata, dict) and metadata.get("Version") == 2, "trivy_db_metadata_version")
    updated = parse_time(metadata.get("UpdatedAt"), "trivy_db_updated_at")
    downloaded = parse_time(metadata.get("DownloadedAt"), "trivy_db_downloaded_at")
    next_update = parse_time(metadata.get("NextUpdate"), "trivy_db_next_update")
    require(updated <= downloaded <= created + timedelta(minutes=5)
            and updated <= created < next_update and next_update > at, "trivy_db_freshness")
    digest, size = hash_file(path)
    metadata_digest, metadata_size = hash_file(metadata_path)
    require(HEX64.fullmatch(digest) and size > 0 and metadata_size > 0, "trivy_db_hash")
    return {
        "sha256": digest,
        "bytes": size,
        "metadata_sha256": metadata_digest,
        "metadata_bytes": metadata_size,
        "updated_at": updated.isoformat().replace("+00:00", "Z"),
        "downloaded_at": downloaded.isoformat().replace("+00:00", "Z"),
        "next_update": next_update.isoformat().replace("+00:00", "Z"),
    }


def package_digest(packages):
    value = {"/".join(key): sorted([list(row) for row in rows]) for key, rows in sorted(packages.items())}
    return hashlib.sha256(canonical(value)).hexdigest()


def verify(args, *, at=None):
    at = (at or datetime.now(timezone.utc)).astimezone(timezone.utc)
    oci = verify_oci(args.archive, args.expected_manifest)
    trivy_path = regular_file(args.trivy, MAX_JSON, "trivy_report")
    sbom_path = regular_file(args.sbom, MAX_JSON, "sbom_report")
    trivy = json_bytes(trivy_path.read_bytes(), "trivy_report")
    sbom = json_bytes(sbom_path.read_bytes(), "sbom_report")
    created, scanned, findings, target_count = verify_trivy(trivy, oci, at)
    _, component_count = verify_sbom(sbom, oci, scanned, created)
    database = verify_database(args.db, args.db_metadata, created, at)
    archive_sha, archive_size = hash_file(args.archive)
    trivy_sha, trivy_size = hash_file(trivy_path)
    sbom_sha, sbom_size = hash_file(sbom_path)
    counts = {"/".join(key): len(rows) for key, rows in sorted(oci["packages"].items())}
    return {
        "schema": SCHEMA,
        "status": "passed",
        "manifest_digest": oci["manifest_digest"],
        "config_digest": oci["config_digest"],
        "archive": {"sha256": archive_sha, "bytes": archive_size},
        "layers": oci["layers"],
        "inventory": {
            "source": "verified_oci_layers",
            "os": oci["os"],
            "packages": counts,
            "package_set_sha256": package_digest(oci["packages"]),
            "ffmpeg_present": False,
            "node_present": False,
            "av_present": False,
        },
        "trivy": {
            "version": TRIVY_VERSION,
            "created_at": created.isoformat().replace("+00:00", "Z"),
            "sha256": trivy_sha,
            "bytes": trivy_size,
            "targets": target_count,
            "findings": findings,
        },
        "sbom": {"format": "CycloneDX", "sha256": sbom_sha, "bytes": sbom_size,
                 "components": component_count},
        "database": database,
        "gates": {
            "oci_config_diffids_layers_verified": True,
            "independent_inventory_equal": True,
            "trivy_and_sbom_complete": True,
            "database_identity_and_freshness_verified": True,
            "unknown_high_critical_absent": True,
            "demo_media_and_node_closed": True,
        },
    }


def write_new(path, value):
    path = Path(path)
    require(path.is_absolute() and path.parent.is_dir() and not path.exists(), "scan_receipt_path")
    raw = json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True).encode("ascii") + b"\n"
    descriptor_number = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    with os.fdopen(descriptor_number, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def parser():
    value = argparse.ArgumentParser(description=__doc__)
    subcommands = value.add_subparsers(dest="operation", required=True)
    check = subcommands.add_parser("verify")
    check.add_argument("--archive", required=True, type=Path)
    check.add_argument("--expected-manifest", required=True)
    check.add_argument("--trivy", required=True, type=Path)
    check.add_argument("--sbom", required=True, type=Path)
    check.add_argument("--db", required=True, type=Path)
    check.add_argument("--db-metadata", required=True, type=Path)
    check.add_argument("--output", required=True, type=Path)
    return value


def main(argv=None):
    os.umask(0o077)
    args = parser().parse_args(argv)
    try:
        receipt = verify(args)
        write_new(args.output, receipt)
    except (ScanBlocked, KeyError, TypeError, OSError, tarfile.TarError, gzip.BadGzipFile):
        print(json.dumps({"status": "blocked", "operation": args.operation,
                          "receipt": "unavailable"}, sort_keys=True))
        return 1
    print(json.dumps({"status": "passed", "operation": args.operation,
                      "manifest_digest": receipt["manifest_digest"],
                      "receipt": str(args.output)}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
