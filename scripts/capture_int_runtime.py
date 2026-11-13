"""Independent INT runtime inventory and exact existing SBOM/SCA comparison.

capture runs only in the named disposable runtime image, offline and without
credentials. verify reads explicitly supplied artifacts outside the checkout;
it never starts a scanner or extracts image archives onto the filesystem.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys
import tarfile
from urllib.parse import parse_qs, unquote


SCHEMA = "clipforge-int-runtime-inventory-1"
VERIFY_SCHEMA = "clipforge-int-runtime-comparison-1"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
TARGETS = {("os-pkgs", "debian"), ("lang-pkgs", "python-pkg")}
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def require(value, message):
    if not value:
        raise ValueError(message)


def normalized_name(name):
    require(isinstance(name, str) and bool(name), "Missing package name")
    return re.sub(r"[-_.]+", "-", name).lower()


def sha256(path):
    digest = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key in artifact")
        result[key] = value
    return result


def json_bytes(data):
    return json.loads(data, object_pairs_hook=no_duplicate_keys)


def json_file(path):
    return json_bytes(Path(path).read_bytes())


def save_new(path, value):
    with Path(path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def debian_packages(status):
    result = []
    for paragraph in status.strip().split("\n\n"):
        fields = dict(line.split(": ", 1) for line in paragraph.splitlines() if line and not line[0].isspace() and ": " in line)
        if fields.get("Status") == "install ok installed":
            result.append({"Name": fields["Package"], "Version": fields["Version"]})
    require(bool(result), "No installed Debian package inventory")
    return sorted(result, key=lambda value: (value["Name"], value["Version"]))


def file_record(path):
    path = Path(path)
    require(path.is_file(), "Missing runtime binary")
    info = path.stat()
    return {"path": str(path), "bytes": info.st_size, "sha256": sha256(path)}


def is_elf(path):
    with Path(path).open("rb") as stream:
        return stream.read(4) == b"\x7fELF"


def native_inventory(distributions):
    """Inventory real ELF files, including wheel .libs outside import packages."""
    owners = {}
    roots = set()
    for distribution in distributions:
        owner = {"Name": normalized_name(distribution.metadata["Name"]), "Version": distribution.version}
        root = Path(distribution.locate_file("")).resolve()
        require(str(root).startswith(("/usr/local/lib/", "/usr/lib/")), "Unexpected runtime package root")
        roots.add(root)
        for name in distribution.files or ():
            path = Path(distribution.locate_file(name)).resolve()
            owners.setdefault(path, []).append(owner)
    native, package_json = [], []
    for root in sorted(roots):
        for path in sorted(root.rglob("*")):
            if not path.is_file():
                continue
            resolved = path.resolve()
            require(resolved.is_relative_to(root), "Package inventory symlink escaped the installed runtime libraries")
            if path.name in {"package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml"}:
                package_json.append(file_record(path))
            if is_elf(path):
                native.append({**file_record(path), "owners": owners.get(resolved, []), "format": "ELF",
                    "vendored_library": ".libs" in str(path) or any(part.endswith(".libs") for part in path.parts)})
    return native, package_json


def capture(image_id, *, status=Path("/var/lib/dpkg/status"), release=Path("/etc/debian_version")):
    require(DIGEST.fullmatch(image_id), "An independently verified local runtime image ID is required")
    distributions = list(importlib.metadata.distributions())
    python = sorted([{"Name": normalized_name(item.metadata["Name"]), "Version": item.version} for item in distributions],
                    key=lambda value: (value["Name"], value["Version"]))
    require(bool(python), "No installed Python package inventory")
    native, node_metadata = native_inventory(distributions)
    node_binaries = [file_record(path) for path in (Path("/usr/local/bin/node"), Path("/usr/bin/node")) if path.is_file()]
    require(not node_metadata and not node_binaries, "Unexpected Node components require their own complete inventory and SCA target")
    import av
    av_libraries = {name: list(version) for name, version in sorted(av.library_versions.items())}
    media = [file_record(path) for path in (Path("/usr/bin/ffmpeg"), Path("/usr/bin/ffprobe"))]
    interpreter = Path(sys.executable).resolve()
    system_native = [file_record(interpreter)]
    system_native += [file_record(path) for path in sorted(Path("/usr/local/lib").glob("libpython*.so*"))
                      if path.is_file() and not path.is_symlink()]
    sources = [file_record(path) for path in sorted(Path("/app/app").rglob("*.py"))]
    return {"schema": SCHEMA, "local_tested_image_id": image_id,
        "os": {"family": "debian", "version": release.read_text().strip()},
        "python_runtime": {"version": sys.version.split()[0], "executable": str(interpreter)},
        "targets": [{"Class": "os-pkgs", "Type": "debian", "Packages": debian_packages(status.read_text())},
                    {"Class": "lang-pkgs", "Type": "python-pkg", "Packages": python}],
        "node": {"present": False, "package_metadata": node_metadata, "binaries": node_binaries},
        "media_binaries": media, "python_runtime_binaries": system_native, "python_native_binaries": native,
        "av_library_versions": av_libraries, "application_sources": sources,
        "scope": "installed dpkg/Python metadata plus native ELF files; no API import or user data",
        "native_sca_limit": "Python package metadata SCA does not establish vulnerability coverage of libraries bundled in native wheels. OS CVEs are not automatically assigned to those libraries."}


def package_set(packages, kind):
    result = set()
    require(isinstance(packages, list) and bool(packages), "Missing complete package list")
    for package in packages:
        name, version = package.get("Name"), package.get("Version")
        require(isinstance(name, str) and bool(name) and isinstance(version, str) and bool(version), "Incomplete package identity")
        if kind == "debian":
            # Trivy stores binary Version, Release and Epoch separately. Match
            # its FormatVersion, retaining Debian revisions/binNMUs and epoch.
            epoch, release = package.get("Epoch", 0), package.get("Release", "")
            require(type(epoch) is int and epoch >= 0 and isinstance(release, str), "Invalid structured Debian version")
            if release:
                version += "-" + release
            if epoch:
                require(":" not in version, "Debian epoch was specified twice")
                version = str(epoch) + ":" + version
            if package.get("ID"):
                require(package["ID"] == name + "@" + version, "SCA package ID differs from its complete binary version")
        key = (normalized_name(name) if kind == "python-pkg" else name, version)
        require(key not in result, "Duplicate package identity")
        result.add(key)
    return result


def target_sets(targets):
    groups = {}
    for target in targets:
        key = (target.get("Class"), target.get("Type"))
        require(key in TARGETS and key not in groups, "Unexpected, repeated or omitted runtime target")
        groups[key] = package_set(target.get("Packages"), key[1])
    require(set(groups) == TARGETS, "Runtime OS and Python targets are both required")
    return groups


def sbom_sets(sbom):
    require(sbom.get("bomFormat") == "CycloneDX", "CycloneDX SBOM required")
    groups = {key: set() for key in TARGETS}
    systems = []
    for component in sbom.get("components", []):
        if component.get("type") == "operating-system":
            systems.append((component.get("name"), component.get("version")))
            continue
        purl = component.get("purl", "")
        if purl.startswith("pkg:deb/debian/"):
            key, prefix = ("os-pkgs", "debian"), "pkg:deb/debian/"
        elif purl.startswith("pkg:pypi/"):
            key, prefix = ("lang-pkgs", "python-pkg"), "pkg:pypi/"
        else:
            raise ValueError("SBOM component has no inventoried runtime ecosystem")
        identity = purl[len(prefix):].split("?", 1)[0].split("#", 1)[0]
        require("@" in identity, "Versioned package URL required")
        name, version = (unquote(part) for part in identity.rsplit("@", 1))
        # Trivy 0.76.2 moves Debian epochs from Version into the explicit
        # epoch qualifier (pkg/purl/purl.go New/parseQualifier). Reconstruct the
        # complete dpkg version; never discard or infer the epoch from a count.
        qualifiers = parse_qs(purl.split("?", 1)[1].split("#", 1)[0], strict_parsing=True) if "?" in purl else {}
        if "epoch" in qualifiers:
            epoch = qualifiers["epoch"]
            require(key[1] == "debian" and len(epoch) == 1 and re.fullmatch(r"[1-9][0-9]*", epoch[0])
                    and ":" not in version, "Invalid Debian package epoch qualifier")
            version = epoch[0] + ":" + version
        component_name = component.get("name")
        if key[1] == "python-pkg":
            name, component_name = normalized_name(name), normalized_name(component_name)
        require(name == component_name and version == component.get("version"), "SBOM package URL and component metadata disagree")
        require((name, version) not in groups[key], "Duplicate SBOM package")
        groups[key].add((name, version))
    require(all(groups.values()) and len(systems) == 1, "SBOM OS/Python scope is incomplete")
    return groups, systems[0]


def verified_blob(layout, digest):
    require(DIGEST.fullmatch(digest), "Invalid OCI blob digest")
    path = Path(layout) / "blobs" / "sha256" / digest.split(":", 1)[1]
    require(path.is_file() and not path.is_symlink(), "OCI metadata blob is not a regular file")
    data = path.read_bytes()
    require("sha256:" + hashlib.sha256(data).hexdigest() == digest, "OCI metadata digest mismatch")
    return json_bytes(data)


def archive_json(archive, name):
    require(name == "manifest.json" or re.fullmatch(r"blobs/sha256/[a-f0-9]{64}|[a-f0-9]{64}\.json", name), "Unexpected Docker metadata member")
    members = [member for member in archive.getmembers() if member.name == name]
    require(len(members) == 1 and members[0].isfile() and members[0].size <= 1024 * 1024, "Invalid or repeated Docker metadata member")
    stream = archive.extractfile(members[0])
    require(stream is not None, "Missing Docker metadata")
    data = stream.read()
    return json_bytes(data), hashlib.sha256(data).hexdigest()


def image_equivalence(layout, archive_path, local_id, *, expected_manifest=None):
    index = json_file(Path(layout) / "index.json")
    manifests = index.get("manifests", [])
    require(len(manifests) == 1, "A single runtime OCI manifest is required")
    descriptor = manifests[0]
    manifest_id = descriptor["digest"]
    require(expected_manifest is None or expected_manifest == manifest_id, "Unexpected scanned OCI manifest")
    manifest = verified_blob(layout, manifest_id)
    require(manifest.get("schemaVersion") == 2 and isinstance(manifest.get("layers"), list), "Invalid OCI runtime manifest")
    config_id = manifest["config"]["digest"]
    config = verified_blob(layout, config_id)
    with tarfile.open(archive_path, "r:*") as archive:
        docker_manifest, _ = archive_json(archive, "manifest.json")
        require(isinstance(docker_manifest, list) and len(docker_manifest) == 1, "A single local Docker image is required")
        local_config, config_hash = archive_json(archive, docker_manifest[0]["Config"])
    require("sha256:" + config_hash == local_id, "Docker archive is not the locally tested image")
    require(local_config == config, "Local and scanned OCI config JSON differ semantically")
    require(len(manifest["layers"]) == len(config["rootfs"]["diff_ids"]) == len(docker_manifest[0]["Layers"]), "Image layer counts disagree")
    canonical = json.dumps(config, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()
    return {"local_tested_image_id": local_id, "oci_manifest_digest": manifest_id, "oci_config_digest": config_id,
        "complete_config_json_equal": True, "rootfs_diff_ids_equal": True, "layer_count": len(manifest["layers"]),
        "canonical_config_sha256": hashlib.sha256(canonical).hexdigest(),
        "scope": "complete parsed config, including rootfs/config/history; metadata blobs verified by digest; serialization alone differs"}, config


def compare(inventory, sbom, sca, *, equivalence, image_config):
    require(inventory.get("schema") == SCHEMA, "Unexpected runtime inventory schema")
    require(inventory.get("local_tested_image_id") == equivalence["local_tested_image_id"], "Inventory belongs to another local image")
    require(sca.get("ArtifactType") == "container_image" and sca.get("Metadata", {}).get("ImageID") == equivalence["oci_config_digest"],
            "SCA belongs to another OCI image")
    require(sca["Metadata"].get("DiffIDs") == image_config["rootfs"]["diff_ids"], "SCA root filesystem identity mismatch")
    require(sca["Metadata"].get("ImageConfig") == image_config, "SCA full image configuration differs from the verified image")
    independent = target_sets(inventory.get("targets", []))
    scanned = target_sets(sca.get("Results", []))
    components, os_identity = sbom_sets(sbom)
    require(independent == scanned == components, "Independent inventory, SBOM and SCA package sets differ")
    require(os_identity == (inventory["os"]["family"], inventory["os"]["version"]), "SBOM operating system identity mismatch")
    properties = sbom.get("metadata", {}).get("component", {}).get("properties", [])
    image_ids = [value["value"] for value in properties if value.get("name") == "aquasecurity:trivy:ImageID"]
    diff_ids = [value["value"] for value in properties if value.get("name") == "aquasecurity:trivy:DiffID"]
    require(image_ids == [equivalence["oci_config_digest"]] and sorted(diff_ids) == sorted(image_config["rootfs"]["diff_ids"]), "SBOM image identity mismatch")
    counts = []
    for target in sca["Results"]:
        key = (target["Class"], target["Type"])
        findings = Counter({severity: 0 for severity in SEVERITIES})
        for finding in target.get("Vulnerabilities", []):
            name = finding.get("PkgName")
            if key[1] == "python-pkg":
                name = normalized_name(name)
            require((name, finding.get("InstalledVersion")) in independent[key], "SCA finding references a package outside the exact inventory")
            require(finding.get("Severity") in SEVERITIES and bool(finding.get("VulnerabilityID")), "Incomplete SCA finding")
            findings[finding["Severity"]] += 1
        counts.append({"Class": key[0], "Type": key[1], "packages": len(independent[key]), "findings": dict(findings)})
    native = inventory.get("python_native_binaries")
    require(isinstance(native, list) and bool(native) and inventory.get("av_library_versions"), "Native wheel binaries and AV versions are required")
    for item in native:
        require(isinstance(item.get("bytes"), int) and item["bytes"] > 0 and re.fullmatch(r"[a-f0-9]{64}", item.get("sha256", "")), "Incomplete native binary fingerprint")
    require(inventory.get("node", {}).get("present") is False, "Unexpected Node runtime requires review")
    return {"targets": counts, "package_sets_equal": True, "python_native_elf_files": len(native),
        "vendored_elf_files": sum(item["vendored_library"] for item in native), "av_library_versions": inventory["av_library_versions"],
        "native_sca_limit": inventory["native_sca_limit"], "node_present": False}


def verify(args):
    inventory, sbom, sca = (json_file(path) for path in (args.inventory, args.sbom, args.sca))
    equivalence, config = image_equivalence(args.oci_layout, args.docker_archive, inventory["local_tested_image_id"], expected_manifest=args.oci_manifest)
    comparison = compare(inventory, sbom, sca, equivalence=equivalence, image_config=config)
    metadata = json_file(args.db_metadata)
    require(metadata.get("Version") == 2 and metadata.get("UpdatedAt") == args.db_updated_at, "Trivy DB version or update timestamp differs")
    database_hash = sha256(args.db)
    require(args.db_sha256 is None or args.db_sha256 == database_hash, "Trivy database fingerprint differs")
    return {"schema": VERIFY_SCHEMA, "status": "matched", "security_approved": False, "cloud_validation": False,
        "image_equivalence": equivalence, "comparison": comparison,
        "scanner": {"name": "Trivy", "version": sca.get("Trivy", {}).get("Version"), "report_created_at": sca.get("CreatedAt"),
            "database": {"sha256": database_hash, "bytes": Path(args.db).stat().st_size, "updated_at": metadata["UpdatedAt"],
                "metadata_sha256": sha256(args.db_metadata), "binding_scope": "explicit existing scanner cache supplied by the scan invocation; report does not independently embed the DB hash"}},
        "artifacts": {name: {"sha256": sha256(path), "bytes": Path(path).stat().st_size} for name, path in
            (("inventory", args.inventory), ("sbom", args.sbom), ("sca", args.sca))}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    collect = commands.add_parser("capture")
    collect.add_argument("--image-id", required=True)
    collect.add_argument("--output", required=True, type=Path)
    check = commands.add_parser("verify")
    for option in ("inventory", "sbom", "sca", "oci-layout", "docker-archive", "db", "db-metadata"):
        check.add_argument("--" + option, required=True, type=Path)
    check.add_argument("--oci-manifest", required=True)
    check.add_argument("--db-updated-at", required=True)
    check.add_argument("--db-sha256")
    check.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        result = capture(args.image_id) if args.action == "capture" else verify(args)
        save_new(args.output, result)
        print(json.dumps({"status": "captured" if args.action == "capture" else result["status"], "output": str(args.output)}))
        return 0
    except (ValueError, OSError, KeyError, TypeError, tarfile.TarError) as error:
        # Never print image Env/config, archives, report bodies or host variables.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "check": str(error) if type(error) is ValueError else None}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
