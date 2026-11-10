"""Capture candidate-only package/source inventory independently of Trivy.

Run inside the disposable CI image, never against the operational installation.
Only stdlib metadata, dpkg status and named candidate source directories are read.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
from pathlib import Path
import re
import sys


def normalized_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def debian_packages(status: str) -> list[dict]:
    packages = []
    for paragraph in status.strip().split("\n\n"):
        fields = {}
        for line in paragraph.splitlines():
            if line and not line[0].isspace() and ": " in line:
                name, value = line.split(": ", 1)
                fields[name] = value
        if fields.get("Status") == "install ok installed":
            packages.append({"Name": fields["Package"], "Version": fields["Version"]})
    return sorted(packages, key=lambda item: (item["Name"], item["Version"]))


def capture(image_id: str, *, root: Path = Path("/app"),
            status: Path = Path("/var/lib/dpkg/status"),
            release: Path = Path("/etc/debian_version")) -> dict:
    if not re.fullmatch(r"sha256:[0-9a-f]{64}", image_id):
        raise ValueError("A verified candidate image ID is required.")
    python = sorted(({
        "Name": normalized_name(distribution.metadata["Name"]),
        "Version": distribution.version,
    } for distribution in importlib.metadata.distributions()), key=lambda item: item["Name"])
    driver = Path(importlib.metadata.distribution("playwright").locate_file(
        "playwright/driver/package/package.json"))
    node = json.loads(driver.read_text(encoding="utf-8"))
    sources = []
    for directory in ("app", "scripts"):
        for path in sorted((root / directory).glob("*.py")):
            if path.is_symlink() or not path.is_file():
                raise ValueError("Candidate sources must be regular files.")
            data = path.read_bytes()
            sources.append({"path": path.relative_to(root).as_posix(),
                            "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    return {
        "schema_version": 1,
        "image_id": image_id,
        "source_root": "/app",
        "os": {"family": "debian", "name": release.read_text().strip()},
        "targets": [
            {"Class": "os-pkgs", "Type": "debian",
             "Packages": debian_packages(status.read_text(encoding="utf-8"))},
            {"Class": "lang-pkgs", "Type": "python-pkg", "Packages": python},
            {"Class": "lang-pkgs", "Type": "node-pkg",
             "Packages": [{"Name": node["name"], "Version": node["version"]}]},
        ],
        "python_sources": sources,
    }


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    inventory = capture(args.image_id)
    # Direct script execution starts at /app/scripts. Import only the authored
    # helper beside this script, without importing the API or reading user data.
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from app.media_binaries import BINARIES, PACKAGE_LIST, resolve_media_binary
    ffmpeg_package = next(package for package in inventory["targets"][0]["Packages"]
                          if package["Name"] == "ffmpeg")
    inventory["media_binaries"] = []
    for name in sorted(BINARIES):
        path = Path(resolve_media_binary(name))
        metadata = path.stat()
        inventory["media_binaries"].append({
            "name": name, "path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "uid": metadata.st_uid, "gid": metadata.st_gid, "mode": oct(metadata.st_mode & 0o7777),
            "package": ffmpeg_package, "package_file_list": str(PACKAGE_LIST),
            "provenance_scope": "root-managed Debian package list; signed APT build; not protection against compromised root/builder",
        })
    with args.output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(inventory, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
