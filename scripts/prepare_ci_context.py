"""Prepare/verify a source-only Docker CI context without reading operator data.

Only named root files and direct source files in four named directories are
considered. Unknown directories are never traversed. The manifest stays outside
both source and context. This filename allowlist is not a content secret scanner.
"""
from __future__ import annotations

import argparse
import fnmatch
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys


SCHEMA = "clipforge-ci-context-1"
ROOT_FILES = (
    "Dockerfile", "Dockerfile.ci", "Dockerfile.ci.dockerignore",
    "requirements.txt", "requirements-test.txt", "requirements-ci.lock",
    "requirements-ci-tools.txt", "requirements-ci-tools.lock",
    "Dockerfile.dev", "Dockerfile.dev.dockerignore", "compose.dev.yaml",
)
DIRECTORIES = {
    "app": frozenset({".py"}),
    "app/static": frozenset({".html", ".js", ".css"}),
    "scripts": frozenset({".py", ".ps1"}),
    "tests": frozenset({".py"}),
}
REQUIRED_FILES = frozenset(ROOT_FILES) | frozenset({
    "app/__init__.py", "app/main.py", "scripts/run_ci_tests.py",
    "scripts/prepare_ci_context.py",
})
PRIVATE_NAMES = frozenset({
    "data", "cache", "backups", "backup", "release", "evidence",
    "test-evidence", "test-output", "restores", "restore", "models",
    ".git", ".aws", ".codex", ".venv", "venv", "__pycache__",
})
PRIVATE_PATTERNS = (
    "gha-creds-*.json",
    ".env*", "restore-check-*", "credentials*", "credential.*", "secrets*",
    "secret.*", "tokens*", "token.*", "auth.json", "id_rsa*", "id_ed25519*",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.tfstate*",
)
CHUNK = 1024 * 1024


class ContextError(ValueError):
    """Unsafe input, source drift or context inventory mismatch."""


def _private(name: str) -> bool:
    folded = name.casefold()
    return folded in PRIVATE_NAMES or any(fnmatch.fnmatchcase(folded, p) for p in PRIVATE_PATTERNS)


def _absolute(value: Path | str) -> Path:
    path = Path(value)
    if ".." in path.parts:
        raise ContextError("Parent traversal is not permitted in input paths.")
    result = Path(os.path.abspath(path))
    if result == Path(result.anchor):
        raise ContextError("A filesystem root cannot be a source, context or manifest.")
    if any(_private(part) for part in result.parts):
        raise ContextError("Excluded private/artifact paths cannot be CI inputs or outputs.")
    return result


def _checked_stat(path: Path):
    metadata = os.lstat(path)
    if stat.S_ISLNK(metadata.st_mode) or (
        getattr(metadata, "st_file_attributes", 0)
        & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0x400)
    ):
        raise ContextError("Symlinks and Windows reparse points are not permitted.")
    return metadata


def _check_components(path: Path) -> None:
    for component in reversed((path, *path.parents)):
        try:
            _checked_stat(component)
        except FileNotFoundError:
            continue


def _inside(path: Path, parent: Path) -> bool:
    return path == parent or parent in path.parents


def _separate(*paths: Path) -> None:
    for index, first in enumerate(paths):
        for second in paths[index + 1:]:
            if _inside(first, second) or _inside(second, first):
                raise ContextError("Source, context and manifest must not overlap.")


def _identity(metadata) -> tuple:
    return (metadata.st_dev, metadata.st_ino, metadata.st_size, metadata.st_mtime_ns)


def _stream_record(path: Path, destination: Path | None = None) -> dict:
    _check_components(path)
    before = _checked_stat(path)
    if not stat.S_ISREG(before.st_mode):
        raise ContextError("Only regular source files may be copied.")
    flags = os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(path, flags)
    with os.fdopen(descriptor, "rb") as original:
        if _identity(os.fstat(original.fileno())) != _identity(before):
            raise ContextError("Source changed before it could be read.")
        copied = destination.open("xb") if destination is not None else None
        try:
            digest = hashlib.sha256()
            count = 0
            while chunk := original.read(CHUNK):
                count += len(chunk)
                digest.update(chunk)
                if copied is not None:
                    copied.write(chunk)
            if copied is not None:
                copied.flush()
                os.fsync(copied.fileno())
            if _identity(os.fstat(original.fileno())) != _identity(before):
                raise ContextError("Source changed while it was read.")
        finally:
            if copied is not None:
                copied.close()
    _check_components(path)
    if _identity(_checked_stat(path)) != _identity(before) or count != before.st_size:
        raise ContextError("Source changed while it was read.")
    return {"bytes": count, "sha256": digest.hexdigest()}


def _files(root: Path, *, strict: bool) -> list[tuple[str, Path]]:
    _check_components(root)
    if not stat.S_ISDIR(_checked_stat(root).st_mode):
        raise ContextError("Source/context must be a regular directory.")
    found = []
    if strict:
        # Reject unknown entries before inspecting or entering their contents.
        permitted = set(ROOT_FILES) | {"app", "scripts", "tests"}
        with os.scandir(root) as entries:
            for entry in entries:
                if entry.name not in permitted:
                    raise ContextError("Context contains an unexpected root entry.")
    for name in ROOT_FILES:
        path = root / name
        if not stat.S_ISREG(_checked_stat(path).st_mode):
            raise ContextError("A required root file is missing or not regular.")
        found.append((name, path))
    for relative, extensions in DIRECTORIES.items():
        directory = root / relative
        _check_components(directory)
        if not stat.S_ISDIR(_checked_stat(directory).st_mode):
            raise ContextError("A required source directory is missing.")
        with os.scandir(directory) as entries:
            for entry in sorted(entries, key=lambda item: item.name):
                if _private(entry.name):
                    if strict:
                        raise ContextError("Context contains an excluded private/artifact entry.")
                    continue
                metadata = _checked_stat(Path(entry.path))
                candidate = f"{relative}/{entry.name}"
                if stat.S_ISDIR(metadata.st_mode):
                    if strict and candidate not in DIRECTORIES:
                        raise ContextError("Context contains an unexpected directory.")
                    continue  # Only explicitly named directories are entered later.
                if not stat.S_ISREG(metadata.st_mode):
                    raise ContextError("Only regular source files may be copied.")
                if Path(entry.name).suffix.lower() not in extensions:
                    if strict:
                        raise ContextError("Context contains a file outside its source allowlist.")
                    continue
                found.append((candidate, Path(entry.path)))
    names = [name for name, _ in found]
    if len({name.casefold() for name in names}) != len(names):
        raise ContextError("Case-colliding source paths are not portable.")
    if not REQUIRED_FILES <= set(names):
        raise ContextError("Required CI/application source files are missing.")
    return sorted(found)


def _inventory(root: Path, *, strict: bool) -> dict[str, dict]:
    return {name: _stream_record(path) for name, path in _files(root, strict=strict)}


def _manifest_inventory(value) -> dict[str, dict]:
    if not isinstance(value, dict) or set(value) != {"schema", "files"} or value["schema"] != SCHEMA:
        raise ContextError("Unsupported context manifest schema.")
    if not isinstance(value["files"], list):
        raise ContextError("Manifest inventory must be a list.")
    result = {}
    folded = set()
    for item in value["files"]:
        if not isinstance(item, dict) or set(item) != {"path", "bytes", "sha256"}:
            raise ContextError("Invalid manifest entry.")
        name = item["path"]
        if not isinstance(name, str) or "\\" in name or ":" in name or "\x00" in name:
            raise ContextError("Invalid manifest path.")
        path = PurePosixPath(name)
        if path.is_absolute() or not path.parts or any(p in {".", ".."} for p in path.parts) or path.as_posix() != name:
            raise ContextError("Invalid manifest path.")
        if any(_private(part) for part in path.parts):
            raise ContextError("Excluded path in manifest.")
        allowed = name in ROOT_FILES or (
            path.parent.as_posix() in DIRECTORIES
            and path.suffix.lower() in DIRECTORIES[path.parent.as_posix()]
        )
        if not allowed or name.casefold() in folded:
            raise ContextError("Duplicate or non-allowlisted manifest path.")
        if type(item["bytes"]) is not int or item["bytes"] < 0 or not isinstance(item["sha256"], str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"]):
            raise ContextError("Invalid manifest size/hash.")
        folded.add(name.casefold())
        result[name] = {"bytes": item["bytes"], "sha256": item["sha256"]}
    if not REQUIRED_FILES <= result.keys():
        raise ContextError("Manifest is missing required source files.")
    return result


def prepare_context(source: Path | str, destination: Path | str, manifest: Path | str) -> dict:
    source, destination, manifest = map(_absolute, (source, destination, manifest))
    _separate(source, destination, manifest)
    for path in (source, destination, manifest):
        _check_components(path)
    if os.path.lexists(destination) or os.path.lexists(manifest):
        raise FileExistsError("Context destination and manifest must both be new.")
    expected = _inventory(source, strict=False)
    destination.parent.mkdir(parents=True, exist_ok=True)
    manifest.parent.mkdir(parents=True, exist_ok=True)
    _check_components(destination.parent)
    _check_components(manifest.parent)
    destination.mkdir()  # Exclusive creation; never reuse/overwrite an existing context.
    for name in DIRECTORIES:
        (destination / name).mkdir(parents=True, exist_ok=True)
    for name, record in expected.items():
        actual = _stream_record(source / name, destination / name)
        if actual != record:
            raise ContextError("Source drift detected; no manifest was published.")
    if _inventory(source, strict=False) != expected:
        raise ContextError("Source drift detected; no manifest was published.")
    if _inventory(destination, strict=True) != expected:
        raise ContextError("Copied context differs from the source inventory.")
    value = {"schema": SCHEMA, "files": [{"path": name, **record} for name, record in expected.items()]}
    # A failed/incomplete copy has no valid manifest and is intentionally retained
    # for inspection. This helper never recursively deletes a caller's directory.
    with manifest.open("x", encoding="utf-8", newline="\n") as output:
        json.dump(value, output, indent=2, sort_keys=True)
        output.write("\n")
        output.flush()
        os.fsync(output.fileno())
    return {"status": "ok", "files": len(expected), "bytes": sum(r["bytes"] for r in expected.values())}


def verify_context(context: Path | str, manifest: Path | str) -> dict:
    context, manifest = map(_absolute, (context, manifest))
    _separate(context, manifest)
    for path in (context, manifest):
        _check_components(path)
    if not stat.S_ISREG(_checked_stat(manifest).st_mode):
        raise ContextError("Manifest must be a regular file.")
    if manifest.stat().st_size > 8 * CHUNK:
        raise ContextError("Manifest is too large.")
    with manifest.open(encoding="utf-8") as source:
        expected = _manifest_inventory(json.load(source))
    if _inventory(context, strict=True) != expected:
        raise ContextError("Context inventory/hash differs from its manifest.")
    return {"status": "ok", "files": len(expected), "bytes": sum(r["bytes"] for r in expected.values())}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    prepare = commands.add_parser("prepare", help="Copy allowlisted source into a new external context")
    prepare.add_argument("--source", required=True, type=Path)
    prepare.add_argument("--destination", required=True, type=Path)
    prepare.add_argument("--manifest", required=True, type=Path)
    verify = commands.add_parser("verify", help="Verify exact context inventory and SHA-256 hashes")
    verify.add_argument("--context", required=True, type=Path)
    verify.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "prepare":
            result = prepare_context(args.source, args.destination, args.manifest)
        else:
            result = verify_context(args.context, args.manifest)
        print(json.dumps(result, sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "message": str(error)}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
