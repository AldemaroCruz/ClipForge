"""Copy only explicitly listed, permitted tracked sources for an offline secret scan.

The NUL-delimited index list must live outside the checkout. Every name is checked
before any source file is opened, including names explicitly forced into Git.
No Git command, network access, application import or installation inventory runs.
"""
from __future__ import annotations

import argparse
import fnmatch
import json
import os
from pathlib import Path, PurePosixPath
import stat
import sys
import unicodedata

try:
    from scripts import prepare_ci_context as context
except ModuleNotFoundError:  # Direct CLI launch from any working directory.
    import prepare_ci_context as context


SCHEMA = "clipforge-ci-source-scan-1"
MANIFEST = ".clipforge-source-manifest.json"
MAX_LIST_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 32 * 1024 * 1024
ROOT_NAMES = frozenset(context.ROOT_FILES) | frozenset({
    ".dockerignore", ".gitignore", ".env.ai.example", "AGENTS.md", "Makefile",
    "Dockerfile.runtime", "Dockerfile.tests", "compose.yaml", "compose.ai.yaml",
    "pyproject.toml", "pytest.ini", "tox.ini", "mypy.ini", "ruff.toml",
    ".ruff.toml", ".pre-commit-config.yaml",
})
CODE = frozenset({".py", ".ps1", ".sh", ".bash", ".js", ".ts", ".html", ".css", ".svg"})
TEXT = frozenset({".md", ".txt", ".json", ".yaml", ".yml", ".toml", ".ini", ".tf", ".hcl", ".example"})
DIRECTORIES = {
    "app": CODE | TEXT, "scripts": CODE | TEXT, "tests": CODE | TEXT,
    "docs": TEXT, "clipforge-roadmap": TEXT, ".github": CODE | TEXT,
    "infra": CODE | TEXT, "infrastructure": CODE | TEXT,
    "terraform": CODE | TEXT, "config": TEXT, "configs": TEXT,
}
PRIVATE_NAMES = context.PRIVATE_NAMES | frozenset({
    ".azure", ".gcloud", ".ssh", ".kube", ".terraform", ".ci-local",
    "ci-results", "node_modules", "uploads", "projects", "storage",
    "dist", "build", "artifacts", "compose.runtime.yaml", "compose.rollback.yaml",
    "runtime-lock.json", "model-lock.json", "runtime-requirements.txt",
    "application_default_credentials.json", "terraform.tfvars", "terraform.tfvars.json",
})
PRIVATE_PATTERNS = context.PRIVATE_PATTERNS + (
    "*.auto.tfvars", "*.auto.tfvars.json", "*.tfvars", "*.tfvars.json", "*.tfplan",
    "*-credentials.*", "*service-account*.json", "client_secret*.json",
    "*.mp4", "*.mov", "*.mkv", "*.avi", "*.webm", "*.mp3", "*.wav",
    "*.zip", "*.tar", "*.gz", "*.sqlite*", "*.db", "*.log", "restored*",
)
WINDOWS_RESERVED = frozenset({"CON", "PRN", "AUX", "NUL"}) | frozenset(
    f"{prefix}{number}" for prefix in ("COM", "LPT") for number in range(1, 10)
)


class ScanError(ValueError):
    """The requested scan would cross a privacy or source-integrity boundary."""


def _private(part: str) -> bool:
    folded = part.casefold()
    return folded in PRIVATE_NAMES or any(fnmatch.fnmatchcase(folded, p) for p in PRIVATE_PATTERNS)


def _absolute(value: Path | str) -> Path:
    result = context._absolute(value)
    if any(_private(part) for part in result.parts):
        raise ScanError("Private/generated locations cannot be scan inputs or outputs.")
    return result


def validate_paths(names: list[str]) -> list[str]:
    """Pure name validation: does not stat or open anything in the source tree."""
    if not names or len(names) > 100_000:
        raise ScanError("A nonempty, bounded tracked-source list is required.")
    seen = set()
    for name in names:
        if (not name or "\\" in name or ":" in name
                or any(ord(character) < 32 or ord(character) == 127 for character in name)):
            raise ScanError("Invalid tracked source path.")
        path = PurePosixPath(name)
        if (path.is_absolute() or path.as_posix() != name or not path.parts
                or any(part in {".", ".."} for part in path.parts)):
            raise ScanError("Absolute paths and traversal are not permitted.")
        for part in path.parts:
            if (part.endswith((".", " ")) or part.split(".", 1)[0].upper() in WINDOWS_RESERVED
                    or unicodedata.normalize("NFC", part) != part):
                raise ScanError("Nonportable source path.")
        # The single authorized example is a root file, never a nested .env file.
        if name != ".env.ai.example" and any(_private(part) for part in path.parts):
            raise ScanError("Tracked private/generated files are forbidden, even when forced into Git.")
        if name == MANIFEST:
            raise ScanError("The snapshot manifest name is reserved.")
        allowed = name in ROOT_NAMES or (
            len(path.parts) == 1 and path.suffix.lower() == ".md"
        ) or (
            len(path.parts) > 1 and path.parts[0] in DIRECTORIES
            and path.suffix.lower() in DIRECTORIES[path.parts[0]]
        )
        if not allowed:
            raise ScanError("A tracked file is outside the permitted source types/locations.")
        folded = name.casefold()
        if folded in seen:
            raise ScanError("Duplicate or case-colliding tracked source paths.")
        seen.add(folded)
    # Reject file/directory collisions before touching the source filesystem.
    for name in seen:
        if any(parent.as_posix().casefold() in seen for parent in PurePosixPath(name).parents if parent.as_posix() != "."):
            raise ScanError("Tracked file/directory paths collide.")
    return sorted(names)


def _read_paths(path: Path) -> list[str]:
    context._check_components(path)
    before = context._checked_stat(path)
    if not stat.S_ISREG(before.st_mode) or before.st_size > MAX_LIST_BYTES or before.st_nlink != 1:
        raise ScanError("The external path list must be a bounded regular file without links.")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0) | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as stream:
        if context._identity(os.fstat(stream.fileno())) != context._identity(before):
            raise ScanError("Tracked path list changed before reading.")
        value = stream.read(MAX_LIST_BYTES + 1)
        if context._identity(os.fstat(stream.fileno())) != context._identity(before):
            raise ScanError("Tracked path list changed while reading.")
    if len(value) > MAX_LIST_BYTES or not value or not value.endswith(b"\0"):
        raise ScanError("The path list must contain complete NUL-terminated records.")
    try:
        return value[:-1].decode("utf-8").split("\0")
    except UnicodeDecodeError as error:
        raise ScanError("Tracked paths must be UTF-8 source names.") from error


def _regular(path: Path):
    context._check_components(path)
    metadata = context._checked_stat(path)
    if (not stat.S_ISREG(metadata.st_mode) or metadata.st_nlink != 1
            or metadata.st_size > MAX_FILE_BYTES):
        raise ScanError("Only bounded regular source files without hard links may be scanned.")
    return metadata


def _verify_copy(destination: Path, expected: dict[str, dict]) -> None:
    actual_names = set()
    for directory, directories, files in os.walk(destination, followlinks=False):
        for name in (*directories, *files):
            path = Path(directory) / name
            metadata = context._checked_stat(path)
            if not (stat.S_ISDIR(metadata.st_mode) or stat.S_ISREG(metadata.st_mode)):
                raise ScanError("Unexpected snapshot file type.")
        for name in files:
            relative = (Path(directory) / name).relative_to(destination).as_posix()
            if relative not in expected:
                raise ScanError("Unexpected snapshot file.")
            actual_names.add(relative)
    if actual_names != set(expected):
        raise ScanError("Snapshot inventory differs from the tracked list.")
    for name, record in expected.items():
        _regular(destination / name)
        if context._stream_record(destination / name) != record:
            raise ScanError("Snapshot bytes/hash differ from the source copy.")


def prepare_scan(source: Path | str, paths: Path | str, destination: Path | str) -> dict:
    source, paths, destination = map(_absolute, (source, paths, destination))
    context._separate(source, paths, destination)
    names = validate_paths(_read_paths(paths))  # Complete name preflight before source access.
    context._check_components(source)
    if not stat.S_ISDIR(context._checked_stat(source).st_mode):
        raise ScanError("Source must be a regular directory.")
    context._check_components(destination)
    if os.path.lexists(destination):
        raise FileExistsError("The scan destination must be new.")
    # Check every file and parent component before opening any source content.
    metadata = {name: _regular(source / name) for name in names}
    destination.parent.mkdir(parents=True, exist_ok=True)
    context._check_components(destination.parent)
    destination.mkdir()
    expected = {}
    for name in names:
        if context._identity(_regular(source / name)) != context._identity(metadata[name]):
            raise ScanError("Source changed after metadata preflight.")
        output = destination / name
        output.parent.mkdir(parents=True, exist_ok=True)
        expected[name] = context._stream_record(source / name, output)
    for name in names:
        if context._identity(_regular(source / name)) != context._identity(metadata[name]):
            raise ScanError("Source changed during snapshot preparation.")
    _verify_copy(destination, expected)
    manifest = {"schema": SCHEMA, "files": [{"path": name, **record} for name, record in expected.items()]}
    # A failure leaves an incomplete new directory; no prior directory is deleted.
    with (destination / MANIFEST).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(manifest, stream, indent=2, sort_keys=True)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    return {"status": "ok", "files": len(expected), "bytes": sum(item["bytes"] for item in expected.values())}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True, type=Path)
    parser.add_argument("--paths", required=True, type=Path)
    parser.add_argument("--destination", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        print(json.dumps(prepare_scan(args.source, args.paths, args.destination), sort_keys=True))
        return 0
    except (OSError, ValueError) as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__,
                          "message": "Source scan snapshot preparation failed; private files are not permitted."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
