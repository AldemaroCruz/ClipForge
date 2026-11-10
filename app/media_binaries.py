"""Select Debian-packaged media tools without PATH or a process wrapper.

The supported desktop setup runs Linux containers, including on Windows/macOS.
Root-owned package records establish installation provenance, not a sandbox or
protection against a compromised image builder/root. CI records SHA256 as well.
"""
from __future__ import annotations

import os
from pathlib import Path
import stat
import sys


BINARIES = {"ffmpeg": "/usr/bin/ffmpeg", "ffprobe": "/usr/bin/ffprobe"}
PACKAGE_LIST = Path("/var/lib/dpkg/info/ffmpeg.list")


def _trusted_path(path: Path, *, directory: bool = False) -> None:
    """Reject links and writable/non-root components; never resolve via PATH."""
    for component in (*reversed(path.parents), path):
        metadata = component.lstat()
        is_directory = component != path or directory
        expected_type = stat.S_ISDIR if is_directory else stat.S_ISREG
        if not expected_type(metadata.st_mode):
            raise PermissionError(f"Media tool trust requires a regular {'directory' if is_directory else 'file'}: {component}")
        if metadata.st_uid != 0 or metadata.st_mode & 0o022:
            raise PermissionError(f"Media tool path must be root-owned and not group/other-writable: {component}")
        if not is_directory and metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
            raise PermissionError(f"Privileged media tool files are not authorized: {component}")


def resolve_media_binary(name: str, *, candidate: str | None = None) -> str:
    """Return the sole authorized absolute path, or fail without any fallback."""
    if name not in BINARIES:
        raise ValueError("Only ffmpeg and ffprobe are authorized media tools")
    if sys.platform != "linux":
        raise RuntimeError("Media tools require Linux containers; on Windows/macOS use Docker Desktop with Linux containers")
    expected = BINARIES[name]
    if candidate is not None and candidate != expected:
        raise PermissionError("Media tool location is not authorized")
    path = Path(expected)
    _trusted_path(path)
    if not os.access(path, os.X_OK):
        raise PermissionError(f"Media tool is not executable by this identity: {path}")
    with path.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            raise PermissionError(f"Media tool must be a native Linux ELF binary: {path}")
    _trusted_path(PACKAGE_LIST)
    if expected not in PACKAGE_LIST.read_text(encoding="utf-8").splitlines():
        raise PermissionError(f"Media tool is not recorded in the Debian ffmpeg package: {path}")
    return expected
