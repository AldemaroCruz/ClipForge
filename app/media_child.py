"""Linux exec launcher binding a media process to its creating parent thread.

The caller resolves the trusted executable first. No PATH lookup, shell,
preexec_fn or Python wrapper remains after exec. Failure to arm the kernel
parent-death signal prevents execution instead of weakening supervision.
"""
from __future__ import annotations

import ctypes
import errno
import os
import re
import signal
import stat
import sys

PR_SET_PDEATHSIG = 1


class MediaChildError(RuntimeError):
    pass


def _validate_command(command):
    if not command or any(not isinstance(item, str) or "\0" in item for item in command):
        raise MediaChildError("Invalid media command")
    path = command[0]
    if not os.path.isabs(path):
        raise MediaChildError("Media command requires an absolute executable")
    metadata = os.stat(path)
    if not stat.S_ISREG(metadata.st_mode) or metadata.st_mode & (stat.S_ISUID | stat.S_ISGID):
        raise MediaChildError("Privileged media executable is forbidden")
    try:
        capability = os.getxattr(path, "security.capability")
    except OSError as error:
        # Linux reports ENODATA when no file capabilities are attached. Other
        # failures leave preservation across exec unconfirmed and fail closed.
        if error.errno != errno.ENODATA:
            raise MediaChildError("Media executable capabilities cannot be verified") from None
    else:
        if capability:
            raise MediaChildError("Media executable file capabilities are forbidden")


def _arm_parent_death(expected_parent):
    if os.getppid() != expected_parent:
        raise MediaChildError("Media parent no longer exists")
    libc = ctypes.CDLL(None, use_errno=True)
    prctl = libc.prctl
    prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]
    prctl.restype = ctypes.c_int
    if prctl(PR_SET_PDEATHSIG, signal.SIGKILL, 0, 0, 0) != 0:
        raise MediaChildError("Media parent-death signal could not be armed")
    # Cover the interval between checking ppid and arming prctl. If the parent
    # died before prctl, Linux does not retrospectively send the signal.
    if os.getppid() != expected_parent:
        raise MediaChildError("Media parent changed before execution")


def main(argv=None):
    arguments = list(sys.argv[1:] if argv is None else argv)
    try:
        if sys.platform != "linux":
            raise MediaChildError("Media supervision requires Linux")
        if len(arguments) < 2 or not re.fullmatch(r"[1-9][0-9]{0,9}", arguments[0]):
            raise MediaChildError("Invalid expected media parent")
        expected_parent = int(arguments[0])
        if expected_parent > 2147483647:
            raise MediaChildError("Invalid expected media parent")
        command = arguments[1:]
        _validate_command(command)
        _arm_parent_death(expected_parent)
        # The production caller supplies the Debian-verified /usr/bin/ffmpeg.
        # Absolute Python commands are used only by isolated process fixtures.
        os.execv(command[0], command)
    except (MediaChildError, OSError, ValueError, AttributeError):
        print("Media launcher refused execution: parent supervision unavailable or invalid command.", file=sys.stderr)
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
