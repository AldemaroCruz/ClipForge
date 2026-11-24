"""Verify existing ClipForge PostgreSQL SCRAM credentials without changing state.

This guest-only helper receives the two candidate passwords on stdin, reads the
two role verifiers through local peer authentication, and emits only booleans
and fixed role names. Passwords and PostgreSQL verifiers never enter stdout.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import re
import subprocess
import sys


SCHEMA = "clipforge-int-hito-a-db-credentials-1"
ROLES = ("clipforge_app", "clipforge_migrator")
PSQL = "/usr/lib/postgresql/17/bin/psql"
RUNUSER = "/usr/sbin/runuser"
MAX_INPUT = 16384
SCRAM = re.compile(
    r"SCRAM-SHA-256\$([1-9][0-9]{0,8}):([A-Za-z0-9+/]+={0,2})\$"
    r"([A-Za-z0-9+/]+={0,2}):([A-Za-z0-9+/]+={0,2})"
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def _decode(value, size):
    raw = base64.b64decode(value, validate=True)
    require(len(raw) == size and base64.b64encode(raw).decode("ascii") == value,
            "scram_encoding")
    return raw


def matches(password, verifier):
    require(isinstance(password, str) and 32 <= len(password) <= 4096
            and password.isascii() and all(33 <= ord(char) <= 126 for char in password),
            "password_shape")
    match = SCRAM.fullmatch(verifier or "")
    require(match is not None, "scram_shape")
    iterations = int(match.group(1))
    require(iterations == 4096, "scram_iterations")
    salt = _decode(match.group(2), 16)
    stored = _decode(match.group(3), 32)
    server = _decode(match.group(4), 32)
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, iterations)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    expected_stored = hashlib.sha256(client).digest()
    expected_server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    return hmac.compare_digest(stored, expected_stored) and hmac.compare_digest(server, expected_server)


def _input(stream):
    raw = stream.read(MAX_INPUT + 1)
    require(0 < len(raw) <= MAX_INPUT, "credential_input_size")

    def pairs(rows):
        value = dict(rows)
        require(len(value) == len(rows), "credential_input_duplicate")
        return value

    value = json.loads(raw, object_pairs_hook=pairs)
    require(isinstance(value, dict) and set(value) == {"app_password", "migrator_password"},
            "credential_input_shape")
    return value


def _verifiers():
    query = ("SELECT rolname || chr(9) || rolpassword FROM pg_authid "
             "WHERE rolname IN ('clipforge_app','clipforge_migrator') ORDER BY rolname;")
    result = subprocess.run(
        [RUNUSER, "-u", "postgres", "--", PSQL, "-X", "-qAt",
         "--set=ON_ERROR_STOP=1", "--dbname=postgres", "--command=" + query],
        stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=15, check=False,
        env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LANG": "C", "LC_ALL": "C"},
    )
    require(result.returncode == 0 and len(result.stdout) <= 4096 and not result.stderr,
            "credential_verifier_read")
    rows = result.stdout.decode("ascii").splitlines()
    parsed = {}
    for row in rows:
        parts = row.split("\t", 1)
        require(len(parts) == 2 and parts[0] in ROLES and parts[0] not in parsed,
                "credential_verifier_rows")
        parsed[parts[0]] = parts[1]
    require(tuple(sorted(parsed)) == ROLES, "credential_verifier_rows")
    return parsed


def collect(stream):
    passwords = _input(stream)
    verifiers = _verifiers()
    require(matches(passwords["app_password"], verifiers["clipforge_app"])
            and matches(passwords["migrator_password"], verifiers["clipforge_migrator"]),
            "credential_mismatch")
    return {"schema": SCHEMA, "status": "verified", "roles": list(ROLES), "read_only": True}


def main():
    try:
        require(sys.platform.startswith("linux") and len(sys.argv) == 1, "credential_platform")
        value = collect(sys.stdin.buffer)
        sys.stdout.write(json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n")
        return 0
    except Exception:
        sys.stdout.write('{"schema":"clipforge-int-hito-a-db-credentials-1","status":"blocked"}\n')
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
