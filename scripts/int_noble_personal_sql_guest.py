"""Pinned PostgreSQL stdin continuation for the personal Noble SQL role."""

from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile


SCHEMA = "clipforge-int-noble-personal-sql-request-1"
RESULT = "clipforge-int-noble-personal-sql-result-1"
MAX_INPUT = 16384
MAX_OUTPUT = 8192
TARGET = {
    "instance_id": "7365414160255801909",
    "boot_disk_id": "8897353356069952044",
    "data_disk_id": "7382984635240536620",
}
BY_ID = Path("/dev/disk/by-id/google-clipforge-noble-pg-data")
MOUNT = Path("/var/lib/clipforge-postgres/data")
PGDATA = str(MOUNT / "pgdata")
BOOT = Path("/proc/sys/kernel/random/boot_id")
CA_FILE = Path("/etc/postgresql/17/main/root.crt")
PSQL = ("/usr/sbin/runuser", "-u", "postgres", "--", "/usr/lib/postgresql/17/bin/psql",
        "-X", "-qAt", "-v", "ON_ERROR_STOP=1", "-h", "/var/run/postgresql", "-p", "5432", "-d", "clipforge")
MODES = {"activate", "revoke", "observe"}
COMMON_FIELDS = {"schema", "action", "operation_id", "boot_id", "controls_commit",
                 "authority_sha256", "payload_sha256", "prior_evidence_sha256",
                 "state_generation", "public_ca_sha256", *TARGET}
HASH = re.compile(r"[a-f0-9]{64}")
UUID = re.compile(r"[a-f0-9]{8}(?:-[a-f0-9]{4}){3}-[a-f0-9]{12}")
SCRAM = re.compile(r"SCRAM-SHA-256\$4096:[A-Za-z0-9+/]{22}==\$[A-Za-z0-9+/]{43}=:[A-Za-z0-9+/]{43}=")
MARKER = re.compile(r"clipforge-int-personal-v1:[a-f0-9]{64}")
VIEWS = ["documents", "projects", "schema_revisions", "workspaces"]
BODY = b"""SET LOCAL search_path = pg_catalog, public;
SET LOCAL statement_timeout = '30s';
SET LOCAL lock_timeout = '5s';
SET LOCAL log_statement = 'none';
SET LOCAL log_min_error_statement = 'panic';
SET LOCAL log_parameter_max_length = 0;
SET LOCAL log_parameter_max_length_on_error = 0;
DO $personal_boundary$
BEGIN
  IF current_user <> 'postgres' OR current_database() <> 'clipforge'
     OR current_setting('server_version_num') <> '170012'
     OR current_setting('data_directory') <> '/var/lib/clipforge-postgres/data/pgdata'
     OR current_setting('listen_addresses') <> '10.80.1.3,127.0.0.1'
     OR current_setting('port') <> '5432' OR current_setting('ssl') <> 'on'
     OR current_setting('password_encryption') <> 'scram-sha-256'
     OR current_setting('ssl_ca_file') <> '/etc/postgresql/17/main/root.crt'
     OR coalesce(current_setting('pgaudit.log', true), 'none') <> 'none'
     OR NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'aldemaro_int'
                    AND NOT rolinherit AND NOT rolsuper AND NOT rolcreatedb AND NOT rolcreaterole
                    AND NOT rolreplication AND NOT rolbypassrls)
     OR EXISTS (SELECT 1 FROM pg_auth_members WHERE member = 'aldemaro_int'::regrole
                                                OR roleid = 'aldemaro_int'::regrole)
     OR NOT pg_try_advisory_xact_lock(1385426753, 1) THEN
    RAISE EXCEPTION 'personal_scope_or_concurrency';
  END IF;
END
$personal_boundary$;
"""
OBSERVE = b"""SELECT json_build_object(
  'login', a.rolcanlogin,
  'verifier_present', a.rolpassword IS NOT NULL,
  'scram', coalesce(a.rolpassword LIKE 'SCRAM-SHA-256$%', false),
  'connect', has_database_privilege(a.rolname, current_database(), 'CONNECT'),
  'view_usage', coalesce((SELECT has_schema_privilege(a.rolname,n.oid,'USAGE')
                          FROM pg_namespace n WHERE n.nspname = 'clipforge_inspect'), false),
  'view_select', ARRAY(SELECT c.relname::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace
                        WHERE n.nspname='clipforge_inspect' AND c.relkind='v'
                        AND has_table_privilege(a.rolname,c.oid,'SELECT') ORDER BY c.relname),
  'activation_marker', CASE WHEN shobj_description(a.oid, 'pg_authid') ~ '^clipforge-int-personal-v1:[a-f0-9]{64}$'
                            THEN shobj_description(a.oid, 'pg_authid') END,
  'sessions', (SELECT count(*) FROM pg_stat_activity WHERE usename='aldemaro_int' AND datname='clipforge')
) FROM pg_authid a WHERE a.rolname = 'aldemaro_int';
"""


class Blocked(Exception):
    """Closed error codes only."""


def require(condition, code):
    if not condition:
        raise Blocked(code)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode("ascii")


def decode(raw):
    def pairs(values):
        result = dict(values)
        require(len(values) == len(result), "duplicate_field")
        return result
    return json.loads(raw, object_pairs_hook=pairs)


def activation_marker(value):
    return "clipforge-int-personal-v1:" + sha256(canonical({key: value[key] for key in COMMON_FIELDS - {"schema"}})).hexdigest()


def request(raw, reviewed_payload):
    require(0 < len(raw) <= MAX_INPUT, "protected_request_size")
    value = decode(raw)
    require(isinstance(value, dict) and value.get("schema") == SCHEMA, "protected_request_schema")
    action = value.get("action")
    extra = {"activate": {"verifier"}, "revoke": {"activation_marker"}, "observe": set()}
    require(action in MODES and set(value) == COMMON_FIELDS | extra[action],
            "protected_request_fields")
    require(all(value[key] == expected for key, expected in TARGET.items())
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"])
            and UUID.fullmatch(value["boot_id"]) and re.fullmatch(r"[a-f0-9]{40}", value["controls_commit"])
            and re.fullmatch(r"[1-9][0-9]{0,30}", value["state_generation"])
            and all(HASH.fullmatch(value[key]) for key in ("authority_sha256", "payload_sha256", "prior_evidence_sha256", "public_ca_sha256"))
            and value["payload_sha256"] == reviewed_payload, "protected_request_identity")
    if action == "activate":
        require(SCRAM.fullmatch(value["verifier"]), "protected_verifier_shape")
    if action == "revoke":
        require(MARKER.fullmatch(value["activation_marker"]), "protected_activation_marker_shape")
    require(raw == canonical(value), "protected_request_canonical")
    return value


def check_target(boot, ca_sha):
    require(os.geteuid() == 0 and BOOT.read_text(encoding="ascii").strip() == boot, "guest_boot_or_identity")
    link = BY_ID.lstat()
    device = BY_ID.stat()
    mount = MOUNT.stat()
    require(stat.S_ISLNK(link.st_mode) and link.st_uid == 0 and stat.S_ISBLK(device.st_mode)
            and mount.st_dev == device.st_rdev and os.path.ismount(MOUNT), "guest_noble_data_mount")
    ca = CA_FILE.lstat()
    require(stat.S_ISREG(ca.st_mode) and 0 < ca.st_size <= 1024 * 1024
            and sha256(CA_FILE.read_bytes()).hexdigest() == ca_sha, "guest_noble_public_ca_changed")


def postgres(raw):
    with tempfile.TemporaryFile(mode="w+b") as receipt:
        completed = subprocess.run(PSQL, input=raw, stdout=receipt, stderr=subprocess.DEVNULL,
                                   env={"LC_ALL": "C", "PATH": "/usr/bin:/bin"}, timeout=75, check=False)
        size = receipt.tell()
        require(completed.returncode == 0 and size <= MAX_OUTPUT, "postgres_operation_requires_reconciliation")
        receipt.seek(0)
        return receipt.read()


def prepare_sql(value, assets):
    action = value["action"]
    if action == "observe":
        return b"BEGIN READ ONLY;\n" + BODY + OBSERVE + b"COMMIT;\n"
    if action == "activate":
        views = assets["views"]
        require(views.count(b"BEGIN;") == views.count(b"COMMIT;") == 1 and views.endswith(b"COMMIT;\n"),
                "reviewed_view_transaction_changed")
        fence = b"""DO $personal_unused$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_authid WHERE rolname='aldemaro_int' AND
              (rolcanlogin OR rolpassword IS NOT NULL OR shobj_description(oid, 'pg_authid') IS NOT NULL))
     OR to_regnamespace('clipforge_inspect') IS NOT NULL THEN
    RAISE EXCEPTION 'personal_existing_state_requires_reconciliation';
  END IF;
END
$personal_unused$;
"""
        verifier = value["verifier"].encode("ascii")
        marker = activation_marker(value).encode("ascii")
        return (b"BEGIN;\n" + BODY + fence + views.replace(b"BEGIN;\n", b"", 1).removesuffix(b"COMMIT;\n")
                + b"RESET ROLE;\n" + assets["acl"]
                + b"ALTER ROLE aldemaro_int LOGIN PASSWORD '" + verifier + b"';\n"
                + b"COMMENT ON ROLE aldemaro_int IS '" + marker + b"';\n" + OBSERVE + b"COMMIT;\n")
    revoke = assets["revoke"]
    require(revoke.count(b"BEGIN;") == revoke.count(b"COMMIT;") == 1, "reviewed_revoke_transaction_changed")
    marker = value["activation_marker"].encode("ascii")
    fence = b"""DO $personal_revoke_owner$
BEGIN
  IF shobj_description('aldemaro_int'::regrole::oid, 'pg_authid') IS DISTINCT FROM '""" + marker + b"""' THEN
    RAISE EXCEPTION 'personal_activation_marker_changed';
  END IF;
END
$personal_revoke_owner$;
"""
    revoke = revoke.replace(b"BEGIN;\n", b"BEGIN;\n" + BODY + fence, 1)
    revoke = revoke.replace(b"COMMIT;\n", b"COMMENT ON ROLE aldemaro_int IS NULL;\nCOMMIT;\n", 1)
    return revoke + b"BEGIN READ ONLY;\n" + OBSERVE + b"COMMIT;\n"


def check_observation(action, row):
    flags = {"login", "verifier_present", "scram", "connect", "view_usage"}
    require(isinstance(row, dict) and set(row) == flags | {"sessions", "view_select", "activation_marker"}
            and all(type(row[key]) is bool for key in flags)
            and (row["activation_marker"] is None or isinstance(row["activation_marker"], str)
                 and MARKER.fullmatch(row["activation_marker"]))
            and type(row["sessions"]) is int and 0 <= row["sessions"] <= 1000
            and isinstance(row["view_select"], list) and all(name in VIEWS for name in row["view_select"]),
            "native_personal_sql_result_shape")
    if action == "activate":
        require(all(row[key] for key in flags) and row["view_select"] == VIEWS, "activation_postcheck_requires_reconciliation")
    if action == "revoke":
        require(not any(row[key] for key in flags) and row["view_select"] == [] and row["activation_marker"] is None
                and row["sessions"] == 0, "revocation_postcheck_requires_reconciliation")


def result(value, raw):
    action = value["action"]
    lines = raw.splitlines()
    require(len(lines) == (2 if action == "revoke" else 1), "native_personal_sql_output_shape")
    if action == "revoke":
        require(lines[0] == b"t", "personal_sessions_not_closed")
    row = decode(lines[-1])
    check_observation(action, row)
    if action == "activate":
        require(row["activation_marker"] == activation_marker(value), "activation_marker_requires_reconciliation")
    return {**{key: item for key, item in value.items() if key not in {"schema", "verifier"}}, "schema": RESULT,
            "status": {"activate": "activated_verified", "revoke": "revoked_verified", "observe": "observed"}[action],
            "observation": row}


def main(raw, reviewed_payload, assets, *, identity=check_target, execute=postgres):
    try:
        value = request(raw, reviewed_payload)
        identity(value["boot_id"], value["public_ca_sha256"])
        output = execute(prepare_sql(value, assets))
        identity(value["boot_id"], value["public_ca_sha256"])
        return 0, result(value, output)
    except Blocked as error:
        return 1, {"schema": RESULT, "status": "blocked_or_indeterminate", "error_code": str(error)}
    except (ValueError, TypeError, KeyError, OSError, subprocess.SubprocessError):
        return 1, {"schema": RESULT, "status": "blocked_or_indeterminate", "error_code": "personal_sql_native_error"}


if __name__ == "__main__":
    code, report = main(sys.stdin.buffer.read(MAX_INPUT + 1), DB01_OPERATOR_SHA256, SQL_ASSETS)
    sys.stdout.buffer.write(canonical(report))
    raise SystemExit(code)
