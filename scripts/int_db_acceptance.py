"""Proposed one-off Direct VPC PostgreSQL clients; never a hosted-runner client.

Two existing service identities keep app and migrator secret access separate.
Rendering is local. Execution needs a later, exact owner decision and deployed
Job definition; this file creates no Cloud Run Job or other cloud resource.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import signal
import sys
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

JOBS = {"migrate": "clipforge-int-db01-migration", "app": "clipforge-int-db01-acceptance"}
ACCOUNTS = {"migrate": "clipforge-migrate-int@clipforgebeta2.iam.gserviceaccount.com", "app": "clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com"}
SOURCES = {"app/auth_migrations.py", "app/auth_db.py", "app/cloud/migrate.py"}
METADATA_EMAIL_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
TABLES = ("auth_users", "auth_workspaces", "auth_memberships", "auth_projects", "auth_sessions", "auth_challenges",
          "auth_login_attempts", "auth_recovery_codes", "auth_audit_events", "auth_security_attempts",
          "cloud_documents", "cloud_tasks", "cloud_outbox", "cloud_requests")


def require(ok, code):
    if not ok: raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def utc(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None, "aware_time_required")
    return result


def decode(raw):
    def pairs(rows):
        value = {}
        for key, item in rows:
            require(key not in value, "duplicate_client_json_key")
            value[key] = item
        return value
    require(isinstance(raw, str) and 0 < len(raw) <= 32768, "bounded_client_json_required")
    return json.loads(raw, object_pairs_hook=pairs)


def source_records(rows):
    require(isinstance(rows, list) and len(rows) == len(SOURCES), "exact_app_sources_required")
    result = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "sha256"} and row["path"] in SOURCES
                and row["path"] not in result and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "app_source_binding_invalid")
        result[row["path"]] = row["sha256"]
    return result


def job_spec(phase, image, versions, app_sources, *, source=None):
    require(phase in JOBS and re.fullmatch(r"us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/runtime@sha256:[a-f0-9]{64}", image), "exact_published_image_digest_required")
    require(isinstance(versions, dict) and set(versions) == {"migrator_password", "app_password", "postgres_ca"}
            and all(re.fullmatch(r"[1-9][0-9]*", value or "") for value in versions.values()), "numeric_secret_versions_required")
    source_records(app_sources)
    raw = Path(__file__).read_bytes() if source is None else source
    source_sha = sha(raw)
    loader = "import base64,sys;sys.path.insert(0,\"/app\");exec(compile(base64.b64decode(\"" + base64.b64encode(raw).decode() + "\"),\"int_db_acceptance.py\",\"exec\"),{\"__name__\":\"__main__\",\"DB01_ACCEPTANCE_SOURCE_SHA256\":\"" + source_sha + "\"})"
    password = "migrator_password" if phase == "migrate" else "app_password"
    secret = "clipforge-int-pg-migrator-password" if phase == "migrate" else "clipforge-int-pg-app-password"
    env = {"CLIPFORGE_DATABASE_HOST": "10.80.1.2", "CLIPFORGE_DATABASE_PORT": "5432", "CLIPFORGE_DATABASE_NAME": "clipforge",
           "CLIPFORGE_DATABASE_SCHEMA": "public", "CLIPFORGE_DATABASE_USER": "clipforge_migrator" if phase == "migrate" else "clipforge_app",
           "CLIPFORGE_DATABASE_PASSWORD_FILE": "/secrets/database/value", "CLIPFORGE_DATABASE_SSL_MODE": "verify-full",
           "CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE": "/secrets/postgres-ca/value", "CLIPFORGE_DATABASE_POOL_SIZE": "2",
           "CLIPFORGE_DATABASE_POOL_OVERFLOW": "1", "CLIPFORGE_ENVIRONMENT": "INT", "CLIPFORGE_STORAGE_BACKEND": "gcs",
           "INT_DB_ACCEPTANCE_SOURCE_SHA256": source_sha, "INT_DB_EXPECTED_IMAGE": image,
           "INT_DB_SECRET_VERSIONS_JSON": json.dumps(versions, sort_keys=True), "INT_DB_APP_SOURCES_JSON": json.dumps(app_sources, sort_keys=True)}
    return {"name": "projects/clipforgebeta2/locations/us-central1/jobs/" + JOBS[phase],
        "labels": {"application": "clipforge", "environment": "int", "purpose": "db01-external-acceptance"},
        "template": {"taskCount": 1, "parallelism": 1, "template": {"serviceAccount": ACCOUNTS[phase], "maxRetries": 0, "timeout": "600s",
            "executionEnvironment": "EXECUTION_ENVIRONMENT_GEN2", "vpcAccess": {"egress": "PRIVATE_RANGES_ONLY", "networkInterfaces": [
                {"network": "clipforge-int-base", "subnetwork": "clipforge-int-base-run"}]},
            "containers": [{"name": "client", "image": image, "command": ["python"], "args": ["-I", "-c", loader, "execute", phase],
                "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
                "resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
                "volumeMounts": [{"name": "database", "mountPath": "/secrets/database"}, {"name": "postgres-ca", "mountPath": "/secrets/postgres-ca"}]}],
            "volumes": [{"name": "database", "secret": {"secret": secret, "items": [{"version": versions[password], "path": "value"}]}},
                        {"name": "postgres-ca", "secret": {"secret": "clipforge-int-postgres-ca", "items": [{"version": versions["postgres_ca"], "path": "value"}]}}]}}}


def validate_client_decision(raw, expected_sha, expected, *, now=None):
    require(isinstance(raw, str) and 0 < len(raw) <= 16384 and sha(raw.encode("ascii")) == expected_sha, "future_owner_client_decision_required")
    value = decode(raw)
    fields = {"schema", "status", "owner", "job", "phase", "operation_id", "source_sha256", "image", "secret_versions", "app_sources", "guest_receipt_sha256", "issued_utc", "expires_utc"}
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == "clipforge-db01-client-decision-1"
            and value["status"] == "authorized_specific_job_execution" and value["owner"] == "admin@ixbalam.studio"
            and value["phase"] in JOBS and value["job"] == JOBS[value["phase"]]
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and re.fullmatch(r"[a-f0-9]{64}", value["source_sha256"]), "exact_cloud_job_authority_required")
    require(set(expected) == {"job", "phase", "source_sha256", "image", "secret_versions", "app_sources"}
            and all(value[key] == item for key, item in expected.items()) and re.fullmatch(r"[a-f0-9]{64}", value["guest_receipt_sha256"]), "reviewed_job_inputs_required")
    job_spec(value["phase"], value["image"], value["secret_versions"], value["app_sources"], source=b"validation-only-no-execution")
    at = datetime.now(timezone.utc) if now is None else now
    issued, expires = utc(value["issued_utc"]), utc(value["expires_utc"])
    require(0 < (expires-issued).total_seconds() <= 3600 and issued <= at and (expires-at).total_seconds() >= 600, "client_decision_expired")
    return value


def job_run_request(decision_raw, decision_sha, *, phase, image, versions, app_sources, source_sha256, now=None):
    """Pure future run body: two authority values only; never secrets or args."""
    require(phase in JOBS, "specific_job_phase_required")
    expected = {"job": JOBS[phase], "phase": phase, "source_sha256": source_sha256, "image": image,
                "secret_versions": versions, "app_sources": app_sources}
    validate_client_decision(decision_raw, decision_sha, expected, now=now)
    return {"resource": "projects/clipforgebeta2/locations/us-central1/jobs/" + JOBS[phase], "method": "POST",
            "body": {"overrides": {"taskCount": 1, "timeout": "600s", "containerOverrides": [{"name": "client", "env": [
                {"name": "INT_DB_CLIENT_DECISION_JSON", "value": decision_raw}, {"name": "INT_DB_CLIENT_DECISION_SHA256", "value": decision_sha}]}]}}}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("metadata_redirect_forbidden")


def observed_service_account():
    request = Request(METADATA_EMAIL_URL, headers={"Metadata-Flavor": "Google"}, method="GET")
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=3) as response:
        require(response.headers.get("Metadata-Flavor") == "Google", "metadata_response_flavor_required")
        raw = response.read(513)
    require(0 < len(raw) <= 512, "bounded_metadata_email_required")
    return raw.decode("ascii").strip()


def execution_authority(env, phase, *, now=None):
    require(phase in JOBS and env.get("CLOUD_RUN_JOB") == JOBS[phase] and env.get("CLOUD_RUN_TASK_INDEX") == "0"
            and env.get("CLOUD_RUN_TASK_ATTEMPT") == "0" and env.get("CLOUD_RUN_TASK_COUNT") == "1", "exact_cloud_job_environment_required")
    expected = {"job": JOBS[phase], "phase": phase, "source_sha256": env.get("INT_DB_ACCEPTANCE_SOURCE_SHA256"),
                "image": env.get("INT_DB_EXPECTED_IMAGE"), "secret_versions": decode(env.get("INT_DB_SECRET_VERSIONS_JSON", "")),
                "app_sources": decode(env.get("INT_DB_APP_SOURCES_JSON", ""))}
    value = validate_client_decision(env.get("INT_DB_CLIENT_DECISION_JSON", ""), env.get("INT_DB_CLIENT_DECISION_SHA256"), expected, now=now)
    require(value["source_sha256"] == globals().get("DB01_ACCEPTANCE_SOURCE_SHA256"), "executed_client_source_digest_required")
    for name, digest in source_records(value["app_sources"]).items():
        path = Path("/app") / name
        require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == digest, "runtime_app_source_changed")
    observed = observed_service_account()
    require(observed == ACCOUNTS[phase], "observed_job_service_account_mismatch")
    return {**value, "_observed_service_account": observed}


def execute(phase, env, *, authority=None):
    decision = (execution_authority if authority is None else authority)(env, phase)
    import psycopg
    from psycopg import sql
    options = {"host": "10.80.1.2", "port": 5432, "dbname": "clipforge", "user": "clipforge_migrator" if phase == "migrate" else "clipforge_app",
        "password": Path("/secrets/database/value").read_text(), "sslmode": "verify-full", "sslrootcert": "/secrets/postgres-ca/value",
        "connect_timeout": 5, "options": "-c statement_timeout=15000 -c lock_timeout=3000"}
    result = {"schema": "clipforge-db01-external-acceptance-1", "status": "failed", "phase": phase,
        "operation_id": decision["operation_id"], "owner_decision_sha256": env["INT_DB_CLIENT_DECISION_SHA256"],
        "guest_receipt_sha256": decision["guest_receipt_sha256"], "checks": [], "runtime_authorized": False, "restore_verified": False,
        "identity": {"configured_service_account": ACCOUNTS[phase], "observed_service_account": decision.get("_observed_service_account"),
                     "source": "GCP_metadata_email" if decision.get("_observed_service_account") else "local_fixture_authority_boundary"}}
    try:
        with psycopg.connect(**options) as connection:
            row = connection.execute("SELECT current_user,host(inet_client_addr()),host(inet_server_addr()),current_setting('server_version_num')::int").fetchone()
            require(row[0] == options["user"] and ipaddress.ip_address(row[1]) in ipaddress.ip_network("10.80.0.0/26")
                    and row[2] == "10.80.1.2" and row[3] == 170012, "direct_vpc_client_or_server_identity_mismatch")
            flags = connection.execute("SELECT rolsuper,rolcreatedb,rolcreaterole,rolreplication,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
            require(flags == (False, False, False, False, False), "unexpected_postgres_role_flags")
            require(connection.execute("SELECT count(*) FROM pg_auth_members WHERE member=(SELECT oid FROM pg_roles WHERE rolname=current_user)").fetchone()[0] == 0, "unexpected_role_memberships")
            tls = connection.execute("SELECT ssl,version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
            require(tls[0] is True and tls[1] in {"TLSv1.2", "TLSv1.3"}
                    and connection.execute("SHOW password_encryption").fetchone()[0] == "scram-sha-256", "verified_tls_scram_contract_failed")
            encoding = connection.execute("SHOW server_encoding").fetchone()[0]
            locale, ctype = connection.execute("SELECT datcollate,datctype FROM pg_database WHERE datname=current_database()").fetchone()
            require(encoding == "UTF8" and locale == ctype == "C.UTF-8", "reviewed_encoding_or_locale_mismatch")
            result["checks"].append({"name": "private_client_tls_role", "status": "passed", "client_address": row[1], "tls": tls[1], "server_encoding": encoding, "lc_collate": locale, "lc_ctype": ctype})
        if phase == "migrate":
            from app.cloud.migrate import upgrade
            first, second = upgrade(), upgrade()
            require(first["status"] in {"applied", "current"} and second["status"] == "current", "migration_idempotence_failed")
            result["checks"].append({"name": "AUTH_and_cloud_migrations", "status": "passed", "first": first, "second": second})
        else:
            with psycopg.connect(**options) as connection:
                require(not connection.execute("SELECT has_database_privilege(current_user,current_database(),'CREATE') OR has_database_privilege(current_user,current_database(),'TEMPORARY') OR has_schema_privilege(current_user,'public','CREATE')").fetchone()[0], "app_schema_or_database_authority")
                for table in TABLES:
                    for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE"):
                        require(connection.execute("SELECT has_table_privilege(current_user,%s,%s)", ("public."+table, privilege)).fetchone()[0], "missing_individual_app_dml_privilege")
                    name = sql.Identifier("public", table)
                    connection.execute(sql.SQL("INSERT INTO {} SELECT * FROM {} WHERE false").format(name, name))
                    column = connection.execute("SELECT attname FROM pg_attribute WHERE attrelid=%s::regclass AND attnum>0 AND NOT attisdropped ORDER BY attnum LIMIT 1", ("public."+table,)).fetchone()[0]
                    connection.execute(sql.SQL("UPDATE {} SET {}={} WHERE false").format(name, sql.Identifier(column), sql.Identifier(column)))
                    connection.execute(sql.SQL("DELETE FROM {} WHERE false").format(name))
                sequences = connection.execute("SELECT c.oid FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind='S'").fetchall()
                require(all(connection.execute("SELECT has_sequence_privilege(current_user,%s,'USAGE')", (row[0],)).fetchone()[0] for row in sequences), "app_sequence_usage_missing")
                connection.rollback()
            for statement in ("CREATE TABLE public.db01_forbidden(id integer)", "CREATE SCHEMA db01_forbidden", "CREATE ROLE db01_forbidden", "ALTER TABLE public.auth_users ADD COLUMN db01_forbidden integer"):
                try:
                    with psycopg.connect(**options) as connection:
                        connection.execute(statement)
                        raise ValueError("app_ddl_unexpectedly_permitted")  # The context rolls it back.
                except psycopg.errors.InsufficientPrivilege:
                    pass
            result["checks"].append({"name": "app_dml_only_and_ddl_denied", "status": "passed", "tables": len(TABLES), "individual_privileges_per_table": 4, "data_rows_changed": 0})
        result["status"] = "passed"
    except Exception as error:
        result["error_type"] = type(error).__name__
        state = getattr(error, "sqlstate", None)
        if isinstance(state, str) and re.fullmatch(r"[A-Z0-9]{5}", state): result["sqlstate"] = state
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("execute",)); parser.add_argument("phase", choices=tuple(JOBS))
    args = parser.parse_args()
    def timeout(signum, frame): raise ValueError("client_total_time_exceeded")
    signal.signal(signal.SIGALRM, timeout); signal.alarm(570)
    try: result = execute(args.phase, os.environ)
    except Exception as error: result = {"schema": "clipforge-db01-external-acceptance-1", "status": "blocked", "error_type": type(error).__name__, "runtime_authorized": False}
    finally: signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__": raise SystemExit(main())
