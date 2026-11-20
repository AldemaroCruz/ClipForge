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
NOBLE_JOBS = {"migrate": "clipforge-int-db01-noble-migration", "app": "clipforge-int-db01-noble-acceptance"}
NOBLE_SOURCES = {
    "app/__init__.py": "2add5623d6be15a1f47f55454d5d9068341a12d1aa5eb74379335181a87896af",
    "app/auth_db.py": "7048c96e50cd3349fd19658d44cf3b97ace90d5efe596151fc5a0459e164c745",
    "app/auth_migrations.py": "f8f4aebbb251744116da7fe770e93bb12c3ff2409a2cac730359b0e9ee8f888d",
    "app/cloud/__init__.py": "08fe97dcf217d39f71de9025ec95fc25150bfd01715cc3e1e1940d11990eba69",
    "app/cloud/migrate.py": "d4833d866c7208f1b87b4a80a8882664d0208f5cd39e7ecee232db34b97235a3",
}
NOBLE_IMAGE = ("us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/db01-noble-client@"
               "sha256:24e4d9ccea365859c6f455c3780c8abe6a0df3f1150e60380e2b2cc73e0dc5b5")
NOBLE_SCOPE = {"name": "noble", "project": "clipforgebeta2", "zone": "us-central1-a",
               "instance_id": "7365414160255801909", "data_disk_id": "7382984635240536620",
               "database_host": "10.80.1.3", "postgres_version_num": 170012}
NOBLE_GUEST_RECEIPT_SHA256 = "39f8588f3a8211d642ba8052f782160d4b86c744f1b5df7b96890705d1302563"
JOB_PATH = "projects/clipforgebeta2/locations/us-central1/jobs/"
METADATA_EMAIL_URL = "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/email"
TABLES = ("auth_users", "auth_workspaces", "auth_memberships", "auth_projects", "auth_sessions", "auth_challenges",
          "auth_login_attempts", "auth_recovery_codes", "auth_audit_events", "auth_security_attempts",
          "cloud_documents", "cloud_tasks", "cloud_outbox", "cloud_requests")
CONNECT_TIMEOUT_SECONDS = 5
STATEMENT_TIMEOUT_MS = 15000
LOCK_TIMEOUT_MS = 3000
SQL_OPTIONS = "-csearch_path=public -cstatement_timeout=15000 -clock_timeout=3000"


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


def route(phase, target):
    require(target in ("debian", "noble") and phase in JOBS, "specific_job_target_and_phase_required")
    if target == "noble":
        return NOBLE_JOBS[phase], NOBLE_SCOPE["database_host"], NOBLE_SCOPE["postgres_version_num"]
    return JOBS[phase], "10.80.1.2", 170012


def source_records(rows, *, target="debian"):
    require(target in ("debian", "noble"), "specific_job_target_required")
    sources = NOBLE_SOURCES if target == "noble" else SOURCES
    require(isinstance(rows, list) and len(rows) == len(sources), "exact_app_sources_required")
    result = {}
    for row in rows:
        require(isinstance(row, dict) and set(row) == {"path", "sha256"} and row["path"] in sources
                and row["path"] not in result and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]), "app_source_binding_invalid")
        result[row["path"]] = row["sha256"]
    if target == "noble":
        require(result == NOBLE_SOURCES, "noble_oci_sources_differ_from_review")
    return result


def noble_evidence(guest_receipt_sha256, bootstrap_receipt_sha256):
    require(guest_receipt_sha256 == NOBLE_GUEST_RECEIPT_SHA256
            and isinstance(bootstrap_receipt_sha256, str) and re.fullmatch(r"[a-f0-9]{64}", bootstrap_receipt_sha256)
            and guest_receipt_sha256 != bootstrap_receipt_sha256, "separate_noble_guest_and_bootstrap_receipts_required")
    return {"guest_receipt_sha256": guest_receipt_sha256, "bootstrap_receipt_sha256": bootstrap_receipt_sha256}


def job_spec(phase, image, versions, app_sources, *, source=None, target="debian", guest_receipt_sha256=None,
             bootstrap_receipt_sha256=None):
    job, database_host, _ = route(phase, target)
    require(image == NOBLE_IMAGE if target == "noble" else
            re.fullmatch(r"us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/runtime@sha256:[a-f0-9]{64}", image),
            "exact_published_image_digest_required")
    require(isinstance(versions, dict) and set(versions) == {"migrator_password", "app_password", "postgres_ca"}
            and all(re.fullmatch(r"[1-9][0-9]*", value or "") for value in versions.values()), "numeric_secret_versions_required")
    source_records(app_sources, target=target)
    raw = Path(__file__).read_bytes() if source is None else source
    source_sha = sha(raw)
    loader = "import base64,sys;sys.path.insert(0,\"/app\");exec(compile(base64.b64decode(\"" + base64.b64encode(raw).decode() + "\"),\"int_db_acceptance.py\",\"exec\"),{\"__name__\":\"__main__\",\"DB01_ACCEPTANCE_SOURCE_SHA256\":\"" + source_sha + "\"})"
    password = "migrator_password" if phase == "migrate" else "app_password"
    secret = "clipforge-int-pg-migrator-password" if phase == "migrate" else "clipforge-int-pg-app-password"
    env = {"CLIPFORGE_DATABASE_HOST": database_host, "CLIPFORGE_DATABASE_PORT": "5432", "CLIPFORGE_DATABASE_NAME": "clipforge",
           "CLIPFORGE_DATABASE_SCHEMA": "public", "CLIPFORGE_DATABASE_USER": "clipforge_migrator" if phase == "migrate" else "clipforge_app",
           "CLIPFORGE_DATABASE_PASSWORD_FILE": "/secrets/database/value", "CLIPFORGE_DATABASE_SSL_MODE": "verify-full",
           "CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE": "/secrets/postgres-ca/value", "CLIPFORGE_DATABASE_POOL_SIZE": "2",
           "CLIPFORGE_DATABASE_POOL_OVERFLOW": "1", "CLIPFORGE_ENVIRONMENT": "INT", "CLIPFORGE_STORAGE_BACKEND": "gcs",
           "INT_DB_ACCEPTANCE_SOURCE_SHA256": source_sha, "INT_DB_EXPECTED_IMAGE": image,
           "INT_DB_SECRET_VERSIONS_JSON": json.dumps(versions, sort_keys=True), "INT_DB_APP_SOURCES_JSON": json.dumps(app_sources, sort_keys=True)}
    args = ["-I", "-c", loader, "execute", phase]
    if target == "noble":
        evidence = noble_evidence(guest_receipt_sha256, bootstrap_receipt_sha256)
        env.update(INT_DB_GUEST_RECEIPT_SHA256=evidence["guest_receipt_sha256"],
                   INT_DB_BOOTSTRAP_RECEIPT_SHA256=evidence["bootstrap_receipt_sha256"])
        args += ["--target", "noble"]
    else:
        require(guest_receipt_sha256 is None and bootstrap_receipt_sha256 is None, "noble_receipts_forbid_debian_job")
    return {"name": JOB_PATH + job,
        "labels": {"application": "clipforge", "environment": "int", "purpose": "db01-external-acceptance"},
        "template": {"taskCount": 1, "parallelism": 1, "template": {"serviceAccount": ACCOUNTS[phase], "maxRetries": 0, "timeout": "600s",
            "executionEnvironment": "EXECUTION_ENVIRONMENT_GEN2", "vpcAccess": {"egress": "PRIVATE_RANGES_ONLY", "networkInterfaces": [
                {"network": "clipforge-int-base", "subnetwork": "clipforge-int-base-run"}]},
            "containers": [{"name": "client", "image": image, "command": ["python"], "args": args,
                "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
                "resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
                "volumeMounts": [{"name": "database", "mountPath": "/secrets/database"}, {"name": "postgres-ca", "mountPath": "/secrets/postgres-ca"}]}],
            "volumes": [{"name": "database", "secret": {"secret": secret, "items": [{"version": versions[password], "path": "value"}]}},
                        {"name": "postgres-ca", "secret": {"secret": "clipforge-int-postgres-ca", "items": [{"version": versions["postgres_ca"], "path": "value"}]}}]}}}


def validate_client_decision(raw, expected_sha, expected, *, now=None, target="debian"):
    job, _, _ = route(expected.get("phase"), target)
    require(isinstance(raw, str) and 0 < len(raw) <= 16384 and sha(raw.encode("ascii")) == expected_sha, "future_owner_client_decision_required")
    value = decode(raw)
    fields = {"schema", "status", "owner", "job", "phase", "operation_id", "source_sha256", "image", "secret_versions", "app_sources", "guest_receipt_sha256", "issued_utc", "expires_utc"}
    exact_fields = {"job", "phase", "source_sha256", "image", "secret_versions", "app_sources"}
    schema = "clipforge-db01-client-decision-1"
    if target == "noble":
        fields |= {"target", "bootstrap_receipt_sha256"}
        exact_fields |= {"target", "guest_receipt_sha256", "bootstrap_receipt_sha256"}
        schema = "clipforge-db01-client-decision-2"
    require(isinstance(value, dict) and set(value) == fields and value["schema"] == schema
            and value["status"] == "authorized_specific_job_execution" and value["owner"] == "admin@ixbalam.studio"
            and value["phase"] == expected["phase"] and value["job"] == job
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and re.fullmatch(r"[a-f0-9]{64}", value["source_sha256"]), "exact_cloud_job_authority_required")
    require(set(expected) == exact_fields
            and all(value[key] == item for key, item in expected.items()) and re.fullmatch(r"[a-f0-9]{64}", value["guest_receipt_sha256"]), "reviewed_job_inputs_required")
    evidence = {}
    if target == "noble":
        require(value["target"] == NOBLE_SCOPE and type(value["target"]["postgres_version_num"]) is int,
                "exact_noble_scope_required")
        evidence = noble_evidence(value["guest_receipt_sha256"], value["bootstrap_receipt_sha256"])
    job_spec(value["phase"], value["image"], value["secret_versions"], value["app_sources"],
             source=b"validation-only-no-execution", target=target, **evidence)
    at = datetime.now(timezone.utc) if now is None else now
    issued, expires = utc(value["issued_utc"]), utc(value["expires_utc"])
    require(0 < (expires-issued).total_seconds() <= 3600 and issued <= at and (expires-at).total_seconds() >= 600, "client_decision_expired")
    return value


def job_run_request(decision_raw, decision_sha, *, phase, image, versions, app_sources, source_sha256, now=None, target="debian",
                    guest_receipt_sha256=None, bootstrap_receipt_sha256=None):
    """Pure future run body: two authority values only; never secrets or args."""
    job, _, _ = route(phase, target)
    expected = {"job": job, "phase": phase, "source_sha256": source_sha256, "image": image,
                "secret_versions": versions, "app_sources": app_sources}
    if target == "noble":
        expected.update(target=NOBLE_SCOPE, **noble_evidence(guest_receipt_sha256, bootstrap_receipt_sha256))
    else:
        require(guest_receipt_sha256 is None and bootstrap_receipt_sha256 is None, "noble_receipts_forbid_debian_job")
    validate_client_decision(decision_raw, decision_sha, expected, now=now, target=target)
    return {"resource": JOB_PATH + job, "method": "POST",
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


def execution_authority(env, phase, *, now=None, target="debian"):
    job, database_host, _ = route(phase, target)
    require(env.get("CLOUD_RUN_JOB") == job and env.get("CLOUD_RUN_TASK_INDEX") == "0"
            and env.get("CLOUD_RUN_TASK_ATTEMPT") == "0" and env.get("CLOUD_RUN_TASK_COUNT") == "1", "exact_cloud_job_environment_required")
    expected = {"job": job, "phase": phase, "source_sha256": env.get("INT_DB_ACCEPTANCE_SOURCE_SHA256"),
                "image": env.get("INT_DB_EXPECTED_IMAGE"), "secret_versions": decode(env.get("INT_DB_SECRET_VERSIONS_JSON", "")),
                "app_sources": decode(env.get("INT_DB_APP_SOURCES_JSON", ""))}
    evidence_keys = ("INT_DB_GUEST_RECEIPT_SHA256", "INT_DB_BOOTSTRAP_RECEIPT_SHA256")
    require(env.get("CLIPFORGE_DATABASE_HOST", database_host if target == "debian" else None) == database_host,
            "cloud_job_database_target_mismatch")
    if target == "noble":
        expected.update(target=NOBLE_SCOPE, **noble_evidence(*(env.get(key) for key in evidence_keys)))
    else:
        require(not any(key in env for key in evidence_keys), "noble_receipts_forbid_debian_job")
    value = validate_client_decision(env.get("INT_DB_CLIENT_DECISION_JSON", ""), env.get("INT_DB_CLIENT_DECISION_SHA256"),
                                     expected, now=now, target=target)
    require(value["source_sha256"] == globals().get("DB01_ACCEPTANCE_SOURCE_SHA256"), "executed_client_source_digest_required")
    for name, digest in source_records(value["app_sources"], target=target).items():
        path = Path("/app") / name
        require(path.is_file() and not path.is_symlink() and sha(path.read_bytes()) == digest, "runtime_app_source_changed")
    observed = observed_service_account()
    require(observed == ACCOUNTS[phase], "observed_job_service_account_mismatch")
    return {**value, "_observed_service_account": observed}


def migration_engine(options):
    """The migration's own connections carry the same native SQL deadlines."""
    from sqlalchemy import URL, create_engine
    from sqlalchemy.pool import NullPool
    require(isinstance(options, dict) and all(options.get(key) for key in
            ("host", "port", "dbname", "user", "password", "sslrootcert"))
            and options.get("sslmode") == "verify-full", "explicit_verified_migration_connection_required")
    url = URL.create("postgresql+psycopg", username=options["user"], password=options["password"],
                     host=options["host"], port=options["port"], database=options["dbname"])
    return create_engine(url, poolclass=NullPool, echo=False, hide_parameters=True,
                         connect_args={"connect_timeout": CONNECT_TIMEOUT_SECONDS, "sslmode": "verify-full",
                                       "sslrootcert": options["sslrootcert"], "options": SQL_OPTIONS})


def apply_migrations(options):
    """Both migration passes use explicit bounded connections and dispose them."""
    from app.cloud.migrate import upgrade
    engine = migration_engine(options)
    try:
        first, second = upgrade(engine), upgrade(engine)
        require(first["status"] in {"applied", "current"} and second["status"] == "current", "migration_idempotence_failed")
        return first, second
    finally:
        engine.dispose()


def execute(phase, env, *, authority=None, target="debian"):
    job, database_host, postgres_version = route(phase, target)
    decision = execution_authority(env, phase, target=target) if authority is None else authority(env, phase)
    if target == "noble":
        require(decision.get("schema") == "clipforge-db01-client-decision-2"
                and decision["target"] == NOBLE_SCOPE and decision["job"] == job, "exact_noble_scope_required")
        noble_evidence(decision["guest_receipt_sha256"], decision["bootstrap_receipt_sha256"])
    else:
        require(not ({"target", "bootstrap_receipt_sha256"} & decision.keys()), "noble_receipts_forbid_debian_job")
    import psycopg
    from psycopg import sql
    options = {"host": database_host, "port": 5432, "dbname": "clipforge", "user": "clipforge_migrator" if phase == "migrate" else "clipforge_app",
        "password": Path("/secrets/database/value").read_text(), "sslmode": "verify-full", "sslrootcert": "/secrets/postgres-ca/value",
        "connect_timeout": CONNECT_TIMEOUT_SECONDS, "options": SQL_OPTIONS}
    result = {"schema": "clipforge-db01-external-acceptance-1", "status": "failed", "phase": phase,
        "operation_id": decision["operation_id"], "owner_decision_sha256": env["INT_DB_CLIENT_DECISION_SHA256"],
        "guest_receipt_sha256": decision["guest_receipt_sha256"], "checks": [], "runtime_authorized": False, "restore_verified": False,
        "identity": {"configured_service_account": ACCOUNTS[phase], "observed_service_account": decision.get("_observed_service_account"),
                     "source": "GCP_metadata_email" if decision.get("_observed_service_account") else "local_fixture_authority_boundary"}}
    if target == "noble":
        result.update(schema="clipforge-db01-external-acceptance-2", job=job, target=decision["target"],
                      bootstrap_receipt_sha256=decision["bootstrap_receipt_sha256"],
                      source_sha256=decision["source_sha256"])
    try:
        with psycopg.connect(**options) as connection:
            row = connection.execute("SELECT current_user,host(inet_client_addr()),host(inet_server_addr()),current_setting('server_version_num')::int").fetchone()
            require(row[0] == options["user"] and ipaddress.ip_address(row[1]) in ipaddress.ip_network("10.80.0.0/26")
                    and row[2] == database_host and row[3] == postgres_version, "direct_vpc_client_or_server_identity_mismatch")
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
            if target == "noble":
                result["checks"][-1].update(server_address=row[2], postgres_version_num=row[3])
        if phase == "migrate":
            first, second = apply_migrations(options)
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
    parser.add_argument("--target", choices=("debian", "noble"), default="debian")
    args = parser.parse_args()
    def timeout(signum, frame): raise ValueError("client_total_time_exceeded")
    signal.signal(signal.SIGALRM, timeout); signal.alarm(570)
    try: result = execute(args.phase, os.environ, target=args.target)
    except Exception as error:
        schema = "clipforge-db01-external-acceptance-2" if args.target == "noble" else "clipforge-db01-external-acceptance-1"
        result = {"schema": schema, "status": "blocked", "error_type": type(error).__name__, "runtime_authorized": False}
    finally: signal.alarm(0)
    print(json.dumps(result, sort_keys=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__": raise SystemExit(main())
