"""Explicit DB-01 regression on a new disposable PG17 database, never INT.

Not part of discovery: the host supplies the exclusive TLS Docker fixture and
mounts only a curated public-source snapshot. No owner database or cloud access.
"""
from __future__ import annotations

import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import os
from pathlib import Path
import sys
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from scripts import int_db_acceptance as client


def require(value, code):
    if not value:
        raise ValueError(code)


def sqlstates(error):
    """Keep native codes, never SQL/DSNs, parameter values or exception text."""
    found, pending, seen = set(), [error], set()
    while pending:
        current = pending.pop()
        if current is None or id(current) in seen:
            continue
        seen.add(id(current))
        code = getattr(current, "sqlstate", None)
        if isinstance(code, str) and len(code) == 5 and code.isalnum():
            found.add(code)
        pending.extend((getattr(current, "orig", None), current.__cause__, current.__context__))
    return sorted(found)


def revisions(connection):
    result = {}
    for name in ("auth_schema_migrations", "cloud_schema_migrations"):
        present = connection.execute("SELECT to_regclass(%s) IS NOT NULL", ("public." + name,)).fetchone()[0]
        # The two literal table identifiers are owned fixture schema metadata.
        if name == "auth_schema_migrations" and present:
            result[name] = [r[0] for r in connection.execute("SELECT revision FROM public.auth_schema_migrations ORDER BY revision")]
        elif name == "cloud_schema_migrations" and present:
            result[name] = [r[0] for r in connection.execute("SELECT revision FROM public.cloud_schema_migrations ORDER BY revision")]
        else:
            result[name] = None
    return result


def occupied_lock(options, key, expected_revisions):
    import psycopg
    with psycopg.connect(**options, autocommit=True) as owner, psycopg.connect(**options, autocommit=True) as monitor:
        owner.execute("SELECT pg_advisory_lock(%s)", (key,))
        observed = False
        started = time.monotonic()
        try:
            with ThreadPoolExecutor(max_workers=1) as pool:
                work = pool.submit(client.apply_migrations, options)
                while not work.done() and time.monotonic() - started < 8:
                    row = monitor.execute("SELECT count(*) FROM pg_stat_activity WHERE usename=current_user AND datname=current_database() AND wait_event_type='Lock' AND wait_event='advisory'").fetchone()
                    observed = observed or row[0] > 0
                    time.sleep(0.025)
                if not work.done():
                    owner.execute("SELECT pg_advisory_unlock(%s)", (key,))
                    raise ValueError("migration_did_not_obey_lock_deadline")
                try:
                    work.result()
                except Exception as error:
                    codes = sqlstates(error)
                else:
                    raise ValueError("occupied_advisory_lock_was_not_rejected")
            elapsed = time.monotonic() - started
            require(observed and "55P03" in codes and 2.5 <= elapsed < 8, "native_lock_timeout_not_observed")
            after = revisions(monitor)
            require(after == expected_revisions, "unexpected_migration_commit_boundary")
            return {"status": "passed", "advisory_key": key, "native_sqlstates": codes,
                    "advisory_wait_observed": observed, "elapsed_ms": round(elapsed * 1000), "revisions_after_failure": after}
        finally:
            # Session ownership only; never force unlock another session.
            owner.execute("SELECT pg_advisory_unlock(%s)", (key,))


def execute(report_path):
    import psycopg
    from sqlalchemy import text
    os.environ["CLIPFORGE_DATABASE_SCHEMA"] = "public"
    options = {"host": "postgres", "port": 5432, "dbname": "clipforge", "user": "clipforge_migrator",
               "password": Path("/run/secrets/database-password").read_text().strip(), "sslmode": "verify-full",
               "sslrootcert": "/run/db01/ca.crt", "connect_timeout": 5, "options": client.SQL_OPTIONS}
    result = {"schema": "clipforge-db01-migration-lock-regression-1", "status": "failed", "checks": [],
              "target": "new exclusive disposable Docker PG17 TLS database with synthetic credentials",
              "INT_or_cloud_executed": False, "full_AUTH_or_browser_suite_repeated": False,
              "vm_package_or_sca_equivalence_claimed": False,
              "difference_from_VM": "PGDG 17.12-1.pgdg13+1 image; VM Debian package 17.12-0+deb13u1 is not exercised"}
    try:
        with psycopg.connect(**options, autocommit=True) as connection:
            version = int(connection.execute("SHOW server_version_num").fetchone()[0])
            tls = connection.execute("SELECT ssl,version FROM pg_stat_ssl WHERE pid=pg_backend_pid()").fetchone()
            require(version == 170012 and tls[0] is True and tls[1] in {"TLSv1.2", "TLSv1.3"}, "wrong_disposable_server")
            require(revisions(connection) == {"auth_schema_migrations": None, "cloud_schema_migrations": None}, "fresh_database_required")
        result["checks"].append({"name": "fresh_PG17_verified_TLS", "status": "passed", "server_version_num": version, "tls": tls[1]})
        engine = client.migration_engine(options)
        try:
            with engine.connect() as connection:
                settings = {key: connection.execute(text("SELECT current_setting(:name)"), {"name": key}).scalar_one()
                            for key in ("statement_timeout", "lock_timeout", "search_path")}
                require(settings == {"statement_timeout": "15s", "lock_timeout": "3s", "search_path": "public"}, "migration_connection_deadlines_missing")
        finally:
            engine.dispose()
        result["checks"].append({"name": "actual_migration_factory_connections", "status": "passed", "settings": settings})
        result["checks"].append({"name": "AUTH_lock", **occupied_lock(options, 1837086401, {"auth_schema_migrations": None, "cloud_schema_migrations": None})})
        result["checks"].append({"name": "cloud_lock_after_AUTH_commit", **occupied_lock(options, 1837086402,
            {"auth_schema_migrations": ["auth01_0001", "auth02_0002"], "cloud_schema_migrations": None})})
        first, second = client.apply_migrations(options)
        require(first["status"] == "applied" and second["status"] == "current", "released_lock_migration_not_idempotent")
        with psycopg.connect(**options, autocommit=True) as connection:
            final = revisions(connection)
        require(final == {"auth_schema_migrations": ["auth01_0001", "auth02_0002"], "cloud_schema_migrations": ["cloud01_0001"]}, "final_revisions_wrong")
        result["checks"].append({"name": "explicit_lab_resume_after_owner_released_locks", "status": "passed", "first": first, "second": second, "revisions": final})
        result["status"] = "passed"
    except Exception as error:
        result["error_type"] = type(error).__name__
        result["native_sqlstates"] = sqlstates(error)
        # Only our fixed validation codes may be exposed, never DB exception text.
        if isinstance(error, ValueError) and len(error.args) == 1 and isinstance(error.args[0], str) and error.args[0].replace("_", "").isalnum():
            result["error_code"] = error.args[0]
    with Path(report_path).open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(result, stream, indent=2)
        stream.write("\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()
    return 0 if execute(args.report)["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
