"""Separate additive cloud revision; historical AUTH migrations stay frozen."""
import json
from sqlalchemy import text
from ..auth_db import get_engine
from ..auth_migrations import upgrade as upgrade_auth

REVISION = "cloud01_0001"
DDL = (
    """CREATE TABLE cloud_documents (
        job_id VARCHAR(32) NOT NULL REFERENCES auth_projects(id),
        kind VARCHAR(16) NOT NULL CHECK(kind IN ('job','export','draft','project')),
        id VARCHAR(32) NOT NULL, revision BIGINT NOT NULL DEFAULT 1 CHECK(revision > 0),
        payload JSONB NOT NULL, manifest JSONB NOT NULL DEFAULT '{}'::jsonb,
        updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        PRIMARY KEY(job_id,kind,id))""",
    """CREATE TABLE cloud_tasks (
        id VARCHAR(32) PRIMARY KEY, job_id VARCHAR(32) NOT NULL REFERENCES auth_projects(id),
        kind VARCHAR(16) NOT NULL CHECK(kind IN ('process','export')), item_id VARCHAR(32) NOT NULL,
        status VARCHAR(16) NOT NULL CHECK(status IN ('queued','running','succeeded','failed')),
        fence BIGINT NOT NULL DEFAULT 0, lease_until TIMESTAMPTZ, cleaned_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        UNIQUE(job_id,kind,item_id))""",
    "CREATE INDEX cloud_tasks_queue_idx ON cloud_tasks(status,created_at,id)",
    """CREATE TABLE cloud_outbox (
        task_id VARCHAR(32) PRIMARY KEY REFERENCES cloud_tasks(id),
        dispatched_at TIMESTAMPTZ, attempts INTEGER NOT NULL DEFAULT 0,
        last_error VARCHAR(64), operation_name VARCHAR(255))""",
    """CREATE TABLE cloud_requests (
        owner_id VARCHAR(32) NOT NULL REFERENCES auth_users(id),
        request_key VARCHAR(64) NOT NULL, fingerprint VARCHAR(64) NOT NULL,
        job_id VARCHAR(32) NOT NULL REFERENCES auth_projects(id),
        kind VARCHAR(16) NOT NULL, item_id VARCHAR(32) NOT NULL,
        PRIMARY KEY(owner_id,request_key))""",
)


def upgrade(engine=None):
    engine = engine or get_engine()
    upgrade_auth(engine)
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(1837086402)"))
        connection.execute(text("CREATE TABLE IF NOT EXISTS cloud_schema_migrations (revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"))
        revisions = connection.execute(text("SELECT revision FROM cloud_schema_migrations ORDER BY revision")).scalars().all()
        if revisions == [REVISION]:
            return {"status": "current", "revision": REVISION}
        if revisions:
            raise ValueError("Unknown cloud schema revision")
        for statement in DDL:
            connection.execute(text(statement))
        connection.execute(text("INSERT INTO cloud_schema_migrations(revision) VALUES (:r)"), {"r": REVISION})
    return {"status": "applied", "revision": REVISION}


def main():
    try:
        print(json.dumps(upgrade()))
        return 0
    except Exception:
        print(json.dumps({"status": "failed", "message": "Cloud migration failed; transaction rolled back."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
