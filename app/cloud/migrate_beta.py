"""Apply Hito B tables alongside the frozen Hito A migration ledger."""
import json

from sqlalchemy import text

from ..auth_db import get_engine
from .migrate import upgrade as upgrade_base

BETA_REVISION = "cloud_beta01_0001"
BETA_DDL = (
    """CREATE TABLE cloud_feedback (
        id VARCHAR(32) PRIMARY KEY,
        user_id VARCHAR(32) NOT NULL REFERENCES auth_users(id),
        category VARCHAR(16) NOT NULL CHECK(category IN ('error','suggestion','quality')),
        comment TEXT NOT NULL CHECK(char_length(comment) BETWEEN 1 AND 2000),
        job_id VARCHAR(32) REFERENCES auth_projects(id),
        clip_file VARCHAR(16) CHECK(clip_file ~ '^clip_[0-9]{2}[.]mp4$'),
        useful BOOLEAN, publishable BOOLEAN,
        error_code VARCHAR(32) CHECK(error_code ~ '^[A-Z_]{1,32}$'),
        application_revision VARCHAR(40) NOT NULL CHECK(application_revision ~ '^[0-9a-f]{40}$'),
        created_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp(),
        CHECK (clip_file IS NULL OR job_id IS NOT NULL),
        CHECK (clip_file IS NOT NULL OR (useful IS NULL AND publishable IS NULL)),
        CHECK (error_code IS NULL OR job_id IS NOT NULL))""",
    "CREATE INDEX cloud_feedback_recent_idx ON cloud_feedback(created_at DESC,id DESC)",
    "CREATE INDEX cloud_feedback_user_idx ON cloud_feedback(user_id,created_at DESC,id DESC)",
)


def upgrade_beta(engine=None):
    engine = engine or get_engine()
    upgrade_base(engine)
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(1837086402)"))
        # The Hito A health route requires exactly [cloud01_0001] in its ledger.
        connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_beta_schema_migrations (
            revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
        revisions = connection.execute(text("SELECT revision FROM cloud_beta_schema_migrations ORDER BY revision")).scalars().all()
        if revisions == [BETA_REVISION]:
            return {"status": "current", "revision": BETA_REVISION}
        if revisions:
            raise ValueError("Unknown cloud beta schema revision")
        for statement in BETA_DDL:
            connection.execute(text(statement))
        connection.execute(text("INSERT INTO cloud_beta_schema_migrations(revision) VALUES (:r)"), {"r": BETA_REVISION})
    return {"status": "applied", "revision": BETA_REVISION}


def beta_schema_ready(connection):
    revisions = connection.execute(text("SELECT revision FROM cloud_beta_schema_migrations ORDER BY revision")).scalars().all()
    return revisions == [BETA_REVISION]


def main():
    try:
        print(json.dumps(upgrade_beta()))
        return 0
    except Exception:
        print(json.dumps({"status": "failed", "message": "Creator beta migration failed."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
