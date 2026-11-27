"""Apply Hito B tables alongside the frozen Hito A migration ledger."""
import json

from sqlalchemy import text

from ..auth_db import get_engine
from .migrate import upgrade as upgrade_base
from .migrate_project_deletions import REVISION as DELETION_REVISION, upgrade_project_deletions

BETA_REVISION = "cloud_beta01_0001"
EDITORIAL_REVISION = "cloud_editorial01_0001"
STYLES_REVISION = "cloud_caption_styles_0001"
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
EDITORIAL_DDL = (
    "ALTER TABLE cloud_documents DROP CONSTRAINT cloud_documents_kind_check",
    """ALTER TABLE cloud_documents ADD CONSTRAINT cloud_documents_kind_check
       CHECK(kind IN ('job','export','draft','project','selection'))""",
    "ALTER TABLE cloud_tasks DROP CONSTRAINT cloud_tasks_kind_check",
    """ALTER TABLE cloud_tasks ADD CONSTRAINT cloud_tasks_kind_check
       CHECK(kind IN ('process','export','selection'))""",
    """CREATE INDEX cloud_selections_day_idx ON cloud_documents ((payload->>'day_utc'))
       WHERE kind='selection'""",
)
STYLES_DDL = (
    """CREATE TABLE cloud_caption_styles (
        id VARCHAR(32) PRIMARY KEY CHECK(id ~ '^[0-9a-f]{32}$'),
        owner_id VARCHAR(32) NOT NULL REFERENCES auth_users(id),
        name VARCHAR(80) NOT NULL CHECK(char_length(name) >= 1),
        name_key TEXT NOT NULL,
        font VARCHAR(32) NOT NULL CHECK(font = 'DejaVu Sans Bold'),
        style JSONB NOT NULL CHECK(jsonb_typeof(style) = 'object'),
        revision INTEGER NOT NULL DEFAULT 1 CHECK(revision >= 1),
        is_default BOOLEAN NOT NULL DEFAULT false,
        UNIQUE(owner_id,name_key))""",
    """CREATE UNIQUE INDEX cloud_caption_styles_default_idx
       ON cloud_caption_styles(owner_id) WHERE is_default""",
)


def upgrade_editorial(connection):
    # Separate ledger keeps the previous beta revision healthy on rollback.
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_editorial_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = connection.execute(text("SELECT revision FROM cloud_editorial_schema_migrations ORDER BY revision")).scalars().all()
    if revisions == [EDITORIAL_REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown cloud editorial schema revision")
    for statement in EDITORIAL_DDL:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO cloud_editorial_schema_migrations(revision) VALUES (:r)"),
                       {"r": EDITORIAL_REVISION})
    return "applied"


def upgrade_styles(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_caption_style_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = connection.execute(text(
        "SELECT revision FROM cloud_caption_style_schema_migrations ORDER BY revision"
    )).scalars().all()
    if revisions == [STYLES_REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown cloud caption styles schema revision")
    for statement in STYLES_DDL:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO cloud_caption_style_schema_migrations(revision) VALUES (:r)"),
                       {"r": STYLES_REVISION})
    return "applied"


def upgrade_beta(engine=None):
    engine = engine or get_engine()
    upgrade_base(engine)
    with engine.begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock(1837086402)"))
        # The Hito A health route requires exactly [cloud01_0001] in its ledger.
        connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_beta_schema_migrations (
            revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
        revisions = connection.execute(text("SELECT revision FROM cloud_beta_schema_migrations ORDER BY revision")).scalars().all()
        if revisions and revisions != [BETA_REVISION]:
            raise ValueError("Unknown cloud beta schema revision")
        if not revisions:
            for statement in BETA_DDL:
                connection.execute(text(statement))
            connection.execute(text("INSERT INTO cloud_beta_schema_migrations(revision) VALUES (:r)"), {"r": BETA_REVISION})
        editorial = upgrade_editorial(connection)
        deletion = upgrade_project_deletions(connection)
        styles = upgrade_styles(connection)
    return {"status": "applied" if not revisions else "current", "revision": BETA_REVISION,
            "editorial_status": editorial, "editorial_revision": EDITORIAL_REVISION,
            "deletion_status": deletion, "deletion_revision": DELETION_REVISION,
            "styles_status": styles, "styles_revision": STYLES_REVISION}


def beta_schema_ready(connection):
    revisions = connection.execute(text("SELECT revision FROM cloud_beta_schema_migrations ORDER BY revision")).scalars().all()
    return revisions == [BETA_REVISION]


def editorial_schema_ready(connection):
    revisions = connection.execute(text("SELECT revision FROM cloud_editorial_schema_migrations ORDER BY revision")).scalars().all()
    return revisions == [EDITORIAL_REVISION]


def styles_schema_ready(connection):
    revisions = connection.execute(text(
        "SELECT revision FROM cloud_caption_style_schema_migrations ORDER BY revision"
    )).scalars().all()
    return revisions == [STYLES_REVISION]


def main():
    try:
        print(json.dumps(upgrade_beta()))
        return 0
    except Exception:
        print(json.dumps({"status": "failed", "message": "Creator beta migration failed."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
