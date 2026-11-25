"""Add INT project deletion without changing the historical cloud ledgers."""

from sqlalchemy import text

REVISION = "cloud_delete01_0001"

DDL = (
    "ALTER TABLE auth_projects ADD COLUMN deletion_started_at TIMESTAMPTZ",
    "ALTER TABLE cloud_tasks DROP CONSTRAINT cloud_tasks_kind_check",
    """ALTER TABLE cloud_tasks ADD CONSTRAINT cloud_tasks_kind_check
       CHECK(kind IN ('process','export','selection','delete'))""",
    "ALTER TABLE cloud_tasks DROP CONSTRAINT cloud_tasks_status_check",
    """ALTER TABLE cloud_tasks ADD CONSTRAINT cloud_tasks_status_check
       CHECK(status IN ('queued','running','succeeded','failed','cancelled'))""",
    """CREATE TABLE cloud_project_deletions (
        job_id VARCHAR(32) PRIMARY KEY REFERENCES auth_projects(id),
        state VARCHAR(16) NOT NULL CHECK(state IN ('deleting','delete_error','deleted')),
        retry_at TIMESTAMPTZ NOT NULL,
        attempts BIGINT NOT NULL DEFAULT 0 CHECK(attempts >= 0),
        cancelled_queued BIGINT NOT NULL CHECK(cancelled_queued >= 0),
        cancelled_active BIGINT NOT NULL CHECK(cancelled_active >= 0),
        completed_at TIMESTAMPTZ,
        CHECK ((state = 'deleted') = (completed_at IS NOT NULL))
    )""",
    # A resumable URL is a short-lived upload capability. Keep it private and
    # only while the incomplete upload might need project-scoped cancellation.
    """CREATE TABLE cloud_upload_sessions (
        job_id VARCHAR(32) PRIMARY KEY REFERENCES auth_projects(id),
        url TEXT NOT NULL CHECK(char_length(url) BETWEEN 1 AND 4096)
    )""",
    """CREATE TABLE cloud_deleted_selection_calls (
        day_utc DATE PRIMARY KEY,
        planned BIGINT NOT NULL CHECK(planned > 0)
    )""",
)


def _revisions(connection):
    return connection.execute(text(
        "SELECT revision FROM cloud_deletion_schema_migrations ORDER BY revision"
    )).scalars().all()


def project_deletion_schema_ready(connection):
    return _revisions(connection) == [REVISION]


def upgrade_project_deletions(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_deletion_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = _revisions(connection)
    if revisions == [REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown cloud deletion schema revision")
    for statement in DDL:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO cloud_deletion_schema_migrations(revision) VALUES (:r)"),
                       {"r": REVISION})
    return "applied"
