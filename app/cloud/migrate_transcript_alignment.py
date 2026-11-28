"""Allow the transcript-alignment work in the existing fenced INT queue."""
from sqlalchemy import text

REVISION = "cloud_transcript_alignment_0001"
DDL = (
    "ALTER TABLE cloud_documents DROP CONSTRAINT cloud_documents_kind_check",
    """ALTER TABLE cloud_documents ADD CONSTRAINT cloud_documents_kind_check
       CHECK(kind IN ('job','export','draft','project','selection','alignment'))""",
    "ALTER TABLE cloud_tasks DROP CONSTRAINT cloud_tasks_kind_check",
    """ALTER TABLE cloud_tasks ADD CONSTRAINT cloud_tasks_kind_check
       CHECK(kind IN ('process','export','selection','delete','alignment'))""",
)


def upgrade_alignment(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_transcript_alignment_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = connection.execute(text(
        "SELECT revision FROM cloud_transcript_alignment_schema_migrations ORDER BY revision"
    )).scalars().all()
    if revisions == [REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown transcript alignment schema revision")
    # Avoid waiting on a creator transaction while holding one queue table.
    connection.execute(text("LOCK TABLE cloud_tasks, cloud_documents IN ACCESS EXCLUSIVE MODE NOWAIT"))
    for statement in DDL:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO cloud_transcript_alignment_schema_migrations(revision) VALUES (:r)"),
                       {"r": REVISION})
    return "applied"
