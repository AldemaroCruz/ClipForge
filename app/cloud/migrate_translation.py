"""Allow E02 queue rows without modifying older migration ledgers."""
from sqlalchemy import text

REVISION = "cloud_subtitle_translation_0001"
_SELECT = "SELECT revision FROM cloud_subtitle_translation_schema_migrations ORDER BY revision"
DDL = (
    "LOCK TABLE cloud_tasks, cloud_documents IN ACCESS EXCLUSIVE MODE NOWAIT",
    "ALTER TABLE cloud_documents DROP CONSTRAINT cloud_documents_kind_check",
    """ALTER TABLE cloud_documents ADD CONSTRAINT cloud_documents_kind_check CHECK(
       kind IN ('job','export','draft','project','selection','alignment','publication','publication_ai','translation_ai'))""",
    "ALTER TABLE cloud_tasks DROP CONSTRAINT cloud_tasks_kind_check",
    """ALTER TABLE cloud_tasks ADD CONSTRAINT cloud_tasks_kind_check CHECK(
       kind IN ('process','export','selection','delete','alignment','publication_ai','translation_ai'))""",
)


def upgrade_translation(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_subtitle_translation_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = connection.execute(text(_SELECT)).scalars().all()
    if revisions == [REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown cloud subtitle translation schema revision")
    for statement in DDL:
        connection.execute(text(statement))
    connection.execute(text("INSERT INTO cloud_subtitle_translation_schema_migrations(revision) VALUES (:r)"),
                       {"r": REVISION})
    return "applied"


def translation_schema_ready(connection):
    return connection.execute(text(_SELECT)).scalars().all() == [REVISION]
