"""Keep E01 preset settings readable independently of older style validators."""
from sqlalchemy import text

REVISION = "cloud_caption_highlight_0001"
_SELECT = "SELECT revision FROM cloud_caption_highlight_schema_migrations ORDER BY revision"


def upgrade_caption_highlight(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_caption_highlight_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = connection.execute(text(_SELECT)).scalars().all()
    if revisions == [REVISION]:
        return "current"
    if revisions:
        raise ValueError("Unknown cloud caption highlight schema revision")
    connection.execute(text("""ALTER TABLE cloud_caption_styles ADD COLUMN style_highlight JSONB
        CHECK(style_highlight IS NULL OR jsonb_typeof(style_highlight) = 'object')"""))
    connection.execute(text("INSERT INTO cloud_caption_highlight_schema_migrations(revision) VALUES (:r)"),
                       {"r": REVISION})
    return "applied"


def caption_highlight_schema_ready(connection):
    return connection.execute(text(_SELECT)).scalars().all() == [REVISION]
