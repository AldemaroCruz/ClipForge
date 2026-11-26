"""Add INT project deletion without changing the historical cloud ledgers."""

from sqlalchemy import text

REVISION = "cloud_delete01_0001"
PURGE_REVISION = "cloud_delete02_0001"

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

PURGE_DDL = (
    "ALTER TABLE cloud_project_deletions ADD COLUMN legacy_upload_until TIMESTAMPTZ",
    """ALTER TABLE cloud_project_deletions ADD COLUMN storage_blockers JSONB NOT NULL DEFAULT CAST('[]' AS jsonb)
       CHECK(jsonb_typeof(storage_blockers)='array')""",
    "ALTER TABLE cloud_project_deletions ADD COLUMN wait_for_publishers BOOLEAN NOT NULL DEFAULT false",
    "ALTER TABLE cloud_project_deletions ADD COLUMN purge_policy_ready BOOLEAN NOT NULL DEFAULT false",
)


def _revisions(connection):
    return connection.execute(text(
        "SELECT revision FROM cloud_deletion_schema_migrations ORDER BY revision"
    )).scalars().all()


def project_deletion_schema_ready(connection):
    return (_revisions(connection) == [REVISION] and connection.execute(text(
        "SELECT revision FROM cloud_deletion_purge_schema_migrations ORDER BY revision"
    )).scalars().all() == [PURGE_REVISION])


def upgrade_project_deletions(connection):
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_deletion_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    revisions = _revisions(connection)
    if revisions not in ([], [REVISION]):
        raise ValueError("Unknown cloud deletion schema revision")
    if not revisions:
        for statement in DDL:
            connection.execute(text(statement))
        connection.execute(text("INSERT INTO cloud_deletion_schema_migrations(revision) VALUES (:r)"),
                           {"r": REVISION})
    # Keep the previous health contract valid if the application rolls back.
    connection.execute(text("""CREATE TABLE IF NOT EXISTS cloud_deletion_purge_schema_migrations (
        revision VARCHAR(32) PRIMARY KEY,
        applied_at TIMESTAMPTZ NOT NULL DEFAULT clock_timestamp())"""))
    purge = connection.execute(text(
        "SELECT revision FROM cloud_deletion_purge_schema_migrations ORDER BY revision"
    )).scalars().all()
    if purge not in ([], [PURGE_REVISION]):
        raise ValueError("Unknown cloud deletion purge schema revision")
    if not purge:
        for statement in PURGE_DDL:
            connection.execute(text(statement))
        connection.execute(text("INSERT INTO cloud_deletion_purge_schema_migrations(revision) VALUES (:r)"),
                           {"r": PURGE_REVISION})
    _rearm_legacy(connection)
    return "applied" if not purge else "current"


def _rearm_legacy(connection):
    """Recognize only existing requests with a committed project tombstone."""
    connection.execute(text("""
        WITH prior AS (
          SELECT d.job_id, CASE WHEN doc.payload->'upload_tracking' IS DISTINCT FROM CAST('true' AS jsonb)
            AND jsonb_typeof(doc.payload->'upload_expires_at')='number'
            THEN CAST(doc.payload->>'upload_expires_at' AS numeric) ELSE NULL END AS expiry,
            p.deletion_started_at
          FROM cloud_project_deletions d JOIN auth_projects p ON p.id=d.job_id
          LEFT JOIN cloud_documents doc ON doc.job_id=d.job_id AND doc.kind='job' AND doc.id=d.job_id
          WHERE p.deletion_started_at IS NOT NULL AND d.state<>'deleted' AND NOT d.purge_policy_ready
        ), dates AS (
          SELECT job_id, CASE WHEN expiry>0 THEN
            to_timestamp(CAST(LEAST(expiry,extract(epoch FROM deletion_started_at)) AS double precision))
              + interval '7 days' ELSE NULL END AS deadline
          FROM prior
        )
        UPDATE cloud_project_deletions d SET state='deleting',retry_at=clock_timestamp(),
          legacy_upload_until=CASE WHEN dates.deadline>clock_timestamp() THEN dates.deadline ELSE NULL END
        FROM dates WHERE d.job_id=dates.job_id
        """))
    connection.execute(text("""
        INSERT INTO cloud_documents(job_id,kind,id,payload)
        SELECT d.job_id,'job',d.job_id,jsonb_build_object('id',d.job_id,'pilot',true,'status','deleted',
          'clips',CAST('[]' AS jsonb),'created_at',extract(epoch FROM p.created_at),'upload_tracking',false)
        FROM cloud_project_deletions d JOIN auth_projects p ON p.id=d.job_id
        WHERE p.deletion_started_at IS NOT NULL AND d.state<>'deleted' AND NOT d.purge_policy_ready
        ON CONFLICT (job_id,kind,id) DO NOTHING
        """))
    connection.execute(text("""
        INSERT INTO cloud_tasks(id,job_id,kind,item_id,status)
        SELECT replace(CAST(gen_random_uuid() AS text),'-',''),d.job_id,'delete',d.job_id,'queued'
        FROM cloud_project_deletions d JOIN auth_projects p ON p.id=d.job_id
        WHERE p.deletion_started_at IS NOT NULL AND d.state<>'deleted' AND NOT d.purge_policy_ready
        ON CONFLICT (job_id,kind,item_id) DO UPDATE
        SET status='queued',lease_until=NULL,fence=cloud_tasks.fence+1,updated_at=clock_timestamp()
        """))
    connection.execute(text("""
        INSERT INTO cloud_outbox(task_id)
        SELECT t.id FROM cloud_tasks t JOIN cloud_project_deletions d ON d.job_id=t.job_id
        JOIN auth_projects p ON p.id=d.job_id
        WHERE t.kind='delete' AND t.item_id=t.job_id AND p.deletion_started_at IS NOT NULL
            AND d.state<>'deleted' AND NOT d.purge_policy_ready
        ON CONFLICT (task_id) DO UPDATE SET dispatched_at=NULL,last_error=NULL,operation_name=NULL
        """))
    connection.execute(text("""
        UPDATE cloud_project_deletions d SET purge_policy_ready=true
        FROM auth_projects p WHERE p.id=d.job_id AND p.deletion_started_at IS NOT NULL
          AND d.state<>'deleted' AND NOT d.purge_policy_ready
        """))
