"""Owner-scoped logical removal and fenced cleanup of INT project contents."""

from contextlib import contextmanager
import math
import re
from time import time

from fastapi import HTTPException
from sqlalchemy import text

from ..auth_db import get_engine
from . import repository as repo
from . import storage

UPLOAD_CAPABILITY_SECONDS = 7 * 24 * 60 * 60


def _owned(connection, principal, job_id):
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise HTTPException(404, "Proyecto no encontrado")
    repo.check_active_workspace(connection, principal)
    owned = connection.execute(text("""
        SELECT p.deletion_started_at FROM auth_projects p
        WHERE p.id=:j AND p.owner_id=:o AND p.workspace_id=:w
        FOR UPDATE OF p
        """), {"j": job_id, "o": principal.id, "w": principal.workspace_id}).mappings().first()
    if owned is None:
        raise HTTPException(404, "Proyecto no encontrado")
    return owned


def _public(job_id, row):
    if row is None:
        return None
    response = {"id": job_id, "status": row["state"], "retryable": row["state"] == "delete_error",
                "attempts": row["attempts"], "cancelled_queued": row["cancelled_queued"],
                "cancelled_active": row["cancelled_active"]}
    if row["state"] != "deleted" and row["retry_at"].timestamp() > time():
        response["retry_at"] = row["retry_at"].timestamp()
    return response


def public_status(job_id, connection=None):
    if connection is None:
        with get_engine().connect() as connection:
            return public_status(job_id, connection)
    row = connection.execute(text("""
        SELECT state,retry_at,attempts,cancelled_queued,cancelled_active
        FROM cloud_project_deletions WHERE job_id=:j
        """), {"j": job_id}).mappings().first()
    return _public(job_id, row)


def status(principal, job_id):
    with get_engine().begin() as connection:
        owned = _owned(connection, principal, job_id)
        if owned["deletion_started_at"] is None:
            raise HTTPException(404, "No hay una eliminación solicitada")
        return public_status(job_id, connection)


def deferred_tasks(connection):
    """The queue can wake other projects while this cleanup waits."""
    return connection.execute(text("""
        SELECT t.id FROM cloud_tasks t JOIN cloud_project_deletions d ON d.job_id=t.job_id
        WHERE t.status='queued' AND t.kind='delete'
          AND (d.retry_at>clock_timestamp() OR EXISTS (
              SELECT 1 FROM cloud_tasks cancelled
              WHERE cancelled.job_id=t.job_id AND cancelled.status='cancelled'
                AND cancelled.lease_until>clock_timestamp()))
        """)).scalars().all()


def _legacy_expiration(payload):
    if payload.get("upload_tracking") is True:
        return None
    deadline = payload.get("upload_expires_at")
    if type(deadline) not in {int, float} or not math.isfinite(deadline):
        deadline = time()
    # Older reservations didn't retain GCS capabilities. They stop at the
    # server upload deadline and are unusable after GCS's one-week expiry.
    return deadline + UPLOAD_CAPABILITY_SECONDS


def begin(principal, job_id):
    """Tombstone once and fence queued and active work in the same transaction."""
    with get_engine().begin() as connection:
        owned = _owned(connection, principal, job_id)
        if owned["deletion_started_at"] is not None:
            return public_status(job_id, connection)
        doc = repo.document(job_id, connection=connection)
        if doc["payload"].get("pilot") is not True:
            raise HTTPException(404, "Proyecto no encontrado")
        connection.execute(text("""
            UPDATE auth_projects SET deletion_started_at=clock_timestamp() WHERE id=:j
            """), {"j": job_id})
        # The Cloud Run supervisor owns the process group it started and will
        # acknowledge its termination. For a lost supervisor, allow the max
        # Cloud Run task lifetime plus a bounded grace period before sweeping.
        queued, active = connection.execute(text("""
            WITH targets AS (
                SELECT id,status FROM cloud_tasks
                WHERE job_id=:j AND status IN ('queued','running') ORDER BY id FOR UPDATE
            ), fenced AS (
                UPDATE cloud_tasks t SET status='cancelled', fence=t.fence+1,
                    lease_until=CASE WHEN targets.status='running'
                        THEN clock_timestamp()+interval '22 minutes' ELSE NULL END,
                    updated_at=clock_timestamp()
                FROM targets WHERE t.id=targets.id RETURNING targets.status
            )
            SELECT count(*) FILTER (WHERE status='queued'),count(*) FILTER (WHERE status='running')
            FROM fenced
            """), {"j": job_id}).one()
        connection.execute(text("""
            UPDATE cloud_documents SET payload=payload || CAST(:p AS jsonb),
                revision=revision+1,updated_at=clock_timestamp()
            WHERE job_id=:j AND kind='job' AND id=:j
            """), {"j": job_id, "p": repo.packed({"status": "deleting", "clips": []})})
        connection.execute(text("""
            INSERT INTO cloud_project_deletions(job_id,state,retry_at,cancelled_queued,cancelled_active)
            VALUES (:j,'deleting',GREATEST(clock_timestamp(),to_timestamp(CAST(:wait AS double precision))),:q,:a)
            """), {"j": job_id, "wait": _legacy_expiration(doc["payload"]), "q": queued, "a": active})
        repo.enqueue(connection, job_id, "delete", job_id)
        return public_status(job_id, connection)


@contextmanager
def publication(task):
    """Serialize each storage upload against the project's deletion marker."""
    with get_engine().begin() as connection:
        active = connection.execute(text("""
            SELECT id FROM auth_projects WHERE id=:j AND deletion_started_at IS NULL FOR SHARE
            """), {"j": task["job_id"]}).scalar()
        valid = connection.execute(text("""
            SELECT EXISTS (SELECT 1 FROM cloud_tasks WHERE id=:i AND job_id=:j
                           AND status='running' AND fence=:f AND lease_until>clock_timestamp())
            """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]}).scalar_one()
        if active is None or not valid:
            raise RuntimeError("Project or task lease no longer permits publication")
        yield


def ack_stopped(task):
    """Release exactly the canceled task slot after its child has stopped."""
    with get_engine().begin() as connection:
        result = connection.execute(text("""
            UPDATE cloud_tasks SET lease_until=NULL,updated_at=clock_timestamp()
            WHERE id=:i AND job_id=:j AND status='cancelled' AND fence=:f+1
            """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]})
        return result.rowcount == 1


def release_expired(task, connection):
    """Persist the retry after a worker crash or a transient cleanup failure."""
    requeued = connection.execute(text("""
        UPDATE cloud_tasks SET status='queued',lease_until=NULL,
            updated_at=clock_timestamp()
        WHERE id=:i AND job_id=:j AND kind='delete' AND status='running' AND fence=:f
        RETURNING id
        """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]}).scalar()
    if requeued is None:
        return
    connection.execute(text("""
        UPDATE cloud_project_deletions SET state='delete_error',attempts=attempts+1,
            retry_at=clock_timestamp()+LEAST((1+attempts)*interval '15 seconds',interval '5 minutes')
        WHERE job_id=:j AND state<>'deleted'
        """), {"j": task["job_id"]})
    connection.execute(text("""
        UPDATE cloud_outbox SET dispatched_at=NULL,last_error=NULL,operation_name=NULL
        WHERE task_id=:i
        """), {"i": task["id"]})


def _scope(connection, task):
    if task["kind"] != "delete" or task["item_id"] != task["job_id"]:
        raise RuntimeError("Invalid project cleanup task")
    job_id = task["job_id"]
    workspace = connection.execute(text("""
        SELECT p.workspace_id FROM auth_projects p
        JOIN cloud_project_deletions d ON d.job_id=p.id
        WHERE p.id=:j AND p.deletion_started_at IS NOT NULL
          AND d.state<>'deleted' AND d.retry_at<=clock_timestamp()
          AND NOT EXISTS (
              SELECT 1 FROM cloud_tasks t
              WHERE t.job_id=p.id AND t.status='cancelled' AND t.lease_until>clock_timestamp())
        FOR UPDATE OF p
        """), {"j": job_id}).scalar()
    if workspace is None:
        raise RuntimeError("Project cleanup is not ready")
    repo.worker_guard(connection, task)
    name = storage.beta_original(workspace, job_id)
    return name.removesuffix("original/input.mp4"), name


def _purge(connection, task):
    job_id = task["job_id"]
    _scope(connection, task)
    connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": repo.BETA_ADMISSION_LOCK})
    connection.execute(text("""
        INSERT INTO cloud_deleted_selection_calls(day_utc,planned)
        SELECT CAST(payload->>'day_utc' AS date),
            sum(CAST(payload->>'provider_calls_planned' AS integer))
        FROM cloud_documents
        WHERE job_id=:j AND kind='selection'
        GROUP BY CAST(payload->>'day_utc' AS date)
        ON CONFLICT (day_utc) DO UPDATE SET
            planned=cloud_deleted_selection_calls.planned+EXCLUDED.planned
        """), {"j": job_id})
    connection.execute(text("DELETE FROM cloud_feedback WHERE job_id=:j"), {"j": job_id})
    connection.execute(text("DELETE FROM cloud_documents WHERE job_id=:j"), {"j": job_id})
    connection.execute(text("""
        DELETE FROM cloud_outbox WHERE task_id IN (SELECT id FROM cloud_tasks WHERE job_id=:j)
        """), {"j": job_id})
    connection.execute(text("DELETE FROM cloud_tasks WHERE job_id=:j AND id<>:i"),
                       {"j": job_id, "i": task["id"]})
    connection.execute(text("""
        UPDATE cloud_tasks SET status='succeeded',lease_until=NULL,updated_at=clock_timestamp()
        WHERE id=:i AND job_id=:j AND fence=:f
        """), {"i": task["id"], "j": job_id, "f": task["fence"]})
    # Ownership and request keys are retained without project content so that
    # repeated confirmations remain authorized and cannot replay old uploads.
    connection.execute(text("""
        UPDATE cloud_project_deletions SET state='deleted',completed_at=clock_timestamp()
        WHERE job_id=:j
        """), {"j": job_id})


def _upload_consumed(name):
    try:
        return storage.beta_original_metadata(name) is not None
    except storage.InvalidUpload:
        # Invalid uploaded data is still an object and belongs in the sweep.
        return True


def execute(task):
    """Cancel any browser capability, sweep live generations and then scrub PG."""
    job_id = task["job_id"]
    with get_engine().begin() as connection:
        prefix, name = _scope(connection, task)
        session = connection.execute(text("SELECT url FROM cloud_upload_sessions WHERE job_id=:j"),
                                     {"j": job_id}).scalar()
        tracking = repo.document(job_id, connection=connection)["payload"].get("upload_tracking") is True
    try:
        if session:
            # A newly tracked project exposes only one usable URI at a time.
            # Its published create-only object proves that URI was consumed.
            if not (tracking and _upload_consumed(name)):
                storage.cancel_resumable(session, name)
            with get_engine().begin() as connection:
                _scope(connection, task)
                connection.execute(text("DELETE FROM cloud_upload_sessions WHERE job_id=:j"), {"j": job_id})
        for item in storage.list_project_live(prefix):
            storage.delete_project_live(item, prefix)
        if storage.list_project_live(prefix):
            raise storage.StorageError("Project still has live objects")
    except storage.StorageError:
        with get_engine().begin() as connection:
            release_expired(task, connection)
        return
    with get_engine().begin() as connection:
        _purge(connection, task)
