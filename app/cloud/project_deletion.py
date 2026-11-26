"""Owner-scoped logical removal and fenced cleanup of INT project contents."""

from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import math
import re

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


def public_status(job_id, connection=None):
    if connection is None:
        with get_engine().connect() as connection:
            return public_status(job_id, connection)
    exists = connection.execute(text("SELECT job_id FROM cloud_project_deletions WHERE job_id=:j"),
                                {"j": job_id}).scalar()
    return {"id": job_id, "status": "deleted"} if exists is not None else None


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
          AND d.retry_at>clock_timestamp()
        """)).scalars().all()


def _legacy_expiration(payload, started):
    if payload.get("upload_tracking") is True:
        return None
    deadline = payload.get("upload_expires_at")
    if type(deadline) not in {int, float} or not math.isfinite(deadline) or deadline <= 0:
        return None
    # Unknown capabilities could have been opened only before the upload
    # deadline and before the tombstone. The first sweep runs immediately.
    expiry = min(deadline, started.timestamp()) + UPLOAD_CAPABILITY_SECONDS
    return datetime.fromtimestamp(expiry, timezone.utc) if expiry > started.timestamp() else None


def begin(principal, job_id, *, include_created=False):
    """Tombstone once and fence queued and active work in the same transaction."""
    with get_engine().begin() as connection:
        owned = _owned(connection, principal, job_id)
        if owned["deletion_started_at"] is not None:
            item = public_status(job_id, connection)
            return (item, False) if include_created else item
        doc = repo.document(job_id, connection=connection)
        if doc["payload"].get("pilot") is not True:
            raise HTTPException(404, "Proyecto no encontrado")
        started = connection.execute(text("""
            UPDATE auth_projects SET deletion_started_at=clock_timestamp() WHERE id=:j
            RETURNING deletion_started_at
            """), {"j": job_id}).scalar_one()
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
            INSERT INTO cloud_project_deletions(
                job_id,state,retry_at,legacy_upload_until,cancelled_queued,cancelled_active,purge_policy_ready)
            VALUES (:j,'deleting',clock_timestamp(),:until,:q,:a,true)
            """), {"j": job_id, "until": _legacy_expiration(doc["payload"], started), "q": queued, "a": active})
        _scrub(connection, job_id)
        repo.enqueue(connection, job_id, "delete", job_id)
        item = {"id": job_id, "status": "deleted"}
        return (item, True) if include_created else item


@contextmanager
def publication(task):
    """Track an in-flight upload without making a tombstone wait on GCS."""
    with get_engine().begin() as connection:
        connection.execute(text("SELECT pg_advisory_xact_lock_shared(:first,:second)"),
                           _publication_key(task["job_id"]))
        active = connection.execute(text("""
            SELECT id FROM auth_projects WHERE id=:j AND deletion_started_at IS NULL
            """), {"j": task["job_id"]}).scalar()
        valid = connection.execute(text("""
            SELECT EXISTS (SELECT 1 FROM cloud_tasks WHERE id=:i AND job_id=:j
                           AND status='running' AND fence=:f AND lease_until>clock_timestamp())
            """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]}).scalar_one()
        if active is None or not valid:
            raise RuntimeError("Project or task lease no longer permits publication")
        yield


def _publication_key(job_id):
    identity = bytes.fromhex(job_id)
    return {"first": int.from_bytes(identity[:4], "big", signed=True),
            "second": int.from_bytes(identity[4:8], "big", signed=True)}


def _publisher_retry(connection, job_id, now):
    cancelled = connection.execute(text("""
        SELECT max(lease_until) FROM cloud_tasks
        WHERE job_id=:j AND status='cancelled' AND lease_until>clock_timestamp()
        """), {"j": job_id}).scalar_one()
    if cancelled is not None:
        return cancelled
    idle = connection.execute(text("SELECT pg_try_advisory_xact_lock(:first,:second)"),
                              _publication_key(job_id)).scalar_one()
    return None if idle else now + timedelta(minutes=1)


def ack_stopped(task):
    """Release exactly the canceled task slot after its child has stopped."""
    with get_engine().begin() as connection:
        connection.execute(text("SELECT id FROM auth_projects WHERE id=:j FOR UPDATE"), {"j": task["job_id"]})
        result = connection.execute(text("""
            UPDATE cloud_tasks SET lease_until=NULL,updated_at=clock_timestamp()
            WHERE id=:i AND job_id=:j AND status='cancelled' AND fence=:f+1
            """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]})
        if result.rowcount == 1:
            connection.execute(text("""
                UPDATE cloud_project_deletions SET retry_at=LEAST(retry_at,clock_timestamp())
                WHERE job_id=:j AND wait_for_publishers AND state<>'deleted'
                  AND NOT EXISTS (
                    SELECT 1 FROM cloud_tasks WHERE job_id=:j AND status='cancelled'
                      AND lease_until>clock_timestamp())
                """), {"j": task["job_id"]})
            _trim_stopped(connection, task["job_id"])
        return result.rowcount == 1


def _requeue(connection, task):
    requeued = connection.execute(text("""
        UPDATE cloud_tasks SET status='queued',lease_until=NULL,
            updated_at=clock_timestamp()
        WHERE id=:i AND job_id=:j AND kind='delete' AND status='running' AND fence=:f
        RETURNING id
        """), {"i": task["id"], "j": task["job_id"], "f": task["fence"]}).scalar()
    if requeued is None:
        return False
    connection.execute(text("""
        UPDATE cloud_outbox SET dispatched_at=NULL,last_error=NULL,operation_name=NULL
        WHERE task_id=:i
        """), {"i": task["id"]})
    return True


def release_expired(task, connection):
    """Persist the retry after a worker crash or a transient cleanup failure."""
    if _requeue(connection, task):
        connection.execute(text("""
            UPDATE cloud_project_deletions SET state='delete_error',attempts=attempts+1,
                retry_at=clock_timestamp()+LEAST((1+attempts)*interval '15 seconds',interval '5 minutes')
            WHERE job_id=:j AND state<>'deleted'
            """), {"j": task["job_id"]})


def _scope(connection, task):
    if task["kind"] != "delete" or task["item_id"] != task["job_id"]:
        raise RuntimeError("Invalid project cleanup task")
    job_id = task["job_id"]
    workspace = connection.execute(text("""
        SELECT p.workspace_id FROM auth_projects p
        JOIN cloud_project_deletions d ON d.job_id=p.id
        WHERE p.id=:j AND p.deletion_started_at IS NOT NULL
          AND d.state<>'deleted' AND d.retry_at<=clock_timestamp()
        FOR UPDATE OF p
        """), {"j": job_id}).scalar()
    if workspace is None:
        raise RuntimeError("Project cleanup is not ready")
    repo.worker_guard(connection, task)
    name = storage.beta_original(workspace, job_id)
    return name.removesuffix("original/input.mp4"), name


def _scrub(connection, job_id):
    """Retire project data while preserving AI budget and the cleanup profile."""
    connection.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": repo.BETA_ADMISSION_LOCK})
    connection.execute(text("""
        INSERT INTO cloud_deleted_selection_calls(day_utc,planned)
        SELECT CAST(payload->>'day_utc' AS date),
            sum(CAST(payload->>'provider_calls_planned' AS integer))
        FROM cloud_documents
        WHERE job_id=:j AND kind='selection'
        GROUP BY CAST(payload->>'day_utc' AS date)
        HAVING sum(CAST(payload->>'provider_calls_planned' AS integer))>0
        ON CONFLICT (day_utc) DO UPDATE SET
            planned=cloud_deleted_selection_calls.planned+EXCLUDED.planned
        """), {"j": job_id})
    connection.execute(text("DELETE FROM cloud_feedback WHERE job_id=:j"), {"j": job_id})
    connection.execute(text("""
        DELETE FROM cloud_documents WHERE job_id=:j AND (kind<>'job' OR id<>:j)
        """), {"j": job_id})
    connection.execute(text("""
        UPDATE cloud_documents d SET manifest=CAST('{}' AS jsonb),
            payload=jsonb_build_object('id',CAST(:j AS text),'pilot',true,'status','deleted',
              'clips',CAST('[]' AS jsonb),'created_at',extract(epoch FROM p.created_at),
              'upload_tracking',COALESCE(d.payload->'upload_tracking'=CAST('true' AS jsonb),false)),
            revision=d.revision+1,updated_at=clock_timestamp()
        FROM auth_projects p WHERE p.id=d.job_id AND d.job_id=:j AND d.kind='job' AND d.id=:j
        """), {"j": job_id})


def _trim_stopped(connection, job_id):
    # Keep live cancellation leases and their outbox rows until the supervisor
    # acknowledges or the lease expires. Admission still counts those leases.
    connection.execute(text("""
        WITH removable AS (
            SELECT t.id FROM cloud_tasks t JOIN cloud_project_deletions d ON d.job_id=t.job_id
            JOIN auth_projects p ON p.id=t.job_id
            WHERE t.job_id=:j AND t.kind<>'delete' AND p.deletion_started_at IS NOT NULL
              AND (t.status IN ('succeeded','failed') OR (t.status='cancelled'
                AND (t.lease_until IS NULL OR t.lease_until<=clock_timestamp())))
            FOR UPDATE OF t
        ), outboxes AS (
            DELETE FROM cloud_outbox WHERE task_id IN (SELECT id FROM removable)
        )
        DELETE FROM cloud_tasks WHERE id IN (SELECT id FROM removable)
        """), {"j": job_id})


def _purge(connection, task):
    job_id = task["job_id"]
    connection.execute(text("DELETE FROM cloud_documents WHERE job_id=:j"), {"j": job_id})
    connection.execute(text("DELETE FROM cloud_outbox WHERE task_id=:i"), {"i": task["id"]})
    connection.execute(text("""
        UPDATE cloud_tasks SET status='succeeded',lease_until=NULL,updated_at=clock_timestamp()
        WHERE id=:i AND job_id=:j AND fence=:f
        """), {"i": task["id"], "j": job_id, "f": task["fence"]})
    # Ownership and request keys are retained without project content so that
    # repeated confirmations remain authorized and cannot replay old uploads.
    connection.execute(text("""
        UPDATE cloud_project_deletions SET state='deleted',completed_at=clock_timestamp(),
          legacy_upload_until=NULL,storage_blockers=CAST('[]' AS jsonb),wait_for_publishers=false
        WHERE job_id=:j
        """), {"j": job_id})
    _trim_stopped(connection, job_id)


def _upload_consumed(name):
    try:
        return storage.beta_original_metadata(name) is not None
    except storage.InvalidUpload:
        # Invalid uploaded data is still an object and belongs in the sweep.
        return True


def _sweep(prefix, now):
    # Independently attempt every removable generation, even on partial failure.
    for item in storage.list_project_generations(prefix):
        try:
            if storage.project_generation_blocker(item, now) is None:
                storage.delete_project_generation(item, prefix)
        except storage.StorageError:
            continue

    pending = []
    incomplete = False
    for item in storage.list_project_generations(prefix):
        restriction = storage.project_generation_blocker(item, now)
        if restriction is None:
            incomplete = True
        else:
            pending.append((item, *restriction))
    for item in storage.list_project_soft_deleted(prefix):
        pending.append((item, "soft_delete", storage.project_soft_delete_time(item)))
    return pending, incomplete


def _save_object_blockers(connection, job_id, pending):
    inventory = [{"name": item["name"], "generation": item["generation"],
                  "reason": reason, "until": until.isoformat() if until is not None else None}
                 for item, reason, until in pending]
    connection.execute(text("""
        UPDATE cloud_project_deletions SET storage_blockers=CAST(:blockers AS jsonb)
        WHERE job_id=:j
        """), {"j": job_id, "blockers": repo.packed(inventory)})


def _finish_sweep(connection, task, pending, final_sweep, now):
    job_id = task["job_id"]
    legacy = connection.execute(text("""
        SELECT legacy_upload_until FROM cloud_project_deletions WHERE job_id=:j
        """), {"j": job_id}).scalar()
    deadlines = [until for _, _, until in pending if until is not None and until > now]
    if any(until is None for _, _, until in pending):
        deadlines.append(now + timedelta(hours=1))
    if any(until is not None and until <= now for _, _, until in pending):
        deadlines.append(now + timedelta(minutes=5))
    if legacy is not None and legacy > now:
        deadlines.append(legacy)
    if not final_sweep:
        # Even when a publisher finished mid-sweep, take a new inventory
        # after the last cancellation acknowledgment or the lease expires.
        deadlines.append(_publisher_retry(connection, job_id, now) or now)
    if not deadlines:
        _purge(connection, task)
        return
    if _requeue(connection, task):
        connection.execute(text("""
            UPDATE cloud_project_deletions
            SET state='deleting',retry_at=:next,wait_for_publishers=:publishing,
              legacy_upload_until=CASE WHEN legacy_upload_until>clock_timestamp()
                THEN legacy_upload_until ELSE NULL END
            WHERE job_id=:j
            """), {"j": job_id, "next": min(deadlines), "publishing": not final_sweep})


def execute(task):
    """Cancel the tracked capability and remove each eligible GCS generation."""
    job_id = task["job_id"]
    now = datetime.now(timezone.utc)
    with get_engine().begin() as connection:
        prefix, name = _scope(connection, task)
        item = repo.document(job_id, connection=connection)["payload"]
        if item["status"] != "deleted":
            _scrub(connection, job_id)
        _trim_stopped(connection, job_id)
        final_sweep = _publisher_retry(connection, job_id, now) is None
        session = connection.execute(text("SELECT url FROM cloud_upload_sessions WHERE job_id=:j"),
                                     {"j": job_id}).scalar()

    session_revoked = False
    if session is not None:
        try:
            if not (item.get("upload_tracking") is True and _upload_consumed(name)):
                storage.cancel_resumable(session, name)
            session_revoked = True
        except storage.StorageError:
            pass
    try:
        pending, incomplete = _sweep(prefix, now)
    except storage.StorageError:
        pending, incomplete = None, True
    with get_engine().begin() as connection:
        _scope(connection, task)
        if session_revoked:
            connection.execute(text("DELETE FROM cloud_upload_sessions WHERE job_id=:j"), {"j": job_id})
        if pending is not None:
            _save_object_blockers(connection, job_id, pending)
        if incomplete or (session is not None and not session_revoked):
            release_expired(task, connection)
        else:
            _finish_sweep(connection, task, pending, final_sweep, datetime.now(timezone.utc))
