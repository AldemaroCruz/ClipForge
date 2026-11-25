"""Durable dispatch outbox. No processing threads run inside the API."""
import argparse
import json
from urllib.parse import quote
from sqlalchemy import text
from ..auth_db import get_engine
from .config import BETA_WORKER_CONCURRENCY, beta_enabled, settings
from .project_deletion import deferred_tasks
from .storage import request, close


def reconcile():
    cfg = settings()
    if cfg.dispatch_mode == "local_manual":
        return {"status": "local_manual", "dispatched": 0}
    sent = 0
    failed = False
    beta = beta_enabled()
    # SQL serialization also makes API-startup reconciliation safe across replicas.
    with get_engine().begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(1837086404)"))
        limit = 100
        deferred = []
        if beta:
            deferred = deferred_tasks(c)
            # Pending Cloud Run starts reserve capacity until the task is
            # actually claimed or the outbox allows a new wakeup.
            busy = c.execute(text("""
                WITH live_owners AS (
                  SELECT DISTINCT p.owner_id FROM cloud_tasks t JOIN auth_projects p ON p.id=t.job_id
                  WHERE t.status IN ('running','cancelled') AND t.lease_until>clock_timestamp()
                )
                SELECT count(*) FILTER (WHERE t.status<>'queued'
                          OR NOT COALESCE(e.payload->'clip_captions'=CAST('true' AS jsonb),false))
                     + count(DISTINCT p.owner_id) FILTER (WHERE t.status='queued'
                          AND e.payload->'clip_captions'=CAST('true' AS jsonb)
                          AND p.owner_id NOT IN (SELECT owner_id FROM live_owners))
                FROM cloud_tasks t JOIN auth_projects p ON p.id=t.job_id
                JOIN cloud_outbox o ON o.task_id=t.id
                LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
                LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
                WHERE (t.status IN ('running','cancelled') AND t.lease_until>clock_timestamp())
                  OR (t.status='queued' AND d.payload->'pilot'=CAST('true' AS jsonb)
                      AND (t.kind IN ('process','selection','delete') OR e.payload->'pilot'=CAST('true' AS jsonb))
                      AND NOT (t.id=ANY(CAST(:deferred AS varchar[])))
                      AND o.dispatched_at>clock_timestamp()-
                        CASE WHEN o.last_error IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END)
                """), {"deferred": deferred}).scalar_one()
            limit = max(0, BETA_WORKER_CONCURRENCY - busy)
        # A supervisor publishes failure for an expired lease and never
        # silently replays it. A queued task can be woken again if unclaimed.
        pending = c.execute(text("""
            SELECT o.task_id FROM cloud_outbox o JOIN cloud_tasks t ON t.id=o.task_id
            JOIN auth_projects p ON p.id=t.job_id
            LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
            LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
            WHERE COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
              AND (NOT :beta OR t.kind IN ('process','selection','delete') OR e.payload->'pilot'=CAST('true' AS jsonb))
              AND ((t.status='queued' AND
                  NOT (t.id=ANY(CAST(:deferred AS varchar[]))) AND
                  (NOT :beta OR NOT COALESCE(e.payload->'clip_captions'=CAST('true' AS jsonb),false)
                    OR NOT EXISTS (
                      SELECT 1 FROM cloud_tasks peer JOIN auth_projects peer_project ON peer_project.id=peer.job_id
                      LEFT JOIN cloud_documents peer_export ON peer_export.job_id=peer.job_id
                          AND peer_export.kind='export' AND peer_export.id=peer.item_id
                      WHERE peer_project.owner_id=p.owner_id
                        AND ((peer.status IN ('running','cancelled') AND peer.lease_until>clock_timestamp())
                          OR (peer.status='queued' AND peer_export.payload->'pilot'=CAST('true' AS jsonb)
                            AND peer_export.payload->'clip_captions'=CAST('true' AS jsonb)
                            AND (peer.created_at,peer.id)<(t.created_at,t.id)))
                    )) AND
                  (o.dispatched_at IS NULL OR o.dispatched_at<=clock_timestamp()-
                   CASE WHEN :beta AND o.last_error IS NOT NULL THEN interval '15 seconds' ELSE interval '5 minutes' END))
                OR (t.status='running' AND (t.lease_until IS NULL OR t.lease_until<=clock_timestamp()) AND
                  (o.dispatched_at IS NULL OR o.dispatched_at<t.lease_until OR o.dispatched_at<=clock_timestamp()-
                   CASE WHEN :beta AND o.last_error IS NOT NULL THEN interval '15 seconds' ELSE interval '5 minutes' END)))
            ORDER BY CASE WHEN :beta AND t.status='running' THEN 0 ELSE 1 END, t.created_at,t.id
            LIMIT :limit
            """), {"beta": beta, "limit": limit, "deferred": deferred}).scalars().all()
        if not pending:
            return {"status": "current", "dispatched": 0}
        url = ("https://run.googleapis.com/v2/projects/" + quote(cfg.project, safe="") + "/locations/" + quote(cfg.region, safe="") + "/jobs/" + quote(cfg.job, safe="") + ":run")
        # The existing Cloud Run Job has one task per execution. One wakeup
        # per available pilot worker permits real parallel processing. Legacy
        # still wakes a single supervisor that drains its whole queue.
        batches = [(task_id,) for task_id in pending] if beta else [pending]
        for task_ids in batches:
            try:
                response = request("POST", url, json={}, timeout=(3, 5)) if beta else request("POST", url, json={})
                try:
                    operation = response.json().get("name", "")
                    if not isinstance(operation, str) or not operation.startswith("projects/") or len(operation) > 255:
                        raise ValueError("Invalid Jobs operation identity")
                finally:
                    close(response)
            except Exception:
                failed = True
                # A lost response may hide a successful API call. Apply a
                # short cooldown instead of starting a new execution on each
                # repeated browser request. The worker fence is authoritative.
                for task in task_ids:
                    c.execute(text("""
                        UPDATE cloud_outbox SET attempts=attempts+1,last_error='DISPATCH_FAILED',
                            dispatched_at=CASE WHEN :beta THEN clock_timestamp() ELSE dispatched_at END
                        WHERE task_id=:i
                        """), {"beta": beta, "i": task})
            else:
                for task in task_ids:
                    c.execute(text("""
                        UPDATE cloud_outbox SET dispatched_at=clock_timestamp(),attempts=attempts+1,
                            last_error=NULL,operation_name=:n WHERE task_id=:i
                        """), {"n": operation, "i": task})
                sent += len(task_ids)
    return {"status": "pending" if failed else "dispatched", "dispatched": sent}


def main():
    parser = argparse.ArgumentParser(description="Reconcile durable cloud dispatches; never changes IAM")
    parser.parse_args()
    try:
        result = reconcile()
        print(json.dumps(result))
        return 1 if result["status"] == "pending" else 0
    except Exception:
        print(json.dumps({"status": "failed", "message": "Dispatch reconciliation unavailable"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
