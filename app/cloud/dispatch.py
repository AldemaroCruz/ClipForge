"""Durable dispatch outbox. No processing threads run inside the API."""
import argparse
import json
from urllib.parse import quote
from sqlalchemy import text
from ..auth_db import get_engine
from .config import BETA_WORKER_CONCURRENCY, beta_enabled, settings
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
        if beta:
            # Pending Cloud Run starts reserve capacity until the task is
            # actually claimed or the outbox allows a new wakeup.
            busy = c.execute(text("""
                SELECT count(*) FROM cloud_tasks t
                JOIN cloud_outbox o ON o.task_id=t.id
                LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
                LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
                WHERE (t.status='running' AND t.lease_until>clock_timestamp())
                  OR (t.status='queued' AND d.payload->'pilot'=CAST('true' AS jsonb)
                      AND (t.kind IN ('process','selection') OR e.payload->'pilot'=CAST('true' AS jsonb))
                      AND o.dispatched_at>clock_timestamp()-
                        CASE WHEN o.last_error IS NULL THEN interval '5 minutes' ELSE interval '15 seconds' END)
                """)).scalar_one()
            limit = max(0, BETA_WORKER_CONCURRENCY - busy)
        # A supervisor publishes failure for an expired lease and never
        # silently replays it. A queued task can be woken again if unclaimed.
        pending = c.execute(text("""
            SELECT o.task_id FROM cloud_outbox o JOIN cloud_tasks t ON t.id=o.task_id
            LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
            LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
            WHERE COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
              AND (NOT :beta OR t.kind IN ('process','selection') OR e.payload->'pilot'=CAST('true' AS jsonb))
              AND ((t.status='queued' AND
                  (o.dispatched_at IS NULL OR o.dispatched_at<=clock_timestamp()-
                   CASE WHEN :beta AND o.last_error IS NOT NULL THEN interval '15 seconds' ELSE interval '5 minutes' END))
                OR (t.status='running' AND (t.lease_until IS NULL OR t.lease_until<=clock_timestamp()) AND
                  (o.dispatched_at IS NULL OR o.dispatched_at<t.lease_until OR o.dispatched_at<=clock_timestamp()-
                   CASE WHEN :beta AND o.last_error IS NOT NULL THEN interval '15 seconds' ELSE interval '5 minutes' END)))
            ORDER BY CASE WHEN :beta AND t.status='running' THEN 0 ELSE 1 END, t.created_at,t.id
            LIMIT :limit
            """), {"beta": beta, "limit": limit}).scalars().all()
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
