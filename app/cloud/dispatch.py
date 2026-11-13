"""Durable dispatch outbox. No processing threads run inside the API."""
import argparse
import json
from urllib.parse import quote
from sqlalchemy import text
from ..auth_db import get_engine
from .config import settings
from .storage import request, close


def reconcile():
    cfg = settings()
    if cfg.dispatch_mode == "local_manual":
        return {"status": "local_manual", "dispatched": 0}
    count = 0
    # SQL serialization also makes API-startup reconciliation safe across replicas.
    with get_engine().begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(1837086404)"))
        # An expired running lease also needs a supervisor wakeup, even when it
        # is the only remaining task. The supervisor fails that interrupted
        # attempt under the global lock; dispatch never requeues or replays it.
        # After a wakeup, wait five minutes before resubmitting an unclaimed
        # task (for example, a Job that timed out waiting for the global lock).
        pending = c.execute(text("""
            SELECT o.task_id FROM cloud_outbox o JOIN cloud_tasks t ON t.id=o.task_id
            WHERE (t.status='queued' AND
                (o.dispatched_at IS NULL OR o.dispatched_at<clock_timestamp()-interval '5 minutes'))
            OR (t.status='running' AND t.lease_until<=clock_timestamp() AND
                (o.dispatched_at IS NULL OR o.dispatched_at<t.lease_until OR
                 o.dispatched_at<clock_timestamp()-interval '5 minutes'))
            ORDER BY t.created_at,t.id LIMIT 100
            """)).scalars().all()
        if not pending:
            return {"status": "current", "dispatched": 0}
        url = ("https://run.googleapis.com/v2/projects/" + quote(cfg.project, safe="") + "/locations/" + quote(cfg.region, safe="") + "/jobs/" + quote(cfg.job, safe="") + ":run")
        try:
            response = request("POST", url, json={})
            try:
                operation = response.json().get("name", "")
                if not isinstance(operation, str) or not operation.startswith("projects/") or len(operation) > 255:
                    raise ValueError("Invalid Jobs operation identity")
            finally:
                close(response)
            for task in pending:
                c.execute(text("UPDATE cloud_outbox SET dispatched_at=clock_timestamp(),attempts=attempts+1,last_error=NULL,operation_name=:n WHERE task_id=:i"), {"n": operation, "i": task})
            count = len(pending)
        except Exception:
            for task in pending:
                c.execute(text("UPDATE cloud_outbox SET attempts=attempts+1,last_error='DISPATCH_FAILED' WHERE task_id=:i"), {"i": task})
            return {"status": "pending", "dispatched": 0}
    return {"status": "dispatched", "dispatched": count}


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
