"""Real disposable PostgreSQL + emulator, simulated Cloud Run HTTP contracts.

Not an actual Cloud Run dispatch or multimedia acceptance. Expired timestamps
below are explicit SQL fixtures in a new test-owned schema. The real interruption
case in browser_int_e2e.py waits for the untouched native lease instead.
"""
from __future__ import annotations

import argparse
from dataclasses import replace
import io
import json
import os
from pathlib import Path
import secrets
import sys
import unittest
from unittest.mock import MagicMock, patch
import uuid


sys.path.insert(0, "/app")


class DispatchDatabaseTests(unittest.TestCase):
    def setUp(self):
        from app.auth_db import get_engine, reset_engine
        from app.cloud.config import settings
        from app.cloud.migrate import upgrade
        from app.auth import create_user, register_project
        from app.cloud import repository, storage
        from sqlalchemy import text
        if (os.getenv("CLIPFORGE_CLOUD_DISPATCH_TEST") != "1" or os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") != "1" or os.getenv("CLIPFORGE_CLOUD_LOCAL_TEST") != "1"
                or settings().dispatch_mode != "local_manual"):
            raise RuntimeError("Explicit isolated local cloud profile required")
        self.original_schema = os.environ["CLIPFORGE_DATABASE_SCHEMA"]
        if not self.original_schema.startswith("int_e2e_"):
            raise RuntimeError("Test schema ownership is not confirmed")
        self.schema = "int_e2e_dispatch_" + secrets.token_hex(8)
        os.environ["CLIPFORGE_DATABASE_SCHEMA"] = self.schema
        reset_engine()
        self.engine = get_engine()
        upgrade(self.engine)
        principal = create_user("dispatch_" + secrets.token_hex(8), secrets.token_urlsafe(30))
        self.job_id = uuid.uuid4().hex
        register_project(self.job_id, principal)
        self.original_bytes = b"explicit synthetic storage contract; not a real video"
        self.original = storage.upload(f"workspaces/{principal.workspace_id}/jobs/{self.job_id}/original/{uuid.uuid4().hex}.mp4",
                                       io.BytesIO(self.original_bytes), "video/mp4")
        with self.engine.begin() as connection:
            repository.insert_document(connection, self.job_id, "job", {"id": self.job_id, "status": "queued", "clips": []},
                                       {"input.mp4": self.original})
            self.task_id = repository.enqueue(connection, self.job_id, "process", self.job_id)
        self.cfg = replace(settings(), dispatch_mode="cloud_run", project="clipforgebeta2", region="us-central1", job="clipforge-int-worker")
        self.text = text

    def tearDown(self):
        from app.auth_db import reset_engine
        # The entire database and storage emulator belong to this invocation and
        # are removed by the outer lifecycle even on a test failure. Never drop
        # an environment schema or delete originals as a test shortcut.
        os.environ["CLIPFORGE_DATABASE_SCHEMA"] = self.original_schema
        reset_engine()

    def reconciler(self):
        from app.cloud import dispatch
        response = MagicMock()
        response.json.return_value = {"name": "projects/clipforgebeta2/locations/us-central1/operations/synthetic-int-e2e"}
        return dispatch, response

    def test_only_expired_running_task_is_woken_once_then_fenced_without_replay(self):
        from app.cloud import repository, storage, worker
        with self.engine.begin() as connection:
            connection.execute(self.text("UPDATE cloud_tasks SET status='running',fence=1,lease_until=clock_timestamp()-interval '1 second' WHERE id=:i"), {"i": self.task_id})
            connection.execute(self.text("UPDATE cloud_outbox SET dispatched_at=clock_timestamp()-interval '2 minutes' WHERE task_id=:i"), {"i": self.task_id})
            self.assertEqual(connection.execute(self.text("SELECT count(*) FROM cloud_tasks WHERE status='queued'")).scalar_one(), 0)
        dispatch, response = self.reconciler()
        with patch.object(dispatch, "settings", return_value=self.cfg), patch.object(dispatch, "request", return_value=response) as request, patch.object(dispatch, "close"):
            self.assertEqual(dispatch.reconcile(), {"status": "dispatched", "dispatched": 1})
            self.assertEqual(dispatch.reconcile(), {"status": "current", "dispatched": 0})
            request.assert_called_once()
            self.assertEqual(request.call_args.args[0], "POST")
            self.assertTrue(request.call_args.args[1].endswith("/jobs/clipforge-int-worker:run"))
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as lock:
            self.assertTrue(lock.execute(self.text("SELECT pg_try_advisory_lock(:i)"), {"i": repository.GLOBAL_LOCK}).scalar_one())
            try:
                self.assertIsNone(worker._claim(lock))
            finally:
                lock.execute(self.text("SELECT pg_advisory_unlock(:i)"), {"i": repository.GLOBAL_LOCK})
        with self.engine.connect() as connection:
            row = connection.execute(self.text("SELECT status,fence,lease_until FROM cloud_tasks WHERE id=:i"), {"i": self.task_id}).one()
        self.assertEqual(tuple(row), ("failed", 2, None))
        document = repository.document(self.job_id)
        self.assertEqual(document["payload"]["error_code"], "WORKER_INTERRUPTED")
        self.assertEqual(document["manifest"], {"input.mp4": self.original})
        response = storage.open_object(self.original)
        try:
            self.assertEqual(response.content, self.original_bytes)
        finally:
            storage.close(response)

    def test_stale_queued_dispatch_reconciles_without_duplicate_immediate_wakeup(self):
        with self.engine.begin() as connection:
            connection.execute(self.text("UPDATE cloud_outbox SET dispatched_at=clock_timestamp()-interval '6 minutes' WHERE task_id=:i"), {"i": self.task_id})
        dispatch, response = self.reconciler()
        with patch.object(dispatch, "settings", return_value=self.cfg), patch.object(dispatch, "request", return_value=response) as request, patch.object(dispatch, "close"):
            self.assertEqual(dispatch.reconcile(), {"status": "dispatched", "dispatched": 1})
            self.assertEqual(dispatch.reconcile(), {"status": "current", "dispatched": 0})
            request.assert_called_once()
        with self.engine.connect() as connection:
            row = connection.execute(self.text("SELECT status,fence FROM cloud_tasks WHERE id=:i"), {"i": self.task_id}).one()
        self.assertEqual(tuple(row), ("queued", 0))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args(argv)
    output = io.StringIO()
    suite = unittest.defaultTestLoader.loadTestsFromTestCase(DispatchDatabaseTests)
    result = unittest.TextTestRunner(stream=output, verbosity=2).run(suite)
    # Keep diagnostics private. unittest errors may include raw response bodies.
    private = Path("/private/cloud-dispatch-diagnostics.txt")
    descriptor = os.open(private, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        stream.write(output.getvalue())
    report = {"schema": "clipforge-int-dispatch-contract-1", "status": "passed" if result.wasSuccessful() and result.testsRun == 2 and not result.skipped else "failed",
        "tests_run": result.testsRun, "failures": len(result.failures), "errors": len(result.errors), "skipped": len(result.skipped),
        "postgresql": "real exclusive schemas", "storage": "emulator", "cloud_run_request": "simulated", "cloud_validation": False,
        "lease_expiry": "explicit SQL fixture; real SIGKILL/native lease tested separately"}
    descriptor = os.open(args.report, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump(report, stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
