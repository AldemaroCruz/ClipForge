"""Concurrent pilot claims and outbox dispatch against disposable PostgreSQL."""
import os
import secrets
import unittest
import uuid
from concurrent.futures import ThreadPoolExecutor
from threading import Barrier
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy import text

from app.auth import create_user, register_project
from app.auth_db import reset_engine
from app.cloud import dispatch, migrate_beta, repository, worker
from app.cloud.config import BETA_WORKER_CONCURRENCY, Settings
from auth_support import auth_environment, prepare_database


class PilotCapacityDatabaseTests(unittest.TestCase):
    def setUp(self):
        if os.environ.get("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires an explicitly disposable PostgreSQL test database")
        schema = "auth01_test_capacity_" + secrets.token_hex(8)
        environment = {**auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": schema,
                       "CLIPFORGE_INT_BETA": "1", "CLIPFORGE_STORAGE_BACKEND": "local",
                       "CLIPFORGE_DATABASE_POOL_SIZE": "8"}
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        migrate_beta.upgrade_beta(self.engine)
        self.table = {}
        self.run_settings = Settings(
            "pilot-test", "https://storage.googleapis.com", False, "cloud_run",
            "clipforgebeta2", "us-central1", "clipforge-int-worker",
        )

    def enqueue(self, pilot=True):
        principal = create_user("qa_capacity_" + secrets.token_hex(8), secrets.token_urlsafe(24))
        job_id = uuid.uuid4().hex
        register_project(job_id, principal)
        original = {"input.mp4": {"generation": "123"}}
        with self.engine.begin() as connection:
            repository.insert_document(connection, job_id, "job", {
                "id": job_id, "pilot": pilot, "status": "queued", "clips": [],
            }, original)
            task_id = repository.enqueue(connection, job_id, "process", job_id)
        self.table[task_id] = job_id
        return task_id

    def claim(self, barrier=None, job_id=None):
        with self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as lock:
            lock.execute(text("SELECT pg_advisory_lock_shared(:i)"), {"i": repository.GLOBAL_LOCK})
            try:
                if barrier is not None:
                    barrier.wait(timeout=10)
                return worker._claim(lock, job_id)
            finally:
                lock.execute(text("SELECT pg_advisory_unlock_shared(:i)"), {"i": repository.GLOBAL_LOCK})

    def test_concurrent_supervisors_only_claim_three_distinct_pilot_tasks(self):
        team = {self.enqueue() for _ in range(BETA_WORKER_CONCURRENCY + 1)}
        legacy = self.enqueue(pilot=False)
        participants = BETA_WORKER_CONCURRENCY + 1
        barrier = Barrier(participants)
        with ThreadPoolExecutor(max_workers=participants) as executor:
            futures = [executor.submit(self.claim, barrier) for _ in range(participants)]
            claims = [future.result(timeout=20) for future in futures]
        active = {claim["id"]: claim for claim in claims if claim is not None}
        self.assertEqual(len(active), BETA_WORKER_CONCURRENCY)
        self.assertTrue(active.keys() <= team)
        self.assertNotIn(legacy, active)
        self.assertEqual(len([claim for claim in claims if claim is None]), 1)

        # Simulate a supervisor whose process stopped without a final write.
        stale = next(iter(active.values()))
        with self.engine.begin() as connection:
            connection.execute(text("""
                UPDATE cloud_tasks SET lease_until=clock_timestamp()-interval '1 second'
                WHERE id=:i
                """), {"i": stale["id"]})
        new = self.claim()
        self.assertEqual(new["id"], (team - active.keys()).pop())
        with self.engine.begin() as connection, self.assertRaisesRegex(RuntimeError, "fencing token"):
            repository.worker_guard(connection, stale)
        failed = repository.document(stale["job_id"])
        self.assertEqual((failed["payload"]["status"], failed["payload"]["error_code"]),
                         ("failed", "WORKER_INTERRUPTED"))
        self.assertEqual(failed["manifest"], {"input.mp4": {"generation": "123"}})

    def test_legacy_lock_and_existing_legacy_lease_block_beta_processing(self):
        legacy = self.enqueue(pilot=False)
        self.enqueue()
        config = {"i": repository.GLOBAL_LOCK}
        with (self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as pilot,
              self.engine.connect().execution_options(isolation_level="AUTOCOMMIT") as other):
            pilot.execute(text("SELECT pg_advisory_lock_shared(:i)"), config)
            try:
                self.assertFalse(other.execute(text("SELECT pg_try_advisory_lock(:i)"), config).scalar_one())
            finally:
                pilot.execute(text("SELECT pg_advisory_unlock_shared(:i)"), config)
        with self.engine.begin() as connection:
            connection.execute(text("""
                UPDATE cloud_tasks SET status='running',fence=1,
                  lease_until=clock_timestamp()+interval '60 seconds' WHERE id=:i
                """), {"i": legacy})
        self.assertEqual(self.claim(), "wait")

    def test_recovery_target_and_pilot_exports_keep_their_existing_scope(self):
        older = self.enqueue()
        target = self.enqueue()
        job_id = self.table[target]
        self.assertEqual(self.claim(job_id=job_id)["id"], target)

        export_ids = []
        with self.engine.begin() as connection:
            for pilot in (False, True):
                item_id = uuid.uuid4().hex
                repository.insert_document(connection, job_id, "export", {
                    "id": item_id, "pilot": pilot, "status": "queued",
                })
                export_ids.append(repository.enqueue(connection, job_id, "export", item_id))
        self.assertEqual(self.claim()["id"], older)
        self.assertEqual(self.claim()["id"], export_ids[1])
        with self.engine.connect() as connection:
            state = connection.execute(text("SELECT status FROM cloud_tasks WHERE id=:i"),
                                       {"i": export_ids[0]}).scalar_one()
        self.assertEqual(state, "queued")

    def test_concurrent_dispatch_has_at_most_three_pending_run_requests(self):
        task_ids = [self.enqueue() for _ in range(BETA_WORKER_CONCURRENCY + 1)]
        self.enqueue(pilot=False)
        barrier = Barrier(2)
        cloud = Mock()
        cloud.json.return_value = {"name": "projects/pilot/locations/test/operations/start"}

        def reconcile():
            barrier.wait(timeout=10)
            return dispatch.reconcile()

        with (patch.object(dispatch, "settings", return_value=self.run_settings),
              patch.object(dispatch, "request", return_value=cloud) as request,
              ThreadPoolExecutor(max_workers=2) as executor):
            futures = [executor.submit(reconcile) for _ in range(2)]
            receipts = [future.result(timeout=20) for future in futures]
        self.assertEqual(sorted(result["dispatched"] for result in receipts), [0, BETA_WORKER_CONCURRENCY])
        self.assertEqual(request.call_count, BETA_WORKER_CONCURRENCY)
        self.assertTrue(all(call.kwargs == {"json": {}, "timeout": (3, 5)} for call in request.call_args_list))
        with self.engine.connect() as connection:
            rows = connection.execute(text("""
                SELECT task_id FROM cloud_outbox WHERE dispatched_at IS NOT NULL
                """)).scalars().all()
        self.assertEqual(set(rows), set(task_ids[:BETA_WORKER_CONCURRENCY]))

    def test_expired_selection_preserves_the_completed_source_and_needs_no_media_cleanup(self):
        migrate_beta.upgrade_beta(self.engine)
        process_id = self.enqueue()
        job_id = self.table[process_id]
        process = self.claim()
        original = repository.document(job_id)
        completed = {**original["payload"], "status": "completed", "clips": [{"file": "clip_01.mp4"}]}
        repository.finish_task(process, completed, original["manifest"])
        analysis_id = uuid.uuid4().hex
        with self.engine.begin() as connection:
            repository.insert_document(connection, job_id, "selection", {"id": analysis_id, "status": "queued"})
            selection_id = repository.enqueue(connection, job_id, "selection", analysis_id)
        selection = self.claim()
        self.assertEqual((selection["id"], selection["kind"]), (selection_id, "selection"))
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE cloud_tasks SET lease_until=clock_timestamp() WHERE id=:i"), {"i": selection_id})

        self.assertIsNone(self.claim())
        interrupted = repository.document(job_id, "selection", analysis_id)["payload"]
        self.assertEqual((interrupted["status"], interrupted["error_code"]), ("failed", "AI_TASK_INTERRUPTED"))
        self.assertEqual(repository.document(job_id)["payload"], completed)
        self.assertEqual(repository.document(job_id)["manifest"], original["manifest"])
        with self.engine.begin() as connection, self.assertRaisesRegex(RuntimeError, "fencing token"):
            repository.worker_guard(connection, selection)
        with patch.object(worker.storage, "list_staged") as storage:
            worker.cleanup_failed()
        storage.assert_not_called()

    def test_caption_batch_reserves_one_wakeup_and_leaves_room_for_other_creators(self):
        principal = create_user("qa_capacity_" + secrets.token_hex(8), secrets.token_urlsafe(24))
        job_id = uuid.uuid4().hex
        register_project(job_id, principal)
        with self.engine.begin() as connection:
            repository.insert_document(connection, job_id, "job", {
                "id": job_id, "pilot": True, "status": "completed", "clips": [],
            })
            captions = []
            for _ in range(5):
                item_id = uuid.uuid4().hex
                repository.insert_document(connection, job_id, "export", {
                    "id": item_id, "pilot": True, "status": "queued", "clip_captions": True,
                })
                captions.append(repository.enqueue(connection, job_id, "export", item_id))
        others = [self.enqueue(), self.enqueue()]
        cloud = Mock()
        cloud.json.return_value = {"name": "projects/pilot/locations/test/operations/start"}
        with (patch.object(dispatch, "settings", return_value=self.run_settings),
              patch.object(dispatch, "request", return_value=cloud) as request):
            self.assertEqual(dispatch.reconcile()["dispatched"], 3)
            self.assertEqual(dispatch.reconcile()["dispatched"], 0)
            self.assertEqual(self.claim(job_id=job_id)["id"], captions[0])
            self.assertEqual(dispatch.reconcile()["dispatched"], 0)
        self.assertEqual(request.call_count, 3)
        with self.engine.connect() as connection:
            claimed = connection.execute(text("SELECT task_id FROM cloud_outbox WHERE dispatched_at IS NOT NULL")).scalars().all()
        self.assertEqual(set(claimed), {captions[0], *others})

    def test_inactive_pending_upload_releases_admission_without_changing_projects(self):
        queued_task, running_task, deleted_task = (self.enqueue() for _ in range(3))
        queued, running, deleted = (self.table[task] for task in (queued_task, running_task, deleted_task))
        pending_owner = create_user("qa_capacity_" + secrets.token_hex(8), secrets.token_urlsafe(24))
        requester = create_user("qa_capacity_" + secrets.token_hex(8), secrets.token_urlsafe(24))
        pending = uuid.uuid4().hex
        register_project(pending, pending_owner)
        snapshot = text("""
            SELECT (SELECT jsonb_agg(to_jsonb(p) ORDER BY p.id) FROM auth_projects p),
                   (SELECT jsonb_agg(to_jsonb(d) ORDER BY d.id) FROM cloud_documents d),
                   (SELECT jsonb_agg(to_jsonb(t) ORDER BY t.id) FROM cloud_tasks t)
        """)
        with self.engine.begin() as connection:
            connection.execute(text("""
                UPDATE auth_users SET is_active=false
                WHERE id IN (SELECT owner_id FROM auth_projects WHERE id IN (:queued, :running, :deleted))
            """), {"queued": queued, "running": running, "deleted": deleted})
            connection.execute(text("""
                UPDATE auth_projects SET deletion_started_at=clock_timestamp() WHERE id=:job
            """), {"job": deleted})
            connection.execute(text("""
                UPDATE cloud_tasks SET status='cancelled', lease_until=clock_timestamp()+interval '1 hour'
                WHERE id=:task
            """), {"task": deleted_task})
            connection.execute(text("""
                UPDATE cloud_tasks SET status='running', lease_until=clock_timestamp()+interval '1 hour'
                WHERE id=:task
            """), {"task": running_task})
            connection.execute(text("""
                UPDATE cloud_documents SET payload=jsonb_set(payload, '{status}', '"rendering"')
                WHERE job_id=:job AND kind='job'
            """), {"job": running})
            expires = connection.execute(text(
                "SELECT extract(epoch FROM clock_timestamp()+interval '1 hour')"
            )).scalar_one()
            repository.insert_document(connection, pending, "job", {
                "id": pending, "pilot": True, "status": "awaiting_upload",
                "upload_expires_at": float(expires),
            })
            before = connection.execute(snapshot).one()

        with self.engine.begin() as connection, self.assertRaises(HTTPException) as full:
            repository.admit_beta(connection, requester.id)
        self.assertEqual(full.exception.status_code, 429)

        with self.engine.begin() as connection:
            connection.execute(text("UPDATE auth_users SET is_active=false WHERE id=:owner"),
                               {"owner": pending_owner.id})
            repository.admit_beta(connection, requester.id)
            self.assertEqual(connection.execute(snapshot).one(), before)

    def test_ambiguous_cloud_failure_has_cooldown_before_retry(self):
        task_id = self.enqueue()
        cloud = Mock()
        cloud.json.return_value = {"name": "projects/pilot/locations/test/operations/start"}
        with (patch.object(dispatch, "settings", return_value=self.run_settings),
              patch.object(dispatch, "request", side_effect=[TimeoutError(), cloud]) as request):
            self.assertEqual(dispatch.reconcile(), {"status": "pending", "dispatched": 0})
            self.assertEqual(dispatch.reconcile(), {"status": "current", "dispatched": 0})
            request.assert_called_once()
            with self.engine.begin() as connection:
                connection.execute(text("""
                    UPDATE cloud_outbox SET dispatched_at=clock_timestamp()-interval '16 seconds'
                    WHERE task_id=:i
                    """), {"i": task_id})
            self.assertEqual(dispatch.reconcile(), {"status": "dispatched", "dispatched": 1})
