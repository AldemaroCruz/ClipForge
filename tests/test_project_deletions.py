"""Scoped deletion on disposable PostgreSQL and contracted Cloud Storage calls."""

from base64 import b64encode
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone
from hashlib import md5, sha256
from io import BytesIO
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import Mock, patch
from uuid import uuid4

from fastapi import HTTPException
from requests import ConnectionError as RequestConnectionError
from sqlalchemy import text

from app.auth import create_user, register_project
from app.auth_db import reset_engine
from app.cloud import migrate_beta, pilot, project_deletion, repository, storage, worker
from app.cloud.config import Settings
from app.cloud.migrate_project_deletions import PURGE_REVISION, REVISION, upgrade_project_deletions
from auth_support import auth_environment, prepare_database


class ProjectDeletionDatabaseTests(unittest.TestCase):
    def setUp(self):
        if os.environ.get("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires an explicitly disposable PostgreSQL test database")
        environment = {**auth_environment(), "CLIPFORGE_INT_BETA": "1",
                       "CLIPFORGE_DATABASE_SCHEMA": "auth01_test_deletion_" + secrets.token_hex(8),
                       "CLIPFORGE_STORAGE_BACKEND": "local"}
        patcher = patch.dict(os.environ, environment, clear=True)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        migrate_beta.upgrade_beta(self.engine)
        self.owner = self.user()
        self.other = self.user()

    def user(self):
        return create_user("qa_deletion_" + secrets.token_hex(8), secrets.token_urlsafe(24))

    def fixture(self, principal, status="completed", **settings):
        job = uuid4().hex
        register_project(job, principal)
        payload = {"id": job, "pilot": True, "status": status, "clips": [],
                   "upload_tracking": True, "source_bytes": 100,
                   "upload_expires_at": time.time()+60, **settings}
        with self.engine.begin() as connection:
            repository.insert_document(connection, job, "job", payload)
        return job

    def task(self, job, kind="process", item=None):
        with self.engine.begin() as connection:
            return repository.enqueue(connection, job, kind, item or job)

    def claim(self, job):
        return worker._claim(None, job)

    def ledger(self, job):
        with self.engine.connect() as connection:
            return connection.execute(text("SELECT * FROM cloud_project_deletions WHERE job_id=:j"),
                                      {"j": job}).mappings().one()

    def test_owner_fences_queued_and_active_work_and_releases_only_exact_child(self):
        job = self.fixture(self.owner, "transcribing")
        process = self.task(job)
        active = self.claim(job)
        self.assertEqual(active["id"], process)
        selection = self.task(job, "selection", uuid4().hex)
        other_job = self.fixture(self.other, "queued")
        other_task = self.task(other_job)
        for action in (project_deletion.begin, project_deletion.status):
            with self.assertRaises(HTTPException) as denied:
                action(self.other, job)
            self.assertEqual(denied.exception.status_code, 404)

        deletion, created = project_deletion.begin(self.owner, job, include_created=True)
        self.assertTrue(created)
        self.assertEqual(deletion, {"id": job, "status": "deleted"})
        ledger = self.ledger(job)
        self.assertEqual((ledger["state"], ledger["cancelled_active"], ledger["cancelled_queued"]), ("deleting", 1, 1))
        self.assertEqual(project_deletion.begin(self.owner, job, include_created=True), (deletion, False))
        self.assertEqual(project_deletion.begin(self.owner, job), deletion)
        marker = repository.document(job)
        self.assertEqual(marker["payload"]["status"], "deleted")
        self.assertIsInstance(marker["payload"]["created_at"], (int, float))
        self.assertNotIn("source_bytes", marker["payload"])
        self.assertEqual(marker["manifest"], {})
        self.assertEqual(self.claim(other_job)["id"], other_task)
        with self.engine.begin() as connection:
            self.assertEqual(connection.execute(text("SELECT status,lease_until FROM cloud_tasks WHERE id=:i"),
                                                {"i": selection}).one(), ("cancelled", None))
            with self.assertRaises(RuntimeError):
                repository.worker_guard(connection, active)
            with self.assertRaises(HTTPException) as denied:
                repository.beta_document(connection, self.owner, job)
            self.assertEqual(denied.exception.status_code, 404)
        with self.assertRaises(HTTPException) as busy, self.engine.begin() as connection:
            repository.admit_beta(connection, self.owner.id)
        self.assertEqual(busy.exception.status_code, 409)
        with self.assertRaises(RuntimeError), project_deletion.publication(active):
            self.fail("A cancelled media child could start a storage upload")
        self.assertFalse(project_deletion.ack_stopped({**active, "fence": active["fence"]+1}))
        cleanup = self.claim(job)
        self.assertEqual(cleanup["kind"], "delete")
        with (patch.object(storage, "list_project_generations", return_value=[]),
              patch.object(storage, "list_project_soft_deleted", return_value=[])):
            project_deletion.execute(cleanup)
            with self.engine.connect() as connection:
                self.assertIsNone(connection.execute(text("SELECT id FROM cloud_tasks WHERE id=:i"), {"i": selection}).scalar())
            self.assertTrue(self.ledger(job)["wait_for_publishers"])
            self.assertIsNone(self.claim(job))
            self.assertTrue(project_deletion.ack_stopped(active))
            with self.engine.begin() as connection:
                repository.admit_beta(connection, self.owner.id)
            project_deletion.execute(self.claim(job))
        self.assertEqual(project_deletion.status(self.owner, job)["status"], "deleted")
        self.assertEqual(self.ledger(job)["state"], "deleted")
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT status FROM cloud_tasks WHERE id=:i"),
                                               {"i": other_task}).scalar_one(), "running")

    def test_partial_cleanup_recovers_without_refunding_ai_or_replaying_upload(self):
        job = self.fixture(self.owner)
        surviving = self.fixture(self.other, "completed")
        name = storage.beta_original(self.owner.workspace_id, job)
        prefix = name.removesuffix("original/input.mp4")
        clip_name = prefix + f"tasks/{uuid4().hex}/1/clip.mp4"
        subtitle_name = clip_name.removesuffix(".mp4") + ".srt"
        other_name = storage.beta_original(self.other.workspace_id, surviving)
        live = {name: "12", clip_name: "34", subtitle_name: "35", other_name: "56"}
        key = "upload-before-removal"
        upload = {"kind": "beta_upload", "filename": "synthetic.mp4", "bytes": 100}
        fingerprint = sha256(repository.packed(upload).encode()).hexdigest()
        with self.engine.begin() as connection:
            repository.remember_request(connection, self.owner.id, key, fingerprint, job, "beta_upload", job)
            repository.insert_document(connection, job, "selection", {
                "id": uuid4().hex, "provider_calls_planned": 2, "day_utc": "2026-11-25",
                "candidates": [{"title": "Synthetic selection"}],
            })
            repository.insert_document(connection, job, "draft", {"id": uuid4().hex})

        def inventory(scope):
            self.assertEqual(scope, prefix)
            return [{"name": item, "generation": version} for item, version in live.items() if item.startswith(scope)]

        attempts = []

        def remove(item, scope):
            self.assertEqual(scope, prefix)
            candidate = item["name"]
            self.assertEqual(live[candidate], item["generation"])
            attempts.append(candidate)
            if attempts == [name, clip_name]:
                raise storage.StorageError("Synthetic transient storage failure")
            del live[candidate]

        project_deletion.begin(self.owner, job)
        with (patch.object(storage, "list_project_generations", side_effect=inventory),
              patch.object(storage, "list_project_soft_deleted", return_value=[]),
              patch.object(storage, "delete_project_generation", side_effect=remove)):
            project_deletion.execute(self.claim(job))
            receipt = project_deletion.status(self.owner, job)
            self.assertEqual(receipt, {"id": job, "status": "deleted"})
            internal = self.ledger(job)
            self.assertEqual((internal["state"], internal["attempts"]), ("delete_error", 1))
            self.assertNotIn(name, live)
            self.assertNotIn(subtitle_name, live)
            self.assertIn(clip_name, live)
            self.assertIsNone(self.claim(job))
            # The database clock is real. Advance only this fixture's retry eligibility.
            with self.engine.begin() as connection:
                connection.execute(text("UPDATE cloud_project_deletions SET retry_at=clock_timestamp() WHERE job_id=:j"),
                                   {"j": job})
            project_deletion.execute(self.claim(job))

        receipt = project_deletion.status(self.owner, job)
        self.assertEqual(receipt, {"id": job, "status": "deleted"})
        internal = self.ledger(job)
        self.assertEqual((internal["state"], internal["attempts"]), ("deleted", 1))
        self.assertEqual(project_deletion.begin(self.owner, job), receipt)
        self.assertEqual(attempts, [name, clip_name, subtitle_name, clip_name])
        self.assertEqual(live, {other_name: "56"})
        self.assertIsNone(repository.document(job, required=False))
        self.assertEqual(repository.list_documents(job, "draft"), [])
        self.assertEqual(repository.document(surviving)["payload"]["status"], "completed")
        with self.engine.begin() as connection:
            self.assertEqual(connection.execute(text("SELECT sum(planned) FROM cloud_deleted_selection_calls")).scalar_one(), 2)
            with self.assertRaises(HTTPException) as budget:
                repository.admit_selection(connection, surviving, "2026-11-25", 1, 2, 5)
            self.assertEqual(budget.exception.status_code, 429)
        with self.assertRaises(HTTPException) as rejected:
            pilot._reserve(self.owner, key, upload["filename"], upload["bytes"])
        self.assertEqual(rejected.exception.status_code, 404)

    def test_publication_does_not_delay_receipt_and_final_sweep_removes_late_writes(self):
        job = self.fixture(self.owner, "rendering")
        self.task(job)
        active = self.claim(job)
        name = storage.beta_original(self.owner.workspace_id, job)
        prefix = name.removesuffix("original/input.mp4")
        live = {"1": {"name": name, "generation": "1"}}

        def remove(item, scope):
            self.assertEqual(scope, prefix)
            del live[item["generation"]]

        with (patch.object(storage, "list_project_generations", side_effect=lambda _: list(live.values())),
              patch.object(storage, "list_project_soft_deleted", return_value=[]),
              patch.object(storage, "delete_project_generation", side_effect=remove),
              ThreadPoolExecutor(max_workers=1) as clients):
            with project_deletion.publication(active):
                receipt = clients.submit(project_deletion.begin, self.owner, job).result(timeout=5)
                self.assertEqual(receipt, {"id": job, "status": "deleted"})
                project_deletion.execute(self.claim(job))
                self.assertEqual(live, {})
                self.assertTrue(self.ledger(job)["wait_for_publishers"])
                # Simulate an upload already admitted before the tombstone.
                live["2"] = {"name": prefix + f"tasks/{active['id']}/{active['fence']}/clip.mp4", "generation": "2"}
            self.assertTrue(project_deletion.ack_stopped(active))
            project_deletion.execute(self.claim(job))
        self.assertEqual(live, {})
        self.assertEqual(self.ledger(job)["state"], "deleted")

    def test_expired_cleanup_lease_is_requeued_with_new_fence(self):
        job = self.fixture(self.owner)
        project_deletion.begin(self.owner, job)
        crashed = self.claim(job)
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE cloud_tasks SET lease_until=clock_timestamp()-interval '1 second' WHERE id=:i"),
                               {"i": crashed["id"]})
        self.assertIsNone(self.claim(job))
        internal = self.ledger(job)
        self.assertEqual((internal["state"], internal["attempts"]), ("delete_error", 1))
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE cloud_project_deletions SET retry_at=clock_timestamp() WHERE job_id=:j"),
                               {"j": job})
        retry = self.claim(job)
        self.assertEqual(retry["id"], crashed["id"])
        self.assertGreater(retry["fence"], crashed["fence"])
        with (patch.object(storage, "list_project_generations", return_value=[]) as inventory,
              patch.object(storage, "list_project_soft_deleted", return_value=[])):
            with self.assertRaises(RuntimeError):
                project_deletion.execute(crashed)
            inventory.assert_not_called()
            project_deletion.execute(retry)
        self.assertEqual(self.ledger(job)["state"], "deleted")

    def test_all_eligible_generations_are_removed_and_policy_dates_remain_exact(self):
        job = self.fixture(self.owner)
        name = storage.beta_original(self.owner.workspace_id, job)
        prefix = name.removesuffix("original/input.mp4")
        retained_until = datetime.now(timezone.utc) + timedelta(minutes=2)
        soft_until = retained_until + timedelta(days=7)
        live = {
            "1": {"name": name, "generation": "1"},
            "2": {"name": name, "generation": "2", "retentionExpirationTime": retained_until.isoformat()},
            "3": {"name": prefix + f"tasks/{uuid4().hex}/1/clip.mp4", "generation": "3"},
        }
        soft = []
        removed = []

        def erase(item, scope):
            self.assertEqual(scope, prefix)
            removed.append(item["generation"])
            del live[item["generation"]]
            soft.append({**item, "hardDeleteTime": soft_until.isoformat()})

        project_deletion.begin(self.owner, job)
        with (patch.object(storage, "list_project_generations", side_effect=lambda _: list(live.values())),
              patch.object(storage, "list_project_soft_deleted", side_effect=lambda _: soft),
              patch.object(storage, "delete_project_generation", side_effect=erase)):
            project_deletion.execute(self.claim(job))
        self.assertEqual(removed, ["1", "3"])
        row = self.ledger(job)
        self.assertEqual(row["retry_at"], retained_until)
        self.assertEqual(row["attempts"], 0)
        self.assertEqual(row["state"], "deleting")
        self.assertEqual({(item["generation"], item["reason"], item["until"]) for item in row["storage_blockers"]},
                         {("2", "retention", retained_until.isoformat()), ("1", "soft_delete", soft_until.isoformat()),
                          ("3", "soft_delete", soft_until.isoformat())})
        self.assertIsNone(self.claim(job))

    def test_migration_rearms_only_pending_legacy_receipts_and_keeps_old_health_ledger(self):
        started = datetime.now(timezone.utc) - timedelta(days=2)
        deadline = started - timedelta(minutes=1)
        pending = self.fixture(self.owner, "deleting", upload_tracking=False, upload_expires_at=deadline.timestamp())
        complete = self.fixture(self.other, "completed")
        pending_task = self.task(pending, "delete")
        completed_task = self.task(complete, "delete")
        with self.engine.begin() as connection:
            connection.execute(text("UPDATE auth_projects SET deletion_started_at=:d WHERE id IN (:p,:c)"),
                               {"d": started, "p": pending, "c": complete})
            connection.execute(text("""
                INSERT INTO cloud_project_deletions(job_id,state,retry_at,cancelled_queued,cancelled_active,completed_at)
                VALUES (:p,'deleting',clock_timestamp()+interval '7 days',0,0,NULL),
                       (:c,'deleted',clock_timestamp(),0,0,clock_timestamp())
                """), {"p": pending, "c": complete})
            connection.execute(text("UPDATE cloud_tasks SET status='succeeded' WHERE id=:i"), {"i": completed_task})
            connection.execute(text("UPDATE cloud_outbox SET dispatched_at=clock_timestamp() WHERE task_id=:i"),
                               {"i": pending_task})
            self.assertEqual(upgrade_project_deletions(connection), "current")
            old_ledger = connection.execute(text("SELECT revision FROM cloud_deletion_schema_migrations")).scalars().all()
            purge_ledger = connection.execute(text("SELECT revision FROM cloud_deletion_purge_schema_migrations")).scalars().all()
            self.assertEqual((old_ledger, purge_ledger), ([REVISION], [PURGE_REVISION]))
            completed = connection.execute(text("SELECT state,purge_policy_ready FROM cloud_project_deletions WHERE job_id=:j"),
                                           {"j": complete}).one()
            self.assertEqual(completed, ("deleted", False))
        scheduled = self.ledger(pending)
        expected_deadline = deadline + timedelta(seconds=project_deletion.UPLOAD_CAPABILITY_SECONDS)
        self.assertAlmostEqual(scheduled["legacy_upload_until"].timestamp(), expected_deadline.timestamp(), places=3)
        with self.engine.begin() as connection:
            upgrade_project_deletions(connection)
        self.assertEqual(self.ledger(pending)["retry_at"], scheduled["retry_at"])
        with (patch.object(storage, "list_project_generations", return_value=[]),
              patch.object(storage, "list_project_soft_deleted", return_value=[])):
            cleanup = self.claim(pending)
            self.assertEqual(cleanup["id"], pending_task)
            project_deletion.execute(cleanup)
        marker = repository.document(pending)["payload"]
        self.assertEqual(set(marker), {"id", "status", "created_at", "pilot", "clips", "upload_tracking"})
        self.assertEqual(marker["status"], "deleted")
        self.assertEqual(self.ledger(pending)["retry_at"], scheduled["legacy_upload_until"])

    def test_legacy_upload_sweeps_now_then_watches_its_original_expiry(self):
        deadline = time.time()+30
        job = self.fixture(self.owner, "awaiting_upload", upload_tracking=False, upload_expires_at=deadline)
        deletion = project_deletion.begin(self.owner, job)
        self.assertEqual(deletion, {"id": job, "status": "deleted"})
        deadline = self.ledger(job)["legacy_upload_until"]
        self.assertAlmostEqual(deadline.timestamp(), time.time()+project_deletion.UPLOAD_CAPABILITY_SECONDS, delta=5)
        with (patch.object(storage, "list_project_generations", return_value=[]) as inventory,
              patch.object(storage, "list_project_soft_deleted", return_value=[])):
            project_deletion.execute(self.claim(job))
        self.assertEqual(inventory.call_count, 2)
        self.assertEqual(self.ledger(job)["retry_at"], deadline)
        self.assertIsNone(self.claim(job))
        self.assertEqual(project_deletion.begin(self.owner, job), deletion)
        self.assertEqual(self.ledger(job)["legacy_upload_until"], deadline)
        with patch.object(storage, "start_resumable") as mint, self.assertRaises(HTTPException):
            pilot._open_upload(self.owner, job)
        mint.assert_not_called()

    def test_upload_default_and_opt_out_and_revocation_of_one_tracked_capability(self):
        subtitles = pilot.Upload(filename="synthetic.mp4", bytes=100)
        self.assertTrue(subtitles.burn_subtitles)
        first = pilot._reserve(self.owner, "default-captions", subtitles.filename, subtitles.bytes)
        second = pilot._reserve(self.other, "opt-out-captions", subtitles.filename, subtitles.bytes, False)
        self.assertTrue(first["options"]["burn_subtitles"])
        self.assertFalse(second["options"]["burn_subtitles"])
        self.assertTrue(first["caption_style"]["burn_subtitles"])
        self.assertFalse(second["caption_style"]["burn_subtitles"])
        job = first["id"]
        location = "https://storage.googleapis.com/upload/storage/v1/b/pilot-unit/o?upload_id=synthetic-capability"
        name = storage.beta_original(self.owner.workspace_id, job)
        with patch.object(storage, "beta_original_metadata", return_value=None), patch.object(
                storage, "start_resumable", return_value=location):
            self.assertEqual(pilot._open_upload(self.owner, job)["upload_url"], location)
        project_deletion.begin(self.owner, job)
        with (patch.object(storage, "cancel_resumable") as cancel,
              patch.object(storage, "beta_original_metadata", return_value=None),
              patch.object(storage, "list_project_generations", return_value=[]),
              patch.object(storage, "list_project_soft_deleted", return_value=[])):
            project_deletion.execute(self.claim(job))
        cancel.assert_called_once_with(location, name)
        self.assertEqual(project_deletion.status(self.owner, job)["status"], "deleted")
        with self.engine.connect() as connection:
            self.assertIsNone(connection.execute(text("SELECT url FROM cloud_upload_sessions WHERE job_id=:j"),
                                                 {"j": job}).scalar())

    def test_unconfirmed_but_completed_upload_is_swept_without_reopening_its_session(self):
        job = self.fixture(self.owner, "awaiting_upload")
        name = storage.beta_original(self.owner.workspace_id, job)
        item = {"name": name, "generation": "78"}
        with self.engine.begin() as connection:
            connection.execute(text("INSERT INTO cloud_upload_sessions(job_id,url) VALUES (:j,:u)"),
                               {"j": job, "u": "https://storage.googleapis.com/upload/storage/v1/b/pilot-unit/o?upload_id=synthetic"})
        project_deletion.begin(self.owner, job)
        with (patch.object(storage, "cancel_resumable") as cancel,
              patch.object(storage, "beta_original_metadata", return_value=item),
              patch.object(storage, "list_project_generations", side_effect=[[item], []]),
              patch.object(storage, "list_project_soft_deleted", return_value=[]),
              patch.object(storage, "delete_project_generation") as remove):
            project_deletion.execute(self.claim(job))
        cancel.assert_not_called()
        remove.assert_called_once_with(item, name.removesuffix("original/input.mp4"))
        self.assertEqual(project_deletion.status(self.owner, job)["status"], "deleted")


class ProjectStorageContractTests(unittest.TestCase):
    def setUp(self):
        self.prefix = f"workspaces/{'a'*32}/jobs/{'b'*32}/"
        self.name = self.prefix + "original/input.mp4"
        settings = patch.object(storage, "settings", return_value=Settings(
            "pilot-unit", "https://storage.googleapis.com", False, "cloud_run", "pilot", "us-central1", "worker",
        ))
        settings.start()
        self.addCleanup(settings.stop)

    def test_inventory_separates_versions_and_soft_deleted_and_pins_deletion(self):
        item = {"name": self.name, "generation": "345"}
        listed = Mock(status_code=200)
        listed.json.return_value = {"items": [item]}
        with patch.object(storage, "request", return_value=listed) as request, patch.object(storage, "close"):
            self.assertEqual(storage.list_project_generations(self.prefix), [item])
            version_query = request.call_args.kwargs["params"]
            self.assertEqual(version_query["versions"], "true")
            self.assertIn("retentionExpirationTime", version_query["fields"])
            self.assertNotIn("softDeleted", version_query)
            self.assertEqual(storage.list_project_soft_deleted(self.prefix), [item])
            recovery_query = request.call_args.kwargs["params"]
            self.assertEqual(recovery_query["softDeleted"], "true")
            self.assertIn("hardDeleteTime", recovery_query["fields"])
            self.assertNotIn("versions", recovery_query)
            storage.delete_project_generation(item, self.prefix)
            self.assertEqual(request.call_args.kwargs["params"], {"generation": "345", "ifGenerationMatch": "345"})
            with self.assertRaises(storage.StorageError):
                storage.delete_project_generation({**item, "name": self.name.replace("b"*32, "c"*32)}, self.prefix)
            self.assertEqual(request.call_count, 3)

    def test_forbidden_delete_is_a_policy_restriction_only_for_exact_gcs_reasons(self):
        denied = Mock(status_code=403)
        item = {"name": self.name, "generation": "345"}
        with patch.object(storage, "request", return_value=denied), patch.object(storage, "close"):
            for reason in ("objectUnderActiveHold", "retentionPolicyNotMet"):
                denied.json.return_value = {"error": {"errors": [{"reason": reason}]}}
                with self.assertRaises(storage.DeletionRestricted):
                    storage.delete_project_generation(item, self.prefix)
            denied.json.return_value = {"error": {"errors": [{"reason": "insufficientPermissions"}]}}
            with self.assertRaises(storage.StorageError) as failure:
                storage.delete_project_generation(item, self.prefix)
            self.assertNotIsInstance(failure.exception, storage.DeletionRestricted)

    def test_live_delete_uses_generation_compare_without_purging_noncurrent_version(self):
        item = {"name": self.name, "generation": "345"}
        with patch.object(storage, "request", return_value=Mock()) as request, patch.object(storage, "close"):
            storage.delete_project_live(item, self.prefix)
            self.assertEqual(request.call_args.args[0], "DELETE")
            self.assertEqual(request.call_args.kwargs["params"], {"ifGenerationMatch": "345"})
        with patch.object(storage, "request", side_effect=storage.ObjectMissing):
            storage.delete_project_live(item, self.prefix)
        with patch.object(storage, "request") as request, self.assertRaises(storage.StorageError):
            storage.delete_project_live({**item, "name": self.name.replace("b"*32, "c"*32)}, self.prefix)
        request.assert_not_called()

    def test_upload_cancel_uses_exact_json_api_scope_and_idempotent_results(self):
        location = "https://storage.googleapis.com/upload/storage/v1/b/pilot-unit/o?upload_id=synthetic-capability"
        with patch.object(storage, "request", return_value=Mock()) as request, patch.object(storage, "close"):
            storage.cancel_resumable(location, self.name)
            self.assertEqual(request.call_args.args, ("DELETE", location))
            self.assertEqual(request.call_args.kwargs["extra_statuses"], (410, 499))
        with patch.object(storage, "request", side_effect=storage.ObjectMissing):
            storage.cancel_resumable(location, self.name)
        with patch.object(storage, "request") as request, self.assertRaises(storage.StorageError):
            storage.cancel_resumable(location.replace("pilot-unit", "unrelated"), self.name)
        request.assert_not_called()

    def test_failed_pilot_staging_preserves_retention_using_exact_task_prefix(self):
        task = self.prefix + f"tasks/{'c'*32}/"
        item = {"name": task + "1/clip.mp4", "generation": "345"}
        with patch.object(storage, "request", return_value=Mock()) as request, patch.object(storage, "close"):
            storage.delete_staged(item, task, live_only=True)
            self.assertEqual(request.call_args.kwargs["params"], {"ifGenerationMatch": "345"})
            storage.delete_staged(item, task)
            self.assertEqual(request.call_args.kwargs["params"], {"generation": "345", "ifGenerationMatch": "345"})
        with patch.object(storage, "request") as request, self.assertRaises(storage.StorageError):
            storage.delete_staged(item, self.prefix + f"tasks/{'d'*32}/", live_only=True)
        request.assert_not_called()

    def test_create_only_upload_recovers_a_committed_transport_failure(self):
        data = b"synthetic exported video"
        response = Mock()
        response.json.return_value = {
            "name": self.name, "generation": "345", "size": str(len(data)),
            "contentType": "video/mp4", "md5Hash": b64encode(md5(data, usedforsecurity=False).digest()).decode(),
        }
        with (patch.object(storage, "request", side_effect=[storage.TransportError, response]) as request,
              patch.object(storage, "close")):
            item = storage.upload(self.name, BytesIO(data), "video/mp4")
        self.assertEqual(item["generation"], "345")
        self.assertEqual(item["sha256"], sha256(data).hexdigest())
        self.assertEqual([call.args[0] for call in request.call_args_list], ["POST", "GET"])
        self.assertEqual(request.call_args_list[0].kwargs["params"]["ifGenerationMatch"], "0")
        self.assertEqual(request.call_args_list[1].args[1], storage.object_url(self.name))

        response.json.return_value["contentType"] = "text/plain"
        with (patch.object(storage, "request", side_effect=[storage.TransportError, response]) as request,
              patch.object(storage, "close"), self.assertRaisesRegex(storage.StorageError, "metadata mismatch")):
            storage.upload(self.name, BytesIO(data), "video/mp4")
        self.assertEqual(request.call_count, 2)
        response.json.return_value["contentType"] = "video/mp4"
        response.json.return_value["md5Hash"] = b64encode(b"x"*16).decode()
        with (patch.object(storage, "request", side_effect=[storage.TransportError, response]) as request,
              patch.object(storage, "close"), self.assertRaisesRegex(storage.StorageError, "metadata mismatch")):
            storage.upload(self.name, BytesIO(data), "video/mp4")
        self.assertEqual(request.call_count, 2)

    def test_create_only_retry_rewinds_and_reconciles_a_late_precondition(self):
        data = b"synthetic exported video"
        response = Mock()
        response.json.return_value = {
            "name": self.name, "generation": "123", "size": str(len(data)), "contentType": "video/mp4",
            "md5Hash": b64encode(md5(data, usedforsecurity=False).digest()).decode(),
        }
        remaining = iter([storage.TransportError(), storage.ObjectMissing(), storage.PreconditionFailed(), response])

        def transport(method, _url, **options):
            if method == "POST":
                self.assertEqual(options["params"]["ifGenerationMatch"], "0")
                self.assertEqual(options["data"].read(), data)
            result = next(remaining)
            if isinstance(result, Exception):
                raise result
            return result

        with patch.object(storage, "request", side_effect=transport) as request, patch.object(storage, "close"):
            self.assertEqual(storage.upload(self.name, BytesIO(data), "video/mp4")["generation"], "123")
            self.assertEqual([call.args[0] for call in request.call_args_list], ["POST", "GET", "POST", "GET"])
        for error in (storage.PreconditionFailed("Already exists"), storage.StorageError("Denied")):
            with patch.object(storage, "request", side_effect=error) as request, self.assertRaises(type(error)):
                storage.upload(self.name, BytesIO(data), "video/mp4")
            request.assert_called_once()

    def test_stream_retry_keeps_exact_generation_and_restarts_only_an_owned_file(self):
        data = b"synthetic video"
        item = {"name": self.name, "generation": "42", "bytes": len(data), "sha256": sha256(data).hexdigest()}
        first = Mock()
        second = Mock()

        def interrupted(_size):
            yield data[:3]
            raise RequestConnectionError("Synthetic broken stream")

        first.iter_content.side_effect = interrupted
        second.iter_content.return_value = [data]
        with TemporaryDirectory() as directory:
            path = Path(directory) / "clip.mp4"
            with (patch.object(storage, "request", side_effect=[first, second]) as request,
                  patch.object(storage, "close") as close):
                storage.download(item, path)
                self.assertEqual(path.read_bytes(), data)
                self.assertEqual(request.call_count, 2)
                self.assertEqual(close.call_count, 2)
                for call in request.call_args_list:
                    self.assertEqual(call.kwargs["params"], {"alt": "media", "generation": "42"})
            with (patch.object(storage, "request", return_value=first) as request,
                  patch.object(storage, "close"), self.assertRaises(FileExistsError)):
                storage.download(item, path)
            request.assert_called_once()
            self.assertEqual(path.read_bytes(), data)

    def test_generation_read_retries_only_transport_with_the_same_range(self):
        item = {"name": self.name, "generation": "42"}
        response = Mock()
        with patch.object(storage, "request", side_effect=[storage.TransportError, response]) as request:
            self.assertIs(storage.open_object(item, "bytes=0-3"), response)
            self.assertEqual(request.call_count, 2)
            self.assertEqual(request.call_args_list[0], request.call_args_list[1])
            self.assertEqual(request.call_args.kwargs["params"], {"alt": "media", "generation": "42"})
        with (patch.object(storage, "request", side_effect=storage.ObjectMissing) as request,
              self.assertRaises(storage.ObjectMissing)):
            storage.open_object(item)
        request.assert_called_once()
