"""Scoped deletion on disposable PostgreSQL and contracted Cloud Storage calls."""

from base64 import b64encode
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

        deletion = project_deletion.begin(self.owner, job)
        self.assertEqual((deletion["status"], deletion["cancelled_active"], deletion["cancelled_queued"]),
                         ("deleting", 1, 1))
        self.assertEqual(project_deletion.begin(self.owner, job), deletion)
        self.assertEqual(repository.document(job)["payload"]["status"], "deleting")
        self.assertIsNone(self.claim(job))
        self.assertEqual(self.claim(other_job)["id"], other_task)
        with self.engine.begin() as connection:
            self.assertEqual(connection.execute(text("SELECT status FROM cloud_tasks WHERE id=:i"),
                                               {"i": selection}).scalar_one(), "cancelled")
            with self.assertRaises(RuntimeError):
                repository.worker_guard(connection, active)
            with self.assertRaises(HTTPException) as denied:
                repository.beta_document(connection, self.owner, job)
            self.assertEqual(denied.exception.status_code, 404)
        with self.assertRaises(RuntimeError), project_deletion.publication(active):
            self.fail("A cancelled media child could start a storage upload")
        self.assertFalse(project_deletion.ack_stopped({**active, "fence": active["fence"]+1}))
        self.assertIsNone(self.claim(job))
        self.assertTrue(project_deletion.ack_stopped(active))
        cleanup = self.claim(job)
        self.assertEqual(cleanup["kind"], "delete")
        with patch.object(storage, "list_project_live", return_value=[]):
            project_deletion.execute(cleanup)
        self.assertEqual(project_deletion.status(self.owner, job)["status"], "deleted")
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT status FROM cloud_tasks WHERE id=:i"),
                                               {"i": other_task}).scalar_one(), "running")

    def test_partial_cleanup_recovers_without_refunding_ai_or_replaying_upload(self):
        job = self.fixture(self.owner)
        surviving = self.fixture(self.other, "completed")
        name = storage.beta_original(self.owner.workspace_id, job)
        prefix = name.removesuffix("original/input.mp4")
        clip_name = prefix + f"tasks/{uuid4().hex}/1/clip.mp4"
        other_name = storage.beta_original(self.other.workspace_id, surviving)
        live = {name: "12", clip_name: "34", other_name: "56"}
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
        with patch.object(storage, "list_project_live", side_effect=inventory), patch.object(
                storage, "delete_project_live", side_effect=remove):
            project_deletion.execute(self.claim(job))
            receipt = project_deletion.status(self.owner, job)
            self.assertEqual((receipt["status"], receipt["attempts"], receipt["retryable"]),
                             ("delete_error", 1, True))
            self.assertNotIn(name, live)
            self.assertIn(clip_name, live)
            self.assertIsNone(self.claim(job))
            # The database clock is real. Advance only this fixture's retry eligibility.
            with self.engine.begin() as connection:
                connection.execute(text("UPDATE cloud_project_deletions SET retry_at=clock_timestamp() WHERE job_id=:j"),
                                   {"j": job})
            project_deletion.execute(self.claim(job))

        receipt = project_deletion.status(self.owner, job)
        self.assertEqual((receipt["status"], receipt["attempts"]), ("deleted", 1))
        self.assertEqual(project_deletion.begin(self.owner, job), receipt)
        self.assertEqual(attempts, [name, clip_name, clip_name])
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

    def test_legacy_upload_waits_out_untracked_capability_and_rejects_confirmation(self):
        deadline = time.time()+30
        job = self.fixture(self.owner, "awaiting_upload", upload_tracking=False, upload_expires_at=deadline)
        deletion = project_deletion.begin(self.owner, job)
        self.assertAlmostEqual(deletion["retry_at"], deadline+project_deletion.UPLOAD_CAPABILITY_SECONDS, places=4)
        self.assertIsNone(self.claim(job))
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
              patch.object(storage, "list_project_live", return_value=[])):
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
              patch.object(storage, "list_project_live", side_effect=[[item], []]),
              patch.object(storage, "delete_project_live") as remove):
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
