"""Isolated contract regressions with mocks; these are not cloud acceptance."""
from __future__ import annotations

import hashlib
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from app.cloud import config, storage, repository
from app.cloud import dispatch


LOCAL = {"CLIPFORGE_CLOUD_LOCAL_TEST": "1", "CLIPFORGE_AUTH_PROFILE": "local-http",
         "CLIPFORGE_GCS_ENDPOINT": "http://gcs:4443", "CLIPFORGE_GCS_BUCKET": "synthetic-e2e",
         "CLIPFORGE_JOBS_DISPATCH_MODE": "local_manual"}
SECURE = {"CLIPFORGE_AUTH_PROFILE": "secure", "CLIPFORGE_GCS_BUCKET": "synthetic-int",
          "CLIPFORGE_CLOUD_PROJECT": "clipforgebeta2", "CLIPFORGE_CLOUD_REGION": "us-central1",
          "CLIPFORGE_CLOUD_JOB": "clipforge-int-worker"}


class ConfigurationTests(unittest.TestCase):
    def test_local_manual_and_emulator_require_explicit_local_profile(self):
        with patch.dict(os.environ, LOCAL, clear=True):
            self.assertTrue(config.settings().local_test)
        for update in ({"CLIPFORGE_CLOUD_LOCAL_TEST": "0"}, {"CLIPFORGE_AUTH_PROFILE": "secure"},
                       {"CLIPFORGE_ENV": "int"}, {"CLIPFORGE_ENVIRONMENT": "INT"}):
            with self.subTest(update=update), patch.dict(os.environ, {**LOCAL, **update}, clear=True):
                with self.assertRaises(ValueError):
                    config.settings()

    def test_secure_runtime_requires_complete_jobs_identity_and_real_storage(self):
        with patch.dict(os.environ, SECURE, clear=True):
            self.assertEqual(config.settings().endpoint, "https://storage.googleapis.com")
        for update in ({"CLIPFORGE_CLOUD_PROJECT": ""}, {"CLIPFORGE_CLOUD_JOB": ""},
                       {"CLIPFORGE_GCS_ENDPOINT": "http://gcs:4443"}, {"CLIPFORGE_JOBS_DISPATCH_MODE": "local_manual"}):
            with self.subTest(update=update), patch.dict(os.environ, {**SECURE, **update}, clear=True):
                with self.assertRaises(ValueError):
                    config.settings()

    def test_storage_endpoint_cannot_embed_credentials_query_or_path(self):
        for endpoint in ("http://user:secret@gcs:4443", "http://gcs:4443/private", "http://gcs:4443?key=authored", "http://gcs:4443#fragment"):
            with self.subTest(endpoint=endpoint), patch.dict(os.environ, {**LOCAL, "CLIPFORGE_GCS_ENDPOINT": endpoint}, clear=True):
                with self.assertRaises(ValueError):
                    config.settings()

    def test_local_dispatch_never_uses_cloud_identity_or_database(self):
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(dispatch, "get_engine") as engine, patch.object(dispatch, "request") as request:
            self.assertEqual(dispatch.reconcile(), {"status": "local_manual", "dispatched": 0})
            engine.assert_not_called()
            request.assert_not_called()


class ObjectIntegrityTests(unittest.TestCase):
    def response(self, payload):
        response = MagicMock()
        response.json.return_value = payload
        return response

    def test_upload_is_create_only_and_records_generation_size_and_digest(self):
        data = b"synthetic media only"
        response = self.response({"name": "workspaces/abc/original/123.mp4", "generation": "12", "size": str(len(data))})
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(storage, "request", return_value=response) as request, patch.object(storage, "close"):
            manifest = storage.upload("workspaces/abc/original/123.mp4", io.BytesIO(data), "video/mp4")
        self.assertEqual(request.call_args.kwargs["params"]["ifGenerationMatch"], "0")
        self.assertEqual(manifest["sha256"], hashlib.sha256(data).hexdigest())
        self.assertEqual((manifest["generation"], manifest["bytes"]), ("12", len(data)))

    def test_upload_metadata_mismatch_cannot_publish_manifest(self):
        for payload in ({"name": "wrong", "generation": "12", "size": "4"},
                        {"name": "safe/item", "generation": "", "size": "4"},
                        {"name": "safe/item", "generation": "12", "size": "99"}):
            with self.subTest(payload=payload), patch.dict(os.environ, LOCAL, clear=True), patch.object(storage, "request", return_value=self.response(payload)), patch.object(storage, "close") as close:
                with self.assertRaises(storage.StorageError):
                    storage.upload("safe/item", io.BytesIO(b"data"), "video/mp4")
                close.assert_called_once()

    def test_reads_pin_generation_and_validate_single_range(self):
        item = {"name": "workspaces/abc/tasks/123/1/clip.mp4", "generation": "42"}
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(storage, "request") as request:
            storage.open_object(item, "bytes=0-1023")
            self.assertEqual(request.call_args.kwargs["params"], {"alt": "media", "generation": "42"})
            self.assertEqual(request.call_args.kwargs["headers"], {"Range": "bytes=0-1023"})
            for invalid in ("bytes=0-1,4-5", "0-1023", "bytes=garbage", "bytes=-"):
                with self.subTest(invalid=invalid), self.assertRaises(storage.StorageError):
                    storage.open_object(item, invalid)

    def test_download_rejects_truncation_extra_bytes_and_changed_content(self):
        item = {"name": "safe/item", "generation": "42", "bytes": 4, "sha256": hashlib.sha256(b"data").hexdigest()}
        for chunks in ([b"dat"], [b"data", b"extra"], [b"evil"]):
            with self.subTest(chunks=chunks), tempfile.TemporaryDirectory() as temporary:
                response = MagicMock()
                response.iter_content.return_value = iter(chunks)
                with patch.object(storage, "open_object", return_value=response), patch.object(storage, "close") as close:
                    with self.assertRaises(storage.StorageError):
                        storage.download(item, Path(temporary) / "copy.mp4")
                    close.assert_called_once_with(response)

    def test_emulator_requests_never_fetch_metadata_credentials(self):
        session = MagicMock()
        session.request.return_value.status_code = 200
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(storage.requests, "Session", return_value=session), patch.object(storage, "token") as token:
            storage.request("GET", "http://gcs:4443/storage/v1/b")
        token.assert_not_called()
        self.assertFalse(session.trust_env)
        self.assertNotIn("Authorization", session.request.call_args.kwargs["headers"])

    def test_staged_delete_is_generation_conditional_and_refuses_originals(self):
        prefix = "workspaces/" + "a" * 32 + "/jobs/" + "b" * 32 + "/tasks/" + "c" * 32 + "/"
        staged = {"name": prefix + "1/clip.mp4", "generation": "42"}
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(storage, "request") as request, patch.object(storage, "close"):
            storage.delete_staged(staged, prefix)
            self.assertEqual(request.call_args.kwargs["params"], {"generation": "42", "ifGenerationMatch": "42"})
            self.assertEqual(request.call_args.args[0], "DELETE")
            with self.assertRaises(storage.StorageError):
                storage.delete_staged({"name": "workspaces/" + "a" * 32 + "/jobs/" + "b" * 32 + "/original/input.mp4", "generation": "42"}, prefix)
        self.assertEqual(request.call_count, 1)

    def test_delete_accepts_204_without_weakening_other_status_checks(self):
        session = MagicMock()
        session.request.return_value.status_code = 204
        with patch.dict(os.environ, LOCAL, clear=True), patch.object(storage.requests, "Session", return_value=session):
            storage.request("DELETE", "http://gcs:4443/storage/v1/b/synthetic/o/file")
            with self.assertRaises(storage.StorageError):
                storage.request("GET", "http://gcs:4443/storage/v1/b/synthetic/o/file")


class PublicationContractTests(unittest.TestCase):
    def test_lost_lease_prevents_final_document_and_task_publication(self):
        connection = MagicMock()
        connection.execute.return_value.mappings.return_value.first.return_value = None
        with patch.object(repository, "get_engine") as engine, patch.object(repository, "update_document") as update:
            engine.return_value.begin.return_value.__enter__.return_value = connection
            with self.assertRaises(RuntimeError):
                repository.finish_task({"id": "a" * 32, "job_id": "b" * 32, "kind": "export", "item_id": "c" * 32, "fence": 2},
                    {"id": "c" * 32, "status": "completed"}, {"clip.mp4": {"generation": "1"}})
        update.assert_not_called()
        self.assertEqual(connection.execute.call_count, 1)

    def test_in_progress_work_never_publishes_completed_status_or_clips(self):
        task = {"id": "a" * 32, "job_id": "b" * 32, "kind": "process", "item_id": "b" * 32, "fence": 1}
        context = {"task": task, "staged": None}
        token = repository.CURRENT_TASK.set(context)
        try:
            payload = {"id": "b" * 32, "status": "completed", "clips": [{"file": "clip_01.mp4"}]}
            with patch.object(repository, "get_engine"), patch.object(repository, "worker_guard"), patch.object(repository, "update_document") as update:
                repository.worker_progress("b" * 32, "job", payload)
            self.assertEqual(update.call_args.args[3]["status"], "rendering")
            self.assertEqual(update.call_args.args[3]["clips"], [])
            self.assertEqual(context["staged"], payload)
            self.assertEqual(payload["status"], "completed")
        finally:
            repository.CURRENT_TASK.reset(token)

    def test_worker_cannot_mutate_another_job_or_document_kind(self):
        task = {"job_id": "b" * 32, "kind": "process", "item_id": "b" * 32}
        token = repository.CURRENT_TASK.set({"task": task})
        try:
            for job, kind, item in (("c" * 32, "job", "c" * 32), ("b" * 32, "export", "b" * 32), ("b" * 32, "job", "c" * 32)):
                with self.subTest(job=job, kind=kind, item=item), self.assertRaises(RuntimeError):
                    repository.worker_progress(job, kind, {"id": item})
        finally:
            repository.CURRENT_TASK.reset(token)


if __name__ == "__main__":
    unittest.main()
