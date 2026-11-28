"""Word marks, durable historical preparation and its project fences."""
import hashlib
import json
import os
from pathlib import Path
import secrets
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
import numpy as np
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth, transcribe
from app.auth_db import reset_engine
from app.cloud import migrate_beta, project_deletion, repository as repo, worker
from auth_support import auth_environment, prepare_database


def word(start, end, value):
    return SimpleNamespace(start=start, end=end, word=value)


class TranscriptionTests(unittest.TestCase):
    def test_pilot_requests_acoustic_words_and_preserves_segment_format(self):
        words = [word(np.float64(1100.12), np.float64(1100.47), " lluvia"),
                 word(np.float64(1101.14), np.float64(1101.65), " lluvia")]
        row = SimpleNamespace(start=np.float64(1100.04), end=np.float64(1101.72), text=" lluvia lluvia", words=words)
        audio = range(1200 * transcribe.SAMPLES_PER_SECOND)
        recorder = Mock()
        with (patch("faster_whisper.WhisperModel") as load,
              patch.object(transcribe, "beta_audio", return_value=audio),
              patch.object(transcribe, "resolve_model", return_value="/isolated/" + "a" * 40)):
            recognizer = load.return_value
            recognizer.transcribe.return_value = ([row], SimpleNamespace(language="es"))
            result = transcribe.transcribe_pilot(Path("original.mp4"), 1200, recorder)
            recognizer.transcribe.assert_called_once_with(audio, beam_size=1, vad_filter=True, word_timestamps=True)
            legacy = transcribe.transcribe_pilot(Path("original.mp4"), 1200, recorder, word_timestamps=False)
            recognizer.transcribe.assert_called_with(audio, beam_size=1, vad_filter=True)
        self.assertEqual(result.segments, [{"start": 1100.04, "end": 1101.72, "text": "lluvia lluvia"}])
        self.assertEqual(legacy.segments, result.segments)
        self.assertIsNone(legacy.alignment)
        self.assertEqual(result.alignment["model_revision"], "a" * 40)
        self.assertEqual(result.alignment["segments"][0]["words"], [
            {"start": 1100.12, "end": 1100.47, "text": "lluvia"},
            {"start": 1101.14, "end": 1101.65, "text": "lluvia"},
        ])
        self.assertIs(type(result.alignment["segments"][0]["words"][0]["start"]), float)

    def test_incomplete_unordered_or_out_of_range_words_use_segment_granularity(self):
        segment = {"start": 100, "end": 103, "text": "dos palabras"}
        invalid = [
            [word(100, 101, " dos")],
            [word(100, 102, " dos"), word(101, 103, " palabras")],
            [word(99, 101, " dos"), word(101, 103, " palabras")],
            [word(100, float("nan"), " dos"), word(101, 103, " palabras")],
            [word(100, 101, " dos"), word(102, 104, " palabras")],
        ]
        for marks in invalid:
            with self.subTest(marks=marks):
                self.assertEqual(transcribe.aligned_words(marks, segment), [])
        marks = [word(100, 100.58, " dos"), word(101.44, 102.16, " palabras")]
        good = {**segment, "words": transcribe.aligned_words(marks, segment)}
        with TemporaryDirectory() as directory:
            artifact = Path(directory) / transcribe.ALIGNMENT_FILE
            self.assertFalse(transcribe.write_alignment(artifact, {"segments": [{**segment, "words": []}]}))
            self.assertFalse(transcribe.write_alignment(artifact, {"segments": [good, {**good, "start": 99}]}))
            self.assertFalse(artifact.exists())
            self.assertTrue(transcribe.write_alignment(artifact, {"segments": [good]}))


class TranscriptQueueTests(unittest.TestCase):
    def setUp(self):
        if os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires an explicitly disposable PostgreSQL test database")
        schema = "auth01_test_alignment_" + secrets.token_hex(8)
        scratch = self.enterContext(TemporaryDirectory(prefix="transcript-processing-"))
        state = patch.dict(os.environ, {**auth_environment(), "CLIPFORGE_INT_BETA": "1",
                                        "CLIPFORGE_DATABASE_SCHEMA": schema,
                                        "CLIPFORGE_DATA_DIR": scratch}, clear=True)
        state.start()
        self.addCleanup(state.stop)
        reset_engine()
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.drop_schema, schema)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["alignment_status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["alignment_status"], "current")
        self.owner = auth.create_user("qa_alignment_owner", secrets.token_urlsafe(32))
        self.visitor = auth.create_user("qa_alignment_visitor", secrets.token_urlsafe(32))
        self.job_id = secrets.token_hex(16)
        auth.register_project(self.job_id, self.owner)
        segments = [{"start": 1100.01, "end": 1103.23, "text": "Texto de la transcripción histórica."}]
        raw = repo.packed(segments).encode()
        self.original_manifest = {"input.mp4": {"generation": "11", "bytes": 123, "name": "fixture/input.mp4"},
                                  "transcript.json": {"generation": "12", "bytes": len(raw), "name": "fixture/transcript.json",
                                                      "sha256": hashlib.sha256(raw).hexdigest()}}
        self.job = {"id": self.job_id, "status": "completed", "pilot": True,
                    "media": {"duration_seconds": 1200}, "clips": [{"file": "clip_01.mp4"}]}
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job_id, "job", self.job, self.original_manifest)
        self.aligned = {"schema": 1, "method": transcribe.ALIGNMENT_METHOD,
                        "model_revision": "b" * 40, "transcriber_version": "1.1.1", "segments": [
                            {"start": 1100.02, "end": 1101.32, "text": "Texto nuevo",
                             "words": [{"start": 1100.02, "end": 1100.5, "text": "Texto"},
                                       {"start": 1101.0, "end": 1101.32, "text": "nuevo"}]}]}

    def drop_schema(self, schema):
        if not schema.startswith("auth01_test_alignment_"):
            raise ValueError("Unexpected QA schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))

    def claim(self, run):
        task = worker._claim(None)
        self.assertEqual((task["kind"], task["item_id"]), ("alignment", run["id"]))
        return task

    def result(self):
        return transcribe.PilotTranscript([], self.aligned, "es", 1200)

    def upload(self, name, opened, mime):
        raw = opened.read()
        self.assertTrue(name.endswith("/" + transcribe.ALIGNMENT_FILE))
        self.assertEqual(mime, "application/json")
        self.assertEqual(json.loads(raw), self.aligned)
        return {"name": name, "generation": "13", "bytes": len(raw),
                "sha256": hashlib.sha256(raw).hexdigest()}

    def test_historical_preparation_deduplicates_retries_and_keeps_original(self):
        with self.assertRaises(HTTPException) as inaccessible:
            repo.prepare_alignment(self.job_id, self.visitor)
        self.assertEqual(inaccessible.exception.status_code, 404)
        queued = repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual(repo.prepare_alignment(self.job_id, self.owner)["id"], queued["id"])
        with self.assertRaises(HTTPException) as busy, self.engine.begin() as connection:
            repo.admit_beta(connection, self.owner.id)
        self.assertEqual(busy.exception.status_code, 409)
        task = self.claim(queued)
        with (patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(worker.storage, "download", side_effect=worker.storage.TransportError("fixture"))):
            worker.execute(task["id"], task["fence"])
        failed = repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual((failed["id"], failed["status"], failed["retryable"]), (queued["id"], "failed", True))
        self.assertEqual(failed["error_code"], "ALIGNMENT_TRANSPORT")
        with patch.object(worker.storage, "list_staged", return_value=[]):
            worker.cleanup_failed()
        retry = repo.prepare_alignment(self.job_id, self.owner, retry=True)
        self.assertEqual((retry["id"], retry["status"], retry["retry_count"]), (queued["id"], "queued", 1))
        repeated = self.claim(retry)
        self.assertEqual(repeated["id"], task["id"])
        self.assertGreater(repeated["fence"], task["fence"])
        with (patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(worker.storage, "download"),
              patch.object(worker.storage, "upload", side_effect=self.upload) as upload,
              patch.object(worker, "transcribe_pilot", return_value=self.result())):
            worker.execute(repeated["id"], repeated["fence"])
        upload.assert_called_once()
        saved = repo.alignment_document(self.job_id, queued["source_fingerprint"])
        self.assertEqual((saved["payload"]["status"], saved["payload"]["word_segments"]), ("completed", 1))
        self.assertEqual(saved["payload"]["source_fingerprint"], queued["source_fingerprint"])
        self.assertEqual(set(saved["manifest"]), {transcribe.ALIGNMENT_FILE})
        self.assertEqual(repo.prepare_alignment(self.job_id, self.owner)["id"], queued["id"])
        self.assertEqual(repo.document(self.job_id)["manifest"], self.original_manifest)
        self.assertEqual(repo.document(self.job_id)["payload"], self.job)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one(), 1)
            self.assertEqual(connection.execute(text("SELECT count(*) FROM cloud_documents WHERE kind='selection'")).scalar_one(), 0)

    def test_result_is_fenced_when_owner_removes_the_project_during_preparation(self):
        queued = repo.prepare_alignment(self.job_id, self.owner)
        task = self.claim(queued)

        def complete_late(*_args):
            self.assertEqual(project_deletion.begin(self.owner, self.job_id)["status"], "deleted")
            return self.result()

        with (patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(worker.storage, "download"), patch.object(worker.storage, "upload") as upload,
              patch.object(worker, "transcribe_pilot", side_effect=complete_late), self.assertRaises(RuntimeError)):
            worker.execute(task["id"], task["fence"])
        upload.assert_not_called()
        self.assertIsNone(repo.alignment_document(self.job_id, queued["source_fingerprint"]))
        with self.assertRaises(HTTPException) as inaccessible:
            repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual(inaccessible.exception.status_code, 404)

    def test_missing_original_has_no_retry(self):
        queued = repo.prepare_alignment(self.job_id, self.owner)
        task = self.claim(queued)
        with (patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(worker.storage, "download", side_effect=worker.storage.ObjectMissing("fixture")),
              patch.object(worker, "transcribe_pilot") as recognize):
            worker.execute(task["id"], task["fence"])
        recognize.assert_not_called()
        failed = repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual((failed["error_code"], failed["retryable"]), ("SOURCE_UNAVAILABLE", False))
        with self.assertRaises(HTTPException) as denied:
            repo.prepare_alignment(self.job_id, self.owner, retry=True)
        self.assertEqual(denied.exception.status_code, 409)

    def test_expired_lease_allows_one_reviewed_retry_on_the_same_task(self):
        def expire(task):
            with self.engine.begin() as connection:
                connection.execute(text("UPDATE cloud_tasks SET lease_until=clock_timestamp()-interval '1 second' WHERE id=:i"),
                                   {"i": task["id"]})
            self.assertIsNone(worker._claim(None))

        queued = repo.prepare_alignment(self.job_id, self.owner)
        first = self.claim(queued)
        expire(first)
        failed = repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual((failed["error_code"], failed["retryable"]), ("WORKER_INTERRUPTED", True))
        with patch.object(worker.storage, "list_staged", return_value=[]):
            worker.cleanup_failed()
        retry = repo.prepare_alignment(self.job_id, self.owner, retry=True)
        second = self.claim(retry)
        self.assertEqual(second["id"], first["id"])
        self.assertGreater(second["fence"], first["fence"])
        expire(second)
        failed = repo.prepare_alignment(self.job_id, self.owner)
        self.assertEqual((failed["error_code"], failed["retryable"]), ("WORKER_INTERRUPTED", False))
        with self.assertRaises(HTTPException) as denied:
            repo.prepare_alignment(self.job_id, self.owner, retry=True)
        self.assertEqual(denied.exception.status_code, 409)

    def test_normal_processing_publishes_the_sidecar_with_fresh_transcript_identity(self):
        from app import main

        source = {"input.mp4": self.original_manifest["input.mp4"]}
        with self.engine.begin() as connection:
            repo.update_document(connection, self.job_id, "job", {**self.job, "status": "queued", "clips": []}, manifest=source)
            repo.enqueue(connection, self.job_id, "process", self.job_id)
        task = worker._claim(None)
        self.assertEqual(task["kind"], "process")

        def process(job_id, **_options):
            folder = main.ROOT / job_id
            (folder / "transcript.json").write_text(repo.packed([{"start": 1, "end": 2, "text": "nuevo"}]), encoding="utf-8")
            self.assertTrue(transcribe.write_alignment(folder / transcribe.ALIGNMENT_FILE, self.aligned))
            repo.worker_progress(job_id, "job", {**self.job, "clips": []})

        def upload(name, opened, mime):
            if name.endswith("/" + transcribe.ALIGNMENT_FILE):
                return self.upload(name, opened, mime)
            raw = opened.read()
            return {"name": name, "generation": "17", "bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}

        with (patch.object(main, "ROOT", main.ROOT), patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(worker, "inspect_beta_media", return_value=self.job["media"]),
              patch.object(main, "_process", side_effect=process), patch.object(worker.storage, "download"),
              patch.object(worker.storage, "upload", side_effect=upload) as publish):
            worker.execute(task["id"], task["fence"])
        self.assertEqual(publish.call_count, 2)
        saved = repo.document(self.job_id)
        fingerprint = saved["payload"]["transcript_alignment"]["source_fingerprint"]
        self.assertEqual(fingerprint, {"source_generation": "11", "transcript_generation": "17",
                                       "source_duration": 1200, "transcript_sha256": saved["manifest"]["transcript.json"]["sha256"]})
        self.assertEqual(saved["manifest"][transcribe.ALIGNMENT_FILE]["generation"], "13")
        self.assertEqual(repo.prepare_alignment(self.job_id, self.owner), saved["payload"]["transcript_alignment"])
