"""Editorial regressions for source coverage, consent and durable publication."""

from concurrent.futures import ThreadPoolExecutor
import hashlib
import json
import os
import secrets
from threading import Barrier
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth
from app.ai_provider import AIConfig, AIError
from app.ai_selection import SelectionCreate, SelectionSpec, validate_answer
from app.auth_db import reset_engine
from app.cloud import editorial_selection as editor
from app.cloud import migrate_beta, repository, router, worker
from auth_support import auth_environment, prepare_database


SETTINGS = {"CLIPFORGE_AI_PROVIDER": "openai", "CLIPFORGE_AI_MODEL": "editorial-fixture",
            "CLIPFORGE_AI_CONFIG_REVISION": "3", "CLIPFORGE_AI_TIMEOUT_SECONDS": "40"}


def transcript(duration=1200):
    return [{"id": start // 3 + 1, "start": start, "end": start + 3,
             "text": f"En el segundo {start}, la conversación explica una decisión y su motivo."}
            for start in range(0, duration, 3)]


def proposal(range_id):
    return {"range_id": range_id, "title": "Una decisión y su motivo",
            "reason": "Combina una decisión con la explicación que la precede.",
            "hook": 4, "clarity": 5, "completeness": 5}


class EditorialCatalogTests(unittest.TestCase):
    def test_complete_long_transcript_partitions_without_losing_times_or_text(self):
        rows = transcript()
        spec = SelectionSpec(max_clips=5)
        config = AIConfig("openai", "fixture", "https://api.openai.com/v1/responses",
                          timeout=40, max_input_chars=26000)
        windows = editor.planned_windows(rows, spec, 1200, config)
        self.assertGreater(len(windows), 1)
        self.assertLessEqual(len(windows), editor.MAX_CALLS)
        self.assertEqual({row["id"] for window in windows for row in window["content"]["segments"]},
                         {row["id"] for row in rows})
        summaries = [window["summary"] for window in windows]
        self.assertEqual((summaries[0]["start"], summaries[-1]["end"]), (0, 1200))
        self.assertTrue(all(a["end"] == b["start"] for a, b in zip(summaries, summaries[1:])))

        last = windows[-1]["content"]
        choices = last["eligible_ranges"]
        self.assertTrue(all(20 <= candidate["duration_seconds"] <= 60 for candidate in choices))
        selected = choices[-1]
        answer = {"summary": "Entrevista con una decisión explicada.",
                  "candidates": [proposal("r999_999"), proposal(selected["range_id"]), proposal(selected["range_id"])]}
        prepared = {"spec": spec.model_dump(), "content": last, "segments": rows}
        _, candidates, warnings = validate_answer(answer, prepared)
        self.assertEqual(len(candidates), 1)
        self.assertEqual((len(warnings), candidates[0]["end"]), (2, 1200))
        self.assertGreater(candidates[0]["start"], 1100)

    def test_preview_does_not_have_access_to_the_worker_credential(self):
        with patch.dict(os.environ, {**SETTINGS, "OPENAI_API_KEY": ""}, clear=False):
            config, first = editor.provider_config()
            self.assertTrue(editor.config_status()["enabled"])
            self.assertEqual(config.api_key, "")
            with self.assertRaises(AIError) as failed:
                editor.provider_config(worker=True)
            self.assertEqual(failed.exception.code, "AI_KEY_REQUIRED")
            with patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-provider-credential"}):
                worker_config, second = editor.provider_config(worker=True)
                self.assertNotEqual(worker_config.api_key, "")
                self.assertEqual(first, second)
            with patch.dict(os.environ, {"CLIPFORGE_AI_CONFIG_REVISION": "4"}):
                self.assertNotEqual(first, editor.provider_config()[1])

    def test_daily_reservation_increase_preserves_existing_int_consent_tokens(self):
        with patch.dict(os.environ, {**SETTINGS, "CLIPFORGE_AI_DAILY_LIMIT": "10",
                                     "OPENAI_API_KEY": "fixture-provider-credential"}):
            original, before = editor.provider_config()
            legacy = {"config": original.fingerprint(include_key=False),
                      "revision": SETTINGS["CLIPFORGE_AI_CONFIG_REVISION"]}
            self.assertEqual(before, hashlib.sha256(repository.packed(legacy).encode()).hexdigest())

            with patch.dict(os.environ, {"CLIPFORGE_AI_DAILY_LIMIT": "100"}):
                api, api_consent = editor.provider_config()
                worker_config, worker_consent = editor.provider_config(worker=True)
                self.assertEqual((api.daily_limit, worker_config.daily_limit), (100, 100))
                self.assertEqual(editor.config_status()["daily_limit"], 100)
                self.assertEqual((api_consent, worker_consent), (before, before))
                self.assertNotEqual(api.fingerprint(include_key=False), legacy["config"])

    def test_combines_windows_and_resolves_duplicates_and_overlaps_globally(self):
        def item(start, end, score):
            return {"start": start, "end": end, "criteria": {"clarity": score, "completeness": score, "hook": score}}

        candidates = [item(19, 45, 3), item(23, 50, 5), item(840, 870, 4), item(840, 870, 4)]
        selected = editor.combine_proposals(candidates, 5)
        self.assertEqual([(row["start"], row["id"]) for row in selected], [(23, "1"), (840, "2")])

    def test_persists_intervals_for_each_successful_provider_response(self):
        item = {"spec": SelectionSpec().model_dump(), "preview_token": "test-preview",
                "provider_calls_planned": 3, "provider_calls": 0, "provider_responses": 0,
                "provider_elapsed_seconds": 0.0, "provider_models_received": [], "usage": {}, "warnings": []}
        task = {"job_id": "test-job", "item_id": "test-selection"}
        prepared = {"preview_token": "test-preview", "config": Mock(), "batches": [{"content": {}}] * 3}
        clock = SimpleNamespace(
            time=Mock(side_effect=[9000, 9001, 9002, 9003, 9004]),
            monotonic=Mock(side_effect=[100, 101, 101.25, 102, 102.5, 103, 104, 104.25]),
        )
        snapshots = []

        def progress(_task, selection):
            snapshots.append((selection["provider_calls"], list(selection["provider_call_intervals"])))

        response = ({}, {})
        with (patch.object(editor.repo, "document", return_value={"payload": item}),
              patch.object(editor.repo, "finish_task") as finish,
              patch.object(editor, "prepare", return_value=prepared),
              patch.object(editor, "_progress", side_effect=progress),
              patch.object(editor, "time", clock),
              patch.object(editor, "request_selection", side_effect=[response, response, AIError("AI_TIMEOUT", "timeout")]),
              patch.object(editor, "validate_answer", return_value=("summary", [], []))):
            editor.execute_task(task)

        first = {"started_at": 9001, "finished_at": 9001.25}
        second = {"started_at": 9002, "finished_at": 9002.5}
        self.assertEqual(snapshots, [(0, []), (1, []), (1, [first]), (2, [first]),
                                     (2, [first, second]), (3, [first, second])])
        finish.assert_called_once_with(task, item, {})
        self.assertEqual(item["provider_call_intervals"], [first, second])
        self.assertEqual(item["provider_elapsed_seconds"], 1.75)
        self.assertEqual(item["provider_responses"], 2)
        self.assertEqual((item["status"], item["error_code"]), ("failed", "AI_TIMEOUT"))


class EditorialDatabaseTests(unittest.TestCase):
    def setUp(self):
        if os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires an explicitly disposable PostgreSQL test database")
        schema = "auth01_test_editorial_" + secrets.token_hex(8)
        env = {**auth_environment(), **SETTINGS, "CLIPFORGE_DATABASE_SCHEMA": schema,
               "CLIPFORGE_INT_BETA": "1", "CLIPFORGE_DATABASE_POOL_SIZE": "8"}
        state = patch.dict(os.environ, env, clear=True)
        state.start()
        self.addCleanup(state.stop)
        reset_engine()
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.drop_schema, schema)
        migrate_beta.upgrade_beta(self.engine)
        self.owner = auth.create_user("qa_editorial_owner", secrets.token_urlsafe(32))
        self.visitor = auth.create_user("qa_editorial_visitor", secrets.token_urlsafe(32))
        self.job_id = secrets.token_hex(16)
        auth.register_project(self.job_id, self.owner)
        self.raw = json.dumps(transcript(120)).encode()
        self.manifest = {"input.mp4": {"generation": "7", "bytes": 1000},
                         "transcript.json": {"generation": "8", "bytes": len(self.raw),
                                             "sha256": hashlib.sha256(self.raw).hexdigest()},
                         "clip_01.mp4": {"generation": "9", "bytes": 300}}
        with self.engine.begin() as connection:
            repository.insert_document(connection, self.job_id, "job", {
                "id": self.job_id, "status": "completed", "pilot": True, "clips": [{"file": "clip_01.mp4"}],
                "media": {"duration_seconds": 120}, "options": {},
            }, self.manifest)
        storage = patch.object(editor.storage, "open_object", side_effect=self.load_transcript)
        storage.start()
        self.addCleanup(storage.stop)

    def drop_schema(self, schema):
        if not schema.startswith("auth01_test_editorial_"):
            raise ValueError("Unexpected QA schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(schema, cascade=True))

    def load_transcript(self, item):
        self.assertEqual(item, self.manifest["transcript.json"])
        response = Mock()
        response.iter_content.return_value = [self.raw[:123], self.raw[123:]]
        return response

    def test_idempotent_selection_and_draft_keep_existing_clips(self):
        spec = SelectionSpec(brief="La justificación del final de la conversación", max_clips=3)
        preview = editor.preview(repository.document(self.job_id), spec)
        body = SelectionCreate(**spec.model_dump(), preview_token=preview["preview_token"],
                               consent=True, request_id=secrets.token_hex(16))
        with self.assertRaises(HTTPException) as refused:
            editor.create(self.job_id, body.model_copy(update={"consent": False}), self.owner)
        self.assertEqual(refused.exception.status_code, 422)
        with self.assertRaises(HTTPException) as forbidden:
            editor.create(self.job_id, body, self.visitor)
        self.assertEqual(forbidden.exception.status_code, 404)

        barrier = Barrier(2)

        def submit():
            barrier.wait(timeout=10)
            return editor.create(self.job_id, body, self.owner)

        with ThreadPoolExecutor(max_workers=2) as pool:
            other = pool.submit(submit)
            first = submit()
            self.assertEqual(first["id"], other.result(timeout=10)["id"])
        self.assertEqual(first["provider_call_intervals"], [])
        with self.engine.connect() as connection:
            task = worker._claim(connection)
            self.assertEqual((task["kind"], task["item_id"]), ("selection", first["id"]))

        def model(config, payload, *, receipt):
            receipt["model"] = "editorial-fixture-versioned"
            choice = payload["eligible_ranges"][-1]["range_id"]
            return {"summary": "La decisión final", "candidates": [proposal(choice)]}, {"total_tokens": 100}

        with (patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-provider-credential"}),
              patch.object(editor, "request_selection", side_effect=model) as call,
              patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
              patch.object(editor.storage, "download") as download):
            worker.execute(task["id"], task["fence"])
        download.assert_not_called()
        call.assert_called_once()
        with (patch.dict(os.environ, {"CLIPFORGE_AI_PROVIDER": "disabled"}),
              patch.object(editor.storage, "open_object") as read):
            analysis = editor.create(self.job_id, body, self.owner)
        read.assert_not_called()
        self.assertEqual((analysis["status"], analysis["provider_calls"], analysis["provider_responses"]),
                         ("completed", 1, 1))
        self.assertEqual(len(analysis["provider_call_intervals"]), 1)
        interval = analysis["provider_call_intervals"][0]
        self.assertLessEqual(interval["started_at"], interval["finished_at"])
        self.assertEqual(analysis["provider_models_received"], ["editorial-fixture-versioned"])
        request = SimpleNamespace(state=SimpleNamespace(principal=self.owner), headers={})
        draft = router.candidate_to_draft(self.job_id, analysis["id"], 1, request)
        again = router.candidate_to_draft(self.job_id, analysis["id"], 1, request)
        self.assertEqual(draft, again)
        self.assertGreater(draft["start"], 80)
        self.assertLessEqual(draft["cues"][-1]["end"], draft["end"] - draft["start"])
        self.assertEqual(draft["selection_origin"]["analysis_id"], analysis["id"])
        with patch.object(router, "reconcile", return_value={"status": "dispatched"}):
            payload = router.RevisionRequest(revision=draft["revision"])
            export = router.export_draft(self.job_id, draft["id"], payload, request)
            again = router.export_draft(self.job_id, draft["id"], payload, request)
        self.assertEqual(export, again)
        self.assertTrue(export["pilot"])
        current = repository.document(self.job_id)
        self.assertEqual(current["manifest"], self.manifest)
        self.assertEqual(current["payload"]["clips"], [{"file": "clip_01.mp4"}])
        with self.engine.connect() as connection:
            kinds = connection.execute(text("SELECT kind FROM cloud_tasks ORDER BY kind")).scalars().all()
            self.assertEqual(kinds, ["export", "selection"])
            self.assertTrue(migrate_beta.beta_schema_ready(connection))
            self.assertTrue(migrate_beta.editorial_schema_ready(connection))
