"""Exact D03 target, consent, shared budget and durable manual text regressions."""
from datetime import datetime, timezone
import hashlib
import json
import os
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth
from app.ai_provider import AIError, build_payload
from app.auth_db import reset_engine
from app.cloud import clip_captions, migrate_beta, project_deletion, publication as pub, repository as repo, worker
from app.presentation import Presentation
from auth_support import auth_environment, prepare_database


SETTINGS = {"CLIPFORGE_AI_PROVIDER": "openai", "CLIPFORGE_AI_MODEL": "publication-fixture",
            "CLIPFORGE_AI_CONFIG_REVISION": "1", "CLIPFORGE_AI_TIMEOUT_SECONDS": "40",
            "CLIPFORGE_AI_DAILY_LIMIT": "100", "CLIPFORGE_INT_BETA": "1"}
CUES = [{"start": 0.1, "end": 2.3, "text": "Recolección de agua de lluvia para el huerto."}]
RESPONSE = {"titles": ["Agua para el huerto", "Cómo aprovechar la lluvia"],
            "description": "Recolectar agua de lluvia para el huerto.", "hashtags": ["#Huerto", "#Lluvia"]}


class PublicationValidationTests(unittest.TestCase):
    def test_response_contract_rejects_invented_numbers_and_links(self):
        source = {"clip_text": CUES, "instructions": ""}
        self.assertEqual(pub._validated_suggestions(RESPONSE, source), RESPONSE)
        for content in ("Ahorra 1000 dólares", "https://otro.example/patrocinio"):
            with self.subTest(content=content), self.assertRaises(AIError) as rejected:
                pub._validated_suggestions({**RESPONSE, "description": content}, source)
            self.assertEqual(rejected.exception.code, "AI_PUBLICATION_UNSUPPORTED")
        with self.assertRaises(AIError) as rejected:
            pub._validated_suggestions({**RESPONSE, "titles": [""]}, source)
        self.assertEqual(rejected.exception.code, "AI_PUBLICATION_INVALID")


class PublicationDatabaseTests(unittest.TestCase):
    def setUp(self):
        if os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires an explicitly disposable PostgreSQL test database")
        self.schema = "auth01_test_publication_" + secrets.token_hex(8)
        state = patch.dict(os.environ, {**auth_environment(), **SETTINGS,
                                        "CLIPFORGE_DATABASE_SCHEMA": self.schema}, clear=True)
        state.start()
        self.addCleanup(state.stop)
        reset_engine()
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["publication_status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["publication_status"], "current")
        self.owner = auth.create_user("qa_publication_owner", secrets.token_urlsafe(32))
        self.visitor = auth.create_user("qa_publication_visitor", secrets.token_urlsafe(32))
        self.job = secrets.token_hex(16)
        auth.register_project(self.job, self.owner)
        self.prefix = f"workspaces/{self.owner.workspace_id}/jobs/{self.job}/tasks/"
        self.options = Presentation(burn_subtitles=True).model_dump()
        self.automatic = {"file": "clip_01.mp4", "start": 10, "end": 14, "title": "Un huerto",
                          "options": self.options, "cues": CUES, "caption_rendered": True}
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job, "job", {
                "id": self.job, "pilot": True, "status": "completed", "language": "es",
                "media": {"duration_seconds": 1200}, "clips": [self.automatic], "options": self.options,
            }, {"input.mp4": self.object("original.mp4"), "clip_01.mp4": self.object("automatic/clip_01.mp4"),
                "transcript.json": self.object("transcript.json")})
        self.first = self.create_export()

    def remove_schema(self):
        if not self.schema.startswith("auth01_test_publication_"):
            raise ValueError("Unexpected QA schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def object(self, filename):
        return {"name": self.prefix + filename, "generation": "11", "bytes": 2,
                "sha256": hashlib.sha256(filename.encode()).hexdigest(), "content_type": "video/mp4"}

    def create_export(self, *, start=10, end=14, captions=CUES, origin=None, status="completed"):
        identity = secrets.token_hex(16)
        item = {"id": identity, "job_id": self.job, "pilot": True, "status": status,
                "title": "Fragmento manual", "clip_file": "manual.mp4", "start": start, "end": end, "cues": captions}
        if origin:
            item.update(draft_id=secrets.token_hex(16), draft_revision=3, selection_origin=origin,
                        title="Una apariencia distinta", options={**self.options, "subtitle_color": "#FFFF00"})
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job, "export", item, {"clip.mp4": self.object(identity + "/clip.mp4")})
        return f"export:{identity}:1"

    def preview(self, selection=None, **kwargs):
        return pub.preview(self.job, pub.PreviewRequest(selection=selection or self.first, **kwargs), self.owner)

    def request(self, preview):
        return pub.SuggestionRequest(selection=preview["selection"], preview_token=preview["preview_token"],
                                     request_id=secrets.token_hex(16), consent=True)

    def save(self, selection=None, revision=0, **fields):
        return pub.save(self.job, pub.SaveRequest(selection=selection or self.first, revision=revision,
                                                title="Título manual", **fields), self.owner)

    def claim(self, item):
        task = worker._claim(None)
        self.assertEqual((task["kind"], task["item_id"]), (pub.SUGGESTION, item["id"]))
        return task

    def execute(self, task, responder):
        with (patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-provider-credential"}),
              patch.object(pub, "request_selection", side_effect=responder) as provider,
              patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True))):
            worker.execute(task["id"], task["fence"])
        provider.assert_called_once()

    def test_manual_write_reuse_and_current_targets(self):
        automatic = repo.document(self.job)
        variant = clip_captions.clip_context(automatic, self.automatic["file"])["output"]["id"]
        automatic_key = f"clip_01.mp4:1:{variant}"
        self.assertEqual(pub.read(self.job, automatic_key, self.owner)["target"]["kind"], "automatic")
        saved = self.save(language="en", description="Primera línea.\nSegunda.", hashtags=["huerto", "#HUERTO"])
        rendered = pub.text_bytes(saved).decode()
        self.assertEqual(rendered, "Título\nTítulo manual\n\nDescripción\nPrimera línea.\nSegunda.\n\nHashtags\n#huerto\n")
        self.assertEqual(saved["language"], "en")
        self.assertEqual(pub.index(self.job, self.owner), {"saved": [{"selection": self.first, "revision": 1}]})
        with self.assertRaises(HTTPException) as stale:
            self.save()
        self.assertEqual(stale.exception.status_code, 409)
        with self.assertRaises(HTTPException) as foreign:
            pub.read(self.job, self.first, self.visitor)
        self.assertEqual(foreign.exception.status_code, 404)
        same = self.create_export(origin={"mode": "transcript"})
        state = pub.read(self.job, same, self.owner)
        self.assertEqual(state["target"]["kind"], "transcript")
        self.assertIsNone(state["saved"])
        self.assertEqual(state["reusable"], [{"selection": self.first, "revision": 1, "title": "Título manual"}])
        old = pub.ReuseRequest(selection=same, revision=0, source_selection=self.first, source_revision=1)
        copied = pub.reuse(self.job, old, self.owner)
        self.assertEqual(pub.text_bytes(copied), pub.text_bytes(saved))
        self.assertEqual(copied["reused_from"]["selection"], self.first)
        changed = self.create_export(start=11)
        self.assertEqual(pub.read(self.job, changed, self.owner)["reusable"], [])
        with self.assertRaises(HTTPException) as wrong:
            pub.reuse(self.job, old.model_copy(update={"selection": changed}), self.owner)
        self.assertEqual(wrong.exception.status_code, 409)
        pending = self.create_export(status="queued")
        with self.assertRaises(HTTPException) as unready:
            pub.read(self.job, pending, self.owner)
        self.assertEqual(unready.exception.status_code, 409)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one(), 0)

    def test_fallback_excludes_neighboring_and_partial_source_passages(self):
        selection = self.create_export(captions=[])
        rows = [{"start": 9, "end": 11, "text": "Tema previo."},
                {"start": 11, "end": 13, "text": "Agua para el huerto."},
                {"start": 13, "end": 15, "text": "Tema posterior."}]
        with patch.object(pub.editorial_selection, "transcript_segments", return_value=rows):
            preview = self.preview(selection)
        self.assertEqual(preview["payload_text"]["context_source"], "transcript")
        self.assertEqual(preview["payload_text"]["clip_text"], [{"start": 1, "end": 3, "text": "Agua para el huerto."}])
        with (patch.object(pub.editorial_selection, "transcript_segments", return_value=[rows[0]]),
              self.assertRaises(HTTPException) as no_content):
            self.preview(selection)
        self.assertEqual(no_content.exception.status_code, 422)
        self.assertEqual(self.save(selection)["revision"], 1)

    def test_explicit_generation_dedupes_and_late_response_preserves_manual_save(self):
        with patch.object(pub, "request_selection") as provider:
            preview = self.preview()
            provider.assert_not_called()
        self.assertEqual(preview["payload_text"]["clip_text"], CUES)
        self.assertEqual(preview["language"], "es")
        config, _ = pub.editorial_selection.provider_config()
        wire = build_payload(config, preview["payload_text"])
        self.assertEqual(json.loads(wire["input"][0]["content"]), preview["payload_text"])
        self.assertEqual(wire["text"]["format"]["name"], "clipforge_publication")
        request = self.request(preview)
        with self.assertRaises(HTTPException) as refused:
            pub.suggest(self.job, request.model_copy(update={"consent": False}), self.owner)
        self.assertEqual(refused.exception.status_code, 422)
        with self.assertRaises(HTTPException) as stale:
            pub.suggest(self.job, request.model_copy(update={"language": "de"}), self.owner)
        self.assertEqual(stale.exception.status_code, 409)
        created = pub.suggest(self.job, request, self.owner)
        second = request.model_copy(update={"request_id": secrets.token_hex(16), "language": "es"})
        self.assertEqual(pub.suggest(self.job, second, self.owner)["id"], created["id"])
        task = self.claim(created)

        def responder(_config, _payload, *, receipt):
            self.save(hashtags=["#manual"])
            receipt["model"] = "publication-fixture-confirmed"
            return RESPONSE, {"total_tokens": 44}

        self.execute(task, responder)
        result = pub.read(self.job, self.first, self.owner)
        self.assertEqual(result["saved"]["title"], "Título manual")
        suggestion = result["suggestion"]
        self.assertEqual(suggestion["status"], "completed")
        self.assertEqual(suggestion["titles"], RESPONSE["titles"])
        self.assertEqual((suggestion["provider_calls_planned"], suggestion["provider_calls"], suggestion["provider_responses"]), (1, 1, 1))
        self.assertEqual(suggestion["provider_models_received"], ["publication-fixture-confirmed"])
        self.assertEqual(pub.suggest(self.job, request, self.owner)["id"], created["id"])
        attempt = request.model_copy(update={"new_attempt": True, "request_id": secrets.token_hex(16)})
        other = pub.suggest(self.job, attempt, self.owner)
        self.assertNotEqual(other["id"], created["id"])
        self.assertEqual(pub.suggest(self.job, attempt, self.owner)["id"], other["id"])

    def test_shared_quota_is_retained_after_late_worker_deletion(self):
        day = datetime.now(timezone.utc).date().isoformat()
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job, "selection", {
                "id": secrets.token_hex(16), "status": "completed", "day_utc": day, "provider_calls_planned": 1,
            })
        with patch.dict(os.environ, {"CLIPFORGE_AI_DAILY_LIMIT": "1"}):
            preview = self.preview()
            request = self.request(preview)
            with self.assertRaises(HTTPException) as quota:
                pub.suggest(self.job, request, self.owner)
        self.assertEqual(quota.exception.status_code, 429)
        queued = pub.suggest(self.job, request, self.owner)
        self.assertEqual(pub.suggest(self.job, request, self.owner)["id"], queued["id"])
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT planned FROM cloud_deleted_selection_calls")).scalar_one(), 1)
            self.assertEqual(self._d02_reserved(connection, day), 2)
        task = self.claim(queued)
        self.save()

        def responder(_config, _payload, **_options):
            project_deletion.begin(self.owner, self.job)
            return RESPONSE, {}

        with self.assertRaises(RuntimeError):
            self.execute(task, responder)
        self.assertEqual(repo.list_documents(self.job, pub.DOCUMENT), [])
        self.assertEqual(repo.list_documents(self.job, pub.SUGGESTION), [])
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT planned FROM cloud_deleted_selection_calls")).scalar_one(), 2)
            self.assertEqual(self._d02_reserved(connection, day), 2)

    def _d02_reserved(self, connection, day):
        return connection.execute(text("""
            SELECT COALESCE(sum(CAST(payload->>'provider_calls_planned' AS integer)),0)
                 + COALESCE((SELECT planned FROM cloud_deleted_selection_calls WHERE day_utc=CAST(CAST(:day AS text) AS date)),0)
            FROM cloud_documents WHERE kind='selection' AND payload->>'day_utc'=:day
            """), {"day": day}).scalar_one()
