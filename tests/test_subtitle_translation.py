"""E02 consent and exact bilingual subtitle variants on disposable PostgreSQL."""
import hashlib
import json
import os
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth
from app.ai_provider import build_payload
from app.auth_db import reset_engine
from app.cloud import clip_captions, clip_package, migrate_beta, project_deletion, publication, repository as repo, router, translation, worker
from app.presentation import Presentation
from auth_support import auth_environment, prepare_database

ES = [{"start": .4, "end": 2.32, "text": "Elena no mezcló 12 litros."},
      {"start": 2.68, "end": 4.42, "text": "Guardó 3 botellas en Lima."}]
EN = [{"start": .4, "end": 2.32, "text": "Elena did not mix 12 liters."},
      {"start": 2.68, "end": 4.42, "text": "She kept 3 bottles in Lima."}]
ANSWER = {"cues": [{"id": f"c{i}", "text": row["text"]} for i, row in enumerate(EN, 1)]}


class TranslationContractTests(unittest.TestCase):
    def test_exact_response_ids_order_no_extra_fields_and_overflow_without_truncation(self):
        original = [{"id": f"c{i}", **row} for i, row in enumerate(ES, 1)]
        for invalid in (ANSWER["cues"][:1], list(reversed(ANSWER["cues"])),
                        [ANSWER["cues"][0]] * 2, [ANSWER["cues"][0], {"id": "c9", "text": "Other"}]):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                translation._merged_cues(original, translation.ProviderResult(cues=invalid).cues)
        with self.assertRaises(ValidationError):
            translation.ProviderResult(cues=[{**ANSWER["cues"][0], "start": 4}])
        long_text = "Keep the whole translation available to edit. " * 4
        values = translation.ProviderResult(cues=[{**ANSWER["cues"][0], "text": long_text}, ANSWER["cues"][1]])
        merged = translation._merged_cues(original, values.cues)
        self.assertEqual([(row["id"], row["start"], row["end"]) for row in merged],
                         [(row["id"], row["start"], row["end"]) for row in original])
        self.assertTrue(merged[0]["overflow"])
        self.assertEqual(merged[0]["text"], long_text.strip())


class TranslationDatabaseTests(unittest.TestCase):
    def setUp(self):
        if os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            self.skipTest("Requires explicitly disposable PostgreSQL")
        self.schema = "auth01_test_e02_" + secrets.token_hex(8)
        state = patch.dict(os.environ, {**auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": self.schema,
                                        "CLIPFORGE_INT_BETA": "1", "CLIPFORGE_AI_PROVIDER": "openai",
                                        "CLIPFORGE_AI_CONFIG_REVISION": "1", "CLIPFORGE_AI_MODEL": "translation-fixture",
                                        "CLIPFORGE_AI_DAILY_LIMIT": "100"}, clear=True)
        state.start()
        self.addCleanup(state.stop)
        reset_engine()
        self.addCleanup(reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["translation_status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["translation_status"], "current")
        self.user = auth.create_user("translation_owner", secrets.token_urlsafe(32))
        self.other = auth.create_user("translation_outsider", secrets.token_urlsafe(32))
        self.job = secrets.token_hex(16)
        auth.register_project(self.job, self.user)
        self.options = Presentation(burn_subtitles=True, subtitle_highlight_enabled=True,
                                    subtitle_color="#00FFFF", subtitle_highlight_color="#FF2800").model_dump()
        self.source = {"id": secrets.token_hex(16), "job_id": self.job, "revision": 1, "clip_file": None,
                       "title": "Prueba Elena", "start": 10.2, "end": 15.34, "options": self.options, "cues": ES,
                       "audio_language": "es", "subtitle_language": "es"}
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job, "job", {
                "id": self.job, "pilot": True, "status": "completed", "language": "es", "options": self.options,
                "media": {"duration_seconds": 120}, "clips": [],
            }, {"input.mp4": self.asset("original.mp4", "mp4")})
            repo.insert_document(connection, self.job, "draft", self.source)

    def remove_schema(self):
        if not self.schema.startswith("auth01_test_e02_"):
            raise ValueError("Unexpected QA schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def asset(self, name, kind):
        return {"name": f"workspaces/{self.user.workspace_id}/jobs/{self.job}/tasks/{name}",
                "generation": "123", "bytes": 18, "sha256": hashlib.sha256(name.encode()).hexdigest(),
                "content_type": clip_package.CONTENT_TYPES[kind]}

    def reference(self, source=None, languages=("es", "en"), *, kind="draft"):
        source = source or self.source
        return translation.PreviewRequest(source={"kind": kind, "id": source["id"], "revision": 1},
                                          source_language=languages[0], target_language=languages[1])

    def consent(self, preview, *, request=None, **overrides):
        view = translation.preview(self.job, preview, self.user)
        request = translation.TranslateRequest(**preview.model_dump(), preview_fingerprint=view["preview_fingerprint"],
                                               request_id=request or secrets.token_hex(16), consent=True)
        return view, request.model_copy(update=overrides)

    def draft_payload(self, texts=ANSWER):
        return translation.DraftRequest.model_validate({"title": "Elena traducido", **texts})

    def save(self, run, texts=ANSWER):
        return translation.save_draft(self.job, run["id"], self.draft_payload(texts), self.user, "test")

    def export(self, draft):
        item = {**draft, "id": secrets.token_hex(16), "draft_id": draft["id"], "draft_revision": draft["revision"],
                "status": "completed", "pilot": True}
        manifest = {f"clip.{kind}": self.asset(f"{item['id']}/clip.{kind}", kind) for kind in clip_package.CONTENT_TYPES}
        with self.engine.begin() as connection:
            repo.insert_document(connection, self.job, "export", item, manifest)
        return item, f"export:{item['id']}:1"

    def test_consent_replay_and_late_provider_preserve_saved_edit_and_source(self):
        with patch.object(translation, "request_selection") as model:
            preview, request = self.consent(self.reference())
            self.assertEqual(translation.index(self.job, self.user)["sources"], [preview["source"]])
            model.assert_not_called()
        config, _ = translation.editorial_selection.provider_config()
        wire = build_payload(config, preview["payload_text"])
        self.assertEqual(wire["input"][0]["content"], preview["text_to_send"])
        self.assertEqual(json.loads(preview["text_to_send"])["cues"], [
            {"id": f"c{i}", "text": row["text"]} for i, row in enumerate(ES, 1)
        ])
        with self.assertRaises(HTTPException) as no_consent:
            translation.submit(self.job, request.model_copy(update={"consent": False}), self.user)
        self.assertEqual(no_consent.exception.status_code, 422)
        run = translation.submit(self.job, request, self.user)
        for repeat in (request, request.model_copy(update={"request_id": secrets.token_hex(16)})):
            self.assertEqual(translation.submit(self.job, repeat, self.user)["id"], run["id"])
        waiting = translation.read(self.job, run["id"], self.user)
        self.assertEqual(waiting["source_cues"], preview["cues"])
        self.assertEqual((run["status"], run["provider_calls_planned"], run["provider_calls"]), ("queued", 1, 0))
        with self.assertRaises(HTTPException) as overlong:
            self.save(run, {"cues": [{**ANSWER["cues"][0], "text": "a" * 501}, ANSWER["cues"][1]]})
        self.assertEqual(overlong.exception.status_code, 422)
        self.assertIn("500", overlong.exception.detail)
        manual = {"cues": [{**ANSWER["cues"][0], "text": "Elena did not mix the 12 liters."}, ANSWER["cues"][1]]}
        saved = self.save(run, manual)
        self.assertFalse(saved["options"]["subtitle_highlight_enabled"])
        self.assertEqual(saved["options"]["subtitle_color"], self.source["options"]["subtitle_color"])
        self.assertEqual(saved["translation_origin"]["cue_ids"], ["c1", "c2"])
        self.assertEqual(self.save(run), saved)
        task = worker._claim(None)
        self.assertEqual((task["kind"], task["item_id"]), (translation.KIND, run["id"]))
        with (patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-provider-credential"}),
              patch.object(translation, "request_selection", return_value=(ANSWER, {"total_tokens": 21})) as provider):
            translation.execute_task(task, self.user.workspace_id)
            provider.assert_called_once()
        finished = translation.read(self.job, run["id"], self.user)
        self.assertEqual((finished["status"], finished["provider_calls"], finished["provider_responses"]), ("completed", 1, 1))
        self.assertEqual(finished["saved_draft"], {"id": saved["id"], "revision": 1})
        self.assertEqual(self.save(run), saved)
        self.assertTrue(repo.document(self.job, "draft", self.source["id"])["payload"]["options"]["subtitle_highlight_enabled"])
        self.assertEqual(translation.submit(self.job, request, self.user)["id"], run["id"])
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT planned FROM cloud_deleted_selection_calls")).scalar_one(), 1)

    def test_stale_source_request_quota_ownership_and_deleted_project(self):
        with patch.dict(os.environ, {"CLIPFORGE_AI_DAILY_LIMIT": "1"}):
            _, allowed = self.consent(self.reference())
            with self.engine.begin() as connection:
                repo.update_document(connection, self.job, "draft", {**self.source, "revision": 2, "title": "Editado"})
            with self.assertRaises(HTTPException) as stale:
                translation.submit(self.job, allowed, self.user)
            self.assertEqual(stale.exception.status_code, 409)
            preview = self.reference()
            preview.source.revision = 2
            _, allowed = self.consent(preview)
            run = translation.submit(self.job, allowed, self.user)
            attempt = allowed.model_copy(update={"new_attempt": True, "request_id": secrets.token_hex(16)})
            with self.assertRaises(HTTPException) as foreign:
                translation.read(self.job, run["id"], self.other)
            self.assertEqual(foreign.exception.status_code, 404)
            task = worker._claim(None)
            with self.engine.begin() as connection:
                connection.execute(text("UPDATE cloud_tasks SET lease_until=clock_timestamp()+interval '1 minute' WHERE id=:i"),
                                   {"i": task["id"]})
            with patch.dict(os.environ, {"OPENAI_API_KEY": "fixture-provider-credential"}):
                with patch.object(translation, "request_selection", return_value=(ANSWER, {})):
                    translation.execute_task(task, self.user.workspace_id)
            with self.assertRaises(HTTPException) as quota:
                translation.submit(self.job, attempt, self.user)
            self.assertEqual(quota.exception.status_code, 429)
        project_deletion.begin(self.user, self.job)
        with self.assertRaises(HTTPException) as gone:
            translation.save_draft(self.job, run["id"], self.draft_payload(), self.user, "test")
        self.assertEqual(gone.exception.status_code, 404)
        with self.engine.connect() as connection:
            self.assertEqual(connection.execute(text("SELECT planned FROM cloud_deleted_selection_calls")).scalar_one(), 1)

    def test_two_languages_static_revision_zip_and_explicit_d03_source_reuse(self):
        original, source_token = self.export({**self.source, "cues": EN, "audio_language": "en", "subtitle_language": "en"})
        prior = publication.save(self.job, publication.SaveRequest(
            selection=source_token, revision=0, language="en", title="Elena in Lima",
        ), self.user)
        preview, request = self.consent(self.reference(original, ("en", "es"), kind="export"))
        self.assertEqual((preview["source_language"], preview["target_language"], preview["audio_language"]), ("en", "es", "en"))
        run = translation.submit(self.job, request, self.user)
        draft = self.save(run, {"cues": [{"id": f"c{i}", "text": row["text"]} for i, row in enumerate(ES, 1)]})
        request = SimpleNamespace(state=SimpleNamespace(principal=self.user))
        input_options = {**draft["options"], "subtitle_highlight_enabled": True}
        payload = router.CloudDraftUpdate(revision=1, title=draft["title"], clip_file=None,
                                          start=draft["start"], end=draft["end"], options=input_options, cues=draft["cues"])
        updated = router.update_draft(self.job, draft["id"], payload, request)
        self.assertFalse(updated["options"]["subtitle_highlight_enabled"])
        self.assertNotIn("word_highlight", updated)
        with self.assertRaises(HTTPException) as changed:
            router.update_draft(self.job, draft["id"], payload.model_copy(update={"revision": 2, "end": 15.5}), request)
        self.assertEqual(changed.exception.status_code, 422)
        copied, translated_token = self.export(updated)
        current = publication.read(self.job, translated_token, self.user)
        self.assertIsNone(current["saved"])
        self.assertEqual(current["target"]["language"], "es")
        self.assertEqual(current["reusable"][0]["language"], "en")
        reused = publication.reuse(self.job, publication.ReuseRequest(
            selection=translated_token, revision=0, source_selection=source_token, source_revision=1,
        ), self.user)
        self.assertEqual((reused["language"], reused["title"]), (prior["language"], prior["title"]))
        self.assertTrue(reused["reused_from"]["translated_subtitles"])
        zipped = clip_package.prepare(self.job, [source_token, translated_token], self.user,
                                      [f"{translated_token}~1"])
        names = [item.filename for item in zipped.members]
        self.assertIn(f"editorial_{original['id']}.mp4", names)
        stem = f"translation_es_{copied['id']}"
        self.assertEqual(set(names[3:]), {f"{stem}/{stem}.{kind}" for kind in clip_package.CONTENT_TYPES}
                         | {f"{stem}/publicacion.txt"})
        self.assertEqual(zipped.export_provenance[-1]["audio_language"], "en")

    def test_automatic_source_uses_exact_archive_revision_and_d03_content_identity(self):
        clip = {"file": "clip_01.mp4", "title": "Una revisión automática", "start": 10, "end": 15,
                "cues": ES, "options": self.options, "caption_rendered": True}
        with self.engine.begin() as connection:
            project = repo.document(self.job, connection=connection)
            project["payload"]["clips"] = [clip]
            project["manifest"][clip["file"]] = self.asset("automatic/clip_01.mp4", "mp4")
            repo.update_document(connection, self.job, "job", project["payload"], manifest=project["manifest"])
            state = clip_captions._caption_state(project, clip, connection)
            token = f"{clip['file']}:{state['revision']}:{state['output']['id']}"
            source = translation.SourceRef(kind="automatic", id=clip["file"], revision=state["revision"], selection=token)
            pinned = translation._source(connection, project, source, self.user.workspace_id)
            identity = publication._resolve(connection, project, token, self.user.workspace_id)
        self.assertEqual(pinned["content_sha256"], identity["content_sha256"])
        self.assertEqual(pinned["source"]["selection"], token)
        self.assertIn(pinned["source"], translation.index(self.job, self.user)["sources"])
