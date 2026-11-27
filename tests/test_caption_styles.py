"""Creator-owned style persistence and render identity on disposable PostgreSQL."""
import os
import re
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth_db
from app.cloud import caption_styles as styles, clip_captions as captions, migrate_beta, pilot, repository, router
from app.editorial import RevisionRequest
from app.presentation import Presentation
from auth_support import auth_environment, fixture_user, prepare_database


class SavedStylesTest(unittest.TestCase):
    def setUp(self):
        self.schema = "auth01_test_c04_styles_" + secrets.token_hex(8)
        state = patch.dict(os.environ, {**auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": self.schema})
        state.start()
        self.addCleanup(state.stop)
        auth_db.reset_engine()
        self.addCleanup(auth_db.reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["styles_status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["styles_status"], "current")
        self.creator = self.request("owner")
        self.other = self.request("neighbor")

    def remove_schema(self):
        if not re.fullmatch(r"auth01_test_c04_styles_[0-9a-f]{16}", self.schema):
            raise ValueError("Refusing to remove an unowned schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def request(self, identity):
        principal = fixture_user(identity)["principal"]
        return SimpleNamespace(state=SimpleNamespace(principal=principal))

    def new_style(self, name=" Bosque  azul ", color="#12ab34"):
        return styles.create_style(styles.StyleInput(
            name=name, font=styles.FONT, style={"subtitle_color": color, "subtitle_font_size": 71,
                                               "subtitle_position": "top", "subtitle_outline": 7},
        ), self.creator)

    def tasks(self):
        with self.engine.begin() as connection:
            return connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one()

    def complete_source(self, item, clips=()):
        job = {**item, "status": "completed", "clips": list(clips), "media": {"duration_seconds": 120}}
        manifest = {"input.mp4": {"generation": "123", "bytes": 10000, "md5": "f" * 32}}
        for clip in clips:
            manifest[clip["file"]] = {"generation": "456"}
        with self.engine.begin() as connection:
            repository.update_document(connection, item["id"], "job", job, manifest=manifest)

    def test_default_snapshots_only_new_jobs_and_keeps_explicit_burn_opt_out(self):
        principal = self.creator.state.principal
        existing = pilot._reserve(principal, "before-style", "first.mp4", 1024)
        self.complete_source(existing)
        one = self.new_style()
        self.assertEqual(one["name"], "Bosque azul")
        self.assertEqual(one["style"]["subtitle_color"], "#12AB34")
        with self.assertRaises(HTTPException) as duplicate:
            self.new_style("BOSQUE Azul")
        self.assertEqual(duplicate.exception.status_code, 409)
        self.assertEqual(styles.list_styles(self.other)["styles"], [])
        styles.choose_default(styles.DefaultStyle(id=one["id"], revision=1), self.creator)
        self.assertTrue(styles.get_style(one["id"], self.creator)["is_default"])

        new_job = pilot._reserve(principal, "after-style", "second.mp4", 2048, False)
        selected = styles.snapshot(one)
        self.assertEqual(new_job["caption_style_template"], selected)
        self.assertEqual(new_job["options"]["subtitle_color"], "#12AB34")
        self.assertFalse(new_job["options"]["burn_subtitles"])
        self.complete_source(new_job)
        revised = styles.update_style(one["id"], styles.StyleUpdate(
            revision=1, name="Nuevo", font=styles.FONT, style={"subtitle_color": "#FFDDEE"},
        ), self.creator)
        self.assertEqual((revised["revision"], revised["is_default"]), (2, True))
        same = pilot._reserve(principal, "after-style", "second.mp4", 2048, False)
        self.assertEqual(same["caption_style_template"], selected)
        self.assertEqual(same["caption_style"]["subtitle_color"], "#12AB34")
        latest = pilot._reserve(principal, "new-default", "third.mp4", 4096)
        self.assertEqual(latest["caption_style_template"], styles.snapshot(revised))
        self.assertEqual(latest["caption_style"]["subtitle_color"], "#FFDDEE")
        self.complete_source(latest)
        styles.delete_style(one["id"], self.creator, revision=2)
        next_job = pilot._reserve(principal, "no-default", "fourth.mp4", 8192)
        self.assertNotIn("caption_style_template", next_job)
        self.assertNotIn("caption_style_template", repository.document(existing["id"])["payload"])
        self.assertEqual(repository.document(latest["id"])["payload"]["caption_style_template"], styles.snapshot(revised))
        self.assertEqual(self.tasks(), 0)

    def test_owned_style_crud_and_optimistic_writes(self):
        one = self.new_style()
        self.assertEqual(styles.list_styles(self.creator)["fonts"], [{"id": styles.FONT, "label": styles.FONT}])
        change = styles.StyleUpdate(name="Bosque", font=styles.FONT, style={}, revision=one["revision"])
        default = styles.DefaultStyle(id=one["id"], revision=one["revision"])
        for operation in (
            lambda: styles.get_style(one["id"], self.other),
            lambda: styles.update_style(one["id"], change, self.other),
            lambda: styles.delete_style(one["id"], self.other, revision=1),
            lambda: styles.choose_default(default, self.other),
        ):
            with self.assertRaises(HTTPException) as foreign:
                operation()
            self.assertEqual(foreign.exception.status_code, 404)
        styles.update_style(one["id"], change, self.creator)
        with self.assertRaises(HTTPException) as stale:
            styles.delete_style(one["id"], self.creator, revision=1)
        self.assertEqual(stale.exception.status_code, 409)
        for invalid in (
            {"font": "A font unavailable to exports"},
            {"style": {"framing": "crop"}},
            {"style": {"subtitle_font_size": 123}},
        ):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                styles.StyleInput.model_validate({"name": "Nombre", "font": styles.FONT, "style": {}, **invalid})
        self.assertEqual(self.tasks(), 0)

    def test_apply_preserves_per_clip_cues_and_never_replaces_an_earlier_export(self):
        principal = self.creator.state.principal
        job = pilot._reserve(principal, "source-ready", "source.mp4", 5000)
        first, second = "clip_01.mp4", "clip_02.mp4"
        first_cue = {"start": 1.504, "end": 3.034, "text": "Voz editada."}
        second_cue = {"start": 0.25, "end": 2.5, "text": "Otra oración."}
        options = Presentation(burn_subtitles=True).model_dump()
        self.complete_source(job, [
            {"file": name, "start": start, "end": start + 16, "options": options,
             "cues": [cue], "caption_rendered": True}
            for name, start, cue in ((first, 1.25, first_cue), (second, 21.0, second_cue))
        ])
        ref = self.new_style()
        reference = {"id": ref["id"], "revision": ref["revision"]}
        submitted_style = captions.style_from(Presentation(burn_subtitles=True))
        self.assertEqual(
            captions.save_project(job["id"], captions.ProjectCaptionUpdate(
                revision=1, style=submitted_style, style_template=reference, render=False, apply_to_all=True,
            ), principal)["style_template"],
            styles.snapshot(ref),
        )
        staged = repository.document(job["id"])
        contexts = [captions.clip_context(staged, name) for name in (first, second)]
        self.assertEqual([clip["cues"] for clip in contexts], [[first_cue], [second_cue]])
        self.assertEqual([(clip["start"], clip["end"]) for clip in contexts], [(1.25, 17.25), (21.0, 37.0)])
        self.assertEqual([clip["status"] for clip in contexts], ["draft", "draft"])
        self.assertTrue(all(clip["output"] is None for clip in contexts))
        self.assertEqual(self.tasks(), 0)

        # The normal save-and-generate carries the staged values, without a
        # live template reference. Updates and deletions leave that copy usable.
        updated = styles.update_style(ref["id"], styles.StyleUpdate(
            revision=1, name="Actualizado", font=styles.FONT, style={"subtitle_color": "#FFFFFF"},
        ), self.creator)
        styles.delete_style(ref["id"], self.creator, revision=updated["revision"])
        first_context = contexts[0]
        generated = captions.save_clip(job["id"], first, captions.ClipCaptionUpdate(
            revision=first_context["revision"], style=first_context["style"], cues=first_context["cues"],
        ), principal)
        self.assertEqual((generated["status"], generated["style_template"]), ("queued", styles.snapshot(ref)))
        self.assertEqual(self.tasks(), 1)
        previous = repository.list_documents(job["id"], "export")[0]["payload"]
        self.assertEqual(previous["caption_revision"], generated["revision"])
        self.assertEqual(previous["style_template"], styles.snapshot(ref))
        self.assertEqual(previous["options"]["subtitle_color"], "#12AB34")
        self.assertEqual(previous["cues"], [first_cue])
        old_id = previous["id"]

        # A different input gets a new immutable export, preserving the old copy.
        changed_cue = {**first_cue, "text": "Una nueva revisión del texto."}
        changed = captions.save_clip(job["id"], first, captions.ClipCaptionUpdate(
            revision=generated["revision"], style=generated["style"], cues=[changed_cue],
        ), principal)
        self.assertEqual(changed["style_template"], styles.snapshot(ref))
        self.assertEqual(self.tasks(), 2)
        self.assertEqual(repository.document(job["id"], "export", old_id)["payload"], previous)

        independent = self.new_style("Otro estilo", "#992211")
        applied = captions.save_clip(job["id"], second, captions.ClipCaptionUpdate(
            revision=contexts[1]["revision"], style=contexts[1]["style"], cues=contexts[1]["cues"], render=False,
            style_template={"id": independent["id"], "revision": independent["revision"]},
        ), principal)
        self.assertEqual(applied["cues"], [second_cue])
        self.assertEqual(applied["style"]["subtitle_color"], "#992211")
        self.assertEqual(applied["style_template"], styles.snapshot(independent))
        self.assertEqual(applied["status"], "draft")
        self.assertEqual(self.tasks(), 2)

    def test_byte_equivalent_base_artifact_uses_applied_preset_revision_for_its_identity(self):
        principal = self.creator.state.principal
        job = pilot._reserve(principal, "already-rendered", "source.mp4", 6000)
        clip = "clip_01.mp4"
        options = Presentation(burn_subtitles=True).model_dump()
        cues = [{"start": 1, "end": 6, "text": "Mantiene sus mismos valores."}]
        self.complete_source(job, [{
            "file": clip, "start": 10, "end": 30, "options": options, "cues": cues, "caption_rendered": True,
        }])
        initial = captions.clip_context(repository.document(job["id"]), clip)
        preset = styles.create_style(styles.StyleInput(name="Igual", font=styles.FONT, style={}), self.creator)
        applied = captions.save_clip(job["id"], clip, captions.ClipCaptionUpdate(
            revision=initial["revision"], style=initial["style"], cues=cues, render=False,
            style_template={"id": preset["id"], "revision": 1},
        ), principal)
        revised = styles.update_style(preset["id"], styles.StyleUpdate(
            revision=1, name="Nombre nuevo", font=styles.FONT, style={},
        ), self.creator)
        reapplied = captions.save_clip(job["id"], clip, captions.ClipCaptionUpdate(
            revision=applied["revision"], style=applied["style"], cues=cues, render=False,
            style_template={"id": preset["id"], "revision": 2},
        ), principal)
        self.assertEqual(initial["output"]["mp4"], reapplied["output"]["mp4"])
        self.assertEqual(reapplied["style_template"], styles.snapshot(revised))
        self.assertEqual(len({item["output"]["id"] for item in (initial, applied, reapplied)}), 3)
        self.assertEqual(self.tasks(), 0)

    def test_editorial_draft_and_its_export_copy_the_preset_independently(self):
        principal = self.creator.state.principal
        job = pilot._reserve(principal, "draft-original", "source.mp4", 7500)
        self.complete_source(job)
        preset = self.new_style()
        draft_id = secrets.token_hex(16)
        content = {
            "title": "Una edición", "clip_file": None, "start": 10, "end": 39,
            "options": Presentation(burn_subtitles=True).model_dump(),
            "cues": [{"start": 2, "end": 7, "text": "Mismo texto y tiempos."}],
        }
        with self.engine.begin() as connection:
            repository.insert_document(connection, job["id"], "draft", {
                **content, "id": draft_id, "job_id": job["id"], "revision": 1,
            })
        request = SimpleNamespace(state=self.creator.state, headers={})
        with patch.dict(os.environ, {"CLIPFORGE_INT_BETA": "1"}), patch.object(router, "_dispatch", side_effect=lambda item: item):
            saved = router.update_draft(job["id"], draft_id, router.CloudDraftUpdate(
                **content, revision=1, style_template={"id": preset["id"], "revision": 1},
            ), request)
            styles.delete_style(preset["id"], self.creator, revision=1)
            # No render occurs on either style operation; export requires approval of the draft revision.
            self.assertEqual(self.tasks(), 0)
            exported = router.export_draft(job["id"], draft_id, RevisionRequest(revision=saved["revision"]), request)
            self.assertEqual((exported["draft_revision"], exported["options"]["subtitle_color"]), (2, "#12AB34"))
            self.assertEqual(exported["cues"], saved["cues"])
            self.assertEqual(exported["style_template"], styles.snapshot(preset))
            self.assertEqual(self.tasks(), 1)
