"""Generated captions retain source-local timing, immutable outputs and project style."""
from contextlib import ExitStack, nullcontext
from copy import deepcopy
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from pydantic import ValidationError

from app.cloud import clip_captions as captions
from app.presentation import Presentation
from app.subtitles import to_srt, to_vtt


JOB = "b" * 32
CLIP = "clip_01.mp4"
OTHER = "clip_02.mp4"
ORIGINAL = {"generation": "123", "bytes": 12345, "md5": "e" * 32}
FIRST_CUE = {"start": 2.0, "end": 7.0, "text": "Voz transcrita."}
EDITED_CUE = {"start": 3.25, "end": 6.125, "text": "Nuestra edición."}


def fixture(*, automatic=False):
    manifest = {"input.mp4": ORIGINAL, "transcript.json": {"generation": "9"}}
    clips = []
    for name, start in ((CLIP, 600.0), (OTHER, 900.0)):
        manifest[name] = {"generation": "5"}
        manifest[name.replace(".mp4", ".srt")] = {"generation": "6"}
        manifest[name.replace(".mp4", ".vtt")] = {"generation": "7"}
        clips.append({
            "file": name, "start": start, "end": start + 30, "cues": [deepcopy(FIRST_CUE)],
            "options": Presentation(burn_subtitles=automatic).model_dump(), "caption_rendered": automatic,
        })
    return {"payload": {"pilot": True, "id": JOB, "status": "completed", "version": "synthetic",
                        "options": Presentation().model_dump(), "clips": clips}, "manifest": manifest}


class ClipCaptionsTest(unittest.TestCase):
    def setUp(self):
        self.job = fixture()
        self.exports = {}
        self.owner = SimpleNamespace(id="a" * 32)
        self.engine = SimpleNamespace(begin=lambda: nullcontext(self), connect=lambda: nullcontext(self))
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(captions, "get_engine", return_value=self.engine))
        self.owned = self.stack.enter_context(patch.object(captions.repo, "beta_document", return_value=self.job))
        self.stack.enter_context(patch.object(captions.repo, "document", side_effect=self.document))
        self.stack.enter_context(patch.object(captions.repo, "insert_document", side_effect=self.insert))
        self.queue = self.stack.enter_context(patch.object(captions.repo, "enqueue"))
        self.admit = self.stack.enter_context(patch.object(captions.repo, "admit_beta"))
        self.stack.enter_context(patch.object(captions.repo, "update_document"))

    def document(self, job_id, kind, export_id, connection=None, *, required=True):
        if required:
            return deepcopy(self.exports[export_id])
        return deepcopy(self.exports.get(export_id))

    def insert(self, connection, job_id, kind, item):
        self.exports[item["id"]] = {"payload": deepcopy(item), "manifest": {}}

    def current_id(self, filename=CLIP):
        return self.job["payload"]["clip_caption_settings"][filename]["export_id"]

    def complete(self, export_id):
        export = self.exports[export_id]
        export["payload"]["status"] = "completed"
        export["manifest"] = {"clip.mp4": {}, "clip.srt": {}, "clip.vtt": {}}

    def submit(self, style=None, *, revision=1, cues=None):
        options = captions.style_from(Presentation(burn_subtitles=True))
        options.update(style or {})
        payload = captions.ClipCaptionUpdate(style=options, revision=revision, cues=[EDITED_CUE] if cues is None else cues)
        return captions.save_clip(JOB, CLIP, payload, self.owner)

    def test_presentation_reuses_existing_validation_and_upload_opt_out(self):
        for invalid in ({"subtitle_font_size": 23}, {"subtitle_color": "#xyz999"},
                        {"subtitle_position": "corner"}, {"framing": "crop"}):
            with self.subTest(invalid=invalid), self.assertRaises(ValidationError):
                captions.CaptionStyle.model_validate(invalid)
        style = captions.CaptionStyle.model_validate({"subtitle_color": "#12ab34", "burn_subtitles": False}).root
        self.assertEqual((style["subtitle_color"], style["subtitle_font_size"]), ("#12AB34", 52))
        self.assertTrue(captions.project_presentation(self.job["payload"]).burn_subtitles)
        self.job["payload"]["caption_style"] = style
        self.assertFalse(captions.project_presentation(self.job["payload"]).burn_subtitles)

    def test_initial_clip_advertises_immutable_mp4_and_actual_caption_sidecars(self):
        result = captions.enrich_job(fixture(automatic=True))
        active = result["clips"][0]["captions"]
        self.assertEqual(active["status"], "completed")
        self.assertTrue(active["output"]["burn_subtitles"])
        prefix = f"/jobs/{JOB}/clips/{CLIP}"
        self.assertEqual([active["output"][field] for field in ("mp4", "srt", "vtt")],
                         [prefix, f"{prefix}/subtitles/srt", f"{prefix}/subtitles/vtt"])
        self.assertEqual(len(active["output"]["id"]), 64)

    def test_old_clip_can_recover_late_cues_from_saved_transcript(self):
        self.job["payload"]["clips"][0].pop("cues")
        with (
            patch.object(captions.editorial_selection, "source_identity", return_value={}),
            patch.object(captions.editorial_selection, "transcript_segments", return_value=[
                {"start": 603.25, "end": 606.125, "text": "Nuestra edición."},
            ]) as stored,
        ):
            context = captions.clip_context(self.job, CLIP)
            queued = self.submit(cues=context["cues"])
        stored.assert_called_once()
        self.assertEqual(context["status"], "unmodified")
        self.assertEqual(context["cues"], [EDITED_CUE])
        self.assertEqual(queued["cues"], [EDITED_CUE])
        self.assertEqual(queued["status"], "queued")
        self.assertIn("00:00:03,250 --> 00:00:06,125", to_srt(queued["cues"]))
        self.assertIn("00:00:03.250 --> 00:00:06.125", to_vtt(queued["cues"]))
        self.admit.assert_called_once_with(self, self.owner.id, caption_job=JOB)

    def test_no_cues_produces_no_caption_claim_or_sidecar_link(self):
        context = self.submit(cues=[])
        self.assertEqual(context["status"], "queued")
        export_id = self.current_id()
        self.assertFalse(self.exports[export_id]["payload"]["options"]["burn_subtitles"])
        self.complete(export_id)
        context = captions.clip_context(self.job, CLIP)
        self.assertEqual(context["status"], "no_speech")
        self.assertIsNotNone(context["output"]["mp4"])
        self.assertIsNone(context["output"]["srt"])
        self.assertIsNone(context["output"]["vtt"])

    def test_older_completion_cannot_displace_latest_and_same_inputs_reuse_variant(self):
        first = self.submit({"subtitle_position": "top"})
        old = self.current_id()
        second = self.submit({"subtitle_position": "center"}, revision=first["revision"])
        latest = self.current_id()
        self.assertNotEqual(old, latest)
        self.complete(old)
        waiting = captions.clip_context(self.job, CLIP)
        self.assertEqual(waiting["status"], "queued")
        self.assertIsNone(waiting["output"])
        self.complete(latest)
        result = self.submit({"subtitle_position": "center"}, revision=second["revision"])
        self.assertEqual(result["output"]["id"], latest)
        self.assertEqual(result["style"]["subtitle_position"], "center")
        self.assertEqual(self.queue.call_count, 2)
        with self.assertRaises(HTTPException) as stale:
            self.submit({"subtitle_position": "top"}, revision=first["revision"])
        self.assertEqual(stale.exception.status_code, 409)

    def test_apply_project_style_keeps_cue_edits_but_removes_individual_style(self):
        override = self.submit({"subtitle_font_size": 66})
        original_overrides = self.current_id()
        shared = captions.ProjectCaptionUpdate(style={"burn_subtitles": True, "subtitle_color": "#d0f000",
                                                      "subtitle_position": "top"}, apply_to_all=True, revision=1)
        project = captions.save_project(JOB, shared, self.owner)
        first = captions.clip_context(self.job, CLIP)
        second = captions.clip_context(self.job, OTHER)
        self.assertEqual(project["revision"], 2)
        self.assertEqual(project["style"]["subtitle_color"], "#D0F000")
        self.assertEqual(first["cues"], [EDITED_CUE])
        self.assertEqual(second["cues"], [FIRST_CUE])
        self.assertEqual(first["style"], second["style"])
        self.assertEqual(first["style"]["subtitle_font_size"], 52)
        self.assertGreater(first["revision"], override["revision"])
        self.assertNotEqual(self.current_id(), original_overrides)
        self.assertEqual(self.queue.call_count, 3)

    def test_project_noop_reuses_both_existing_renders(self):
        self.job = fixture(automatic=True)
        self.owned.return_value = self.job
        shared = captions.ProjectCaptionUpdate(style=captions.style_from(Presentation(burn_subtitles=True)),
                                               apply_to_all=True, revision=1)
        captions.save_project(JOB, shared, self.owner)
        self.queue.assert_not_called()
        self.admit.assert_not_called()
        self.assertIsNone(self.current_id())

    def test_fingerprint_covers_source_revision_range_and_render_configuration(self):
        options = Presentation(burn_subtitles=True).model_dump()
        actual = captions.render_fingerprint(ORIGINAL, 600, 630, options, [FIRST_CUE])
        cases = (
            ({**ORIGINAL, "generation": "124"}, 600, 630, options, [FIRST_CUE]),
            (ORIGINAL, 601, 631, options, [FIRST_CUE]),
            (ORIGINAL, 600, 630, {**options, "subtitle_position": "top"}, [FIRST_CUE]),
            (ORIGINAL, 600, 630, options, [EDITED_CUE]),
        )
        for case in cases:
            with self.subTest(case=case):
                self.assertNotEqual(captions.render_fingerprint(*case), actual)
