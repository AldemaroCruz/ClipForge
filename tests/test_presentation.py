"""Presentation regressions. New export integration uses REAL FFmpeg, cached text.

No Whisper inference is needed for editing; it is not simulated as a success here.
"""
import copy
import hashlib
import json
import math
import os
import shutil
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from auth_support import AuthenticatedTestClient as TestClient
from pydantic import ValidationError
from app.presentation import Presentation, ExportRequest
from app.subtitles import SubtitleError, cues_from_segments, validate_cues, timestamp, to_ass, to_srt, to_vtt
from app.render import render_clip, build_filter
from app.check_presentation import make_source
from app.state import write_json_atomic
with tempfile.TemporaryDirectory() as boot:
    with mock.patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": boot}):
        from app import main

ID = "b" * 32


class SubtitleTests(unittest.TestCase):
    def test_clip_local_timestamps_and_intersections(self):
        cues = cues_from_segments([
            {"start": 90, "end": 99, "text": "Fuera"},
            {"start": 100, "end": 103, "text": "¡Hola!"},
            {"start": 103, "end": 106, "text": "Segunda frase"},
            {"start": 112, "end": 114, "text": "Después"},
        ], 101, 105)
        self.assertEqual(cues, [{"start": 0, "end": 2, "text": "¡Hola!"},
                                {"start": 2, "end": 4, "text": "Segunda frase"}])
        self.assertIn("00:00:00,000 --> 00:00:02,000", to_srt(cues))
        self.assertIn("00:00:00.000 --> 00:00:02.000", to_vtt(cues))

    def test_long_segment_is_split_without_claiming_word_timing(self):
        text = "Una frase larga necesita revisión antes de publicar el resultado. " * 5
        cues = cues_from_segments([{"start": 0, "end": 25, "text": text}], 0, 25)
        self.assertGreater(len(cues), 1)
        self.assertEqual(" ".join(c["text"] for c in cues), text.strip())
        self.assertEqual(cues[0]["start"], 0)
        self.assertEqual(cues[-1]["end"], 25)
        validate_cues(cues, 25)

    def test_millisecond_carry(self):
        self.assertEqual(timestamp(3599.9996), "01:00:00,000")
        self.assertEqual(timestamp(59.9996, vtt=True), "00:01:00.000")
        self.assertEqual(timestamp(59.996, ass=True), "0:01:00.00")

    def test_plaintext_cannot_inject_ass_or_webvtt(self):
        cues = validate_cues([{"start": 0, "end": 2, "text": r"{\pos(1,1)} \N <script>ñ & é</script>"}], 3)
        ass = to_ass(cues).split("[Events]", 1)[1]
        self.assertNotIn(r"{\pos", ass)
        self.assertNotIn(r"\N", ass)
        self.assertNotIn("<script>", to_vtt(cues))
        self.assertIn("&lt;script&gt;", to_srt(cues))
        self.assertIn("ñ", ass)

    def test_invalid_times_overlap_and_text_rejected(self):
        for cues in (
            [{"start": float("nan"), "end": 2, "text": "x"}],
            [{"start": 0, "end": float("inf"), "text": "x"}],
            [{"start": 0, "end": 4, "text": "x"}],
            [{"start": 2, "end": 1, "text": "x"}],
            [{"start": 0, "end": 2, "text": "x"}, {"start": 1, "end": 3, "text": "y"}],
            [{"start": 0, "end": 2, "text": "  "}],
            [{"start": 0, "end": 2, "text": "x" * 501}],
        ):
            with self.subTest(cues=cues), self.assertRaises(SubtitleError):
                validate_cues(cues, 3)

    def test_bad_transcript_is_not_silently_accepted(self):
        for segs in ({"not": "list"}, [{"start": "bad", "end": 1, "text": "x"}],
                     [{"start": 0, "end": math.inf, "text": "x"}]):
            with self.assertRaises(SubtitleError):
                cues_from_segments(segs, 0, 3)

    def test_options_are_bounded_and_filters_not_accepted(self):
        for options in ({"framing": "movie=http://example.invalid"}, {"crop_x": -1},
                        {"crop_y": 2}, {"crop_zoom": 0}, {"crop_zoom": 10}, {"crop_x": math.nan},
                        {"filter": "null"}):
            with self.subTest(options=options), self.assertRaises(ValidationError):
                Presentation.model_validate(options)

    def test_cropped_graph_contains_validated_numeric_values(self):
        graph = build_filter(Presentation(framing="crop", crop_x=1, crop_y=0, crop_zoom=3))
        self.assertIn("3.000000", graph)
        self.assertIn("scale=1080:1920", graph)
        self.assertNotIn("ass=", graph)
        with self.assertRaises(ValueError):
            build_filter(Presentation(), video_index="0];evil")

    def test_empty_caption_list_requires_burn_off(self):
        with tempfile.TemporaryDirectory() as root:
            with self.assertRaisesRegex(ValueError, "No hay subtítulos"):
                render_clip(Path(root) / "missing.mp4", Path(root) / "out.mp4", start=0,
                            end=3, options=Presentation(burn_subtitles=True), cues=[])

    def test_renderer_failure_does_not_replace_existing_outputs(self):
        with tempfile.TemporaryDirectory() as root:
            output = Path(root) / "clip.mp4"
            output.write_bytes(b"original")
            with self.assertRaisesRegex(RuntimeError, "broken"):
                render_clip(Path(root) / "source.mp4", output, start=0, end=3,
                            options=Presentation(), cues=[], runner=mock.Mock(side_effect=RuntimeError("broken")))
            self.assertEqual(output.read_bytes(), b"original")
            self.assertEqual(list(Path(root).glob(".render-*")), [])


@unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg required")
class EditingApiTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.source = Path(cls.fixtures.name) / "source.mp4"
        make_source(cls.source, 6)

    @classmethod
    def tearDownClass(cls):
        cls.fixtures.cleanup()

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.patch = mock.patch.object(main, "ROOT", self.root)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        folder = self.root / ID
        folder.mkdir()
        shutil.copyfile(self.source, folder / "input.mp4")
        # Simulates persisted v0.1.4 schema, not a simulated speech-recognition run.
        (folder / "clip_01.mp4").write_bytes(b"preserved legacy clip")
        write_json_atomic(folder / "job.json", {"id": ID, "status": "completed", "clips": [
            {"file": "clip_01.mp4", "start": 2, "end": 5, "text": "Texto guardado"}]})
        write_json_atomic(folder / "transcript.json", [
            {"start": 2, "end": 3.5, "text": "Texto guardado"},
            {"start": 3.5, "end": 5, "text": "Segunda frase"}])
        self.client = TestClient(main.app, projects=(ID,))
        self.client.__enter__()
        self.addCleanup(lambda: self.client.__exit__(None, None, None))
        self.context = self.client.get(f"/jobs/{ID}/clips/clip_01.mp4/editor").json()

    def wait_export(self, export_id):
        limit = time.monotonic() + 20
        while time.monotonic() < limit:
            state = self.client.get(f"/jobs/{ID}/exports/{export_id}").json()
            if state["status"] in {"failed", "completed"}:
                return state
            time.sleep(.05)
        self.fail("export timed out")

    def request_export(self, options=None, cues=None):
        return self.client.post(f"/jobs/{ID}/clips/clip_01.mp4/exports", json={
            "options": options or {"framing": "crop", "burn_subtitles": True},
            "cues": self.context["cues"] if cues is None else cues})

    def test_legacy_editor_reuses_transcript_without_rewriting_job(self):
        folder = self.root / ID
        before = (folder / "job.json").read_bytes()
        self.assertEqual(self.context["duration"], 3)
        self.assertEqual(self.context["cues"][0]["start"], 0)
        self.assertEqual(self.context["options"]["framing"], "contain")
        self.assertEqual((folder / "job.json").read_bytes(), before)
        self.assertEqual(self.client.get(f"/jobs/{ID}/clips/clip_01.mp4/subtitles/srt").status_code, 200)

    def test_real_export_download_range_audio_and_source_preservation(self):
        folder = self.root / ID
        paths = [folder / p for p in ("input.mp4", "clip_01.mp4", "job.json", "transcript.json")]
        hashes = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths}
        cues = copy.deepcopy(self.context["cues"])
        cues[0]["text"] = "Corrección: edición local, sin repetir Whisper."
        response = self.request_export(cues=cues)
        self.assertEqual(response.status_code, 202, response.text)
        export_id = response.json()["id"]
        result = self.wait_export(export_id)
        self.assertEqual(result["status"], "completed", result.get("error"))
        self.assertEqual(result["cues"][0]["text"], cues[0]["text"])
        base = f"/jobs/{ID}/exports/{export_id}/files"
        video = self.client.get(f"{base}/clip.mp4?inline=true", headers={"Range": "bytes=0-31"})
        self.assertEqual(video.status_code, 206)
        self.assertEqual(len(video.content), 32)
        self.assertIn("inline", video.headers["content-disposition"])
        srt = self.client.get(f"{base}/clip.srt")
        self.assertIn("Corrección", srt.text)
        self.assertIn("00:00:00,000", srt.text)
        self.assertIn("attachment", srt.headers["content-disposition"])
        self.assertEqual(self.client.get(f"{base}/export.json").status_code, 404)
        self.assertEqual(hashes, {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in paths})
        items = self.client.get(f"/jobs/{ID}/exports").json()["exports"]
        self.assertEqual(len(items), 1)

    def test_source_supports_byte_ranges(self):
        response = self.client.get(f"/jobs/{ID}/source", headers={"Range": "bytes=0-31"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, self.source.read_bytes()[:32])

    def test_invalid_options_and_cues_create_no_exports(self):
        for options, cues in (({"framing": "bad"}, None), ({"crop_x": -1}, None),
                              (None, [{"start": 0, "end": 4, "text": "too long"}]),
                              (None, [{"start": 2, "end": 1, "text": "reversed"}]),
                              (None, [])):
            with self.subTest(options=options, cues=cues):
                self.assertEqual(self.request_export(options, cues).status_code, 422)
        self.assertFalse((self.root / ID / "exports").exists())

    def test_failed_export_keeps_draft_and_old_clip(self):
        with mock.patch.object(main, "render_clip", side_effect=RuntimeError("test codec failure")):
            response = self.request_export()
            state = self.wait_export(response.json()["id"])
        self.assertEqual(state["status"], "failed")
        self.assertIn("test codec failure", state["error"])
        self.assertEqual(state["cues"], self.context["cues"])
        self.assertEqual(self.client.get(f"/jobs/{ID}").json()["status"], "completed")
        self.assertEqual(self.client.get(f"/jobs/{ID}/exports/{state['id']}/files/clip.mp4").status_code, 409)

    def test_missing_original_or_transcript_returns_actionable_conflict(self):
        (self.root / ID / "transcript.json").unlink()
        self.assertEqual(self.client.get(f"/jobs/{ID}/clips/clip_01.mp4/editor").status_code, 409)
        (self.root / ID / "input.mp4").unlink()
        response = self.client.get(f"/jobs/{ID}/clips/clip_01.mp4/editor")
        self.assertEqual(response.status_code, 409)
        self.assertIn("input.mp4", response.json()["detail"])

    def test_restart_marks_only_unfinished_exports(self):
        item = {"id": "e" * 32, "job_id": ID, "status": "rendering", "cues": []}
        main.persist_export(ID, item)
        main.mark_interrupted_exports()
        self.assertEqual(main.read_export(ID, item["id"])["status"], "failed")
        self.assertIn("reinicio", main.read_export(ID, item["id"])["error"])
        self.assertEqual(main.load_job(ID)["status"], "completed")

    def test_unknown_files_and_bad_ids_cannot_read_arbitrary_paths(self):
        for url in (f"/jobs/{ID}/clips/input.mp4/editor", f"/jobs/{ID}/exports/not-valid", f"/jobs/{'z'*32}/source"):
            self.assertEqual(self.client.get(url).status_code, 404)

    def test_upload_rejects_invalid_framing_before_processing(self):
        with mock.patch.object(main, "process") as processing:
            response = self.client.post("/jobs", files={"file": ("test.mp4", b"a", "video/mp4")},
                                        data={"framing": "crop", "crop_zoom": "9"})
        self.assertEqual(response.status_code, 422)
        processing.assert_not_called()


if __name__ == "__main__":
    unittest.main()
