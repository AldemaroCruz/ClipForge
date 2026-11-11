"""Subtitle style regression tests for v0.2.1.

Only the short export test executes real FFmpeg. Upload scheduling is mocked to
inspect request validation without invoking Whisper. No real ASR is claimed.
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
from app.presentation import Presentation
from app.subtitles import to_ass, to_srt, to_vtt
from app.render import render_clip
from app.check_presentation import make_source, caption_color_stats
from app.state import write_json_atomic
with tempfile.TemporaryDirectory() as boot:
    with mock.patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": boot}):
        from app import main

ID = "d" * 32
CUES = [{"start": .1, "end": 1.8, "text": "Color y tamaño"}]


class StyleSchemaTests(unittest.TestCase):
    def test_legacy_options_get_original_defaults(self):
        options = Presentation.model_validate({"framing": "crop", "burn_subtitles": True})
        self.assertEqual(options.subtitle_font_size, 52)
        self.assertEqual(options.subtitle_color, "#FFFFFF")

    def test_bounds_and_uppercase_hex(self):
        for size in (24, 52, 64, 120):
            options = Presentation(subtitle_font_size=size, subtitle_color="#fFd54f")
            self.assertEqual(options.model_dump()["subtitle_font_size"], size)
            self.assertEqual(options.model_dump()["subtitle_color"], "#FFD54F")

    def test_invalid_sizes_rejected_not_clamped(self):
        for size in (0, 23, 121, -8, 52.5, True, False, "64", None, math.nan, math.inf):
            with self.subTest(size=size), self.assertRaises(ValidationError):
                Presentation(subtitle_font_size=size)

    def test_invalid_colors_rejected_before_ass(self):
        for color in (None, True, "red", "#fff", "#12345678", "#FFFFFF\n", " #FFFFFF",
                      "#GG0000", "&H00FFFFFF", "#12345g", "#fff,Fontsize=999", "{\\c&HFF&}"):
            with self.subTest(color=color), self.assertRaises(ValidationError):
                Presentation(subtitle_color=color)

    def test_rgb_is_converted_to_opaque_ass_bgr(self):
        for rgb, expected in (("#FF0000", "&H000000FF"), ("#0000FF", "&H00FF0000"),
                              ("#00FF00", "&H0000FF00"), ("#12AB34", "&H0034AB12"),
                              ("#000000", "&H00000000"), ("#fFd54f", "&H004FD5FF")):
            with self.subTest(rgb=rgb):
                text = to_ass(CUES, font_size=72, color=rgb)
                self.assertIn(f"Style: Default,DejaVu Sans,72,{expected},{expected},", text)
                self.assertIn("PlayResX: 1080\nPlayResY: 1920", text)

    def test_default_style_keeps_v020_header(self):
        self.assertIn("Style: Default,DejaVu Sans,52,&H00FFFFFF,&H00FFFFFF,&H00101520,&H80000000,-1,0,0,0,100,100,0,0,1,3,1,2,95,95,230,1", to_ass(CUES))

    def test_direct_ass_calls_are_also_validated(self):
        for kwargs in ({"font_size": 9999}, {"font_size": "52,Arial"},
                       {"color": "#FFFFFF\n[Events]"}):
            with self.assertRaises(ValidationError):
                to_ass(CUES, **kwargs)

    def test_style_does_not_change_cue_text_or_times(self):
        before = copy.deepcopy(CUES)
        one = to_ass(CUES, font_size=24, color="#FFD54F").split("[Events]")[1]
        two = to_ass(CUES, font_size=120, color="#FF0000").split("[Events]")[1]
        self.assertEqual(one, two)
        self.assertEqual(CUES, before)
        self.assertNotIn("Fontsize", to_srt(CUES))
        self.assertNotIn("STYLE", to_vtt(CUES))

    def test_renderer_passes_both_validated_style_fields(self):
        with tempfile.TemporaryDirectory() as root:
            target = Path(root) / "clip.mp4"
            # Only inspect arguments. This is explicitly not a real video render.
            def fake_runner(*args):
                Path(args[-1]).write_bytes(b"simulated-render")
            with mock.patch("app.render.to_ass", wraps=to_ass) as serialize:
                render_clip(Path(root)/"input.mp4", target, start=0, end=2,
                            options=Presentation(burn_subtitles=True, subtitle_font_size=88,
                                                 subtitle_color="#33aa77"), cues=CUES, runner=fake_runner)
            self.assertEqual(serialize.call_args.kwargs, {"font_size": 88, "color": "#33AA77",
                "position": "bottom", "margin_v": 230, "outline": 3,
                "outline_color": "#201510", "shadow": 1})


class StyleApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patch = mock.patch.object(main, "ROOT", self.root)
        patch.start(); self.addCleanup(patch.stop)
        self.client = TestClient(main.app, projects=(ID,))
        self.client.__enter__()
        self.addCleanup(lambda: self.client.__exit__(None, None, None))

    def seed_legacy(self):
        folder = self.root / ID
        folder.mkdir()
        (folder/"input.mp4").write_bytes(b"legacy fixture, not a playable video")
        (folder/"clip_01.mp4").write_bytes(b"old clip")
        write_json_atomic(folder/"job.json", {"id": ID, "status": "completed", "clips": [
            {"file": "clip_01.mp4", "start": 0, "end": 2,
             "options": {"framing": "contain", "burn_subtitles": False}}]})
        write_json_atomic(folder/"transcript.json", CUES)
        return folder

    def test_upload_custom_style_saved_and_normalized(self):
        with mock.patch.object(main.threading, "Thread") as thread:
            r = self.client.post("/jobs", files={"file": ("source.mp4", b"fixture", "video/mp4")},
                                 data={"subtitle_font_size": "80", "subtitle_color": "#ff0000", "burn_subtitles": "true"})
        self.assertEqual(r.status_code, 202, r.text)
        state = self.client.get(f"/jobs/{r.json()['id']}").json()
        self.assertEqual(state["options"]["subtitle_font_size"], 80)
        self.assertEqual(state["options"]["subtitle_color"], "#FF0000")
        self.assertTrue(state["options"]["burn_subtitles"])
        thread.return_value.start.assert_called_once()

    def test_legacy_upload_without_style_keeps_defaults(self):
        with mock.patch.object(main.threading, "Thread"):
            r = self.client.post("/jobs", files={"file": ("source.mp4", b"fixture", "video/mp4")})
        self.assertEqual(r.status_code, 202, r.text)
        self.assertEqual(r.json()["options"]["subtitle_font_size"], 52)
        self.assertEqual(r.json()["options"]["subtitle_color"], "#FFFFFF")

    def test_bad_upload_style_never_queues_job(self):
        with mock.patch.object(main.threading, "Thread") as thread:
            for data in ({"subtitle_font_size": "121"}, {"subtitle_font_size": "64.5"},
                         {"subtitle_color": "red"}, {"subtitle_color": "#ffffff,broken"}):
                r = self.client.post("/jobs", files={"file": ("source.mp4", b"fixture", "video/mp4")}, data=data)
                self.assertEqual(r.status_code, 422, r.text)
            thread.assert_not_called()
        self.assertEqual([p for p in self.root.iterdir() if p.name != ".clipforge-runtime.lock"], [])

    def test_editor_defaults_do_not_rewrite_v020_job(self):
        folder = self.seed_legacy()
        before = (folder/"job.json").read_bytes()
        r = self.client.get(f"/jobs/{ID}/clips/clip_01.mp4/editor")
        self.assertEqual(r.status_code, 200, r.text)
        self.assertEqual(r.json()["options"]["subtitle_font_size"], 52)
        self.assertEqual(r.json()["options"]["subtitle_color"], "#FFFFFF")
        self.assertEqual((folder/"job.json").read_bytes(), before)

    def test_saved_variant_retains_style_even_with_burn_disabled(self):
        self.seed_legacy()
        with mock.patch.object(main.threading, "Thread"):
            r = self.client.post(f"/jobs/{ID}/clips/clip_01.mp4/exports", json={"cues": CUES,
                "options": {"burn_subtitles": False, "subtitle_font_size": 96, "subtitle_color": "#12ab34"}})
        self.assertEqual(r.status_code, 202, r.text)
        stored = self.client.get(f"/jobs/{ID}/exports/{r.json()['id']}").json()
        self.assertEqual(stored["options"]["subtitle_font_size"], 96)
        self.assertEqual(stored["options"]["subtitle_color"], "#12AB34")
        self.assertFalse(stored["options"]["burn_subtitles"])
        self.assertEqual(stored["cues"], CUES)

    def test_invalid_variant_style_creates_no_files(self):
        folder = self.seed_legacy()
        with mock.patch.object(main.threading, "Thread") as thread:
            for style in ({"subtitle_font_size": 121}, {"subtitle_font_size": 40.5},
                          {"subtitle_color": "#FFF"}, {"subtitle_color": "#FFFF00\n"}):
                r = self.client.post(f"/jobs/{ID}/clips/clip_01.mp4/exports", json={"cues": CUES, "options": style})
                self.assertEqual(r.status_code, 422, r.text)
            thread.assert_not_called()
        self.assertFalse((folder/"exports").exists())

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg required")
    def test_real_styled_export_preserves_originals_and_srt(self):
        folder = self.seed_legacy()
        make_source(folder/"input.mp4", 2)
        files = [folder/n for n in ("job.json", "transcript.json", "input.mp4", "clip_01.mp4")]
        before = {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files}
        r = self.client.post(f"/jobs/{ID}/clips/clip_01.mp4/exports", json={"cues": CUES,
            "options": {"burn_subtitles": True, "subtitle_font_size": 72, "subtitle_color": "#ff0000"}})
        self.assertEqual(r.status_code, 202, r.text)
        eid = r.json()["id"]
        deadline = time.monotonic()+25
        while time.monotonic() < deadline:
            state = self.client.get(f"/jobs/{ID}/exports/{eid}").json()
            if state["status"] in {"failed", "completed"}:
                break
            time.sleep(.05)
        self.assertEqual(state["status"], "completed", state)
        path = folder/"exports"/eid/"clip.mp4"
        self.assertGreater(caption_color_stats(path, "#FF0000")["matching_pixels"], 100)
        self.assertEqual(before, {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in files})
        self.assertEqual(state["options"]["subtitle_font_size"], 72)
        srt = self.client.get(f"/jobs/{ID}/exports/{eid}/files/clip.srt")
        self.assertEqual(srt.status_code, 200)
        self.assertEqual(srt.text, to_srt(CUES))
        self.assertIn("0.4.2", state["version"])
