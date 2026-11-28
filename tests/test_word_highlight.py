"""Versioned timing, text identity and real rendering regressions for E01."""
import hashlib
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest

from PIL import Image

from app.cloud import caption_styles, clip_captions, word_highlight
from app.presentation import Presentation
from app.render import render_clip, run_ffmpeg
from app.subtitles import to_ass, to_srt, to_vtt


VERSION = "a" * 64


def mark(identity, text, start, end):
    return {"id": identity, "text": text, "start": start, "end": end}


def alignment(segments):
    return {"alignment_status": "ready", "segments": segments, "method": word_highlight.METHOD,
            "version": VERSION, "alignment_generation": "123", "alignment_sha256": "b" * 64}


class WordHighlightTests(unittest.TestCase):
    def test_late_repeated_words_are_pinned_after_case_punctuation_and_newline_edits(self):
        clip_start, clip_end = 1099.98, 1102.72
        cues = [{"start": .1, "end": 1.405, "text": "¡Lluvia!\nLLUVIA."},
                {"start": 1.5, "end": 2.68, "text": "Ahora, lluvia."}]
        marks = alignment([
            {"start": 1100.2, "end": 1101.2, "words": [mark("w3.1", "lluvia", 1100.2, 1100.51),
                                                       mark("w3.2", "lluvia", 1100.82, 1101.2)]},
            {"start": 1101.72, "end": 1102.52, "words": [mark("w4.1", "ahora", 1101.72, 1102.05),
                                                          mark("w4.2", "lluvia", 1102.11, 1102.52)]},
        ])
        plan = word_highlight.plan(cues, clip_start, clip_end, marks, version=VERSION)
        self.assertEqual((plan["status"], plan["version"], plan["timing"]), ("ready", VERSION, "centiseconds"))
        first, last = plan["cues"]
        self.assertEqual(first["text"], cues[0]["text"])
        self.assertEqual([(w["id"], w["start"], w["end"]) for w in first["words"]], [
            ("w3.1", .22, .53), ("w3.2", .84, 1.22),
        ])
        self.assertEqual(last["words"][-1]["id"], "w4.2")
        self.assertEqual(last["words"][-1]["text"], "lluvia.")
        for row in plan["cues"]:
            for word in row["words"]:
                self.assertEqual(row["text"][word["offset_start"]:word["offset_end"]], word["text"])

    def test_mutated_lexical_order_incomplete_alignment_and_changed_version_remain_static(self):
        cues = [{"start": 0.05, "end": 1.5, "text": "Café fresco"},
                {"start": 1.6, "end": 2.6, "text": "Frase sin marcas"}]
        marks = alignment([
            {"start": .15, "end": 1.41, "words": [mark("w1.1", "café", .15, .43), mark("w1.2", "fresco", .9, 1.41)]},
            {"start": 1.65, "end": 2.41, "words": []},
        ])
        plan = word_highlight.plan(cues, 0, 3, marks)
        self.assertEqual((plan["status"], plan["reason"]), ("partial", "unmatched_cues"))
        self.assertEqual(plan["cues"][1]["words"], [])
        for text in ("Fresco café", "Café", "Café muy fresco", "Cafés frescos"):
            with self.subTest(text=text):
                changed = word_highlight.plan([{**cues[0], "text": text}], 0, 3, marks)
                self.assertEqual((changed["status"], changed["cues"][0]["words"]), ("unavailable", []))
        changed = word_highlight.plan(cues, 0, 3, marks, version="c" * 64)
        self.assertEqual((changed["status"], changed["reason"]), ("unavailable", "alignment_changed"))
        self.assertEqual(changed["version"], "c" * 64)
        self.assertIsNone(changed["alignment_generation"])
        self.assertIsNone(changed["alignment_sha256"])

    def test_old_static_render_identity_and_style_defaults_are_preserved(self):
        source = {"generation": "4", "bytes": 5, "sha256": "1" * 64}
        options = Presentation(burn_subtitles=True).model_dump()
        old_options = {
            key: value
            for key, value in Presentation.model_validate(options).model_dump().items()
            if not key.startswith("subtitle_highlight_")
        }
        cues = [{"start": 0.0, "end": 1.0, "text": "Fijo"}]
        old = [{key: source.get(key) for key in ("generation", "bytes", "md5", "sha256")}, 0.0, 1.0, old_options, cues]
        expected = hashlib.sha256(json.dumps(old, ensure_ascii=False, sort_keys=True, separators=(",", ":"),
                                              allow_nan=False).encode()).hexdigest()
        self.assertEqual(clip_captions.render_fingerprint(source, 0, 1, old_options, cues), expected)
        self.assertEqual(clip_captions.render_fingerprint(source, 0, 1, {**options, "subtitle_highlight_color": "#00AAFF"}, cues), expected)
        self.assertNotEqual(clip_captions.render_fingerprint(source, 0, 1, {**options, "subtitle_highlight_enabled": True}, cues), expected)
        values = caption_styles.style_values({"subtitle_color": "#00ff21"})
        self.assertEqual((values["subtitle_highlight_enabled"], values["subtitle_highlight_color"]), (False, "#FFFF00"))

    def test_ass_keeps_complete_caption_between_word_events_and_escapes_author_markup(self):
        text = "Lluvia {extra}"
        cues = [{"start": 0, "end": 2.4, "text": text}]
        marks = alignment([{ "start": .50, "end": 1.7,
                             "words": [mark("w1.1", "lluvia", .5, .9), mark("w1.2", "extra", 1.4, 1.7)]}])
        plan = word_highlight.plan(cues, 0, 3, marks)
        rows = [row for row in to_ass(cues, word_highlight=plan, highlight_color="#00FF00").splitlines()
                if row.startswith("Dialogue:")]
        self.assertEqual([(row.split(",")[1], row.split(",")[2]) for row in rows], [
            ("0:00:00.00", "0:00:00.50"), ("0:00:00.50", "0:00:00.90"), ("0:00:00.90", "0:00:01.40"),
            ("0:00:01.40", "0:00:01.70"), ("0:00:01.70", "0:00:02.40"),
        ])
        self.assertTrue(all("Lluvia" in row and "｛extra｝" in row for row in rows))
        self.assertEqual([row.count(r"{\1c&H00FF00&}") for row in rows], [0, 1, 0, 1, 0])
        self.assertIn(text, to_srt(cues))
        self.assertIn(text, to_vtt(cues))


class HighlightRenderTests(unittest.TestCase):
    def test_actual_mp4_changes_one_word_without_moving_cue_and_preserves_sidecars(self):
        cues = [{"start": 0.04, "end": 2.38, "text": "Lluvia\nHuerto"}]
        marks = alignment([{ "start": .5, "end": 1.8,
                             "words": [mark("w1.1", "Lluvia", .5, .89), mark("w1.2", "Huerto", 1.42, 1.8)]}])
        plan = word_highlight.plan(cues, 0, 2.4, marks)
        with TemporaryDirectory() as directory:
            folder = Path(directory)
            source = folder / "input.mp4"
            run_ffmpeg("-f", "lavfi", "-i", "color=black:s=320x180:r=24", "-f", "lavfi", "-i", "sine=frequency=400",
                       "-t", 2.4, "-c:v", "libx264", "-threads", 1, "-c:a", "aac", source)
            enabled = folder / "enabled.mp4"
            disabled = folder / "disabled.mp4"
            options = Presentation(burn_subtitles=True, subtitle_highlight_enabled=True, subtitle_highlight_color="#00FF00")
            self.assertTrue(render_clip(source, enabled, start=0, end=2.4, cues=cues, options=options, word_highlight=plan))
            self.assertFalse(render_clip(source, disabled, start=0, end=2.4, cues=cues,
                                         options=options.model_copy(update={"subtitle_highlight_enabled": False}),
                                         word_highlight=plan))
            stored = {"options": options.model_dump(), "word_highlight": plan}
            self.assertEqual(clip_captions._highlight_receipt(stored)["highlight"]["status"], "unavailable")
            completed = clip_captions._highlight_receipt({**stored, "word_highlight_rendered": True})
            self.assertEqual(completed["highlight"]["status"], "ready")
            for suffix in (".srt", ".vtt"):
                self.assertEqual(enabled.with_suffix(suffix).read_bytes(), disabled.with_suffix(suffix).read_bytes())
            frames = []
            for index, (video, seconds) in enumerate(((enabled, .64), (enabled, 1.11), (enabled, 1.58), (disabled, .64))):
                png = folder / f"frame-{index}.png"
                run_ffmpeg("-ss", seconds, "-i", video, "-frames:v", 1, "-threads", 1, "-update", 1, png)
                with Image.open(png) as frame:
                    frames.append(self.pixels(frame))
            first, gap, last, static = frames
            self.assertGreater(first[1], 50)
            self.assertGreater(last[1], 50)
            self.assertEqual((gap[1], static[1]), (0, 0))
            self.assertLess(first[2], last[2])
            for bounds, _, _ in frames[:3]:
                self.assertTrue(all(abs(a - b) <= 2 for a, b in zip(bounds, static[0])))

    def pixels(self, frame):
        rgb = frame.convert("RGB")
        green = []
        bright = []
        for y in range(1400, 1920):
            for x in range(400, 680):
                r, g, b = rgb.getpixel((x, y))
                if max(r, g, b) > 215:
                    bright.append((x, y))
                if g > 180 and g - max(r, b) > 100:
                    green.append(y)
        xs, ys = zip(*bright)
        return (min(xs), max(xs), min(ys), max(ys)), len(green), sum(green) / len(green) if green else 0
