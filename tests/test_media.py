"""Input validation regressions. Real FFmpeg/ffprobe; no real Whisper inference."""
import contextlib
import copy
import io
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from auth_support import AuthenticatedTestClient as TestClient
from app import media
from app.check_media import make_fixture
from app import check_media as smoke

with tempfile.TemporaryDirectory() as bootstrap:
    with mock.patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": bootstrap}):
        from app import main

GOOD = {"duration_seconds": 22.0, "audio_streams": 1, "video_streams": 1,
        "video_stream_index": 0, "audio_stream_index": 1}
JOB_ID = "e" * 32


class MediaUnitTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "test.mp4"
        self.path.write_bytes(b"mock ffprobe input")

    def probe_result(self, payload):
        return mock.patch.object(media.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), ""))

    def test_valid_media_and_unknown_duration_allowed(self):
        for duration in (20, 60, None):
            media.validate_media({**GOOD, "duration_seconds": duration})

    def test_no_audio_is_distinct_from_silence(self):
        with self.assertRaises(media.MediaValidationError) as ctx:
            media.validate_media({**GOOD, "audio_streams": 0})
        self.assertEqual(ctx.exception.code, "NO_AUDIO_STREAM")
        self.assertIn("no contiene una pista de audio", str(ctx.exception))
        media.validate_media(GOOD)  # Metadata alone says nothing about speech.

    def test_no_video_rejected_but_audio_diagnostic_can_allow(self):
        with self.assertRaises(media.MediaValidationError) as ctx:
            media.validate_media({**GOOD, "video_streams": 0})
        self.assertEqual(ctx.exception.code, "NO_VIDEO_STREAM")
        media.validate_media({**GOOD, "video_streams": 0}, require_video=False)

    def test_short_video_rejected_without_rounding_away_boundary(self):
        with self.assertRaises(media.MediaValidationError) as ctx:
            media.validate_media({**GOOD, "duration_seconds": 19.999})
        self.assertEqual(ctx.exception.code, "VIDEO_TOO_SHORT")

    def test_missing_and_empty_files_do_not_run_ffprobe(self):
        with mock.patch.object(media.subprocess, "run") as run:
            with self.assertRaises(media.MediaValidationError) as ctx:
                media.inspect_media(self.path.parent / "missing.mp4")
            self.assertEqual(ctx.exception.code, "INPUT_NOT_FOUND")
            self.path.write_bytes(b"")
            with self.assertRaises(media.MediaValidationError) as ctx:
                media.inspect_media(self.path)
            self.assertEqual(ctx.exception.code, "EMPTY_INPUT")
            run.assert_not_called()

    def test_tool_missing_is_not_no_audio(self):
        with mock.patch.object(media.subprocess, "run", side_effect=FileNotFoundError):
            with self.assertRaisesRegex(RuntimeError, "ffprobe no está instalado"):
                media.inspect_media(self.path)

    def test_timeout_has_distinct_code(self):
        with mock.patch.object(media.subprocess, "run", side_effect=subprocess.TimeoutExpired("ffprobe", 30)):
            with self.assertRaises(media.MediaValidationError) as ctx:
                media.inspect_media(self.path)
        self.assertEqual(ctx.exception.code, "PROBE_TIMEOUT")

    def test_probe_failure_is_not_no_audio_even_with_empty_streams(self):
        result = subprocess.CompletedProcess([], 1, '{"streams": []}', 'Invalid data')
        with mock.patch.object(media.subprocess, "run", return_value=result):
            with self.assertRaises(media.MediaValidationError) as ctx:
                media.inspect_media(self.path)
        self.assertEqual(ctx.exception.code, "INVALID_MEDIA")

    def test_invalid_probe_json_and_shape_rejected(self):
        for payload in ("", "{", '[]', '{"streams":null}', '{"streams":[null]}', '{"format":[]}'):
            with self.subTest(payload=payload):
                result = subprocess.CompletedProcess([], 0, payload, "")
                with mock.patch.object(media.subprocess, "run", return_value=result):
                    with self.assertRaisesRegex(RuntimeError, "metadatos JSON inválidos"):
                        media.probe_media(self.path)

    def test_no_streams_returns_empty_metadata_then_validation_error(self):
        with self.probe_result({"format": {"duration": "5"}}):
            result = media.probe_media(self.path)
        self.assertEqual(result["audio_streams"], 0)
        self.assertEqual(result["video_streams"], 0)

    def test_primary_video_duration_preferred_over_long_audio(self):
        payload = {"format": {"duration": "120"}, "streams": [
            {"index": 0, "codec_type": "video", "duration": "5"},
            {"index": 1, "codec_type": "audio", "duration": "120"}]}
        with self.probe_result(payload):
            result = media.probe_media(self.path)
        self.assertEqual(result["duration_seconds"], 5)

    def test_unknown_and_nonfinite_durations_not_serialized_as_nan(self):
        for value in ("N/A", "nan", "inf", "-inf", "0", "-1", None):
            with self.probe_result({"format": {"duration": value}}):
                self.assertIsNone(media.probe_media(self.path)["duration_seconds"])

    def test_attached_cover_is_not_usable_video_and_stream_index_preserved(self):
        payload = {"streams": [
            {"index": 0, "codec_type": "video", "disposition": {"attached_pic": 1}},
            {"index": 1, "codec_type": "audio"},
            {"index": 2, "codec_type": "video"}]}
        with self.probe_result(payload):
            result = media.probe_media(self.path)
        self.assertEqual(result["video_streams"], 1)
        self.assertEqual(result["video_stream_index"], 2)
        self.assertEqual(result["audio_stream_index"], 1)

    def test_no_audio_prioritized_over_short_duration(self):
        with self.assertRaises(media.MediaValidationError) as ctx:
            media.validate_media({**GOOD, "audio_streams": 0, "duration_seconds": 5})
        self.assertEqual(ctx.exception.code, "NO_AUDIO_STREAM")

    def test_cli_codes_and_read_only_diagnostics(self):
        for exception, expected in ((media.MediaValidationError("NO_AUDIO_STREAM", "sin audio", GOOD), 2), (RuntimeError("tool failed"), 1)):
            stream = io.StringIO()
            with mock.patch.object(media, "inspect_media", side_effect=exception), contextlib.redirect_stdout(stream):
                code = media.main([str(self.path)])
            self.assertEqual(code, expected)
            self.assertFalse(json.loads(stream.getvalue())["transcription_tested"])
        with mock.patch.object(media, "inspect_media", return_value=GOOD), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(media.main([str(self.path)]), 0)

    def test_structural_smoke_fails_if_guard_silently_accepts_missing_audio(self):
        with mock.patch.object(smoke, "make_fixture"), mock.patch.object(smoke, "inspect_media", return_value=GOOD):
            report = smoke.check_media()
        self.assertEqual(report["status"], "failed")
        self.assertTrue(any(e["case"] == "without_audio" for e in report["errors"]))


@unittest.skipUnless(shutil.which("ffprobe") and shutil.which("ffmpeg"), "FFmpeg/ffprobe not installed")
class RealMediaTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.fixtures = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.fixtures.cleanup)
        cls.paths = {}
        for name, options in [("with_audio", {}), ("no_audio", {"audio": None}),
                              ("short", {"seconds": 5}), ("silence", {"audio": "silence"}),
                              ("audio_only", {"video": False})]:
            path = Path(cls.fixtures.name) / f"{name}.mp4"
            make_fixture(path, **options)
            cls.paths[name] = path
        cls.paths["invalid"] = Path(cls.fixtures.name) / "invalid.mp4"
        cls.paths["invalid"].write_bytes(b"not an mp4")

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        patcher = mock.patch.object(main, "ROOT", self.root)
        patcher.start()
        self.addCleanup(patcher.stop)
        main.JOBS.clear()

    def seed(self, fixture):
        main.persist(JOB_ID, {"id": JOB_ID, "status": "queued", "clips": []})
        target = self.root / JOB_ID / "input.mp4"
        target.write_bytes(self.paths[fixture].read_bytes())
        return target

    def test_real_ffprobe_recognizes_no_audio(self):
        result = media.probe_media(self.paths["no_audio"])
        self.assertEqual(result["audio_streams"], 0)
        self.assertEqual(result["video_streams"], 1)
        with self.assertRaises(media.MediaValidationError) as ctx:
            media.inspect_media(self.paths["no_audio"])
        self.assertEqual(ctx.exception.code, "NO_AUDIO_STREAM")

    def test_real_silence_is_an_audio_stream_not_no_audio(self):
        result = media.inspect_media(self.paths["silence"])
        self.assertEqual(result["audio_streams"], 1)
        self.assertEqual(result["audio_codec"], "aac")

    def test_real_short_and_audio_only_inputs_have_distinct_codes(self):
        for name, code in (("short", "VIDEO_TOO_SHORT"), ("audio_only", "NO_VIDEO_STREAM"), ("invalid", "INVALID_MEDIA")):
            with self.subTest(name=name), self.assertRaises(media.MediaValidationError) as ctx:
                media.inspect_media(self.paths[name])
            self.assertEqual(ctx.exception.code, code)

    def test_pipeline_rejects_no_audio_before_whisper_and_preserves_source(self):
        source = self.seed("no_audio")
        original = source.read_bytes()
        cls = mock.Mock(side_effect=AssertionError("Whisper must not be constructed"))
        with mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=cls)}):
            main.process(JOB_ID)
        cls.assert_not_called()
        result = main.load_job(JOB_ID)
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["error_code"], "NO_AUDIO_STREAM")
        self.assertEqual(result["media"]["audio_streams"], 0)
        self.assertEqual(result["clips"], [])
        self.assertEqual(source.read_bytes(), original)
        self.assertFalse((source.parent / "transcript.json").exists())
        with TestClient(main.app, projects=(JOB_ID,)) as client:
            response = client.get(f"/jobs/{JOB_ID}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["error_code"], "NO_AUDIO_STREAM")

    def test_pipeline_rejects_short_audio_before_whisper(self):
        self.seed("short")
        cls = mock.Mock(side_effect=AssertionError("Whisper must not be constructed"))
        with mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=cls)}):
            main.process(JOB_ID)
        cls.assert_not_called()
        self.assertEqual(main.load_job(JOB_ID)["error_code"], "VIDEO_TOO_SHORT")

    def test_upload_thread_to_poll_real_no_audio(self):
        cls = mock.Mock(side_effect=AssertionError("Whisper must not be constructed"))
        with mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=cls)}), TestClient(main.app, projects=(JOB_ID,)) as client:
            response = client.post("/jobs", files={"file": ("no_audio.mp4", self.paths["no_audio"].read_bytes(), "video/mp4")})
            self.assertEqual(response.status_code, 202)
            job_id = response.json()["id"]
            deadline = time.monotonic() + 10
            while True:
                job = client.get(f"/jobs/{job_id}").json()
                if job["status"] == "failed" or time.monotonic() > deadline:
                    break
                time.sleep(0.02)
            self.assertEqual(job["status"], "failed")
            self.assertEqual(job["error_code"], "NO_AUDIO_STREAM")
            cls.assert_not_called()
            self.assertEqual((self.root / job_id / "input.mp4").read_bytes(), self.paths["no_audio"].read_bytes())

    def test_real_valid_file_proceeds_to_transcribing_and_native_errors_not_mislabeled(self):
        self.seed("with_audio")
        model = mock.Mock()
        model.transcribe.side_effect = IndexError("tuple index out of range in a different location")
        cls = mock.Mock(return_value=model)
        statuses = []
        real_persist = main.persist
        def record(job_id, state):
            statuses.append(state["status"])
            real_persist(job_id, state)
        with mock.patch.object(main, "persist", side_effect=record), mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=cls)}):
            main.process(JOB_ID)
        self.assertEqual(statuses, ["validating", "transcribing", "failed"])
        result = main.load_job(JOB_ID)
        self.assertNotIn("error_code", result)
        self.assertIn("different location", result["error"])

    def test_silence_with_mocked_empty_asr_has_no_speech_code(self):
        self.seed("silence")
        model = mock.Mock()
        model.transcribe.return_value = iter([]), types.SimpleNamespace(language="es")
        with mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=mock.Mock(return_value=model))}):
            main.process(JOB_ID)
        self.assertEqual(main.load_job(JOB_ID)["error_code"], "NO_SPEECH_DETECTED")

    def test_whitespace_only_asr_is_not_a_clip_candidate(self):
        self.seed("with_audio")
        model = mock.Mock()
        model.transcribe.return_value = iter([types.SimpleNamespace(start=0, end=22, text="  ")]), types.SimpleNamespace(language="es")
        with mock.patch.dict(sys.modules, {"faster_whisper": types.SimpleNamespace(WhisperModel=mock.Mock(return_value=model))}):
            main.process(JOB_ID)
        self.assertEqual(main.load_job(JOB_ID)["error_code"], "NO_SPEECH_DETECTED")

    def test_restart_recognizes_validating_state(self):
        self.seed("with_audio")
        main.persist(JOB_ID, {"id": JOB_ID, "status": "validating", "clips": []})
        main.mark_interrupted_jobs()
        self.assertEqual(main.load_job(JOB_ID)["status"], "failed")
        self.assertIn("reinicio", main.load_job(JOB_ID)["error"])


if __name__ == "__main__":
    unittest.main()
