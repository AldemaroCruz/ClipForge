"""Regression tests. Whisper is mocked: no model download or ASR quality claim."""

import concurrent.futures
import copy
import json
import os
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import types
import unittest
from pathlib import Path
from unittest import mock

from fastapi.testclient import TestClient

with tempfile.TemporaryDirectory() as bootstrap:
    with mock.patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": bootstrap}):
        from app import main
from app.state import write_json_atomic

JOB_ID = "a" * 32


def state(status="queued"):
    return {"id": JOB_ID, "status": status, "clips": []}


def whisper_stub(segments=None, failure=None):
    module = types.ModuleType("faster_whisper")
    if segments is None:
        segments = [
            types.SimpleNamespace(start=0.0, end=11.0, text="Una idea que comienza aquí."),
            types.SimpleNamespace(start=11.0, end=22.0, text="Y una conclusión para cerrar el fragmento."),
        ]

    class FakeWhisper:
        def __init__(self, *args, **kwargs):
            if failure:
                raise failure

        def transcribe(self, *args, **kwargs):
            return iter(segments), types.SimpleNamespace(language="es")

    module.WhisperModel = FakeWhisper
    return mock.patch.dict(sys.modules, {"faster_whisper": module})


class AtomicStateTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "job.json"

    def test_unicode_and_complete_json_round_trip(self):
        value = {"text": "transcripción ñ 漢字", "clips": []}
        write_json_atomic(self.path, value)
        self.assertEqual(json.loads(self.path.read_text()), value)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_creates_missing_parent_directory(self):
        target = self.path.parent / "new" / "nested" / "job.json"
        write_json_atomic(target, state())
        self.assertEqual(json.loads(target.read_text()), state())

    def test_serialization_failure_does_not_truncate_existing_state(self):
        write_json_atomic(self.path, state())
        original = self.path.read_bytes()
        with self.assertRaises(TypeError):
            write_json_atomic(self.path, {"bad": object()})
        self.assertEqual(self.path.read_bytes(), original)

    def test_nan_rejected_without_changing_state(self):
        write_json_atomic(self.path, state())
        with self.assertRaises(ValueError):
            write_json_atomic(self.path, {"bad": float("nan")})
        self.assertEqual(json.loads(self.path.read_text()), state())

    def test_replace_failure_keeps_previous_file_and_cleans_temp(self):
        write_json_atomic(self.path, state())
        with mock.patch("app.state.os.replace", side_effect=PermissionError("locked")):
            with self.assertRaises(PermissionError):
                write_json_atomic(self.path, state("rendering"))
        self.assertEqual(json.loads(self.path.read_text()), state())
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_fsync_failure_keeps_previous_file_and_cleans_temp(self):
        write_json_atomic(self.path, state())
        with mock.patch("app.state.os.fsync", side_effect=OSError("disk error")):
            with self.assertRaises(OSError):
                write_json_atomic(self.path, state("rendering"))
        self.assertEqual(json.loads(self.path.read_text()), state())
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_readers_see_old_file_until_replace(self):
        write_json_atomic(self.path, state())
        real_replace = os.replace
        observed = []

        def inspect_replace(source, destination):
            self.assertEqual(Path(source).parent, self.path.parent)
            observed.append(json.loads(self.path.read_text()))
            self.assertEqual(json.loads(Path(source).read_text())["status"], "rendering")
            real_replace(source, destination)

        with mock.patch("app.state.os.replace", side_effect=inspect_replace):
            write_json_atomic(self.path, state("rendering"))
        self.assertEqual(observed, [state()])
        self.assertEqual(json.loads(self.path.read_text()), state("rendering"))

    def test_300_writes_with_four_unlocked_concurrent_readers(self):
        write_json_atomic(self.path, {"sequence": 0, "payload": "x" * 10000})
        start = threading.Barrier(5)

        def writer():
            start.wait(timeout=10)
            for sequence in range(1, 301):
                write_json_atomic(self.path, {"sequence": sequence, "payload": "x" * 10000})
                time.sleep(0.0001)

        def reader():
            start.wait(timeout=10)
            for _ in range(400):
                value = json.loads(self.path.read_text(encoding="utf-8"))
                self.assertEqual(value["payload"], "x" * 10000)
                self.assertIn(value["sequence"], range(301))
                time.sleep(0.0001)

        with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
            futures = [pool.submit(writer)] + [pool.submit(reader) for _ in range(4)]
            for future in futures:
                future.result(timeout=30)
        self.assertEqual(json.loads(self.path.read_text())["sequence"], 300)


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = mock.patch.object(main, "ROOT", self.root)
        self.delay_patch = mock.patch.object(main, "READ_DELAY_SECONDS", 0)
        self.root_patch.start()
        self.delay_patch.start()
        main.JOBS.clear()
        self.client = TestClient(main.app)
        self.client.__enter__()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(self.root_patch.stop)
        self.addCleanup(self.delay_patch.stop)
        self.addCleanup(lambda: self.client.__exit__(None, None, None))

    def seed(self, status="queued"):
        value = state(status)
        main.persist(JOB_ID, value)
        return value

    def test_health_version(self):
        response = self.client.get("/health")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {"status": "ok", "version": "0.4.2"})

    def test_home_and_static_assets(self):
        self.assertIn("v0.1.4", self.client.get("/").text)
        self.assertIn("MAX_RETRIES = 5", self.client.get("/static/app.js").text)
        self.assertEqual(self.client.get("/favicon.ico").status_code, 204)

    def test_valid_get_and_no_cache_header(self):
        self.seed()
        response = self.client.get(f"/jobs/{JOB_ID}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), state())
        self.assertEqual(response.headers["cache-control"], "no-store")

    def test_unknown_job_is_404(self):
        self.assertEqual(self.client.get(f"/jobs/{JOB_ID}").status_code, 404)

    def test_invalid_job_id_is_404(self):
        for value in ["invalid", "a" * 31, "A" * 32, "a" * 33]:
            with self.subTest(id=value):
                self.assertEqual(self.client.get(f"/jobs/{value}").status_code, 404)

    def test_corrupt_states_return_503_not_500_and_preserve_bytes(self):
        path = self.root / JOB_ID / "job.json"
        path.parent.mkdir()
        corrupt = [b"", b"{", b"null", b"[]", b"{}", b"\xff", b'{"id": "wrong"}',
                   json.dumps({**state(), "status": []}).encode(),
                   json.dumps({**state(), "clips": [None]}).encode()]
        for data in corrupt:
            with self.subTest(data=data):
                path.write_bytes(data)
                response = self.client.get(f"/jobs/{JOB_ID}")
                self.assertEqual(response.status_code, 503)
                self.assertEqual(response.headers["retry-after"], "2")
                self.assertEqual(path.read_bytes(), data)

    def test_transient_invalid_json_is_retried(self):
        self.seed()
        with mock.patch.object(Path, "read_text", side_effect=["", json.dumps(state())]) as read:
            response = self.client.get(f"/jobs/{JOB_ID}")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(read.call_count, 2)

    def test_permission_error_returns_503(self):
        self.seed()
        with mock.patch.object(Path, "read_text", side_effect=PermissionError("locked")):
            self.assertEqual(self.client.get(f"/jobs/{JOB_ID}").status_code, 503)

    def test_memory_snapshot_does_not_alias_worker_state(self):
        value = self.seed()
        value["clips"].append({"file": "clip_01.mp4"})
        self.assertEqual(main.JOBS[JOB_ID]["clips"], [])
        self.assertEqual(self.client.get(f"/jobs/{JOB_ID}").json()["clips"], [])

    def test_persist_failure_does_not_publish_memory_snapshot(self):
        self.seed()
        with mock.patch.object(main, "write_json_atomic", side_effect=OSError("full")):
            with self.assertRaises(OSError):
                main.persist(JOB_ID, state("completed"))
        self.assertEqual(main.JOBS[JOB_ID]["status"], "queued")
        self.assertEqual(main.load_job(JOB_ID)["status"], "queued")

    def test_polling_while_state_is_updated(self):
        self.seed()
        def writer():
            for _ in range(120):
                main.persist(JOB_ID, state("rendering"))
                time.sleep(0.0001)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(writer)
            for _ in range(120):
                response = self.client.get(f"/jobs/{JOB_ID}")
                self.assertEqual(response.status_code, 200)
                self.assertIn(response.json()["status"], ["queued", "rendering"])
            future.result(timeout=30)

    def test_upload_accepted_and_state_already_readable(self):
        # Do not launch Whisper in an HTTP contract test.
        with mock.patch.object(main, "process") as process:
            response = self.client.post("/jobs", files={"file": ("video.mp4", b"sample", "video/mp4")})
        self.assertEqual(response.status_code, 202)
        job_id = response.json()["id"]
        self.assertEqual(self.client.get(f"/jobs/{job_id}").status_code, 200)
        self.assertEqual((self.root / job_id / "input.mp4").read_bytes(), b"sample")

    def test_empty_upload_rejected_and_cleaned(self):
        response = self.client.post("/jobs", files={"file": ("video.mp4", b"", "video/mp4")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual([p for p in self.root.iterdir() if p.name != ".clipforge-runtime.lock"], [])

    def test_non_mp4_upload_rejected(self):
        response = self.client.post("/jobs", files={"file": ("video.txt", b"text", "text/plain")})
        self.assertEqual(response.status_code, 400)
        self.assertEqual([p for p in self.root.iterdir() if p.name != ".clipforge-runtime.lock"], [])

    def test_oversized_upload_rejected_and_cleaned(self):
        with mock.patch.object(main, "MAX_MB", 1):
            response = self.client.post("/jobs", files={"file": ("video.mp4", b"x" * (1024 * 1024 + 1), "video/mp4")})
        self.assertEqual(response.status_code, 413)
        self.assertEqual([p for p in self.root.iterdir() if p.name != ".clipforge-runtime.lock"], [])

    def test_clip_not_downloadable_before_publication(self):
        self.seed("rendering")
        (self.root / JOB_ID / "clip_01.mp4").write_bytes(b"unfinished")
        response = self.client.get(f"/jobs/{JOB_ID}/clips/clip_01.mp4")
        self.assertEqual(response.status_code, 404)

    def test_completed_clip_download(self):
        job = self.seed("completed")
        job["clips"] = [{"file": "clip_01.mp4", "start": 0, "end": 22}]
        main.persist(JOB_ID, job)
        (self.root / JOB_ID / "clip_01.mp4").write_bytes(b"finished")
        response = self.client.get(f"/jobs/{JOB_ID}/clips/clip_01.mp4")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"finished")
        self.assertIn("attachment", response.headers["content-disposition"])

    def test_non_clip_filename_rejected(self):
        self.seed()
        response = self.client.get(f"/jobs/{JOB_ID}/clips/input.mp4")
        self.assertEqual(response.status_code, 404)

    def test_restart_marks_unfinished_job_without_deleting_input(self):
        self.seed("transcribing")
        (self.root / JOB_ID / "input.mp4").write_bytes(b"preserve me")
        main.mark_interrupted_jobs()
        job = main.load_job(JOB_ID)
        self.assertEqual(job["status"], "failed")
        self.assertIn("reinicio", job["error"])
        self.assertEqual((self.root / JOB_ID / "input.mp4").read_bytes(), b"preserve me")

    def test_restart_preserves_completed_state_and_corrupt_file(self):
        job = self.seed("completed")
        main.mark_interrupted_jobs()
        self.assertEqual(main.load_job(JOB_ID), job)
        path = self.root / JOB_ID / "job.json"
        path.write_bytes(b"{broken")
        main.mark_interrupted_jobs()
        self.assertEqual(path.read_bytes(), b"{broken")

    @mock.patch.object(main, "inspect_media", return_value={"duration_seconds": 22.0, "audio_streams": 1, "video_streams": 1, "video_stream_index": 0})
    def test_processing_success_with_mocked_whisper_and_renderer(self, _probe):
        self.seed()
        with whisper_stub(), mock.patch.object(main, "ffmpeg", side_effect=lambda *args: Path(args[-1]).write_bytes(b"mock clip")):
            main.process(JOB_ID)
        job = main.load_job(JOB_ID)
        self.assertEqual(job["status"], "completed")
        self.assertEqual(len(job["clips"]), 1)
        self.assertEqual(job["language"], "es")
        self.assertEqual(len(json.loads((self.root / JOB_ID / "transcript.json").read_text())), 2)
        self.assertNotIn(JOB_ID, main.JOBS)

    @mock.patch.object(main, "inspect_media", return_value={"duration_seconds": 22.0, "audio_streams": 1, "video_streams": 1, "video_stream_index": 0})
    def test_processing_failure_is_persisted(self, _probe):
        self.seed()
        with whisper_stub(failure=RuntimeError("model unavailable")):
            main.process(JOB_ID)
        self.assertEqual(main.load_job(JOB_ID)["status"], "failed")
        self.assertIn("model unavailable", main.load_job(JOB_ID)["error"])

    @mock.patch.object(main, "inspect_media", return_value={"duration_seconds": 22.0, "audio_streams": 1, "video_streams": 1, "video_stream_index": 0})
    def test_no_speech_is_reported(self, _probe):
        self.seed()
        with whisper_stub(segments=[]):
            main.process(JOB_ID)
        self.assertEqual(main.load_job(JOB_ID)["status"], "failed")
        self.assertIn("No se detectó voz", main.load_job(JOB_ID)["error"])

    @mock.patch.object(main, "inspect_media", return_value={"duration_seconds": 22.0, "audio_streams": 1, "video_streams": 1, "video_stream_index": 0})
    def test_short_video_is_reported(self, _probe):
        self.seed()
        segments = [types.SimpleNamespace(start=0, end=10, text="demasiado corto")]
        with whisper_stub(segments=segments):
            main.process(JOB_ID)
        self.assertEqual(main.load_job(JOB_ID)["status"], "failed")
        self.assertIn("20 y 60 segundos", main.load_job(JOB_ID)["error"])

    def test_ffmpeg_error_includes_stderr(self):
        result = subprocess.CompletedProcess(args=[], returncode=1, stdout="", stderr="invalid video stream")
        with mock.patch.object(subprocess, "run", return_value=result):
            with self.assertRaisesRegex(RuntimeError, "invalid video stream"):
                main.ffmpeg("-i", "bad.mp4")

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/ffprobe not installed")
    def test_real_ffmpeg_render_and_download_with_stub_transcript(self):
        # Real encode/probe/decode; synthetic media and stubbed ASR, not real speech.
        self.seed()
        source = self.root / JOB_ID / "input.mp4"
        subprocess.run([
            "ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", "testsrc2=size=320x180:rate=5",
            "-f", "lavfi", "-i", "sine=frequency=440:sample_rate=16000",
            "-t", "22", "-c:v", "libx264", "-threads", "2", "-preset", "ultrafast",
            "-pix_fmt", "yuv420p", "-c:a", "aac", str(source),
        ], check=True, capture_output=True, timeout=30)
        with whisper_stub():
            main.process(JOB_ID)
        job = main.load_job(JOB_ID)
        self.assertEqual(job["status"], "completed", job.get("error"))
        clip = self.root / JOB_ID / job["clips"][0]["file"]
        probe = subprocess.run([
            "ffprobe", "-v", "error", "-show_streams", "-show_format", "-of", "json", str(clip),
        ], check=True, capture_output=True, text=True, timeout=10)
        data = json.loads(probe.stdout)
        video = next(s for s in data["streams"] if s["codec_type"] == "video")
        self.assertEqual((video["width"], video["height"]), (1080, 1920))
        self.assertEqual(video["pix_fmt"], "yuv420p")
        self.assertEqual(video["codec_name"], "h264")
        self.assertTrue(any(s["codec_type"] == "audio" for s in data["streams"]))
        self.assertAlmostEqual(float(data["format"]["duration"]), 22, delta=0.5)
        subprocess.run([
            "ffmpeg", "-nostdin", "-v", "error", "-i", str(clip), "-f", "null", "-",
        ], check=True, capture_output=True, timeout=30)
        response = self.client.get(f"/jobs/{JOB_ID}/clips/clip_01.mp4")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, clip.read_bytes())


if __name__ == "__main__":
    unittest.main()
