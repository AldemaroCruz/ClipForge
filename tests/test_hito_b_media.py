"""INT pilot upload, admission and media processing regressions."""
import base64
from datetime import datetime, timezone
import hashlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from fastapi import HTTPException

from app import media
from app.cloud import pilot, repository, storage
from app.cloud.config import BETA_MAX_BYTES, BETA_MAX_SECONDS, Settings


JOB = "a" * 32
OWNER = "b" * 32
WORKSPACE = "c" * 32
ORIGIN = "https://beta.example.test"
BUCKET = "pilot-unit"
ENDPOINT = "https://storage.googleapis.com"
UPLOAD_PATH = "/upload/storage/v1/b/" + BUCKET + "/o"
ORIGINAL = storage.beta_original(WORKSPACE, JOB)
PRINCIPAL = SimpleNamespace(id=OWNER, workspace_id=WORKSPACE)


class UploadStorageTests(TestCase):
    def setUp(self):
        settings = patch.object(storage, "settings", return_value=Settings(
            BUCKET, ENDPOINT, False, "cloud_run", "pilot", "us-central1", "worker",
        ))
        settings.start()
        self.addCleanup(settings.stop)

    def test_upload_capability_sets_origin_size_and_create_only_precondition(self):
        location = ENDPOINT + UPLOAD_PATH + "?uploadType=resumable&upload_id=synthetic-capability"
        response = MagicMock(headers={"Location": location})
        with patch.object(storage, "request", return_value=response) as request, patch.object(storage, "close") as close:
            self.assertEqual(storage.start_resumable(ORIGINAL, 2_147_483_648, ORIGIN), location)
        self.assertEqual(request.call_args.args, ("POST", ENDPOINT + UPLOAD_PATH))
        self.assertEqual(request.call_args.kwargs["params"], {
            "uploadType": "resumable", "name": ORIGINAL, "ifGenerationMatch": "0",
        })
        self.assertEqual(request.call_args.kwargs["headers"], {
            "Origin": ORIGIN, "X-Upload-Content-Type": "video/mp4", "X-Upload-Content-Length": "2147483648",
        })
        close.assert_called_once_with(response)

    def test_oversized_worker_original_is_rejected_before_opening_storage(self):
        with TemporaryDirectory() as temporary, patch.object(storage, "_download_once") as download:
            target = Path(temporary) / "worker" / "input.mp4"
            for size in (2_147_483_649, 0, True):
                with self.subTest(size=size), self.assertRaises(storage.InvalidUpload):
                    storage.download({"bytes": size}, target, max_bytes=BETA_MAX_BYTES)
            self.assertFalse(target.parent.exists())
            download.assert_not_called()
            accepted = {"bytes": 2_147_483_648}
            storage.download(accepted, target, max_bytes=BETA_MAX_BYTES)
            download.assert_called_once_with(accepted, target)

    def test_upload_destination_cannot_escape_origin_or_allocated_object(self):
        for location in (
            "https://other.example.test" + UPLOAD_PATH + "?upload_id=synthetic",
            ENDPOINT + "/upload/storage/v1/b/other/o?upload_id=synthetic",
            ENDPOINT + UPLOAD_PATH + "?upload_id=synthetic&name=another-object",
            ENDPOINT + UPLOAD_PATH + "?upload_id=synthetic&ifGenerationMatch=1",
        ):
            response = MagicMock(headers={"Location": location})
            with self.subTest(location=location), patch.object(storage, "request", return_value=response), patch.object(storage, "close"):
                with self.assertRaises(storage.StorageError):
                    storage.start_resumable(ORIGINAL, 1000, ORIGIN)

    def test_original_must_have_a_generation_size_and_checksum(self):
        data = b"synthetic bytes"
        digest = hashlib.md5(data, usedforsecurity=False).digest()
        metadata = {"name": ORIGINAL, "size": str(len(data)), "generation": "34",
                    "contentType": "video/mp4", "md5Hash": base64.b64encode(digest).decode()}
        response = MagicMock()
        response.json.return_value = metadata
        with patch.object(storage, "request", return_value=response) as request, patch.object(storage, "close"):
            item = storage.beta_original_metadata(ORIGINAL)
            self.assertEqual((item["generation"], item["bytes"], item["md5"]), ("34", len(data), digest.hex()))
            for changes in ({"generation": 34}, {"size": "0"}, {"contentEncoding": "gzip"}, {"md5Hash": "AAA="}):
                with self.subTest(changes=changes), self.assertRaises(storage.InvalidUpload):
                    response.json.return_value = {**metadata, **changes}
                    storage.beta_original_metadata(ORIGINAL)
            request.side_effect = storage.ObjectMissing
            self.assertIsNone(storage.beta_original_metadata(ORIGINAL))

        with TemporaryDirectory() as temporary, patch.object(storage, "request", return_value=response) as request, patch.object(storage, "close"):
            response.iter_content.return_value = [data]
            target = Path(temporary) / "synthetic.mp4"
            storage.download(item, target)
            self.assertEqual(target.read_bytes(), data)
            self.assertEqual(request.call_args.kwargs["params"], {"alt": "media", "generation": "34"})
            response.iter_content.return_value = [b"x" * len(data)]
            with self.assertRaises(storage.StorageError):
                storage.download(item, Path(temporary) / "incorrect.mp4")


class AdmissionTests(TestCase):
    request = SimpleNamespace(state=SimpleNamespace(principal=PRINCIPAL), headers={"Idempotency-Key": "same-request"})

    def test_oversize_never_reserves_a_project_or_cloud_capability(self):
        with patch.object(pilot, "_reserve") as reserve, self.assertRaises(HTTPException) as rejected:
            pilot.create_upload(pilot.Upload(filename="video.mp4", bytes=BETA_MAX_BYTES + 1), self.request)
        self.assertEqual(rejected.exception.status_code, 413)
        self.assertEqual(pilot.limits()["max_bytes"], 2_147_483_648)
        reserve.assert_not_called()

    def test_start_is_idempotent_and_pins_the_original(self):
        item = {"id": JOB, "pilot": True, "status": "awaiting_upload", "source_bytes": 2_147_483_648,
                "upload_expires_at": 2_000_000_000}
        doc = {"payload": item, "manifest": {}}
        original = {"name": ORIGINAL, "bytes": 2_147_483_648, "generation": "123"}
        with (
            patch.object(pilot, "get_engine"),
            patch.object(pilot.time, "time", return_value=1_000_000_000),
            patch.object(repository, "beta_document", return_value=doc) as read,
            patch.object(repository, "admit_beta") as admit,
            patch.object(repository, "update_document") as update,
            patch.object(repository, "enqueue") as enqueue,
            patch.object(storage, "beta_original_metadata", return_value=original) as metadata,
            patch.object(pilot, "_dispatch", side_effect=lambda job: job),
        ):
            self.assertEqual(pilot.start_job(JOB, self.request)["status"], "queued")
            self.assertEqual(pilot.start_job(JOB, self.request)["status"], "queued")
            self.assertEqual(read.call_count, 2)
            metadata.assert_called_once_with(ORIGINAL)
            admit.assert_called_once_with(read.call_args.args[0], OWNER, current_job=JOB)
            enqueue.assert_called_once()
            self.assertEqual(update.call_args.kwargs["manifest"], {"input.mp4": original})

    def test_ownership_check_precedes_document_access(self):
        connection = MagicMock()
        connection.execute.return_value.scalar.side_effect = [OWNER, None]
        with patch.object(repository, "document") as document, self.assertRaises(HTTPException) as rejected:
            repository.beta_document(connection, PRINCIPAL, JOB)
        self.assertEqual(rejected.exception.status_code, 404)
        self.assertEqual(connection.execute.call_args.args[1], {"i": JOB, "o": OWNER, "w": WORKSPACE})
        document.assert_not_called()

    def test_mismatched_or_oversized_stored_object_fails_without_dispatching(self):
        for stored_bytes, status in ((8, 422), (2_147_483_649, 413)):
            item = {"id": JOB, "pilot": True, "status": "awaiting_upload", "source_bytes": 7,
                    "upload_expires_at": 2_000_000_000}
            with (
                self.subTest(stored_bytes=stored_bytes),
                patch.object(pilot, "get_engine"),
                patch.object(pilot.time, "time", return_value=1_000_000_000),
                patch.object(repository, "beta_document", return_value={"payload": item}),
                patch.object(repository, "update_document"),
                patch.object(repository, "enqueue") as enqueue,
                patch.object(storage, "beta_original_metadata", return_value={"bytes": stored_bytes}),
                patch.object(pilot, "_dispatch") as dispatch,
            ):
                with self.assertRaises(HTTPException) as rejected:
                    pilot.start_job(JOB, self.request)
                self.assertEqual((rejected.exception.status_code, item["status"], item["error_code"]),
                                 (status, "failed", "UPLOAD_MISMATCH"))
                enqueue.assert_not_called()
                dispatch.assert_not_called()

    def test_retry_unpublishes_failed_state_and_reuses_only_the_existing_task(self):
        task_id = "d" * 32
        connection = MagicMock()
        connection.execute.return_value.mappings.return_value.first.return_value = {
            "id": task_id, "status": "failed", "cleaned_at": object(),
            "fence": 1, "updated_at": datetime(2026, 11, 25, tzinfo=timezone.utc), "attempts": 1,
        }
        item = {"id": JOB, "pilot": True, "status": "failed", "error_code": "WORKER_INTERRUPTED", "error": "raw"}
        with patch.object(repository, "update_document") as update:
            repository.retry_beta(connection, JOB, item)
            update.assert_called_once()
            self.assertEqual(connection.execute.call_args.args[1], {"i": task_id})
            self.assertEqual((item["status"], item["retry_count"]), ("queued", 1))
            self.assertNotIn("error", item)
            self.assertEqual(item["attempt_history"][0]["error_code"], "WORKER_INTERRUPTED")
            item.update(status="failed", error_code="WORKER_INTERRUPTED")
            repository.public_beta_failure(item)
            self.assertFalse(item["retryable"])
            with self.assertRaises(HTTPException):
                repository.retry_beta(connection, JOB, item)


class PilotMediaTests(TestCase):
    def test_metadata_checks_the_real_streams_duration_dimensions_and_aspect(self):
        valid = {"duration_seconds": 30, "container_duration_seconds": 30, "audio_duration_seconds": 30,
                 "format_name": "mov,mp4,m4a,3gp,3g2,mj2", "video_streams": 1, "audio_streams": 1,
                 "video_codec": "h264", "audio_codec": "aac", "major_brand": "isom",
                 "width": 1920, "height": 1080, "sample_aspect_ratio": "1:1"}
        original = Path("synthetic.mp4")
        with patch.object(media, "probe_media", return_value=valid) as probe:
            self.assertEqual(media.inspect_beta_media(original), valid)
            probe.assert_called_once_with(original, pilot=True)
            boundary = {**valid, "duration_seconds": BETA_MAX_SECONDS,
                        "container_duration_seconds": BETA_MAX_SECONDS + 0.02,
                        "audio_duration_seconds": BETA_MAX_SECONDS + 0.02}
            probe.return_value = boundary
            self.assertEqual(media.inspect_beta_media(original), boundary)
            for changes, code in (
                ({"duration_seconds": 19}, "VIDEO_TOO_SHORT"),
                ({"duration_seconds": None}, "VIDEO_OUTSIDE_LIMITS"),
                ({"duration_seconds": BETA_MAX_SECONDS + 0.02}, "VIDEO_OUTSIDE_LIMITS"),
                ({"audio_duration_seconds": BETA_MAX_SECONDS + 1}, "VIDEO_OUTSIDE_LIMITS"),
                ({"width": 1921}, "VIDEO_OUTSIDE_LIMITS"),
                ({"sample_aspect_ratio": "100:1"}, "VIDEO_OUTSIDE_LIMITS"),
                ({"sample_aspect_ratio": "1:4"}, "VIDEO_OUTSIDE_LIMITS"),
                ({"audio_codec": "opus"}, "UNSUPPORTED_MEDIA"),
                ({"major_brand": "qt  "}, "UNSUPPORTED_MEDIA"),
            ):
                with self.subTest(changes=changes), self.assertRaises(media.MediaValidationError) as rejected:
                    probe.return_value = {**valid, **changes}
                    media.inspect_beta_media(original)
                self.assertEqual(rejected.exception.code, code)

    def test_transcription_input_is_bounded_pcm_and_temp_file_is_removed(self):
        with TemporaryDirectory() as temporary, patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": temporary}):
            from app import transcribe

            def decode(*args):
                args[-1].write_bytes(bytes.fromhex("008000000040"))

            with patch.object(transcribe, "run_ffmpeg", side_effect=decode) as run:
                source = Path(temporary) / "input.mp4"
                samples = transcribe.beta_audio(source)
                self.assertEqual(samples.dtype.name, "float32")
                self.assertEqual(samples.tolist(), [-1.0, 0.0, 0.5])
                command = run.call_args.args
                self.assertEqual(command[:6], ("-protocol_whitelist", "file,pipe", "-f", "mov", "-i", source.resolve()))
                self.assertIn(16000, command)
                self.assertEqual(command[command.index("-af") + 1], "aresample=async=1:first_pts=0")
                self.assertEqual(command[command.index("-t") + 1], BETA_MAX_SECONDS + 1)
                self.assertEqual(command[command.index("-fs") + 1], (BETA_MAX_SECONDS + 1) * 32000)
                self.assertFalse(command[-1].parent.exists())

    def test_audio_budget_exhaustion_fails_before_passing_truncated_pcm_to_asr(self):
        with TemporaryDirectory() as temporary, patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": temporary}):
            from app import transcribe
            from app.cloud import config

            def decode(*args):
                args[-1].write_bytes(bytes(args[args.index("-fs") + 1]))

            with (patch.object(config, "BETA_MAX_SECONDS", 1),
                  patch.object(transcribe, "run_ffmpeg", side_effect=decode),
                  self.assertRaises(media.MediaValidationError) as rejected):
                transcribe.beta_audio(Path(temporary) / "input.mp4")
            self.assertEqual(rejected.exception.code, "VIDEO_OUTSIDE_LIMITS")

    def test_beta_transcript_and_clip_use_the_original_timeline(self):
        from app import main, transcribe

        job = {"id": JOB}
        source = {"duration_seconds": 1200, "video_streams": 1, "audio_streams": 1, "video_stream_index": 0}
        recognized = [
            SimpleNamespace(start=1174.0, end=1185.0, text="comienza el último fragmento"),
            SimpleNamespace(start=1185.0, end=1203.4, text="llega al final del video"),
            SimpleNamespace(start=1201.0, end=1204.0, text="segmento fuera del video"),
        ]
        model = MagicMock()
        model.transcribe.return_value = iter(recognized), SimpleNamespace(language="es")
        whisper = SimpleNamespace(WhisperModel=MagicMock(return_value=model))
        with (
            TemporaryDirectory() as temporary,
            patch.dict("sys.modules", {"faster_whisper": whisper}),
            patch.object(main, "ROOT", Path(temporary)),
            patch.object(transcribe, "resolve_model", return_value="test-model"),
            patch.object(main, "load_job", return_value=job),
            patch.object(main, "persist"),
            patch.object(transcribe, "beta_audio", return_value=range(1200 * 16000)),
            patch.object(main, "write_json_atomic") as write,
            patch.object(main, "render_clip") as render,
        ):
            main._process(JOB, MagicMock(), validated_media=source)

        self.assertEqual((job["status"], job["analysis_seconds"], job["speech_until_seconds"]),
                         ("completed", 1200.0, 1200.0))
        self.assertTrue(model.transcribe.call_args.kwargs["word_timestamps"])
        self.assertEqual(write.call_args.args[1], [
            {"start": 1174.0, "end": 1185.0, "text": "comienza el último fragmento"},
            {"start": 1185.0, "end": 1200.0, "text": "llega al final del video"},
        ])
        render.assert_called_once()
        self.assertTrue(render.call_args.kwargs["options"].burn_subtitles)
        self.assertTrue(job["clips"][0]["caption_rendered"])
        self.assertEqual(render.call_args.kwargs["cues"][0]["start"], 0.0)
        self.assertEqual(render.call_args.kwargs["cues"][-1]["end"], 26.0)
        self.assertEqual((render.call_args.kwargs["start"], render.call_args.kwargs["end"]),
                         (1174.0, 1200.0))

    def test_pilot_clip_has_bounded_encoding_options(self):
        from app.presentation import Presentation
        from app.render import render_clip

        with TemporaryDirectory() as temporary:
            folder = Path(temporary)
            commands = []

            def runner(*args):
                commands.append(args)
                args[-1].write_bytes(b"synthetic")

            for pilot_mode in (False, True):
                render_clip(folder / "input.mp4", folder / "clip.mp4", start=0, end=60.001,
                            options=Presentation(), cues=[], runner=runner, pilot=pilot_mode)
            legacy, bounded = commands
            self.assertNotIn("-maxrate", legacy)
            self.assertEqual(bounded[bounded.index("-maxrate"):bounded.index("-movflags")],
                             ("-maxrate", "2200k", "-bufsize", "4400k", "-b:a", "128k"))
            self.assertEqual(bounded[bounded.index("-t") + 1], "60.000")
