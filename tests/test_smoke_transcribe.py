"""Unit tests for the manual real-ASR diagnostic; these tests use mocked ASR."""
import contextlib
import io
import tempfile
import types
import unittest
from pathlib import Path
from unittest import mock

from app import smoke_transcribe as smoke


class SmokeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.source = Path(self.temp.name) / "voice.mp4"
        self.source.write_bytes(b"unit test, not actual video")
        probe = mock.patch.object(smoke, "inspect_media", return_value={"audio_streams": 1})
        probe.start()
        self.addCleanup(probe.stop)
        self.model = mock.Mock()
        self.cls = mock.Mock(return_value=self.model)
        self.importer = mock.patch.object(smoke.importlib, "import_module", return_value=types.SimpleNamespace(WhisperModel=self.cls))
        self.importer.start()
        self.addCleanup(self.importer.stop)
        self.model.transcribe.return_value = (iter([types.SimpleNamespace(start=0, end=22, text=" Hola ")]),
                                               types.SimpleNamespace(language="es"))

    def test_success_consumes_generator_and_does_not_modify_source(self):
        original = self.source.read_bytes()
        rows_seen = []
        def rows():
            for i in range(3):
                rows_seen.append(i)
                yield types.SimpleNamespace(start=i, end=i+1, text="Voz")
        self.model.transcribe.return_value = rows(), types.SimpleNamespace(language="es")
        report = smoke.transcribe_file(self.source, model_name="tiny")
        self.assertEqual(report["status"], "ok")
        self.assertEqual(rows_seen, [0, 1, 2])
        self.assertTrue(report["transcription_tested"])
        self.assertEqual(self.source.read_bytes(), original)
        self.model.transcribe.assert_called_once_with(str(self.source), language=None, beam_size=1, vad_filter=True)

    def test_late_inference_failure_is_not_a_success(self):
        def bad():
            yield types.SimpleNamespace(start=0, end=1, text="partial")
            raise RuntimeError("inference failed")
        self.model.transcribe.return_value = bad(), types.SimpleNamespace(language="es")
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(smoke.main([str(self.source)]), 1)

    def test_no_speech_has_distinct_nonzero_exit(self):
        self.model.transcribe.return_value = iter([]), types.SimpleNamespace(language="es")
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.main([str(self.source)]), 2)

    def test_missing_audio_never_imports_or_constructs_model(self):
        from app.media import MediaValidationError
        with mock.patch.object(smoke, "inspect_media", side_effect=MediaValidationError("NO_AUDIO_STREAM", "sin audio")):
            with self.assertRaises(MediaValidationError):
                smoke.transcribe_file(self.source, model_name="tiny")
        self.cls.assert_not_called()

    def test_missing_input_never_constructs_model(self):
        with self.assertRaises(FileNotFoundError):
            smoke.transcribe_file(self.source.parent / "absent.mp4", model_name="tiny")
        self.cls.assert_not_called()

    def test_empty_input_rejected(self):
        self.source.write_bytes(b"")
        with self.assertRaises(ValueError):
            smoke.transcribe_file(self.source, model_name="tiny")

    def test_cli_language_and_local_files_only_pass_through(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(smoke.main([str(self.source), "--language", "es", "--local-files-only"]), 0)
        self.cls.assert_called_once_with("tiny", device="cpu", compute_type="int8", local_files_only=True)
        self.model.transcribe.assert_called_once_with(str(self.source), language="es", beam_size=1, vad_filter=True)


if __name__ == "__main__":
    unittest.main()
