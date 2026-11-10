"""Unit tests of the checker, NOT a substitute for its real Docker build run."""

import contextlib
import io
import json
import subprocess
import types
import unittest
from pathlib import Path
from unittest import mock

from app import check_runtime as runtime


class RuntimeCheckTests(unittest.TestCase):
    def setUp(self):
        # Unit-test checker behavior without requiring a model or native wheels.
        self.symbols = {}
        def fake_import(name):
            module = types.SimpleNamespace()
            for _, import_name, symbol in runtime.DEPENDENCIES:
                if name == import_name and symbol:
                    function = mock.Mock(name=f"{name}.{symbol}")
                    self.symbols[(name, symbol)] = function
                    setattr(module, symbol, function)
            return module
        self.imports = mock.patch.object(runtime.importlib, "import_module", side_effect=fake_import).start()
        self.versions = mock.patch.object(runtime, "version", return_value="test-version").start()
        self.which = mock.patch.object(runtime.shutil, "which", side_effect=lambda n: f"/usr/bin/{n}").start()
        self.run = mock.patch.object(runtime.subprocess, "run", return_value=subprocess.CompletedProcess(
            [], 0, stdout="binary version test\n", stderr=""
        )).start()
        self.functional = mock.patch.object(runtime, "check_audio_stack", return_value={
            "status": "ok", "checks": {name: {"status": "ok"} for name in
                ("wav_decode", "mp4_decode", "silero_vad")}, "errors": []
        }).start()
        self.addCleanup(mock.patch.stopall)

    def test_all_real_runtime_imports_are_requested(self):
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["errors"], [])
        self.assertEqual(set(report["packages"]), {d for d, _, _ in runtime.DEPENDENCIES})
        self.imports.assert_any_call("requests")
        self.imports.assert_any_call("faster_whisper")
        self.assertEqual(set(report["binaries"]), {"ffmpeg", "ffprobe"})

    def test_missing_requests_fails_but_still_checks_whisper(self):
        original = self.imports.side_effect
        def missing(name):
            if name == "requests":
                raise ModuleNotFoundError("No module named 'requests'")
            return original(name)
        self.imports.side_effect = missing
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["component"], "requests")
        self.assertIn("ModuleNotFoundError", report["errors"][0]["error"])
        self.imports.assert_any_call("faster_whisper")

    def test_native_library_loading_error_is_failure(self):
        original = self.imports.side_effect
        self.imports.side_effect = lambda n: (_ for _ in ()).throw(OSError("missing shared library")) if n == "ctranslate2" else original(n)
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["component"], "ctranslate2")

    def test_missing_whisper_symbol_is_failure(self):
        original = self.imports.side_effect
        self.imports.side_effect = lambda n: types.SimpleNamespace() if n == "faster_whisper" else original(n)
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertIn("WhisperModel", report["errors"][0]["error"])

    def test_checker_never_instantiates_or_downloads_model(self):
        report = runtime.check_runtime()
        self.symbols[("faster_whisper", "WhisperModel")].assert_not_called()
        self.symbols[("huggingface_hub", "snapshot_download")].assert_not_called()
        self.symbols[("requests", "get")].assert_not_called()
        self.assertFalse(report["model_download_tested"])
        self.assertFalse(report["transcription_tested"])

    def test_missing_ffmpeg_is_failure(self):
        self.which.side_effect = lambda n: None if n == "ffmpeg" else f"/usr/bin/{n}"
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["component"], "ffmpeg")

    def test_failing_binary_is_failure(self):
        self.run.side_effect = subprocess.CalledProcessError(1, ["ffmpeg", "-version"])
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["errors"]), 2)

    def test_binary_timeout_is_failure(self):
        self.run.side_effect = subprocess.TimeoutExpired(["ffmpeg", "-version"], 10)
        self.assertEqual(runtime.check_runtime()["status"], "failed")

    def test_empty_binary_output_is_failure(self):
        self.run.return_value = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        self.assertEqual(runtime.check_runtime()["status"], "failed")

    def test_functional_checks_required_for_success(self):
        report = runtime.check_runtime()
        self.functional.assert_called_once_with()
        self.assertTrue(report["audio_decode_tested"])
        self.assertTrue(report["vad_tested"])
        self.assertFalse(report["transcription_tested"])

    def test_decoder_metadata_error_is_reported_and_cli_fails(self):
        self.functional.return_value = {
            "status": "failed", "checks": {"wav_decode": {"status": "failed"}},
            "errors": [{"component": "wav_decode", "error": "TypeError: open() got an unexpected keyword argument 'metadata_errors'"}]
        }
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertFalse(report["audio_decode_tested"])
        self.assertIn("metadata_errors", json.dumps(report))
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(runtime.main(), 1)

    def test_missing_functional_results_cannot_pass(self):
        self.functional.return_value = {"status": "ok", "checks": {}, "errors": []}
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["errors"]), 3)

    def test_functional_crash_is_a_controlled_failure(self):
        self.functional.side_effect = RuntimeError("native operation failed")
        report = runtime.check_runtime()
        self.assertEqual(report["status"], "failed")
        self.assertIn("native operation failed", json.dumps(report))

    def test_failed_import_does_not_run_functional_checks(self):
        self.imports.side_effect = ModuleNotFoundError("missing runtime")
        report = runtime.check_runtime()
        self.functional.assert_not_called()
        self.assertEqual(report["functional_checks"]["status"], "not_run")

    def test_cli_nonzero_on_failed_check(self):
        with mock.patch.object(runtime, "check_runtime", return_value={"status": "failed"}):
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(runtime.main(), 1)

    def test_cli_zero_on_success(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            self.assertEqual(runtime.main(), 0)
        self.assertIn("Runtime check OK", output.getvalue())


class PackagingTests(unittest.TestCase):
    def test_requests_is_an_explicit_pinned_dependency(self):
        root = Path(__file__).resolve().parents[1]
        requirements = (root / "requirements.txt").read_text(encoding="utf-8").splitlines()
        self.assertIn("requests==2.34.2", requirements)

    def test_pyav_compatibility_is_an_exact_pin(self):
        root = Path(__file__).resolve().parents[1]
        lines = (root / "requirements.txt").read_text().splitlines()
        self.assertIn("av==18.1.0", lines)
        self.assertIn("faster-whisper==1.1.1", lines)

    def test_docker_must_run_functional_checker_after_copy(self):
        root = Path(__file__).resolve().parents[1]
        text = (root / "Dockerfile").read_text()
        self.assertIn("python -m pip check", text)
        self.assertIn("RUN python -m app.check_runtime", text)
        self.assertLess(text.index("COPY app/"), text.index("RUN python -m app.check_runtime"))


if __name__ == "__main__":
    unittest.main()
