"""SEC-03 capture contracts over authored metadata and controlled subprocesses.

Packages, model snapshot, pip check, platform and clock are synthetic fixtures.
No installed-package inventory or model cache is read. The optional controlled
process is Python itself, never FFmpeg, network access or inference. CLI tests
execute the actual entry-block AST under the same fixture namespace.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager, ExitStack, redirect_stderr, redirect_stdout
import copy
import io
import json
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import capture_runtime as capture


SOURCE_ROOT = Path(__file__).resolve().parents[1]
EMPTY_VERSION = "FFmpeg version output is empty; capture stopped"
VERSION_LINE = "  ffmpeg version SYNTHETIC-CAPTURE-FIXTURE  "
PACKAGES = {name: "1.0.0" for name in sorted((
    "fastapi", "uvicorn", "python-multipart", "faster-whisper", "requests", "av",
))}
MODEL = {
    "schema": 1, "model": "tiny", "repo_id": "Systran/faster-whisper-tiny",
    "revision": "a" * 40, "network_used": False,
    "files": [{"name": name, "bytes": 1, "sha256": "b" * 64}
              for name in ("config.json", "model.bin", "tokenizer.json")],
}


class CaptureRuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-capture-contract-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.output = self.root / "capture-output"
        self.home = self.root / "synthetic-model-home-not-read"

    @contextmanager
    def fixtures(self, *, output=VERSION_LINE + "\nsynthetic secondary line\n", error=None, pip_code=0):
        with ExitStack() as stack:
            packages = stack.enter_context(patch.object(capture, "packages", return_value=copy.deepcopy(PACKAGES)))
            model = stack.enter_context(patch.object(capture, "model_snapshot", return_value=copy.deepcopy(MODEL)))
            pip = stack.enter_context(patch.object(capture.subprocess, "run", return_value=SimpleNamespace(returncode=pip_code)))
            ffmpeg = stack.enter_context(patch.object(capture.subprocess, "check_output", return_value=output, side_effect=error))
            stack.enter_context(patch.object(capture.platform, "python_version", return_value="3.12.0"))
            stack.enter_context(patch.object(capture.platform, "machine", return_value="synthetic-machine"))
            stack.enter_context(patch.object(capture.platform, "system", return_value="synthetic-system"))
            stack.enter_context(patch.object(capture.time, "time", return_value=123.0))
            yield SimpleNamespace(packages=packages, model=model, pip=pip, ffmpeg=ffmpeg)

    def test_ffmpeg_version_preserves_first_line_and_timeout_ten(self):
        with patch.object(capture.subprocess, "check_output", return_value=VERSION_LINE + "\nsecond line") as command:
            self.assertEqual(capture.ffmpeg_version(), VERSION_LINE)
        command.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_ffmpeg_version_rejects_empty_or_blank_first_line(self):
        for value in ("", "\n", "\r\n", " \t\n", "\nffmpeg version SYNTHETIC later line"):
            with self.subTest(output=value):
                with patch.object(capture.subprocess, "check_output", return_value=value) as command:
                    with self.assertRaises(ValueError) as raised:
                        capture.ffmpeg_version()
                self.assertEqual(str(raised.exception), EMPTY_VERSION)
                command.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_ffmpeg_version_preserves_nonzero_command_failure(self):
        error = subprocess.CalledProcessError(7, ["ffmpeg", "-version"], output="SYNTHETIC command output")
        with patch.object(capture.subprocess, "check_output", side_effect=error) as command:
            with self.assertRaises(subprocess.CalledProcessError) as raised:
                capture.ffmpeg_version()
        self.assertIs(raised.exception, error)
        self.assertEqual(raised.exception.returncode, 7)
        command.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_ffmpeg_version_preserves_timeout_exception(self):
        error = subprocess.TimeoutExpired(["ffmpeg", "-version"], 10)
        with patch.object(capture.subprocess, "check_output", side_effect=error) as command:
            with self.assertRaises(subprocess.TimeoutExpired) as raised:
                capture.ffmpeg_version()
        self.assertIs(raised.exception, error)
        self.assertEqual(raised.exception.timeout, 10)
        command.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_controlled_python_process_exercises_success_error_and_timeout(self):
        original = subprocess.check_output
        cases = (
            ("print('ffmpeg version SYNTHETIC controlled child')", None, 5.0),
            ("import sys; sys.exit(7)", subprocess.CalledProcessError, 5.0),
            ("import time; time.sleep(1)", subprocess.TimeoutExpired, 0.1),
        )
        for script, expected_error, fixture_timeout in cases:
            with self.subTest(expected_error=expected_error):
                def controlled(command, *, text, timeout):
                    self.assertEqual(command, ["ffmpeg", "-version"])
                    self.assertIs(text, True)
                    self.assertEqual(timeout, 10)  # The production setting never changes.
                    return original(
                        [sys.executable, "-B", "-S", "-c", script], text=text,
                        timeout=fixture_timeout, cwd=self.root,
                    )
                with patch.object(capture.subprocess, "check_output", side_effect=controlled):
                    if expected_error is None:
                        self.assertEqual(capture.ffmpeg_version(), "ffmpeg version SYNTHETIC controlled child")
                    else:
                        with self.assertRaises(expected_error) as raised:
                            capture.ffmpeg_version()
                        if expected_error is subprocess.CalledProcessError:
                            self.assertEqual(raised.exception.returncode, 7)
                        else:
                            self.assertEqual(raised.exception.timeout, 0.1)

    def test_capture_valid_version_writes_only_synthetic_capture_outputs(self):
        output = io.StringIO()
        with self.fixtures() as mocks, redirect_stdout(output):
            capture.capture(self.output, self.home, "tiny")
        self.assertEqual({path.name for path in self.output.iterdir()}, {
            "runtime-lock.json", "runtime-requirements.txt", "model-lock.json",
        })
        report = json.loads((self.output / "runtime-lock.json").read_text(encoding="utf-8"))
        self.assertEqual(report["ffmpeg"], VERSION_LINE)
        self.assertEqual(report["packages"], PACKAGES)
        self.assertEqual(report["python"], "3.12.0")
        self.assertEqual(report["machine"], "synthetic-machine")
        self.assertEqual(report["system"], "synthetic-system")
        self.assertEqual(report["captured_at"], 123.0)
        self.assertFalse(report["network_used"])
        self.assertFalse(report["inference_tested"])
        self.assertEqual(json.loads((self.output / "model-lock.json").read_text(encoding="utf-8")), MODEL)
        requirements = (self.output / "runtime-requirements.txt").read_text(encoding="utf-8")
        self.assertEqual(requirements.splitlines()[1:], [f"{name}=={version}" for name, version in PACKAGES.items()])
        self.assertEqual(json.loads(output.getvalue())["status"], "ok")
        mocks.packages.assert_called_once_with()
        mocks.model.assert_called_once_with(self.home, "tiny")
        mocks.pip.assert_called_once_with([sys.executable, "-m", "pip", "check"], capture_output=True, text=True, timeout=60)
        mocks.ffmpeg.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)
        self.assertFalse(self.home.exists())

    def test_capture_ffmpeg_failures_publish_no_outputs(self):
        failures = (
            ("", None, ValueError), (" \n", None, ValueError),
            (None, subprocess.CalledProcessError(7, ["ffmpeg", "-version"]), subprocess.CalledProcessError),
            (None, subprocess.TimeoutExpired(["ffmpeg", "-version"], 10), subprocess.TimeoutExpired),
        )
        for index, (text, error, expected_type) in enumerate(failures):
            with self.subTest(error=expected_type, output=text):
                destination = self.root / f"failed-capture-{index}"
                with self.fixtures(output=text, error=error) as mocks:
                    with self.assertRaises(expected_type):
                        capture.capture(destination, self.home, "tiny")
                self.assertFalse(destination.exists())
                self.assertFalse(self.home.exists())
                mocks.ffmpeg.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_cli_source_entry_fails_closed_without_publishing_outputs(self):
        tree = ast.parse(Path(capture.__file__).read_text(encoding="utf-8"))
        guards = [node for node in tree.body if isinstance(node, ast.If)
                  and isinstance(node.test, ast.Compare) and isinstance(node.test.left, ast.Name)
                  and node.test.left.id == "__name__"]
        self.assertEqual(len(guards), 1)
        entry = compile(ast.Module(body=guards, type_ignores=[]), str(capture.__file__), "exec")
        failures = (
            ("", None, "ValueError"),
            (None, subprocess.CalledProcessError(7, ["ffmpeg", "-version"], output="SYNTHETIC_MUST_NOT_LEAK"), "CalledProcessError"),
            (None, subprocess.TimeoutExpired(["ffmpeg", "-version"], 10), "TimeoutExpired"),
        )
        for index, (text, error, error_type) in enumerate(failures):
            with self.subTest(error_type=error_type):
                destination = self.root / f"failed-cli-{index}"
                stderr, stdout = io.StringIO(), io.StringIO()
                namespace = {"__name__": "__main__", "__doc__": capture.__doc__, "argparse": argparse,
                             "Path": Path, "capture": capture.capture, "json": json, "sys": sys}
                argv = ["capture_runtime.py", "--output", str(destination), "--cache", str(self.home), "--model", "tiny"]
                with self.fixtures(output=text, error=error) as mocks, patch.object(sys, "argv", argv), \
                        redirect_stderr(stderr), redirect_stdout(stdout):
                    with self.assertRaises(SystemExit) as raised:
                        exec(entry, namespace)
                self.assertEqual(raised.exception.code, 1)
                result = json.loads(stderr.getvalue())
                self.assertEqual(result["status"], "failed")
                self.assertEqual(result["error_type"], error_type)
                self.assertEqual(result["message"], EMPTY_VERSION if error_type == "ValueError"
                                 else "Cannot capture runtime/model; original data unchanged.")
                self.assertNotIn("SYNTHETIC_MUST_NOT_LEAK", stderr.getvalue())
                self.assertEqual(stdout.getvalue(), "")
                self.assertFalse(destination.exists())
                self.assertFalse(self.home.exists())
                mocks.model.assert_called_once_with(self.home, "tiny")
                mocks.ffmpeg.assert_called_once_with(["ffmpeg", "-version"], text=True, timeout=10)

    def test_pip_check_failure_remains_blocking_before_model_or_ffmpeg(self):
        with self.fixtures(pip_code=1) as mocks:
            with self.assertRaisesRegex(ValueError, "pip check failed in existing runtime; capture stopped"):
                capture.capture(self.output, self.home, "tiny")
        self.assertFalse(self.output.exists())
        self.assertFalse(self.home.exists())
        mocks.model.assert_not_called()
        mocks.ffmpeg.assert_not_called()
        mocks.pip.assert_called_once_with([sys.executable, "-m", "pip", "check"], capture_output=True, text=True, timeout=60)

    def test_main_has_no_unused_subprocess_import_without_importing_application(self):
        tree = ast.parse((SOURCE_ROOT / "app/main.py").read_text(encoding="utf-8"))
        imports = [alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names]
        from_imports = [node.module for node in ast.walk(tree) if isinstance(node, ast.ImportFrom)]
        self.assertNotIn("subprocess", imports)
        self.assertNotIn("subprocess", from_imports)


if __name__ == "__main__":
    unittest.main()
