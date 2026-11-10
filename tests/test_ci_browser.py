"""Browser-runner gates only: dummy scripts and toolchain, no browser/HTTP here."""
from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import MagicMock, patch

from scripts import run_ci_browser as browser


class CIBrowserGateTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-ci-browser-gates-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.source = self.root / "source"
        for directory, _ in browser.SOURCE_DIRECTORIES:
            (self.source / directory).mkdir(parents=True, exist_ok=True)
        (self.source / "app" / "__init__.py").write_text("", encoding="utf-8")
        (self.source / "app" / "static" / "index.html").write_text("<p>fixture</p>", encoding="utf-8")
        for _, filename, _ in browser.SCENARIOS:
            (self.source / "tests" / filename).write_text("# Authored dummy script; not a browser test.\n", encoding="utf-8")
        (self.source / "data").mkdir()
        (self.source / "data" / "excluded.txt").write_text("fixture must not be copied", encoding="utf-8")
        (self.source / ".env").write_text("fixture, no credential", encoding="utf-8")
        self.executed = []

    def toolchain(self):
        return {"playwright_version": "fixture-version", "chromium_version": "fixture-browser",
                "chromium_revision": "fixture-revision", "executable": "/fixture/chromium"}

    def execute(self, script, source, environment, stdout, stderr, timeout):
        self.executed.append(script.name)
        self.assertNotEqual(source, self.source)
        self.assertTrue(script.is_file())
        self.assertFalse((source / "data").exists())
        self.assertFalse((source / ".env").exists())
        self.assertEqual(environment["CLIPFORGE_AI_PROVIDER"], "disabled")
        self.assertEqual(environment["CLIPFORGE_BROWSER_BRIDGE"], "0")
        self.assertEqual(environment["CHROMIUM_EXECUTABLE"], "/fixture/chromium")
        self.assertTrue(Path(environment["CLIPFORGE_DATA_DIR"]).is_relative_to(Path(tempfile.gettempdir()).resolve()))
        stdout.write_text("PASS: authored runner fixture, no browser was run\n", encoding="utf-8")
        stderr.write_text("", encoding="utf-8")
        return {"returncode": 0, "timed_out": False}

    def gate(self, **kwargs):
        return browser.run_browsers(
            self.source, self.root / "artifacts", environ={},
            toolchain_inspector=kwargs.pop("toolchain_inspector", self.toolchain),
            script_executor=kwargs.pop("script_executor", self.execute),
            which=kwargs.pop("which", lambda name: "/fixture/" + name), **kwargs,
        )

    def test_six_scenarios_are_attempted_with_smoke_simulation_separate(self):
        report = self.gate()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(len(self.executed), 6)
        self.assertEqual(report["direct_http_scenarios_passed"], 5)
        self.assertEqual(report["simulated_api_scenarios_passed"], 1)
        self.assertFalse(report["bridge_allowed"])
        self.assertFalse(report["real_asr_inference_tested"])
        self.assertFalse(report["real_llm_inference_tested"])

    def test_nonzero_scenario_fails_but_remaining_scenarios_are_attempted(self):
        def execute(*args):
            outcome = self.execute(*args)
            if args[0].name == "browser_editorial.py":
                outcome["returncode"] = 9
            return outcome
        report = self.gate(script_executor=execute)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(len(self.executed), 6)
        self.assertEqual(next(s for s in report["scenarios"] if s["name"] == "editorial")["status"], "failed")

    def test_bridge_output_cannot_be_reported_as_direct_http_success(self):
        def execute(*args):
            outcome = self.execute(*args)
            if args[0].name == "browser_operations.py":
                args[3].write_text("PASS: fixture\nSCOPE: HTTP bridge\n", encoding="utf-8")
            return outcome
        report = self.gate(script_executor=execute)
        self.assertEqual(report["exit_code"], 1)
        operation = next(s for s in report["scenarios"] if s["name"] == "operations")
        self.assertTrue(operation["bridge_detected"])
        self.assertEqual(operation["status"], "failed")

    def test_zero_exit_without_reported_steps_is_not_a_success(self):
        def execute(*args):
            outcome = self.execute(*args)
            args[3].write_text("", encoding="utf-8")
            return outcome
        report = self.gate(script_executor=execute)
        self.assertEqual(report["exit_code"], 1)
        self.assertTrue(all(s["status"] == "failed" for s in report["scenarios"]))

    def test_missing_toolchain_blocks_all_scenarios_without_faking_execution(self):
        def unavailable():
            raise ModuleNotFoundError("PRIVATE_TOOLCHAIN_FIXTURE")
        report = self.gate(toolchain_inspector=unavailable)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self.executed, [])
        self.assertEqual(len(report["scenarios"]), 6)
        self.assertTrue(all(s["status"] == "blocked" for s in report["scenarios"]))
        self.assertNotIn("PRIVATE_TOOLCHAIN_FIXTURE", json.dumps(report))

    def test_missing_ffprobe_is_a_failed_prerequisite(self):
        report = self.gate(which=lambda name: None if name == "ffprobe" else "/fixture/ffmpeg")
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(self.executed, [])
        self.assertEqual(report["direct_http_scenarios_passed"], 0)

    def test_existing_artifact_directory_is_never_reused(self):
        artifacts = self.root / "artifacts"
        artifacts.mkdir()
        sentinel = artifacts / "preserve.txt"
        sentinel.write_text("fixture unchanged", encoding="utf-8")
        report = self.gate()
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(sentinel.read_text(encoding="utf-8"), "fixture unchanged")
        self.assertEqual(self.executed, [])

    def test_module_import_does_not_start_processes_or_create_temporary_directories(self):
        spec = importlib.util.spec_from_file_location("clipforge_browser_import_fixture", browser.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(subprocess, "Popen") as process, patch.object(tempfile, "TemporaryDirectory") as temporary:
            spec.loader.exec_module(module)
        process.assert_not_called()
        temporary.assert_not_called()

    def test_timeout_terminates_only_the_owned_process_group(self):
        process = MagicMock()
        process.pid = 98765
        process.returncode = -15
        process.wait.side_effect = [subprocess.TimeoutExpired("fixture command", 1), -15]
        with patch.object(subprocess, "Popen", return_value=process) as start, \
                patch.object(os, "killpg", create=True) as kill_group:
            result = browser.execute_browser_script(
                self.source / "tests" / "browser_smoke.py", self.source, {},
                self.root / "stdout.log", self.root / "stderr.log", 1,
            )
        self.assertTrue(start.call_args.kwargs["start_new_session"])
        self.assertTrue(result["timed_out"])
        if os.name == "posix":
            kill_group.assert_called_once_with(process.pid, browser.signal.SIGTERM)
        else:
            process.terminate.assert_called_once()


if __name__ == "__main__":
    unittest.main()
