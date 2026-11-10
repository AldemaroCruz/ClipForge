"""Strict CI gate regressions using stdlib, in-memory suites and temporary files.

These tests do not execute Docker, pip, FFmpeg, application imports or inference.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import importlib.util
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import run_ci_tests as ci


class CIRunnerTests(unittest.TestCase):
    def setUp(self):
        self.environment = {
            "CLIPFORGE_AI_PROVIDER": "disabled",
            "CLIPFORGE_DATA_DIR": str(Path(tempfile.gettempdir()) / "clipforge-ci-config-fixture"),
        }
        self.environment_patch = patch.dict(os.environ, self.environment, clear=True)
        self.environment_patch.start()
        self.addCleanup(self.environment_patch.stop)
        self.commands = []

    def command(self, command, **kwargs):
        self.commands.append((command, kwargs))
        return SimpleNamespace(returncode=0)

    def gate(self, *, suite_factory=None, **kwargs):
        if suite_factory is None:
            suite_factory = lambda: unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        return ci.run_ci(
            Path(__file__).resolve().parents[1],
            environ=self.environment,
            command_runner=kwargs.pop("command_runner", self.command),
            which=kwargs.pop("which", lambda name: "/fixture/" + name),
            discover=kwargs.pop("discover", lambda root: suite_factory()),
            stream=io.StringIO(),
            **kwargs,
        )

    def test_import_has_no_checker_discovery_or_environment_side_effects(self):
        before_environment = dict(os.environ)
        before_path = sys.path[:]
        before_bytecode = sys.dont_write_bytecode
        spec = importlib.util.spec_from_file_location("clipforge_ci_import_fixture", ci.__file__)
        module = importlib.util.module_from_spec(spec)
        with patch.object(subprocess, "run") as command, \
                patch.object(tempfile, "TemporaryDirectory") as temporary, \
                patch.object(unittest.TestLoader, "discover") as discovery:
            spec.loader.exec_module(module)
        command.assert_not_called()
        temporary.assert_not_called()
        discovery.assert_not_called()
        self.assertEqual(dict(os.environ), before_environment)
        self.assertEqual(sys.path, before_path)
        self.assertEqual(sys.dont_write_bytecode, before_bytecode)

    def test_complete_gate_passes_and_attempts_every_offline_checker(self):
        report = self.gate()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["tests"]["tests_run"], 1)
        self.assertEqual(len(self.commands), 5)
        self.assertEqual(
            [command[3:] for command, _ in self.commands],
            [["pip", "check"], ["app.check_runtime"], ["app.check_media"],
             ["app.check_presentation"], ["app.check_branding"]],
        )
        for command, options in self.commands:
            self.assertEqual(command[:3], [sys.executable, "-B", "-m"])
            self.assertEqual(options["env"]["HF_HUB_OFFLINE"], "1")
            self.assertEqual(options["env"]["PIP_NO_INDEX"], "1")
        self.assertFalse(report["real_asr_inference_tested"])
        self.assertFalse(report["real_llm_inference_tested"])

    def test_empty_suite_is_a_failure(self):
        report = self.gate(suite_factory=unittest.TestSuite)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["tests_run"], 0)
        self.assertEqual(report["suite_status"], "failed")

    def test_skipped_case_is_a_failure(self):
        class Skipped(unittest.TestCase):
            @unittest.skip("fixture skip")
            def runTest(self):
                pass
        report = self.gate(suite_factory=lambda: unittest.TestSuite([Skipped()]))
        self.assertEqual(report["tests"]["skipped"], 1)
        self.assertEqual(report["exit_code"], 1)

    def test_expected_failure_is_a_failure(self):
        class Expected(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                self.fail("fixture expected failure")
        report = self.gate(suite_factory=lambda: unittest.TestSuite([Expected()]))
        self.assertEqual(report["tests"]["expected_failures"], 1)
        self.assertEqual(report["exit_code"], 1)

    def test_unexpected_success_is_a_failure(self):
        class Unexpected(unittest.TestCase):
            @unittest.expectedFailure
            def runTest(self):
                pass
        report = self.gate(suite_factory=lambda: unittest.TestSuite([Unexpected()]))
        self.assertEqual(report["tests"]["unexpected_successes"], 1)
        self.assertEqual(report["exit_code"], 1)

    def test_assertion_failure_is_a_failure_without_error_text_in_report(self):
        class Failed(unittest.TestCase):
            def runTest(self):
                self.fail("PRIVATE_FIXTURE_DO_NOT_REPORT")
        report = self.gate(suite_factory=lambda: unittest.TestSuite([Failed()]))
        self.assertEqual(report["tests"]["failures"], 1)
        self.assertEqual(report["exit_code"], 1)
        self.assertNotIn("PRIVATE_FIXTURE_DO_NOT_REPORT", json.dumps(report))

    def test_runtime_error_is_a_failure(self):
        def raises():
            raise RuntimeError("fixture error")
        report = self.gate(suite_factory=lambda: unittest.TestSuite([unittest.FunctionTestCase(raises)]))
        self.assertEqual(report["tests"]["errors"], 1)
        self.assertEqual(report["exit_code"], 1)

    def test_discovery_exception_fails_after_all_checks_without_leaking_message(self):
        def broken(root):
            raise ImportError("PRIVATE_FIXTURE_IMPORT")
        report = self.gate(discover=broken)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["errors"], 1)
        self.assertEqual(report["suite_error_type"], "ImportError")
        self.assertEqual(len(self.commands), 5)
        self.assertNotIn("PRIVATE_FIXTURE_IMPORT", json.dumps(report))

    def test_discovery_system_exit_is_an_error_and_cannot_bypass_the_report(self):
        def exits(root):
            raise SystemExit(0)
        report = self.gate(discover=exits)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["errors"], 1)
        self.assertEqual(report["suite_error_type"], "SystemExit")
        self.assertEqual(len(self.commands), 5)

    def test_real_discovery_reports_broken_import_and_runs_other_cases(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-discovery-") as temporary:
            root = Path(temporary)
            tests = root / "tests"
            tests.mkdir()
            (tests / "test_ci_fixture_broken.py").write_text(
                "raise ImportError('deliberate fixture import failure')\n", encoding="utf-8"
            )
            (tests / "test_ci_fixture_success.py").write_text(
                "import unittest\nclass Fixture(unittest.TestCase):\n"
                "    def test_pass(self): pass\n", encoding="utf-8"
            )
            try:
                report = ci.run_ci(
                    root, environ=self.environment, command_runner=self.command,
                    which=lambda name: "/fixture/" + name, stream=io.StringIO(),
                )
            finally:
                for name in ("test_ci_fixture_broken", "test_ci_fixture_success"):
                    sys.modules.pop(name, None)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["tests_run"], 2)
        self.assertEqual(report["tests"]["errors"], 1)

    def test_missing_binary_still_attempts_all_checks_and_the_suite(self):
        report = self.gate(which=lambda name: None if name == "ffprobe" else "/fixture/ffmpeg")
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["suite_status"], "passed")
        self.assertEqual(report["tests"]["tests_run"], 1)
        self.assertEqual(len(self.commands), 5)
        self.assertEqual(next(c for c in report["checks"] if c["name"] == "ffprobe")["status"], "failed")

    def test_checker_nonzero_still_runs_remaining_checks_and_suite(self):
        def command(arguments, **kwargs):
            self.command(arguments, **kwargs)
            return SimpleNamespace(returncode=7 if "app.check_runtime" in arguments else 0)
        report = self.gate(command_runner=command)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["suite_status"], "passed")
        self.assertEqual(len(self.commands), 5)
        self.assertEqual(next(c for c in report["checks"] if c["name"] == "runtime")["returncode"], 7)

    def test_checker_timeout_is_reported_without_skipping_suite(self):
        def command(arguments, **kwargs):
            self.command(arguments, **kwargs)
            if "pip" in arguments:
                raise subprocess.TimeoutExpired("PRIVATE_FIXTURE_COMMAND", 60)
            return SimpleNamespace(returncode=0)
        report = self.gate(command_runner=command)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["tests_run"], 1)
        self.assertEqual(len(self.commands), 5)
        self.assertEqual(next(c for c in report["checks"] if c["name"] == "pip_check")["error_type"], "TimeoutExpired")
        self.assertNotIn("PRIVATE_FIXTURE_COMMAND", json.dumps(report))

    def test_data_and_ai_are_isolated_before_checks_and_discovery_then_restored(self):
        original_path = sys.path[:]
        original_bytecode = sys.dont_write_bytecode
        observed = []
        def observe():
            path = Path(os.environ["CLIPFORGE_DATA_DIR"])
            self.assertNotEqual(str(path), self.environment["CLIPFORGE_DATA_DIR"])
            self.assertTrue(path.is_relative_to(Path(tempfile.gettempdir()).resolve()))
            self.assertEqual(os.environ["CLIPFORGE_AI_PROVIDER"], "disabled")
            self.assertTrue(sys.dont_write_bytecode)
            observed.append(path)
        def command(arguments, **kwargs):
            observe()
            return self.command(arguments, **kwargs)
        def discover(root):
            observe()
            return unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        report = self.gate(command_runner=command, discover=discover)
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(len(observed), 6)
        self.assertEqual(dict(os.environ), self.environment)
        self.assertEqual(sys.path, original_path)
        self.assertEqual(sys.dont_write_bytecode, original_bytecode)
        self.assertFalse(observed[0].parent.exists())

    def test_unsafe_input_environment_fails_but_suite_uses_fresh_disabled_settings(self):
        self.environment.update(CLIPFORGE_AI_PROVIDER="openai", CLIPFORGE_DATA_DIR="/data")
        def discover(root):
            self.assertEqual(os.environ["CLIPFORGE_AI_PROVIDER"], "disabled")
            self.assertNotEqual(os.environ["CLIPFORGE_DATA_DIR"], "/data")
            return unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        report = self.gate(discover=discover)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["suite_status"], "passed")
        self.assertEqual(report["checks"][0]["status"], "failed")

    def test_missing_relative_or_temp_root_data_path_is_rejected(self):
        for value in ("", "relative-data", tempfile.gettempdir()):
            with self.subTest(value=value):
                env = {**self.environment, "CLIPFORGE_DATA_DIR": value}
                self.assertEqual(ci.environment_check(env)["status"], "failed")

    def test_main_writes_failure_report_and_returns_nonzero(self):
        report = self.gate(which=lambda name: None)
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-report-") as temporary:
            destination = Path(temporary) / "artifacts" / "summary.json"
            output = io.StringIO()
            with patch.object(ci, "run_ci", return_value=report), redirect_stdout(output):
                exit_code = ci.main(["--report", str(destination)])
            written = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(exit_code, 1)
        self.assertEqual(written["status"], "failed")
        self.assertEqual(json.loads(output.getvalue()), written)

    def test_report_never_overwrites_existing_artifact(self):
        report = self.gate()
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-report-") as temporary:
            destination = Path(temporary) / "summary.json"
            destination.write_text("preserve fixture", encoding="utf-8")
            output = io.StringIO()
            with patch.object(ci, "run_ci", return_value=report), redirect_stdout(output):
                exit_code = ci.main(["--report", str(destination)])
            self.assertEqual(destination.read_text(encoding="utf-8"), "preserve fixture")
        self.assertEqual(exit_code, 1)
        result = json.loads(output.getvalue())
        self.assertEqual(result["checks"][-1]["name"], "report_write")
        self.assertEqual(result["checks"][-1]["error_type"], "FileExistsError")

    def test_inventory_contains_sorted_actual_ids_before_suite_is_consumed(self):
        class Fixture(unittest.TestCase):
            def test_alpha(self): pass
            def test_beta(self): pass
        cases = [Fixture("test_beta"), Fixture("test_alpha")]
        expected = sorted(case.id() for case in cases)
        report = self.gate(suite_factory=lambda: unittest.TestSuite(cases))
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["test_inventory"]["ids"], expected)
        self.assertEqual(report["test_inventory"]["discovered"], 2)
        self.assertEqual(report["test_inventory"]["unique"], 2)
        self.assertEqual(report["test_inventory"]["duplicate_ids"], [])

    def test_duplicate_discovered_ids_cannot_inflate_a_green_inventory(self):
        class Fixture(unittest.TestCase):
            def runTest(self): pass
        report = self.gate(suite_factory=lambda: unittest.TestSuite([Fixture(), Fixture()]))
        self.assertEqual(report["suite_status"], "passed")
        self.assertEqual(report["tests"]["tests_run"], 2)
        self.assertEqual(report["test_inventory"]["unique"], 1)
        self.assertEqual(len(report["test_inventory"]["duplicate_ids"]), 1)
        self.assertEqual(report["exit_code"], 1)

    def test_prematurely_stopped_suite_cannot_hide_discovered_cases(self):
        class Fixture(unittest.TestCase):
            def test_alpha(self): pass
            def test_beta(self): pass
        def incomplete(suite, stream):
            first = next(iter(suite))
            return ci.execute_suite(unittest.TestSuite([first]), stream)
        report = self.gate(suite_factory=lambda: unittest.TestSuite([
            Fixture("test_alpha"), Fixture("test_beta"),
        ]), suite_executor=incomplete)
        self.assertEqual(report["tests"]["tests_run"], 1)
        self.assertEqual(report["test_inventory"]["discovered"], 2)
        self.assertEqual(report["exit_code"], 1)

    def test_coverage_measures_before_discovery_with_explicit_sources_and_no_omit(self):
        observed = {}
        class Collector:
            def __init__(self, **kwargs):
                observed["options"] = kwargs
            def start(self): observed["started"] = True
            def stop(self): observed["stopped"] = True
            def save(self): observed["saved"] = True
            def json_report(self, *, outfile, pretty_print):
                Path(outfile).write_text('{"totals":{"percent_covered":42.5}}', encoding="utf-8")
                return 42.5
            def xml_report(self, *, outfile):
                Path(outfile).write_text('<coverage/>', encoding="utf-8")
        def discover(root):
            self.assertTrue(observed["started"])
            return unittest.TestSuite([unittest.FunctionTestCase(lambda: None)])
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-coverage-") as temporary:
            destination = Path(temporary) / "coverage"
            report = self.gate(discover=discover, coverage_directory=destination, coverage_factory=Collector)
            self.assertTrue((destination / "coverage.json").is_file())
            self.assertTrue((destination / "coverage.xml").is_file())
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["coverage"]["percent_covered"], 42.5)
        self.assertTrue(report["coverage"]["measured"])
        self.assertIsNone(report["coverage"]["threshold"])
        self.assertFalse(report["coverage"]["browser_included"])
        options = observed["options"]
        source_root = Path(__file__).resolve().parents[1]
        self.assertEqual(options["source"], [str(source_root / "app"), str(source_root / "scripts")])
        self.assertEqual(options["omit"], [])
        self.assertFalse(options["config_file"])
        self.assertTrue(options["branch"])
        self.assertTrue(observed["stopped"])
        self.assertTrue(observed["saved"])

    def test_missing_coverage_tool_fails_without_hiding_suite(self):
        def unavailable(**kwargs):
            raise ModuleNotFoundError("PRIVATE_FIXTURE_COVERAGE")
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-coverage-") as temporary:
            report = self.gate(coverage_directory=Path(temporary) / "coverage", coverage_factory=unavailable)
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["tests_run"], 1)
        self.assertEqual(report["coverage"]["status"], "failed")
        self.assertNotIn("PRIVATE_FIXTURE_COVERAGE", json.dumps(report))

    def test_coverage_export_failure_is_not_a_passing_measurement(self):
        class Collector:
            def __init__(self, **kwargs): pass
            def start(self): pass
            def stop(self): pass
            def save(self): pass
            def json_report(self, **kwargs): raise OSError("fixture export failure")
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-coverage-") as temporary:
            report = self.gate(coverage_directory=Path(temporary) / "coverage", coverage_factory=Collector)
        self.assertEqual(report["suite_status"], "passed")
        self.assertEqual(report["exit_code"], 1)
        self.assertFalse(report["coverage"]["measured"])
        self.assertEqual(report["coverage"]["status"], "failed")

    def test_coverage_does_not_reuse_an_existing_artifact_directory(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-coverage-") as temporary:
            destination = Path(temporary) / "coverage"
            destination.mkdir()
            sentinel = destination / "coverage.json"
            sentinel.write_text("preserve fixture", encoding="utf-8")
            report = self.gate(coverage_directory=destination)
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "preserve fixture")
        self.assertEqual(report["exit_code"], 1)
        self.assertEqual(report["tests"]["tests_run"], 1)

    def test_ci_report_enables_coverage_by_default(self):
        report = self.gate()
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-report-") as temporary:
            destination = Path(temporary) / "summary.json"
            with patch.object(ci, "run_ci", return_value=report) as run, redirect_stdout(io.StringIO()):
                exit_code = ci.main(["--report", str(destination)])
            self.assertEqual(run.call_args.kwargs["coverage_directory"], destination.parent / "coverage")
        self.assertEqual(exit_code, 0)


if __name__ == "__main__":
    unittest.main()
