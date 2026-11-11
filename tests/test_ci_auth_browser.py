"""Runner contract fixtures only; real PostgreSQL/browser run separately in CI."""
import ast
import contextlib
import copy
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest
from unittest.mock import patch

from scripts import run_ci_auth_browser as runner
from scripts.validate_ci_reports import AUTH_STEPS, RECOVERY_STEPS


class BrowserRunnerFixtures:
    scenario = "auth"
    script_name = "browser_auth.py"
    report_name = "browser-auth-summary.json"
    step_ids = AUTH_STEPS

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ci-auth-runner-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        for part in ("app/static", "scripts", "tests"):
            (self.source / part).mkdir(parents=True)
        (self.source / "tests" / self.script_name).write_text("# Authored contract fixture\n")
        self.fixture_runs = 0
        self.raw = {"schema_version": 1, "status": "passed", "exit_code": 0,
                    "script": self.script_name, "timed_out": False, "steps": len(self.step_ids),
                    "details": [{"id": name, "status": "passed"} for name in sorted(self.step_ids)],
                    "transport": "direct_http", "postgresql": "real", "auth_mocked": False,
                    "external_network": False, "process_restart": True}
        if self.scenario == "auth":
            for detail in self.raw["details"]:
                detail["detail"] = "Authored fixture: " + detail["id"]

    def execute(self, script, source, env, stdout, stderr, timeout):
        self.assertNotEqual(source, self.source)
        self.assertEqual(script.name, self.script_name)
        self.assertTrue(script.is_file())
        self.assertEqual(env["CLIPFORGE_AI_PROVIDER"], "disabled")
        self.assertEqual(env["CLIPFORGE_AUTH_TEST_DATABASE"], "1")
        self.assertEqual(env["CLIPFORGE_BROWSER_BRIDGE"], "0")
        stdout.write_text("PASS: synthetic runner fixture\n")
        stderr.write_text("")
        output = source / "test-output"
        output.mkdir()
        (output / self.report_name).write_text(json.dumps(self.raw))
        return {"returncode": 0, "timed_out": False}

    def run_fixture(self, **kwargs):
        self.fixture_runs += 1
        return runner.run_auth_browser(self.source, self.root / f"artifacts-{self.fixture_runs}", "sha256:" + "a" * 64,
            "sha256:" + "b" * 64, "c" * 64,
            scenario=kwargs.pop("scenario", self.scenario),
            environ=kwargs.pop("environ", {"CLIPFORGE_AUTH_TEST_DATABASE": "1"}),
            inspector=lambda: {"executable": "/fixture/chromium", "playwright_version": "1.64.1",
                               "chromium_version": "156.0.8078.4", "chromium_revision": "1248",
                               "system": "Linux", "machine": "x86_64"},
            executor=kwargs.pop("executor", self.execute), **kwargs)

class AuthBrowserRunnerTests(BrowserRunnerFixtures, unittest.TestCase):
    def test_success_requires_complete_real_auth_contract_in_copied_sources(self):
        report = self.run_fixture()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["steps"], 7)
        self.assertEqual(report["context_manifest_sha256"], "c" * 64)

    def test_missing_postgres_profile_blocks_before_execution(self):
        def forbidden(*args):
            self.fail("Execution must not start")
        self.assertEqual(self.run_fixture(environ={}, executor=forbidden)["exit_code"], 1)

    def test_nonzero_or_timeout_cannot_reuse_apparent_success_report(self):
        def failed(*args):
            self.execute(*args)
            return {"returncode": 9, "timed_out": True}
        report = self.run_fixture(executor=failed)
        self.assertEqual(report["exit_code"], 1)
        self.assertTrue(report["timed_out"])

    def test_incomplete_or_simulated_report_is_rejected(self):
        self.raw["auth_mocked"] = True
        self.raw["details"].pop()
        self.assertEqual(self.run_fixture()["exit_code"], 1)

    def test_missing_report_and_exception_details_are_not_published(self):
        def fail(*args):
            raise RuntimeError("PRIVATE_RUNNER_FIXTURE")
        report = self.run_fixture(executor=fail)
        self.assertEqual(report["exit_code"], 1)
        self.assertNotIn("PRIVATE_RUNNER_FIXTURE", json.dumps(report))

    def test_browser_failure_hook_does_not_emit_exception_arguments(self):
        script = Path(__file__).with_name("browser_auth.py")
        tree = ast.parse(script.read_text(encoding="utf-8"))
        hook = next(node for node in tree.body if isinstance(node, ast.FunctionDef) and node.name == "report_failure")
        namespace = {"sys": sys, "results": ["fixture"]}
        exec(compile(ast.Module(body=[hook], type_ignores=[]), str(script), "exec"), namespace)
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            namespace["report_failure"](RuntimeError, RuntimeError("PRIVATE_PASSWORD_FIXTURE"), None)
        self.assertIn("after 1 steps: RuntimeError", output.getvalue())
        self.assertNotIn("PRIVATE_PASSWORD_FIXTURE", output.getvalue())

    def test_error_fields_cannot_be_discarded_by_export_allowlist(self):
        self.raw["error_type"] = "RuntimeError"
        self.assertEqual(self.run_fixture()["exit_code"], 1)

    def test_duplicate_json_fields_fail_closed(self):
        def duplicate(*args):
            result = self.execute(*args)
            path = args[1] / "test-output/browser-auth-summary.json"
            path.write_text('{"exit_code":9,' + json.dumps(self.raw)[1:])
            return result
        self.assertEqual(self.run_fixture(executor=duplicate)["exit_code"], 1)

    def test_boolean_exit_is_not_success(self):
        def boolean(*args):
            self.execute(*args)
            return {"returncode": False, "timed_out": False}
        self.assertEqual(self.run_fixture(executor=boolean)["exit_code"], 1)


class RecoveryBrowserRunnerTests(BrowserRunnerFixtures, unittest.TestCase):
    scenario = "recovery"
    script_name = "browser_auth_recovery.py"
    report_name = "browser-auth-recovery-summary.json"
    step_ids = RECOVERY_STEPS

    def test_recovery_selects_its_own_script_report_and_eight_step_contract(self):
        report = self.run_fixture()
        self.assertEqual(report["exit_code"], 0)
        self.assertEqual(report["script"], self.script_name)
        self.assertEqual(report["steps"], 8)
        self.assertEqual({step["id"] for step in report["details"]}, RECOVERY_STEPS)
        self.assertTrue(AUTH_STEPS.isdisjoint(RECOVERY_STEPS))
        self.assertTrue(all(set(step) == {"id", "status"} for step in report["details"]))
        self.assertEqual(report["toolchain"]["system"], "Linux")

    def test_every_raw_recovery_field_is_mandatory(self):
        original = copy.deepcopy(self.raw)
        for field in runner.PUBLIC_FIELDS:
            with self.subTest(field=field):
                self.raw = copy.deepcopy(original)
                del self.raw[field]
                report = self.run_fixture()
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["details"], [])

    def test_recovery_rejects_simulation_incomplete_and_wrong_typed_fields(self):
        original = copy.deepcopy(self.raw)
        mutations = [("schema_version", True), ("status", "failed"), ("exit_code", False),
                     ("timed_out", True), ("timed_out", 0), ("script", "browser_auth.py"),
                     ("transport", "simulated_fetch"), ("postgresql", "mocked"),
                     ("process_restart", False), ("process_restart", 1), ("auth_mocked", True),
                     ("auth_mocked", 0), ("external_network", True), ("external_network", 0),
                     ("steps", True), ("steps", 7), ("details", []), ("details", {})]
        for field, value in mutations:
            with self.subTest(field=field, value=value):
                self.raw = copy.deepcopy(original)
                self.raw[field] = value
                report = self.run_fixture()
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["details"], [])

    def test_recovery_never_exports_unvalidated_details_or_extra_raw_fields(self):
        original = copy.deepcopy(self.raw)
        for location in ("step", "root"):
            with self.subTest(location=location):
                self.raw = copy.deepcopy(original)
                target = self.raw["details"][0] if location == "step" else self.raw
                target["recovery_code"] = "DO_NOT_EXPORT_FIXTURE"
                report = self.run_fixture()
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["details"], [])
                self.assertNotIn("DO_NOT_EXPORT_FIXTURE", json.dumps(report))

    def test_recovery_rejects_auth7_output_in_place_of_recovery_report(self):
        def wrong_report(*args):
            outcome = self.execute(*args)
            generated = args[1] / "test-output" / self.report_name
            generated.rename(generated.with_name("browser-auth-summary.json"))
            return outcome
        self.assertEqual(self.run_fixture(executor=wrong_report)["exit_code"], 1)

    def test_recovery_subprocess_failure_timeout_or_boolean_exit_remains_failed(self):
        for code, timed_out in ((1, False), (0, True), (False, False), (0, 0)):
            with self.subTest(code=code, timed_out=timed_out):
                def failed(*args):
                    self.execute(*args)
                    return {"returncode": code, "timed_out": timed_out}
                report = self.run_fixture(executor=failed)
                self.assertEqual(report["exit_code"], 1)
                self.assertEqual(report["details"], [])

    def test_recovery_duplicate_json_fields_and_error_evidence_fail_closed(self):
        def duplicate(*args):
            outcome = self.execute(*args)
            path = args[1] / "test-output" / self.report_name
            path.write_text('{"exit_code":9,' + json.dumps(self.raw)[1:])
            return outcome
        self.assertEqual(self.run_fixture(executor=duplicate)["exit_code"], 1)
        self.raw["error_type"] = "RuntimeError"
        self.assertEqual(self.run_fixture()["exit_code"], 1)

    def test_unknown_scenario_cannot_select_arbitrary_script(self):
        def forbidden(*args):
            self.fail("Execution must not start for an unknown scenario")
        for scenario in ("../private", [], None):
            with self.subTest(scenario=scenario):
                self.assertEqual(self.run_fixture(scenario=scenario, executor=forbidden)["exit_code"], 1)

    def test_cli_recovery_uses_separate_artifacts_and_passes_scenario(self):
        report_path = self.root / self.report_name
        with patch.object(runner, "run_auth_browser", return_value={"status": "passed", "exit_code": 0, "steps": 8}) as execute:
            with contextlib.redirect_stdout(io.StringIO()):
                code = runner.main(["--scenario", "recovery", "--report", str(report_path),
                                    "--image-id", "sha256:" + "a" * 64,
                                    "--postgres-image-id", "sha256:" + "b" * 64,
                                    "--context-manifest-sha256", "c" * 64])
        self.assertEqual(code, 0)
        self.assertEqual(execute.call_args.args[1].name, "auth-recovery-artifacts")
        self.assertEqual(execute.call_args.kwargs["scenario"], "recovery")


if __name__ == "__main__":
    unittest.main()
