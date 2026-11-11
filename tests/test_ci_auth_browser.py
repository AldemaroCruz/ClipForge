"""Runner contract fixtures only; real PostgreSQL/browser run separately in CI."""
import ast
import contextlib
import io
import json
from pathlib import Path
import tempfile
import sys
import unittest

from scripts import run_ci_auth_browser as runner
from scripts.validate_ci_reports import AUTH_STEPS


class AuthBrowserRunnerTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ci-auth-runner-fixture-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.source = self.root / "source"
        for part in ("app/static", "scripts", "tests"):
            (self.source / part).mkdir(parents=True)
        (self.source / "tests/browser_auth.py").write_text("# Authored contract fixture\n")
        self.raw = {"schema_version": 1, "status": "passed", "exit_code": 0,
                    "script": "browser_auth.py", "timed_out": False, "steps": 7,
                    "details": [{"id": name, "status": "passed", "detail": "Authored fixture: " + name} for name in sorted(AUTH_STEPS)],
                    "transport": "direct_http", "postgresql": "real", "auth_mocked": False,
                    "external_network": False, "process_restart": True}

    def execute(self, script, source, env, stdout, stderr, timeout):
        self.assertNotEqual(source, self.source)
        self.assertEqual(env["CLIPFORGE_AI_PROVIDER"], "disabled")
        self.assertEqual(env["CLIPFORGE_AUTH_TEST_DATABASE"], "1")
        self.assertEqual(env["CLIPFORGE_BROWSER_BRIDGE"], "0")
        stdout.write_text("PASS: synthetic runner fixture\n")
        stderr.write_text("")
        output = source / "test-output"
        output.mkdir()
        (output / "browser-auth-summary.json").write_text(json.dumps(self.raw))
        return {"returncode": 0, "timed_out": False}

    def run_fixture(self, **kwargs):
        return runner.run_auth_browser(self.source, self.root / "artifacts", "sha256:" + "a" * 64,
            "sha256:" + "b" * 64, "c" * 64,
            environ=kwargs.pop("environ", {"CLIPFORGE_AUTH_TEST_DATABASE": "1"}),
            inspector=lambda: {"executable": "/fixture/chromium"},
            executor=kwargs.pop("executor", self.execute), **kwargs)

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


if __name__ == "__main__":
    unittest.main()
