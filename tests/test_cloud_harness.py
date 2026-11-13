"""Pure lifecycle safety regressions. Docker/network/media are not simulated as acceptance."""
import importlib.util
import ast
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_int_e2e as harness


class ControlProtocolTests(unittest.TestCase):
    def test_database_contract_is_separate_from_discovery_and_failure_is_mandatory(self):
        path = harness.ROOT / harness.DATABASE_CONTRACT
        self.assertTrue(path.is_file())
        self.assertFalse(path.name.startswith("test_"))
        self.assertFalse(path.with_name("test_cloud_dispatch.py").exists())
        tree = ast.parse(path.read_text(encoding="utf-8"))
        decorators = [node for node in ast.walk(tree) if isinstance(node, (ast.ClassDef, ast.FunctionDef)) for node in node.decorator_list]
        self.assertFalse(any("skip" in ast.unparse(node) for node in decorators))
        instance = object.__new__(harness.Harness)
        instance.private, instance.public = Path("synthetic-private"), Path("synthetic-public")
        instance.runtime_image = "sha256:" + "a" * 64
        instance.app_args = lambda *args, **kwargs: []
        with patch.object(instance, "run_and_wait", side_effect=harness.AcceptanceError("explicit failed contract")) as run:
            with self.assertRaises(harness.AcceptanceError):
                instance.run_dispatch_contracts()
        command = run.call_args.args[0]
        self.assertIn("CLIPFORGE_CLOUD_DISPATCH_TEST=1", command)
        self.assertIn("/qa/cloud_dispatch_contract.py", command)
        self.assertIn("/public/cloud-dispatch-summary.json", command)

    def test_mounted_driver_can_import_runtime_without_inheriting_int_profile(self):
        instance = object.__new__(harness.Harness)
        instance.private = Path("synthetic-private")
        instance.nonce, instance.prefix = "a" * 32, "synthetic-e2e"
        instance.base_args = lambda *args, **kwargs: []
        arguments = instance.app_args("fixture")
        environment = dict(arguments[i + 1].split("=", 1) for i, value in enumerate(arguments) if value == "--env")
        self.assertEqual(environment["PYTHONPATH"], "/app")
        self.assertEqual(environment["CLIPFORGE_CLOUD_LOCAL_TEST"], "1")
        self.assertEqual(environment["CLIPFORGE_AUTH_PROFILE"], "local-http")
        self.assertEqual(environment["CLIPFORGE_ENVIRONMENT"], "")
        self.assertEqual(environment["CLIPFORGE_JOBS_DISPATCH_MODE"], "local_manual")

    def test_digest_remains_required_with_or_without_optional_image_tag(self):
        digest = "sha256:" + "a" * 64
        for value in ("postgres@" + digest, "postgres:18.7-trixie@" + digest):
            self.assertIsNotNone(harness.IMAGE_REF.fullmatch(value))
        for value in ("postgres", "postgres:18.7-trixie", "postgres@sha256:short", "postgres@sha256:" + "a" * 63):
            self.assertIsNone(harness.IMAGE_REF.fullmatch(value))

    def test_only_exact_allowlisted_actions_and_execution_identity_are_valid(self):
        nonce = "a" * 32
        for action in harness.ACTIONS:
            self.assertEqual(harness.validate_request({"nonce": nonce, "sequence": 1, "action": action}, nonce), (1, action))
        for request in ({"nonce": nonce, "sequence": 1, "action": "apply"},
                        {"nonce": "b" * 32, "sequence": 1, "action": "drain"},
                        {"nonce": nonce, "sequence": True, "action": "drain"},
                        {"nonce": nonce, "sequence": 0, "action": "drain"},
                        {"nonce": nonce, "sequence": 1, "action": "drain", "command": "anything"}):
            with self.subTest(request=request), self.assertRaises(harness.AcceptanceError):
                harness.validate_request(request, nonce)

    def test_cleanup_requires_both_execution_and_manager_labels(self):
        self.assertTrue(harness.owned({"labels": {harness.OWNER_LABEL: "a", harness.MANAGER_LABEL: harness.MANAGER}}, "a"))
        for item in ({}, {"labels": {harness.OWNER_LABEL: "a"}},
                     {"labels": {harness.OWNER_LABEL: "b", harness.MANAGER_LABEL: harness.MANAGER}},
                     {"labels": {harness.OWNER_LABEL: "a", harness.MANAGER_LABEL: "other"}}):
            self.assertFalse(harness.owned(item, "a"))

    def test_cleanup_does_not_remove_foreign_container(self):
        instance = object.__new__(harness.Harness)
        instance.nonce, instance.containers = "a", ["synthetic-container"]
        calls = []
        def docker(arguments, **kwargs):
            calls.append(arguments)
            return json.dumps({"labels": {harness.OWNER_LABEL: "b", harness.MANAGER_LABEL: harness.MANAGER}})
        instance.docker = docker
        with self.assertRaises(harness.AcceptanceError):
            instance.remove_container("synthetic-container")
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "inspect")
        self.assertEqual(instance.containers, ["synthetic-container"])

    def test_failure_always_cleans_only_owned_resources_and_remains_failed(self):
        instance = object.__new__(harness.Harness)
        with tempfile.TemporaryDirectory() as temporary:
            instance.private = Path(temporary)
            instance.public = Path(temporary) / "public"
            instance.public.mkdir()
            instance.fixture = Path(temporary) / "synthetic.mp4"
            instance.fixture.write_bytes(b"synthetic fixture")
            instance.runtime_image = instance.browser_image = "sha256:" + "a" * 64
            instance.postgres_image = "postgres@sha256:" + "b" * 64
            instance.postgres_id = instance.emulator_id = None
            instance.user, instance.api_replacements = "10001:10001", 0
            instance.prepare = lambda: (_ for _ in ()).throw(harness.AcceptanceError("synthetic failure"))
            with patch.object(instance, "cleanup", return_value={"status": "passed"}) as cleanup:
                result = instance.run()
            cleanup.assert_called_once()
            self.assertEqual(result["status"], "failed")
            self.assertFalse(result["cloud_validation"])
            self.assertEqual(result["error_type"], "AcceptanceError")
            self.assertNotIn("synthetic failure", json.dumps(result))

    def test_private_results_cannot_be_overwritten(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "value.json"
            harness.write_new(path, {"status": "first"})
            with self.assertRaises(FileExistsError):
                harness.write_new(path, {"status": "second"})
            self.assertEqual(json.loads(path.read_text()), {"status": "first"})

    def test_browser_public_steps_cannot_accept_response_bodies_or_secrets(self):
        path = Path(__file__).with_name("browser_int_e2e.py")
        specification = importlib.util.spec_from_file_location("browser_int_e2e_contract", path)
        browser = importlib.util.module_from_spec(specification)
        specification.loader.exec_module(browser)
        instance = object.__new__(browser.Acceptance)
        instance.report = {"steps": []}
        with self.assertRaises(RuntimeError):
            instance.record("arbitrary-secret-value")
        self.assertEqual(instance.report["steps"], [])

    def test_public_failure_checks_are_source_literals_never_runtime_values(self):
        tree = ast.parse(Path(__file__).with_name("browser_int_e2e.py").read_text(encoding="utf-8"))
        checks = [node for node in ast.walk(tree) if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id == "ensure"]
        self.assertGreater(len(checks), 40)
        for check in checks:
            self.assertIsInstance(check.args[1], ast.Constant)
            self.assertIsInstance(check.args[1].value, str)


if __name__ == "__main__":
    unittest.main()
