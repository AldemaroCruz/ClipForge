"""Lifecycle boundary fixtures only; these do not establish real DB isolation."""
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import ci_postgres as pg


class LifecycleBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-ci-postgres-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.scratch = Path(self.temporary.name)
        self.reports = self.scratch / "reports"
        self.reports.mkdir(mode=0o700)
        self.config = pg.Configuration(self.scratch, self.reports, "1001:1001", "fixture-2", "sha256:" + "c" * 64)
        self.commands = []
        self.objects = {}
        self.networks = {}
        self.failure = None
        self.lifecycle = pg.Lifecycle(self.config, self.execute)
        self.resolver = patch.object(pg.dev_local, "host_executable", return_value="/reviewed/docker")
        self.resolver.start()
        self.addCleanup(self.resolver.stop)

    def state(self):
        self.config.state_root.mkdir(mode=0o700)
        nonce = "a" * 32
        value = {"schema": pg.SCHEMA, "nonce": nonce, "run_key": self.config.run_key,
                 "prefix": "clipforge-ci-auth-" + hashlib.sha256(self.config.run_key.encode()).hexdigest()[:12] + "-" + nonce[:12],
                 "scratch": str(self.scratch), "reports": str(self.reports), "user": self.config.user}
        pg.save_new(self.config.state_root / "state.json", value)
        return value

    def resource(self, value, identifier, suffix, kind="container"):
        resource = {"id": identifier, "name": value["prefix"] + "-" + suffix,
                    "labels": {pg.OWNER_LABEL: value["nonce"], pg.MANAGER_LABEL: pg.MANAGER}}
        (self.objects if kind == "container" else self.networks)[identifier] = resource
        return resource

    def execute(self, argv, stdout, stderr, timeout):
        command = argv[5:]
        self.commands.append(command)
        code, output, error = 0, "", ""
        if self.failure:
            response = self.failure(command)
            if response:
                code, output, error = response
                stdout.write(output.encode())
                stderr.write(error.encode())
                return SimpleNamespace(returncode=code)
        if command[:2] == ["ps", "-aq"]:
            output = "\n".join(self.objects)
        elif command[:2] == ["network", "ls"]:
            output = "\n".join(self.networks)
        elif command[:2] == ["image", "inspect"]:
            output = ("sha256:" + "b" * 64 if command[-1] == pg.POSTGRES_IMAGE else command[-1]) + "|linux|amd64"
        elif command[:2] == ["network", "create"]:
            value = self.lifecycle.state()
            self.resource(value, "d" * 64, "network", "network")
            output = "d" * 64
        elif command[:2] == ["run", "-d"]:
            value = self.lifecycle.state()
            self.resource(value, "e" * 64, "postgres")
            output = "e" * 64
        elif command[:2] == ["inspect", "--format"] and command[2].startswith("{{.State"):
            output = "running|healthy"
        elif command[:2] == ["inspect", "--format"]:
            output = json.dumps(self.objects[command[-1]])
        elif command[:2] == ["network", "inspect"]:
            output = json.dumps(self.networks[command[-1]])
        elif command[:2] == ["rm", "-f"]:
            del self.objects[command[-1]]
        elif command[:2] == ["network", "rm"]:
            del self.networks[command[-1]]
        stdout.write(output.encode())
        stderr.write(error.encode())
        return SimpleNamespace(returncode=code)

    def test_postgres_pin_matches_reviewed_auth_digest(self):
        self.assertEqual(pg.POSTGRES_IMAGE, "postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42")

    def test_configuration_rejects_checkout_and_reports_state_overlap_before_access(self):
        cases = [(pg.ROOT / "scratch", pg.ROOT / "scratch/reports"),
                 (self.scratch, self.scratch), (self.scratch, self.scratch / "ci-postgres/reports"),
                 (self.scratch, self.scratch.parent / "reports")]
        for scratch, reports in cases:
            with self.subTest(scratch=scratch, reports=reports), patch.object(pg, "safe_directory") as access:
                with self.assertRaises(pg.LifecycleError):
                    pg.Configuration.from_environment({"CI_SCRATCH": str(scratch), "CI_REPORTS": str(reports), "CI_CONTAINER_USER": "1001:1001"})
                access.assert_not_called()

    def test_configuration_rejects_root_implicit_user_mutable_image_and_run_key(self):
        base = {"CI_SCRATCH": str(self.scratch), "CI_REPORTS": str(self.reports), "CI_CONTAINER_USER": "1001:1001"}
        for update in [{"CI_CONTAINER_USER": "0:0"}, {"CI_CONTAINER_USER": "1001:0"}, {"CI_CONTAINER_USER": "runner"},
                       {"CI_IMAGE_ID": "candidate:latest"}, {"CI_RUN_KEY": "../../other"}]:
            with self.subTest(update=update), patch.object(pg, "safe_directory") as access:
                with self.assertRaises(pg.LifecycleError):
                    pg.Configuration.from_environment({**base, **update})
                access.assert_not_called()

    def test_prepare_records_only_pinned_image_identity_without_credentials(self):
        result = self.lifecycle.prepare()
        self.assertEqual(result["status"], "prepared")
        self.assertEqual((self.reports / "postgres-image-ref.txt").read_text().strip(), pg.POSTGRES_IMAGE)
        self.assertEqual((self.reports / "postgres-image-id.txt").read_text().strip(), "sha256:" + "b" * 64)
        self.assertFalse(self.config.private.exists())
        self.assertEqual(self.commands[0], ["pull", "--platform", "linux/amd64", pg.POSTGRES_IMAGE])
        with self.assertRaises(FileExistsError):
            self.lifecycle.prepare()

    def test_start_uses_private_generated_files_and_persists_resource_ids(self):
        self.lifecycle.prepare()
        with patch.object(pg.secrets, "token_urlsafe", side_effect=["synthetic-admin", "synthetic-app"]):
            result = self.lifecycle.start()
        self.assertEqual(result["status"], "healthy")
        self.assertFalse(pg.context._inside(self.config.private, self.reports))
        self.assertEqual(json.loads((self.config.state_root / "network.json").read_text())["id"], "d" * 64)
        self.assertEqual(json.loads((self.config.state_root / "postgres.json").read_text())["id"], "e" * 64)
        all_reports = "".join(path.read_text(encoding="utf-8") for path in self.reports.rglob("*") if path.is_file())
        self.assertNotIn("synthetic-admin", all_reports)
        self.assertNotIn("synthetic-app", all_reports)
        self.assertIn("CREATE ROLE clipforge_ci LOGIN", (self.config.private / "initialize.sql").read_text())
        self.assertNotIn("SUPERUSER", (self.config.private / "initialize.sql").read_text())
        if os.name == "posix":
            self.assertEqual((self.config.private / "database-password").stat().st_mode & 0o777, 0o600)

    def test_runtime_commands_have_internal_network_nonroot_no_ports_and_no_socket(self):
        value = self.state()
        for command in [self.lifecycle.start_arguments(value), self.lifecycle.runner_arguments(value, "unit", self.reports)]:
            self.assertEqual(command[command.index("--network") + 1], value["prefix"] + "-network")
            self.assertEqual(command[command.index("--user") + 1], "1001:1001")
            self.assertIn("--read-only", command)
            self.assertEqual(command[command.index("--cap-drop") + 1], "ALL")
            self.assertEqual(command[command.index("--security-opt") + 1], "no-new-privileges")
            self.assertTrue(all(item not in command for item in ["--privileged", "--cap-add", "--publish", "-p", "-P", "--network=host"]))
            mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
            self.assertTrue(all("docker.sock" not in mount and str(pg.ROOT) not in mount for mount in mounts))
        command = self.lifecycle.start_arguments(value)
        self.assertIn("/var/lib/postgresql:rw,nosuid,nodev,uid=1001,gid=1001,mode=0700,size=1g", command)

    def test_runner_only_mounts_reports_and_own_password_file(self):
        value = self.state()
        command = self.lifecycle.runner_arguments(value, "auth-browser", self.reports, browser=True)
        mounts = [command[index + 1] for index, item in enumerate(command) if item == "--mount"]
        self.assertEqual(mounts, [f"type=bind,src={self.reports},dst=/ci-results",
                                  f"type=bind,src={self.config.private / 'database-password'},dst=/run/secrets/database-password,readonly"])
        self.assertIn("--init", command)
        self.assertIn("--shm-size=1g", command)
        self.assertIn("CLIPFORGE_DATABASE_SCHEMA=auth01_test_aaaaaaaaaaaa_auth_browser", command)

    def test_command_refuses_inline_secret_and_traversal_inputs(self):
        invalid = [["sh", "-c", "true"], ["python", "-c", "print(1)"], ["python", "../scripts/auth_migrate.py"],
                   ["python", "scripts/auth_migrate.py", "--password", "fixture"],
                   ["python", "scripts/auth_migrate.py", "postgresql://fixture"],
                   ["python", "scripts/auth_migrate.py", "broken\nargument"]]
        for command in invalid:
            with self.subTest(command=command), self.assertRaises(pg.LifecycleError):
                pg.validate_command(command)
        self.assertEqual(pg.validate_command(["--", "python", "scripts/run_ci_tests.py"]),
                         ["/usr/local/bin/python", "-B", "scripts/run_ci_tests.py"])

    def test_role_traversal_refused_before_state_or_attempt_creation(self):
        with patch.object(self.lifecycle, "state") as state:
            with self.assertRaises(pg.LifecycleError):
                self.lifecycle.run("../../outside", ["python", "scripts/run_ci_tests.py"])
        state.assert_not_called()

    def test_tests_require_real_migration_marker(self):
        self.state()
        pg.save_new(self.config.state_root / "checked.json", {"status": "passed"})
        with self.assertRaises(pg.LifecycleError):
            self.lifecycle.run("unit", ["python", "scripts/run_ci_tests.py"])
        self.assertEqual(self.commands, [])

    def test_wrong_run_and_tampered_prefix_refused(self):
        value = self.state()
        for key in ("run_key", "prefix", "user", "reports"):
            changed = {**value, key: "other"}
            (self.config.state_root / "state.json").write_text(json.dumps(changed))
            with self.subTest(key=key), self.assertRaises(pg.LifecycleError):
                self.lifecycle.state()

    def test_cleanup_removes_running_tests_and_pg_only_with_matching_labels_and_names(self):
        value = self.state()
        self.resource(value, "a" * 64, "postgres")
        self.resource(value, "b" * 64, "unit-12345678")
        self.resource(value, "c" * 64, "network", "network")
        self.config.private.mkdir()
        for name in ("postgres-password", "database-password", "initialize.sql"):
            pg.private_write(self.config.private / name, "synthetic")
        first = self.lifecycle.cleanup()
        summary = (self.reports / "postgres-cleanup.json").read_bytes()
        second = self.lifecycle.cleanup()
        self.assertEqual(len(first["containers_removed"]), 2)
        self.assertEqual(first["remaining_container_ids"], [])
        self.assertEqual(first["remaining_network_ids"], [])
        self.assertEqual(second["containers_removed"], [])
        self.assertEqual((self.reports / "postgres-cleanup.json").read_bytes(), summary)
        self.assertNotEqual(first["report"], second["report"])
        self.assertTrue(all("prune" not in command and "volume" not in command for command in self.commands))

    def test_cleanup_validates_every_selected_resource_before_deletion(self):
        value = self.state()
        self.resource(value, "a" * 64, "postgres")
        foreign = self.resource(value, "b" * 64, "unit-12345678")
        foreign["labels"][pg.MANAGER_LABEL] = "another-manager"
        with self.assertRaises(pg.LifecycleError):
            self.lifecycle.cleanup()
        self.assertFalse(any(command[:2] == ["rm", "-f"] for command in self.commands))
        self.assertFalse((self.reports / "postgres-cleanup.json").exists())

    def test_cleanup_rejects_replaced_recorded_resource_even_with_same_name_labels(self):
        value = self.state()
        self.resource(value, "b" * 64, "postgres")
        pg.save_new(self.config.state_root / "postgres.json", {"id": "a" * 64, "name": value["prefix"] + "-postgres"})
        with self.assertRaises(pg.LifecycleError):
            self.lifecycle.cleanup()
        self.assertFalse(any(command[:2] == ["rm", "-f"] for command in self.commands))

    def test_cleanup_accepts_container_exiting_during_inspect_but_not_daemon_error(self):
        value = self.state()
        self.resource(value, "a" * 64, "unit-12345678")
        def disappeared(command):
            if command[:2] == ["inspect", "--format"]:
                self.objects.clear()
                return 1, "", "Error response from daemon: No such object: " + command[-1]
        self.failure = disappeared
        self.assertEqual(self.lifecycle.cleanup()["status"], "clean")
        self.failure = lambda command: (1, "", "Cannot connect to the Docker daemon") if command[:2] == ["inspect", "--format"] else None
        self.resource(value, "b" * 64, "unit-12345678")
        with self.assertRaises(pg.LifecycleError):
            self.lifecycle.cleanup()

    def test_failed_test_exit_is_preserved_without_teardown_before_always_step(self):
        self.state()
        for name in ("checked.json", "migrated.json"):
            pg.save_new(self.config.state_root / name, {"status": "passed"})
        self.failure = lambda command: (7, "synthetic test failure", "") if command[:2] == ["run", "--rm"] else None
        result = self.lifecycle.run("unit", ["python", "scripts/run_ci_tests.py"])
        self.assertEqual(result["exit_code"], 7)
        self.assertEqual(result["status"], "failed")
        self.assertFalse(any(command[:2] == ["ps", "-aq"] for command in self.commands))

    def test_main_failed_start_and_sigterm_cleanup_with_failure_code(self):
        for failure, expected in [(pg.LifecycleError("fixture"), 1), (InterruptedError("fixture"), 130)]:
            with self.subTest(failure=type(failure).__name__), patch.object(pg.Configuration, "from_environment", return_value=self.config), \
                 patch.object(pg, "Lifecycle") as factory, patch.object(pg.signal, "signal"), \
                 contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                factory.return_value.start.side_effect = failure
                self.assertEqual(pg.main(["start"]), expected)
                factory.return_value.cleanup.assert_called_once_with()

    def test_missing_state_cleanup_has_no_daemon_or_operational_access(self):
        result = self.lifecycle.cleanup()
        self.assertEqual(result["containers_removed"], [])
        self.assertEqual(self.commands, [])
        self.assertFalse((self.reports / "postgres-cleanup.json").exists())


if __name__ == "__main__":
    unittest.main()
