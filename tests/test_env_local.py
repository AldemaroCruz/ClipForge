"""ENV-01 regression fixtures; no Docker daemon or operational data is used.

Real PostgreSQL/FFmpeg/lifecycle evidence is produced separately by the local
acceptance runner. These tests protect refusal and ownership boundaries in CI.
"""
import http.cookiejar
import io
import json
from pathlib import Path
import secrets
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import accept_env_local as acceptance
from scripts import dev_backup
from scripts import dev_local as dev


class EnvironmentOwnershipTests(unittest.TestCase):
    def setUp(self):
        blocker = patch.object(dev.subprocess, "run", side_effect=AssertionError("Unit fixtures must never invoke Docker"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def value(self, environment="dev"):
        return {"schema": dev.ENV_SCHEMA, "environment": environment,
                "project": "clipforge-" + environment, "owner": "a" * 32,
                "image": "sha256:" + "b" * 64, "revision": "c" * 40,
                "source_manifest_sha256": "d" * 64,
                "context": "context", "manifest": "context-manifest.json"}

    def test_foreign_name_collision_is_rejected_before_compose_down(self):
        for labels in ({}, {dev.OWNER_LABEL: "e" * 32, dev.MANAGER_LABEL: dev.MANAGER,
                            "com.docker.compose.project": "clipforge-dev"}):
            with self.subTest(labels=labels), tempfile.TemporaryDirectory(prefix="clipforge-env01-owner-fixture-") as temporary:
                state = Path(temporary)
                def run(_directory, label, _argv, **_kwargs):
                    if label == "owned-list-container-name":
                        return "f" * 64
                    if label.startswith("owned-inspect-container-"):
                        return json.dumps({"name": "/clipforge-dev-app-1", "labels": labels})
                    return ""
                with patch.object(dev, "run", side_effect=run) as runner, \
                     patch.object(dev, "host_executable", return_value=str(state / "docker")):
                    with self.assertRaises(dev.DevelopmentError):
                        dev.execute("down", state, self.value())
                self.assertFalse(any(call.args[1] == "down" for call in runner.call_args_list))
                self.assertFalse((state / "operation.lock").exists())

    def test_environment_cookie_and_resource_variables_are_independent(self):
        dev_value, int_value = self.value(), self.value("int")
        for value in (dev_value, int_value):
            value.update(port=49152, origin="http://127.0.0.1:49152", cookie_namespace=value["environment"])
        dev_vars = dev.runtime_values(Path("C:/ENV01/dev"), dev_value)
        int_vars = dev.runtime_values(Path("C:/ENV01/int"), int_value)
        self.assertIn("CLIPFORGE_DEV_COOKIE_NAMESPACE='dev'", dev_vars)
        self.assertIn("CLIPFORGE_DEV_COOKIE_NAMESPACE='int'", int_vars)
        self.assertNotEqual(dev_vars, int_vars)
        self.assertNotEqual(dev_value["project"], int_value["project"])

    def test_existing_state_is_never_reprepared_or_adopted(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-existing-fixture-") as temporary:
            state = Path(temporary)
            sentinel = state / "owner-marker.txt"
            sentinel.write_text("fixture owner data", encoding="utf-8")
            with patch.object(dev, "host_executable", return_value="reviewed-git"), \
                 patch.object(dev.subprocess, "check_output", return_value=b"app/main.py\0"), \
                 patch.object(dev.context, "prepare_context") as prepare:
                with self.assertRaises(dev.DevelopmentError):
                    dev.prepare(state, 0, True, "dev")
            prepare.assert_not_called()
            self.assertEqual(sentinel.read_text(encoding="utf-8"), "fixture owner data")

    def test_busy_persistent_port_never_stops_its_holder(self):
        value = self.value()
        value["port"] = 49152
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-port-fixture-") as temporary:
            with patch.object(dev, "docker", return_value=["reviewed-docker"]), \
                 patch.object(dev, "run", return_value="") as runner, \
                 patch.object(dev, "choose_port", side_effect=OSError("authored busy port fixture")):
                with self.assertRaises(dev.DevelopmentError):
                    dev.check_available_port(Path(temporary), value, Path(temporary))
            self.assertEqual(runner.call_count, 1)
            self.assertNotIn("stop", runner.call_args.args[2])

    def test_promote_consumes_exact_dev_image_without_build(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-promote-fixture-") as temporary:
            root = Path(temporary)
            source, destination = root / "dev", root / "int"
            source.mkdir(); destination.mkdir()
            dev_value, int_value = self.value(), self.value("int")
            build = {"image_id": dev_value["image"], "source_manifest_sha256": dev_value["source_manifest_sha256"],
                     "revision": dev_value["revision"], "migration_revision": "auth02_0002"}
            (source / "validated.json").write_text(json.dumps({**build, "status": "passed"}), encoding="utf-8")
            with patch.object(dev, "load_state", return_value=(source, dev_value)), \
                 patch.object(dev, "verify_ownership"), patch.object(dev, "require_image"), patch.object(dev, "verify_active_image"), \
                 patch.object(dev, "read_build", return_value=build), \
                 patch.object(dev.context, "prepare_context"), \
                 patch.object(dev, "manifest_hash", return_value=dev_value["source_manifest_sha256"]), \
                 patch.object(dev, "activate") as activate, patch.object(dev, "build") as builder:
                dev.promote(destination, int_value, source)
            builder.assert_not_called()
            actual_state, actual_build = activate.call_args.args[1:]
            self.assertEqual(actual_state["image"], build["image_id"])
            self.assertEqual(actual_build["image_id"], build["image_id"])
            self.assertFalse(actual_build["promotion_rebuilt"])

    def test_running_container_image_must_match_recorded_image(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-active-image-fixture-") as temporary:
            value = self.value()
            with patch.object(dev, "docker", return_value=["reviewed-docker"]), \
                 patch.object(dev, "run", return_value="sha256:" + "e" * 64 + "|true"), \
                 patch.object(dev, "read_build", return_value={"image_id": value["image"]}):
                with self.assertRaises(dev.DevelopmentError):
                    dev.verify_active_image(Path(temporary), value, Path(temporary))

    def test_schema_mismatch_blocks_rollback_before_activation(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-rollback-fixture-") as temporary:
            state = Path(temporary)
            value = self.value("int")
            (state / "previous.json").write_text(json.dumps({"state": value,
                "build": {"migration_revision": "auth01_0001"}}), encoding="utf-8")
            with patch.object(dev, "schema_revision", return_value="auth02_0002"), \
                 patch.object(dev, "activate") as activate, patch.object(dev, "run") as runner:
                with self.assertRaises(dev.DevelopmentError):
                    dev.rollback(state, value, state)
            activate.assert_not_called()
            runner.assert_not_called()


class BackupBoundaryTests(unittest.TestCase):
    def setUp(self):
        blocker = patch.object(dev.subprocess, "run", side_effect=AssertionError("Unit fixtures must never invoke Docker"))
        blocker.start()
        self.addCleanup(blocker.stop)

    def test_backup_refuses_active_writer_before_dump_and_resumes_app(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-backup-fixture-") as temporary:
            root = Path(temporary)
            state, directory = root / "state", root / "attempt"
            state.mkdir(); directory.mkdir()
            value = {"schema": dev.ENV_SCHEMA, "project": "clipforge-int"}
            def run(_directory, label, _argv, **_kwargs):
                return "synthetic-running-container" if label in {"backup-app-running", "backup-writers"} else ""
            with patch.object(dev, "require_image"), patch.object(dev, "verify_active_image"), patch.object(dev, "compose", return_value=["docker", "compose"]), \
                 patch.object(dev, "docker", return_value=["docker"]), \
                 patch.object(dev, "run", side_effect=run) as runner, patch.object(dev_backup, "stream") as stream:
                with self.assertRaises(dev.DevelopmentError):
                    dev_backup.backup(state, value, directory, root / "new-private-output")
            stream.assert_not_called()
            labels = [call.args[1] for call in runner.call_args_list]
            self.assertLess(labels.index("backup-quiesce"), labels.index("backup-writers"))
            self.assertEqual(labels[-1], "backup-resume")

    def test_restore_never_reuses_existing_destination(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-restore-fixture-") as temporary:
            state = Path(temporary)
            sentinel = state / "keep.txt"
            sentinel.write_text("fixture", encoding="utf-8")
            with patch.object(dev_backup, "read_backup", return_value=(state.parent / "fixture-backup", {})), \
                 patch.object(dev, "prepare") as prepare:
                with self.assertRaises(dev.DevelopmentError):
                    dev_backup.restore(state.parent / "fixture-backup", state, 0, True)
            prepare.assert_not_called()
            self.assertEqual(sentinel.read_text(), "fixture")

    def test_restore_rejects_traversal_absolute_and_link_archive_members(self):
        for name, kind in (("../escape", tarfile.REGTYPE), ("/absolute", tarfile.REGTYPE),
                           ("link", tarfile.SYMTYPE), ("hardlink", tarfile.LNKTYPE)):
            with self.subTest(name=name, kind=kind), tempfile.TemporaryDirectory(prefix="clipforge-env01-tar-fixture-") as temporary:
                destination = Path(temporary)
                payload = io.BytesIO()
                with tarfile.open(fileobj=payload, mode="w") as archive:
                    member = tarfile.TarInfo(name)
                    member.type = kind
                    member.linkname = "../escape" if kind != tarfile.REGTYPE else ""
                    archive.addfile(member)
                payload.seek(0)
                with patch("pathlib.Path", return_value=destination), \
                     patch("sys.stdin", SimpleNamespace(buffer=payload)):
                    with self.assertRaises(SystemExit):
                        exec(compile(dev_backup.EXTRACT, "<restore-extract-fixture>", "exec"), {})
                self.assertEqual(list(destination.iterdir()), [])


class AcceptancePrivacyTests(unittest.TestCase):
    def test_acceptance_rejects_nonloopback_origins(self):
        for origin in ("http://example.invalid:49152", "http://0.0.0.0:49152",
                       "https://127.0.0.1:49152", "http://127.0.0.1:49152/path"):
            with self.subTest(origin=origin), self.assertRaises(acceptance.AcceptanceError):
                acceptance.Client(origin)

    def test_noninteractive_bootstrap_is_rejected_before_docker(self):
        with patch.object(acceptance.sys.stdin, "isatty", return_value=False), \
             patch.object(acceptance.subprocess, "run") as runner:
            with self.assertRaises(acceptance.AcceptanceError):
                acceptance.bootstrap_interactive(Path("C:/fixture"), {"environment": "dev"}, ("synthetic_admin", secrets.token_urlsafe(24)))
        runner.assert_not_called()

    def test_interactive_bootstrap_password_is_only_anonymous_pipe_input(self):
        password = secrets.token_urlsafe(24)
        with patch.object(acceptance.sys.stdin, "isatty", return_value=True), \
             patch.object(dev, "execute"), patch.object(dev, "compose", return_value=["reviewed-docker", "compose"]), \
             patch.object(acceptance.subprocess, "run", return_value=SimpleNamespace(returncode=0, stdout=b'{"created": true}')) as runner:
            acceptance.bootstrap_interactive(Path("C:/fixture"), {"environment": "dev"}, ("synthetic_admin", password))
        argv = runner.call_args.args[0]
        self.assertNotIn(password, " ".join(argv))
        self.assertNotIn("env", runner.call_args.kwargs)
        self.assertEqual(json.loads(runner.call_args.kwargs["input"])["password"], password)
        self.assertTrue(runner.call_args.kwargs["capture_output"])

    def test_public_report_creation_never_overwrites_existing_file(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-env01-report-fixture-") as temporary:
            report = Path(temporary) / "summary.json"
            acceptance.write_report(report, {"status": "fixture"})
            with self.assertRaises(FileExistsError):
                acceptance.write_report(report, {"status": "replacement"})
            self.assertEqual(json.loads(report.read_text()), {"status": "fixture"})


if __name__ == "__main__":
    unittest.main()
