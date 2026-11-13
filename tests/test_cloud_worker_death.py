"""Safety contracts for the real worker-child interruption probe, with mocks.

The actual kernel/FFmpeg acceptance is a separate required browser E2E step.
"""
import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import run_int_e2e as harness


def driver_module():
    path = Path(__file__).with_name("browser_int_e2e.py")
    specification = importlib.util.spec_from_file_location("int_worker_death_driver", path)
    module = importlib.util.module_from_spec(specification)
    specification.loader.exec_module(module)
    return module


class WorkerChildDeathProbeTests(unittest.TestCase):
    def setUp(self):
        self.driver = driver_module()
        self.environment = {"CLIPFORGE_CLOUD_LOCAL_TEST": "1", "CLIPFORGE_AUTH_PROFILE": "local-http", "INT_E2E_NONCE": "a" * 32}
        self.initial = {
            1: {"comm": "python", "supervisor": True, "execute": False, "state": "S", "start": "10", "parent": 0},
            2: {"comm": "python", "supervisor": False, "execute": True, "state": "S", "start": "20", "parent": 1},
            3: {"comm": "ffmpeg", "supervisor": False, "execute": False, "state": "R", "start": "30", "parent": 2}}

    def test_signals_only_execute_parent_and_proves_media_dead_with_supervisor_alive(self):
        after = {1: self.initial[1], 3: {**self.initial[3], "state": "Z"}}
        with patch.dict(os.environ, self.environment, clear=True), patch.object(self.driver, "process_table", side_effect=[self.initial, self.initial, after]), \
                patch.object(self.driver.os, "kill") as kill, patch("builtins.print") as output:
            self.assertEqual(self.driver.terminate_worker_child(), 0)
        kill.assert_called_once_with(2, self.driver.signal.SIGTERM)
        report = json.loads(output.call_args.args[0])
        self.assertTrue(report["container_preserved"])
        self.assertFalse(report["old_media_active"])
        self.assertFalse(report["native_lease_modified"])
        self.assertEqual(report["zombie_media_observed"], 1)
        self.assertNotIn("pid", report)

    def test_pid_reuse_is_rejected_before_signaling_any_process(self):
        changed = {**self.initial, 2: {**self.initial[2], "start": "different"}}
        with patch.dict(os.environ, self.environment, clear=True), patch.object(self.driver, "process_table", side_effect=[self.initial, changed]), \
                patch.object(self.driver.os, "kill") as kill:
            with self.assertRaises(self.driver.CheckFailed):
                self.driver.terminate_worker_child()
        kill.assert_not_called()

    def test_container_exit_cannot_pass_as_parent_death_cleanup(self):
        with patch.dict(os.environ, self.environment, clear=True), patch.object(self.driver, "process_table", side_effect=[self.initial, self.initial, {}]), \
                patch.object(self.driver.os, "kill"), patch("builtins.print") as output:
            with self.assertRaises(self.driver.CheckFailed):
                self.driver.terminate_worker_child()
        output.assert_not_called()

    def test_media_surviving_one_second_fails_instead_of_waiting_for_render_end(self):
        with patch.dict(os.environ, self.environment, clear=True), patch.object(self.driver, "process_table", return_value=self.initial), \
                patch.object(self.driver.os, "kill"), patch.object(self.driver.time, "monotonic", side_effect=[0, 0, 0, 0, 2]), \
                patch.object(self.driver.time, "sleep"), patch("builtins.print") as output:
            with self.assertRaises(self.driver.CheckFailed):
                self.driver.terminate_worker_child()
        output.assert_not_called()

    def test_host_rejects_probe_if_container_no_longer_running(self):
        instance = object.__new__(harness.Harness)
        instance.workers, instance.user = ["synthetic-owned-worker"], "10001:10001"
        report = {"schema": "clipforge-int-worker-child-death-1", "status": "passed", "container_preserved": True, "old_media_active": False}
        with tempfile.TemporaryDirectory() as temporary:
            instance.public = Path(temporary)
            with patch.object(instance, "docker", side_effect=[json.dumps(report), "exited"]):
                with self.assertRaises(harness.AcceptanceError):
                    instance.action("terminate_worker_child")
            self.assertFalse((instance.public / "worker-child-termination-summary.json").exists())


if __name__ == "__main__":
    unittest.main()
