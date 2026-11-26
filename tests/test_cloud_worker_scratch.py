"""Isolated task directory and measurements contract for the Cloud Run supervisor."""
import io
import json
import os
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
from unittest import TestCase, skipUnless
from unittest.mock import patch

from app.cloud import worker
from app.cloud.worker_measurements import SCRATCH_ENV, WorkerMeasurements, scratch_context


TASK = {"id": "a" * 32, "job_id": "b" * 32, "item_id": "b" * 32, "kind": "process", "fence": 1}


class WorkerMeasurementTests(TestCase):
    def test_resource_receipt_distinguishes_task_samples_and_execution_peak(self):
        with TemporaryDirectory() as temporary:
            base = Path(temporary)
            cgroup, proc, scratch = (base / item for item in ("cgroup", "proc", "scratch"))
            for path in (cgroup, proc / "123", scratch):
                path.mkdir(parents=True)
            (cgroup / "memory.max").write_text("4294967296", encoding="ascii")
            (cgroup / "memory.current").write_text("1073741824", encoding="ascii")
            (cgroup / "memory.peak").write_text("1547483648", encoding="ascii")
            (proc / "123" / "status").write_text("VmHWM:\t2048 kB\n", encoding="ascii")
            source = scratch / "input.mp4"
            source.write_bytes(b"test")
            (scratch / "worker-stages.json").write_text(
                json.dumps({"download": 2.15, "publication": "private control", "publish": True}),
                encoding="utf-8",
            )
            with (
                patch("app.cloud.worker_measurements.CGROUP", cgroup),
                patch("app.cloud.worker_measurements.PROC", proc),
            ):
                measurements = WorkerMeasurements(scratch, TASK, "synthetic-execution")
                measurements.sample(123)
                source.unlink()
                (cgroup / "memory.current").write_text("1000", encoding="ascii")
                receipt = measurements.receipt("succeeded")
            self.assertEqual(receipt["event"], "worker_resources")
            self.assertEqual(receipt["cgroup_memory_max_sampled_bytes"], 1_073_741_824)
            self.assertEqual(receipt["cgroup_memory_peak_bytes_execution"], 1_547_483_648)
            self.assertEqual(receipt["child_rss_max_sampled_bytes"], 2_097_152)
            self.assertGreaterEqual(receipt["scratch_max_sampled_bytes"], 4)
            self.assertEqual(receipt["stage_seconds"], {"download": 2.15})

    def test_child_can_only_borrow_the_private_managed_directory(self):
        with TemporaryDirectory() as unrelated, patch.dict(os.environ, {SCRATCH_ENV: unrelated}):
            with self.assertRaises(ValueError):
                scratch_context()

    @skipUnless(os.name == "posix", "Worker supervision runs in a Linux container")
    def test_supervisor_removes_task_files_even_when_the_child_cannot_unwind(self):
        spawn = subprocess.Popen
        allocated = []
        child_script = """
from pathlib import Path
import os
import signal
from app.cloud.worker_measurements import scratch_context

with scratch_context() as directory:
    Path(directory, "abandoned-media.mp4").write_bytes(b"synthetic")
    os.kill(os.getpid(), signal.SIGKILL)
"""

        def create(_command, *, start_new_session, env):
            scratch = Path(env[SCRATCH_ENV])
            allocated.append(scratch)
            return spawn([sys.executable, "-B", "-c", child_script],
                         start_new_session=start_new_session, env=env)

        with TemporaryDirectory() as unrelated:
            retained = Path(unrelated) / "sentinel"
            retained.write_bytes(b"untouched")
            with (
                patch.dict(os.environ, {"CLOUD_RUN_EXECUTION": "synthetic-execution"}),
                patch.object(worker, "settings", return_value=SimpleNamespace(local_test=True)),
                patch.object(worker, "enabled", return_value=True),
                patch.object(worker, "beta_enabled", return_value=True),
                patch.object(worker, "get_engine"),
                patch.object(worker, "cleanup_failed"),
                patch.object(worker, "_claim", return_value=TASK),
                patch.object(worker, "_finish_child", return_value="failed") as finish,
                patch.object(worker.subprocess, "Popen", side_effect=create),
                patch("sys.stdout", new_callable=io.StringIO) as output,
            ):
                worker.drain(max_tasks=1)
            finish.assert_called_once_with(TASK)
            self.assertEqual(len(allocated), 1)
            self.assertFalse(allocated[0].exists())
            self.assertEqual(retained.read_bytes(), b"untouched")
            samples = [json.loads(line) for line in output.getvalue().splitlines()]
            self.assertEqual(samples[-1]["status"], "failed")
            self.assertEqual(samples[-1]["scratch_max_sampled_bytes"], len(b"synthetic"))
