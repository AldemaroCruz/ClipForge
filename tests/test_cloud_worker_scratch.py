"""Isolated task directory and measurements contract for the Cloud Run supervisor."""
from datetime import datetime, timezone
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
from app.cloud.worker_measurements import (
    CLAIM_ENV, ENTRY_ENV, SCRATCH_ENV, WorkerMeasurements, completed_receipt, scratch_context,
)
from app.telemetry import Recorder


TASK = {"id": "a" * 32, "job_id": "b" * 32, "item_id": "b" * 32, "kind": "process", "fence": 1,
        "created_at": datetime.fromtimestamp(100, tz=timezone.utc),
        "updated_at": datetime.fromtimestamp(107, tz=timezone.utc), "dispatch_ack_epoch": 101.5}


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
            self.assertIsNone(receipt["clip_renders"])

    def test_receipt_reads_completed_clip_timings_and_rejects_extra_content(self):
        with TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            with patch("app.telemetry.time.monotonic", side_effect=(10, 16, 24, 25)):
                recorder = Recorder(scratch, TASK["job_id"], "process", TASK["item_id"])
                recorder.clip_rendered(started=12)
                recorder.clip_rendered(started=18)
                recorder.finish("completed")
            measurements = WorkerMeasurements(scratch, TASK, "synthetic-execution")
            self.assertEqual(measurements.receipt("succeeded")["clip_renders"], [
                {"render_seconds": 4, "seconds_since_recorder_start": 6},
                {"render_seconds": 6, "seconds_since_recorder_start": 14},
            ])

            raw = json.loads(recorder.path.read_text(encoding="utf-8"))
            raw["clip_renders"][0]["content"] = "Private material must not appear in a log"
            recorder.path.write_text(json.dumps(raw), encoding="utf-8")
            self.assertIsNone(measurements.receipt("succeeded")["clip_renders"])

    def test_completed_receipt_keeps_separate_wall_timestamps_and_local_durations(self):
        with TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            metrics = scratch / TASK["job_id"] / "metrics"
            metrics.mkdir(parents=True)
            (metrics / f"process-{TASK['item_id']}.json").write_text(
                json.dumps({"stage_seconds": {"transcription": 10, "private": 1}, "private": "not part of receipt"}),
                encoding="utf-8",
            )
            (scratch / "memory.peak").write_text("131072", encoding="ascii")
            with (patch("app.cloud.worker_measurements.CGROUP", scratch),
                  patch.dict(os.environ, {ENTRY_ENV: "105", CLAIM_ENV: "107"}),
                  patch("app.cloud.worker_measurements.time.time", return_value=120),
                  patch("app.cloud.worker_measurements._render_rss", return_value={
                      "worker_process_peak_rss_bytes": 65536, "largest_child_peak_rss_bytes": 262144,
                  })):
                receipt = completed_receipt(scratch, TASK, {"prepare": 0.8, "publish": 2, "no": 3})
            self.assertEqual(receipt["timestamps"], {"activated_epoch": 100, "dispatch_ack_epoch": 101.5,
                                                     "worker_entry_epoch": 105, "claim_epoch": 107,
                                                     "upload_complete_observed_epoch": 120})
            self.assertEqual(receipt["stage_seconds"], {"prepare": 0.8, "transcription": 10, "publish": 2})
            self.assertEqual(receipt["container_peak_bytes_through_upload"], 131072)
            self.assertEqual(receipt["worker_process_peak_rss_bytes"], 65536)
            self.assertEqual(receipt["largest_child_peak_rss_bytes"], 262144)

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
