"""Temporary-file ownership and content-free media worker measurements."""
from contextlib import nullcontext
import json
import math
import os
from pathlib import Path
import re
import stat
import tempfile
import time

from ..state import write_json_atomic

SCRATCH_ENV = "CLIPFORGE_WORKER_SCRATCH"
ENTRY_ENV = "CLIPFORGE_WORKER_ENTRY_EPOCH"
CLAIM_ENV = "CLIPFORGE_WORKER_CLAIM_EPOCH"
SCRATCH_PREFIX = "clipforge-worker-"
SAMPLE_INTERVAL_SECONDS = 2
CGROUP = Path("/sys/fs/cgroup")
PROC = Path("/proc")
STAGES = {"prepare", "download", "probe", "validation", "model_load", "transcription", "selection", "render", "publish"}


def scratch_context():
    """Borrow the supervisor's private task directory, or own a standalone one."""
    inherited = os.getenv(SCRATCH_ENV)
    if inherited is None:
        return tempfile.TemporaryDirectory(prefix=SCRATCH_PREFIX)
    path = Path(inherited)
    if (path.parent != Path(tempfile.gettempdir()).resolve()
            or not re.fullmatch(SCRATCH_PREFIX + r"[a-z0-9_]{8}", path.name)):
        raise ValueError("Invalid worker scratch directory")
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or
            (os.name == "posix" and (info.st_mode & 0o077 or info.st_uid != os.geteuid()))):
        raise ValueError("Worker scratch directory must be private and owned")
    return nullcontext(str(path))


def record_stage(scratch, timings, name, began):
    timings[name] = round(time.monotonic() - began, 6)
    try:
        write_json_atomic(Path(scratch) / "worker-stages.json", timings)
    except OSError:
        return


def _read_number(path):
    try:
        return int(path.read_text(encoding="ascii"))
    except (OSError, ValueError):
        return None


def _child_rss(pid):
    try:
        with (PROC / str(pid) / "status").open(encoding="ascii") as status:
            for line in status:
                if line.startswith("VmHWM:"):
                    return int(line.split()[1]) * 1024
    except (OSError, ValueError, IndexError):
        return None
    return None


def _file_bytes(directory):
    total = 0
    for folder, _, names in os.walk(directory):
        for name in names:
            try:
                info = (Path(folder) / name).lstat()
            except OSError:
                info = None
            if info is not None and stat.S_ISREG(info.st_mode):
                total += info.st_size
    return total


def _metrics(path):
    try:
        with path.open("rb") as source:
            data = json.loads(source.read(16385))
    except (OSError, ValueError):
        return {}
    return data if isinstance(data, dict) else {}


def _valid_seconds(value):
    return type(value) in {int, float} and 0 <= value <= 86400 and math.isfinite(value)


def _timings(data):
    if not isinstance(data, dict):
        return {}
    return {key: value for key, value in data.items() if key in STAGES and _valid_seconds(value)}


def _clip_renders(data):
    if not isinstance(data, list) or not 1 <= len(data) <= 5:
        return None
    keys = {"render_seconds", "seconds_since_recorder_start"}
    if any(not isinstance(item, dict) or set(item) != keys
           or not all(_valid_seconds(value) for value in item.values()) for item in data):
        return None
    return data


def completed_receipt(directory, task, timings):
    """Capture a completed task's timings within the same publication fence."""
    directory = Path(directory)
    metrics_path = directory / task["job_id"] / "metrics" / f"{task['kind']}-{task['item_id']}.json"
    metrics = _metrics(metrics_path)
    # Cross-process timestamps come from UTC wall time. In-process durations
    # use monotonic clocks. A claim by an existing supervisor may have no
    # measured Cloud Run dispatch for the task.
    timestamps = {"activated_epoch": task["created_at"].timestamp(),
                  "dispatch_ack_epoch": task["dispatch_ack_epoch"]}
    for name, variable in (("worker_entry_epoch", ENTRY_ENV), ("claim_epoch", CLAIM_ENV)):
        value = os.getenv(variable)
        if value:
            try:
                stamp = float(value)
            except ValueError:
                continue
            if math.isfinite(stamp) and stamp > 0:
                timestamps[name] = stamp
    return {"schema": 1, "task_id": task["id"], "fence": task["fence"],
            "kind": task["kind"], "timestamps": {**timestamps, "upload_complete_observed_epoch": time.time()},
            "stage_seconds": _timings(metrics.get("stage_seconds")) | _timings(timings),
            "container_peak_bytes_through_upload": _read_number(CGROUP / "memory.peak")}


class WorkerMeasurements:
    def __init__(self, directory, task, execution):
        self.directory = Path(directory)
        self.task = task
        self.execution = execution
        self.scratch = 0
        self.memory = None
        self.rss = None
        self.limit = _read_number(CGROUP / "memory.max")

    def sample(self, pid=None):
        self.scratch = max(self.scratch, _file_bytes(self.directory))
        if self.limit is not None:
            current = _read_number(CGROUP / "memory.current")
            if current is not None:
                self.memory = max(self.memory or 0, current)
        if pid is not None:
            rss = _child_rss(pid)
            if rss is not None:
                self.rss = max(self.rss or 0, rss)

    def receipt(self, status):
        self.sample()
        task = self.task
        metrics = self.directory / task["job_id"] / "metrics" / f"{task['kind']}-{task['item_id']}.json"
        task_metrics = _metrics(metrics)
        stages = _timings(task_metrics.get("stage_seconds")) | _timings(_metrics(self.directory / "worker-stages.json"))
        return {
            "event": "worker_resources", "execution": self.execution, "job_id": task["job_id"],
            "task_id": task["id"], "fence": task["fence"], "kind": task["kind"], "status": status,
            "scratch_max_sampled_bytes": self.scratch, "cgroup_memory_max_sampled_bytes": self.memory,
            "cgroup_memory_peak_bytes_execution": _read_number(CGROUP / "memory.peak") if self.limit is not None else None,
            "cgroup_memory_limit_bytes": self.limit, "child_rss_max_sampled_bytes": self.rss,
            "sample_interval_seconds": SAMPLE_INTERVAL_SECONDS, "stage_seconds": stages,
            "clip_renders": _clip_renders(task_metrics.get("clip_renders")),
        }
