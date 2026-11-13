"""Cloud Run Jobs entrypoint: fenced durable queue, one global media process.

The supervisor owns the PostgreSQL session advisory lock. Media runs in its own
process group, which is stopped before releasing the lock if heartbeats fail.
Expired interrupted work is failed explicitly; it is never silently replayed.
"""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time
from sqlalchemy import text
from ..auth_db import get_engine
from . import enabled
from .config import settings
from . import repository as repo
from . import storage


def _terminate(child):
    if child.poll() is not None:
        return
    if os.name == "posix":
        os.killpg(child.pid, signal.SIGTERM)
    else:
        child.terminate()
    try:
        child.wait(timeout=5)
    except subprocess.TimeoutExpired:
        if os.name == "posix":
            os.killpg(child.pid, signal.SIGKILL)
        else:
            child.kill()
        child.wait(timeout=5)


def _claim(connection):
    # The global advisory lock has already excluded every other supervisor.
    running = connection.execute(text("SELECT * FROM cloud_tasks WHERE status='running' ORDER BY created_at LIMIT 1")).mappings().first()
    if running:
        active = connection.execute(text("SELECT lease_until>clock_timestamp() FROM cloud_tasks WHERE id=:i"), {"i": running["id"]}).scalar()
        if active:
            return "wait"
        # Crash recovery fences the previous child before publishing failure.
        with get_engine().begin() as c:
            row = c.execute(text("SELECT * FROM cloud_tasks WHERE id=:i FOR UPDATE"), {"i": running["id"]}).mappings().one()
            kind = "job" if row["kind"] == "process" else "export"
            doc = repo.document(row["job_id"], kind, row["item_id"], c)
            item = doc["payload"]
            item.update(status="failed", error="Procesamiento interrumpido; el original se conserva. Crea una nueva variante para reintentar.", error_code="WORKER_INTERRUPTED")
            repo.update_document(c, row["job_id"], kind, item)
            c.execute(text("UPDATE cloud_tasks SET status='failed',fence=fence+1,lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i"), {"i": row["id"]})
    with get_engine().begin() as c:
        row = c.execute(text("SELECT * FROM cloud_tasks WHERE status='queued' ORDER BY created_at,id LIMIT 1 FOR UPDATE SKIP LOCKED")).mappings().first()
        if row is None:
            return None
        return dict(c.execute(text("UPDATE cloud_tasks SET status='running',fence=fence+1,lease_until=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp() WHERE id=:i RETURNING *"), {"i": row["id"]}).mappings().one())


def cleanup_failed():
    """Delete only unpublished generations owned by failed task attempts.

    The supervisor still owns the global advisory lock. Originals are outside
    this namespace, and every manifest reference is checked before deletion.
    """
    with get_engine().connect() as c:
        tasks = c.execute(text("SELECT t.*,p.workspace_id FROM cloud_tasks t JOIN auth_projects p ON p.id=t.job_id WHERE t.status='failed' AND t.cleaned_at IS NULL ORDER BY t.created_at LIMIT 100")).mappings().all()
    for task in tasks:
        prefix = f"workspaces/{task['workspace_id']}/jobs/{task['job_id']}/tasks/{task['id']}/"
        try:
            with get_engine().begin() as c:
                current = c.execute(text("SELECT status FROM cloud_tasks WHERE id=:i FOR UPDATE"), {"i": task["id"]}).scalar()
                if current != "failed":
                    continue
                manifests = c.execute(text("SELECT manifest FROM cloud_documents WHERE job_id=:j"), {"j": task["job_id"]}).scalars().all()
                references = {(value["name"], value["generation"]) for manifest in manifests for value in manifest.values()}
                for item in storage.list_staged(prefix):
                    if (item["name"], item["generation"]) in references:
                        raise RuntimeError("Failed task has a published manifest reference; cleanup refused")
                    storage.delete_staged(item, prefix)
                c.execute(text("UPDATE cloud_tasks SET cleaned_at=clock_timestamp() WHERE id=:i AND status='failed'"), {"i": task["id"]})
        except Exception:
            # Keep the exact task/fence durable so the operator can reconcile.
            print(json.dumps({"status": "cleanup_pending", "task_id": task["id"]}), file=sys.stderr)


def drain(max_tasks=None):
    cfg = settings()
    if not enabled():
        raise ValueError("Worker requires the explicit cloud backend")
    completed = 0
    child = None
    interrupted = False
    previous = {}
    def stop(signum, frame):
        nonlocal interrupted
        interrupted = True
        if child is not None:
            _terminate(child)
        raise KeyboardInterrupt
    for signum in (signal.SIGTERM, signal.SIGINT):
        previous[signum] = signal.signal(signum, stop)
    try:
        with get_engine().connect().execution_options(isolation_level="AUTOCOMMIT") as lock:
            lock.execute(text("SELECT pg_advisory_lock(:i)"), {"i": repo.GLOBAL_LOCK})
            lock.execute(text("SET statement_timeout='10s'"))
            try:
                cleanup_failed()
                while max_tasks is None or completed < max_tasks:
                    task = _claim(lock)
                    if task == "wait":
                        time.sleep(1)
                        continue
                    if task is None:
                        cleanup_failed()
                        break
                    command = [sys.executable, "-m", "app.cloud.worker", "--execute", task["id"], "--fence", str(task["fence"])]
                    # Fixed interpreter/module; only database-generated UUID/fence arguments.
                    child = subprocess.Popen(command, start_new_session=os.name == "posix")
                    try:
                        while child.poll() is None:
                            try:
                                child.wait(timeout=2)
                            except subprocess.TimeoutExpired:
                                result = lock.execute(text("UPDATE cloud_tasks SET lease_until=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp() WHERE id=:i AND fence=:f AND status='running' AND lease_until>clock_timestamp()"), {"i": task["id"], "f": task["fence"]})
                                if result.rowcount != 1:
                                    status = lock.execute(text("SELECT status FROM cloud_tasks WHERE id=:i AND fence=:f"), {"i": task["id"], "f": task["fence"]}).scalar()
                                    if status not in {"succeeded", "failed"}:
                                        raise RuntimeError("Worker lease lost")
                        with get_engine().connect() as c:
                            status = c.execute(text("SELECT status FROM cloud_tasks WHERE id=:i"), {"i": task["id"]}).scalar()
                        if status == "running":
                            repo.mark_crashed(task)
                    except BaseException:
                        _terminate(child)
                        raise
                    finally:
                        child = None
                    completed += 1
                    cleanup_failed()
            finally:
                # A failed connection invalidates its lock; no child survives us.
                if child is not None:
                    _terminate(child)
                if not lock.invalidated:
                    lock.execute(text("SELECT pg_advisory_unlock(:i)"), {"i": repo.GLOBAL_LOCK})
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
    return {"status": "interrupted" if interrupted else "drained", "tasks": completed, "local_test": cfg.local_test}


def execute(task_id, fence):
    cfg = settings()
    with get_engine().connect() as c:
        task = c.execute(text("SELECT * FROM cloud_tasks WHERE id=:i AND fence=:f AND status='running' AND lease_until>clock_timestamp()"), {"i": task_id, "f": fence}).mappings().first()
        if task is None:
            raise RuntimeError("Task lease unavailable")
        task = dict(task)
        workspace = c.execute(text("SELECT workspace_id FROM auth_projects WHERE id=:i"), {"i": task["job_id"]}).scalar_one()
    # Offline weights are compulsory for automatic cloud transcription.
    if not cfg.local_test and not os.getenv("CLIPFORGE_MODEL_LOCK"):
        raise RuntimeError("Cloud worker requires an identified offline model lock")
    os.environ["HF_HUB_OFFLINE"] = "1"
    os.environ["TRANSFORMERS_OFFLINE"] = "1"
    with tempfile.TemporaryDirectory(prefix="clipforge-worker-") as cache:
        os.environ["CLIPFORGE_DATA_DIR"] = cache
        from .. import main
        main.ROOT = Path(cache)
        folder = main.ROOT / task["job_id"]
        folder.mkdir()
        job = repo.document(task["job_id"])
        storage.download(job["manifest"]["input.mp4"], folder / "input.mp4")
        if "transcript.json" in job["manifest"]:
            storage.download(job["manifest"]["transcript.json"], folder / "transcript.json")
        context = {"task": task, "staged": None}
        reset = repo.CURRENT_TASK.set(context)
        try:
            if task["kind"] == "process":
                main._process(task["job_id"])
                kind, directory = "job", folder
            else:
                (folder / "exports" / task["item_id"]).mkdir(parents=True)
                main.process_export(task["job_id"], task["item_id"])
                kind, directory = "export", folder / "exports" / task["item_id"]
            payload = context["staged"]
            if payload is None:
                raise RuntimeError("Worker produced no durable state")
            doc = repo.document(task["job_id"], kind, task["item_id"])
            manifest = doc["manifest"]
            if payload["status"] == "completed":
                if kind == "job":
                    names = ["transcript.json"] if (directory / "transcript.json").is_file() else []
                    for clip in payload["clips"]:
                        names.extend([clip["file"], Path(clip["file"]).with_suffix(".srt").name, Path(clip["file"]).with_suffix(".vtt").name])
                else:
                    names = ["clip.mp4", "clip.srt", "clip.vtt"]
                for name in names:
                    path = directory / name
                    if not path.is_file():
                        raise RuntimeError("Incomplete worker artifact set")
                    mime = {".mp4": "video/mp4", ".srt": "application/x-subrip", ".vtt": "text/vtt", ".json": "application/json"}[path.suffix]
                    object_name = f"workspaces/{workspace}/jobs/{task['job_id']}/tasks/{task['id']}/{task['fence']}/{name}"
                    with path.open("rb") as source:
                        manifest[name] = storage.upload(object_name, source, mime)
            repo.finish_task(task, payload, manifest)
        finally:
            repo.CURRENT_TASK.reset(reset)


def main(argv=None):
    parser = argparse.ArgumentParser(description="Drain persistent multimedia tasks with native PostgreSQL exclusion")
    parser.add_argument("--max-tasks", type=int)
    parser.add_argument("--execute", help=argparse.SUPPRESS)
    parser.add_argument("--fence", type=int, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    try:
        if args.execute:
            import re
            if not re.fullmatch("[a-f0-9]{32}", args.execute) or not args.fence or args.fence < 1:
                raise ValueError("Invalid task identity")
            execute(args.execute, args.fence)
        else:
            if args.max_tasks is not None and args.max_tasks < 1:
                raise ValueError("Invalid task limit")
            print(json.dumps(drain(args.max_tasks)))
        return 0
    except (Exception, KeyboardInterrupt) as exc:
        result = {"status": "failed", "error_type": type(exc).__name__,
                  "message": "Cloud worker stopped; inspect durable task status, no credentials logged."}
        if isinstance(exc, storage.StorageError):
            result["cloud_error"] = str(exc)  # Fixed messages and HTTP status only.
        print(json.dumps(result), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
