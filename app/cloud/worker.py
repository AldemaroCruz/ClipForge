"""Cloud Run Jobs entrypoint: fenced durable queue, one global media process.

The supervisor owns the PostgreSQL session advisory lock. Media runs in its own
process group, which is stopped before releasing the lock if heartbeats fail.
Expired interrupted work is failed explicitly; it is never silently replayed.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import tempfile
import time
from sqlalchemy import text
from ..auth_db import get_engine
from ..media import MediaValidationError, inspect_beta_media
from . import enabled
from .config import beta_enabled, settings
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


def _claim(connection, job_id=None):
    # The global advisory lock has already excluded every other supervisor.
    # A worker whose supervisor lost its connection may still hold a live lease.
    # Honor that lease across profiles before handling expired or queued work.
    active = connection.execute(text("""
        SELECT EXISTS(SELECT 1 FROM cloud_tasks WHERE status='running' AND lease_until>clock_timestamp())
        """)).scalar()
    if active:
        return "wait"
    profile = {"beta": beta_enabled(), "job": job_id}
    running = connection.execute(text("""
        SELECT t.* FROM cloud_tasks t
        LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
        LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
        WHERE t.status='running' AND COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
          AND (NOT :beta OR t.kind='process' OR e.payload->'pilot'=CAST('true' AS jsonb))
        ORDER BY t.created_at LIMIT 1
        """), profile).mappings().first()
    if running:
        # Crash recovery fences the previous child before publishing failure.
        with get_engine().begin() as c:
            row = c.execute(text("SELECT * FROM cloud_tasks WHERE id=:i FOR UPDATE"), {"i": running["id"]}).mappings().one()
            kind = "job" if row["kind"] == "process" else "export"
            doc = repo.document(row["job_id"], kind, row["item_id"], c)
            item = doc["payload"]
            item.update(status="failed", error="Procesamiento interrumpido; el original se conserva. Crea una nueva variante para reintentar.", error_code="WORKER_INTERRUPTED")
            repo.public_beta_failure(item)
            repo.update_document(c, row["job_id"], kind, item)
            c.execute(text("UPDATE cloud_tasks SET status='failed',fence=fence+1,lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i"), {"i": row["id"]})
    with get_engine().begin() as c:
        row = c.execute(text("""
            SELECT t.* FROM cloud_tasks t
            LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
            LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
            WHERE t.status='queued' AND COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
              AND (NOT :beta OR t.kind='process' OR e.payload->'pilot'=CAST('true' AS jsonb))
              AND (CAST(:job AS text) IS NULL OR t.job_id=:job)
            ORDER BY t.created_at,t.id LIMIT 1 FOR UPDATE OF t SKIP LOCKED
            """), profile).mappings().first()
        if row is None:
            return None
        return dict(c.execute(text("UPDATE cloud_tasks SET status='running',fence=fence+1,lease_until=clock_timestamp()+interval '60 seconds',updated_at=clock_timestamp() WHERE id=:i RETURNING *"), {"i": row["id"]}).mappings().one())


def cleanup_failed():
    """Delete only unpublished generations owned by failed task attempts.

    The supervisor still owns the global advisory lock. Originals are outside
    this namespace, and every manifest reference is checked before deletion.
    """
    with get_engine().connect() as c:
        tasks = c.execute(text("""
            SELECT t.*,p.workspace_id FROM cloud_tasks t JOIN auth_projects p ON p.id=t.job_id
            LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
            LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
            WHERE t.status='failed' AND t.cleaned_at IS NULL
              AND COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
              AND (NOT :beta OR t.kind='process' OR e.payload->'pilot'=CAST('true' AS jsonb))
            ORDER BY t.created_at LIMIT 100
            """), {"beta": beta_enabled()}).mappings().all()
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


def prepare_recovery(job_id, generation):
    """Only retry the confirmed generation of an existing beta limit rejection."""
    with get_engine().begin() as c:
        project = c.execute(text("""
            SELECT p.owner_id,p.workspace_id FROM auth_projects p
            JOIN auth_users u ON u.id=p.owner_id AND u.is_active
            WHERE p.id=:job FOR UPDATE OF p
            """), {"job": job_id}).mappings().first()
        if project is None:
            raise ValueError("The approved recovery project is unavailable")
        doc = repo.document(job_id, connection=c)
        item, manifest = doc["payload"], doc["manifest"]
        original = manifest.get("input.mp4", {})
        if (item.get("pilot") is not True or original.get("generation") != generation
                or original.get("name") != storage.beta_original(project["workspace_id"], job_id)):
            raise ValueError("Recovery source identity did not match the approved original")
        if item["status"] == "completed":
            return False
        if item["status"] == "queued" and item.get("attempt_history"):
            return True
        if item["status"] != "failed" or set(manifest) != {"input.mp4"}:
            raise ValueError("Recovery requires a failed job without published results")
        observed = storage.beta_original_metadata(original["name"])
        if observed != original:
            raise ValueError("Recovery source metadata or generation changed")
        repo.admit_beta(c, project["owner_id"])
        repo.retry_beta(c, job_id, item, expected_error="VIDEO_OUTSIDE_LIMITS")
        print(json.dumps({"status": "recovery_queued", "job_id": job_id,
                          "previous_error": "VIDEO_OUTSIDE_LIMITS", "generation": generation}), flush=True)
        return True


def drain(max_tasks=None, recovery=None):
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
                recover_job = None
                if recovery:
                    recover_job, generation = recovery
                    if not prepare_recovery(recover_job, generation):
                        return {"status": "already_completed", "job_id": recover_job}
                while max_tasks is None or completed < max_tasks:
                    task = _claim(lock, recover_job) if recover_job else _claim(lock)
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
    if recovery:
        item = repo.document(recover_job)["payload"]
        report = {"status": item["status"], "job_id": recover_job, "clips": len(item["clips"]),
                  "error_code": item.get("error_code"), "analysis_seconds": item.get("analysis_seconds"),
                  "speech_until_seconds": item.get("speech_until_seconds")}
        print(json.dumps(report), flush=True)
        if item["status"] != "completed" or not item["clips"]:
            raise ValueError("The recovery did not publish clips")
        return report
    return {"status": "interrupted" if interrupted else "drained", "tasks": completed, "local_test": cfg.local_test}


def execute(task_id, fence):
    cfg = settings()
    with get_engine().connect() as c:
        task = c.execute(text("""
            SELECT t.* FROM cloud_tasks t
            LEFT JOIN cloud_documents d ON d.job_id=t.job_id AND d.kind='job' AND d.id=t.job_id
            LEFT JOIN cloud_documents e ON e.job_id=t.job_id AND e.kind='export' AND e.id=t.item_id
            WHERE t.id=:i AND t.fence=:f AND t.status='running' AND t.lease_until>clock_timestamp()
              AND COALESCE(d.payload->'pilot'=CAST('true' AS jsonb),false)=:beta
              AND (NOT :beta OR t.kind='process' OR e.payload->'pilot'=CAST('true' AS jsonb))
            """), {"i": task_id, "f": fence, "beta": beta_enabled()}).mappings().first()
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
        pilot = job["payload"].get("pilot") is True
        try:
            storage.download(job["manifest"]["input.mp4"], folder / "input.mp4")
        except storage.StorageError:
            if not pilot:
                raise
            item = (job["payload"] if task["kind"] == "process" else
                    repo.document(task["job_id"], "export", task["item_id"])["payload"])
            item.update(status="failed", error_code="SOURCE_UNAVAILABLE")
            manifest = job["manifest"] if task["kind"] == "process" else {}
            repo.finish_task(task, item, manifest)
            return
        if "transcript.json" in job["manifest"]:
            storage.download(job["manifest"]["transcript.json"], folder / "transcript.json")
        context = {"task": task, "staged": None}
        reset = repo.CURRENT_TASK.set(context)
        try:
            if task["kind"] == "process":
                if pilot:
                    item = job["payload"]
                    item["status"] = "validating"
                    repo.worker_progress(task["job_id"], "job", item)
                    try:
                        media = inspect_beta_media(folder / "input.mp4")
                    except MediaValidationError as exc:
                        print(json.dumps({"status": "media_rejected", "job_id": task["job_id"],
                                          "error_code": exc.code}), flush=True)
                        item.update(status="failed", error_code=exc.code)
                        repo.finish_task(task, item, job["manifest"])
                        return
                    main._process(task["job_id"], validated_media=media)
                else:
                    main._process(task["job_id"])
                kind, directory = "job", folder
            else:
                (folder / "exports" / task["item_id"]).mkdir(parents=True)
                main.process_export(task["job_id"], task["item_id"], pilot=pilot)
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
    parser.add_argument("--recover-job")
    parser.add_argument("--expected-generation")
    args = parser.parse_args(argv)
    try:
        if args.execute:
            if not re.fullmatch("[a-f0-9]{32}", args.execute) or not args.fence or args.fence < 1:
                raise ValueError("Invalid task identity")
            execute(args.execute, args.fence)
        else:
            if args.max_tasks is not None and args.max_tasks < 1:
                raise ValueError("Invalid task limit")
            if args.recover_job or args.expected_generation:
                if (not beta_enabled() or not re.fullmatch(r"[a-f0-9]{32}", args.recover_job or "")
                        or not re.fullmatch(r"[1-9][0-9]{0,30}", args.expected_generation or "")):
                    raise ValueError("Approved recovery job and generation required")
                print(json.dumps(drain(1, (args.recover_job, args.expected_generation))))
            else:
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
