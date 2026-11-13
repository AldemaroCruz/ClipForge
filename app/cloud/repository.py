"""PostgreSQL is authoritative for cloud metadata, work and publication."""
import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import uuid
from sqlalchemy import text
from fastapi import HTTPException
from ..auth_db import get_engine

GLOBAL_LOCK = 1837086403
LEASE_SECONDS = 60
CURRENT_TASK = ContextVar("cloud_task", default=None)


def packed(value):
    return json.dumps(value, allow_nan=False, separators=(",", ":"))


def document(job_id, kind="job", item_id=None, connection=None):
    item_id = item_id or job_id
    def read(c):
        row = c.execute(text("SELECT payload,manifest,revision FROM cloud_documents WHERE job_id=:j AND kind=:k AND id=:i"),
                        {"j": job_id, "k": kind, "i": item_id}).mappings().first()
        if row is None:
            raise HTTPException(404, "Proyecto o documento no encontrado")
        return copy.deepcopy(dict(row))
    if connection is not None:
        return read(connection)
    with get_engine().connect() as c:
        return read(c)


def list_documents(job_id, kind, connection=None):
    def read(c):
        return [copy.deepcopy(dict(r)) for r in c.execute(text("SELECT payload,manifest,revision FROM cloud_documents WHERE job_id=:j AND kind=:k ORDER BY updated_at DESC,id DESC"), {"j": job_id, "k": kind}).mappings()]
    if connection is not None:
        return read(connection)
    with get_engine().connect() as c:
        return read(c)


def insert_document(c, job_id, kind, item, manifest=None):
    c.execute(text("INSERT INTO cloud_documents(job_id,kind,id,payload,manifest) VALUES (:j,:k,:i,CAST(:p AS jsonb),CAST(:m AS jsonb))"),
              {"j": job_id, "k": kind, "i": item["id"], "p": packed(item), "m": packed(manifest or {})})


def update_document(c, job_id, kind, item, revision=None, manifest=None):
    values = {"j": job_id, "k": kind, "i": item["id"], "p": packed(item)}
    fragment = ""
    if manifest is not None:
        fragment = ",manifest=CAST(:m AS jsonb)"
        values["m"] = packed(manifest)
    revision_filter = ""
    if revision is not None:
        revision_filter = " AND revision=:r"
        values["r"] = revision
    result = c.execute(text("UPDATE cloud_documents SET payload=CAST(:p AS jsonb),revision=revision+1,updated_at=clock_timestamp()" + fragment + " WHERE job_id=:j AND kind=:k AND id=:i" + revision_filter), values)
    if result.rowcount != 1:
        raise HTTPException(409, "El documento cambió. Vuelve a abrirlo antes de guardar.")


def enqueue(c, job_id, kind, item_id):
    task_id = uuid.uuid4().hex
    c.execute(text("INSERT INTO cloud_tasks(id,job_id,kind,item_id,status) VALUES (:i,:j,:k,:n,'queued')"), {"i": task_id, "j": job_id, "k": kind, "n": item_id})
    c.execute(text("INSERT INTO cloud_outbox(task_id) VALUES (:i)"), {"i": task_id})
    return task_id


@contextmanager
def request_transaction(owner, key, fingerprint):
    # A stable per-owner key serializes duplicate HTTP submissions across replicas.
    if not key:
        key = uuid.uuid4().hex
    import re
    if not re.fullmatch(r"[A-Za-z0-9._-]{8,64}", key):
        raise HTTPException(422, "Idempotency-Key inválida")
    lock = int.from_bytes(hashlib.sha256((owner + ":" + key).encode()).digest()[:8], "big", signed=True)
    with get_engine().begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": lock})
        row = c.execute(text("SELECT * FROM cloud_requests WHERE owner_id=:o AND request_key=:k"), {"o": owner, "k": key}).mappings().first()
        if row and row["fingerprint"] != fingerprint:
            raise HTTPException(409, "La clave de solicitud ya identifica otro contenido")
        yield c, dict(row) if row else None, key


def remember_request(c, owner, key, fingerprint, job_id, kind, item_id):
    c.execute(text("INSERT INTO cloud_requests(owner_id,request_key,fingerprint,job_id,kind,item_id) VALUES (:o,:k,:f,:j,:t,:i)"),
              {"o": owner, "k": key, "f": fingerprint, "j": job_id, "t": kind, "i": item_id})


def worker_guard(c, task):
    row = c.execute(text("SELECT * FROM cloud_tasks WHERE id=:i AND status='running' AND fence=:f AND lease_until>clock_timestamp() FOR UPDATE"), {"i": task["id"], "f": task["fence"]}).mappings().first()
    if row is None:
        raise RuntimeError("Worker lease or fencing token lost")
    return dict(row)


def worker_progress(job_id, kind, payload):
    context = CURRENT_TASK.get()
    if context is None or context["task"]["job_id"] != job_id:
        raise RuntimeError("Cloud mutations require a fenced worker task")
    task = context["task"]
    expected = "job" if task["kind"] == "process" else "export"
    if kind != expected or payload["id"] != task["item_id"]:
        raise RuntimeError("Worker attempted to mutate another document")
    context["staged"] = copy.deepcopy(payload)
    safe = copy.deepcopy(payload)
    # Only the final atomic manifest transaction can publish output references.
    if kind == "job":
        safe["clips"] = []
    if safe["status"] == "completed":
        safe["status"] = "rendering"
    with get_engine().begin() as c:
        worker_guard(c, task)
        update_document(c, job_id, kind, safe)


def finish_task(task, payload, manifest):
    kind = "job" if task["kind"] == "process" else "export"
    with get_engine().begin() as c:
        worker_guard(c, task)
        update_document(c, task["job_id"], kind, payload, manifest=manifest)
        c.execute(text("UPDATE cloud_tasks SET status=:s,lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i AND fence=:f"),
                  {"s": "succeeded" if payload["status"] == "completed" else "failed", "i": task["id"], "f": task["fence"]})


def mark_crashed(task):
    with get_engine().begin() as c:
        worker_guard(c, task)
        kind = "job" if task["kind"] == "process" else "export"
        doc = document(task["job_id"], kind, task["item_id"], c)
        item = doc["payload"]
        item.update(status="failed", error="Procesamiento interrumpido. El original se conserva; revisa el estado antes de reintentar.", error_code="WORKER_INTERRUPTED")
        update_document(c, task["job_id"], kind, item)
        c.execute(text("UPDATE cloud_tasks SET status='failed',lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i AND fence=:f"), {"i": task["id"], "f": task["fence"]})
