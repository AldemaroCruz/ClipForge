"""PostgreSQL is authoritative for cloud metadata, work and publication."""
import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import re
import uuid
from sqlalchemy import Text, bindparam, cast, column, func, table, text, update
from sqlalchemy.dialects.postgresql import JSONB
from fastapi import HTTPException
from ..auth_db import get_engine
from .config import BETA_MAX_ACTIVE, BETA_RETRIES, BETA_RETRYABLE

GLOBAL_LOCK = 1837086403
BETA_ADMISSION_LOCK = 1837086410
LEASE_SECONDS = 60
CURRENT_TASK = ContextVar("cloud_task", default=None)
_DOCUMENTS = table("cloud_documents", *(column(name) for name in (
    "job_id", "kind", "id", "payload", "manifest", "revision", "updated_at",
)))


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
    doc = _DOCUMENTS.c
    statement = update(_DOCUMENTS).where(
        doc.job_id == bindparam("j"), doc.kind == bindparam("k"), doc.id == bindparam("i"),
    ).values(payload=cast(bindparam("p", type_=Text()), JSONB),
             revision=doc.revision + 1, updated_at=func.clock_timestamp())
    if manifest is not None:
        statement = statement.values(manifest=cast(bindparam("m", type_=Text()), JSONB))
        values["m"] = packed(manifest)
    if revision is not None:
        statement = statement.where(doc.revision == bindparam("r"))
        values["r"] = revision
    result = c.execute(statement, values)
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


def admit_beta(c, owner, current_job=""):
    # One lock covers independent accounts and replicas. Pending uploads
    # release their capacity when their server-controlled deadline expires.
    c.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": BETA_ADMISSION_LOCK})
    active, own = c.execute(text("""
        SELECT count(*), count(*) FILTER (WHERE p.owner_id=:o)
        FROM cloud_documents d JOIN auth_projects p ON p.id=d.job_id
        WHERE d.kind='job' AND d.job_id<>:j AND (
            d.payload->>'status' IN ('queued','validating','transcribing','rendering')
            OR (d.payload->>'status'='awaiting_upload' AND
                CASE WHEN jsonb_typeof(d.payload->'upload_expires_at')='number'
                    THEN (d.payload->>'upload_expires_at')::double precision > extract(epoch from clock_timestamp())
                    ELSE false END))
        """), {"o": owner, "j": current_job}).one()
    if own:
        raise HTTPException(409, "Ya tienes una carga o un procesamiento pendiente. Continúa desde Tus trabajos.")
    if active >= BETA_MAX_ACTIVE:
        raise HTTPException(429, "La cola del piloto está llena. Intenta nuevamente cuando termine un trabajo.")


def check_active_workspace(c, principal):
    active = c.execute(text("""
        SELECT u.id FROM auth_users u
        JOIN auth_workspaces w ON w.owner_id=u.id
        WHERE u.id=:o AND u.is_active AND w.id=:w FOR SHARE OF u,w
        """), {"o": principal.id, "w": principal.workspace_id}).scalar()
    if active is None:
        raise HTTPException(401, "Inicia sesión para continuar")


def beta_document(c, principal, job_id):
    if not re.fullmatch(r"[a-f0-9]{32}", job_id):
        raise HTTPException(404, "Trabajo no encontrado")
    check_active_workspace(c, principal)
    owned = c.execute(text("""
        SELECT id FROM auth_projects
        WHERE id=:i AND owner_id=:o AND workspace_id=:w FOR UPDATE
        """), {"i": job_id, "o": principal.id, "w": principal.workspace_id}).scalar()
    if owned is None:
        raise HTTPException(404, "Trabajo no encontrado")
    doc = document(job_id, connection=c)
    if doc["payload"].get("pilot") is not True:
        raise HTTPException(404, "Trabajo no encontrado")
    return doc


def retry_beta(c, job_id, item):
    """Reuse the unique task on the original generation and issue a new fence."""
    task = c.execute(text("""
        SELECT id,status,cleaned_at FROM cloud_tasks
        WHERE job_id=:j AND kind='process' AND item_id=:j FOR UPDATE
        """), {"j": job_id}).mappings().first()
    if task is None or task["status"] != "failed" or task["cleaned_at"] is None:
        raise HTTPException(409, "La tarea anterior aún se está conciliando. Intenta de nuevo en unos segundos.")
    if item.get("error_code") not in BETA_RETRYABLE or item.get("retry_count", 0) >= BETA_RETRIES:
        raise HTTPException(409, "Este trabajo no se puede reintentar. Puedes subir otro video.")
    item.update(status="queued", retryable=False, clips=[], retry_count=item.get("retry_count", 0) + 1)
    for key in ("error", "error_code", "media", "language", "dispatch_status"):
        item.pop(key, None)
    update_document(c, job_id, "job", item)
    c.execute(text("""
        UPDATE cloud_tasks SET status='queued',lease_until=NULL,cleaned_at=NULL,
            updated_at=clock_timestamp() WHERE id=:i AND status='failed'
        """), {"i": task["id"]})
    c.execute(text("""
        UPDATE cloud_outbox SET dispatched_at=NULL,attempts=0,last_error=NULL,operation_name=NULL
        WHERE task_id=:i
        """), {"i": task["id"]})


_BETA_ERRORS = {
    "INPUT_NOT_FOUND": "No se encontró el original privado. Intenta nuevamente.",
    "EMPTY_INPUT": "El archivo está vacío. Selecciona un MP4 con imagen y voz.",
    "INVALID_MEDIA": "No se pudo leer el video. Vuelve a exportarlo como MP4 con H.264 y AAC.",
    "NO_VIDEO_STREAM": "El archivo no contiene una pista de video utilizable.",
    "NO_AUDIO_STREAM": "El archivo no contiene audio. Sube un MP4 con voz.",
    "VIDEO_TOO_SHORT": "El video debe durar al menos 20 segundos.",
    "PROBE_TIMEOUT": "El video tardó demasiado en verificarse. Prueba otro archivo.",
    "NO_SPEECH_DETECTED": "No se detectó voz transcribible. Prueba una conversación audible.",
    "NO_CLIP_WINDOWS": "La voz detectada no forma una ventana de 20 a 60 segundos. Prueba una conversación más larga.",
    "VIDEO_OUTSIDE_LIMITS": "El video está fuera de los límites del piloto. Revisa la duración y resolución.",
    "UNSUPPORTED_MEDIA": "El piloto admite MP4 con video H.264 y audio AAC.",
    "UPLOAD_MISMATCH": "El archivo recibido no coincide con la carga autorizada. Sube otro video.",
    "SOURCE_UNAVAILABLE": "El original privado no está disponible en este momento.",
    "WORKER_INTERRUPTED": "El procesamiento se interrumpió. El original se conserva.",
    "PROCESSING_FAILED": "No se pudo generar los clips. El original se conserva.",
}


def public_beta_error_code(code):
    return code if isinstance(code, str) and code in _BETA_ERRORS else "PROCESSING_FAILED"


def public_beta_failure(item):
    if item.get("pilot") is not True or item.get("status") != "failed":
        return
    code = public_beta_error_code(item.get("error_code"))
    item.update(error_code=code, error=_BETA_ERRORS[code], clips=[],
                retryable=code in BETA_RETRYABLE and item.get("retry_count", 0) < BETA_RETRIES)
    # A parser failure can include untrusted metadata. No raw diagnostics in
    # the public job document or feedback context.
    item.pop("media", None)


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
    public_beta_failure(payload)
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
    public_beta_failure(payload)
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
        public_beta_failure(item)
        update_document(c, task["job_id"], kind, item)
        c.execute(text("UPDATE cloud_tasks SET status='failed',lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i AND fence=:f"), {"i": task["id"], "f": task["fence"]})
