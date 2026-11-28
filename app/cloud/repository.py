"""PostgreSQL is authoritative for cloud metadata, work and publication."""
import copy
from contextlib import contextmanager
from contextvars import ContextVar
import hashlib
import json
import re
import time
import uuid
from sqlalchemy import Text, bindparam, cast, column, func, table, text, update
from sqlalchemy.dialects.postgresql import JSONB
from fastapi import HTTPException
from ..auth_db import get_engine
from ..presentation import HIGHLIGHT_DEFAULTS, separate_highlight
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


def _presentation_metadata(kind, item, *, read=False):
    def convert(container, field):
        if field not in container:
            return
        sibling = field + "_highlight"
        if read:
            extension = container.pop(sibling, None)
            for key, default in HIGHLIGHT_DEFAULTS.items():
                container[field].setdefault(key, default)
            if extension:
                container[field].update(extension)
        else:
            container[field], extension = separate_highlight(container[field])
            if extension:
                container[sibling] = extension
            else:
                container.pop(sibling, None)

    if kind not in {"job", "draft", "export"}:
        return item
    if not read:
        item = copy.deepcopy(item)
    convert(item, "options")
    if kind == "job":
        convert(item, "caption_style")
        for clip in item.get("clips", []):
            convert(clip, "options")
        for settings in item.get("clip_caption_settings", {}).values():
            convert(settings, "style")
    return item


def _read_document(row, kind):
    result = copy.deepcopy(dict(row))
    _presentation_metadata(kind, result["payload"], read=True)
    return result


def document(job_id, kind="job", item_id=None, connection=None, *, required=True, live=False):
    item_id = item_id or job_id
    def read(c):
        statement = ("SELECT payload,manifest,revision FROM cloud_documents "
                     "WHERE job_id=:j AND kind=:k AND id=:i")
        if live:
            statement += (" AND EXISTS (SELECT 1 FROM auth_projects p WHERE p.id=:j "
                          "AND p.deletion_started_at IS NULL)")
        row = c.execute(text(statement),
                        {"j": job_id, "k": kind, "i": item_id}).mappings().first()
        if row is None:
            if required:
                raise HTTPException(404, "Proyecto o documento no encontrado")
            return None
        return _read_document(row, kind)
    if connection is not None:
        return read(connection)
    with get_engine().connect() as c:
        return read(c)


def list_documents(job_id, kind, connection=None):
    def read(c):
        rows = c.execute(text("SELECT payload,manifest,revision FROM cloud_documents WHERE job_id=:j AND kind=:k ORDER BY updated_at DESC,id DESC"), {"j": job_id, "k": kind}).mappings()
        return [_read_document(row, kind) for row in rows]
    if connection is not None:
        return read(connection)
    with get_engine().connect() as c:
        return read(c)


def insert_document(c, job_id, kind, item, manifest=None):
    c.execute(text("INSERT INTO cloud_documents(job_id,kind,id,payload,manifest) VALUES (:j,:k,:i,CAST(:p AS jsonb),CAST(:m AS jsonb))"),
              {"j": job_id, "k": kind, "i": item["id"], "p": packed(_presentation_metadata(kind, item)), "m": packed(manifest or {})})


def update_document(c, job_id, kind, item, revision=None, manifest=None):
    values = {"j": job_id, "k": kind, "i": item["id"], "p": packed(_presentation_metadata(kind, item))}
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


def admit_beta(c, owner, current_job="", *, caption_job=""):
    # Only an active owner can use a pending upload to start processing.
    # Already queued work and live task leases still consume capacity.
    c.execute(text("SELECT pg_advisory_xact_lock(:lock)"), {"lock": BETA_ADMISSION_LOCK})
    active, own = c.execute(text("""
        WITH candidates AS (
          SELECT p.owner_id,
                 CASE WHEN d.payload->'clip_captions'=CAST('true' AS jsonb)
                      THEN d.job_id ELSE d.id END AS slot
          FROM cloud_documents d JOIN auth_projects p ON p.id=d.job_id
          JOIN auth_users u ON u.id=p.owner_id
          WHERE d.kind IN ('job','export','selection','alignment','publication_ai') AND d.payload->'pilot'=CAST('true' AS jsonb)
            AND p.deletion_started_at IS NULL AND d.job_id<>:j
            AND NOT (d.job_id=:caption AND COALESCE(d.payload->'clip_captions'=CAST('true' AS jsonb),false))
            AND (
            d.payload->>'status' IN ('queued','validating','transcribing','rendering','running')
            OR (d.payload->>'status'='awaiting_upload' AND u.is_active AND
                CASE WHEN jsonb_typeof(d.payload->'upload_expires_at')='number'
                    THEN (d.payload->>'upload_expires_at')::double precision > extract(epoch from clock_timestamp())
                    ELSE false END))
          UNION ALL
          SELECT p.owner_id,t.id AS slot
          FROM cloud_tasks t JOIN auth_projects p ON p.id=t.job_id
          WHERE p.deletion_started_at IS NOT NULL AND t.kind<>'delete'
            AND t.status='cancelled' AND t.lease_until>clock_timestamp())
        SELECT count(DISTINCT slot),count(DISTINCT slot) FILTER (WHERE owner_id=:o) FROM candidates
        """), {"o": owner, "j": current_job, "caption": caption_job}).one()
    if own:
        raise HTTPException(409, "Ya tienes una carga o un procesamiento pendiente. Continúa desde Tus trabajos.")
    if active >= BETA_MAX_ACTIVE:
        raise HTTPException(429, "La cola del piloto está llena. Intenta nuevamente cuando termine un trabajo.")


def admit_selection(c, job_id, day, planned_calls, daily_limit, max_runs, *, kind="selection"):
    """Reserve all provider calls under the existing admission transaction lock."""
    runs = c.execute(text("""
        SELECT count(*) FROM cloud_documents WHERE job_id=:j AND kind=:kind
        """), {"j": job_id, "kind": kind}).scalar_one()
    if runs >= max_runs:
        raise HTTPException(409, "Este trabajo alcanzó el máximo de análisis guardados.")
    reserved = c.execute(text("""
        SELECT COALESCE(sum(CAST(payload->>'provider_calls_planned' AS integer)),0)
             + COALESCE((SELECT planned FROM cloud_deleted_selection_calls WHERE day_utc=CAST(CAST(:day AS text) AS date)),0)
        FROM cloud_documents WHERE kind='selection' AND payload->>'day_utc'=:day
        """), {"day": day}).scalar_one()
    if reserved + planned_calls > daily_limit:
        raise HTTPException(429, "Se alcanzó el presupuesto diario de solicitudes por IA. Podés intentarlo otro día.")
    if kind == "publication_ai":
        # Keep D03 reservations in the shared aggregate at admission. D02's
        # unchanged quota query still counts them after restoring its runtime,
        # even if that runtime later scrubs the D03 project and run documents.
        c.execute(text("""
            INSERT INTO cloud_deleted_selection_calls(day_utc,planned) VALUES (CAST(CAST(:day AS text) AS date),:planned)
            ON CONFLICT (day_utc) DO UPDATE SET planned=cloud_deleted_selection_calls.planned+EXCLUDED.planned
            """), {"day": day, "planned": planned_calls})


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
        WHERE id=:i AND owner_id=:o AND workspace_id=:w AND deletion_started_at IS NULL FOR UPDATE
        """), {"i": job_id, "o": principal.id, "w": principal.workspace_id}).scalar()
    if owned is None:
        raise HTTPException(404, "Trabajo no encontrado")
    doc = document(job_id, connection=c)
    if doc["payload"].get("pilot") is not True:
        raise HTTPException(404, "Trabajo no encontrado")
    return doc


def _alignment_id(job_id, fingerprint):
    canonical = json.dumps({**fingerprint, "source_duration": float(fingerprint["source_duration"]), "job_id": job_id},
                           allow_nan=False, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()[:32]


def alignment_document(job_id, fingerprint, connection=None):
    return document(job_id, "alignment", _alignment_id(job_id, fingerprint), connection, required=False, live=True)


def prepare_alignment(job_id, principal, retry=False):
    from .editorial_selection import source_identity
    from .transcript_selection import SIDECAR

    with get_engine().begin() as connection:
        job = beta_document(connection, principal, job_id)
        fingerprint = source_identity(job)
        existing_words = job["payload"].get("transcript_alignment")
        if (SIDECAR in job["manifest"] and existing_words
                and existing_words.get("source_fingerprint") == fingerprint):
            return existing_words
        previous = alignment_document(job_id, fingerprint, connection)
        if previous:
            item = previous["payload"]
            if not retry or item["status"] in {"queued", "running", "completed"}:
                return item
            if not item.get("retryable") or previous["manifest"]:
                raise HTTPException(409, "Esta preparación ya no admite un reintento.")
            admit_beta(connection, principal.id)
            task = _failed_task(connection, job_id, "alignment", item["id"])
            _requeue_failed_task(connection, job_id, "alignment", item, task)
            return item
        if retry:
            raise HTTPException(409, "No hay una preparación anterior de esta versión para reintentar.")
        admit_beta(connection, principal.id)
        item = {"id": _alignment_id(job_id, fingerprint), "job_id": job_id, "pilot": True, "status": "queued",
                "source_fingerprint": fingerprint, "created_at": time.time(), "retryable": False}
        insert_document(connection, job_id, "alignment", item)
        enqueue(connection, job_id, "alignment", item["id"])
        return item


def _failed_task(c, job_id, kind, item_id):
    task = c.execute(text("""
        SELECT t.id,t.status,t.cleaned_at,t.fence,t.updated_at,o.attempts
        FROM cloud_tasks t LEFT JOIN cloud_outbox o ON o.task_id=t.id
        WHERE t.job_id=:j AND t.kind=:kind AND t.item_id=:item FOR UPDATE OF t
        """), {"j": job_id, "kind": kind, "item": item_id}).mappings().first()
    if task is None or task["status"] != "failed":
        raise HTTPException(409, "La tarea anterior aún se está conciliando.")
    if task["cleaned_at"] is None:
        raise HTTPException(409, "La limpieza del intento anterior sigue pendiente. El video original se conserva.")
    return task


def _requeue_failed_task(c, job_id, kind, item, task):
    item.setdefault("attempt_history", []).append({
        "error_code": item["error_code"] if kind == "alignment" else public_beta_error_code(item.get("error_code")),
        "fence": task["fence"],
        "finished_at": task["updated_at"].isoformat(), "dispatches": task["attempts"],
    })
    item.update(status="queued", retryable=False, retry_count=item.get("retry_count", 0) + 1)
    for key in ("error", "error_code", "dispatch_status"):
        item.pop(key, None)
    if kind == "alignment":
        item.pop("started_at", None)
        item.pop("completed_at", None)
    update_document(c, job_id, kind, item)
    c.execute(text("""
        UPDATE cloud_tasks SET status='queued',lease_until=NULL,cleaned_at=NULL,
            updated_at=clock_timestamp() WHERE id=:i AND status='failed'
        """), {"i": task["id"]})
    c.execute(text("""
        UPDATE cloud_outbox SET dispatched_at=NULL,attempts=0,last_error=NULL,operation_name=NULL
        WHERE task_id=:i
        """), {"i": task["id"]})


def retry_beta(c, job_id, item, *, expected_error=None):
    """Reuse the unique task on the original generation and issue a new fence."""
    task = _failed_task(c, job_id, "process", job_id)
    code = item.get("error_code")
    eligible = code == expected_error if expected_error is not None else code in BETA_RETRYABLE
    if not eligible or item.get("retry_count", 0) >= BETA_RETRIES:
        raise HTTPException(409, "Este trabajo no se puede reintentar. Puedes subir otro video.")
    item["clips"] = []
    for key in ("media", "language", "analysis_seconds", "speech_until_seconds"):
        item.pop(key, None)
    _requeue_failed_task(c, job_id, "job", item, task)


def manual_export_retryable(item):
    return (item["status"] == "failed" and item.get("retry_count", 0) < BETA_RETRIES
            and public_beta_error_code(item.get("error_code")) in BETA_RETRYABLE)


def retry_manual_export(c, job_id, document, owner):
    item = document["payload"]
    if document["manifest"] or not manual_export_retryable(item):
        raise HTTPException(409, "Este clip manual ya no admite un reintento.")
    if item.get("clip_captions") is True:
        admit_beta(c, owner, caption_job=job_id)
    else:
        admit_beta(c, owner)
    task = _failed_task(c, job_id, "export", item["id"])
    item["pilot"] = True
    _requeue_failed_task(c, job_id, "export", item, task)


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
    "LOGO_UNAVAILABLE": "El logo guardado no está disponible. Conservamos el original y las exportaciones anteriores.",
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


_ALIGNMENT_ERRORS = {
    "SOURCE_UNAVAILABLE": "No se pudo verificar el video original de esta transcripción.",
    "ALIGNMENT_INCOMPLETE": "Las marcas disponibles son insuficientes. Podés seguir seleccionando por frases.",
    "ALIGNMENT_SOURCE_CHANGED": "El original o la transcripción cambió durante la preparación.",
    "WORKER_INTERRUPTED": "La preparación se interrumpió. Podés volver a intentar.",
    "ALIGNMENT_TRANSPORT": "La transferencia de la preparación se interrumpió. Podés volver a intentar.",
    "ALIGNMENT_FAILED": "No se pudieron preparar las marcas. La transcripción guardada se conserva.",
}


def alignment_failure(item, code):
    item.update(status="failed", error_code=code, error=_ALIGNMENT_ERRORS[code], completed_at=time.time(),
                retryable=code in {"ALIGNMENT_TRANSPORT", "WORKER_INTERRUPTED"}
                and item.get("retry_count", 0) < BETA_RETRIES)
    item.pop("word_segments", None)


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
    kind = "job" if task["kind"] == "process" else task["kind"]
    if kind not in {"selection", "alignment", "publication_ai"}:
        public_beta_failure(payload)
    with get_engine().begin() as c:
        if kind == "alignment":
            # Deletion takes the project lock before fencing all of its tasks.
            project = c.execute(text("""
                SELECT id FROM auth_projects WHERE id=:j AND deletion_started_at IS NULL FOR UPDATE
                """), {"j": task["job_id"]}).scalar()
            if project is None:
                raise RuntimeError("Project no longer permits alignment publication")
        worker_guard(c, task)
        if kind == "alignment" and payload["status"] == "completed":
            from .editorial_selection import source_identity

            try:
                fingerprint = source_identity(document(task["job_id"], connection=c))
            except HTTPException:
                fingerprint = None
            if fingerprint != payload["source_fingerprint"]:
                alignment_failure(payload, "ALIGNMENT_SOURCE_CHANGED")
                manifest = {}
        update_document(c, task["job_id"], kind, payload, manifest=manifest)
        c.execute(text("UPDATE cloud_tasks SET status=:s,lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i AND fence=:f"),
                  {"s": "succeeded" if payload["status"] == "completed" else "failed", "i": task["id"], "f": task["fence"]})


def mark_crashed(task):
    with get_engine().begin() as c:
        worker_guard(c, task)
        kind = "job" if task["kind"] == "process" else task["kind"]
        doc = document(task["job_id"], kind, task["item_id"], c)
        item = doc["payload"]
        if kind == "selection":
            interrupt_selection(item)
        elif kind == "publication_ai":
            interrupt_publication(item)
        elif kind == "alignment":
            alignment_failure(item, "WORKER_INTERRUPTED")
        else:
            item.update(status="failed", error="Procesamiento interrumpido. El original se conserva; revisa el estado antes de reintentar.", error_code="WORKER_INTERRUPTED")
            public_beta_failure(item)
        update_document(c, task["job_id"], kind, item)
        c.execute(text("UPDATE cloud_tasks SET status='failed',lease_until=NULL,updated_at=clock_timestamp() WHERE id=:i AND fence=:f"), {"i": task["id"], "f": task["fence"]})


def interrupt_selection(item):
    item.update(status="failed", error_code="AI_TASK_INTERRUPTED", completed_at=time.time(),
                error="El análisis se interrumpió. Para intentarlo de nuevo, revisa y autoriza otra solicitud.")
    if "topic" in item.get("spec", {}):
        item["retryable"] = not item.get("retry_of") and not item.get("retry_consumed")


def interrupt_publication(item):
    item.update(status="failed", error_code="AI_TASK_INTERRUPTED", completed_at=time.time(),
                error="La generación se interrumpió. Podés editar o conservar tus textos guardados.")
