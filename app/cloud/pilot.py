"""Invitation-only upload and queue contract for the INT browser pilot."""
from hashlib import sha256
import re
import time
import uuid

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import text

from ..auth import settings as auth_settings
from ..auth_db import get_engine
from ..environment import identity
from ..presentation import Presentation
from . import repository as repo
from . import storage
from .config import (
    BETA_MAX_ACTIVE, BETA_MAX_BYTES, BETA_MAX_DIMENSION, BETA_MAX_SECONDS,
    BETA_MIN_SECONDS, BETA_UPLOAD_SECONDS,
)
from .router import _dispatch


router = APIRouter(prefix="/beta")


class Upload(BaseModel):
    model_config = ConfigDict(extra="forbid")
    filename: str = Field(min_length=5, max_length=255)
    bytes: int = Field(gt=0, strict=True)


@router.get("/limits")
def limits():
    return {"max_bytes": BETA_MAX_BYTES, "min_duration_seconds": BETA_MIN_SECONDS,
            "max_duration_seconds": BETA_MAX_SECONDS, "max_dimension": BETA_MAX_DIMENSION,
            "formats": ["MP4 (H.264 + AAC)"], "worker_concurrency": 1,
            "active_jobs_per_user": 1, "queue_capacity": BETA_MAX_ACTIVE,
            "selection_mode": "heuristic_voice"}


def _reserve(principal, key, filename, size):
    fingerprint = sha256(repo.packed({"kind": "beta_upload", "filename": filename, "bytes": size}).encode()).hexdigest()
    with repo.request_transaction(principal.id, key, fingerprint) as (connection, previous, key):
        if previous:
            if previous["kind"] != "beta_upload":
                raise HTTPException(409, "La clave identifica otro tipo de solicitud.")
            return repo.beta_document(connection, principal, previous["job_id"])["payload"]
        repo.check_active_workspace(connection, principal)
        repo.admit_beta(connection, principal.id)
        job_id = uuid.uuid4().hex
        now = time.time()
        connection.execute(text("""
            INSERT INTO auth_projects(id,workspace_id,owner_id,created_at)
            VALUES (:i,:w,:o,clock_timestamp())
            """), {"i": job_id, "w": principal.workspace_id, "o": principal.id})
        item = {
            "pilot": True, "id": job_id, "status": "awaiting_upload", "clips": [],
            "options": Presentation().model_dump(), "processing_mode": "auto",
            "selection_mode": "heuristic_voice", "version": identity()["revision"],
            "created_at": now, "upload_expires_at": now + BETA_UPLOAD_SECONDS,
            "source_filename": filename, "source_bytes": size, "retry_count": 0,
            "retryable": False,
        }
        repo.insert_document(connection, job_id, "job", item)
        repo.remember_request(connection, principal.id, key, fingerprint, job_id, "beta_upload", job_id)
        return item


def _original(principal, item):
    if item["upload_expires_at"] <= time.time():
        raise HTTPException(409, "La carga caducó. Crea un trabajo nuevo y vuelve a seleccionar el video.")
    return storage.beta_original(principal.workspace_id, item["id"])


@router.post("/uploads", status_code=201)
def create_upload(payload: Upload, request: Request):
    filename = payload.filename.strip()
    if (len(filename) < 5 or not filename.lower().endswith(".mp4") or "/" in filename or "\\" in filename
            or re.search(r"[\x00-\x1f\x7f]", filename)):
        raise HTTPException(422, "Selecciona un archivo MP4 con un nombre válido.")
    if payload.bytes > BETA_MAX_BYTES:
        raise HTTPException(413, "El video supera el máximo de 100 MiB del piloto.")
    key = request.headers.get("Idempotency-Key")
    if not key:
        raise HTTPException(428, "Se requiere Idempotency-Key para crear una carga.")
    principal = request.state.principal
    item = _reserve(principal, key, filename, payload.bytes)
    result = {"id": item["id"], "status": item["status"], "upload_url": None}
    if item["status"] != "awaiting_upload":
        return result
    name = _original(principal, item)
    try:
        # A replay can mint another session for an incomplete upload only.
        # Both sessions carry the same create-only generation precondition.
        if storage.beta_original_metadata(name) is None:
            result["upload_url"] = storage.start_resumable(name, item["source_bytes"], auth_settings().origin)
    except storage.InvalidUpload:
        # The object exists. The start transaction records the terminal error
        # without creating a task or granting a new upload capability.
        return result
    except storage.StorageError:
        raise HTTPException(503, "No se pudo abrir la carga privada. Reintenta con el mismo archivo.") from None
    return result


@router.post("/uploads/{job_id}/start", status_code=202)
def start_job(job_id: str, request: Request):
    principal = request.state.principal
    mismatch = False
    with get_engine().begin() as connection:
        document = repo.beta_document(connection, principal, job_id)
        item = document["payload"]
        if item["status"] == "awaiting_upload":
            name = _original(principal, item)
            try:
                original = storage.beta_original_metadata(name)
                if original is None:
                    raise HTTPException(409, "La carga del video todavía no ha terminado.")
                mismatch = original["bytes"] != item["source_bytes"] or original["bytes"] > BETA_MAX_BYTES
            except storage.InvalidUpload:
                mismatch = True
            except storage.StorageError:
                raise HTTPException(503, "No se pudo confirmar la carga privada. Intenta nuevamente.") from None
            if mismatch:
                item.update(status="failed", error_code="UPLOAD_MISMATCH")
                repo.public_beta_failure(item)
                repo.update_document(connection, job_id, "job", item)
            else:
                repo.admit_beta(connection, principal.id, current_job=job_id)
                _original(principal, item)  # Check expiry again after GCS and the admission lock.
                item["status"] = "queued"
                repo.update_document(connection, job_id, "job", item, manifest={"input.mp4": original})
                repo.enqueue(connection, job_id, "process", job_id)
    if mismatch:
        raise HTTPException(422, item["error"])
    return _dispatch(item) if item["status"] == "queued" else item


@router.post("/jobs/{job_id}/retry", status_code=202)
def retry_job(job_id: str, request: Request):
    principal = request.state.principal
    with get_engine().begin() as connection:
        document = repo.beta_document(connection, principal, job_id)
        item = document["payload"]
        if item["status"] == "failed":
            if not item.get("retryable") or "input.mp4" not in document["manifest"]:
                raise HTTPException(409, "Este trabajo no se puede reintentar. Puedes subir otro video.")
            repo.admit_beta(connection, principal.id)
            repo.retry_beta(connection, job_id, item)
        elif not item.get("retry_count"):
            raise HTTPException(409, "Reintentar sólo está disponible para fallos recuperables.")
    return _dispatch(item) if item["status"] == "queued" else item
