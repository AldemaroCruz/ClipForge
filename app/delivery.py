"""Local presentation templates, revisioned reviews, immutable ZIP deliveries.

No external service, no publishing, no writes to source media/transcripts/exports.
Single-process MVP only. Files selected for delivery must be approved rendered
variants. ZIP creation is bounded, streamed to disk, and has an explicit snapshot.
"""
import copy
import hashlib
import json
import os
import re
import shutil
import tempfile
import threading
import time
import uuid
import zipfile
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, ConfigDict, Field, field_validator

from .presentation import Presentation
from .state import write_json_atomic

router = APIRouter()
DELIVERY_LOCK = threading.Lock()
MAX_DELIVERY_BYTES = 2 * 1024 ** 3
ID_PATTERN = r"^[0-9a-f]{32}$"


def backend():
    from . import main
    return main


def clean_text(value: str) -> str:
    return re.sub(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]", "", value).strip()


class TemplateRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    options: Presentation

    @field_validator("name")
    @classmethod
    def name_is_not_blank(cls, value):
        value = " ".join(clean_text(value).split())
        if not value:
            raise ValueError("Escribe un nombre para la plantilla.")
        return value


def template_path(template_id: str) -> Path:
    if not re.fullmatch(ID_PATTERN, template_id):
        raise HTTPException(404, "Plantilla no encontrada")
    return backend().ROOT / "templates" / f"{template_id}.json"


def read_template(template_id: str) -> dict:
    path = template_path(template_id)
    try:
        with backend().LOCK:
            item = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(item, dict) or item.get("id") != template_id:
            raise ValueError("Invalid template")
        payload = TemplateRequest.model_validate({k: item[k] for k in ("name", "options")})
        return {**item, **payload.model_dump()}
    except FileNotFoundError as exc:
        raise HTTPException(404, "Plantilla no encontrada") from exc
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise HTTPException(503, "Plantilla ilegible. Se conserva el archivo; no se reemplaza con valores vacíos.") from exc


@router.get("/templates")
def list_templates(response: Response):
    response.headers["Cache-Control"] = "no-store"
    items, unreadable = [], 0
    for path in (backend().ROOT / "templates").glob("*.json"):
        if not re.fullmatch(ID_PATTERN, path.stem):
            continue
        try:
            items.append(read_template(path.stem))
        except HTTPException:
            unreadable += 1
    items.sort(key=lambda x: (x["name"].casefold(), x["id"]))
    return {"templates": items, "unreadable": unreadable}


@router.post("/templates", status_code=201)
def create_template(request: TemplateRequest):
    service = backend()
    with service.LOCK:
        files = list((service.ROOT / "templates").glob("*.json"))
        if len(files) >= 200:
            raise HTTPException(409, "Límite local de 200 plantillas alcanzado.")
        for path in files:
            try:
                previous = read_template(path.stem)
            except HTTPException:
                continue
            if previous["name"].casefold() == request.name.casefold():
                raise HTTPException(409, "Ese nombre ya existe. Usa otro nombre; las plantillas guardadas no se sobrescriben.")
        item = {"id": uuid.uuid4().hex, "created_at": time.time(),
                "version": service.VERSION, **request.model_dump()}
        try:
            write_json_atomic(template_path(item["id"]), item)
        except OSError as exc:
            raise HTTPException(503, "No se pudo guardar la plantilla. Revisa espacio y permisos.") from exc
    return copy.deepcopy(item)


@router.get("/templates/{template_id}")
def get_template(template_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return read_template(template_id)


class ReviewContent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    status: Literal["pending", "approved", "rejected"] = "pending"
    title: str = Field(default="", max_length=120)
    notes: str = Field(default="", max_length=2000)

    @field_validator("title", "notes")
    @classmethod
    def sanitize(cls, value):
        return clean_text(value)


class ReviewRequest(ReviewContent):
    revision: int = Field(ge=0, strict=True)


def read_review(job_id: str, export_id: str) -> dict:
    path = backend().export_path(job_id, export_id) / "review.json"
    try:
        with backend().LOCK:
            item = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(item, dict) or item.get("export_id") != export_id
                or item.get("job_id") != job_id or type(item.get("revision")) is not int
                or item["revision"] < 1):
            raise ValueError("Invalid review")
        content = ReviewContent.model_validate({k: item[k] for k in ReviewContent.model_fields})
        return {**item, **content.model_dump()}
    except FileNotFoundError:
        return {"job_id": job_id, "export_id": export_id, "status": "pending",
                "revision": 0, "title": "", "notes": "", "updated_at": None}
    except (ValueError, OSError, KeyError, TypeError) as exc:
        raise HTTPException(503, "Revisión ilegible. Se conserva el archivo; no se puede entregar esta variante.") from exc


@router.get("/jobs/{job_id}/exports/{export_id}/review")
def get_review(job_id: str, export_id: str, response: Response):
    backend().read_export(job_id, export_id)
    response.headers["Cache-Control"] = "no-store"
    return read_review(job_id, export_id)


@router.put("/jobs/{job_id}/exports/{export_id}/review")
def save_review(job_id: str, export_id: str, request: ReviewRequest):
    service = backend()
    with service.LOCK:
        item = service.read_export(job_id, export_id)
        if item["status"] != "completed":
            raise HTTPException(409, "Solo se revisan variantes renderizadas y completadas.")
        if request.status == "approved":
            for filename in ("clip.mp4", "clip.srt"):
                safe_export_file(job_id, export_id, filename)
        previous = read_review(job_id, export_id)
        if previous["revision"] != request.revision:
            raise HTTPException(409, "La revisión cambió en otra pestaña. Recarga las variantes antes de guardar.")
        review = {**request.model_dump(exclude={"revision"}), "job_id": job_id,
                  "export_id": export_id, "revision": previous["revision"] + 1,
                  "updated_at": time.time(), "version": service.VERSION}
        try:
            write_json_atomic(service.export_path(job_id, export_id) / "review.json", review)
        except OSError as exc:
            raise HTTPException(503, "No se pudo guardar la revisión; el estado anterior se conserva.") from exc
    return review


class DeliverySelection(BaseModel):
    model_config = ConfigDict(extra="forbid")
    export_id: str = Field(pattern=ID_PATTERN, min_length=32, max_length=32)
    review_revision: int = Field(ge=1, strict=True)


class DeliveryRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    selections: list[DeliverySelection] = Field(min_length=1, max_length=30)

    @field_validator("selections")
    @classmethod
    def unique(cls, values):
        if len({v.export_id for v in values}) != len(values):
            raise ValueError("No repitas una variante en la entrega.")
        return values


def safe_export_file(job_id: str, export_id: str, filename: str) -> Path:
    folder = backend().export_path(job_id, export_id)
    path = folder / filename
    # Never include arbitrary paths or symlinks in a customer delivery.
    if (filename not in {"clip.mp4", "clip.srt", "clip.vtt"}
            or folder.is_symlink() or path.is_symlink() or not path.is_file()
            or path.resolve().parent != folder.resolve()
            or not path.resolve().is_relative_to((backend().ROOT / job_id).resolve())
            or (filename == "clip.mp4" and path.stat().st_size == 0)):
        raise HTTPException(409, f"Archivo ausente o no seguro: {export_id[:8]}/{filename}. No se generó una entrega parcial.")
    return path


def checked_selection(job_id: str, selection: DeliverySelection) -> tuple[dict, dict, list[Path]]:
    service = backend()
    item = service.read_export(job_id, selection.export_id)
    review = read_review(job_id, selection.export_id)
    if item["status"] != "completed" or review["status"] != "approved":
        raise HTTPException(409, "Todas las variantes seleccionadas deben estar completadas y aprobadas.")
    if review["revision"] != selection.review_revision:
        raise HTTPException(409, "Cambió una revisión. Actualiza las variantes y selecciona de nuevo la entrega.")
    paths = [safe_export_file(job_id, selection.export_id, n) for n in ("clip.mp4", "clip.srt")]
    vtt = service.export_path(job_id, selection.export_id) / "clip.vtt"
    if vtt.exists() or vtt.is_symlink():
        paths.append(safe_export_file(job_id, selection.export_id, "clip.vtt"))
    return item, review, paths


def delivery_path(job_id: str, delivery_id: str) -> Path:
    backend().validate_job_id(job_id)
    if not re.fullmatch(ID_PATTERN, delivery_id):
        raise HTTPException(404, "Entrega no encontrada")
    return backend().ROOT / job_id / "deliveries" / delivery_id


def read_delivery(job_id: str, delivery_id: str) -> dict:
    try:
        item = json.loads((delivery_path(job_id, delivery_id) / "delivery.json").read_text(encoding="utf-8"))
        if not isinstance(item, dict) or item.get("id") != delivery_id or item.get("job_id") != job_id or not isinstance(item.get("clips"), list):
            raise ValueError("Invalid delivery")
        return item
    except FileNotFoundError as exc:
        raise HTTPException(404, "Entrega no encontrada") from exc
    except (ValueError, OSError, TypeError) as exc:
        raise HTTPException(503, "No se pudo leer la entrega; se conserva el archivo.") from exc


def _zip_add_file(archive: zipfile.ZipFile, path: Path, arcname: str) -> dict:
    """Stream bytes once; fingerprint the actual bytes in the ZIP, not another read."""
    digest = hashlib.sha256()
    size = 0
    with path.open("rb") as source, archive.open(arcname, "w", force_zip64=True) as target:
        while chunk := source.read(1024 * 1024):
            target.write(chunk)
            digest.update(chunk)
            size += len(chunk)
            if size > MAX_DELIVERY_BYTES:
                raise HTTPException(413, "El archivo creció por encima del límite de entrega.")
    return {"path": arcname, "bytes": size, "sha256": digest.hexdigest()}


@router.post("/jobs/{job_id}/deliveries", status_code=201)
def create_delivery(job_id: str, request: DeliveryRequest):
    service = backend()
    service.load_job(job_id)
    if not DELIVERY_LOCK.acquire(blocking=False):
        raise HTTPException(409, "Hay otra entrega en preparación. Reintenta cuando termine.")
    try:
        with service.LOCK:
            selected = [checked_selection(job_id, s) for s in request.selections]
        total = sum(p.stat().st_size for _, _, files in selected for p in files)
        if total > MAX_DELIVERY_BYTES:
            raise HTTPException(413, "La entrega supera 2 GiB. Selecciona menos variantes.")
        parent = service.ROOT / job_id / "deliveries"
        parent.mkdir(parents=True, exist_ok=True)
        if shutil.disk_usage(parent).free < total + 16 * 1024 ** 2:
            raise HTTPException(507, "No hay suficiente espacio para preparar el ZIP. Libera espacio y reintenta.")
        delivery_id = uuid.uuid4().hex
        manifest = {"id": delivery_id, "job_id": job_id, "created_at": time.time(),
                    "version": service.VERSION, "review_scope": "approval_snapshot_at_creation",
                    "clips": [], "download_url": f"/jobs/{job_id}/deliveries/{delivery_id}/file"}
        # Nothing is published until the archive is complete and all approvals are
        # rechecked. On errors the temporary directory is removed automatically.
        with tempfile.TemporaryDirectory(prefix=".delivery-", dir=parent) as temporary:
            staging = Path(temporary)
            notes = ["CLIPFORGE — ENTREGA REVISADA", "Títulos y notas editoriales; no hay publicaciones automáticas.", ""]
            with zipfile.ZipFile(staging / "delivery.zip", "w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
                for index, (item, review, paths) in enumerate(selected, 1):
                    prefix = f"{index:02}_{item['id'][:8]}"
                    title = review["title"] or item.get("title") or item["clip_file"]
                    entry = {"export_id": item["id"], "title": title, "notes": review["notes"],
                             "review_revision": review["revision"], "reviewed_at": review["updated_at"],
                             "start": item["start"], "end": item["end"], "options": item["options"], "files": []}
                    for path in paths:
                        stat = path.stat()
                        content = _zip_add_file(archive, path, f"{prefix}/{path.name}")
                        if content["bytes"] != stat.st_size or path.stat().st_mtime_ns != stat.st_mtime_ns:
                            raise HTTPException(409, "Un archivo cambió mientras se preparaba la entrega. Reintenta.")
                        entry["files"].append(content)
                    manifest["clips"].append(entry)
                    notes.extend([f"{index:02}. {title}", f"Carpeta: {prefix}", review["notes"], ""])
                archive.writestr("manifest.json", json.dumps(manifest, ensure_ascii=False, indent=2), compress_type=zipfile.ZIP_DEFLATED)
                archive.writestr("titulos-y-notas.txt", "\n".join(notes), compress_type=zipfile.ZIP_DEFLATED)
                archive.writestr("LEEME.txt", "Entrega local de ClipForge. Incluye solo las variantes aprobadas seleccionadas.\n"
                    "El SRT/VTT contiene texto y tiempos, no los estilos del MP4.\n"
                    "No se incluye el video original ni otros proyectos. Revisa derechos y contenido antes de publicar.\n"
                    "Esta entrega es una copia fija: cambiar una aprobación posteriormente NO revoca ni altera este ZIP.\n"
                    "manifest.json incluye SHA-256 de cada archivo de video/subtítulos.\n", compress_type=zipfile.ZIP_DEFLATED)
            manifest["zip_bytes"] = (staging / "delivery.zip").stat().st_size
            with service.LOCK:
                for selection in request.selections:
                    checked_selection(job_id, selection)
                write_json_atomic(staging / "delivery.json", manifest)
                os.replace(staging, delivery_path(job_id, delivery_id))
        return manifest
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, TypeError) as exc:
        service.LOGGER.exception("No se pudo preparar la entrega de %s", job_id)
        raise HTTPException(503, "No se pudo preparar el ZIP. Los clips se conservan; revisa espacio, permisos y logs.") from exc
    finally:
        DELIVERY_LOCK.release()


@router.get("/jobs/{job_id}/deliveries")
def list_deliveries(job_id: str, response: Response):
    backend().load_job(job_id)
    response.headers["Cache-Control"] = "no-store"
    paths = sorted((backend().ROOT / job_id / "deliveries").glob("*/delivery.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    result, unreadable = [], 0
    for path in paths[:100]:
        if not re.fullmatch(ID_PATTERN, path.parent.name):
            continue
        try:
            item = read_delivery(job_id, path.parent.name)
            result.append({k: item[k] for k in ("id", "job_id", "created_at", "download_url", "zip_bytes")}
                          | {"clips_count": len(item["clips"])})
        except (HTTPException, KeyError):
            unreadable += 1
    return {"deliveries": result, "has_more": len(paths) > 100, "unreadable": unreadable}


@router.get("/jobs/{job_id}/deliveries/{delivery_id}/file")
def get_delivery_file(job_id: str, delivery_id: str):
    backend().load_job(job_id)
    read_delivery(job_id, delivery_id)
    path = delivery_path(job_id, delivery_id) / "delivery.zip"
    if not path.is_file() or path.is_symlink() or path.parent.is_symlink():
        raise HTTPException(404, "ZIP no encontrado")
    return FileResponse(path, media_type="application/zip", filename=f"clipforge-{job_id[:8]}-{delivery_id[:8]}.zip",
                        headers={"Cache-Control": "no-store"})
