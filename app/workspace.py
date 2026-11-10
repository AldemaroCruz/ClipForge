"""Additive local project library, immutable export snapshots and editable drafts.

Original job.json, transcript.json and media are never rewritten by these routes.
JSON sidecars use the MVP's single-process lock and atomic persistence. This is
not a multi-worker database; keep Uvicorn at one process and localhost only.
"""
import copy
import json
import math
import os
import re
import subprocess
import tempfile
import threading
from threading import Thread
import time
import uuid
from pathlib import Path
from typing import Any

from fastapi import APIRouter, HTTPException, Query, Response
from fastapi.responses import FileResponse

from .editorial import (DraftUpdate, EditorialContent, ProjectName, RangeChange,
                        RevisionRequest, retime_cues, validate_range)
from .media import inspect_media, MediaValidationError
from .presentation import Presentation
from .state import write_json_atomic
from .subtitles import SubtitleError, cues_from_segments, validate_cues

router = APIRouter()
THUMB_LOCK = threading.Lock()


def backend():
    # Lazy import avoids a module cycle while letting tests isolate ROOT/locks.
    from . import main
    return main


def workspace_source(job_id: str) -> tuple[dict, Path, dict]:
    service = backend()
    job = service.load_job(job_id)
    if job["status"] in service.ACTIVE_STATUSES:
        raise HTTPException(409, "Espera a que termine el procesamiento antes de editar este proyecto.")
    source = service.ROOT / job_id / "input.mp4"
    if not source.is_file():
        raise HTTPException(409, "Falta input.mp4. Conserva o restaura el original para editar.")
    try:
        media = inspect_media(source, min_duration=0)
    except MediaValidationError as exc:
        raise HTTPException(409, str(exc)) from exc
    duration = media.get("duration_seconds")
    if not isinstance(duration, (int, float)) or not math.isfinite(duration) or duration <= 0:
        raise HTTPException(409, "No se pudo medir la duración del original; no es seguro recortarlo.")
    return job, source, media


def read_transcript(folder: Path) -> tuple[list[dict], str | None]:
    path = folder / "transcript.json"
    if not path.is_file():
        return [], "Sin transcripción guardada. Puedes crear el clip sin texto o escribir subtítulos manualmente."
    try:
        segments = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(segments, list):
            raise ValueError("Transcript is not a list")
        for s in segments:
            if (not isinstance(s, dict) or not isinstance(s.get("text"), str)
                    or not math.isfinite(float(s["start"])) or not math.isfinite(float(s["end"]))
                    or float(s["start"]) < 0 or float(s["end"]) < float(s["start"])):
                raise ValueError("Invalid transcript segment")
        return segments, None if segments else "La transcripción está vacía; no se inventarán subtítulos."
    except (ValueError, OSError, TypeError, KeyError, OverflowError):
        return [], "No se pudo leer la transcripción guardada. Se conserva el archivo; edita el texto manualmente."


@router.get("/jobs/{job_id}/workspace")
def get_workspace(job_id: str, response: Response):
    job, source, media = workspace_source(job_id)
    segments, warning = read_transcript(source.parent)
    response.headers["Cache-Control"] = "no-store"
    try:
        options = Presentation.model_validate(job.get("options", {})).model_dump()
    except ValueError:
        options = Presentation().model_dump()
    return {"job_id": job_id, "source_url": f"/jobs/{job_id}/source",
            "source_duration": media["duration_seconds"], "media": media,
            "options": options, "transcript_available": bool(segments),
            "warning": warning, "version": backend().VERSION}


@router.post("/jobs/{job_id}/editor/range")
def change_range(job_id: str, request: RangeChange):
    _, source, media = workspace_source(job_id)
    segments, warning = read_transcript(source.parent)
    try:
        start, end = validate_range(request.start, request.end, media["duration_seconds"])
        if request.previous_start is not None and request.previous_end is not None:
            validate_range(request.previous_start, request.previous_end, media["duration_seconds"])
        cues, stats = retime_cues([c.model_dump() for c in request.cues], request.previous_start,
                                 request.previous_end, start, end, segments)
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"start": start, "end": end, "duration": round(end - start, 3),
            "source_duration": media["duration_seconds"], "cues": cues,
            "changes": stats, "warning": warning,
            "timing_note": "Los subtítulos cortados conservan su texto completo: revisa las frases en los bordes. No hay tiempos por palabra."}


def draft_path(job_id: str, draft_id: str) -> Path:
    service = backend()
    service.validate_job_id(job_id)
    if not re.fullmatch(r"[0-9a-f]{32}", draft_id):
        raise HTTPException(404, "Borrador no encontrado")
    return service.ROOT / job_id / "drafts" / f"{draft_id}.json"


def read_draft(job_id: str, draft_id: str) -> dict:
    path = draft_path(job_id, draft_id)
    try:
        with backend().LOCK:
            item = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(item, dict) or item.get("id") != draft_id
                or item.get("job_id") != job_id or type(item.get("revision")) is not int
                or item["revision"] < 1
                or not all(type(item.get(k)) in (int, float) and math.isfinite(item[k]) and item[k] > 0 for k in ("created_at", "updated_at"))):
            raise ValueError("Invalid draft")
        # Validate stored data too, without rewriting it.
        payload = EditorialContent.model_validate({k: item[k] for k in EditorialContent.model_fields})
        start, end = float(payload.start), float(payload.end)
        validate_range(start, end, max(end, 1))
        validate_cues([c.model_dump() for c in payload.cues], round(end - start, 3))
        return item
    except FileNotFoundError as exc:
        raise HTTPException(404, "Borrador no encontrado") from exc
    except (ValueError, OSError, TypeError, KeyError) as exc:
        raise HTTPException(503, "No se pudo leer el borrador. El archivo se conserva; no se reemplazará con datos vacíos.") from exc


def validate_content(job_id: str, payload: EditorialContent) -> dict:
    _, _, media = workspace_source(job_id)
    if payload.clip_file:
        backend().clip_context(job_id, payload.clip_file)
    try:
        start, end = validate_range(payload.start, payload.end, media["duration_seconds"])
        cues = validate_cues([c.model_dump() for c in payload.cues], round(end - start, 3))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"title": payload.title, "clip_file": payload.clip_file, "start": start,
            "end": end, "options": payload.options.model_dump(), "cues": cues}


def draft_summary(item: dict) -> dict:
    return {k: item[k] for k in ("id", "job_id", "title", "clip_file", "start", "end",
                                "created_at", "updated_at", "revision", "options")}


@router.get("/jobs/{job_id}/drafts")
def list_drafts(job_id: str, response: Response, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    service = backend()
    service.load_job(job_id)
    response.headers["Cache-Control"] = "no-store"
    items, unreadable = [], 0
    for path in (service.ROOT / job_id / "drafts").glob("*.json"):
        if not re.fullmatch(r"[0-9a-f]{32}", path.stem):
            continue
        try:
            items.append(draft_summary(read_draft(job_id, path.stem)))
        except HTTPException:
            unreadable += 1
    items.sort(key=lambda item: (item["updated_at"], item["id"]), reverse=True)
    return {"drafts": items[offset:offset + limit], "total": len(items), "offset": offset,
            "limit": limit, "has_more": offset + limit < len(items), "unreadable": unreadable}


@router.post("/jobs/{job_id}/drafts", status_code=201)
def create_draft(job_id: str, request: EditorialContent):
    service = backend()
    content = validate_content(job_id, request)
    now, draft_id = time.time(), uuid.uuid4().hex
    item = {**content, "id": draft_id, "job_id": job_id, "revision": 1,
            "created_at": now, "updated_at": now, "version": service.VERSION}
    with service.LOCK:
        try:
            write_json_atomic(draft_path(job_id, draft_id), item)
        except OSError as exc:
            raise HTTPException(503, "No se pudo guardar el borrador en disco. Se conserva la versión anterior; revisa espacio y permisos.") from exc
    return copy.deepcopy(item)


@router.get("/jobs/{job_id}/drafts/{draft_id}")
def get_draft(job_id: str, draft_id: str, response: Response):
    backend().load_job(job_id)
    response.headers["Cache-Control"] = "no-store"
    return read_draft(job_id, draft_id)


@router.put("/jobs/{job_id}/drafts/{draft_id}")
def update_draft(job_id: str, draft_id: str, request: DraftUpdate):
    service = backend()
    content = validate_content(job_id, request)
    with service.LOCK:
        previous = read_draft(job_id, draft_id)
        if previous["revision"] != request.revision:
            raise HTTPException(409, "Este borrador cambió en otra pestaña. Guarda una copia o vuelve a abrir la versión guardada; tus cambios actuales no se han sobrescrito.")
        item = {**previous, **content, "revision": previous["revision"] + 1, "updated_at": time.time(), "version": service.VERSION}
        try:
            write_json_atomic(draft_path(job_id, draft_id), item)
        except OSError as exc:
            raise HTTPException(503, "No se pudo guardar el borrador en disco. Se conserva la versión anterior; revisa espacio y permisos.") from exc
    return copy.deepcopy(item)


@router.post("/jobs/{job_id}/drafts/{draft_id}/exports", status_code=202)
def export_draft(job_id: str, draft_id: str, request: RevisionRequest):
    service = backend()
    with service.LOCK:
        draft = read_draft(job_id, draft_id)
        if draft["revision"] != request.revision:
            raise HTTPException(409, "La versión guardada del borrador cambió. Vuelve a abrirla antes de exportar.")
        snapshot = copy.deepcopy(draft)
    # Validate the snapshot against the actual input, without holding IO lock.
    validate_content(job_id, EditorialContent.model_validate({k: snapshot[k] for k in EditorialContent.model_fields}))
    if snapshot["options"]["burn_subtitles"] and not snapshot["cues"]:
        raise HTTPException(422, "El borrador está guardado. Agrega subtítulos o desactiva «Incrustar subtítulos» antes de exportar.")
    export_id = uuid.uuid4().hex
    item = {"id": export_id, "job_id": job_id, "draft_id": draft_id,
            "draft_revision": snapshot["revision"], "title": snapshot["title"],
            "clip_file": snapshot["clip_file"] or f"manual_{draft_id[:8]}.mp4",
            "source_clip_file": snapshot["clip_file"], "status": "queued",
            "created_at": time.time(), "version": service.VERSION,
            "start": snapshot["start"], "end": snapshot["end"],
            "options": snapshot["options"], "cues": snapshot["cues"]}
    if "selection_origin" in snapshot:
        item["selection_origin"] = copy.deepcopy(snapshot["selection_origin"])
    service.persist_export(job_id, item)
    try:
        Thread(target=service.process_export, args=(job_id, export_id), daemon=True, name=f"export-{export_id}").start()
    except Exception as exc:
        item.update(status="failed", error="No se pudo iniciar la exportación. Tu borrador está guardado.")
        service.persist_export(job_id, item)
        raise HTTPException(503, item["error"]) from exc
    return copy.deepcopy(item)


def project_metadata(job_id: str) -> tuple[dict, bool]:
    path = backend().ROOT / job_id / "project.json"
    if not path.exists():
        return {}, False
    try:
        item = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(item, dict) or item.get("id") != job_id:
            raise ValueError("Invalid project")
        ProjectName(title=item["title"])
        return item, False
    except (ValueError, KeyError, OSError):
        return {}, True


def project_summary(folder: Path) -> dict:
    service = backend()
    job_id = folder.name
    metadata, bad_metadata = project_metadata(job_id)
    state_path = folder / "job.json"
    try:
        job = service.load_job(job_id)
    except HTTPException:
        job = {"id": job_id, "status": "unreadable", "clips": []}
    draft_files = list((folder / "drafts").glob("*.json"))
    export_files = list((folder / "exports").glob("*/export.json"))
    def mtime(path):
        try:
            return path.stat().st_mtime
        except OSError:
            return 0
    timestamp = job.get("created_at")
    reliable_date = type(timestamp) in (int, float) and math.isfinite(timestamp) and timestamp > 0
    created_at = timestamp if reliable_date else mtime(state_path)
    updated = max([created_at, mtime(state_path), mtime(folder / "project.json")]
                  + [mtime(p) for p in draft_files + export_files])
    media = job.get("media") if isinstance(job.get("media"), dict) else {}
    duration = media.get("duration_seconds")
    if type(duration) not in (int, float) or not math.isfinite(duration) or duration <= 0:
        duration = None
    filename = job.get("source_filename") if isinstance(job.get("source_filename"), str) else None
    return {"id": job_id, "title": metadata.get("title") or filename or f"Proyecto {job_id[:8]}",
            "source_filename": filename, "status": job["status"],
            "created_at": created_at, "date_kind": "uploaded" if reliable_date else "legacy_file",
            "updated_at": updated, "duration": duration,
            "clips_count": len(job["clips"]), "drafts_count": len(draft_files), "exports_count": len(export_files),
            "source_available": (folder / "input.mp4").is_file(),
            "thumbnail_url": f"/projects/{job_id}/thumbnail",
            "metadata_warning": bad_metadata}


@router.get("/projects")
def list_projects(response: Response, q: str = Query("", max_length=150),
                  offset: int = Query(0, ge=0), limit: int = Query(12, ge=1, le=50)):
    response.headers["Cache-Control"] = "no-store"
    items = [project_summary(p.parent) for p in backend().ROOT.glob("*/job.json")
             if re.fullmatch(r"[0-9a-f]{32}", p.parent.name)]
    query = q.strip().casefold()
    if query:
        items = [item for item in items if query in f"{item['title']} {item['id']} {item.get('source_filename') or ''}".casefold()]
    items.sort(key=lambda item: (item["updated_at"], item["id"]), reverse=True)
    return {"projects": items[offset:offset + limit], "total": len(items), "offset": offset,
            "limit": limit, "has_more": offset + limit < len(items),
            "unreadable": sum(item["status"] == "unreadable" or item["metadata_warning"] for item in items)}


@router.patch("/projects/{job_id}")
def rename_project(job_id: str, request: ProjectName):
    service = backend()
    service.load_job(job_id)
    with service.LOCK:
        _, corrupt = project_metadata(job_id)
        if corrupt:
            raise HTTPException(409, "project.json está dañado. Se conserva sin sobrescribir; revisa o respalda el archivo.")
        write_json_atomic(service.ROOT / job_id / "project.json", {"id": job_id, "title": request.title, "updated_at": time.time()})
    return project_summary(service.ROOT / job_id)


@router.get("/projects/{job_id}/thumbnail")
def project_thumbnail(job_id: str):
    service = backend()
    job = service.load_job(job_id)
    if job["status"] in service.ACTIVE_STATUSES:
        raise HTTPException(409, "Miniatura disponible al terminar el procesamiento")
    source = service.ROOT / job_id / "input.mp4"
    if not source.is_file():
        raise HTTPException(404, "Original no encontrado")
    directory = source.parent / "previews"
    target = directory / "source.jpg"
    with THUMB_LOCK:
        if not target.is_file():
            directory.mkdir(exist_ok=True)
            with tempfile.TemporaryDirectory(prefix=".thumb-", dir=directory) as temporary:
                output = Path(temporary) / "source.jpg"
                try:
                    result = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-y",
                        "-protocol_whitelist", "file,pipe", "-i", str(source), "-map", "0:v:0", "-frames:v", "1",
                        "-vf", "scale=320:-2", "-threads", "1", str(output)], capture_output=True, timeout=15)
                    if result.returncode or not output.is_file():
                        raise ValueError("No thumbnail")
                    os.replace(output, target)
                except (ValueError, OSError, subprocess.TimeoutExpired) as exc:
                    raise HTTPException(422, "No se pudo generar una miniatura; el video no se modificó.") from exc
    return FileResponse(target, media_type="image/jpeg", headers={"Cache-Control": "private, max-age=3600"})
