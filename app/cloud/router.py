"""Existing editor contracts backed by PG and private generation-pinned GCS."""
import copy
import hashlib
import json
import math
from pathlib import Path
import re
import tempfile
import time
import uuid
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, Depends, File, HTTPException, Query, Request, Response, UploadFile
from fastapi.responses import StreamingResponse
from pydantic import ValidationError
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from ..ai_selection import SelectionCreate, SelectionSpec
from ..auth_db import get_engine
from ..editorial import EditorialContent, DraftUpdate, ProjectName, RangeChange, RevisionRequest, retime_cues, validate_range
from ..logo_placement import LogoPlacement
from ..presentation import Presentation, ExportRequest
from ..subtitles import SubtitleError, cues_from_segments, to_srt, to_vtt, validate_cues
from . import caption_styles, clip_captions, clip_package, creator_logos, project_deletion
from . import editorial_selection as selection
from . import repository as repo
from .config import beta_enabled
from . import storage
from .dispatch import reconcile

router = APIRouter()
VERSION = "0.4.2"
SOURCE_PREVIEW_RANGE_BYTES = 8 * 1024 * 1024


class CloudDraftCreate(EditorialContent):
    style_template: caption_styles.StyleRevision | None = None
    logo: LogoPlacement | None = None


class CloudDraftUpdate(DraftUpdate):
    style_template: caption_styles.StyleRevision | None = None
    logo: LogoPlacement | None = None


def _int_product_route():
    if not beta_enabled():
        raise HTTPException(404, "Función no disponible")


def _doc(job_id, kind="job", item_id=None):
    if not re.fullmatch(r"[a-f0-9]{32}", job_id) or (item_id and not re.fullmatch(r"[a-f0-9]{32}", item_id)):
        raise HTTPException(404, "Documento no encontrado")
    return repo.document(job_id, kind, item_id, live=beta_enabled())


def _dispatch(item):
    try:
        result = reconcile()
    except Exception:
        result = {"status": "pending"}
    # Submission was committed before dispatch. A failure stays visible and can
    # be reconciled at startup or by the operator; no fabricated running state.
    return {**item, "dispatch_status": result["status"]}


def _create_upload(request, source, filename, options, processing_mode, digest, size):
    principal = request.state.principal
    fingerprint = hashlib.sha256(repo.packed({"sha256": digest, "bytes": size, "options": options, "processing_mode": processing_mode}).encode()).hexdigest()
    with repo.request_transaction(principal.id, request.headers.get("Idempotency-Key"), fingerprint) as (c, previous, key):
        active = c.execute(text("SELECT u.id FROM auth_users u JOIN auth_workspaces w ON w.owner_id=u.id WHERE u.id=:o AND u.is_active=true AND w.id=:w FOR SHARE OF u,w"), {"o": principal.id, "w": principal.workspace_id}).scalar()
        if not active:
            raise HTTPException(401, "Inicia sesión para continuar")
        if previous:
            if previous["kind"] != "job":
                raise HTTPException(409, "La clave identifica otro tipo de solicitud")
            item = repo.document(previous["job_id"], connection=c)["payload"]
        else:
            job_id = uuid.uuid4().hex
            # Names contain server-owned opaque identities only, never filenames.
            name = f"workspaces/{principal.workspace_id}/jobs/{job_id}/original/{uuid.uuid4().hex}.mp4"
            original = storage.upload(name, source, "video/mp4")
            c.execute(text("INSERT INTO auth_projects(id,workspace_id,owner_id,created_at) VALUES (:i,:w,:o,clock_timestamp())"), {"i": job_id, "w": principal.workspace_id, "o": principal.id})
            item = {"id": job_id, "status": "queued", "clips": [], "options": options, "version": VERSION,
                    "created_at": time.time(), "source_filename": filename, "processing_mode": processing_mode,
                    "request_id": key}
            repo.insert_document(c, job_id, "job", item, {"input.mp4": original})
            repo.enqueue(c, job_id, "process", job_id)
            repo.remember_request(c, principal.id, key, fingerprint, job_id, "job", job_id)
    return _dispatch(item)


@router.post("/jobs", status_code=202)
async def create_job(request: Request, file: UploadFile = File(...)):
    fields = await request.form()
    allowed = set(Presentation.model_fields) | {"file", "processing_mode"}
    if set(fields) - allowed or set(request.query_params):
        await file.close()
        raise HTTPException(422, "Campos de upload no admitidos; la propiedad la asigna el servidor")
    try:
        option_values = {k: fields[k] for k in Presentation.model_fields if k in fields}
        # Multipart is textual; preserve the strict integer JSON contract after
        # the same explicit conversion performed by the legacy Form arguments.
        for name in ("subtitle_font_size", "subtitle_margin_v", "subtitle_outline", "subtitle_shadow"):
            if name in option_values:
                value = option_values[name]
                if not isinstance(value, str) or not re.fullmatch(r"[0-9]{1,4}", value):
                    raise HTTPException(422, "Ajustes de presentación inválidos")
                option_values[name] = int(value)
        options = Presentation.model_validate(option_values).model_dump()
        mode = fields.get("processing_mode", "auto")
        if mode not in {"auto", "manual"}:
            raise HTTPException(422, "Modo inválido: auto o manual")
        if not file.filename or not file.filename.lower().endswith(".mp4"):
            raise HTTPException(400, "Solo MP4")
        filename = re.sub(r"[\x00-\x1f\x7f]", "", file.filename.replace("\\", "/").rsplit("/", 1)[-1])[:255]
        import os
        maximum = int(os.getenv("MAX_UPLOAD_MB", "300")) * 1024 * 1024
        digest, size = hashlib.sha256(), 0
        # Only an upload staging buffer: persistence is GCS + the DB transaction.
        with tempfile.TemporaryFile(mode="w+b") as source:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > maximum:
                    raise HTTPException(413, "Archivo demasiado grande")
                digest.update(chunk)
                source.write(chunk)
            if size == 0:
                raise HTTPException(400, "El archivo está vacío")
            source.seek(0)
            return await run_in_threadpool(_create_upload, request, source, filename, options, mode, digest.hexdigest(), size)
    except ValidationError:
        raise HTTPException(422, "Ajustes de presentación inválidos") from None
    except storage.StorageError:
        raise HTTPException(503, "El original no pudo guardarse; no se inició procesamiento") from None
    finally:
        await file.close()


@router.get("/jobs/{job_id}")
def get_job(job_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    doc = _doc(job_id)
    item = doc["payload"]
    if item.get("pilot") is True and _needs_dispatch(job_id, "process", [item]):
        if item["status"] != "queued":
            item = {**item, "lease_expired": True}
        return _dispatch(item)
    if item.get("pilot") is True and item["status"] == "completed":
        item = clip_captions.enrich_job(doc)
        captions = [clip["captions"] for clip in item["clips"] if "captions" in clip]
        if _needs_dispatch(job_id, "export", captions):
            return _dispatch(item)
    return item


@router.get("/jobs/{project_id}/deletion", dependencies=[Depends(_int_product_route)])
def deletion_status(project_id: str, request: Request):
    return project_deletion.status(request.state.principal, project_id)


@router.post("/jobs/{project_id}/deletion", status_code=202, dependencies=[Depends(_int_product_route)])
def delete_project(project_id: str, request: Request, background: BackgroundTasks):
    item, created = project_deletion.begin(request.state.principal, project_id, include_created=True)
    if created:
        background.add_task(reconcile_project_cleanups)
    return item


def reconcile_project_cleanups():
    try:
        return reconcile(cleanup_only=True)
    except Exception:
        return {"status": "pending", "dispatched": 0}


def _needs_dispatch(job_id, kind, items):
    if any(item["status"] == "queued" for item in items):
        return True
    if not any(item["status"] in {"validating", "transcribing", "rendering", "running"} for item in items):
        return False
    with get_engine().connect() as connection:
        return connection.execute(text("""
            SELECT EXISTS(SELECT 1 FROM cloud_tasks
                          WHERE job_id=:job AND kind=:kind AND status='running'
                            AND (lease_until IS NULL OR lease_until<=clock_timestamp()))
            """), {"job": job_id, "kind": kind}).scalar_one()


def _source_preview_range(item, range_header):
    size = item.get("bytes")
    if type(size) is not int or size <= SOURCE_PREVIEW_RANGE_BYTES:
        return range_header
    opened = re.fullmatch(r"bytes=([0-9]{1,19})-", range_header or "")
    if not opened:
        return range_header
    start = int(opened.group(1))
    if start >= size:
        return range_header
    end = min(start + SOURCE_PREVIEW_RANGE_BYTES - 1, size - 1)
    return f"bytes={start}-{end}"


def _stream(item, request, filename, inline=False, *, chunk_large=False):
    range_header = request.headers.get("Range")
    if chunk_large and beta_enabled():
        # Browsers can request the next window when playback needs more bytes.
        range_header = _source_preview_range(item, range_header)
    try:
        upstream = storage.open_object(item, range_header)
    except storage.StorageError:
        raise HTTPException(503, "El objeto privado no está disponible") from None
    def chunks():
        try:
            yield from upstream.iter_content(1024 * 1024)
        finally:
            storage.close(upstream)
    headers = {"Cache-Control": "private, no-store", "Accept-Ranges": "bytes",
               "Content-Disposition": f'{"inline" if inline else "attachment"}; filename="{filename}"'}
    content_range = upstream.headers.get("Content-Range")
    if content_range is not None:
        headers["Content-Range"] = content_range
    length = upstream.headers.get("Content-Length")
    # Large responses must remain chunked across both Cloud Run hops.
    if length is not None and (not chunk_large or (length.isdecimal() and int(length) <= 30 * 1024 * 1024)):
        headers["Content-Length"] = length
    return StreamingResponse(chunks(), status_code=upstream.status_code, media_type=item["content_type"], headers=headers)


@router.get("/jobs/{job_id}/source")
def source(job_id: str, request: Request):
    item = _doc(job_id)["manifest"].get("input.mp4")
    if not item:
        raise HTTPException(404, "Original no disponible")
    return _stream(item, request, "input.mp4", True, chunk_large=True)


def _clip(job_id, filename):
    if not re.fullmatch(r"clip_\d{2}\.mp4", filename):
        raise HTTPException(404, "Clip no encontrado")
    doc = _doc(job_id)
    clip = next((c for c in doc["payload"]["clips"] if c.get("file") == filename), None)
    if clip is None or filename not in doc["manifest"]:
        raise HTTPException(404, "Clip no disponible todavía")
    return doc, clip


@router.get("/jobs/{job_id}/clips/{filename}")
def clip(job_id: str, filename: str, request: Request, inline: bool = False):
    doc, _ = _clip(job_id, filename)
    return _stream(doc["manifest"][filename], request, filename, inline)


@router.get("/jobs/{job_id}/clips/{filename}/editor")
def editor(job_id: str, filename: str):
    doc, item = _clip(job_id, filename)
    duration = round(float(item["end"]) - float(item["start"]), 3)
    return {"job_id": job_id, "clip_file": filename, "start": item["start"], "end": item["end"],
            "duration": duration, "cues": validate_cues(item["cues"], duration),
            "options": Presentation.model_validate(item.get("options", doc["payload"]["options"])).model_dump(),
            "source_url": f"/jobs/{job_id}/source", "version": VERSION}


@router.get("/jobs/{job_id}/clips/{filename}/subtitles/{kind}")
def subtitles(job_id: str, filename: str, kind: str, request: Request):
    if kind not in {"srt", "vtt"}:
        raise HTTPException(404, "Formato no disponible")
    if beta_enabled():
        doc, _ = _clip(job_id, filename)
        name = f"{Path(filename).stem}.{kind}"
        if name not in doc["manifest"]:
            raise HTTPException(404, "Archivo no encontrado")
        return _stream(doc["manifest"][name], request, name)
    context = editor(job_id, filename)
    return Response(to_srt(context["cues"]) if kind == "srt" else to_vtt(context["cues"]),
                    media_type="application/x-subrip" if kind == "srt" else "text/vtt",
                    headers={"Content-Disposition": f'attachment; filename="{Path(filename).stem}.{kind}"', "Cache-Control": "no-store"})


@router.get("/jobs/{job_id}/clips/{filename}/captions", dependencies=[Depends(_int_product_route)])
def clip_caption_context(job_id: str, filename: str):
    return clip_captions.clip_context(_doc(job_id), filename)


@router.get("/jobs/{job_id}/clips.zip", dependencies=[Depends(_int_product_route)])
def download_clip_package(
    job_id: str, request: Request,
    selection: list[str] = Query(min_length=1, max_length=clip_package.MAX_CLIPS),
    inspect: Literal["1"] | None = None,
):
    if set(request.query_params) - {"selection", "inspect"} or len(request.query_params.getlist("inspect")) > 1:
        raise HTTPException(422, "La selección de clips no es válida.")
    package = clip_package.prepare(job_id, selection, request.state.principal)
    if inspect is not None:
        return package.summary()
    return StreamingResponse(clip_package.chunks(package), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="clipforge-{job_id[:8]}-clips.zip"',
        "Cache-Control": "no-store",
    })


@router.put("/jobs/{job_id}/clips/{filename}/captions", status_code=202, dependencies=[Depends(_int_product_route)])
def save_clip_captions(job_id: str, filename: str, payload: clip_captions.ClipCaptionUpdate, request: Request):
    item = clip_captions.save_clip(job_id, filename, payload, request.state.principal)
    return _dispatch(item) if payload.render and item["status"] == "queued" else item


@router.post("/jobs/{job_id}/clips/{filename}/captions/retry", status_code=202, dependencies=[Depends(_int_product_route)])
def retry_clip_captions(job_id: str, filename: str, request: Request):
    item = clip_captions.retry_clip(job_id, filename, request.state.principal)
    return _dispatch(item) if item["status"] == "queued" else item


@router.put("/jobs/{job_id}/captions", status_code=202, dependencies=[Depends(_int_product_route)])
def save_project_captions(job_id: str, payload: clip_captions.ProjectCaptionUpdate, request: Request):
    item = clip_captions.save_project(job_id, payload, request.state.principal)
    return _dispatch(item) if payload.render else item


def _workspace(job_id):
    doc = _doc(job_id)
    job = doc["payload"]
    if job["status"] not in {"completed", "failed"}:
        raise HTTPException(409, "Espera a que termine el procesamiento")
    if "input.mp4" not in doc["manifest"]:
        raise HTTPException(409, "Original no disponible")
    media = job.get("media", {})
    duration = media.get("duration_seconds")
    if type(duration) not in {int, float} or not math.isfinite(duration) or duration <= 0:
        raise HTTPException(409, "La duración del original no fue validada")
    return doc, duration


def _transcript(doc):
    item = doc["manifest"].get("transcript.json")
    if not item:
        return []
    if item["bytes"] > 32 * 1024 * 1024:
        raise HTTPException(409, "Transcripción fuera del límite")
    response = storage.open_object(item)
    try:
        data = response.content
        if len(data) != item["bytes"] or hashlib.sha256(data).hexdigest() != item["sha256"]:
            raise HTTPException(503, "La transcripción no pasó su verificación")
        return json.loads(data)
    finally:
        storage.close(response)


@router.get("/jobs/{job_id}/workspace")
def workspace(job_id: str):
    doc, duration = _workspace(job_id)
    return {"job_id": job_id, "source_url": f"/jobs/{job_id}/source", "source_duration": duration,
            "media": doc["payload"]["media"], "options": doc["payload"]["options"],
            "transcript_available": "transcript.json" in doc["manifest"],
            "warning": None if "transcript.json" in doc["manifest"] else "Sin transcripción: escribe los subtítulos manualmente.", "version": VERSION}


@router.post("/jobs/{job_id}/editor/range")
def change_range(job_id: str, request: RangeChange):
    doc, duration = _workspace(job_id)
    try:
        start, end = validate_range(request.start, request.end, duration)
        if request.previous_start is not None and request.previous_end is not None:
            validate_range(request.previous_start, request.previous_end, duration)
        cues, stats = retime_cues([c.model_dump() for c in request.cues], request.previous_start, request.previous_end, start, end, _transcript(doc))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"start": start, "end": end, "duration": round(end-start, 3), "source_duration": duration,
            "cues": cues, "changes": stats, "warning": None,
            "timing_note": "Los subtítulos usan tiempos por segmento; revisa los bordes."}


@router.get("/jobs/{job_id}/selections/context")
def selection_context(job_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return selection.context(_doc(job_id))


@router.post("/jobs/{job_id}/selections/preview")
def selection_preview(job_id: str, payload: SelectionSpec, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return selection.preview(_doc(job_id), payload)


@router.post("/jobs/{job_id}/selections", status_code=202)
def create_selection(job_id: str, payload: SelectionCreate, request: Request):
    item = selection.create(job_id, payload, request.state.principal)
    return _dispatch(item) if item["status"] == "queued" else item


@router.get("/jobs/{job_id}/selections")
def selections(job_id: str, response: Response, offset: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=50)):
    response.headers["Cache-Control"] = "no-store"
    _doc(job_id)
    items = [entry["payload"] for entry in repo.list_documents(job_id, "selection")]
    items.sort(key=lambda item: (item["created_at"], item["id"]), reverse=True)
    if _needs_dispatch(job_id, "selection", items):
        _dispatch({})
    return {"analyses": items[offset:offset+limit], "total": len(items), "has_more": len(items) > offset+limit,
            "unreadable": 0}


@router.get("/jobs/{job_id}/selections/{run_id}")
def get_selection(job_id: str, run_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    item = _doc(job_id, "selection", run_id)["payload"]
    if _needs_dispatch(job_id, "selection", [item]):
        return _dispatch(item)
    return item


@router.post("/jobs/{job_id}/selections/{run_id}/candidates/{candidate_id}/draft", status_code=201)
def candidate_to_draft(job_id: str, run_id: str, candidate_id: int, request: Request):
    item = _doc(job_id, "selection", run_id)["payload"]
    if item["status"] != "completed":
        raise HTTPException(409, "El análisis aún no está completado.")
    candidate = next((entry for entry in item["candidates"] if entry["id"] == str(candidate_id)), None)
    if candidate is None:
        raise HTTPException(404, "Propuesta no encontrada")
    draft_id = uuid.uuid5(uuid.NAMESPACE_URL, f"clipforge:{job_id}:{run_id}:{candidate_id}").hex
    principal = request.state.principal
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        previous = repo.document(job_id, "draft", draft_id, connection, required=False)
        if previous is not None:
            return previous["payload"]
    identity = selection.source_identity(job)
    if identity != item["source_fingerprint"]:
        raise HTTPException(409, "El original o la transcripción cambió. Generá una nueva selección.")
    segments = selection.transcript_segments(job, identity)
    indexed = {segment["id"]: segment for segment in segments}
    try:
        start = indexed[candidate["start_segment"]]["start"]
        end = indexed[candidate["end_segment"]]["end"]
        if start != candidate["start"] or end != candidate["end"] or not 20 <= round(end - start, 3) <= 60:
            raise ValueError("Candidate limits")
        cues = cues_from_segments(segments, start, end)
        options = clip_captions.project_presentation(job["payload"])
        if not cues:
            options = options.model_copy(update={"burn_subtitles": False})
        draft_content = EditorialContent(title=candidate["title"], start=start, end=end, cues=cues, options=options)
    except (ValueError, KeyError, TypeError):
        raise HTTPException(409, "La propuesta guardada no tiene límites o subtítulos válidos.") from None
    now = time.time()
    draft = {**draft_content.model_dump(), "id": draft_id, "job_id": job_id, "revision": 1,
             "created_at": now, "updated_at": now, "version": VERSION,
             "selection_origin": {"analysis_id": run_id, "candidate_id": str(candidate_id), "mode": "llm",
                                  "range_id": candidate["range_id"], "transcript_sha256": identity["transcript_sha256"],
                                  "provider": item["provider"], "model": item["model"]}}
    if job["payload"].get("caption_style_template"):
        draft["style_template"] = job["payload"]["caption_style_template"]
    if job["payload"].get("caption_logo"):
        draft["logo"] = job["payload"]["caption_logo"]
    with get_engine().begin() as connection:
        current = repo.beta_document(connection, principal, job_id)
        previous = repo.document(job_id, "draft", draft_id, connection, required=False)
        if previous is not None:
            return previous["payload"]
        if selection.source_identity(current) != identity:
            raise HTTPException(409, "Cambió la transcripción. Generá una nueva selección.")
        repo.insert_document(connection, job_id, "draft", draft)
    return draft


def _content(job_id, request):
    _, duration = _workspace(job_id)
    if request.clip_file:
        _clip(job_id, request.clip_file)
    try:
        start, end = validate_range(request.start, request.end, duration)
        cues = validate_cues([c.model_dump() for c in request.cues], round(end-start, 3))
    except (ValueError, TypeError) as exc:
        raise HTTPException(422, str(exc)) from exc
    return {"title": request.title, "clip_file": request.clip_file, "start": start, "end": end,
            "options": request.options.model_dump(), "cues": cues}


@router.get("/jobs/{job_id}/drafts")
def drafts(job_id: str, offset: int = Query(0, ge=0), limit: int = Query(20, ge=1, le=100)):
    _doc(job_id)
    items = [d["payload"] for d in repo.list_documents(job_id, "draft")]
    return {"drafts": items[offset:offset+limit], "total": len(items), "offset": offset,
            "limit": limit, "has_more": offset+limit < len(items), "unreadable": 0}


@router.post("/jobs/{job_id}/drafts", status_code=201)
def create_draft(job_id: str, payload: CloudDraftCreate, request: Request):
    now = time.time()
    content = _content(job_id, payload)
    if not beta_enabled() and (payload.style_template is not None or "logo" in payload.model_fields_set):
        raise HTTPException(404, "Función no disponible")
    item = {**content, "id": uuid.uuid4().hex, "job_id": job_id,
            "revision": 1, "created_at": now, "updated_at": now, "version": VERSION}
    owner = request.state.principal.id
    intent = payload.model_dump(include={"logo", "style_template"}, exclude_unset=True)
    fingerprint = hashlib.sha256(repo.packed({"job_id": job_id, "kind": "draft",
                                             "content": content, **intent}).encode()).hexdigest()
    with repo.request_transaction(owner, request.headers.get("Idempotency-Key"), fingerprint) as (c, previous, key):
        job = None
        if beta_enabled():
            job = repo.beta_document(c, request.state.principal, job_id)["payload"]
        if previous:
            if previous["kind"] != "draft" or previous["job_id"] != job_id:
                raise HTTPException(409, "La clave identifica otra solicitud")
            item = repo.document(job_id, "draft", previous["item_id"], c)["payload"]
        else:
            if job:
                default = clip_captions.project_presentation(job).model_dump()
                options, template, logo = caption_styles.resolve(
                    c, request.state.principal, payload, content["options"], default,
                    job.get("caption_style_template"), job.get("caption_logo"),
                )
                item["options"] = options
                if template:
                    item["style_template"] = template
                if logo is not None:
                    item["logo"] = logo
            repo.insert_document(c, job_id, "draft", item)
            repo.remember_request(c, owner, key, fingerprint, job_id, "draft", item["id"])
    return item


@router.get("/jobs/{job_id}/drafts/{draft_id}")
def draft(job_id: str, draft_id: str):
    return _doc(job_id, "draft", draft_id)["payload"]


@router.put("/jobs/{job_id}/drafts/{draft_id}")
def update_draft(job_id: str, draft_id: str, payload: CloudDraftUpdate, request: Request):
    content = _content(job_id, payload)
    is_beta = beta_enabled()
    if not is_beta and (payload.style_template is not None or "logo" in payload.model_fields_set):
        raise HTTPException(404, "Función no disponible")
    principal = request.state.principal
    with get_engine().begin() as c:
        if is_beta:
            repo.beta_document(c, principal, job_id)
        previous = repo.document(job_id, "draft", draft_id, c)
        if previous["revision"] != payload.revision:
            raise HTTPException(409, "El borrador cambió en otra pestaña")
        current = previous["payload"]
        item = {**current, **content, "revision": payload.revision+1, "updated_at": time.time()}
        if is_beta:
            options, template, logo = caption_styles.resolve(
                c, principal, payload, content["options"], current["options"],
                current.get("style_template"), current.get("logo"),
            )
            item["options"] = options
            if template:
                item["style_template"] = template
            else:
                item.pop("style_template", None)
            if logo is not None:
                item["logo"] = logo
            else:
                item.pop("logo", None)
        repo.update_document(c, job_id, "draft", item, payload.revision)
    return item


def _submit_export(job_id, item, request, *, pilot=False, request_key=None):
    owner = request.state.principal.id
    fingerprint = hashlib.sha256(repo.packed({k: v for k, v in item.items() if k not in {"id", "created_at"}}).encode()).hexdigest()
    idempotency_key = request_key or request.headers.get("Idempotency-Key")
    with repo.request_transaction(owner, idempotency_key, fingerprint) as (c, previous, key):
        if pilot:
            repo.beta_document(c, request.state.principal, job_id)
        if previous:
            if previous["kind"] != "export" or previous["job_id"] != job_id:
                raise HTTPException(409, "La clave identifica otra solicitud")
            item = repo.document(job_id, "export", previous["item_id"], c)["payload"]
        else:
            if pilot:
                repo.admit_beta(c, owner)
                item["pilot"] = True
            item["request_id"] = key
            repo.insert_document(c, job_id, "export", item)
            repo.enqueue(c, job_id, "export", item["id"])
            repo.remember_request(c, owner, key, fingerprint, job_id, "export", item["id"])
    return _dispatch(item)


@router.post("/jobs/{job_id}/editor/exports", status_code=202)
def export_manual_range(job_id: str, payload: RangeChange, request: Request):
    doc, source_duration = _workspace(job_id)
    if doc["payload"].get("pilot") is not True:
        raise HTTPException(404, "Trabajo del piloto no encontrado")
    if payload.previous_start is not None or payload.previous_end is not None or payload.cues:
        raise HTTPException(422, "Indica solamente el inicio y el fin del fragmento.")
    try:
        start, end = validate_range(payload.start, payload.end, source_duration)
        cues, _ = retime_cues([], None, None, start, end, _transcript(doc))
    except (SubtitleError, TypeError, ValueError) as exc:
        raise HTTPException(422, str(exc)) from exc
    item = {"id": uuid.uuid4().hex, "job_id": job_id, "title": "Fragmento manual",
            "clip_file": "manual.mp4", "status": "queued", "created_at": time.time(),
            "version": VERSION, "start": start, "end": end,
            "options": Presentation().model_dump(), "cues": cues}
    return _submit_export(job_id, item, request, pilot=True)


@router.post("/jobs/{job_id}/exports/{export_id}/retry", status_code=202)
def retry_manual_export(job_id: str, export_id: str, request: Request):
    if not re.fullmatch(r"[a-f0-9]{32}", export_id):
        raise HTTPException(404, "Variante no encontrada")
    principal = request.state.principal
    with get_engine().begin() as connection:
        # Serialize owner mutations with existing upload and processing retries.
        job = repo.beta_document(connection, principal, job_id)
        document = repo.document(job_id, "export", export_id, connection)
        item = document["payload"]
        if item.get("id") != export_id or not clip_package.is_pilot_manual_export(item):
            raise HTTPException(404, "Variante no encontrada")
        if item["status"] == "failed":
            if "input.mp4" not in job["manifest"]:
                raise HTTPException(409, "Original no disponible")
            repo.retry_manual_export(connection, job_id, document, principal.id)
        elif not item.get("retry_count"):
            raise HTTPException(409, "El reintento sólo está disponible para clips manuales fallidos.")
    return _dispatch(item) if item["status"] == "queued" else item


@router.post("/jobs/{job_id}/drafts/{draft_id}/exports", status_code=202)
def export_draft(job_id: str, draft_id: str, payload: RevisionRequest, request: Request):
    doc = _doc(job_id, "draft", draft_id)
    if doc["revision"] != payload.revision:
        raise HTTPException(409, "La versión del borrador cambió")
    snapshot = doc["payload"]
    _content(job_id, EditorialContent.model_validate({k: snapshot[k] for k in EditorialContent.model_fields}))
    if snapshot["options"]["burn_subtitles"] and not snapshot["cues"]:
        raise HTTPException(422, "Agrega subtítulos o desactiva incrustarlos")
    item = {"id": uuid.uuid4().hex, "job_id": job_id, "draft_id": draft_id, "draft_revision": payload.revision,
            "title": snapshot["title"], "clip_file": snapshot["clip_file"] or f"manual_{draft_id[:8]}.mp4",
            "source_clip_file": snapshot["clip_file"], "status": "queued", "created_at": time.time(), "version": VERSION,
            "start": snapshot["start"], "end": snapshot["end"], "options": snapshot["options"], "cues": snapshot["cues"]}
    if snapshot.get("style_template"):
        item["style_template"] = snapshot["style_template"]
    if snapshot.get("logo"):
        item["logo"] = snapshot["logo"]
    pilot = _doc(job_id)["payload"].get("pilot") is True
    key = f"draft-{draft_id}-{payload.revision}" if pilot else None
    return _submit_export(job_id, item, request, pilot=pilot, request_key=key)


@router.post("/jobs/{job_id}/clips/{filename}/exports", status_code=202)
def create_export(job_id: str, filename: str, payload: ExportRequest, request: Request):
    context = editor(job_id, filename)
    try:
        cues = validate_cues([cue.model_dump() for cue in payload.cues], context["duration"])
        if payload.options.burn_subtitles and not cues:
            raise SubtitleError("Agrega subtítulos o desactiva incrustarlos")
    except SubtitleError as exc:
        raise HTTPException(422, str(exc)) from exc
    item = {"id": uuid.uuid4().hex, "job_id": job_id, "clip_file": filename, "status": "queued", "created_at": time.time(),
            "version": VERSION, "start": context["start"], "end": context["end"], "options": payload.options.model_dump(), "cues": cues}
    return _submit_export(job_id, item, request)


@router.get("/jobs/{job_id}/exports")
def exports(job_id: str, request: Request):
    job = _doc(job_id)["payload"]
    variants = repo.list_documents(job_id, "export")
    items = [variant["payload"] for variant in variants]
    if job.get("pilot") is True:
        for variant in variants:
            item = variant["payload"]
            if clip_package.is_pilot_manual_export(item) and item["status"] == "failed":
                item["retryable"] = not variant["manifest"] and repo.manual_export_retryable(item)
            item.update(clip_package.export_selection(variant, job_id, request.state.principal.workspace_id))
        if any(item.get("status") == "queued" and item.get("pilot") is None
               and item.get("clip_file") == "manual.mp4" for item in items):
            # The first manual-export endpoint persisted the variant but omitted
            # its routing marker. Repair only its existing queued records.
            with get_engine().begin() as c:
                c.execute(text("""
                    UPDATE cloud_documents SET payload=payload || jsonb_build_object('pilot',true)
                    WHERE job_id=:j AND kind='export' AND payload->>'status'='queued'
                      AND payload->>'clip_file'='manual.mp4' AND payload->>'title'='Fragmento manual'
                      AND NOT payload ? 'pilot'
                    """), {"j": job_id})
        if _needs_dispatch(job_id, "export", items):
            _dispatch({})
    return {"exports": items[:100], "limit": 100, "has_more": len(items) > 100}


@router.get("/jobs/{job_id}/exports/{export_id}")
def export(job_id: str, export_id: str):
    return _doc(job_id, "export", export_id)["payload"]


@router.get("/jobs/{job_id}/exports/{export_id}/files/{filename}")
def export_file(job_id: str, export_id: str, filename: str, request: Request, inline: bool = False):
    if filename not in {"clip.mp4", "clip.srt", "clip.vtt"}:
        raise HTTPException(404, "Archivo no encontrado")
    doc = _doc(job_id, "export", export_id)
    if doc["payload"]["status"] != "completed":
        raise HTTPException(409, "La variante todavía no está disponible")
    if filename not in doc["manifest"]:
        raise HTTPException(404, "Archivo no encontrado")
    return _stream(doc["manifest"][filename], request, filename, inline)


def _summary(c, doc):
    item = doc["payload"]
    metadata = c.execute(text("SELECT payload FROM cloud_documents WHERE job_id=:j AND kind='project' AND id=:j"), {"j": item["id"]}).scalar() or {}
    counts = dict(c.execute(text("SELECT kind,count(*) FROM cloud_documents WHERE job_id=:j GROUP BY kind"), {"j": item["id"]}).all())
    return {"id": item["id"], "title": metadata.get("title") or item.get("source_filename") or f"Proyecto {item['id'][:8]}",
            "source_filename": item.get("source_filename"), "status": item["status"], "created_at": item["created_at"],
            "date_kind": "uploaded", "updated_at": metadata.get("updated_at", item["created_at"]),
            "duration": item.get("media", {}).get("duration_seconds"), "clips_count": len(item["clips"]),
            "drafts_count": counts.get("draft", 0), "exports_count": counts.get("export", 0),
            "source_available": "input.mp4" in doc["manifest"], "thumbnail_url": None, "metadata_warning": False}


@router.get("/projects")
def projects(request: Request, q: str = Query("", max_length=150), offset: int = Query(0, ge=0), limit: int = Query(12, ge=1, le=50)):
    principal = request.state.principal
    with get_engine().connect() as c:
        # The shared legacy route can run on a schema without the beta column.
        rows = c.execute(text("""
            SELECT d.payload,d.manifest FROM cloud_documents d JOIN auth_projects p ON p.id=d.job_id
            WHERE d.kind='job' AND p.owner_id=:o AND p.workspace_id=:w
              AND (NOT :beta OR to_jsonb(p)->>'deletion_started_at' IS NULL)
            ORDER BY d.updated_at DESC,d.id DESC
        """), {"o": principal.id, "w": principal.workspace_id, "beta": beta_enabled()}).mappings()
        items = [_summary(c, row) for row in rows]
    if q.strip():
        items = [item for item in items if q.strip().casefold() in f"{item['title']} {item['id']} {item.get('source_filename') or ''}".casefold()]
    return {"projects": items[offset:offset+limit], "total": len(items), "offset": offset, "limit": limit, "has_more": offset+limit < len(items), "unreadable": 0}


@router.patch("/projects/{job_id}")
def rename(job_id: str, request: ProjectName):
    doc = _doc(job_id)
    item = {"id": job_id, "title": request.title, "updated_at": time.time()}
    with get_engine().begin() as c:
        c.execute(text("SELECT pg_advisory_xact_lock(:i)"), {"i": int(job_id[:15], 16)})
        if repo.list_documents(job_id, "project", c):
            repo.update_document(c, job_id, "project", item)
        else:
            repo.insert_document(c, job_id, "project", item)
        return _summary(c, doc)


@router.get("/cloud/capabilities")
def capabilities():
    return {"backend": "gcs", "durable_jobs": True, "external_llm": False,
            "features": {"delivery": False, "reviews": False, "templates": False, "operations": False, "thumbnails": False}}


@router.get("/ai/config")
def ai_config(response: Response):
    response.headers["Cache-Control"] = "no-store"
    return selection.config_status()


def unavailable():
    raise HTTPException(409, "Esta función todavía no está habilitada en el backend cloud")


# Registered only after the supported routes, before every legacy disk router.
# Do not accidentally serve another instance's local cache for cloud metadata.
def install_fallbacks(app):
    for path in ("/jobs/{job_id}/{remaining:path}", "/projects/{job_id}/{remaining:path}", "/templates", "/templates/{remaining:path}", "/ops/summary"):
        app.add_api_route(path, unavailable, methods=["GET", "POST", "PUT", "PATCH", "DELETE"])
