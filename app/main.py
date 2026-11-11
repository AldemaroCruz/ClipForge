"""ClipForge v0.4.2: a local, single-process video clipping MVP.

AUTH-01 adds private local accounts. One worker; publication remains blocked.
"""

import copy
import json
import logging
import math
import os
import re
import shutil
import threading
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

from fastapi import Depends, FastAPI, File, Form, HTTPException, Request, Response, UploadFile
from pydantic import ValidationError
from fastapi.responses import FileResponse, HTMLResponse
from fastapi.staticfiles import StaticFiles

from .media import MediaValidationError, inspect_media
from .state import write_json_atomic
from .lease import data_lease
from .telemetry import Recorder
from .model_source import resolve_model
from .presentation import Presentation, ExportRequest
from .render import render_clip, run_ffmpeg
from .subtitles import SubtitleError, cues_from_segments, validate_cues, to_srt, to_vtt
from .auth import AuthenticationBoundary, require_access, register_project, unregister_project, router as auth_router

VERSION = "0.4.2"
ROOT = Path(os.getenv("CLIPFORGE_DATA_DIR", "/data"))
ROOT.mkdir(parents=True, exist_ok=True)
ASSETS = Path(__file__).resolve().parent / "static"
LOGGER = logging.getLogger("uvicorn.error")
JOBS: dict[str, dict[str, Any]] = {}
LOCK = threading.RLock()
PROCESS_LOCK = threading.Lock()  # Only one video at a time in this local MVP.
MAX_MB = int(os.getenv("MAX_UPLOAD_MB", "300"))
FFMPEG_THREADS = max(1, int(os.getenv("FFMPEG_THREADS", "2")))
READ_ATTEMPTS = 3
READ_DELAY_SECONDS = 0.05
ACTIVE_STATUSES = {"queued", "validating", "transcribing", "rendering"}
STATUSES = ACTIVE_STATUSES | {"completed", "failed"}


def validate_job_id(job_id: str) -> None:
    if not re.fullmatch(r"[0-9a-f]{32}", job_id):
        raise HTTPException(status_code=404, detail="Job no encontrado")


def persist(job_id: str, data: dict[str, Any]) -> None:
    """All job state writers must use this function, never Path.write_text."""
    validate_job_id(job_id)
    snapshot = copy.deepcopy(data)
    with LOCK:
        write_json_atomic(ROOT / job_id / "job.json", snapshot)
        # Do not expose a mutable reference owned by the processing thread.
        JOBS[job_id] = snapshot


def load_job(job_id: str) -> dict[str, Any]:
    """Read a snapshot, with bounded retries for old/corrupt/inaccessible files."""
    validate_job_id(job_id)
    path = ROOT / job_id / "job.json"
    for attempt in range(READ_ATTEMPTS):
        try:
            with LOCK:
                state = json.loads(path.read_text(encoding="utf-8"))
            if (
                not isinstance(state, dict)
                or state.get("id") != job_id
                or not isinstance(state.get("status"), str)
                or state["status"] not in STATUSES
                or not isinstance(state.get("clips"), list)
                or not all(isinstance(clip, dict) for clip in state["clips"])
            ):
                raise ValueError("Estructura de job.json inválida")
            return state
        except FileNotFoundError as exc:
            raise HTTPException(status_code=404, detail="Job no encontrado") from exc
        except (ValueError, UnicodeDecodeError, OSError):
            if attempt + 1 < READ_ATTEMPTS:
                time.sleep(READ_DELAY_SECONDS * (attempt + 1))
    # Keep the original file for diagnosis. Do not invent a running state.
    LOGGER.warning("Job %s: job.json no disponible tras %s intentos", job_id, READ_ATTEMPTS)
    raise HTTPException(
        status_code=503,
        detail=(
            "No se pudo leer job.json. Puede estar temporalmente inaccesible o "
            "dañado. Reintenta; si persiste, conserva data/ y sube el video de nuevo."
        ),
        headers={"Retry-After": "2", "Cache-Control": "no-store"},
    )


def mark_interrupted_jobs() -> None:
    """Jobs cannot resume after restart; mark valid unfinished states honestly."""
    for path in ROOT.glob("*/job.json"):
        job_id = path.parent.name
        if not re.fullmatch(r"[0-9a-f]{32}", job_id):
            continue
        try:
            job = load_job(job_id)
            if job["status"] in ACTIVE_STATUSES:
                job["status"] = "failed"
                job["error"] = (
                    "Procesamiento interrumpido por un reinicio. Los archivos existentes "
                    "se conservan. Sube de nuevo el video para crear otro job."
                )
                persist(job_id, job)
                LOGGER.warning("Job %s marcado como interrumpido por reinicio", job_id)
        except (HTTPException, OSError):
            LOGGER.warning("No se modificó el estado ilegible del job %s", job_id)


@asynccontextmanager
async def lifespan(application: FastAPI):
    # One filesystem owner. Offline backup refuses to run while this lease is held.
    with data_lease(ROOT):
        mark_interrupted_jobs()
        mark_interrupted_exports()
        from .ai_selection import mark_interrupted_selections
        mark_interrupted_selections()
        yield


app = FastAPI(title="ClipForge MVP", version=VERSION, lifespan=lifespan,
              dependencies=[Depends(require_access)], docs_url=None, redoc_url=None,
              openapi_url=None)
app.mount("/static", StaticFiles(directory=str(ASSETS)), name="static")
app.add_middleware(AuthenticationBoundary)
app.include_router(auth_router)


def ffmpeg(*args: Any) -> None:
    """Compatibility wrapper, shared by processing and regression tests."""
    run_ffmpeg(*args)


def select_clips(segments: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Original baseline: up to five non-overlapping 20–60 second voice windows."""
    candidates = []
    for index, segment in enumerate(segments):
        start = segment["start"]
        words: list[str] = []
        for candidate in segments[index:]:
            if candidate["end"] - start > 60:
                break
            end = candidate["end"]
            words.extend(candidate["text"].split())
            if end - start >= 20:
                candidates.append((len(words), start, end, " ".join(words)))
    candidates.sort(reverse=True)
    chosen: list[dict[str, Any]] = []
    for score, start, end, text in candidates:
        if all(end <= item["start"] or start >= item["end"] for item in chosen):
            chosen.append({"start": round(start, 2), "end": round(end, 2), "text": text})
        if len(chosen) == 5:
            break
    return chosen


def process(job_id: str) -> None:
    recorder = Recorder(ROOT, job_id, "process", job_id)
    recorder.phase("queue")
    with PROCESS_LOCK:
        _process(job_id, recorder)


def _process(job_id: str, recorder: Recorder | None = None) -> None:
    recorder = recorder or Recorder(ROOT, job_id, "process", job_id)
    folder = ROOT / job_id
    job: dict[str, Any] | None = None
    try:
        job = load_job(job_id)
        recorder.phase("validation")
        job["status"] = "validating"
        persist(job_id, job)
        LOGGER.info("Job %s: validando pistas y duración con ffprobe", job_id)
        job["media"] = inspect_media(folder / "input.mp4", min_duration=1 if job.get("processing_mode") == "manual" else 20)
        LOGGER.info("Job %s: video=%s audio=%s duración=%s s", job_id,
                    job["media"]["video_streams"], job["media"]["audio_streams"],
                    job["media"]["duration_seconds"])
        if job.get("processing_mode") == "manual":
            job.update(status="completed", message="Original listo para crear clips manuales. No se ejecutó Whisper.")
            persist(job_id, job)
            return
        job["status"] = "transcribing"
        persist(job_id, job)
        LOGGER.info("Job %s: cargando Whisper y transcribiendo", job_id)
        from faster_whisper import WhisperModel

        recorder.phase("model_load")
        model = WhisperModel(resolve_model(), device="cpu", compute_type="int8")
        recorder.phase("transcription")
        segments, info = model.transcribe(str(folder / "input.mp4"), beam_size=1, vad_filter=True)
        segs = [{"start": s.start, "end": s.end, "text": s.text.strip()}
                for s in segments if s.text.strip()]
        write_json_atomic(folder / "transcript.json", segs)
        if not segs:
            raise MediaValidationError("NO_SPEECH_DETECTED", "No se detectó voz transcribible en el video. Hay una pista de audio, pero podría contener silencio, música o voz poco clara. Prueba una conversación audible de 1–3 minutos.", job["media"])
        job["status"] = "rendering"
        job["language"] = info.language
        persist(job_id, job)
        recorder.phase("selection")
        chosen = select_clips(segs)
        if not chosen:
            raise MediaValidationError("NO_CLIP_WINDOWS", "No se encontraron ventanas de voz de entre 20 y 60 segundos. Se obtuvo una transcripción, pero no alcanza el rango del selector actual. Prueba una conversación más larga.", job["media"])
        recorder.phase("render")
        for index, clip in enumerate(chosen, 1):
            filename = f"clip_{index:02}.mp4"
            output = folder / filename
            options = Presentation.model_validate(job.get("options", {}))
            cues = cues_from_segments(segs, clip["start"], clip["end"])
            LOGGER.info("Job %s: renderizando clip %s/%s (%s)", job_id, index, len(chosen), options.framing)
            render_clip(
                folder / "input.mp4", output, start=clip["start"], end=clip["end"],
                options=options, cues=cues, video_index=job["media"]["video_stream_index"],
                threads=FFMPEG_THREADS, runner=ffmpeg,
            )
            clip["cues"] = cues
            clip["options"] = options.model_dump()
            clip["file"] = filename
            # Only publish links after FFmpeg has successfully closed the file.
            job["clips"] = chosen[:index]
            persist(job_id, job)
        job["status"] = "completed"
        persist(job_id, job)
        LOGGER.info("Job %s: completado (%s clips)", job_id, len(chosen))
    except Exception as exc:
        if isinstance(exc, MediaValidationError):
            if job and job.get("processing_mode") == "manual":
                if exc.code == "NO_AUDIO_STREAM":
                    exc = MediaValidationError(exc.code, "Este render requiere un MP4 con pista de video y audio. El modo manual no exige voz, pero todavía no exporta videos sin pista de audio.", exc.media)
                elif exc.code == "VIDEO_TOO_SHORT":
                    exc = MediaValidationError(exc.code, "El modo manual requiere un video de al menos 1 segundo.", exc.media)
            LOGGER.warning("Job %s: %s — %s", job_id, exc.code, exc)
        else:
            LOGGER.exception("Job %s falló", job_id)
        if job is not None:
            job["status"] = "failed"
            job["error"] = str(exc)
            if isinstance(exc, MediaValidationError):
                job["error_code"] = exc.code
                if exc.media is not None:
                    job["media"] = exc.media
            try:
                persist(job_id, job)
            except Exception:
                LOGGER.exception("No se pudo guardar el estado de error del job %s", job_id)
    finally:
        recorder.finish(job.get("status", "failed") if job else "failed",
                        job.get("error_code") if job else "STATE_UNAVAILABLE")
        with LOCK:
            JOBS.pop(job_id, None)  # Disk is the source of truth; do not grow memory forever.


@app.get("/", response_class=HTMLResponse)
def home():
    return HTMLResponse(
        (ASSETS / "index.html").read_text(encoding="utf-8"),
        headers={"Cache-Control": "no-store"},
    )


@app.get("/favicon.ico", include_in_schema=False, status_code=204)
def favicon():
    return Response(status_code=204)


@app.get("/health")
def health():
    return {"status": "ok", "version": VERSION}


@app.post("/jobs", status_code=202)
async def create_job(
    request: Request,
    file: UploadFile = File(...), framing: str = Form("contain"),
    burn_subtitles: bool = Form(False), crop_x: float = Form(0.5),
    crop_y: float = Form(0.5), crop_zoom: float = Form(1),
    subtitle_font_size: int = Form(52), subtitle_color: str = Form("#FFFFFF"),
    processing_mode: str = Form("auto"),
    subtitle_position: str = Form("bottom"), subtitle_margin_v: int = Form(230),
    subtitle_outline: int = Form(3), subtitle_outline_color: str = Form("#201510"),
    subtitle_shadow: int = Form(1),
):
    # Ownership is created from the authenticated server-side membership only.
    fields = await request.form()
    if {"owner_id", "workspace_id", "role", "user_id"} & (set(fields) | set(request.query_params)):
        await file.close()
        raise HTTPException(422, "La propiedad y los permisos los asigna el servidor.")
    try:
        options = Presentation(framing=framing, burn_subtitles=burn_subtitles,
                               crop_x=crop_x, crop_y=crop_y, crop_zoom=crop_zoom,
                               subtitle_font_size=subtitle_font_size, subtitle_color=subtitle_color,
                               subtitle_position=subtitle_position, subtitle_margin_v=subtitle_margin_v,
                               subtitle_outline=subtitle_outline, subtitle_outline_color=subtitle_outline_color,
                               subtitle_shadow=subtitle_shadow)
    except ValidationError as exc:
        await file.close()
        raise HTTPException(status_code=422, detail="Ajustes inválidos: encuadre contain, blur o crop; x/y entre 0 y 1, zoom entre 1 y 3; tamaño 24–120, colores #RRGGBB, posición bottom/center/top, margen 0–650, contorno 0–12 y sombra 0–8.") from exc
    if processing_mode not in {"auto", "manual"}:
        await file.close()
        raise HTTPException(422, "Modo de procesamiento inválido: auto o manual.")
    if not file.filename or not file.filename.lower().endswith(".mp4"):
        await file.close()
        raise HTTPException(status_code=400, detail="Solo MP4")
    job_id = uuid.uuid4().hex
    folder = ROOT / job_id
    folder.mkdir()
    size = 0
    try:
        with (folder / "input.mp4").open("wb") as out:
            while chunk := await file.read(1024 * 1024):
                size += len(chunk)
                if size > MAX_MB * 1024 * 1024:
                    raise HTTPException(status_code=413, detail=f"Máximo {MAX_MB} MB")
                out.write(chunk)
        if not size:
            raise HTTPException(status_code=400, detail="El archivo está vacío")
        job = {"id": job_id, "status": "queued", "clips": [], "options": options.model_dump(), "version": VERSION,
               "created_at": time.time(), "source_filename": re.sub(r"[\x00-\x1f\x7f]", "", file.filename.replace("\\", "/").rsplit("/", 1)[-1])[:255],
               "processing_mode": processing_mode}
        register_project(job_id, request.state.principal)
        persist(job_id, job)
    except Exception:
        # This is a newly allocated UUID directory, never an existing user's job.
        shutil.rmtree(folder, ignore_errors=True)
        with LOCK:
            JOBS.pop(job_id, None)
        unregister_project(job_id, request.state.principal)
        raise
    finally:
        await file.close()
    response = copy.deepcopy(job)
    try:
        threading.Thread(target=process, args=(job_id,), daemon=True, name=f"job-{job_id}").start()
    except Exception as exc:
        job["status"] = "failed"
        job["error"] = "No se pudo iniciar el procesamiento. Revisa los logs."
        persist(job_id, job)
        LOGGER.exception("No se pudo iniciar el hilo del job %s", job_id)
        raise HTTPException(status_code=503, detail=job["error"]) from exc
    return response


@app.get("/jobs/{job_id}")
def get_job(job_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return load_job(job_id)


@app.get("/jobs/{job_id}/clips/{filename}")
def download(job_id: str, filename: str, inline: bool = False):
    validate_job_id(job_id)
    if not re.fullmatch(r"clip_\d{2}\.mp4", filename):
        raise HTTPException(status_code=404, detail="Clip no encontrado")
    job = load_job(job_id)
    if not any(clip.get("file") == filename for clip in job["clips"]):
        raise HTTPException(status_code=404, detail="Clip no disponible todavía")
    path = ROOT / job_id / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Clip no encontrado")
    return FileResponse(path, media_type="video/mp4", filename=filename,
                        content_disposition_type="inline" if inline else "attachment")


# Presentation editing is additive. It reads the source and cached transcript,
# and writes an isolated export directory; it never rewrites an old job or clip.
def clip_context(job_id: str, filename: str) -> tuple[dict, dict, Path]:
    validate_job_id(job_id)
    if not re.fullmatch(r"clip_\d{2}\.mp4", filename):
        raise HTTPException(status_code=404, detail="Clip no encontrado")
    job = load_job(job_id)
    clip = next((c for c in job["clips"] if c.get("file") == filename), None)
    if clip is None:
        raise HTTPException(status_code=404, detail="Clip no disponible todavía")
    folder = ROOT / job_id
    return job, copy.deepcopy(clip), folder


def editor_context(job_id: str, filename: str) -> dict:
    job, clip, folder = clip_context(job_id, filename)
    if not (folder / "input.mp4").is_file():
        raise HTTPException(status_code=409, detail="Falta input.mp4. Se necesita el original para volver a encuadrar.")
    try:
        start, end = float(clip["start"]), float(clip["end"])
        duration = round(end - start, 3)
        if not math.isfinite(start) or not math.isfinite(end) or start < 0 or not 0 < duration <= 60.001:
            raise ValueError("Límites de clip inválidos")
        if "cues" in clip:
            cues = validate_cues(clip["cues"], duration)
        else:
            segments = json.loads((folder / "transcript.json").read_text(encoding="utf-8"))
            cues = cues_from_segments(segments, start, end)
        options = Presentation.model_validate(clip.get("options", job.get("options", {})))
    except (OSError, ValueError, TypeError, KeyError) as exc:
        raise HTTPException(status_code=409, detail="La transcripción o los tiempos guardados no son editables. Conserva los archivos y crea un job nuevo.") from exc
    return {"job_id": job_id, "clip_file": filename, "start": start, "end": end,
            "duration": duration, "cues": cues, "options": options.model_dump(),
            "source_url": f"/jobs/{job_id}/source", "version": VERSION}


@app.get("/jobs/{job_id}/source")
def source_video(job_id: str):
    load_job(job_id)
    path = ROOT / job_id / "input.mp4"
    if not path.is_file():
        raise HTTPException(status_code=404, detail="No se encontró el video original")
    return FileResponse(path, media_type="video/mp4", filename="input.mp4", content_disposition_type="inline")


@app.get("/jobs/{job_id}/clips/{filename}/editor")
def get_editor(job_id: str, filename: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return editor_context(job_id, filename)


@app.get("/jobs/{job_id}/clips/{filename}/subtitles/{kind}")
def get_subtitles(job_id: str, filename: str, kind: str):
    if kind not in {"srt", "vtt"}:
        raise HTTPException(status_code=404, detail="Formato no disponible")
    context = editor_context(job_id, filename)
    return Response(to_srt(context["cues"]) if kind == "srt" else to_vtt(context["cues"]),
                    media_type="application/x-subrip" if kind == "srt" else "text/vtt",
                    headers={"Content-Disposition": f'attachment; filename="{Path(filename).stem}.{kind}"',
                             "Cache-Control": "no-store"})


def export_path(job_id: str, export_id: str) -> Path:
    validate_job_id(job_id)
    if not re.fullmatch(r"[0-9a-f]{32}", export_id):
        raise HTTPException(status_code=404, detail="Variante no encontrada")
    return ROOT / job_id / "exports" / export_id


def read_export(job_id: str, export_id: str) -> dict:
    path = export_path(job_id, export_id) / "export.json"
    try:
        with LOCK:
            item = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(item, dict) or item.get("id") != export_id or item.get("job_id") != job_id
                or item.get("status") not in {"queued", "rendering", "completed", "failed"}):
            raise ValueError("Invalid export state")
        return item
    except FileNotFoundError as exc:
        raise HTTPException(status_code=404, detail="Variante no encontrada") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(status_code=503, detail="Estado de variante temporalmente no disponible", headers={"Retry-After": "2"}) from exc


def persist_export(job_id: str, item: dict) -> None:
    with LOCK:
        write_json_atomic(export_path(job_id, item["id"]) / "export.json", item)


def mark_interrupted_exports() -> None:
    for path in ROOT.glob("*/exports/*/export.json"):
        job_id, export_id = path.parents[2].name, path.parent.name
        try:
            item = read_export(job_id, export_id)
            if item["status"] in {"queued", "rendering"}:
                item.update(status="failed", error="Exportación interrumpida por reinicio. Los originales se conservan; genera una variante nueva.")
                persist_export(job_id, item)
        except (HTTPException, OSError):
            LOGGER.warning("No se modificó la variante ilegible %s", path)


def process_export(job_id: str, export_id: str) -> None:
    recorder = Recorder(ROOT, job_id, "export", export_id)
    recorder.phase("queue")
    item = None
    try:
        with PROCESS_LOCK:
            item = read_export(job_id, export_id)
            item["status"] = "rendering"
            persist_export(job_id, item)
            source = ROOT / job_id / "input.mp4"
            recorder.phase("validation")
            # Validate the actual source; legacy job metadata may omit stream IDs.
            media = inspect_media(source, min_duration=0)
            options = Presentation.model_validate(item["options"])
            target = export_path(job_id, export_id) / "clip.mp4"
            LOGGER.info("Variante %s: renderizando %s sin repetir Whisper", export_id, options.framing)
            recorder.phase("render")
            render_clip(source, target, start=item["start"], end=item["end"],
                        options=options, cues=item["cues"], video_index=media["video_stream_index"],
                        threads=FFMPEG_THREADS)
            item.update(status="completed", completed_at=time.time())
            persist_export(job_id, item)
    except Exception as exc:
        LOGGER.exception("Variante %s falló", export_id)
        if item is not None:
            item.update(status="failed", error=str(exc))
            try:
                persist_export(job_id, item)
            except Exception:
                LOGGER.exception("No se pudo guardar el error de la variante %s", export_id)
    finally:
        recorder.finish(item.get("status", "failed") if item else "failed",
                        "EXPORT_FAILED" if not item or item.get("status") != "completed" else None)


@app.post("/jobs/{job_id}/clips/{filename}/exports", status_code=202)
def create_export(job_id: str, filename: str, request: ExportRequest):
    context = editor_context(job_id, filename)
    try:
        cues = validate_cues([cue.model_dump() for cue in request.cues], context["duration"])
        if request.options.burn_subtitles and not cues:
            raise SubtitleError("Agrega subtítulos o desactiva «Incrustar subtítulos».")
    except SubtitleError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    export_id = uuid.uuid4().hex
    item = {"id": export_id, "job_id": job_id, "clip_file": filename,
            "status": "queued", "created_at": time.time(), "version": VERSION,
            "start": context["start"], "end": context["end"],
            "options": request.options.model_dump(), "cues": cues}
    persist_export(job_id, item)
    try:
        threading.Thread(target=process_export, args=(job_id, export_id), daemon=True,
                         name=f"export-{export_id}").start()
    except Exception as exc:
        item.update(status="failed", error="No se pudo iniciar la exportación. Revisa los logs.")
        persist_export(job_id, item)
        raise HTTPException(status_code=503, detail=item["error"]) from exc
    return copy.deepcopy(item)


@app.get("/jobs/{job_id}/exports")
def list_exports(job_id: str, response: Response):
    load_job(job_id)
    response.headers["Cache-Control"] = "no-store"
    paths = sorted((ROOT / job_id / "exports").glob("*/export.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    items = []
    from .delivery import read_review
    for path in paths[:100]:
        try:
            item = read_export(job_id, path.parent.name)
            try:
                item["review"] = read_review(job_id, path.parent.name)
            except HTTPException:
                item["review"] = {"status": "unreadable", "revision": None,
                                  "error": "Revisión ilegible; archivo conservado, entrega bloqueada."}
            items.append(item)
        except HTTPException:
            continue
    return {"exports": items, "limit": 100, "has_more": len(paths) > 100}


@app.get("/jobs/{job_id}/exports/{export_id}")
def get_export(job_id: str, export_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    return read_export(job_id, export_id)


@app.get("/jobs/{job_id}/exports/{export_id}/files/{filename}")
def export_file(job_id: str, export_id: str, filename: str, inline: bool = False):
    types = {"clip.mp4": "video/mp4", "clip.srt": "application/x-subrip", "clip.vtt": "text/vtt"}
    if filename not in types:
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    item = read_export(job_id, export_id)
    if item["status"] != "completed":
        raise HTTPException(status_code=409, detail="La variante todavía no está disponible")
    path = export_path(job_id, export_id) / filename
    if not path.is_file():
        raise HTTPException(status_code=404, detail="Archivo no encontrado")
    name = f"{Path(item['clip_file']).stem}_{export_id[:8]}{path.suffix}"
    return FileResponse(path, media_type=types[filename], filename=name,
                        content_disposition_type="inline" if inline else "attachment")


from .workspace import router as workspace_router
app.include_router(workspace_router)

from .delivery import router as delivery_router
app.include_router(delivery_router)


from .ai_selection import router as ai_router
app.include_router(ai_router)

from .operations import router as operations_router
app.include_router(operations_router)

@app.get("/ops", response_class=HTMLResponse)
def operations_page():
    return HTMLResponse((ASSETS / "operations.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store"})


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return HTMLResponse((ASSETS / "login.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store"})


@app.get("/recover", response_class=HTMLResponse)
def recovery_page():
    return HTMLResponse((ASSETS / "recover.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store"})


@app.get("/account", response_class=HTMLResponse)
def account_page():
    return HTMLResponse((ASSETS / "account.html").read_text(encoding="utf-8"),
                        headers={"Cache-Control": "no-store"})
