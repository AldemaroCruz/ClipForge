"""Caption settings and immutable render variants for the public INT clips."""
import hashlib
import json
from pathlib import PurePosixPath
import re
import time
import uuid
from typing import Literal

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, RootModel, model_validator

from ..auth_db import get_engine
from ..presentation import Cue, Presentation
from ..subtitles import cues_from_segments, validate_cues
from . import editorial_selection, repository as repo

_STYLE = tuple(key for key in Presentation.model_fields if key == "burn_subtitles" or key.startswith("subtitle_"))
_CLIP = re.compile(r"clip_[0-9]{2}\.mp4")


def style_from(options: Presentation) -> dict:
    return options.model_dump(include=set(_STYLE))


class CaptionStyle(RootModel[dict]):
    @model_validator(mode="before")
    @classmethod
    def validate_style(cls, value):
        if not isinstance(value, dict) or not value.keys() <= set(_STYLE):
            raise ValueError("El estilo admite únicamente los controles de subtítulos.")
        return style_from(Presentation.model_validate({"burn_subtitles": True, **value}))


class ClipCaptionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    style: CaptionStyle
    cues: list[Cue] = Field(max_length=400)
    revision: int = Field(ge=1, strict=True)


class ProjectCaptionUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    style: CaptionStyle
    apply_to_all: Literal[True]
    revision: int = Field(ge=1, strict=True)


def project_presentation(job: dict) -> Presentation:
    """Give earlier INT projects the enabled default when requesting new clips."""
    style = job.get("caption_style", {"burn_subtitles": True})
    return Presentation.model_validate({**job.get("options", {}), **style})


def _clip(doc, filename):
    if not _CLIP.fullmatch(filename) or filename not in doc["manifest"]:
        raise HTTPException(404, "Clip no disponible")
    for item in doc["payload"]["clips"]:
        if item["file"] == filename:
            return item
    raise HTTPException(404, "Clip no disponible")


def _settings(job, item):
    return job.get("clip_caption_settings", {}).get(item["file"], {"revision": 1})


def _cues(doc, item, settings):
    if "cues" in settings:
        return settings["cues"]
    if "cues" in item:
        return item["cues"]
    if "transcript.json" not in doc["manifest"]:
        return []
    identity = editorial_selection.source_identity(doc)
    segments = editorial_selection.transcript_segments(doc, identity)
    return cues_from_segments(segments, item["start"], item["end"])


def _options(job, item, style, cues):
    options = Presentation.model_validate({
        **item.get("options", job.get("options", {})), **style,
    })
    return options if cues else options.model_copy(update={"burn_subtitles": False})


def render_fingerprint(original, start, end, options, cues):
    """Bind the artifact to the original generation, source interval and render inputs."""
    source = {key: original.get(key) for key in ("generation", "bytes", "md5", "sha256")}
    # Validate defaults and stored JSON the same way so integral JSON numbers
    # cannot turn a saved render into a different variant.
    normalized_options = Presentation.model_validate(options).model_dump()
    normalized_cues = [{**cue, "start": float(cue["start"]), "end": float(cue["end"])} for cue in cues]
    data = json.dumps([source, float(start), float(end), normalized_options, normalized_cues],
                      ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    return hashlib.sha256(data.encode()).hexdigest()


def _base_output(doc, item):
    filename = item["file"]
    root = f"/jobs/{doc['payload']['id']}/clips/{filename}"
    manifest = doc["manifest"]
    options = item["options"]
    cues = item.get("cues", [])
    return {
        "id": render_fingerprint(manifest["input.mp4"], item["start"], item["end"], options, cues),
        "mp4": root,
        "srt": f"{root}/subtitles/srt" if cues and PurePosixPath(filename).with_suffix(".srt").name in manifest else None,
        "vtt": f"{root}/subtitles/vtt" if cues and PurePosixPath(filename).with_suffix(".vtt").name in manifest else None,
        "burn_subtitles": options["burn_subtitles"],
    }


def _variant_output(job_id, variant):
    item = variant["payload"]
    manifest = variant["manifest"]
    export_id = item["id"]
    root = f"/jobs/{job_id}/exports/{export_id}/files"
    return {
        "id": export_id,
        "mp4": f"{root}/clip.mp4" if "clip.mp4" in manifest else None,
        "srt": f"{root}/clip.srt" if item["cues"] and "clip.srt" in manifest else None,
        "vtt": f"{root}/clip.vtt" if item["cues"] and "clip.vtt" in manifest else None,
        "burn_subtitles": item["options"]["burn_subtitles"],
    }


def _caption_state(doc, item, connection=None):
    job = doc["payload"]
    settings = _settings(job, item)
    state = {"revision": settings["revision"], "status": "unmodified",
             "output": None, "notice": None, "retryable": False}
    export_id = settings.get("export_id")
    if export_id:
        variant = repo.document(job["id"], "export", export_id, connection)
        payload = variant["payload"]
        state["status"] = payload["status"]
        if payload["status"] == "completed":
            state["output"] = _variant_output(job["id"], variant)
        elif payload["status"] == "failed":
            state["retryable"] = not variant["manifest"] and repo.manual_export_retryable(payload)
            state["notice"] = payload.get("error", "No se pudo generar el clip con el estilo guardado.")
    elif item.get("caption_rendered") is True:
        state.update(status="completed", output=_base_output(doc, item))
    else:
        state["notice"] = "Generá una versión subtitulada desde Editar subtítulos."
    if state["status"] == "completed":
        cues = settings.get("cues", item.get("cues"))
        if not cues:
            state.update(status="no_speech", notice="Este fragmento no tiene texto de voz para subtitular.")
        elif not state["output"]["burn_subtitles"]:
            state["notice"] = "Los subtítulos están disponibles como archivos independientes."
    return state


def _project_state(job):
    return {"style": style_from(project_presentation(job)), "revision": job.get("caption_style_revision", 1)}


def enrich_job(doc):
    job = doc["payload"]
    if job.get("pilot") is not True:
        return job
    clips = job.get("clips", [])
    if clips:
        with get_engine().connect() as connection:
            clips = [{**item, "captions": _caption_state(doc, item, connection)} for item in clips]
    result = {key: value for key, value in job.items()
              if key not in {"clip_caption_settings", "caption_style_revision"}}
    return {**result, "clips": clips, "caption_style": _project_state(job)}


def clip_context(doc, filename, *, connection=None):
    job = doc["payload"]
    item = _clip(doc, filename)
    settings = _settings(job, item)
    return {
        **_caption_state(doc, item, connection),
        "start": item["start"], "end": item["end"], "duration": round(item["end"] - item["start"], 3),
        "cues": _cues(doc, item, settings), "style": settings.get("style", _project_state(job)["style"]),
        "source_url": f"/jobs/{job['id']}/source",
    }


def _plan(connection, doc, item, style, cues, *, inherited=False):
    job, source = doc["payload"], doc["manifest"].get("input.mp4")
    if source is None:
        raise HTTPException(409, "Original no disponible")
    try:
        cues = validate_cues(cues, round(item["end"] - item["start"], 3))
    except ValueError as error:
        raise HTTPException(422, str(error)) from None
    options = _options(job, item, style, cues).model_dump()
    fingerprint = render_fingerprint(source, item["start"], item["end"], options, cues)
    settings = _settings(job, item)
    current_render = (
        item.get("caption_rendered") is True
        and fingerprint == render_fingerprint(source, item["start"], item["end"], item["options"], item["cues"])
    )
    export_id = None if current_render else uuid.uuid5(
        uuid.NAMESPACE_URL, f"clipforge:{job['id']}:{item['file']}:{fingerprint}",
    ).hex
    revision = settings["revision"]
    desired = {"revision": revision, "cues": cues, "export_id": export_id}
    if not inherited:
        desired["style"] = style
    if desired != settings:
        desired["revision"] += 1
    if export_id is None or repo.document(job["id"], "export", export_id, connection, required=False):
        return desired, None
    variant = {
        "id": export_id, "job_id": job["id"], "status": "queued", "created_at": time.time(),
        "title": "Clip con estilo de subtítulos", "version": job["version"],
        "clip_file": item["file"], "source_clip": item["file"], "clip_captions": True,
        "start": item["start"], "end": item["end"], "options": options, "cues": cues,
        "render_fingerprint": fingerprint, "pilot": True,
    }
    return desired, variant


def _publish(connection, principal, doc, planned):
    job = doc["payload"]
    job_id = job["id"]
    if any(variant is not None for _, _, variant in planned):
        repo.admit_beta(connection, principal.id, caption_job=job_id)
    settings = job.setdefault("clip_caption_settings", {})
    for filename, desired, variant in planned:
        settings[filename] = desired
        if variant is not None:
            repo.insert_document(connection, job_id, "export", variant)
            repo.enqueue(connection, job_id, "export", variant["id"])
    repo.update_document(connection, job_id, "job", job)


def save_clip(job_id, filename, payload: ClipCaptionUpdate, principal):
    with get_engine().begin() as connection:
        doc = repo.beta_document(connection, principal, job_id)
        item = _clip(doc, filename)
        if payload.revision != _settings(doc["payload"], item)["revision"]:
            raise HTTPException(409, "Los subtítulos cambiaron. Volvé a abrir el clip.")
        desired, variant = _plan(connection, doc, item, payload.style.root,
                                 [cue.model_dump() for cue in payload.cues])
        _publish(connection, principal, doc, [(filename, desired, variant)])
        return clip_context(doc, filename, connection=connection)


def save_project(job_id, payload: ProjectCaptionUpdate, principal):
    with get_engine().begin() as connection:
        doc = repo.beta_document(connection, principal, job_id)
        job = doc["payload"]
        current = _project_state(job)
        if payload.revision != current["revision"]:
            raise HTTPException(409, "El estilo cambió. Volvé a abrir el proyecto.")
        if job["status"] != "completed":
            raise HTTPException(409, "Esperá a que termine el procesamiento.")
        style = payload.style.root
        planned = []
        for item in job["clips"]:
            desired, variant = _plan(connection, doc, item, style, _cues(doc, item, _settings(job, item)), inherited=True)
            planned.append((item["file"], desired, variant))
        job.update(caption_style=style, caption_style_revision=payload.revision + 1)
        _publish(connection, principal, doc, planned)
        return _project_state(job)


def retry_clip(job_id, filename, principal):
    with get_engine().begin() as connection:
        doc = repo.beta_document(connection, principal, job_id)
        item = _clip(doc, filename)
        export_id = _settings(doc["payload"], item).get("export_id")
        if export_id is None:
            raise HTTPException(409, "No hay una versión fallida para reintentar.")
        variant = repo.document(job_id, "export", export_id, connection)
        repo.retry_manual_export(connection, job_id, variant, principal.id)
        return clip_context(doc, filename, connection=connection)
