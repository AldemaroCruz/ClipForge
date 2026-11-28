"""Consented translation of saved subtitle revisions without changing their clock."""
from datetime import datetime, timezone
import hashlib
import json
import re
import time
from typing import Literal
import uuid

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from ..ai_provider import (AIError, TRANSLATION_CONTRACT, TRANSLATION_PROMPT_VERSION,
                           TRANSLATION_SYSTEM_PROMPT, build_payload, check_input_budget, request_selection)
from ..auth_db import get_engine
from ..editorial import validate_range
from ..presentation import Presentation
from ..subtitles import plain_text, validate_cues
from . import clip_captions, clip_package, editorial_selection, publication, repository as repo

KIND = "translation_ai"
LANGUAGES = ("es", "en")
MAX_RUNS = 100
DOCUMENT_ID = r"^[a-f0-9]{32}$"


class SourceRef(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    kind: Literal["draft", "export", "automatic"]
    id: str = Field(max_length=32)
    revision: int = Field(ge=1, lt=10**19)
    selection: str | None = Field(default=None, max_length=110)

    @model_validator(mode="after")
    def reference(self):
        if self.kind == "automatic":
            if not self.selection or not re.fullmatch(r"clip_[0-9]{2}\.mp4", self.id):
                raise ValueError("Seleccioná una revisión exacta del clip.")
        elif self.selection is not None or not re.fullmatch(DOCUMENT_ID, self.id):
            raise ValueError("Seleccioná una revisión exacta del documento.")
        return self


class PreviewRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    source: SourceRef
    source_language: Literal["es", "en"]
    target_language: Literal["es", "en"]

    @model_validator(mode="after")
    def distinct_languages(self):
        if self.source_language == self.target_language:
            raise ValueError("Los idiomas de origen y destino deben ser distintos.")
        return self


class TranslateRequest(PreviewRequest):
    request_id: str = Field(pattern=DOCUMENT_ID)
    preview_fingerprint: str = Field(pattern=r"^[a-f0-9]{64}$")
    consent: bool = False
    new_attempt: bool = False


class TranslatedCue(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    id: str = Field(pattern=r"^c[1-9][0-9]{0,2}$")
    text: str = Field(min_length=1, max_length=1500)


class DraftRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    title: str | None = Field(default=None, min_length=1, max_length=120)
    cues: list[TranslatedCue] = Field(min_length=1, max_length=400)


class ProviderResult(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    cues: list[TranslatedCue] = Field(min_length=1, max_length=400)


def _language(value):
    if not isinstance(value, str):
        return None
    code = value.lower().split("-", 1)[0]
    return code if code in LANGUAGES else None


def _source_asset(job, workspace):
    item = job["manifest"].get("input.mp4")
    clip_package._validate_object(item, "mp4", f"workspaces/{workspace}/jobs/{job['payload']['id']}/")
    return publication._asset(item)


def _source(connection, job, ref, workspace):
    project = job["payload"]
    job_id = project["id"]
    original = _source_asset(job, workspace)
    if project.get("status") != "completed":
        raise HTTPException(409, "El proyecto todavía no tiene un original disponible.")
    selection = None
    if ref.kind == "automatic":
        chosen = clip_package._parse([ref.selection])[0]
        if (chosen.filename, chosen.revision) != (ref.id, ref.revision):
            raise HTTPException(409, "Cambió la revisión del clip. Volvé a seleccionarlo.")
        objects = clip_captions.selected_output(job, chosen.filename, chosen.revision, chosen.output_id, connection)
        for name, asset in objects.items():
            clip_package._validate_object(asset, name, f"workspaces/{workspace}/jobs/{job_id}/")
        auto = clip_captions._clip(job, ref.id)
        export_id = clip_captions._settings(project, auto).get("export_id")
        item = ({**auto, **repo.document(job_id, "export", export_id, connection)["payload"]}
                if export_id else auto)
        selection = ref.selection
    else:
        document = repo.document(job_id, ref.kind, ref.id, connection)
        if document["revision"] != ref.revision:
            raise HTTPException(409, "Cambió la revisión de los subtítulos. Volvé a seleccionarla.")
        item = document["payload"]
        if ref.kind == "export":
            selection = clip_package.export_selection(document, job_id, workspace).get("archive_selection")
            if not selection:
                raise HTTPException(409, "La exportación todavía no está disponible.")
    try:
        start, end = validate_range(float(item["start"]), float(item["end"]), project["media"]["duration_seconds"])
        duration = round(end - start, 3)
        cues = validate_cues(item.get("cues", []), duration)
        options = Presentation.model_validate(item.get("options", {})).model_dump()
    except (KeyError, TypeError, ValueError):
        raise HTTPException(409, "No se pudo verificar el intervalo o los subtítulos de esa revisión.") from None
    if not cues:
        raise HTTPException(422, "La revisión elegida no tiene subtítulos para traducir.")
    origin = item.get("translation_origin", {})
    audio = _language(item.get("audio_language") or origin.get("audio_language") or project.get("language"))
    subtitle = _language(item.get("subtitle_language") or origin.get("target_language"))
    descriptor = {**ref.model_dump(exclude_none=True), "title": plain_text(item.get("title") or "Clip"),
                  "start": start, "end": end, "audio_language": audio, "subtitle_language": subtitle,
                  "cue_count": len(cues)}
    clip_file = item.get("clip_file", item.get("file"))
    source = {"source": descriptor, "original": original, "options": options,
              "clip_file": clip_file if isinstance(clip_file, str) and re.fullmatch(r"clip_[0-9]{2}\.mp4", clip_file) else None,
              "cues": [{"id": f"c{index}", **cue} for index, cue in enumerate(cues, 1)],
              "content_sha256": publication.content_hash(original, start, end, publication._cues(cues, duration))}
    if selection:
        source["archive_selection"] = selection
    for key in ("logo", "style_template"):
        if item.get(key):
            source[key] = item[key]
    return source


def _available_sources(connection, job, workspace):
    project = job["payload"]
    job_id = project["id"]
    refs = []
    for kind in ("draft", "export"):
        refs.extend(SourceRef(kind=kind, id=row["payload"]["id"], revision=row["revision"])
                    for row in repo.list_documents(job_id, kind, connection))
    for clip in project.get("clips", []):
        state = clip_captions._caption_state(job, clip, connection)
        if state["status"] == "completed" and state["output"]["mp4"]:
            filename, revision, output_id = clip["file"], state["revision"], state["output"]["id"]
            refs.append(SourceRef(kind="automatic", id=filename, revision=revision,
                                  selection=f"{filename}:{revision}:{output_id}"))
    sources = []
    for ref in refs:
        try:
            sources.append(_source(connection, job, ref, workspace)["source"])
        except HTTPException:
            continue
    return sources


def _prepared(job_id, source, source_language, target_language, *, worker=False):
    config, config_id = editorial_selection.provider_config(worker=worker)
    content = {"selection_contract": TRANSLATION_CONTRACT, "source_language": source_language,
               "target_language": target_language,
               "cues": [{"id": row["id"], "text": row["text"]} for row in source["cues"]]}
    budget = check_input_budget(config, content)
    bound = json.dumps([job_id, source, config_id, TRANSLATION_PROMPT_VERSION, content],
                       sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)
    token = hashlib.sha256(bound.encode()).hexdigest()
    return config, content, budget, token


def _prepare_http(job_id, source, source_language, target_language):
    try:
        return _prepared(job_id, source, source_language, target_language)
    except AIError as exc:
        status = 413 if exc.code in {"AI_INPUT_TOO_LARGE", "AI_CONTEXT_LIMIT"} else 409
        raise HTTPException(status, f"[{exc.code}] {exc}") from None


def _read(connection, item):
    result = {key: value for key, value in item.items() if key not in {"snapshot", "preview_fingerprint"}}
    result.update(source=item["snapshot"]["source"], source_cues=item["snapshot"]["cues"], saved_draft=None)
    saved = repo.document(item["job_id"], "draft", item["id"], connection, required=False)
    if saved:
        result["saved_draft"] = {"id": saved["payload"]["id"], "revision": saved["revision"]}
    return result


def index(job_id, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        sources = _available_sources(connection, job, principal.workspace_id)
        runs = [_read(connection, row["payload"]) for row in repo.list_documents(job_id, KIND, connection)[:20]]
    return {"sources": sources, "runs": runs, "provider": editorial_selection.config_status(),
            "languages": list(LANGUAGES)}


def read(job_id, run_id, principal):
    with get_engine().begin() as connection:
        repo.beta_document(connection, principal, job_id)
        return _read(connection, repo.document(job_id, KIND, run_id, connection)["payload"])


def preview(job_id, payload, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        source = _source(connection, job, payload.source, principal.workspace_id)
    config, content, budget, token = _prepare_http(job_id, source, payload.source_language, payload.target_language)
    return {"source": source["source"], "audio_language": source["source"]["audio_language"], "cues": source["cues"],
            "source_language": payload.source_language, "target_language": payload.target_language,
            "provider": config.provider, "model": config.model, "endpoint": config.endpoint,
            "preview_fingerprint": token, "prompt_version": TRANSLATION_PROMPT_VERSION,
            "text_to_send": build_payload(config, content)["input"][0]["content"], "payload_text": content,
            "system_instructions": TRANSLATION_SYSTEM_PROMPT, "max_cue_chars": 500,
            "budget": {**budget, "provider_calls": 1}}


def submit(job_id, payload, principal):
    if not payload.consent:
        raise HTTPException(422, "Revisá y autorizá explícitamente el envío al proveedor.")
    intent = [KIND, job_id, payload.source.model_dump(exclude_none=True), payload.source_language,
              payload.target_language, payload.preview_fingerprint, payload.new_attempt]
    request_key = publication.digest([KIND, job_id, payload.request_id])
    fingerprint = publication.digest(intent)
    # An exact request replay works even after the creator edits the source.
    with repo.request_transaction(principal.id, request_key, fingerprint) as (connection, previous, key):
        job = repo.beta_document(connection, principal, job_id)
        previous_id = previous["item_id"] if previous else None
        if not previous_id and not payload.new_attempt:
            previous_id = repo.translation_by_fingerprint(connection, job_id, payload.preview_fingerprint)
        if previous_id:
            item = repo.document(job_id, KIND, previous_id, connection)["payload"]
            expected = payload.source.model_dump(exclude_none=True)
            if (any(item["snapshot"]["source"].get(name) != value for name, value in expected.items())
                    or item["source_language"] != payload.source_language or item["target_language"] != payload.target_language):
                raise HTTPException(409, "Cambió la revisión o el idioma. Revisá un nuevo envío.")
            if not previous:
                repo.remember_request(connection, principal.id, key, fingerprint, job_id, KIND, previous_id)
            return _read(connection, item)
        source = _source(connection, job, payload.source, principal.workspace_id)
        config, _, _, token = _prepare_http(job_id, source, payload.source_language, payload.target_language)
        if token != payload.preview_fingerprint:
            raise HTTPException(409, "Cambió la revisión o el proveedor. Revisá un nuevo envío.")
        day = datetime.now(timezone.utc).date().isoformat()
        repo.admit_beta(connection, principal.id)
        repo.admit_selection(connection, job_id, day, 1, config.daily_limit, MAX_RUNS, kind=KIND)
        now = time.time()
        item = {"id": uuid.uuid4().hex, "job_id": job_id, "status": "queued", "pilot": True, "day_utc": day,
                "created_at": now, "consent_at": now, "source_language": payload.source_language,
                "target_language": payload.target_language, "audio_language": source["source"]["audio_language"],
                "snapshot": source, "preview_fingerprint": token, "prompt_version": TRANSLATION_PROMPT_VERSION,
                "provider": config.provider, "model": config.model, "provider_calls_planned": 1,
                "provider_calls": 0, "provider_responses": 0, "provider_response_received": False,
                "provider_models_received": [], "usage": {}, "cues": []}
        repo.insert_document(connection, job_id, KIND, item)
        repo.enqueue(connection, job_id, KIND, item["id"])
        repo.remember_request(connection, principal.id, key, fingerprint, job_id, KIND, item["id"])
        return _read(connection, item)


def _merged_cues(source_cues, proposed):
    if [row.id for row in proposed] != [row["id"] for row in source_cues]:
        raise ValueError("La traducción debe incluir los mismos identificadores y el mismo orden.")
    merged = []
    for source, result in zip(source_cues, proposed, strict=True):
        lines = [plain_text(line) for line in result.text.split("\n")]
        text = "\n".join(line for line in lines if line)
        if not text:
            raise ValueError("Completá el texto de cada subtítulo.")
        overflow = len(text) > 72 or len(text) / (source["end"] - source["start"]) > 22
        merged.append({**source, "text": text, "overflow": overflow})
    return merged


def force_static(item):
    if item.get("translation_origin"):
        item["options"] = {**item["options"], "subtitle_highlight_enabled": False}
        item.pop("word_highlight", None)


def check_original(job, item, workspace):
    if _source_asset(job, workspace) != item["translation_origin"]["source_asset"]:
        raise HTTPException(409, "Cambió el original de la revisión fuente.")


def enforce_unchanged_timing(previous, item):
    def intervals(value):
        return [(cue["start"], cue["end"]) for cue in value["cues"]]

    if previous.get("translation_origin") and (
            (item["start"], item["end"], item["clip_file"], intervals(item)) !=
            (previous["start"], previous["end"], previous["clip_file"], intervals(previous))):
        raise HTTPException(422, "La variante traducida conserva el recorte y los tiempos de la revisión fuente.")


def save_draft(job_id, run_id, payload, principal, version):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        item = repo.document(job_id, KIND, run_id, connection)["payload"]
        stored = repo.document(job_id, "draft", run_id, connection, required=False)
        if stored:
            return stored["payload"]
        source = item["snapshot"]
        original = _source_asset(job, principal.workspace_id)
        if original != source["original"]:
            raise HTTPException(409, "Cambió el original de la revisión fuente.")
        descriptor = source["source"]
        try:
            rows = _merged_cues(source["cues"], payload.cues)
            cues = validate_cues(rows, round(descriptor["end"] - descriptor["start"], 3))
        except ValueError as exc:
            raise HTTPException(422, str(exc)) from None
        suffix = f" · {item['target_language'].upper()}"
        title = plain_text(payload.title) if payload.title else descriptor["title"][:120-len(suffix)] + suffix
        if not title:
            raise HTTPException(422, "Escribí un título para la variante.")
        now = time.time()
        origin = {"run_id": run_id, "source": descriptor, "source_language": item["source_language"],
                  "target_language": item["target_language"], "audio_language": item["audio_language"],
                  "source_content_sha256": source["content_sha256"], "source_asset": original,
                  "cue_ids": [row["id"] for row in rows]}
        if source.get("archive_selection"):
            origin["source_selection"] = source["archive_selection"]
        draft = {"id": run_id, "job_id": job_id, "revision": 1, "created_at": now, "updated_at": now,
                 "version": version, "title": title, "start": descriptor["start"], "end": descriptor["end"],
                 "clip_file": source["clip_file"], "options": {**source["options"], "burn_subtitles": True},
                 "cues": cues, "translation_origin": origin, "audio_language": item["audio_language"],
                 "subtitle_language": item["target_language"]}
        for key in ("logo", "style_template"):
            if key in source:
                draft[key] = source[key]
        force_static(draft)
        repo.insert_document(connection, job_id, "draft", draft)
        return draft


def _progress(task, item):
    with get_engine().begin() as connection:
        repo.worker_guard(connection, task)
        repo.update_document(connection, task["job_id"], KIND, item)


def execute_task(task, workspace):
    job_id = task["job_id"]
    item = repo.document(job_id, KIND, task["item_id"], live=True)["payload"]
    item.update(status="running", started_at=time.time())
    _progress(task, item)
    receipt = {}
    started = time.monotonic()
    try:
        job = repo.document(job_id, live=True)
        source = item["snapshot"]
        if _source_asset(job, workspace) != source["original"]:
            raise AIError("AI_SOURCE_UNAVAILABLE", "Cambió el original de la revisión autorizada.")
        config, content, _, token = _prepared(job_id, source, item["source_language"], item["target_language"], worker=True)
        if token != item["preview_fingerprint"]:
            raise AIError("AI_PREVIEW_STALE", "Cambió la configuración. Revisá el envío nuevamente.")
        item["provider_calls"] = 1
        _progress(task, item)
        answer, usage = request_selection(config, content, receipt=receipt)
        item.update(provider_responses=1, usage=usage or {})
        item["cues"] = _merged_cues(source["cues"], ProviderResult.model_validate(answer).cues)
        item["status"] = "completed"
    except AIError as exc:
        item.update(status="failed", error_code=exc.code, error=str(exc))
    except ValidationError:
        item.update(status="failed", error_code="AI_TRANSLATION_INVALID",
                    error="El proveedor no conservó los subtítulos esperados. Podés seguir editando manualmente.")
    except ValueError:
        item.update(status="failed", error_code="AI_TRANSLATION_INVALID",
                    error="El proveedor no conservó los identificadores o su orden. Podés seguir editando manualmente.")
    except HTTPException:
        item.update(status="failed", error_code="AI_SOURCE_UNAVAILABLE", error="El original ya no está disponible.")
    except Exception:
        item.update(status="failed", error_code="AI_INTERNAL_ERROR",
                    error="No se pudo terminar la traducción. Podés seguir editando manualmente.")
    if receipt.get("response_received"):
        item["provider_responses"] = 1
    item["provider_response_received"] = bool(item["provider_responses"])
    if model := receipt.get("model"):
        item["provider_models_received"].append(model)
    item.update(completed_at=time.time(), elapsed_seconds=round(time.monotonic() - started, 3))
    repo.finish_task(task, item, {})
