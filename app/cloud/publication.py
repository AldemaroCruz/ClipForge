"""Revision-pinned publication text and consented, text-only suggestions."""
from datetime import datetime, timezone
import hashlib
import math
import re
import time
import uuid

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from ..ai_provider import (AIError, PUBLICATION_CONTRACT, PUBLICATION_PROMPT_VERSION,
                           PUBLICATION_SYSTEM_PROMPT, check_input_budget, request_selection)
from ..auth_db import get_engine
from ..subtitles import plain_text
from . import clip_captions, editorial_selection, repository as repo

DOCUMENT = "publication"
SUGGESTION = "publication_ai"
MAX_RUNS_PER_JOB = 100
LANGUAGE = r"^(?:auto|[A-Za-z]{2,3}(?:-[A-Za-z]{2,8}){0,2})$"
EXTERNAL_LINK = re.compile(r"(?:https?://|www\.)[^\s<>]+", re.I)
NUMBER = re.compile(r"(?<!\w)\d+(?:[.,]\d+)*(?!\w)")


def description_text(value):
    return "\n".join(plain_text(line) for line in value.splitlines()).strip()


def normalized_tags(values):
    result, seen = [], set()
    for value in values:
        tag = "#" + value.strip().removeprefix("#")
        if not re.fullmatch(r"#[^\W_][\w]{0,38}", tag):
            raise ValueError("Usá hashtags breves con letras, números o guion bajo.")
        key = tag.casefold()
        if key not in seen:
            seen.add(key)
            result.append(tag)
    return result


class TargetRequest(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    selection: str = Field(min_length=1, max_length=110)


class PreviewRequest(TargetRequest):
    language: str | None = Field(default=None, pattern=LANGUAGE)
    instructions: str = Field(default="", max_length=600)

    @field_validator("instructions")
    @classmethod
    def clean_instructions(cls, value):
        return plain_text(value)


class SuggestionRequest(PreviewRequest):
    preview_token: str = Field(pattern=r"^[a-f0-9]{64}$")
    request_id: str = Field(pattern=r"^[a-f0-9]{32}$")
    consent: bool = False
    new_attempt: bool = False


class SaveRequest(TargetRequest):
    revision: int = Field(ge=0, le=10**18)
    language: str | None = Field(default=None, pattern=LANGUAGE)
    title: str = Field(default="", max_length=120)
    description: str = Field(default="", max_length=1000)
    hashtags: list[str] = Field(default_factory=list, max_length=8)
    suggestion_id: str | None = Field(default=None, pattern=r"^[a-f0-9]{32}$")

    @field_validator("title", "description", "hashtags")
    @classmethod
    def clean_texts(cls, value, info):
        if info.field_name == "hashtags":
            return normalized_tags(value)
        return description_text(value) if info.field_name == "description" else plain_text(value)

    @model_validator(mode="after")
    def needs_text(self):
        if not (self.title or self.description or self.hashtags):
            raise ValueError("Escribí un título, descripción o hashtag para guardar.")
        return self


class ReuseRequest(TargetRequest):
    revision: int = Field(ge=0, le=10**18)
    source_selection: str = Field(min_length=1, max_length=110)
    source_revision: int = Field(ge=1, le=10**18)


class SuggestionTexts(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    titles: list[str] = Field(min_length=1, max_length=3)
    description: str = Field(min_length=1, max_length=500)
    hashtags: list[str] = Field(max_length=6)

    @field_validator("titles", "description", "hashtags")
    @classmethod
    def clean_response(cls, value, info):
        if info.field_name == "hashtags":
            return normalized_tags(value)
        if info.field_name == "description":
            if normalized := description_text(value):
                return normalized
            raise ValueError("Missing description")
        titles = [plain_text(title) for title in value]
        if any(not 1 <= len(title) <= 120 for title in titles):
            raise ValueError("Invalid title")
        unique = {}
        for title in titles:
            unique.setdefault(title.casefold(), title)
        return list(unique.values())


def digest(value):
    return hashlib.sha256(repo.packed(value).encode()).hexdigest()


def _asset(item):
    return {key: item[key] for key in ("generation", "sha256", "md5") if key in item}


def _cues(rows, duration):
    result = []
    for row in rows:
        start, end = row["start"], row["end"]
        if any(type(value) not in {int, float} or not math.isfinite(value) for value in (start, end)):
            raise HTTPException(409, "Los tiempos de los subtítulos de esta exportación no son válidos.")
        start, end = max(0, round(start, 3)), min(duration, round(end, 3))
        text = plain_text(row["text"])
        if start < end and text:
            result.append({"start": float(start), "end": float(end), "text": text})
    return result


def content_hash(original, start, end, captions, transcript=None):
    return digest([original, float(start), float(end), captions if captions else {"source_transcript": transcript or {}}])


def _resolve(connection, job, selection, workspace):
    # The archive resolver enforces the same completed/current media boundary.
    from . import clip_package

    chosen = clip_package._parse([selection])[0]
    project, manifest = job["payload"], job["manifest"]
    job_id = project["id"]
    if project.get("status") != "completed" or "input.mp4" not in manifest:
        raise HTTPException(409, "Necesitás un clip finalizado para preparar sus textos.")
    origin = {}
    if chosen.filename:
        assets = clip_captions.selected_output(job, chosen.filename, chosen.revision, chosen.output_id, connection)
        automatic = clip_captions._clip(job, chosen.filename)
        variant_id = clip_captions._settings(project, automatic).get("export_id")
        item = ({**automatic, **repo.document(job_id, "export", variant_id, connection)["payload"]}
                if variant_id else automatic)
        title = automatic.get("title", "")
        kind = "automatic"
    else:
        export = repo.document(job_id, "export", chosen.output_id, connection, required=False)
        if not export:
            raise HTTPException(404, "Exportación no disponible.")
        kind, assets = clip_package._completed_export(export)
        if export["revision"] != chosen.revision or export["payload"].get("id") != chosen.output_id or not assets:
            raise HTTPException(409, "Cambió la exportación. Actualizá la lista y volvé a seleccionarla.")
        item = export["payload"]
        title = item.get("title", "")
        origin = item.get("selection_origin", {})
        if origin.get("mode") == "transcript":
            kind = "transcript"
    translation_origin = item.get("translation_origin", {})
    for asset_kind, value in assets.items():
        clip_package._validate_object(value, asset_kind, f"workspaces/{workspace}/jobs/{job_id}/")
    try:
        start, end = (float(item[key]) for key in ("start", "end"))
        source_duration = float(project["media"]["duration_seconds"])
        if not 0 <= start < end <= source_duration or end - start > 60.001:
            raise ValueError("Invalid range")
        captions = _cues(item.get("cues", []), round(end - start, 3))
        original = _asset(manifest["input.mp4"])
        transcript = _asset(manifest.get("transcript.json", {}))
        if origin.get("transcript_sha256") and origin["transcript_sha256"] != transcript.get("sha256"):
            # The exact earlier text can be taken from rendered cues, even if
            # the current source transcript differs from its prior provenance.
            transcript = {key: origin[key] for key in ("transcript_sha256", "transcript_generation") if key in origin}
            transcript = {key.removeprefix("transcript_"): value for key, value in transcript.items()}
        compatible_transcript = bool(transcript) and transcript == _asset(manifest.get("transcript.json", {}))
        context = "subtitles" if captions else "transcript" if compatible_transcript else None
        language = translation_origin.get("target_language") or project.get("language") or "auto"
        language = language.lower() if re.fullmatch(LANGUAGE, language) else "auto"
        identity = {"selection": selection, "source": original, "start": start, "end": end,
                    "transcript": transcript, "media": {name: _asset(value) for name, value in assets.items()}}
        for key in ("transcript_version", "alignment_sha256", "alignment_generation", "draft_revision"):
            if (value := origin.get(key, item.get(key))) is not None:
                identity[key] = value
        content = content_hash(original, start, end, captions, transcript)
    except (KeyError, TypeError, ValueError, OverflowError):
        raise HTTPException(409, "La fuente de esta exportación no se pudo verificar.") from None
    target = {"kind": kind, "title": plain_text(title)[:120] if isinstance(title, str) else "",
              "title_source": "automatic_title" if chosen.filename else "export_title", "language": language,
              "start": start, "end": end, "has_content": context is not None, "context_source": context}
    resolved = {"target": target, "binding": identity, "content_sha256": content, "cues": captions}
    if translation_origin:
        resolved["translation_source_content_sha256"] = translation_origin["source_content_sha256"]
    return resolved


def _by_selection(connection, job_id, selection):
    return repo.document(job_id, DOCUMENT, digest(selection)[:32], connection, required=False)


def saved_for_selection(connection, job_id, selection):
    document = _by_selection(connection, job_id, selection)
    return document["payload"] if document else None


def text_bytes(saved):
    tags = " ".join(saved["hashtags"])
    return f"Título\n{saved['title']}\n\nDescripción\n{saved['description']}\n\nHashtags\n{tags}\n".encode("utf-8")


def _current_saved(connection, job_id, selection, resolved):
    saved = saved_for_selection(connection, job_id, selection)
    if saved and saved["content_sha256"] != resolved["content_sha256"]:
        raise HTTPException(409, "Cambió el contenido guardado de esta exportación. Actualizá la lista.")
    return saved


def _reusable(source, resolved):
    return source["content_sha256"] in {resolved["content_sha256"], resolved.get("translation_source_content_sha256")}


def index(job_id, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        ready = []
        for row in repo.list_documents(job_id, DOCUMENT, connection):
            saved = row["payload"]
            try:
                resolved = _resolve(connection, job, saved["selection"], principal.workspace_id)
            except HTTPException:
                continue
            if resolved["content_sha256"] == saved["content_sha256"]:
                ready.append({"selection": saved["selection"], "revision": saved["revision"]})
    return {"saved": ready}


def read(job_id, selection, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        resolved = _resolve(connection, job, selection, principal.workspace_id)
        saved = _current_saved(connection, job_id, selection, resolved)
        previous = [row["payload"] for row in repo.list_documents(job_id, DOCUMENT, connection)]
        suggestions = [row["payload"] for row in repo.list_documents(job_id, SUGGESTION, connection)
                       if row["payload"]["selection"] == selection
                       and row["payload"]["content_sha256"] == resolved["content_sha256"]]
    reusable = []
    for row in previous:
        if row["selection"] == selection or not _reusable(row, resolved):
            continue
        entry = {key: row[key] for key in ("selection", "revision", "title")}
        if row["content_sha256"] != resolved["content_sha256"]:
            entry.update(language=row["language"], translated_subtitles=True)
        reusable.append(entry)
    suggestion = max(suggestions, key=lambda row: (row["created_at"], row["id"])) if suggestions else None
    return {"selection": selection, "target": resolved["target"], "content_sha256": resolved["content_sha256"],
            "saved": saved, "suggestion": suggestion, "reusable": reusable, "provider": editorial_selection.config_status()}


def _language(language, target):
    return target["language"] if language in {None, "auto"} else language.lower()


def _prepared(job, resolved, language, instructions, *, worker=False):
    target = resolved["target"]
    clip_text = resolved["cues"]
    if target["context_source"] == "transcript":
        source = editorial_selection.source_identity(job)
        start, end = target["start"], target["end"]
        # A straddling segment has no word-boundary evidence for the excluded
        # words. Send only complete segments inside this clip in the fallback.
        clip_text = [{"start": round(row["start"] - start, 3), "end": round(row["end"] - start, 3), "text": row["text"]}
                     for row in editorial_selection.transcript_segments(job, source)
                     if start <= row["start"] < row["end"] <= end]
    if not clip_text:
        raise AIError("AI_NO_PUBLICATION_CONTENT", "No hay texto verificable dentro de este recorte. Podés escribir los textos manualmente.")
    config, config_id = editorial_selection.provider_config(worker=worker)
    language = _language(language, target)
    content = {"selection_contract": PUBLICATION_CONTRACT, "language": language, "instructions": instructions,
               "prior_title": target["title"], "context_source": target["context_source"], "clip_text": clip_text}
    budget = check_input_budget(config, content)
    token = digest([job["payload"]["id"], resolved["binding"], resolved["content_sha256"], config_id,
                    PUBLICATION_PROMPT_VERSION, content])
    return {"config": config, "language": language, "content": content, "budget": budget, "preview_token": token}


def _prepare_http(job, resolved, language, instructions):
    try:
        return _prepared(job, resolved, language, instructions)
    except AIError as exc:
        code = {"AI_INPUT_TOO_LARGE": 413, "AI_NO_PUBLICATION_CONTENT": 422}.get(exc.code, 409)
        raise HTTPException(code, f"[{exc.code}] {exc}") from None


def preview(job_id, payload, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        resolved = _resolve(connection, job, payload.selection, principal.workspace_id)
    prepared = _prepare_http(job, resolved, payload.language, payload.instructions)
    return {"selection": payload.selection, "content_sha256": resolved["content_sha256"],
            "language": prepared["language"], "preview_token": prepared["preview_token"],
            "provider": prepared["config"].public(), "payload_text": prepared["content"],
            "system_instructions": PUBLICATION_SYSTEM_PROMPT, "prompt_version": PUBLICATION_PROMPT_VERSION,
            "budget": {**prepared["budget"], "provider_calls": 1}}


def _previous_suggestion(connection, job_id, previous, payload, resolved):
    item = repo.document(job_id, SUGGESTION, previous["item_id"], connection)["payload"]
    if (item["language"] != _language(payload.language, resolved["target"])
            or item["instructions"] != payload.instructions):
        raise HTTPException(409, "Cambió el idioma o la configuración. Revisá un nuevo envío.")
    return item


def suggest(job_id, payload, principal):
    if not payload.consent:
        raise HTTPException(422, "Revisá y autorizá explícitamente el envío al proveedor.")
    operation = [SUGGESTION, job_id, payload.selection, payload.preview_token,
                 payload.request_id if payload.new_attempt else None]
    key = digest(operation)
    fingerprint = key
    with repo.request_transaction(principal.id, key, fingerprint) as (connection, previous, _):
        job = repo.beta_document(connection, principal, job_id)
        resolved = _resolve(connection, job, payload.selection, principal.workspace_id)
        if previous:
            return _previous_suggestion(connection, job_id, previous, payload, resolved)
    prepared = _prepare_http(job, resolved, payload.language, payload.instructions)
    if payload.preview_token != prepared["preview_token"]:
        raise HTTPException(409, "Cambió el contenido, el idioma o la configuración. Revisá un nuevo envío.")
    with repo.request_transaction(principal.id, key, fingerprint) as (connection, previous, key):
        current = repo.beta_document(connection, principal, job_id)
        now_target = _resolve(connection, current, payload.selection, principal.workspace_id)
        if previous:
            return _previous_suggestion(connection, job_id, previous, payload, now_target)
        if now_target != resolved:
            raise HTTPException(409, "Cambió la exportación. Revisá un nuevo envío.")
        config = prepared["config"]
        day = datetime.now(timezone.utc).date().isoformat()
        repo.admit_beta(connection, principal.id)
        repo.admit_selection(connection, job_id, day, 1, config.daily_limit, MAX_RUNS_PER_JOB, kind=SUGGESTION)
        now = time.time()
        item = {"id": uuid.uuid4().hex, "job_id": job_id, "selection": payload.selection,
                "status": "queued", "pilot": True, "day_utc": day, "created_at": now, "consent_at": now,
                "content_sha256": resolved["content_sha256"], "binding": resolved["binding"],
                "preview_token": payload.preview_token, "language": prepared["language"], "instructions": payload.instructions,
                "prompt_version": PUBLICATION_PROMPT_VERSION, "provider": config.provider, "model": config.model,
                "titles": [], "description": "", "hashtags": [], "provider_calls_planned": 1,
                "provider_calls": 0, "provider_responses": 0, "provider_response_received": False,
                "provider_models_received": [], "usage": {}}
        repo.insert_document(connection, job_id, SUGGESTION, item)
        repo.enqueue(connection, job_id, SUGGESTION, item["id"])
        repo.remember_request(connection, principal.id, key, fingerprint, job_id, SUGGESTION, item["id"])
    return item


def _save(connection, job_id, resolved, revision, fields):
    selection = resolved["binding"]["selection"]
    previous = _current_saved(connection, job_id, selection, resolved)
    if revision != (previous["revision"] if previous else 0):
        raise HTTPException(409, "Cambió la revisión guardada. Volvé a abrirla antes de guardar.")
    item = {"id": digest(selection)[:32], "job_id": job_id, "revision": revision + 1, "selection": selection,
            "content_sha256": resolved["content_sha256"], "binding": resolved["binding"],
            "saved_at": time.time(), **fields}
    if previous:
        repo.update_document(connection, job_id, DOCUMENT, item, revision)
    else:
        repo.insert_document(connection, job_id, DOCUMENT, item)
    return item


def save(job_id, payload, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        resolved = _resolve(connection, job, payload.selection, principal.workspace_id)
        fields = payload.model_dump(include={"title", "description", "hashtags", "suggestion_id"}, exclude_none=True)
        fields["language"] = _language(payload.language, resolved["target"])
        if payload.suggestion_id is not None:
            run = repo.document(job_id, SUGGESTION, payload.suggestion_id, connection, required=False)
            item = run["payload"] if run else {}
            if (item.get("status") != "completed" or item.get("selection") != payload.selection
                    or item.get("content_sha256") != resolved["content_sha256"]):
                raise HTTPException(409, "La sugerencia no corresponde a esta versión del clip.")
        return _save(connection, job_id, resolved, payload.revision, fields)


def reuse(job_id, payload, principal):
    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
        resolved = _resolve(connection, job, payload.selection, principal.workspace_id)
        source = saved_for_selection(connection, job_id, payload.source_selection)
        if (not source or payload.source_selection == payload.selection or source["revision"] != payload.source_revision
                or not _reusable(source, resolved)):
            raise HTTPException(409, "Los textos se pueden reutilizar en una exportación con el mismo contenido o en su traducción vinculada.")
        fields = {key: source[key] for key in ("language", "title", "description", "hashtags")}
        fields["reused_from"] = {key: source[key] for key in ("selection", "revision", "content_sha256")}
        if source["content_sha256"] != resolved["content_sha256"]:
            fields["reused_from"]["translated_subtitles"] = True
        return _save(connection, job_id, resolved, payload.revision, fields)


def _validated_suggestions(data, content):
    try:
        texts = SuggestionTexts.model_validate(data).model_dump()
    except ValidationError:
        raise AIError("AI_PUBLICATION_INVALID", "La respuesta no cumple el formato de sugerencias. Podés continuar manualmente.") from None
    source = " ".join([row["text"] for row in content["clip_text"]] + [content["instructions"]])
    result = " ".join([*texts["titles"], texts["description"]])
    source_links = {link.rstrip(".,;!?)]}").casefold() for link in EXTERNAL_LINK.findall(source)}
    proposed_links = {link.rstrip(".,;!?)]}").casefold() for link in EXTERNAL_LINK.findall(result)}
    if not proposed_links <= source_links or not set(NUMBER.findall(result)) <= set(NUMBER.findall(source)):
        raise AIError("AI_PUBLICATION_UNSUPPORTED", "Las sugerencias contienen cifras o enlaces sin respaldo en el recorte o tus indicaciones.")
    return texts


def _progress(task, item):
    with get_engine().begin() as connection:
        repo.worker_guard(connection, task)
        repo.update_document(connection, task["job_id"], SUGGESTION, item)


def execute_task(task, workspace):
    job_id = task["job_id"]
    item = repo.document(job_id, SUGGESTION, task["item_id"])["payload"]
    item.update(status="running", started_at=time.time())
    _progress(task, item)
    receipt = {}
    started = time.monotonic()
    try:
        with get_engine().connect() as connection:
            job = repo.document(job_id, connection=connection, live=True)
            resolved = _resolve(connection, job, item["selection"], workspace)
        plan = _prepared(job, resolved, item["language"], item["instructions"], worker=True)
        if plan["preview_token"] != item["preview_token"]:
            raise AIError("AI_PREVIEW_STALE", "Cambió la exportación o la configuración. Prepará una nueva revisión del envío.")
        item["provider_calls"] = 1
        _progress(task, item)
        data, usage = request_selection(plan["config"], plan["content"], receipt=receipt)
        item.update(provider_responses=1, usage=usage or {})
        item.update(_validated_suggestions(data, plan["content"]), status="completed")
    except AIError as exc:
        item.update(status="failed", error_code=exc.code, error=str(exc))
    except HTTPException:
        item.update(status="failed", error_code="AI_SOURCE_UNAVAILABLE",
                    error="El clip no está disponible en la revisión autorizada. Podés conservar tus textos manuales.")
    except Exception:
        item.update(status="failed", error_code="AI_INTERNAL_ERROR",
                    error="No se pudieron generar sugerencias. Podés continuar con la edición manual.")
    if receipt.get("response_received"):
        item["provider_responses"] = 1
    item["provider_response_received"] = bool(item["provider_responses"])
    if actual_model := receipt.get("model"):
        item["provider_models_received"].append(actual_model)
    item.update(completed_at=time.time(), elapsed_seconds=round(time.monotonic() - started, 3))
    repo.finish_task(task, item, {})
