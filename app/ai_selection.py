"""Reviewable, opt-in selection runs against an existing transcript.

No mutation of original jobs/clips, no automatic render, no model-driven tools.
Preview -> explicit consent -> one bounded call -> validated proposals -> draft.
Single Uvicorn process, same processing lock as ASR/render. Local-only MVP.
"""
import copy
from datetime import datetime, timezone
import hashlib
import json
import math
import re
from threading import Thread
import time
import uuid
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, HTTPException, Query, Response
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from .ai_provider import (AIConfig, AIError, PROMPT_VERSION, SYSTEM_PROMPT, SELECTION_CONTRACT, MAX_ELIGIBLE_RANGES,
                          check_input_budget, get_config, request_selection)
from .editorial import EditorialContent
from .presentation import Presentation
from .state import write_json_atomic
from .subtitles import cues_from_segments, plain_text
from .workspace import backend, workspace_source, draft_path, read_draft, validate_content

router = APIRouter()
MAX_SEGMENTS = 2000
MAX_RUNS_PER_JOB = 100


class SelectionSpec(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: Literal["llm", "heuristic"] = "llm"
    brief: str = Field(default="Busca ideas completas, útiles y comprensibles sin el video completo.", max_length=800, strict=True)
    max_clips: int = Field(default=3, ge=1, le=5, strict=True)
    min_seconds: int = Field(default=20, ge=20, le=60, strict=True)
    max_seconds: int = Field(default=60, ge=20, le=60, strict=True)
    window_start: float = Field(default=0, ge=0, allow_inf_nan=False)
    window_end: float | None = Field(default=None, gt=0, allow_inf_nan=False)

    @field_validator("brief")
    @classmethod
    def clean_brief(cls, value):
        return plain_text(value)

    @model_validator(mode="after")
    def check_lengths(self):
        if self.min_seconds > self.max_seconds:
            raise ValueError("La duración mínima no puede superar la máxima.")
        return self


class SelectionCreate(SelectionSpec):
    preview_token: str = Field(pattern=r"^[0-9a-f]{64}$")
    request_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    consent: bool = Field(default=False, strict=True)


class ModelCandidate(BaseModel):
    model_config = ConfigDict(extra="forbid")
    range_id: str = Field(min_length=1, max_length=32, strict=True)
    title: str = Field(min_length=1, max_length=120, strict=True)
    reason: str = Field(min_length=1, max_length=600, strict=True)
    hook: int = Field(ge=1, le=5, strict=True)
    clarity: int = Field(ge=1, le=5, strict=True)
    completeness: int = Field(ge=1, le=5, strict=True)

    @field_validator("title", "reason")
    @classmethod
    def clean_words(cls, value):
        result = plain_text(value)
        if not result:
            raise ValueError("Empty text")
        return result


class ModelAnswer(BaseModel):
    model_config = ConfigDict(extra="forbid")
    summary: str = Field(max_length=800, strict=True)
    candidates: list[ModelCandidate] = Field(max_length=5)


def safe_error(exc: AIError, status=422):
    return HTTPException(status, f"[{exc.code}] {exc}")


def transcript_snapshot(folder: Path, duration: float) -> tuple[list[dict], str]:
    path = folder / "transcript.json"
    if not path.is_file():
        raise HTTPException(409, "No hay transcripción guardada. La selección por texto requiere un proyecto transcrito; el modo manual sigue disponible.")
    try:
        if path.is_symlink() or path.stat().st_size > 4 * 1024 * 1024:
            raise ValueError("Transcript file limit")
        raw = path.read_bytes()
        segments = json.loads(raw)
        if not isinstance(segments, list) or len(segments) > 50000:
            raise ValueError("Transcript type/size")
        result = []
        previous_start, previous_end = -1, -1
        for i, segment in enumerate(segments, 1):
            if not isinstance(segment, dict) or not isinstance(segment.get("text"), str):
                raise ValueError("Invalid segment")
            a, b = segment["start"], segment["end"]
            if (type(a) not in (int, float) or type(b) not in (int, float)
                    or not all(math.isfinite(v) for v in (a, b))
                    or a < 0 or b < a or b > duration + .05
                    or a < previous_start or b < previous_end):
                raise ValueError("Invalid times/order")
            previous_start, previous_end = a, b
            text = plain_text(segment["text"])
            if len(text) > 15000:
                raise ValueError("Segment too long")
            if text and b > a:
                result.append({"id": i, "start": round(a, 3), "end": round(min(b, duration), 3), "text": text})
        if not result:
            raise HTTPException(409, "La transcripción está vacía. No se inventarán palabras ni propuestas.")
        return result, hashlib.sha256(raw).hexdigest()
    except HTTPException:
        raise
    except (OSError, ValueError, KeyError, TypeError, OverflowError) as exc:
        raise HTTPException(409, "La transcripción guardada no tiene tiempos/texto válidos para analizar. El archivo se conserva; revisa el proyecto.") from exc


def eligible_ranges(selected: list[dict], minimum: int, maximum: int) -> list[dict]:
    """Exhaustive contiguous complete-segment intervals; never silently sample.

    Transcript times are millisecond-quantized before this call. Avoid float-boundary
    errors by computing durations in integers. A full range still needs editorial
    review: silence, meaning and image quality are not judged by this function.
    """
    result = []
    for i, first in enumerate(selected):
        for last in selected[i:]:
            ms = round(last["end"] * 1000) - round(first["start"] * 1000)
            if ms > maximum * 1000:
                break  # snapshot enforces monotonic segment ends
            if ms < minimum * 1000:
                continue
            result.append({"range_id": f"r{first['id']}_{last['id']}",
                           "start_segment": first["id"], "end_segment": last["id"],
                           "duration_seconds": ms / 1000})
            if len(result) > MAX_ELIGIBLE_RANGES:
                raise HTTPException(413, f"[AI_RANGE_CATALOG_TOO_LARGE] Hay más de {MAX_ELIGIBLE_RANGES} intervalos válidos. Reduce el tramo de análisis o estrecha las duraciones. No se truncó el catálogo ni se llamó al modelo.")
    if not result:
        raise HTTPException(422, "[AI_NO_ELIGIBLE_RANGES] No hay intervalos de segmentos completos con la duración solicitada. Amplía el tramo o ajusta las duraciones; no se llamó al modelo ni se consumió cuota local.")
    return result


def prepare(job_id: str, spec: SelectionSpec) -> dict:
    job, source, media = workspace_source(job_id)
    duration = media["duration_seconds"]
    segments, digest = transcript_snapshot(source.parent, duration)
    start = round(spec.window_start, 3)
    end = round(spec.window_end if spec.window_end is not None else duration, 3)
    if start >= end or end > duration + .001:
        raise HTTPException(422, "El tramo de análisis debe estar dentro del original y tener inicio menor que fin.")
    selected = [s for s in segments if s["start"] >= start and s["end"] <= end + .001]
    if not selected:
        raise HTTPException(422, "No hay segmentos completos dentro del tramo elegido. Amplía sus límites.")
    if len(selected) > MAX_SEGMENTS:
        raise HTTPException(413, f"El tramo contiene más de {MAX_SEGMENTS} segmentos. Analiza una parte menor; no se truncará la transcripción.")
    content = {"brief": spec.brief, "max_clips": spec.max_clips,
               "min_seconds": spec.min_seconds, "max_seconds": spec.max_seconds,
               "analysis_window": {"start": start, "end": end}, "segments": selected}
    if spec.mode == "llm":
        content["selection_contract"] = SELECTION_CONTRACT
        content["eligible_ranges"] = eligible_ranges(selected, spec.min_seconds, spec.max_seconds)
    try:
        config = get_config() if spec.mode == "llm" else AIConfig("disabled", "", "")
        if spec.mode == "llm" and config.provider == "disabled":
            raise AIError("AI_DISABLED", "La IA está desactivada. Configura un proveedor o usa «Comparación heurística local».")
        if spec.mode == "llm":
            budget = check_input_budget(config, content)
        else:
            size = len(json.dumps(content, ensure_ascii=False))
            if size > 120000:
                raise HTTPException(413, "El tramo supera el límite de texto local; selecciona una parte menor.")
            budget = {"request_chars": size, "request_bytes": len(json.dumps(content, ensure_ascii=False).encode()), "input_tokens_estimated": None}
    except AIError as exc:
        raise safe_error(exc, 409 if exc.code in {"AI_DISABLED", "AI_CONFIG_INVALID", "AI_KEY_REQUIRED", "AI_MODEL_REQUIRED"} else 413) from exc
    spec_dict = spec.model_dump()
    # Include source metadata to prevent using an old preview after input replacement.
    source_stat = source.stat()
    fingerprint = {"spec": spec_dict, "transcript": digest,
                   "source_size": source_stat.st_size, "source_mtime_ns": source_stat.st_mtime_ns,
                   "source_duration": duration, "config": config.fingerprint(), "prompt": PROMPT_VERSION}
    token = hashlib.sha256(json.dumps(fingerprint, sort_keys=True, ensure_ascii=False).encode()).hexdigest()
    coverage = round(sum(s["end"] - s["start"] for s in selected), 3)
    return {"job": job, "config": config, "segments": segments, "content": content,
            "spec": spec_dict, "preview_token": token, "transcript_sha256": digest,
            "source_fingerprint": {k: fingerprint[k] for k in ("source_size", "source_mtime_ns", "source_duration")},
            "budget": budget, "coverage": coverage,
            "source_duration": duration, "segment_count": len(selected), "total_segments": len(segments)}


def run_path(job_id: str, run_id: str) -> Path:
    service = backend()
    service.validate_job_id(job_id)
    if not re.fullmatch(r"[0-9a-f]{32}", run_id):
        raise HTTPException(404, "Análisis no encontrado")
    path = service.ROOT / job_id / "selections" / run_id
    if path.is_symlink() or path.parent.is_symlink():
        raise HTTPException(409, "No se admiten enlaces simbólicos en análisis.")
    return path / "selection.json"


def read_run(job_id: str, run_id: str) -> dict:
    path = run_path(job_id, run_id)
    try:
        with backend().LOCK:
            if path.is_symlink() or path.stat().st_size > 1024 * 1024:
                raise ValueError("Unsafe file")
            item = json.loads(path.read_text(encoding="utf-8"))
        if (not isinstance(item, dict) or item.get("id") != run_id or item.get("job_id") != job_id
                or item.get("status") not in {"running", "completed", "failed"}
                or not isinstance(item.get("candidates"), list)
                or not isinstance(item.get("baseline"), list)):
            raise ValueError("Invalid analysis state")
        return item
    except FileNotFoundError as exc:
        raise HTTPException(404, "Análisis no encontrado") from exc
    except (OSError, ValueError, TypeError) as exc:
        raise HTTPException(503, "No se pudo leer el análisis. El archivo se conserva; no se sustituye por resultados vacíos.") from exc


def persist_run(item: dict):
    with backend().LOCK:
        write_json_atomic(run_path(item["job_id"], item["id"]), item)


def build_candidate(segments: list[dict], first: int, last: int, title: str, reason: str,
                    criteria: dict | None, origin: str, position: int) -> dict:
    indexed = {s["id"]: i for i, s in enumerate(segments)}
    a, b = indexed[first], indexed[last]
    chosen = segments[a:b + 1]
    return {"id": str(position), "start_segment": first, "end_segment": last,
            "start": chosen[0]["start"], "end": chosen[-1]["end"],
            "duration": round(chosen[-1]["end"] - chosen[0]["start"], 3),
            "title": title, "reason": reason, "criteria": criteria, "origin": origin,
            "transcript_excerpt": " ".join(s["text"] for s in chosen),
            "context_before": " ".join(s["text"] for s in segments[max(0, a-2):a]),
            "context_after": " ".join(s["text"] for s in segments[b+1:b+3])}


def baseline_candidates(prepared: dict) -> list[dict]:
    spec, selected = prepared["spec"], prepared["content"]["segments"]
    results = []
    # Exact existing selection algorithm: this is a baseline, not a fake LLM.
    for clip in backend().select_clips(selected):
        first = next((s for s in selected if abs(s["start"] - clip["start"]) <= .011), None)
        last = next((s for s in reversed(selected) if abs(s["end"] - clip["end"]) <= .011), None)
        if not first or not last:
            continue
        length = round(last["end"] - first["start"], 3)
        if not spec["min_seconds"] <= length <= spec["max_seconds"]:
            continue
        results.append(build_candidate(prepared["segments"], first["id"], last["id"],
            f"Heurística local · propuesta {len(results)+1}",
            "Selector original: prioriza cantidad de palabras en ventanas de 20–60 s, sin evaluar significado ni usar el brief.",
            None, "heuristic", len(results)+1))
        if len(results) >= spec["max_clips"]:
            break
    return results


def validate_answer(data: dict, prepared: dict, diagnostics: dict | None = None) -> tuple[str, list[dict], list[str]]:
    """Accept only catalog references. Reject without repairing or using heuristics.

    Diagnostics retain safe structural/numeric facts, not raw provider bodies,
    response text, exception inputs or API keys. They survive the all-rejected case.
    """
    report = diagnostics if diagnostics is not None else {}
    report.update(contract=SELECTION_CONTRACT, eligible_ranges=len(prepared["content"].get("eligible_ranges", [])),
                  proposed_count=0, accepted_count=0, rejected_count=0, rejected=[], rejection_counts={})
    try:
        answer = ModelAnswer.model_validate(data)
    except ValueError as exc:
        report["schema_valid"] = False
        # Do not persist Pydantic input/context, unknown property names or messages.
        if hasattr(exc, "errors"):
            allowed = {"summary", "candidates", "range_id", "title", "reason", "hook", "clarity", "completeness"}
            report["schema_issues"] = [
                {"path": [v if type(v) is int or v in allowed else "unknown_field" for v in e["loc"]],
                 "type": e["type"]}
                for e in exc.errors(include_input=False, include_context=False, include_url=False)[:10]]
        raise AIError("AI_SCHEMA_INVALID", "La salida no cumple el contrato editorial de intervalos. Consulta el diagnóstico; no hubo sustitución ni reintento.", diagnostics=report) from exc
    report.update(schema_valid=True, proposed_count=len(answer.candidates))
    if len(answer.candidates) > prepared["spec"]["max_clips"]:
        raise AIError("AI_SCHEMA_INVALID", "El modelo excedió el número solicitado de propuestas. No se utilizará esa salida.", diagnostics=report)
    catalog = {r["range_id"]: r for r in prepared["content"].get("eligible_ranges", [])}
    allowed = {s["id"]: s for s in prepared["content"]["segments"]}
    accepted, warnings = [], []

    def reject(i: int, candidate: ModelCandidate, code: str, message: str, **details):
        label = candidate.range_id if re.fullmatch(r"r[1-9][0-9]{0,5}_[1-9][0-9]{0,5}", candidate.range_id) else "invalid_id"
        warnings.append(f"Propuesta {i} descartada [{code}]: {message}")
        report["rejected"].append({"proposal": i, "range_id": label, "code": code, **details})
        report["rejection_counts"][code] = report["rejection_counts"].get(code, 0) + 1
        report["rejected_count"] += 1

    for i, candidate in enumerate(answer.candidates, 1):
        interval = catalog.get(candidate.range_id)
        if interval is None:
            reject(i, candidate, "UNKNOWN_RANGE", "el ID no pertenece al catálogo autorizado.")
            continue
        a, b = allowed.get(interval["start_segment"]), allowed.get(interval["end_segment"])
        if not a or not b or b["id"] < a["id"]:
            reject(i, candidate, "INVALID_SEGMENTS", "los extremos no pertenecen al tramo autorizado.")
            continue
        length = (round(b["end"] * 1000) - round(a["start"] * 1000)) / 1000
        if not prepared["spec"]["min_seconds"] <= length <= prepared["spec"]["max_seconds"]:
            reject(i, candidate, "DURATION_OUT_OF_RANGE", f"duración {length:.3f} s; permitida {prepared['spec']['min_seconds']}–{prepared['spec']['max_seconds']} s.",
                   actual_seconds=length, min_seconds=prepared["spec"]["min_seconds"], max_seconds=prepared["spec"]["max_seconds"])
            continue
        prior = next((c for c in accepted if a["start"] < c["end"] and b["end"] > c["start"]), None)
        if prior:
            reject(i, candidate, "OVERLAP", f"se solapa con la propuesta aceptada {prior['id']} ({prior['start']:.3f}–{prior['end']:.3f} s).",
                   overlaps_candidate=prior["id"], start=a["start"], end=b["end"])
            continue
        item = build_candidate(prepared["segments"], a["id"], b["id"], candidate.title, candidate.reason,
                               {k: getattr(candidate, k) for k in ("hook", "clarity", "completeness")},
                               "llm", len(accepted)+1)
        item["range_id"] = candidate.range_id
        accepted.append(item)
    report["accepted_count"] = len(accepted)
    if answer.candidates and not accepted:
        raise AIError("AI_NO_VALID_CANDIDATES", "El modelo respondió, pero ninguna propuesta superó la validación local. Consulta el desglose de rechazos. No se cambiaron duraciones, modelo ni clips.",
                      warnings=warnings, diagnostics=report)
    return plain_text(answer.summary), accepted, warnings


def daily_calls_used() -> int:
    day = datetime.now(timezone.utc).date().isoformat()
    count = 0
    for path in backend().ROOT.glob("*/selections/*/selection.json"):
        try:
            item = read_run(path.parents[2].name, path.parent.name)
            if item.get("mode") == "llm" and item.get("day_utc") == day:
                count += 1  # Reserved runs count too; errors do not free quota.
        except HTTPException:
            # A corrupt record may represent a charged call; do not treat it as free.
            try:
                if datetime.fromtimestamp(path.stat().st_mtime, timezone.utc).date().isoformat() == day:
                    count += 1
            except OSError:
                count += 1
    return count


@router.get("/ai/config")
def public_config(response: Response):
    response.headers["Cache-Control"] = "no-store"
    try:
        config = get_config()
        result = config.public()
        result["reason"] = "Proveedor configurado. Esta consulta de configuración no prueba la conexión; cada análisis informa si recibió respuesta." if result["configured"] else "IA desactivada. Configura .env.ai y compose.ai.yaml para activarla. La comparación heurística local no necesita IA."
    except AIError as exc:
        result = {"configured": False, "provider": "invalid", "model": "", "external": False,
                  "reason": str(exc), "error_code": exc.code, "connection_tested": False}
    result["daily_used_utc"] = daily_calls_used()
    return result


@router.get("/jobs/{job_id}/selections/context")
def selection_context(job_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    _, source, media = workspace_source(job_id)
    try:
        segments, _ = transcript_snapshot(source.parent, media["duration_seconds"])
        return {"available": True, "duration": media["duration_seconds"],
                "segments": len(segments), "last_transcript_end": segments[-1]["end"],
                "note": "Solo se analiza texto guardado; no imágenes, música ni cambios de plano."}
    except HTTPException as exc:
        return {"available": False, "duration": media["duration_seconds"], "segments": 0, "note": exc.detail}


@router.post("/jobs/{job_id}/selections/preview")
def preview(job_id: str, request: SelectionSpec):
    prepared = prepare(job_id, request)
    config = prepared["config"]
    return {"preview_token": prepared["preview_token"], "spec": prepared["spec"],
            "provider": config.public() if request.mode == "llm" else {"provider": "heuristic", "model": "", "external": False, "destination": "Proceso local"},
            "prompt_version": PROMPT_VERSION, "system_instructions": SYSTEM_PROMPT if request.mode == "llm" else "No se envía nada a un modelo. Se ejecuta el selector heurístico original.",
            "payload_text": prepared["content"], "budget": prepared["budget"],
            "segment_count": prepared["segment_count"], "total_segments": prepared["total_segments"],
            "eligible_range_count": len(prepared["content"].get("eligible_ranges", [])),
            "source_duration": prepared["source_duration"], "segment_seconds": prepared["coverage"],
            "note": "Se incluyen solo segmentos completos dentro del tramo. No se ha contactado al proveedor ni generado video. La vista previa no equivale a tokens exactos."}


def process_selection(item: dict, prepared: dict):
    service = backend()
    started = time.monotonic()
    try:
        item["baseline"] = baseline_candidates(prepared)
        if item["mode"] == "heuristic":
            item["summary"] = "Comparación local: mismo selector de cantidad de palabras. No se utilizó IA y el brief no interviene."
            item["candidates"] = copy.deepcopy(item["baseline"])
            item["warnings"] = []
        else:
            # Record that transmission was attempted before network IO. Incomplete
            # runs after a crash may have incurred cost; never auto-retry them.
            item["request_started_at"] = time.time()
            persist_run(item)
            data, usage = request_selection(prepared["config"], prepared["content"])
            item["usage"] = usage
            item["provider_response_received"] = True
            item["response_received_at"] = time.time()
            item["validation"] = {}
            item["summary"], item["candidates"], item["warnings"] = validate_answer(data, prepared, item["validation"])
        item.update(status="completed", completed_at=time.time())
    except AIError as exc:
        item.update(status="failed", error_code=exc.code, error=str(exc))
        if exc.warnings:
            item["warnings"] = exc.warnings
        if exc.diagnostics is not None:
            item["validation"] = exc.diagnostics
        if exc.usage is not None:
            item["usage"] = exc.usage
        service.LOGGER.warning("Análisis %s: %s", item["id"], exc.code)
    except Exception:
        # No raw exception: provider exception strings may contain request data.
        item.update(status="failed", error_code="AI_INTERNAL_ERROR", error="El análisis no pudo completarse. Originales intactos; no hubo reintento automático.")
        service.LOGGER.warning("Análisis %s: fallo interno; datos sensibles omitidos", item["id"])
    finally:
        item["elapsed_seconds"] = round(time.monotonic() - started, 3)
        try:
            persist_run(item)
        except OSError:
            service.LOGGER.error("Análisis %s: no se pudo persistir el resultado; revisa disco", item["id"])
        finally:
            service.PROCESS_LOCK.release()


@router.post("/jobs/{job_id}/selections", status_code=202)
def create_selection(job_id: str, request: SelectionCreate):
    service = backend()
    service.load_job(job_id)
    spec = SelectionSpec.model_validate({k: getattr(request, k) for k in SelectionSpec.model_fields})
    # Idempotency: a network retry of this POST never launches a second paid call.
    with service.LOCK:
        path = run_path(job_id, request.request_id)
        if path.exists():
            existing = read_run(job_id, request.request_id)
            if existing.get("preview_token") != request.preview_token or existing.get("spec") != spec.model_dump():
                raise HTTPException(409, "Este ID ya corresponde a otro análisis. Prepara una vista previa nueva.")
            return existing
    if not request.consent:
        raise HTTPException(422, "Debes revisar y autorizar explícitamente esta solicitud.")
    prepared = prepare(job_id, spec)
    if prepared["preview_token"] != request.preview_token:
        raise HTTPException(409, "Cambió el texto, archivo, modelo o configuración después de la vista previa. Prepara y autoriza una nueva.")
    if not service.PROCESS_LOCK.acquire(blocking=False):
        raise HTTPException(409, "Hay un análisis, transcripción o render en curso. Espera a que termine; no se envió otra solicitud.")
    try:
        with service.LOCK:
            # Recheck after the lock to cover simultaneous duplicate submissions.
            if path.exists():
                existing = read_run(job_id, request.request_id)
                if existing.get("preview_token") != request.preview_token or existing.get("spec") != spec.model_dump():
                    raise HTTPException(409, "Este ID ya corresponde a otro análisis. Prepara una vista previa nueva.")
                service.PROCESS_LOCK.release()
                return existing
            if len(list(path.parent.parent.glob("*/selection.json"))) >= MAX_RUNS_PER_JOB:
                raise HTTPException(409, f"Este proyecto alcanzó {MAX_RUNS_PER_JOB} análisis guardados. No se iniciará otro.")
            if spec.mode == "llm" and daily_calls_used() >= prepared["config"].daily_limit:
                raise HTTPException(429, "Se alcanzó el límite local diario de consultas IA (día UTC). Los fallos también cuentan; no se enviará otra solicitud.")
            item = {"id": request.request_id, "job_id": job_id, "version": service.VERSION,
                    "status": "running", "mode": spec.mode, "spec": prepared["spec"],
                    "preview_token": request.preview_token, "transcript_sha256": prepared["transcript_sha256"],
                    "source_fingerprint": prepared["source_fingerprint"],
                    "prompt_version": PROMPT_VERSION,
                    "eligible_range_count": len(prepared["content"].get("eligible_ranges", [])),
                    "provider_response_received": False,
                    "provider": prepared["config"].provider if spec.mode == "llm" else "heuristic",
                    "model": prepared["config"].model, "created_at": time.time(),
                    "day_utc": datetime.now(timezone.utc).date().isoformat(), "consent_at": time.time(),
                    "budget": prepared["budget"], "segment_count": prepared["segment_count"],
                    "usage": None, "cost_usd": None, "candidates": [], "baseline": [], "warnings": []}
            persist_run(item)
        result = copy.deepcopy(item)
        Thread(target=process_selection, args=(item, prepared), daemon=True,
                         name=f"selection-{item['id']}").start()
        return result
    except Exception as exc:
        if 'item' in locals():
            item.update(status="failed", error_code="AI_START_FAILED", error="No se pudo iniciar el análisis; revisa disco o recursos. No se reintentó.")
            try:
                persist_run(item)
            except OSError:
                pass
        service.PROCESS_LOCK.release()
        if isinstance(exc, HTTPException):
            raise
        raise HTTPException(503, "No se pudo guardar o iniciar el análisis. No se enviaron solicitudes automáticamente.") from exc


@router.get("/jobs/{job_id}/selections")
def list_selections(job_id: str, response: Response, offset: int = Query(0, ge=0), limit: int = Query(10, ge=1, le=50)):
    service = backend()
    service.load_job(job_id)
    response.headers["Cache-Control"] = "no-store"
    items, unreadable = [], 0
    for path in (service.ROOT / job_id / "selections").glob("*/selection.json"):
        try:
            items.append(read_run(job_id, path.parent.name))
        except HTTPException:
            unreadable += 1
    items.sort(key=lambda v: (v.get("created_at", 0), v["id"]), reverse=True)
    return {"analyses": items[offset:offset+limit], "total": len(items), "has_more": len(items) > offset+limit,
            "unreadable": unreadable}


@router.get("/jobs/{job_id}/selections/{run_id}")
def get_selection(job_id: str, run_id: str, response: Response):
    response.headers["Cache-Control"] = "no-store"
    backend().load_job(job_id)
    return read_run(job_id, run_id)


@router.post("/jobs/{job_id}/selections/{run_id}/candidates/{candidate_id}/draft", status_code=201)
def candidate_to_draft(job_id: str, run_id: str, candidate_id: int):
    service = backend()
    item = read_run(job_id, run_id)
    if item["status"] != "completed":
        raise HTTPException(409, "El análisis no está completado.")
    candidate = next((c for c in item["candidates"] if c.get("id") == str(candidate_id)), None)
    if candidate is None:
        raise HTTPException(404, "Propuesta no encontrada")
    draft_id = uuid.uuid5(uuid.NAMESPACE_URL, f"clipforge:{job_id}:{run_id}:{candidate_id}").hex
    with service.LOCK:
        if draft_path(job_id, draft_id).exists():
            return read_draft(job_id, draft_id)  # Preserve any subsequent edits.
        job, source, media = workspace_source(job_id)
        segments, digest = transcript_snapshot(source.parent, media["duration_seconds"])
        stat = source.stat()
        fingerprint = {"source_size": stat.st_size, "source_mtime_ns": stat.st_mtime_ns,
                       "source_duration": media["duration_seconds"]}
        if digest != item.get("transcript_sha256") or fingerprint != item.get("source_fingerprint"):
            raise HTTPException(409, "El original o la transcripción cambió desde el análisis. Genera otra selección; no se reutilizan tiempos obsoletos.")
        indexed = {s["id"]: s for s in segments}
        try:
            a, b = indexed[candidate["start_segment"]], indexed[candidate["end_segment"]]
            if (candidate["start"] != a["start"] or candidate["end"] != b["end"]
                    or b["id"] < a["id"]):
                raise ValueError("Candidate mismatch")
            options = Presentation.model_validate(job.get("options", {}))
            payload = EditorialContent(title=candidate["title"], start=a["start"], end=b["end"],
                                       cues=cues_from_segments(segments, a["start"], b["end"]), options=options)
            content = validate_content(job_id, payload)
        except (ValueError, KeyError, TypeError) as exc:
            raise HTTPException(409, "La propuesta guardada no tiene límites o texto válidos. No se creará un borrador.") from exc
        now = time.time()
        draft = {**content, "id": draft_id, "job_id": job_id, "revision": 1,
                 "created_at": now, "updated_at": now, "version": service.VERSION,
                 "selection_origin": {"analysis_id": run_id, "candidate_id": str(candidate_id),
                                      "mode": item["mode"], "provider": item["provider"], "model": item["model"]}}
        try:
            write_json_atomic(draft_path(job_id, draft_id), draft)
        except OSError as exc:
            raise HTTPException(503, "No se pudo guardar el borrador. Los originales se conservan.") from exc
        return copy.deepcopy(draft)


def mark_interrupted_selections():
    for path in backend().ROOT.glob("*/selections/*/selection.json"):
        try:
            item = read_run(path.parents[2].name, path.parent.name)
            if item["status"] == "running":
                item.update(status="failed", error_code="AI_INTERRUPTED",
                            error="Análisis interrumpido por reinicio. No se reintentará automáticamente; una solicitud externa podría haberse facturado.")
                persist_run(item)
        except (HTTPException, OSError):
            backend().LOGGER.warning("Se conserva un análisis ilegible al reiniciar")
