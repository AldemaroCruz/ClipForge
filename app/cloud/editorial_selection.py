"""Prepare and execute a consented, text-only selection on the durable pilot queue."""

from bisect import bisect_left, bisect_right
from datetime import datetime, timezone
import hashlib
import json
import math
import os
import re
import time
import uuid

from fastapi import HTTPException

from ..ai_provider import (AIError, PROMPT_VERSION, SELECTION_CONTRACT, SYSTEM_PROMPT,
                           check_input_budget, get_config, request_selection)
from ..ai_selection import MAX_RUNS_PER_JOB, SelectionSpec, validate_answer
from ..auth_db import get_engine
from ..subtitles import plain_text
from . import repository as repo
from . import storage
from .config import BETA_MAX_SECONDS

MAX_TRANSCRIPT_BYTES = 4 * 1024 * 1024
MAX_TRANSCRIPT_SEGMENTS = 12000
MAX_CATALOG = 180
MIN_TARGET_CATALOG = 24
MAX_CALLS = 8
MAX_PROVIDER_SECONDS = 600


def provider_config(*, worker=False):
    try:
        config = get_config(require_api_key=worker)
    except AIError as exc:
        if exc.code == "AI_KEY_REQUIRED":
            raise AIError(exc.code, "El servicio de IA de INT aún no tiene una credencial válida.") from None
        raise
    revision = os.getenv("CLIPFORGE_AI_CONFIG_REVISION", "").strip()
    if config.provider == "disabled":
        raise AIError("AI_DISABLED", "La selección por IA está desactivada en INT. Podés usar los clips automáticos y el editor.")
    if config.provider != "openai" or not re.fullmatch(r"[1-9][0-9]{0,18}", revision):
        raise AIError("AI_CONFIG_INVALID", "El proveedor de INT aún no tiene una configuración de servidor válida.")
    public_fingerprint = {"config": config.fingerprint(include_key=False), "revision": revision}
    return config, hashlib.sha256(repo.packed(public_fingerprint).encode()).hexdigest()


def config_status():
    try:
        config, _ = provider_config()
    except AIError as exc:
        return {"enabled": False, "configured": False, "connection_tested": False,
                "provider": "disabled" if exc.code == "AI_DISABLED" else "invalid",
                "error_code": exc.code, "reason": str(exc)}
    return {**config.public(), "enabled": True,
            "reason": "Proveedor configurado. Cada análisis confirma si el modelo respondió."}


def source_identity(job):
    item, manifest = job["payload"], job["manifest"]
    source, transcript = manifest.get("input.mp4"), manifest.get("transcript.json")
    duration = item.get("media", {}).get("duration_seconds")
    if item.get("pilot") is not True or item.get("status") != "completed" or not source or not transcript:
        raise HTTPException(409, "Necesitás un trabajo del piloto completado con transcripción guardada.")
    if type(duration) not in {int, float} or not math.isfinite(duration) or not 0 < duration <= BETA_MAX_SECONDS:
        raise HTTPException(409, "El original no tiene una duración válida para analizar.")
    return {"source_generation": source["generation"], "transcript_generation": transcript["generation"],
            "transcript_sha256": transcript["sha256"], "source_duration": duration}


def transcript_segments(job, identity):
    transcript = job["manifest"]["transcript.json"]
    if not 0 < transcript["bytes"] <= MAX_TRANSCRIPT_BYTES:
        raise HTTPException(409, "La transcripción guardada supera el límite del editor.")
    try:
        response = storage.open_object(transcript)
        try:
            chunks = bytearray()
            for chunk in response.iter_content(65536):
                if len(chunks) + len(chunk) > transcript["bytes"]:
                    raise ValueError("Transcript size")
                chunks.extend(chunk)
        finally:
            storage.close(response)
        if len(chunks) != transcript["bytes"] or hashlib.sha256(chunks).hexdigest() != identity["transcript_sha256"]:
            raise ValueError("Transcript integrity")
        rows = json.loads(chunks)
        if not isinstance(rows, list) or len(rows) > MAX_TRANSCRIPT_SEGMENTS:
            raise ValueError("Transcript shape")
        duration_ms = math.floor(identity["source_duration"] * 1000)
        result = []
        previous_start = previous_end = -1
        for index, row in enumerate(rows, 1):
            start, end = row["start"], row["end"]
            if (type(start) not in {float, int} or type(end) not in {float, int}
                    or not all(math.isfinite(value) for value in (start, end)) or end < start):
                raise ValueError("Transcript timestamp")
            start = max(0, round(start * 1000))
            end = min(duration_ms, round(end * 1000))
            words = plain_text(row["text"])
            if len(words) > 15000 or (start < previous_start or end < previous_end):
                # Overlapping starts are valid, but catalogue search and context
                # require canonical increasing boundaries.
                raise ValueError("Transcript order or segment size")
            if start < end and words:
                result.append({"id": index, "start": start / 1000, "end": end / 1000, "text": words})
                previous_start, previous_end = start, end
        if not result:
            raise HTTPException(409, "La transcripción guardada está vacía.")
        return result
    except storage.StorageError:
        raise HTTPException(503, "No se pudo leer la transcripción privada. Podés intentarlo de nuevo.") from None
    except (KeyError, TypeError, ValueError, OverflowError):
        raise HTTPException(409, "La transcripción guardada no pasó la validación de tiempos o integridad.") from None


def evenly_spaced(ranges, count):
    return [ranges[i * (len(ranges) - 1) // (count - 1)] for i in range(count)]


def catalog(segments, ends, start, stop, spec):
    """Build valid complete-segment options, evenly distributed across starts."""
    ranges = []
    for index in range(start, stop):
        first = segments[index]
        millis = round(first["start"] * 1000)
        left = bisect_left(ends, millis + spec.min_seconds * 1000, lo=index)
        right = bisect_right(ends, millis + spec.max_seconds * 1000, lo=left)
        for endpoint in sorted({left, (left + right - 1) // 2, right - 1}) if left < right else ():
            last = segments[endpoint]
            ranges.append({"range_id": f"r{first['id']}_{last['id']}", "start_segment": first["id"],
                           "end_segment": last["id"], "duration_seconds": (ends[endpoint] - millis) / 1000})
    if len(ranges) <= MAX_CATALOG:
        return ranges
    return evenly_spaced(ranges, MAX_CATALOG)


def planned_windows(segments, spec, duration, config):
    starts = [round(row["start"] * 1000) for row in segments]
    ends = [round(row["end"] * 1000) for row in segments]
    batches = []

    def plan(start, stop):
        choices = catalog(segments, ends, start, stop, spec)
        if not choices:
            return
        if len(batches) >= MAX_CALLS:
            raise AIError("AI_INPUT_TOO_LARGE", "El análisis completo supera la cantidad de solicitudes permitida.")
        # The primary intervals partition the time axis. Context extends on
        # both sides so ranges near a partition can reach their natural end.
        window_start = 0 if start == 0 else segments[start]["start"]
        window_end = duration if stop == len(segments) else segments[stop]["start"]
        left = bisect_left(ends, starts[start] - 15000)
        right = bisect_right(starts, starts[stop - 1] + spec.max_seconds * 1000)
        selected = segments[left:right]
        content = {"brief": spec.brief, "max_clips": spec.max_clips, "min_seconds": spec.min_seconds,
                   "max_seconds": spec.max_seconds, "analysis_window": {"start": selected[0]["start"],
                                                                         "end": selected[-1]["end"]},
                   "segments": selected, "selection_contract": SELECTION_CONTRACT, "eligible_ranges": choices}
        while True:
            try:
                budget = check_input_budget(config, content)
                break
            except AIError as exc:
                if exc.code != "AI_INPUT_TOO_LARGE":
                    raise
                if len(choices) > MIN_TARGET_CATALOG:
                    choices = evenly_spaced(choices, max(MIN_TARGET_CATALOG, len(choices) // 2))
                    content["eligible_ranges"] = choices
                    continue
                if stop - start <= 1:
                    raise
                middle = (start + stop) // 2
                plan(start, middle)
                plan(middle, stop)
                return
        batches.append({"content": content, "budget": budget, "summary": {
            "start": window_start, "end": window_end, "segments": len(selected), "eligible_ranges": len(choices),
        }})

    plan(0, len(segments))
    if not batches:
        raise AIError("AI_NO_ELIGIBLE_RANGES", "No hay intervalos válidos de la duración pedida. Ajustá las duraciones.")
    covered = {row["id"] for batch in batches for row in batch["content"]["segments"]}
    if covered != {row["id"] for row in segments} or len(batches) * (config.timeout + 10) > MAX_PROVIDER_SECONDS:
        raise AIError("AI_INPUT_TOO_LARGE", "La configuración actual no permite analizar toda la transcripción dentro del presupuesto.")
    return batches


def prepare(job, spec, *, worker=False):
    if spec.mode != "llm" or spec.window_start != 0 or spec.window_end is not None:
        raise HTTPException(422, "La selección por IA de INT usa la transcripción completa del trabajo.")
    config, config_id = provider_config(worker=worker)
    identity = source_identity(job)
    segments = transcript_segments(job, identity)
    batches = planned_windows(segments, spec, identity["source_duration"], config)
    spec_data = {**spec.model_dump(), "window_start": 0.0}
    payload_hash = hashlib.sha256(repo.packed([batch["content"] for batch in batches]).encode()).hexdigest()
    token = hashlib.sha256(repo.packed({"job_id": job["payload"]["id"], "identity": identity,
                                       "spec": spec_data, "config": config_id,
                                       "prompt": PROMPT_VERSION, "payload": payload_hash}).encode()).hexdigest()
    return {"config": config, "identity": identity, "segments": segments, "spec": spec_data,
            "batches": batches, "preview_token": token}


def prepare_request(job, spec):
    try:
        return prepare(job, spec)
    except AIError as exc:
        status = 413 if exc.code == "AI_INPUT_TOO_LARGE" else 422 if exc.code == "AI_NO_ELIGIBLE_RANGES" else 409
        raise HTTPException(status, f"[{exc.code}] {exc}") from None


def context(job):
    try:
        identity = source_identity(job)
        segments = transcript_segments(job, identity)
    except HTTPException as exc:
        return {"available": False, "segments": 0, "note": exc.detail}
    return {"available": True, "duration": identity["source_duration"], "segments": len(segments),
            "last_transcript_end": segments[-1]["end"],
            "note": "El proveedor recibe texto de la transcripción, intervalos candidatos y el objetivo editorial."}


def preview(job, spec):
    prepared = prepare_request(job, spec)
    batches = prepared["batches"]
    payloads = [batch["content"] for batch in batches]
    payload_text = payloads[0] if len(payloads) == 1 else {
        "segments": prepared["segments"], "chunks": payloads,
        "analysis_window": {"start": 0, "end": prepared["identity"]["source_duration"]},
    }
    count = len(prepared["segments"])
    return {"preview_token": prepared["preview_token"], "provider": prepared["config"].public(),
            "spec": prepared["spec"], "prompt_version": PROMPT_VERSION, "system_instructions": SYSTEM_PROMPT,
            "payload_text": payload_text, "segment_count": count, "total_segments": count,
            "source_duration": prepared["identity"]["source_duration"],
            "eligible_range_count": sum(len(payload["eligible_ranges"]) for payload in payloads),
            "analysis_windows": [batch["summary"] for batch in batches],
            "budget": {"provider_calls": len(batches),
                       "request_chars": sum(batch["budget"]["request_chars"] for batch in batches),
                       "request_bytes": sum(batch["budget"]["request_bytes"] for batch in batches)},
            "note": "Vista previa del texto que se enviará con tu consentimiento. Aún no se llamó al proveedor."}


def create(job_id, request, principal):
    if not request.consent:
        raise HTTPException(422, "Debes revisar y autorizar explícitamente esta solicitud.")
    spec = SelectionSpec.model_validate(request.model_dump(include=set(SelectionSpec.model_fields)))
    fingerprint = hashlib.sha256(repo.packed({"kind": "selection", "job_id": job_id,
                                             "request": request.model_dump()}).encode()).hexdigest()
    # Duplicate submissions return the committed run before rereading GCS or
    # checking a changed provider configuration. Another session still needs ownership.
    with repo.request_transaction(principal.id, request.request_id, fingerprint) as (c, previous, key):
        job = repo.beta_document(c, principal, job_id)
        if previous:
            return repo.document(job_id, "selection", previous["item_id"], c)["payload"]
    prepared = prepare_request(job, spec)
    if request.preview_token != prepared["preview_token"]:
        raise HTTPException(409, "Cambió el original, el objetivo o la configuración. Prepará y autorizá una nueva vista previa.")
    with repo.request_transaction(principal.id, request.request_id, fingerprint) as (c, previous, key):
        current = repo.beta_document(c, principal, job_id)
        if previous:
            return repo.document(job_id, "selection", previous["item_id"], c)["payload"]
        if source_identity(current) != prepared["identity"]:
            raise HTTPException(409, "Cambió la transcripción. Prepará y autorizá una nueva vista previa.")
        repo.admit_beta(c, principal.id)
        day = datetime.now(timezone.utc).date().isoformat()
        batches = prepared["batches"]
        config = prepared["config"]
        repo.admit_selection(c, job_id, day, len(batches), config.daily_limit, MAX_RUNS_PER_JOB)
        now = time.time()
        item = {"id": uuid.uuid4().hex, "job_id": job_id, "status": "queued", "mode": "llm",
                "pilot": True, "spec": prepared["spec"], "preview_token": request.preview_token,
                "source_fingerprint": prepared["identity"], "transcript_sha256": prepared["identity"]["transcript_sha256"],
                "provider": config.provider, "model": config.model, "prompt_version": PROMPT_VERSION,
                "day_utc": day, "created_at": now, "consent_at": now, "provider_calls_planned": len(batches),
                "provider_calls": 0, "provider_responses": 0, "provider_response_received": False,
                "provider_elapsed_seconds": 0.0, "provider_call_intervals": [],
                "provider_models_received": [],
                "analysis_windows": [batch["summary"] for batch in batches],
                "segment_count": len(prepared["segments"]), "last_transcript_end": prepared["segments"][-1]["end"],
                "candidates": [], "summary": "", "warnings": [], "usage": {}}
        repo.insert_document(c, job_id, "selection", item)
        repo.enqueue(c, job_id, "selection", item["id"])
        repo.remember_request(c, principal.id, key, fingerprint, job_id, "selection", item["id"])
    return item


def combine_proposals(candidates, maximum):
    ordered = sorted(candidates, key=lambda item: (
        -sum(item["criteria"].values()), -item["criteria"]["completeness"], -item["criteria"]["clarity"],
        item["start"], item["end"],
    ))
    selected = []
    for item in ordered:
        if any(item["start"] < other["end"] and item["end"] > other["start"] for other in selected):
            continue
        selected.append({**item, "id": str(len(selected) + 1)})
        if len(selected) == maximum:
            break
    return selected


def _progress(task, item):
    with get_engine().begin() as connection:
        repo.worker_guard(connection, task)
        repo.update_document(connection, task["job_id"], "selection", item)


def execute_task(task):
    job_id = task["job_id"]
    item = repo.document(job_id, "selection", task["item_id"])["payload"]
    call_intervals = item.setdefault("provider_call_intervals", [])
    started = time.monotonic()
    item.update(status="running", started_at=time.time())
    _progress(task, item)
    try:
        prepared = prepare(repo.document(job_id), SelectionSpec.model_validate(item["spec"]), worker=True)
        if (item["preview_token"] != prepared["preview_token"] or
                item["provider_calls_planned"] != len(prepared["batches"])):
            raise AIError("AI_PREVIEW_STALE", "Cambió el original o la configuración. Prepará y autorizá una nueva vista previa.")
        possible, summaries, invalid = [], [], None
        for batch in prepared["batches"]:
            item["provider_calls"] += 1
            _progress(task, item)
            receipt = {}
            call_started_at = time.time()
            call_started = time.monotonic()
            try:
                data, usage = request_selection(prepared["config"], batch["content"], receipt=receipt)
            finally:
                call_elapsed = time.monotonic() - call_started
                item["provider_elapsed_seconds"] = round(item["provider_elapsed_seconds"] + call_elapsed, 3)
            call_intervals.append({"started_at": call_started_at, "finished_at": call_started_at + call_elapsed})
            item["provider_responses"] += 1
            item["provider_response_received"] = True
            actual_model = receipt.get("model")
            if actual_model is not None and actual_model not in item["provider_models_received"]:
                item["provider_models_received"].append(actual_model)
            for key, value in (usage or {}).items():
                item["usage"][key] = item["usage"].get(key, 0) + value
            try:
                summary, candidates, warnings = validate_answer(data, {**prepared, "content": batch["content"]})
            except AIError as exc:
                if exc.code != "AI_NO_VALID_CANDIDATES":
                    raise
                invalid = exc
                item["warnings"].extend(exc.warnings)
            else:
                possible.extend(candidates)
                summaries.append(summary)
                item["warnings"].extend(warnings)
            _progress(task, item)
        item["candidates"] = combine_proposals(possible, item["spec"]["max_clips"])
        if invalid and not summaries:
            raise invalid
        item["summary"] = " ".join(filter(None, summaries))[:800]
        if len(item["candidates"]) < item["spec"]["max_clips"]:
            item["warnings"].append(
                f"Se obtuvieron {len(item['candidates'])} propuestas válidas sin solapamientos para este objetivo.")
        item["status"] = "completed"
    except AIError as exc:
        item.update(status="failed", error_code=exc.code, error=str(exc))
    except HTTPException as exc:
        item.update(status="failed", error_code="AI_SOURCE_UNAVAILABLE", error=exc.detail)
    except Exception:
        item.update(status="failed", error_code="AI_INTERNAL_ERROR",
                    error="El análisis se interrumpió. Prepará y autorizá una nueva solicitud para volver a intentar.")
    item.update(completed_at=time.time(), elapsed_seconds=round(time.monotonic() - started, 3))
    repo.finish_task(task, item, {})
