"""Generation-pinned source transcript views and continuous clip selections."""
import hashlib
import json
import math
import re

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..editorial import MAX_CLIP_SECONDS, MIN_CLIP_SECONDS, validate_range
from ..subtitles import cues_from_segments, plain_text
from . import editorial_selection, repository as repo, storage


SIDECAR = "transcript-words.json"
METHOD = "faster-whisper-word-timestamps"
MAX_SIDECAR_BYTES = 4 * 1024 * 1024
VERSION_PATTERN = r"^[a-f0-9]{64}$"
ANCHOR_PATTERN = r"^(?:s[1-9][0-9]{0,4}|w[1-9][0-9]{0,4}\.[1-9][0-9]{0,3})$"


class AlignmentRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    retry: bool = Field(default=False, strict=True)


class TranscriptClip(BaseModel):
    model_config = ConfigDict(extra="forbid")
    version: str = Field(pattern=VERSION_PATTERN)
    first: str = Field(pattern=ANCHOR_PATTERN)
    last: str = Field(pattern=ANCHOR_PATTERN)


def alignment_record(job, identity, connection=None):
    payload, manifest = job["payload"], job["manifest"]
    embedded = payload.get("transcript_alignment") or {}
    if embedded.get("source_fingerprint") == identity and SIDECAR in manifest:
        return embedded, manifest[SIDECAR]
    record = repo.alignment_document(payload["id"], identity, connection)
    if record:
        return record["payload"], record["manifest"].get(SIDECAR)
    return {}, None


def _sidecar(item):
    size = item["bytes"]
    if type(size) is not int or not 0 < size <= MAX_SIDECAR_BYTES:
        raise ValueError("Invalid alignment size")
    response = storage.open_object(item)
    try:
        raw = bytearray()
        for part in response.iter_content(65536):
            raw.extend(part)
            if len(raw) > size:
                raise ValueError("Alignment size mismatch")
    finally:
        storage.close(response)
    if len(raw) != size or hashlib.sha256(raw).hexdigest() != item["sha256"]:
        raise ValueError("Alignment integrity mismatch")
    data = json.loads(raw)
    if (not isinstance(data, dict) or data.get("schema") != 1 or data.get("method") != METHOD
            or not isinstance(data.get("model_revision"), str)
            or not re.fullmatch(r"[a-f0-9]{40}", data["model_revision"])
            or not isinstance(data.get("transcriber_version"), str)
            or not re.fullmatch(r"[A-Za-z0-9._+-]{1,40}", data["transcriber_version"])):
        raise ValueError("Invalid alignment provenance")
    return data


def _bounds(row, duration):
    values = row["start"], row["end"]
    if (not all(type(value) in {int, float} and math.isfinite(value) for value in values)
            or not 0 <= values[0] < values[1] <= duration):
        raise ValueError("Invalid alignment time")
    start, end = (round(value, 3) for value in values)
    end = min(end, math.floor(duration * 1000) / 1000)
    if start >= end:
        raise ValueError("Alignment outside the original")
    return start, end


def _words(rows, segment, index, source_duration, raw_end):
    if not isinstance(rows, list) or not 1 <= len(rows) <= 1000:
        return []
    words = []
    previous_end = segment["start"]
    try:
        for position, row in enumerate(rows, 1):
            start, end = _bounds(row, source_duration)
            text = plain_text(row["text"])
            if start < previous_end or row["end"] > raw_end or not 1 <= len(text) <= 160:
                return []
            words.append({"id": f"w{index}.{position}", "start": start, "end": end, "text": text})
            previous_end = end
    except (KeyError, TypeError, ValueError):
        return []
    # Faster Whisper merges punctuation into adjacent words. Ignore spacing
    # when checking the coverage of the audio-derived word list against its row.
    def compact(value):
        return "".join(value.split())

    if "".join(compact(word["text"]) for word in words) != compact(segment["text"]):
        return []
    return words


def _aligned(rows, duration):
    if not isinstance(rows, list) or not 1 <= len(rows) <= editorial_selection.MAX_TRANSCRIPT_SEGMENTS:
        raise ValueError("Invalid alignment segments")
    segments = []
    previous_start = previous_end = 0
    for index, row in enumerate(rows, 1):
        start, end = _bounds(row, duration)
        text = plain_text(row["text"])
        if start < previous_start or end < previous_end or not 1 <= len(text) <= 15000:
            raise ValueError("Invalid alignment segment")
        segment = {"id": f"s{index}", "start": start, "end": end, "text": text}
        segment["words"] = _words(row.get("words"), segment, index, duration, row["end"])
        segments.append(segment)
        previous_start, previous_end = start, end
    return segments


def version_id(job_id, identity, sidecar=None):
    reference = [job_id, identity["source_generation"], identity["transcript_generation"],
                 identity["transcript_sha256"], identity["source_duration"]]
    if sidecar:
        reference.extend((sidecar["generation"], sidecar["sha256"]))
    return hashlib.sha256(repo.packed(reference).encode()).hexdigest()


def _comparison(segments):
    return [(row["id"], row["start"], row["end"], row["text"]) for row in segments]


def snapshot(job):
    identity = editorial_selection.source_identity(job)
    job_id = job["payload"]["id"]
    source = editorial_selection.transcript_segments(job, identity)
    original = [{**row, "id": f"s{row['id']}", "words": []} for row in source]
    base = {"id": version_id(job_id, identity), "method": "segments", "alternate": False,
            "segments": original, "label": "Transcripción original por segmentos"}
    versions = [base]
    default = base["id"]
    record, sidecar = alignment_record(job, identity)
    status = {"completed": "ready", "queued": "queued", "running": "running", "failed": "failed"}.get(
        record.get("status"), "not_prepared",
    )
    partial = False
    if sidecar and status == "ready":
        try:
            data = _sidecar(sidecar)
            aligned = _aligned(data["segments"], identity["source_duration"])
        except (KeyError, TypeError, ValueError, storage.StorageError):
            status, partial = "failed", True
        else:
            alternate = _comparison(aligned) != _comparison(original)
            partial = any(not row["words"] for row in aligned)
            version = {"id": version_id(job_id, identity, sidecar), "method": METHOD, "alternate": alternate,
                       "segments": aligned, "partial": partial, "model_revision": data["model_revision"],
                       "transcriber_version": data["transcriber_version"],
                       "alignment_generation": sidecar["generation"], "alignment_sha256": sidecar["sha256"],
                       "label": "Transcripción alineada adicional" if alternate else "Transcripción con tiempos por palabra"}
            versions.append(version)
            if not alternate and any(row["words"] for row in aligned):
                default = version["id"]
    elif status == "ready":
        status, partial = "failed", True
    return {"job_id": job_id, "source_url": f"/jobs/{job_id}/source", "source_duration": identity["source_duration"],
            "min_seconds": MIN_CLIP_SECONDS, "max_seconds": MAX_CLIP_SECONDS, "alignment_status": status,
            "retryable": bool(record.get("retryable")) and status == "failed", "partial": partial,
            "default_version": default, "versions": versions}, identity


def find_version(view, version):
    result = next((row for row in view["versions"] if row["id"] == version), None)
    if result is None:
        raise HTTPException(409, "La versión de la transcripción cambió. Volvé a abrirla.")
    return result


def _anchor(segments, reference, *, final=False):
    for index, segment in enumerate(segments):
        words = segment["words"]
        if segment["id"] == reference:
            return index, max(0, len(words) - 1) if final else 0, segment
        for position, word in enumerate(words):
            if word["id"] == reference:
                return index, position, word
    raise HTTPException(422, "No se encontró una referencia de la selección.")


def resolve(view, identity, request):
    version = find_version(view, request.version)
    segments = version["segments"]
    first, word_start, left = _anchor(segments, request.first)
    last, word_end, right = _anchor(segments, request.last, final=True)
    if (first, word_start) > (last, word_end):
        raise ValueError("Marcá un final posterior al inicio de la selección.")
    start, end = validate_range(left["start"], right["end"], identity["source_duration"])
    selected = []
    for index in range(first, last + 1):
        row = segments[index]
        words = row["words"]
        begin = word_start if index == first else 0
        stop = word_end + 1 if index == last else len(words)
        if words and (begin or stop != len(words)):
            chosen = words[begin:stop]
            selected.append({"start": chosen[0]["start"], "end": chosen[-1]["end"],
                             "text": " ".join(word["text"] for word in chosen)})
        else:
            selected.append(row)
    cues = cues_from_segments(selected, start, end)
    origin = {"mode": "transcript", "transcript_version": version["id"], "method": version["method"],
              "first": request.first, "last": request.last, "start": start, "end": end, **identity}
    for key in ("alignment_generation", "alignment_sha256", "model_revision", "transcriber_version"):
        origin[key] = version.get(key)
    return start, end, cues, origin
