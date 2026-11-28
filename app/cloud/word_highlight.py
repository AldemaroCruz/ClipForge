"""Resolve subtitle highlights from exact generation-pinned acoustic marks."""
from bisect import bisect_left
import re
import unicodedata

from fastapi import HTTPException
from pydantic import BaseModel, ConfigDict, Field

from ..editorial import validate_range
from ..presentation import Cue
from ..subtitles import validate_cues
from . import editorial_selection, repository as repo, storage, transcript_selection

METHOD = transcript_selection.METHOD


class HighlightRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: float = Field(ge=0, allow_inf_nan=False)
    end: float = Field(gt=0, allow_inf_nan=False)
    cues: list[Cue] = Field(max_length=400)
    version: str | None = Field(default=None, pattern=transcript_selection.VERSION_PATTERN)


def centiseconds(value):
    return round(value * 100) / 100


def _lexical(text):
    value = unicodedata.normalize("NFC", text).casefold()
    # Ignore punctuation around words and case changes, preserving spelling,
    # diacritics and punctuation inside the lexical word.
    return re.sub(r"^\W+|\W+$", "", value)


def _tokens(text):
    return [(value, match) for match in re.finditer(r"\S+", text)
            if (value := _lexical(match.group(0)))]


def provenance(job_id, identity, item):
    return {"method": METHOD, "version": transcript_selection.version_id(job_id, identity, item),
            "alignment_generation": item["generation"], "alignment_sha256": item["sha256"]}


def load(job):
    """Read private data outside project mutation locks."""
    try:
        identity = editorial_selection.source_identity(job)
    except HTTPException:
        return {"alignment_status": "not_prepared"}
    record, asset = transcript_selection.alignment_record(job, identity)
    status = {"completed": "ready", "queued": "queued", "running": "running",
              "failed": "failed"}.get(record.get("status"), "not_prepared")
    if status != "ready" or not asset:
        return {"alignment_status": "failed" if status == "ready" else status,
                "retryable": bool(record.get("retryable"))}
    try:
        parsed = transcript_selection._sidecar(asset)
        segments = transcript_selection._aligned(parsed["segments"], identity["source_duration"])
        binding = provenance(job["payload"]["id"], identity, asset)
    except (KeyError, TypeError, ValueError, storage.StorageError):
        return {"alignment_status": "failed"}
    return {"alignment_status": "ready", "segments": segments, "identity": identity, **binding}


def load_for_owner(job_id, principal):
    from ..auth_db import get_engine

    with get_engine().begin() as connection:
        job = repo.beta_document(connection, principal, job_id)
    return load(job)


def current(job, loaded, connection=None):
    if loaded.get("alignment_status") != "ready":
        return loaded
    try:
        identity = editorial_selection.source_identity(job)
    except HTTPException:
        return {"alignment_status": "failed", "reason": "alignment_changed"}
    _, asset = transcript_selection.alignment_record(job, identity, connection)
    if (identity != loaded.get("identity") or not asset
            or asset.get("sha256") != loaded.get("alignment_sha256")
            or asset.get("generation") != loaded.get("alignment_generation")):
        return {"alignment_status": "failed", "reason": "alignment_changed"}
    return loaded


def local_alignment(raw, source_duration):
    """Apply the same canonical reader to a new worker's pre-upload sidecar."""
    if not raw:
        return {"alignment_status": "not_prepared"}
    try:
        segments = transcript_selection._aligned(raw["segments"], source_duration)
    except (KeyError, TypeError, ValueError):
        return {"alignment_status": "failed"}
    return {"alignment_status": "ready", "segments": segments, "method": METHOD}


def from_snapshot(view, identity):
    aligned = next((version for version in view["versions"] if version["method"] == METHOD), None)
    if aligned is None:
        return {"alignment_status": view["alignment_status"], "retryable": view.get("retryable", False)}
    return {"alignment_status": "ready", "identity": identity, "version": aligned["id"],
            **{key: aligned[key] for key in ("segments", "method", "alignment_sha256", "alignment_generation")}}


def selected_version(item):
    if version := item.get("word_highlight", {}).get("version"):
        return version
    origin = item.get("selection_origin", {})
    return origin.get("transcript_version") if origin.get("method") == METHOD else None


def plan(cues, start, end, alignment, *, version=None):
    # Use timed word midpoints to establish the exact audible word sequence
    # for a cue, including repeated occurrences. Do not guess a subsequence
    # after manual deletions, insertions, or changes to ordering.
    mismatched_version = version is not None and version != alignment.get("version")
    segments = [] if mismatched_version else alignment.get("segments", [])
    incomplete = [segment for segment in segments if not segment["words"]]
    source = []
    for segment in segments:
        source.extend((word, lexical) for word in segment["words"] if (lexical := _lexical(word["text"])))
    source.sort(key=lambda item: (item[0]["start"] + item[0]["end"]) / 2)
    centers = [(word["start"] + word["end"]) / 2 for word, _ in source]
    rows = []
    for index, cue in enumerate(cues):
        local_a = centiseconds(cue["start"])
        local_b = centiseconds(min(cue["end"], end - start))
        row = {"index": index, "text": cue["text"], "start": local_a, "end": local_b, "words": []}
        rows.append(row)
        a, b = start + cue["start"], min(end, start + cue["end"])
        if not segments or any(segment["start"] < b and a < segment["end"] for segment in incomplete):
            continue
        actual = source[bisect_left(centers, a):bisect_left(centers, b)]
        tokens = _tokens(cue["text"])
        if not tokens or [key for _, key in actual] != [key for key, _ in tokens]:
            continue
        words = []
        previous_end = local_a
        for (word, _), (_, token) in zip(actual, tokens):
            left = max(local_a, centiseconds(max(0, word["start"] - start)))
            right = min(local_b, centiseconds(min(end, word["end"]) - start))
            if not previous_end <= left < right <= local_b:
                break
            words.append({"id": word["id"], "text": token.group(0), "start": left, "end": right,
                          "offset_start": token.start(), "offset_end": token.end()})
            previous_end = right
        if len(words) == len(tokens):
            row["words"] = words
    count = sum(bool(row["words"]) for row in rows)
    status = "ready" if rows and count == len(rows) else "partial" if count else "unavailable"
    reason = alignment.get("reason")
    if status != "ready":
        if mismatched_version:
            reason = "alignment_changed"
        elif alignment["alignment_status"] == "ready":
            reason = "unmatched_cues"
        else:
            reason = reason or alignment["alignment_status"]
    binding = {key: alignment.get(key) for key in ("method", "version", "alignment_generation", "alignment_sha256")}
    if mismatched_version:
        binding.update(version=version, method=METHOD, alignment_generation=None, alignment_sha256=None)
    return {"status": status, "alignment_status": alignment["alignment_status"], "reason": reason,
            "retryable": bool(alignment.get("retryable")) and not mismatched_version,
            "timing": "centiseconds", "cues": rows, **binding}


def attach(item, alignment, *, version=None):
    if item["options"].get("subtitle_highlight_enabled"):
        item["word_highlight"] = plan(item["cues"], item["start"], item["end"], alignment, version=version)
    else:
        item.pop("word_highlight", None)


def preview(job, payload):
    try:
        start, end = validate_range(payload.start, payload.end, job["payload"]["media"]["duration_seconds"])
        cues = validate_cues([row.model_dump() for row in payload.cues], round(end - start, 3))
    except (KeyError, ValueError, TypeError) as error:
        raise HTTPException(422, str(error)) from None
    return plan(cues, start, end, load(job), version=payload.version)
