"""Validated editorial ranges and subtitle retiming; no ASR, network or rendering."""
import math
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator
from .presentation import Cue, Presentation
from .subtitles import SubtitleError, cues_from_segments, plain_text, validate_cues

MIN_CLIP_SECONDS = 1.0
MAX_CLIP_SECONDS = 60.0


class EditorialContent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(default="Nuevo clip", min_length=1, max_length=120)
    clip_file: str | None = Field(default=None, pattern=r"^clip_\d{2}\.mp4$")
    start: float = Field(ge=0, allow_inf_nan=False)
    end: float = Field(gt=0, allow_inf_nan=False)
    options: Presentation = Field(default_factory=Presentation)
    cues: list[Cue] = Field(default_factory=list, max_length=400)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        value = plain_text(value)
        if not value:
            raise ValueError("Escribe un nombre para el clip.")
        return value


class DraftUpdate(EditorialContent):
    revision: int = Field(ge=1, strict=True)


class RevisionRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    revision: int = Field(ge=1, strict=True)


class ProjectName(BaseModel):
    model_config = ConfigDict(extra="forbid")
    title: str = Field(min_length=1, max_length=120)

    @field_validator("title")
    @classmethod
    def clean_title(cls, value: str) -> str:
        return EditorialContent.clean_title(value)


class RangeChange(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: float = Field(ge=0, allow_inf_nan=False)
    end: float = Field(gt=0, allow_inf_nan=False)
    previous_start: float | None = Field(default=None, ge=0, allow_inf_nan=False)
    previous_end: float | None = Field(default=None, gt=0, allow_inf_nan=False)
    cues: list[Cue] = Field(default_factory=list, max_length=400)


def validate_range(start: float, end: float, source_duration: float) -> tuple[float, float]:
    """Times in absolute source seconds, rounded to milliseconds (not frame IDs)."""
    if not all(math.isfinite(x) for x in (start, end, source_duration)) or source_duration <= 0:
        raise ValueError("No se pudo determinar una duración finita del original.")
    start, end = round(start, 3), round(end, 3)
    if start < 0 or end > source_duration + .001:
        raise ValueError(f"El rango debe estar dentro del original: 0–{source_duration:.3f} s.")
    duration = round(end - start, 3)
    if not MIN_CLIP_SECONDS <= duration <= MAX_CLIP_SECONDS:
        raise ValueError("Selecciona un fragmento de entre 1 y 60 segundos (inicio < fin).")
    return start, end


def retime_cues(cues: list[dict[str, Any]], previous_start: float | None,
                previous_end: float | None, start: float, end: float,
                segments: list[dict[str, Any]]) -> tuple[list[dict[str, Any]], dict[str, int]]:
    """Keep edited cues in overlap; fill only newly exposed time from transcript.

    Deletions/gaps inside the old range stay deleted. A cut caption keeps its full
    text: segment-level timestamps cannot tell which words survived a cut.
    """
    duration = round(end - start, 3)
    if previous_start is None and previous_end is None:
        if cues:
            raise SubtitleError("Indica los límites anteriores para conservar los subtítulos enviados.")
        out = cues_from_segments(segments, start, end)
        return out, {"preserved": 0, "trimmed": 0, "removed": 0, "added": len(out)}
    if previous_start is None or previous_end is None:
        raise SubtitleError("Indica ambos límites anteriores o ninguno.")
    old_cues = validate_cues(cues, round(previous_end - previous_start, 3))
    result, stats = [], {"preserved": 0, "trimmed": 0, "removed": 0, "added": 0}
    for cue in old_cues:
        absolute_start = previous_start + cue["start"]
        absolute_end = previous_start + cue["end"]
        a, b = max(start, absolute_start), min(end, absolute_end)
        if round(b - a, 3) < .04:
            stats["removed"] += 1
            continue
        result.append({"start": round(a - start, 3), "end": round(b - start, 3), "text": cue["text"]})
        stats["preserved"] += 1
        if a > absolute_start + .001 or b < absolute_end - .001:
            stats["trimmed"] += 1
    # Do not refill deletions within the user's previous selection.
    for left, right in ((start, min(end, previous_start)), (max(start, previous_end), end)):
        if right - left < .04:
            continue
        for cue in cues_from_segments(segments, left, right):
            result.append({**cue, "start": round(cue["start"] + left - start, 3),
                           "end": round(cue["end"] + left - start, 3)})
            stats["added"] += 1
    result.sort(key=lambda cue: (cue["start"], cue["end"]))
    return validate_cues(result, duration), stats
