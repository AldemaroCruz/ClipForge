"""Clip-local subtitles, with bounded text/times and no user-supplied ASS markup.

Long ASR segments are split by text length using approximate timing within the
segment, NOT word timestamps. Editors can correct times before exporting.
"""
import html
import math
import re
import textwrap
from typing import Any

from .presentation import Presentation


class SubtitleError(ValueError):
    pass


def plain_text(value: str) -> str:
    # Remove control characters, including bidirectional formatting controls.
    text = re.sub(r"[\x00-\x08\x0b-\x1f\x7f\u202a-\u202e\u2066-\u2069]", "", value)
    return " ".join(text.split())


def validate_cues(cues: list[dict[str, Any]], duration: float) -> list[dict[str, Any]]:
    if not isinstance(cues, list) or len(cues) > 400:
        raise SubtitleError("Se admiten como máximo 400 subtítulos por clip.")
    result = []
    previous_end = 0.0
    total = 0
    for index, cue in enumerate(cues, 1):
        try:
            start, end = float(cue["start"]), float(cue["end"])
            text = plain_text(cue["text"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SubtitleError(f"Subtítulo {index}: formato inválido.") from exc
        if not all(math.isfinite(t) for t in (start, end)):
            raise SubtitleError(f"Subtítulo {index}: tiempo no finito.")
        start, end = round(start, 3), round(end, 3)
        if start < 0 or end > duration + 0.001 or end - start < 0.04:
            raise SubtitleError(f"Subtítulo {index}: usa 0 ≤ inicio < fin ≤ {duration:.3f} s (mínimo 0.04 s).")
        if start < previous_end - 0.001:
            raise SubtitleError(f"Subtítulo {index}: los tiempos deben estar ordenados y no solaparse.")
        if not text or len(text) > 500:
            raise SubtitleError(f"Subtítulo {index}: escribe entre 1 y 500 caracteres.")
        total += len(text)
        if total > 50000:
            raise SubtitleError("El texto total supera 50 000 caracteres.")
        result.append({"start": start, "end": min(end, duration), "text": text})
        previous_end = end
    return result


def cues_from_segments(segments: list[dict[str, Any]], start: float, end: float) -> list[dict[str, Any]]:
    if not isinstance(segments, list) or not math.isfinite(start) or not math.isfinite(end) or end <= start:
        raise SubtitleError("Transcripción o límites del clip inválidos.")
    duration = round(end - start, 3)
    out = []
    previous_end = 0.0
    for segment in segments:
        try:
            a, b = float(segment["start"]), float(segment["end"])
            text = plain_text(segment["text"])
        except (KeyError, TypeError, ValueError, AttributeError) as exc:
            raise SubtitleError("La transcripción guardada no tiene el formato esperado.") from exc
        if not math.isfinite(a) or not math.isfinite(b) or b < a:
            raise SubtitleError("La transcripción contiene tiempos inválidos.")
        a, b = max(0, a - start, previous_end), min(duration, b - start)
        if b - a < 0.04 or not text:
            continue
        # Keep each generated caption to around two lines. The timing subdivision
        # is approximate; the UI explicitly describes this limitation.
        lines = textwrap.wrap(text, width=36, break_long_words=True, break_on_hyphens=False)
        chunks = [" ".join(lines[i:i + 2]) for i in range(0, len(lines), 2)]
        if (b - a) / len(chunks) < 0.04:
            chunks = [text[:500]]
        weights = sum(len(t) for t in chunks)
        cursor = a
        for n, chunk in enumerate(chunks):
            finish = b if n == len(chunks) - 1 else cursor + (b - a) * len(chunk) / weights
            if round(finish, 3) - round(cursor, 3) >= 0.04:
                out.append({"start": round(cursor, 3), "end": round(finish, 3), "text": chunk})
            cursor = finish
        previous_end = b
    return validate_cues(out, duration)


def timestamp(seconds: float, *, ass: bool = False, vtt: bool = False) -> str:
    scale = 100 if ass else 1000
    value = max(0, round(seconds * scale))
    hours, value = divmod(value, 3600 * scale)
    minutes, value = divmod(value, 60 * scale)
    whole, fraction = divmod(value, scale)
    if ass:
        return f"{hours}:{minutes:02}:{whole:02}.{fraction:02}"
    separator = "." if vtt else ","
    return f"{hours:02}:{minutes:02}:{whole:02}{separator}{fraction:03}"


def to_srt(cues: list[dict[str, Any]]) -> str:
    blocks = []
    for i, cue in enumerate(cues, 1):
        # Escape possible HTML rather than allowing user text to become markup.
        text = html.escape(cue["text"], quote=False)
        blocks.append(f"{i}\n{timestamp(cue['start'])} --> {timestamp(cue['end'])}\n{text}\n")
    return "\n".join(blocks)


def to_vtt(cues: list[dict[str, Any]]) -> str:
    blocks = ["WEBVTT\n"]
    for cue in cues:
        text = html.escape(cue["text"], quote=False)
        blocks.append(f"{timestamp(cue['start'], vtt=True)} --> {timestamp(cue['end'], vtt=True)}\n{text}\n")
    return "\n".join(blocks)


def to_ass(cues: list[dict[str, Any]], *, font_size: int = 52,
           color: str = "#FFFFFF", position: str = "bottom", margin_v: int = 230,
           outline: int = 3, outline_color: str = "#201510", shadow: int = 1) -> str:
    # Validate even direct calls: never interpolate arbitrary ASS/style markup.
    style = Presentation(subtitle_font_size=font_size, subtitle_color=color,
                         subtitle_position=position, subtitle_margin_v=margin_v,
                         subtitle_outline=outline, subtitle_outline_color=outline_color,
                         subtitle_shadow=shadow)
    rgb = style.subtitle_color[1:]
    ass_color = f"&H00{rgb[4:6]}{rgb[2:4]}{rgb[0:2]}"  # opaque AABBGGRR
    border = style.subtitle_outline_color[1:]
    ass_border = f"&H00{border[4:6]}{border[2:4]}{border[0:2]}"
    alignment = {"bottom": 2, "center": 5, "top": 8}[style.subtitle_position]
    # Font is provided by the container OS package; no font bytes are bundled.
    header = f"""[Script Info]
ScriptType: v4.00+
PlayResX: 1080
PlayResY: 1920
WrapStyle: 0
ScaledBorderAndShadow: yes

[V4+ Styles]
Format: Name, Fontname, Fontsize, PrimaryColour, SecondaryColour, OutlineColour, BackColour, Bold, Italic, Underline, StrikeOut, ScaleX, ScaleY, Spacing, Angle, BorderStyle, Outline, Shadow, Alignment, MarginL, MarginR, MarginV, Encoding
Style: Default,DejaVu Sans,{style.subtitle_font_size},{ass_color},{ass_color},{ass_border},&H80000000,-1,0,0,0,100,100,0,0,1,{style.subtitle_outline},{style.subtitle_shadow},{alignment},95,95,{style.subtitle_margin_v},1

[Events]
Format: Layer, Start, End, Style, Name, MarginL, MarginR, MarginV, Effect, Text
"""
    rows = []
    for cue in cues:
        # Fullwidth literals block ASS override tags and \N / \h injection.
        text = plain_text(cue["text"]).translate(str.maketrans({"\\": "＼", "{": "｛", "}": "｝"}))
        rows.append(f"Dialogue: 0,{timestamp(cue['start'], ass=True)},{timestamp(cue['end'], ass=True)},Default,,0,0,0,,{text}")
    return header + "\n".join(rows) + "\n"
