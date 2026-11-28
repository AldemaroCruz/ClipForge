"""Timeline-preserving audio and Faster Whisper timestamps for the INT worker."""
from dataclasses import dataclass
import math
from numbers import Real
from pathlib import Path
import re
from tempfile import TemporaryDirectory

from .media import MediaValidationError
from .model_source import resolve_model
from .render import run_ffmpeg
from .state import write_json_atomic
from .subtitles import plain_text

ALIGNMENT_FILE = "transcript-words.json"
ALIGNMENT_METHOD = "faster-whisper-word-timestamps"
MAX_ALIGNMENT_BYTES = 4 * 1024 * 1024
MAX_ALIGNMENT_WORDS = 20000
MAX_WORDS_PER_SEGMENT = 1000
SAMPLES_PER_SECOND = 16000


@dataclass
class PilotTranscript:
    segments: list[dict]
    alignment: dict | None
    language: str
    decoded_seconds: float


def beta_audio(source: Path):
    import numpy as np
    from .cloud.config import BETA_AUDIO_PADDING_SECONDS, BETA_MAX_SECONDS

    probe_seconds = BETA_MAX_SECONDS + 1
    byte_limit = probe_seconds * SAMPLES_PER_SECOND * 2
    admitted_bytes = int((BETA_MAX_SECONDS + BETA_AUDIO_PADDING_SECONDS) * SAMPLES_PER_SECOND) * 2
    with TemporaryDirectory(prefix=".audio-", dir=source.parent) as directory:
        pcm = Path(directory) / "voice.pcm"
        run_ffmpeg(
            "-protocol_whitelist", "file,pipe", "-f", "mov", "-i", source.resolve(),
            "-map", "0:a:0", "-vn", "-sn", "-dn",
            # Fill timeline gaps so Whisper offsets still refer to the original.
            "-af", "aresample=async=1:first_pts=0",
            "-ar", SAMPLES_PER_SECOND, "-ac", 1, "-c:a", "pcm_s16le",
            "-t", probe_seconds, "-fs", byte_limit, "-f", "s16le", pcm,
        )
        with pcm.open("rb") as audio:
            data = audio.read(byte_limit + 1)
    if len(data) > admitted_bytes:
        raise MediaValidationError("VIDEO_OUTSIDE_LIMITS", "La pista de audio excede la duración admitida.")
    if not data or len(data) % 2:
        raise MediaValidationError("UNSUPPORTED_MEDIA", "No se pudo decodificar la pista de audio.")
    return np.frombuffer(data, dtype="<i2").astype(np.float32) / 32768.0


def aligned_words(raw_words, segment):
    """A partially aligned segment keeps its phrase boundaries only."""
    if (not raw_words or len(raw_words) > MAX_WORDS_PER_SEGMENT
            or any(not isinstance(word.word, str) for word in raw_words)):
        return []
    if plain_text("".join(word.word for word in raw_words)) != plain_text(segment["text"]):
        return []
    words = []
    previous_end = segment["start"]
    for word in raw_words:
        start, end = word.start, word.end
        value = plain_text(word.word)
        # Faster Whisper derives these values from NumPy arrays. Normalize
        # real scalars only after checking the original acoustic boundaries.
        if (not all(isinstance(time, Real) and not isinstance(time, bool) for time in (start, end))
                or not previous_end <= start < end <= segment["end"] or not 1 <= len(value) <= 160):
            return []
        words.append({"start": float(start), "end": float(end), "text": value})
        previous_end = end
    return words


def write_alignment(path: Path, alignment: dict | None) -> bool:
    if alignment is None or not any(row["words"] for row in alignment["segments"]):
        return False
    segments = alignment["segments"]
    if any(a["start"] > b["start"] or a["end"] > b["end"] for a, b in zip(segments, segments[1:])):
        return False
    write_json_atomic(path, alignment)
    if path.stat().st_size <= MAX_ALIGNMENT_BYTES:
        return True
    path.unlink()
    return False


def transcribe_pilot(source: Path, duration: float, recorder, *, word_timestamps=True) -> PilotTranscript:
    import faster_whisper

    recorder.phase("model_load")
    snapshot = resolve_model()
    model = faster_whisper.WhisperModel(snapshot, device="cpu", compute_type="int8")
    recorder.phase("transcription")
    audio = beta_audio(source)
    decoded_seconds = len(audio) / SAMPLES_PER_SECOND
    timeline_end = min(decoded_seconds, duration)
    options = {"word_timestamps": True} if word_timestamps else {}
    source_rows, info = model.transcribe(audio, beam_size=1, vad_filter=True, **options)
    segments, marks = [], []
    remaining_words = MAX_ALIGNMENT_WORDS
    for row in source_rows:
        value, start, end = row.text.strip(), row.start, row.end
        if not value or not math.isfinite(start) or not math.isfinite(end):
            continue
        start, end = max(0.0, float(start)), min(timeline_end, float(end))
        if start >= end:
            continue
        segment = {"start": start, "end": end, "text": value}
        segments.append(segment)
        if word_timestamps:
            raw_words = getattr(row, "words", None)
            words = aligned_words(raw_words, segment) if raw_words and len(raw_words) <= remaining_words else []
            marks.append({**segment, "words": words})
            remaining_words -= len(words)
    alignment = None
    if word_timestamps:
        revision = Path(snapshot).name
        alignment = {"schema": 1, "method": ALIGNMENT_METHOD,
                     "transcriber_version": getattr(faster_whisper, "__version__", "unversioned"),
                     "model_revision": revision if re.fullmatch(r"[a-f0-9]{40}", revision) else None,
                     "segments": marks}
    return PilotTranscript(segments, alignment, info.language, decoded_seconds)
