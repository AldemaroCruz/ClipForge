"""Read-only media preflight. Uses ffprobe, never imports or loads Whisper.

CLI: python -m app.media /data/<job_id>/input.mp4
Exit codes: 0 = passes structural checks, 2 = unsuitable input, 1 = tooling failure.
Passing this check does not prove that the audio is decodable or contains speech.
"""

import argparse
import json
import math
import subprocess
import sys
from pathlib import Path
from typing import Any


class MediaValidationError(ValueError):
    """Expected input rejection, with a stable code and safe user-facing message."""

    def __init__(self, code: str, message: str, media: dict[str, Any] | None = None):
        super().__init__(message)
        self.code = code
        self.media = media


def _duration(value: Any) -> float | None:
    try:
        number = float(value)
    except (TypeError, ValueError, OverflowError):
        return None
    return number if math.isfinite(number) and number > 0 else None


def probe_media(path: Path) -> dict[str, Any]:
    """Inspect local stream metadata only; preserve the input bytes unchanged."""
    path = Path(path)
    if not path.is_file():
        raise MediaValidationError("INPUT_NOT_FOUND", "No se encontró el archivo de entrada. Sube el MP4 de nuevo.")
    if path.stat().st_size == 0:
        raise MediaValidationError("EMPTY_INPUT", "El archivo está vacío. Sube un MP4 con video y voz.")
    try:
        result = subprocess.run(
            ["ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe",
             "-show_entries",
             "format=duration,format_name:stream=index,codec_type,codec_name,duration,sample_rate,channels,width,height:stream_disposition=attached_pic",
             "-of", "json", str(path.resolve())],
            capture_output=True, text=True, errors="replace", timeout=30,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("ffprobe no está instalado. Reconstruye la imagen Docker.") from exc
    except subprocess.TimeoutExpired as exc:
        raise MediaValidationError("PROBE_TIMEOUT", "No se pudo inspeccionar el archivo en 30 segundos. Prueba otro MP4 o vuelve a exportarlo.") from exc
    if result.returncode != 0:
        # Do not mislabel an unreadable container as a video without audio.
        raise MediaValidationError("INVALID_MEDIA", "ffprobe no pudo leer el archivo. Puede estar dañado, incompleto o no ser un MP4 válido; vuelve a exportarlo.")
    try:
        payload = json.loads(result.stdout)
        if not isinstance(payload, dict):
            raise ValueError("Expected object")
        streams = payload.get("streams", [])
        if not isinstance(streams, list) or not all(isinstance(s, dict) for s in streams):
            raise ValueError("Expected stream list")
        container = payload.get("format", {})
        if not isinstance(container, dict):
            raise ValueError("Expected format object")
    except (ValueError, TypeError) as exc:
        raise RuntimeError("ffprobe devolvió metadatos JSON inválidos. Revisa la imagen y los logs.") from exc

    videos = [s for s in streams if s.get("codec_type") == "video"
              and not s.get("disposition", {}).get("attached_pic", 0)]
    audios = [s for s in streams if s.get("codec_type") == "audio"]
    primary_video = videos[0] if videos else {}
    primary_audio = audios[0] if audios else {}
    # Prefer video duration for a clipping job; container duration can include a
    # much longer audio track. Unknown duration is not treated as zero seconds.
    duration = (_duration(primary_video.get("duration"))
                or _duration(container.get("duration"))
                or _duration(primary_audio.get("duration")))
    return {
        "duration_seconds": duration,
        "format_name": container.get("format_name"),
        "video_streams": len(videos), "audio_streams": len(audios),
        "video_stream_index": primary_video.get("index"),
        "audio_stream_index": primary_audio.get("index"),
        "video_codec": primary_video.get("codec_name"),
        "audio_codec": primary_audio.get("codec_name"),
        "width": primary_video.get("width"), "height": primary_video.get("height"),
        "audio_channels": primary_audio.get("channels"),
        "audio_sample_rate": primary_audio.get("sample_rate"),
    }


def validate_media(media: dict[str, Any], *, require_video: bool = True,
                   min_duration: float = 20.0) -> None:
    """Structural validation, NOT speech recognition or a full decoder test."""
    if require_video and media["video_streams"] == 0:
        raise MediaValidationError("NO_VIDEO_STREAM", "El archivo no contiene una pista de video utilizable. Para crear clips, sube un MP4 con imagen y voz.", media)
    if media["audio_streams"] == 0:
        raise MediaValidationError(
            "NO_AUDIO_STREAM",
            "El MP4 no contiene una pista de audio reconocida. Este MVP selecciona clips a partir de la voz, no de las imágenes. Sube un video con conversación audible de 1–3 minutos; agregar silencio o música no sustituye la voz.",
            media,
        )
    duration = media["duration_seconds"]
    if duration is not None and duration < min_duration:
        raise MediaValidationError(
            "VIDEO_TOO_SHORT",
            f"El archivo dura {duration:.2f} segundos; el selector actual necesita ventanas de voz de al menos {min_duration:g} segundos. Para probarlo, usa 1–3 minutos de conversación.",
            media,
        )


def inspect_media(path: Path, *, require_video: bool = True,
                  min_duration: float = 20.0) -> dict[str, Any]:
    media = probe_media(path)
    validate_media(media, require_video=require_video, min_duration=min_duration)
    return media


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path)
    args = parser.parse_args(argv)
    report: dict[str, Any] = {"scope": "ffprobe_stream_metadata_only", "transcription_tested": False}
    try:
        report.update(status="valid", media=inspect_media(args.input))
        result = 0
    except MediaValidationError as exc:
        report.update(status="rejected", error_code=exc.code, error=str(exc), media=exc.media)
        result = 2
    except Exception as exc:
        report.update(status="failed", error=f"{type(exc).__name__}: {exc}")
        result = 1
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return result


if __name__ == "__main__":
    raise SystemExit(main())
