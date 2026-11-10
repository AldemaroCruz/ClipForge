"""Offline, functional checks of the same decoder used by WhisperModel.transcribe.

No Whisper weights, network calls, or user files are needed. Silero VAD uses the
ONNX assets distributed with faster-whisper. Failures are reported, never hidden
by replacing the decoder, swallowing metadata_errors, or manufacturing silence.
"""

import importlib
import math
import struct
import subprocess
import tempfile
import wave
from pathlib import Path
from typing import Any

from .media_binaries import resolve_media_binary

SAMPLE_RATE = 16000
DURATION_SECONDS = 1


def make_test_wav(path: Path) -> None:
    """Stereo PCM16 at 44.1 kHz exercises downmixing AND resampling to 16 kHz."""
    rate = 44100
    frames = bytearray()
    for i in range(rate * DURATION_SECONDS):
        value = round(6000 * math.sin(2 * math.pi * 440 * i / rate))
        frames.extend(struct.pack("<hh", value, value))
    with wave.open(str(path), "wb") as wav:
        wav.setnchannels(2)
        wav.setsampwidth(2)
        wav.setframerate(rate)
        wav.writeframes(frames)


def make_test_mp4(wav: Path, mp4: Path) -> None:
    executable = resolve_media_binary("ffmpeg")
    command = [
        executable, "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
        "-f", "lavfi", "-i", "color=c=black:s=160x90:r=5",
        "-i", str(wav), "-t", str(DURATION_SECONDS),
        "-map", "0:v:0", "-map", "1:a:0", "-c:v", "libx264", "-threads", "1",
        "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-c:a", "aac", str(mp4),
    ]
    result = subprocess.run(command, capture_output=True, text=True,
                            errors="replace", timeout=30)
    if result.returncode:
        raise RuntimeError(f"FFmpeg test fixture failed: {result.stderr[-2000:].strip()}")
    if not mp4.is_file() or mp4.stat().st_size == 0:
        raise RuntimeError("FFmpeg did not create the test MP4")


def verify_decoded_audio(audio: Any, np: Any) -> dict[str, Any]:
    """Reject empty, malformed, silent or incorrectly resampled fixture output."""
    if not isinstance(audio, np.ndarray) or audio.ndim != 1:
        raise ValueError("Whisper decoder must return a one-dimensional NumPy array")
    if audio.dtype != np.dtype("float32"):
        raise ValueError(f"Expected float32 decoder output, got {audio.dtype}")
    # AAC can have a few extra samples because of codec frame padding.
    if abs(audio.size - SAMPLE_RATE * DURATION_SECONDS) > SAMPLE_RATE * 0.12:
        raise ValueError(f"Unexpected sample count at 16 kHz: {audio.size}")
    if not np.isfinite(audio).all():
        raise ValueError("Non-finite decoder output")
    peak = float(np.max(np.abs(audio)))
    if not 0.01 < peak < 1.0:
        raise ValueError(f"Test tone lost or incorrectly scaled: peak={peak}")
    return {"status": "ok", "samples": int(audio.size), "sample_rate": SAMPLE_RATE,
            "dtype": str(audio.dtype), "peak": round(peak, 6)}


def check_audio_stack() -> dict[str, Any]:
    report: dict[str, Any] = {"status": "ok", "checks": {}, "errors": []}

    def run_check(name: str, operation: Any) -> None:
        try:
            report["checks"][name] = operation()
        except Exception as exc:
            report["checks"][name] = {"status": "failed"}
            report["errors"].append({"component": name,
                                     "error": f"{type(exc).__name__}: {exc}"})

    try:
        np = importlib.import_module("numpy")
        decoder = importlib.import_module("faster_whisper.audio").decode_audio
        vad = importlib.import_module("faster_whisper.vad").get_speech_timestamps
        with tempfile.TemporaryDirectory(prefix="clipforge-audio-check-") as temp:
            folder = Path(temp)
            wav, mp4 = folder / "tone.wav", folder / "tone.mp4"
            make_test_wav(wav)

            def check_wav() -> dict[str, Any]:
                return verify_decoded_audio(decoder(str(wav), sampling_rate=SAMPLE_RATE), np)

            def check_mp4() -> dict[str, Any]:
                make_test_mp4(wav, mp4)
                return verify_decoded_audio(decoder(str(mp4), sampling_rate=SAMPLE_RATE), np)

            def check_vad() -> dict[str, Any]:
                chunks = vad(np.zeros(SAMPLE_RATE * 2, dtype=np.float32))
                if not isinstance(chunks, list) or chunks:
                    raise ValueError(f"Expected no speech in two seconds of silence, got {chunks!r}")
                return {"status": "ok", "input_seconds": 2, "speech_regions": 0,
                        "scope": "bundled_silero_onnx_on_silence_only"}

            run_check("wav_decode", check_wav)
            run_check("mp4_decode", check_mp4)
            run_check("silero_vad", check_vad)
    except Exception as exc:
        report["errors"].append({"component": "audio_setup",
                                 "error": f"{type(exc).__name__}: {exc}"})
    if report["errors"]:
        report["status"] = "failed"
    return report
