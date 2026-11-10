"""Offline real-FFmpeg/ffprobe regression smoke, without Whisper or user data.

Run: python -m app.check_media
Synthetic tones and silence here are NOT speech-recognition fixtures.
"""

import json
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .media import MediaValidationError, inspect_media


def make_fixture(path: Path, *, audio: str | None = "tone", video: bool = True,
                 seconds: float = 22) -> None:
    """Create cheap synthetic MP4s in a caller-owned temporary directory."""
    args = ["ffmpeg", "-nostdin", "-v", "error", "-y"]
    if video:
        args += ["-f", "lavfi", "-i", "color=c=black:s=160x90:r=2"]
    if audio is not None:
        source = "anullsrc=r=16000:cl=mono" if audio == "silence" else "sine=frequency=440:sample_rate=16000"
        args += ["-f", "lavfi", "-i", source]
    args += ["-t", str(seconds)]
    if video:
        args += ["-c:v", "libx264", "-threads", "1", "-preset", "ultrafast", "-pix_fmt", "yuv420p"]
    if audio is not None:
        args += ["-c:a", "aac"]
    else:
        args += ["-an"]
    args += [str(path)]
    subprocess.run(args, check=True, capture_output=True, timeout=30)


def check_media() -> dict[str, Any]:
    report: dict[str, Any] = {"status": "ok", "scope": "real_ffmpeg_ffprobe_structural_validation",
                              "checks": {}, "errors": [], "transcription_tested": False}
    cases = [
        ("with_audio", {"audio": "tone"}, None),
        ("without_audio", {"audio": None}, "NO_AUDIO_STREAM"),
        ("silence_track", {"audio": "silence"}, None),
        ("short_with_audio", {"seconds": 5}, "VIDEO_TOO_SHORT"),
        ("audio_only", {"video": False}, "NO_VIDEO_STREAM"),
        ("invalid_mp4", None, "INVALID_MEDIA"),
    ]
    with tempfile.TemporaryDirectory(prefix="clipforge-media-check-") as temp:
        for name, options, expected in cases:
            try:
                path = Path(temp) / f"{name}.mp4"
                if options is None:
                    path.write_bytes(b"This is not a media file.")
                else:
                    make_fixture(path, **options)
                try:
                    media = inspect_media(path)
                    actual = None
                except MediaValidationError as exc:
                    actual, media = exc.code, exc.media
                if actual != expected:
                    raise AssertionError(f"Expected {expected!r}, got {actual!r}")
                report["checks"][name] = {"status": "ok", "observed": actual or "valid", "media": media}
            except Exception as exc:
                report["status"] = "failed"
                report["errors"].append({"case": name, "error": f"{type(exc).__name__}: {exc}"})
    return report


def main() -> int:
    report = check_media()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "ok":
        return 1
    print("Media check OK (6 real FFmpeg/ffprobe cases; speech recognition NOT tested).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
