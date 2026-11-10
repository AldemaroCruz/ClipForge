"""Real, read-only ASR smoke. May download Whisper weights into HF_HOME.

Example in Docker: python -m app.smoke_transcribe /data/<job_id>/input.mp4
This diagnostic does not retry a job, render clips, or modify existing files.
Run separately from active processing; model loading can use significant RAM.
"""

import argparse
import importlib
import json
import os
import sys
import time
from pathlib import Path
from typing import Any

from .media import inspect_media


def transcribe_file(path: Path, *, model_name: str, language: str | None = None,
                    local_files_only: bool = False) -> dict[str, Any]:
    if not path.is_file():
        raise FileNotFoundError(f"Input file not found: {path}")
    if path.stat().st_size == 0:
        raise ValueError("The input file is empty")
    # ASR diagnostics may use short audio-only files, but they must have audio.
    inspect_media(path, require_video=False, min_duration=0)
    whisper = importlib.import_module("faster_whisper")
    started = time.monotonic()
    selected_model = model_name
    if os.getenv("CLIPFORGE_MODEL_LOCK"):
        if model_name != os.getenv("WHISPER_MODEL", "tiny"):
            raise ValueError("El modelo solicitado no coincide con el lock de la instalación.")
        from .model_source import resolve_model
        selected_model = resolve_model()
    model = whisper.WhisperModel(selected_model, device="cpu", compute_type="int8",
                                 local_files_only=local_files_only)
    segments, info = model.transcribe(str(path), language=language, beam_size=1, vad_filter=True)
    # Inference is lazy: calling transcribe() alone is NOT a completed ASR test.
    rows = [{"start": float(s.start), "end": float(s.end), "text": s.text.strip()}
            for s in segments]
    text_found = any(row["text"] for row in rows)
    return {"status": "ok" if text_found else "no_speech",
            "scope": "real_whisper_transcription_no_render",
            "model": model_name, "language": info.language,
            "elapsed_seconds": round(time.monotonic() - started, 2),
            "transcription_tested": True, "segments": rows}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", type=Path, help="Existing local media file in the container")
    parser.add_argument("--model", default=os.getenv("WHISPER_MODEL", "tiny"))
    parser.add_argument("--language", default=None, help="Optional language code, e.g. es")
    parser.add_argument("--local-files-only", action="store_true", help="Fail rather than download missing weights")
    args = parser.parse_args(argv)
    try:
        report = transcribe_file(args.input, model_name=args.model, language=args.language,
                                 local_files_only=args.local_files_only)
        print(json.dumps(report, ensure_ascii=False, indent=2))
        return 0 if report["status"] == "ok" else 2
    except Exception as exc:
        print(json.dumps({"status": "failed", "transcription_tested": False,
                          "error": f"{type(exc).__name__}: {exc}"}, ensure_ascii=False), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
