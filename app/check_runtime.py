"""Offline dependency smoke test. Run with: python -m app.check_runtime.

This is intentionally separate from HTTP /health and mocked ASR unit tests.
It imports the real runtime packages without constructing a Whisper model,
reading user media, downloading Whisper weights, or making external API calls.
Also decodes generated WAV/MP4 fixtures and runs bundled Silero ONNX on silence.
"""

import importlib
import json
import platform
import shutil
import subprocess
import sys
from importlib.metadata import version
from typing import Any

from .audio_check import check_audio_stack

# (distribution name, import name, required callable or None).
DEPENDENCIES = (
    ("requests", "requests", "get"),
    ("numpy", "numpy", "array"),
    ("fastapi", "fastapi", "FastAPI"),
    ("uvicorn", "uvicorn", "run"),
    ("python-multipart", "python_multipart", None),
    ("ctranslate2", "ctranslate2", "get_supported_compute_types"),
    ("av", "av", "open"),
    ("tokenizers", "tokenizers", "Tokenizer"),
    ("onnxruntime", "onnxruntime", "InferenceSession"),
    ("huggingface-hub", "huggingface_hub", "snapshot_download"),
    ("faster-whisper", "faster_whisper", "WhisperModel"),
)
BINARIES = ("ffmpeg", "ffprobe")


def check_runtime() -> dict[str, Any]:
    report: dict[str, Any] = {
        "status": "ok",
        "scope": "real_imports_binaries_audio_decode_and_vad",
        "python": platform.python_version(),
        "packages": {},
        "binaries": {},
        "errors": [],
        "functional_checks": {},
        "audio_decode_tested": False,
        "vad_tested": False,
        "model_download_tested": False,
        "transcription_tested": False,
    }
    for distribution, module_name, symbol in DEPENDENCIES:
        try:
            module = importlib.import_module(module_name)
            if symbol is not None and not callable(getattr(module, symbol, None)):
                raise ImportError(f"{module_name}.{symbol} is missing or not callable")
            report["packages"][distribution] = version(distribution)
        except Exception as exc:
            report["errors"].append({
                "component": distribution,
                "error": f"{type(exc).__name__}: {exc}",
            })
    for name in BINARIES:
        try:
            executable = shutil.which(name)
            if executable is None:
                raise FileNotFoundError(f"{name} is not installed or not on PATH")
            result = subprocess.run(
                [executable, "-version"], check=True, capture_output=True,
                text=True, errors="replace", timeout=10,
            )
            first_lines = result.stdout.strip().splitlines()
            if not first_lines:
                raise RuntimeError(f"{name} returned no version information")
            report["binaries"][name] = first_lines[0]
        except Exception as exc:
            report["errors"].append({
                "component": name,
                "error": f"{type(exc).__name__}: {exc}",
            })
    if not report["errors"]:
        try:
            functional = check_audio_stack()
            report["functional_checks"] = functional["checks"]
            report["errors"].extend(functional["errors"])
            for name in ("wav_decode", "mp4_decode", "silero_vad"):
                if functional["checks"].get(name, {}).get("status") != "ok" and not any(
                    err["component"] == name for err in report["errors"]
                ):
                    report["errors"].append({"component": name, "error": "Functional check did not pass"})
            report["audio_decode_tested"] = all(
                functional["checks"].get(name, {}).get("status") == "ok"
                for name in ("wav_decode", "mp4_decode")
            )
            report["vad_tested"] = functional["checks"].get("silero_vad", {}).get("status") == "ok"
        except Exception as exc:
            report["errors"].append({"component": "functional_checks",
                                     "error": f"{type(exc).__name__}: {exc}"})
    else:
        report["functional_checks"] = {"status": "not_run", "reason": "Import or binary checks failed"}
    if report["errors"]:
        report["status"] = "failed"
    return report


def main() -> int:
    report = check_runtime()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "ok":
        print(
            "Runtime check FAILED. Fix the image dependencies before processing videos.",
            file=sys.stderr,
        )
        return 1
    print("Runtime check OK (imports + WAV/MP4 decode + Silero VAD; Whisper transcription NOT tested).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
