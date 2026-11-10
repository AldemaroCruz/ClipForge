"""Real FFmpeg presentation pipeline. Original inputs are never overwritten."""
import os
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from .presentation import Presentation
from .media_binaries import resolve_media_binary
from .subtitles import to_ass, to_srt, to_vtt, validate_cues


def run_ffmpeg(*args: Any) -> None:
    try:
        result = subprocess.run(
            [resolve_media_binary("ffmpeg"), "-nostdin", "-hide_banner", "-loglevel", "error", "-y", *map(str, args)],
            capture_output=True, text=True, errors="replace", timeout=1800,
        )
    except FileNotFoundError as exc:
        raise RuntimeError("FFmpeg no está instalado; reconstruye la imagen Docker") from exc
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError("FFmpeg superó el límite de 1800 segundos por clip") from exc
    if result.returncode:
        raise RuntimeError(f"FFmpeg falló ({result.returncode}): {result.stderr[-2000:].strip()}")


def _filter_path(path: Path) -> str:
    # Path has two parsers: filter options and the filter graph. No shell involved.
    # Use FFmpeg single quotes and escape chars inside; single quote exits/reenters.
    value = str(path.resolve()).replace("\\", "/").replace(":", "\\:")
    return "'" + value.replace("'", "'\\''") + "'"


def build_filter(options: Presentation, *, video_index: int = 0,
                 ass_path: Path | None = None) -> str:
    if isinstance(video_index, bool) or not isinstance(video_index, int) or video_index < 0:
        raise ValueError("Índice de pista de video inválido")
    # Normalize sample aspect ratio before crop/pad. FFmpeg autorotation remains on.
    prefix = f"[0:{video_index}]setpts=PTS-STARTPTS,scale=trunc(iw*sar/2)*2:ih,setsar=1"
    contain = "scale=1080:1920:force_original_aspect_ratio=decrease:force_divisible_by=2"
    cover = "scale=1080:1920:force_original_aspect_ratio=increase:force_divisible_by=2,crop=1080:1920"
    if options.framing == "contain":
        graph = f"{prefix},{contain},pad=1080:1920:(ow-iw)/2:(oh-ih)/2:color=black[framed]"
    elif options.framing == "blur":
        graph = (f"{prefix},split=2[bg][fg];[bg]{cover},gblur=sigma=30:steps=2[back];"
                 f"[fg]{contain}[front];[back][front]overlay=(W-w)/2:(H-h)/2:shortest=1[framed]")
    else:
        z, x, y = options.crop_zoom, options.crop_x, options.crop_y
        crop = (f"crop=w='trunc(min(iw,ih*9/16)/{z:.6f}/2)*2':"
                f"h='trunc(min(ih,iw*16/9)/{z:.6f}/2)*2':"
                f"x='trunc((iw-ow)*{x:.6f}/2)*2':y='trunc((ih-oh)*{y:.6f}/2)*2'")
        graph = f"{prefix},{crop},scale=1080:1920[framed]"
    tail = "setsar=1"
    if options.burn_subtitles and ass_path is not None:
        tail += f",ass=filename={_filter_path(ass_path)}"
    return f"{graph};[framed]{tail}[outv]"


def render_clip(source: Path, output: Path, *, start: float, end: float,
                options: Presentation, cues: list[dict[str, Any]], video_index: int = 0,
                threads: int = 2, runner: Callable[..., None] = run_ffmpeg) -> None:
    if not 0 < end - start <= 60.001:
        raise ValueError("La duración de exportación debe ser mayor que 0 y no superar 60 segundos.")
    duration = round(end - start, 3)
    cues = validate_cues(cues, duration)
    if options.burn_subtitles and not cues:
        raise ValueError("No hay subtítulos para incrustar. Agrega texto o desactiva esa opción.")
    output.parent.mkdir(parents=True, exist_ok=True)
    # Stage all outputs in a private directory on the destination filesystem.
    # Publication happens only after FFmpeg closes its MP4 successfully.
    with tempfile.TemporaryDirectory(prefix=".render-", dir=output.parent) as directory:
        folder = Path(directory)
        ass = folder / "captions.ass"
        ass.write_text(to_ass(cues, font_size=options.subtitle_font_size,
                              color=options.subtitle_color, position=options.subtitle_position,
                              margin_v=options.subtitle_margin_v, outline=options.subtitle_outline,
                              outline_color=options.subtitle_outline_color,
                              shadow=options.subtitle_shadow), encoding="utf-8")
        target = folder / "clip.mp4"
        runner(
            "-filter_complex_threads", max(1, threads),
            "-ss", f"{start:.3f}", "-protocol_whitelist", "file,pipe", "-i", source.resolve(), "-t", f"{duration:.3f}",
            "-filter_complex", build_filter(options, video_index=video_index, ass_path=ass),
            "-map", "[outv]", "-map", "0:a:0", "-af", "asetpts=PTS-STARTPTS",
            "-c:v", "libx264", "-threads", max(1, threads), "-preset", "veryfast",
            "-crf", "26", "-pix_fmt", "yuv420p", "-c:a", "aac", "-movflags", "+faststart", target,
        )
        if not target.is_file() or target.stat().st_size == 0:
            raise RuntimeError("FFmpeg no generó un archivo de video válido.")
        for suffix, text in ((".srt", to_srt(cues)), (".vtt", to_vtt(cues))):
            temp = folder / f"captions{suffix}"
            temp.write_text(text, encoding="utf-8")
            os.replace(temp, output.with_suffix(suffix))
        os.replace(target, output)
