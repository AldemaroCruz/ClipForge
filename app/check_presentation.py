"""Offline functional check: actual framing, audio, ASS burn-in and subtitle files.

No Whisper, no model downloads, no external services or user data.
"""
import json
import subprocess
import tempfile
from pathlib import Path
from .media import probe_media
from .presentation import Presentation
from .render import render_clip


def make_source(path: Path, seconds: float = 2) -> None:
    subprocess.run([
        "ffmpeg", "-nostdin", "-v", "error", "-y", "-f", "lavfi", "-i",
        "testsrc2=size=320x180:rate=5", "-f", "lavfi", "-i",
        "sine=frequency=440:sample_rate=16000", "-t", str(seconds),
        "-c:v", "libx264", "-threads", "1", "-preset", "ultrafast",
        "-pix_fmt", "yuv420p", "-c:a", "aac", str(path),
    ], check=True, capture_output=True, timeout=30)


def caption_pixels(path: Path) -> bytes:
    return subprocess.run([
        "ffmpeg", "-nostdin", "-v", "error", "-ss", "0.8", "-i", str(path),
        "-frames:v", "1", "-vf", "crop=880:400:100:1280,format=gray",
        "-f", "rawvideo", "-",
    ], check=True, capture_output=True, timeout=30).stdout


def caption_color_stats(path: Path, color: str) -> dict:
    """Inspect actual encoded RGB pixels in a lower black-bar region.

    Pure red/blue detect an RGB-to-ASS BGR swap, not just non-black text. Small and
    large yellow use the same one-line text to verify size in the final MP4.
    """
    width, height = 1080, 480
    pixels = subprocess.run([
        "ffmpeg", "-nostdin", "-v", "error", "-ss", "0.8", "-i", str(path),
        "-frames:v", "1", "-vf", f"crop={width}:{height}:0:1320,format=rgb24",
        "-f", "rawvideo", "-",
    ], check=True, capture_output=True, timeout=30).stdout
    if len(pixels) != width * height * 3:
        raise AssertionError("Invalid RGB caption ROI")
    red, green, blue = (int(color[index:index+2], 16) for index in (1, 3, 5))
    count, x_min, y_min, x_max, y_max = 0, width, height, -1, -1
    for offset in range(0, len(pixels), 3):
        r, g, b = pixels[offset:offset+3]
        # Tolerance accommodates H.264/AAC pipeline chroma/quantization. Not a
        # claim of bit-perfect RGB fidelity after lossy video compression.
        if max(abs(r-red), abs(g-green), abs(b-blue)) <= 55:
            y, x = divmod(offset // 3, width)
            count += 1
            x_min, x_max = min(x_min, x), max(x_max, x)
            y_min, y_max = min(y_min, y), max(y_max, y)
    return {"matching_pixels": count, "width": x_max-x_min+1 if count else 0,
            "height": y_max-y_min+1 if count else 0, "expected_color": color}


def check_presentation() -> dict:
    report = {"status": "ok", "scope": "real_ffmpeg_framing_audio_and_custom_subtitle_style",
              "checks": {}, "errors": [], "transcription_tested": False}
    with tempfile.TemporaryDirectory(prefix="clipforge-presentation-") as directory:
        root = Path(directory)
        source = root / "source.mp4"
        try:
            make_source(source)
            cues = [{"start": .1, "end": 1.8, "text": "Edición local: voz, encuadre y subtítulos."}]
            for name, options in (
                ("contain_clean", Presentation()),
                ("contain_captions", Presentation(burn_subtitles=True)),
                ("blur_captions", Presentation(framing="blur", burn_subtitles=True)),
                ("crop_captions", Presentation(framing="crop", crop_x=.75, crop_zoom=1.2, burn_subtitles=True)),
            ):
                path = root / f"{name}.mp4"
                render_clip(source, path, start=0, end=2, options=options, cues=cues)
                metadata = probe_media(path)
                if ((metadata["width"], metadata["height"]) != (1080, 1920)
                    or metadata["audio_streams"] != 1 or metadata["video_codec"] != "h264"
                    or metadata["audio_codec"] != "aac"):
                    raise AssertionError(f"Invalid export metadata: {name}")
                subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(path),
                                "-f", "null", "-"], check=True, capture_output=True, timeout=30)
                if "Edición local" not in path.with_suffix(".srt").read_text(encoding="utf-8"):
                    raise AssertionError("Missing SRT content")
                if not path.with_suffix(".vtt").read_text().startswith("WEBVTT"):
                    raise AssertionError("Invalid WebVTT")
                report["checks"][name] = {"status": "ok", "width": 1080, "height": 1920,
                                           "audio": True, "decode": True, "sidecars": True}
            clean = caption_pixels(root / "contain_clean.mp4")
            burned = caption_pixels(root / "contain_captions.mp4")
            if len(clean) != 880 * 400 or len(burned) != len(clean):
                raise AssertionError("Invalid decoded caption ROI")
            delta = sum(v > 220 for v in burned) - sum(v > 220 for v in clean)
            if delta < 500:
                raise AssertionError(f"Captions not visible in the encoded video: {delta}")
            report["checks"]["visible_captions"] = {"status": "ok", "extra_bright_pixels": delta,
                                                        "scope": "decoded_MP4_pixels_not_just_file_presence"}
            # Exercise custom style through the same renderer used by API exports.
            style_cues = [{"start": .1, "end": 1.8, "text": "Color y tamaño"}]
            for name, size, color in (
                ("style_small_yellow", 32, "#FFD54F"),
                ("style_large_yellow", 96, "#FFD54F"),
                ("style_red", 72, "#FF0000"),
                ("style_blue", 72, "#0000FF"),
            ):
                path = root / f"{name}.mp4"
                options = Presentation(burn_subtitles=True, subtitle_font_size=size, subtitle_color=color)
                render_clip(source, path, start=0, end=2, options=options, cues=style_cues)
                stats = caption_color_stats(path, color)
                if stats["matching_pixels"] < 100:
                    raise AssertionError(f"Requested caption color not present: {name}: {stats}")
                report["checks"][name] = {"status": "ok", "font_size": size, **stats}
            small = report["checks"]["style_small_yellow"]
            large = report["checks"]["style_large_yellow"]
            if (large["matching_pixels"] <= small["matching_pixels"]*4
                or large["width"] <= small["width"]*2
                or large["height"] <= small["height"]*2):
                raise AssertionError("Subtitle size change not visible in the exported MP4")
            report["checks"]["visible_size_change"] = {
                "status": "ok", "small_size": 32, "large_size": 96,
                "colored_pixel_ratio": round(large["matching_pixels"]/small["matching_pixels"], 3),
                "scope": "same_caption_different_font_sizes_in_decoded_MP4_pixels"}
        except Exception as exc:
            report["status"] = "failed"
            report["errors"].append(f"{type(exc).__name__}: {exc}")
    return report


def main() -> int:
    report = check_presentation()
    print(json.dumps(report, ensure_ascii=False, indent=2))
    if report["status"] != "ok":
        return 1
    print("Presentation check OK (real MP4 framing + audio + subtitle sizes/colors; no Whisper inference).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
