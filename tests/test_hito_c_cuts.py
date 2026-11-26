"""Check the approved source interval against decoded MP4 and subtitle timing."""
from array import array
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from app.media_binaries import resolve_media_binary
from app.presentation import Presentation
from app.render import render_clip


AUDIO_HZ = 8000
NATIVE_FRAME_SECONDS = 1001 / 24000
CUTS = ((180.123, 184.600, 181.000), (202.017, 207.978, 205.000))


def run(tool, *args):
    return subprocess.run([resolve_media_binary(tool), "-v", "error", *map(str, args)],
                          capture_output=True, check=True, timeout=60).stdout


def make_fixture(path, *, voice=None):
    # The native 24000/1001 cadence has deliberate gaps. Video changes
    # luma at each marker and the two matching sound pulses are independent.
    if voice is None:
        audio = ["-itsoffset", "180.750", "-f", "lavfi", "-i",
                 "aevalsrc=0.55*sin(2*PI*880*t)*(between(t\\,0.250\\,0.510)+between(t\\,24.250\\,24.510)):s=48000:d=27.25"]
    else:
        audio = ["-stream_loop", "-1", "-i", voice, "-f", "lavfi", "-i",
                 "aevalsrc=0.65*sin(2*PI*880*t)*(between(t\\,181\\,181.26)+between(t\\,205\\,205.26)):s=48000:d=208",
                 "-filter_complex", "[1:a]volume=0.15[voice];[voice][2:a]amix=inputs=2:duration=shortest:normalize=0[a]",
                 "-map", "0:v", "-map", "[a]"]
    run("ffmpeg", "-nostdin", "-f", "lavfi", "-i", "color=c=black:s=64x64:r=24000/1001:d=208", *audio,
        "-vf", "select='not(eq(mod(n,5),1))',drawbox=x=0:y=0:w=iw:h=ih:color=white:t=fill:"
               "enable='between(t,181,181.25)+between(t,205,205.25)'",
        "-fps_mode:v", "passthrough", "-enc_time_base:v", "filter", "-c:v", "libx264", "-threads", 1,
        "-preset", "ultrafast", "-c:a", "aac", "-movflags", "+faststart", path)


def frame_times(path):
    probe = json.loads(run("ffprobe", "-select_streams", "v:0", "-show_entries",
                           "frame=best_effort_timestamp_time", "-of", "json", path))
    return [float(frame["best_effort_timestamp_time"]) for frame in probe["frames"]]


def video_marker(path, times, start=0, end=float("inf")):
    levels = run("ffmpeg", "-nostdin", "-i", path, "-an", "-vf", "crop=16:16,scale=1:1,format=gray",
                 "-fps_mode:v", "passthrough", "-f", "rawvideo", "-")
    return next(t for t, level in zip(times, levels, strict=True) if start <= t < end and level > 180)


def audio_samples(path):
    raw = run("ffmpeg", "-nostdin", "-i", path, "-vn", "-af", "aresample=async=1:first_pts=0",
              "-ar", AUDIO_HZ, "-ac", 1, "-c:a", "pcm_s16le", "-f", "s16le", "-")
    samples = array("h")
    samples.frombytes(raw)
    return samples


def audio_marker(samples, start=0):
    return next(index / AUDIO_HZ for index in range(round(start * AUDIO_HZ), len(samples))
                if abs(samples[index]) > 6000)


def subtitle_marker(path, times):
    frames = run("ffmpeg", "-nostdin", "-i", path, "-an", "-vf",
                 "crop=880:400:100:1350,scale=88:40,format=gray",
                 "-fps_mode:v", "passthrough", "-f", "rawvideo", "-")
    dimension = 88 * 40
    if len(frames) != len(times) * dimension:
        raise AssertionError("Subtitle scan and MP4 timestamps differ in length")
    return next(time for frame, time in enumerate(times)
                if sum(level > 90 for level in frames[frame * dimension:(frame + 1) * dimension]) > 20)


def subtitle_timestamp(seconds, separator):
    seconds, milliseconds = divmod(round(seconds * 1000), 1000)
    minutes, seconds = divmod(seconds, 60)
    return f"00:{minutes:02d}:{seconds:02d}{separator}{milliseconds:03d}"


def measure_cut(source, target, start, end, marker, *, cue=None):
    """Inspect one downloaded synthetic MP4 and, when supplied, its exact cue."""
    source_times = frame_times(source)
    expected = [time - start for time in source_times if start <= time < end]
    observed = frame_times(target)
    if len(expected) != len(observed) or len(observed) < 2:
        raise AssertionError("MP4 did not keep the native frames inside the approved interval")
    largest_gap = max(b - a for a, b in zip(observed, observed[1:]))
    error = max(abs(a - b) for a, b in zip(expected, observed, strict=True))
    if largest_gap <= NATIVE_FRAME_SECONDS * 1.8 or error >= 0.002:
        raise AssertionError("MP4 did not retain source frame timestamps and cadence")
    probe = json.loads(run("ffprobe", "-show_entries", "format=duration", "-of", "json", target))
    duration = float(probe["format"]["duration"])
    if abs(duration - (end - start)) > largest_gap + 0.002:
        raise AssertionError("MP4 duration drift exceeded one observed frame interval")

    visual_expected = video_marker(source, source_times, start, end) - start
    visual_observed = video_marker(target, observed)
    sound_expected = audio_marker(audio_samples(source), start) - start
    sound_observed = audio_marker(audio_samples(target))
    visual_error = visual_observed - visual_expected
    sound_error = sound_observed - sound_expected
    if (abs(visual_expected - (marker - start)) >= 2 * NATIVE_FRAME_SECONDS
            or abs(sound_expected - (marker - start)) >= 0.025):
        raise AssertionError("Synthetic source markers did not appear at their expected time")
    if abs(visual_error) >= 0.002 or abs(sound_error) >= 0.025 or abs(visual_error - sound_error) >= 0.027:
        raise AssertionError("MP4 picture or sound moved relative to the approved source interval")

    measurement = {
        "approved_start": start, "approved_end": end, "mp4_duration": duration,
        "frames": len(observed), "native_frame_interval_seconds": NATIVE_FRAME_SECONDS,
        "maximum_frame_gap_seconds": round(largest_gap, 6), "maximum_video_pts_error_ms": round(error * 1000, 3),
        "visual_marker_seconds": round(visual_observed, 6), "audio_marker_seconds": round(sound_observed, 6),
        "audio_marker_error_ms": round(sound_error * 1000, 3),
        "audio_video_sync_change_ms": round((sound_error - visual_error) * 1000, 3),
    }
    if cue is not None:
        burned_at = subtitle_marker(target, observed)
        if not -0.01 <= burned_at - cue["start"] < 2 * NATIVE_FRAME_SECONDS + 0.01:
            raise AssertionError("MP4 subtitle drift exceeded one observed frame interval")
        for suffix, separator in ((".srt", ","), (".vtt", ".")):
            sidecar = target.with_suffix(suffix).read_text(encoding="utf-8")
            line = subtitle_timestamp(cue["start"], separator) + " --> " + subtitle_timestamp(cue["end"], separator)
            if line not in sidecar or cue["text"] not in sidecar:
                raise AssertionError("Subtitle sidecar did not keep the approved relative timing and text")
        measurement.update(subtitle_start=cue["start"], subtitle_end=cue["end"],
                           subtitle_display_seconds=round(burned_at, 6), srt_verified=True, vtt_verified=True)
    return measurement


@unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg required")
class PrecisionCutTests(unittest.TestCase):
    def test_native_frames_audio_and_relative_subtitles_across_late_cuts(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-precision-cut-") as directory:
            source = Path(directory) / "source.mp4"
            make_fixture(source)
            for index, (start, end, marker) in enumerate(CUTS):
                with self.subTest(start=start, end=end):
                    target = source.with_name(f"clip-{index}.mp4")
                    relative_marker = round(marker - start, 3)
                    cue_end = round(relative_marker + 0.4, 3)
                    cues = [{"start": relative_marker, "end": cue_end, "text": "Marcador de audio"}]
                    render_clip(source, target, start=start, end=end, options=Presentation(burn_subtitles=True),
                                cues=cues, pilot=True)
                    self.assertTrue(measure_cut(source, target, start, end, marker, cue=cues[0])["srt_verified"])
