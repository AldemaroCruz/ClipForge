"""Real FFmpeg checks for creator logo geometry, alpha, and subtitle sidecars."""
from fractions import Fraction
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from unittest import TestCase, skipUnless

import av
import numpy as np
from pydantic import ValidationError

from app.logo_placement import LogoPlacement
from app.media import probe_media
from app.presentation import Presentation
from app.render import build_filter, render_clip


LOGO_ID = "a" * 32
LOGO = LogoPlacement(id=LOGO_ID, revision=1, size=20, opacity=50, position="bottom-right", margin=10)


class LogoPlacementTests(TestCase):
    def test_placement_is_bounded_and_rejects_unknown_filter_values(self):
        for changes in ({"size": 41}, {"opacity": -1}, {"margin": 21}, {"revision": True},
                        {"revision": 2_147_483_648}, {"position": "overlay=evil"},
                        {"id": "../other.png"}, {"path": "/tmp/other.png"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                LogoPlacement.model_validate({**LOGO.model_dump(), **changes})

    def test_logo_is_anchored_to_each_corner_after_crop_and_before_subtitles(self):
        for position, x, y in (
            ("top-left", "108", "108"),
            ("top-right", "W-w-108", "108"),
            ("bottom-left", "108", "H-h-108"),
            ("bottom-right", "W-w-108", "H-h-108"),
        ):
            with self.subTest(position=position):
                logo = LogoPlacement.model_validate({**LOGO.model_dump(), "position": position})
                graph = build_filter(Presentation(framing="crop", burn_subtitles=True),
                                     ass_path=Path("test.ass"), logo=logo)
                self.assertIn("scale=1080:1920[framed]", graph)
                self.assertIn("max(1,floor(iw*216/max(iw,ih)+0.5))", graph)
                self.assertIn(f"[framed][logo]overlay=x={x}:y={y}:", graph)
                self.assertIn("[branded]setsar=1,ass=", graph)
                self.assertIn("colorchannelmixer=aa=0.50", graph)


@skipUnless(sys.platform == "linux", "FFmpeg integration runs in Linux containers")
class LogoRenderTests(TestCase):
    def make_source(self, path):
        with av.open(str(path), "w") as output:
            video = output.add_stream("libx264", rate=6, options={"threads": "1"})
            video.width, video.height, video.pix_fmt = 320, 180, "yuv420p"
            audio = output.add_stream("aac", rate=16000)
            audio.layout = "mono"
            data = np.broadcast_to(np.array([32, 64, 128], dtype=np.uint8), (180, 320, 3)).copy()
            for _ in range(18):
                frame = av.VideoFrame.from_ndarray(data, format="rgb24")
                output.mux(video.encode(frame))
            output.mux(video.encode())
            frame = av.AudioFrame.from_ndarray(np.zeros((1, 48000), dtype=np.int16), format="s16", layout="mono")
            frame.sample_rate = 16000
            output.mux(audio.encode(frame))
            output.mux(audio.encode())

    def make_logo(self, path):
        # Tall logo with transparent, fully opaque, and half-alpha regions.
        data = np.zeros((40, 20, 4), dtype=np.uint8)
        data[:, :, 0] = 255
        data[:20, 10:, 3] = 255
        data[20:, :, 3] = 128
        encoder = av.CodecContext.create("png", "w")
        encoder.width, encoder.height, encoder.pix_fmt = 20, 40, "rgba"
        encoder.time_base = Fraction(1, 1)
        frame = av.VideoFrame.from_ndarray(data, format="rgba")
        path.write_bytes(b"".join(bytes(packet) for packet in encoder.encode(frame) + encoder.encode()))

    def pixels(self, path):
        with av.open(str(path)) as video:
            return next(frame.to_ndarray(format="rgb24") for frame in video.decode(video=0) if frame.time >= 1.25)

    def test_crop_encodes_png_alpha_and_keeps_previous_files_and_sidecars(self):
        with TemporaryDirectory(prefix="clipforge-logo-test-") as directory:
            root = Path(directory)
            source, png = root / "source.mp4", root / "creator-logo.png"
            self.make_source(source)
            self.make_logo(png)
            untouched, branded = root / "original-variant.mp4", root / "logo-variant.mp4"
            options = Presentation(framing="crop", crop_x=.2, crop_y=.8, crop_zoom=1.5, burn_subtitles=True)
            cues = [{"start": .25, "end": 1.8, "text": "Subtítulos guardados"}]
            render_clip(source, untouched, start=.5, end=2.5, options=options, cues=cues, pilot=True)
            previous = untouched.read_bytes()
            render_clip(source, branded, start=.5, end=2.5, options=options, cues=cues, pilot=True,
                        logo=LOGO, logo_path=png)
            result = probe_media(branded)
            self.assertEqual((result["width"], result["height"], result["audio_streams"]), (1080, 1920, 1))
            self.assertGreater(result["duration_seconds"], 1.8)
            self.assertEqual(untouched.read_bytes(), previous)
            self.assertNotEqual(branded.read_bytes(), previous)
            for suffix in (".srt", ".vtt"):
                self.assertEqual(untouched.with_suffix(suffix).read_bytes(), branded.with_suffix(suffix).read_bytes())

            diff = self.pixels(branded).astype(np.int16) - self.pixels(untouched)
            # 216 × 216 box fits a 108 × 216 asset. After the 108-pixel
            # margins, the bottom-right logo spans x=864..971, y=1596..1811.
            for x, y in ((851, 1700), (980, 1700), (950, 1585), (950, 1820), (890, 1625)):
                with self.subTest(point=(x, y)):
                    self.assertLessEqual(np.abs(diff[y, x]).max(), 12)
            red_delta_full = diff[1630, 950, 0]
            red_delta_half = diff[1760, 950, 0]
            self.assertGreater(red_delta_full, 80)
            self.assertLess(red_delta_full, 140)
            self.assertGreater(red_delta_half, red_delta_full * .35)
            self.assertLess(red_delta_half, red_delta_full * .65)

            blurred = root / "blurred-variant.mp4"
            render_clip(source, blurred, start=.5, end=2.5,
                        options=options.model_copy(update={"framing": "blur"}), cues=cues, pilot=True,
                        logo=LOGO, logo_path=png)
            blurred_pixels = self.pixels(blurred)
            self.assertEqual(blurred_pixels.shape, (1920, 1080, 3))
            self.assertGreater(int(blurred_pixels[1630, 950, 0]), int(blurred_pixels[1625, 890, 0]) + 80)
