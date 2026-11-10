"""Checker regression tests; decoder/VAD are mocked except where explicitly stated."""

import json
import shutil
import subprocess
import tempfile
import types
import unittest
import wave
from pathlib import Path
from unittest import mock

import numpy as np
from app import audio_check as audio


def test_tone():
    return (0.15 * np.sin(2 * np.pi * 440 * np.arange(16000) / 16000)).astype(np.float32)


class AudioCheckTests(unittest.TestCase):
    def setUp(self):
        self.decoder = mock.Mock(return_value=test_tone())
        self.vad = mock.Mock(return_value=[])
        modules = {"numpy": np, "faster_whisper.audio": types.SimpleNamespace(decode_audio=self.decoder),
                   "faster_whisper.vad": types.SimpleNamespace(get_speech_timestamps=self.vad)}
        patch = mock.patch.object(audio.importlib, "import_module", side_effect=modules.__getitem__)
        patch.start()
        self.addCleanup(patch.stop)
        patch = mock.patch.object(audio, "make_test_mp4", side_effect=lambda wav, mp4: mp4.write_bytes(b"mock fixture"))
        patch.start()
        self.addCleanup(patch.stop)

    def test_decodes_both_formats_at_16khz_and_cleans_temp(self):
        paths = []
        def decode(path, *, sampling_rate):
            paths.append(Path(path))
            self.assertTrue(Path(path).is_file())
            self.assertEqual(sampling_rate, 16000)
            return test_tone()
        self.decoder.side_effect = decode
        report = audio.check_audio_stack()
        self.assertEqual(report["status"], "ok")
        self.assertEqual({p.suffix for p in paths}, {".wav", ".mp4"})
        self.assertTrue(all(not p.parent.exists() for p in paths))
        self.assertEqual(self.vad.call_count, 1)
        silence = self.vad.call_args.args[0]
        self.assertEqual(silence.shape, (32000,))
        self.assertEqual(float(np.max(np.abs(silence))), 0.0)

    def test_metadata_errors_exception_is_not_swallowed(self):
        self.decoder.side_effect = TypeError("open() got an unexpected keyword argument 'metadata_errors'")
        report = audio.check_audio_stack()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(len(report["errors"]), 2)
        self.assertIn("metadata_errors", json.dumps(report))
        self.assertEqual(report["checks"]["silero_vad"]["status"], "ok")

    def test_decoder_empty_array_fails(self):
        self.decoder.return_value = np.array([], dtype=np.float32)
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_decoder_nan_fails(self):
        result = test_tone()
        result[4] = np.nan
        self.decoder.return_value = result
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_decoder_float64_fails(self):
        self.decoder.return_value = test_tone().astype(np.float64)
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_decoder_stereo_fails(self):
        self.decoder.return_value = np.vstack([test_tone(), test_tone()])
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_decoder_silence_does_not_falsely_pass(self):
        self.decoder.return_value = np.zeros(16000, dtype=np.float32)
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_vad_failure_does_not_hide_successful_decodes(self):
        self.vad.side_effect = RuntimeError("ONNX asset unavailable")
        result = audio.check_audio_stack()
        self.assertEqual(result["status"], "failed")
        self.assertEqual(result["checks"]["wav_decode"]["status"], "ok")
        self.assertEqual(result["errors"][0]["component"], "silero_vad")

    def test_unexpected_speech_on_silence_fails(self):
        self.vad.return_value = [{"start": 0, "end": 16000}]
        self.assertEqual(audio.check_audio_stack()["status"], "failed")

    def test_fixture_failure_is_reported(self):
        with mock.patch.object(audio, "make_test_mp4", side_effect=RuntimeError("missing AAC encoder")):
            report = audio.check_audio_stack()
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["errors"][0]["component"], "mp4_decode")

    def test_setup_import_failure_is_reported(self):
        with mock.patch.object(audio.importlib, "import_module", side_effect=ImportError("missing av")):
            self.assertEqual(audio.check_audio_stack()["status"], "failed")


class RealFixtureTests(unittest.TestCase):
    def test_wav_fixture_is_real_pcm_stereo_44100hz(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / "tone.wav"
            audio.make_test_wav(path)
            with wave.open(str(path), "rb") as wav:
                self.assertEqual((wav.getnchannels(), wav.getsampwidth(), wav.getframerate(), wav.getnframes()),
                                 (2, 2, 44100, 44100))

    @unittest.skipUnless(shutil.which("ffmpeg") and shutil.which("ffprobe"), "FFmpeg/ffprobe needed")
    def test_real_mp4_aac_fixture_is_decodable_by_ffmpeg(self):
        # FFmpeg real. This does NOT prove PyAV or Whisper decoding.
        with tempfile.TemporaryDirectory() as folder:
            wav, mp4 = Path(folder) / "tone.wav", Path(folder) / "tone.mp4"
            audio.make_test_wav(wav)
            audio.make_test_mp4(wav, mp4)
            probe = subprocess.run(["ffprobe", "-v", "error", "-show_streams", "-of", "json", str(mp4)],
                                   check=True, capture_output=True, text=True, timeout=10)
            streams = json.loads(probe.stdout)["streams"]
            self.assertTrue(any(s["codec_name"] == "aac" for s in streams))
            self.assertTrue(any(s["codec_name"] == "h264" for s in streams))
            pcm = subprocess.run(["ffmpeg", "-nostdin", "-v", "error", "-i", str(mp4),
                                  "-vn", "-ar", "16000", "-ac", "1", "-f", "f32le", "pipe:1"],
                                 check=True, capture_output=True, timeout=10)
            report = audio.verify_decoded_audio(np.frombuffer(pcm.stdout, dtype=np.float32), np)
            self.assertEqual(report["status"], "ok")

    def test_mp4_fixture_failure_propagates(self):
        with mock.patch.object(audio.subprocess, "run", return_value=subprocess.CompletedProcess([], 1, "", "encoder failed")):
            with self.assertRaisesRegex(RuntimeError, "encoder failed"):
                audio.make_test_mp4(Path("unused.wav"), Path("unused.mp4"))


if __name__ == "__main__":
    unittest.main()
