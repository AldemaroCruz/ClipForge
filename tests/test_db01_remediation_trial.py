"""Synthetic archive/patch-scope tests; no Docker or source build."""
import io
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import db01_remediation_trial as trial


class RemediationTrial(unittest.TestCase):
    def test_unreviewed_patch_or_arbitrary_path_cannot_start_a_container(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); inputs = root / "input"; inputs.mkdir()
            output = root / "trial"
            for candidate in ("../owned.patch", "/tmp/unreviewed.patch", "reference_2_9_14 --fuzz=3"):
                with self.subTest(candidate=candidate), mock.patch.object(trial.os, "name", "nt"), \
                        mock.patch.object(trial.subprocess, "run") as native:
                    with self.assertRaisesRegex(ValueError, "reviewed_patch_candidate_required"):
                        trial.run(inputs, output, candidate)
                    native.assert_not_called()
                    self.assertFalse(output.exists())

    def test_archive_paths_and_link_types_are_closed_before_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "out"; output.mkdir()
            for index, name in enumerate(("../outside", "/absolute", "source/../outside", "C:/outside")):
                archive = root / (str(index) + ".tar.xz")
                with tarfile.open(archive, "w:xz") as stream:
                    info = tarfile.TarInfo(name); info.size = 1; stream.addfile(info, io.BytesIO(b"x"))
                with self.subTest(name=name), self.assertRaises(ValueError):
                    trial.extract_archive(archive, output, "source")
                self.assertEqual(list(output.iterdir()), [])
            archive = root / "link.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                info = tarfile.TarInfo("source/link"); info.type = tarfile.SYMTYPE; info.linkname = "/unreviewed"; stream.addfile(info)
            with self.assertRaises(ValueError):
                trial.extract_archive(archive, output, "source")

    def test_regular_source_extracts_once_and_series_rejects_options_or_traversal(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary); output = root / "out"; output.mkdir(); archive = root / "source.tar.xz"
            with tarfile.open(archive, "w:xz") as stream:
                info = tarfile.TarInfo("source/parser.c"); info.size = 1; stream.addfile(info, io.BytesIO(b"x"))
            trial.extract_archive(archive, output, "source")
            self.assertEqual((output / "source/parser.c").read_bytes(), b"x")
            with self.assertRaises(FileExistsError):
                trial.extract_archive(archive, output, "source")
            patches = output / "source/debian/patches"; patches.mkdir(parents=True)
            (patches / "known.patch").write_text("authored patch")
            for name in ("../other.patch", "known.patch -p0", "known.patch\nknown.patch"):
                (patches / "series").write_text(name)
                with self.subTest(name=name), self.assertRaises(ValueError):
                    trial.series_paths(output / "source")
            (patches / "series").write_text("known.patch\n")
            self.assertEqual(trial.series_paths(output / "source"), ["known.patch"])
