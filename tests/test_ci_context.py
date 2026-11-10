"""Source-context security regressions using temporary authored files only."""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import stat
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import prepare_ci_context as ci


class CIContextTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-ci-context-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        for directory in ci.DIRECTORIES:
            (self.source / directory).mkdir(parents=True, exist_ok=True)
        for name in ci.ROOT_FILES:
            (self.source / name).write_text("authored root fixture\n", encoding="utf-8")
        for name in ("app/__init__.py", "app/main.py", "scripts/run_ci_tests.py", "scripts/prepare_ci_context.py", "tests/test_example.py"):
            (self.source / name).write_text("# authored source fixture\n", encoding="utf-8")
        (self.source / "app/static/index.html").write_text("<p>synthetic</p>", encoding="utf-8")
        self.destination = self.base / "context"
        self.manifest = self.base / "context-manifest.json"

    def prepare(self):
        return ci.prepare_context(self.source, self.destination, self.manifest)

    def verify(self):
        return ci.verify_context(self.destination, self.manifest)

    def test_context_roundtrip_hashes_exact_authored_files(self):
        prepared = self.prepare()
        self.assertEqual(self.verify(), prepared)
        manifest = json.loads(self.manifest.read_text(encoding="utf-8"))
        for item in manifest["files"]:
            data = (self.destination / item["path"]).read_bytes()
            self.assertEqual(item["bytes"], len(data))
            self.assertEqual(item["sha256"], hashlib.sha256(data).hexdigest())
        self.assertFalse((self.destination / self.manifest.name).exists())

    def test_private_trees_and_files_are_not_entered_or_copied(self):
        private = ("data", "cache", "backups", "release", "evidence", "test-evidence", "restore-check-fixture")
        for name in private:
            directory = self.source / name
            directory.mkdir()
            (directory / "private.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / ".env.ai").write_text("SYNTHETIC_ONLY=never-copy", encoding="utf-8")
        (self.source / "scripts/.env.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / "scripts/credentials.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / "app/private.mp4").write_bytes(b"synthetic non-video bytes")
        nested = self.source / "scripts/data"
        nested.mkdir()
        (nested / "private.py").write_text("synthetic private sentinel", encoding="utf-8")
        visited = []
        scandir = os.scandir

        def record(path):
            visited.append(Path(path))
            self.assertNotIn(Path(path).name, private)
            return scandir(path)

        with mock.patch.object(ci.os, "scandir", side_effect=record):
            self.prepare()
        self.assertNotIn(self.source, visited)  # Root private entries are never enumerated.
        actual = {path.relative_to(self.destination).as_posix() for path in self.destination.rglob("*")}
        self.assertNotIn("scripts/credentials.py", actual)
        self.assertNotIn("scripts/.env.py", actual)
        self.assertNotIn("scripts/data", actual)
        self.assertNotIn("app/private.mp4", actual)
        self.assertTrue(all(not any(part in private for part in Path(name).parts) for name in actual))

    def test_unknown_subdirectories_are_never_traversed(self):
        unknown = self.source / "app/unlisted"
        unknown.mkdir()
        (unknown / "extra.py").write_text("# must not copy", encoding="utf-8")
        self.prepare()
        self.assertFalse((self.destination / "app/unlisted").exists())

    def test_existing_destination_is_not_overwritten(self):
        self.destination.mkdir()
        marker = self.destination / "keep"
        marker.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(marker.read_bytes(), b"preserve")
        self.assertFalse(self.manifest.exists())

    def test_existing_manifest_is_not_overwritten(self):
        self.manifest.write_bytes(b"preserve")
        with self.assertRaises(FileExistsError):
            self.prepare()
        self.assertEqual(self.manifest.read_bytes(), b"preserve")
        self.assertFalse(self.destination.exists())

    def test_destination_inside_source_is_rejected(self):
        with self.assertRaises(ci.ContextError):
            ci.prepare_context(self.source, self.source / "new-context", self.manifest)
        self.assertFalse((self.source / "new-context").exists())

    def test_destination_containing_source_is_rejected(self):
        with self.assertRaises(ci.ContextError):
            ci.prepare_context(self.source, self.base, self.manifest)

    def test_manifest_inside_source_or_context_is_rejected(self):
        for manifest in (self.source / "manifest.json", self.destination / "manifest.json"):
            with self.subTest(manifest=manifest), self.assertRaises(ci.ContextError):
                ci.prepare_context(self.source, self.destination, manifest)
        self.assertFalse(self.destination.exists())

    def test_private_input_or_manifest_paths_are_rejected_before_access(self):
        for source, manifest in (
            (self.source / "data", self.manifest),
            (self.source, self.base / ".env.ai"),
            (self.source, self.base / "backups/manifest.json"),
        ):
            with self.subTest(source=source, manifest=manifest):
                with self.assertRaisesRegex(ci.ContextError, "Excluded private/artifact paths"):
                    ci.prepare_context(source, self.destination, manifest)
        self.assertFalse(self.destination.exists())

    def _fake_metadata(self, target, *, symlink=False, reparse=False):
        original = os.lstat

        def changed(path, *args, **kwargs):
            metadata = original(path, *args, **kwargs)
            if Path(path) != target:
                return metadata
            return SimpleNamespace(
                st_mode=stat.S_IFLNK if symlink else metadata.st_mode,
                st_file_attributes=0x400 if reparse else 0,
            )

        return changed

    def test_source_symlink_is_rejected_before_file_contents_are_read(self):
        target = self.source / "app/main.py"
        with mock.patch.object(ci.os, "lstat", side_effect=self._fake_metadata(target, symlink=True)):
            with self.assertRaisesRegex(ci.ContextError, "Symlinks"):
                self.prepare()
        self.assertFalse(self.destination.exists())

    def test_source_directory_reparse_point_is_rejected(self):
        target = self.source / "app/static"
        with mock.patch.object(ci.os, "lstat", side_effect=self._fake_metadata(target, reparse=True)):
            with self.assertRaisesRegex(ci.ContextError, "reparse"):
                self.prepare()
        self.assertFalse(self.destination.exists())

    def test_context_symlink_is_rejected_during_verification(self):
        self.prepare()
        target = self.destination / "app/main.py"
        with mock.patch.object(ci.os, "lstat", side_effect=self._fake_metadata(target, symlink=True)):
            with self.assertRaisesRegex(ci.ContextError, "Symlinks"):
                self.verify()

    def test_hash_drift_with_unchanged_file_size_is_rejected(self):
        self.prepare()
        path = self.destination / "app/main.py"
        original = path.read_bytes()
        path.write_bytes(b"!" + original[1:])
        with self.assertRaisesRegex(ci.ContextError, "inventory/hash"):
            self.verify()

    def test_missing_required_file_is_rejected(self):
        self.prepare()
        (self.destination / "app/main.py").unlink()
        with self.assertRaises((ci.ContextError, FileNotFoundError)):
            self.verify()

    def test_extra_allowlisted_source_file_is_rejected(self):
        self.prepare()
        (self.destination / "scripts/unrecorded.py").write_text("# extra", encoding="utf-8")
        with self.assertRaisesRegex(ci.ContextError, "inventory/hash"):
            self.verify()

    def test_extra_empty_directory_is_rejected(self):
        self.prepare()
        (self.destination / "app/extra").mkdir()
        with self.assertRaisesRegex(ci.ContextError, "unexpected directory"):
            self.verify()

    def test_extra_private_entry_is_rejected_without_reading_its_contents(self):
        self.prepare()
        secret = self.destination / "scripts/.env.py"
        secret.write_text("SYNTHETIC_ONLY=never-read", encoding="utf-8")
        reader = ci._stream_record

        def safe_reader(path, destination=None):
            self.assertNotEqual(path, secret)
            return reader(path, destination)

        with mock.patch.object(ci, "_stream_record", side_effect=safe_reader):
            with self.assertRaisesRegex(ci.ContextError, "private/artifact"):
                self.verify()

    def test_extra_root_tree_is_rejected_without_entering_it(self):
        self.prepare()
        (self.destination / "data").mkdir()
        with self.assertRaisesRegex(ci.ContextError, "unexpected root entry"):
            self.verify()

    def test_manifest_traversal_and_duplicate_paths_are_rejected(self):
        self.prepare()
        original = json.loads(self.manifest.read_text(encoding="utf-8"))
        for path in ("../outside.py", "app/../outside.py", "/app/main.py", "app\\main.py", "app//main.py"):
            value = json.loads(json.dumps(original))
            value["files"][0]["path"] = path
            self.manifest.write_text(json.dumps(value), encoding="utf-8")
            with self.subTest(path=path), self.assertRaises(ci.ContextError):
                self.verify()
        original["files"].append(dict(original["files"][0]))
        self.manifest.write_text(json.dumps(original), encoding="utf-8")
        with self.assertRaisesRegex(ci.ContextError, "Duplicate"):
            self.verify()

    def test_source_drift_during_copy_does_not_publish_manifest(self):
        reader = ci._stream_record
        changed = False

        def drift(path, destination=None):
            nonlocal changed
            result = reader(path, destination)
            if destination is not None and not changed:
                changed = True
                (self.source / "app/main.py").write_text("# changed during copy", encoding="utf-8")
            return result

        with mock.patch.object(ci, "_stream_record", side_effect=drift):
            with self.assertRaisesRegex(ci.ContextError, "drift"):
                self.prepare()
        self.assertFalse(self.manifest.exists())


if __name__ == "__main__":
    unittest.main()
