"""SEC-04 synthetic trust trees and mocked process contracts; no real media/IA.

These fixtures exercise Linux selection policy without reading host binaries,
package records, credentials or operational files. They do not establish actual
image/package provenance; the coordinator measures that in isolated candidates.
"""
from __future__ import annotations

from contextlib import ExitStack
import io
import json
import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest
from unittest import mock

from app import audio_check, media, media_binaries, render


class SyntheticTrustTree:
    """All filesystem trust observations are synthetic and fail on unknown IO."""

    PACKAGE = "/var/lib/dpkg/info/ffmpeg.list"
    DIRECTORIES = ("/", "/usr", "/usr/bin", "/var", "/var/lib", "/var/lib/dpkg", "/var/lib/dpkg/info")
    TOOLS = ("/usr/bin/ffmpeg", "/usr/bin/ffprobe")

    def __init__(self):
        self.metadata = {path: self.record(stat.S_IFDIR | 0o755) for path in self.DIRECTORIES}
        self.metadata.update({path: self.record(stat.S_IFREG | 0o755) for path in self.TOOLS})
        self.metadata[self.PACKAGE] = self.record(stat.S_IFREG | 0o644)
        self.magic = {path: b"\x7fELFSYNTHETIC-not-a-real-executable" for path in self.TOOLS}
        self.package = "/.\n/usr\n/usr/bin\n/usr/bin/ffmpeg\n/usr/bin/ffprobe\n"
        self.stat_calls = []
        self.open_calls = []
        self.read_text_calls = []
        self.magic_reads = []
        self.access = mock.Mock(return_value=True)

    @staticmethod
    def record(mode, uid=0):
        return os.stat_result((mode, 1, 1, 1, uid, 0, 64, 0, 0, 0))

    def lstat(self, path):
        name = path.as_posix()
        self.stat_calls.append(name)
        if name not in self.metadata:
            raise AssertionError("Unexpected filesystem metadata read: " + name)
        value = self.metadata[name]
        if isinstance(value, Exception):
            raise value
        return value

    def open(self, path, mode="r", *args, **kwargs):
        name = path.as_posix()
        self.open_calls.append((name, mode))
        if name not in self.magic or mode != "rb" or args or kwargs:
            raise AssertionError("Unexpected filesystem open: " + name)
        value = self.magic[name]
        if isinstance(value, Exception):
            raise value
        observations = self.magic_reads

        class MagicBytes(io.BytesIO):
            def read(self, size=-1):
                observations.append((name, size))
                return super().read(size)

        return MagicBytes(value)

    def read_text(self, path, *args, **kwargs):
        name = path.as_posix()
        self.read_text_calls.append((name, args, kwargs))
        if name != self.PACKAGE or args or kwargs != {"encoding": "utf-8"}:
            raise AssertionError("Unexpected package record read: " + name)
        if isinstance(self.package, Exception):
            raise self.package
        return self.package

    def __enter__(self):
        self.stack = ExitStack()
        self.stack.enter_context(mock.patch.object(media_binaries.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(Path, "lstat", lambda path: self.lstat(path)))
        self.stack.enter_context(mock.patch.object(Path, "open", lambda path, *a, **kw: self.open(path, *a, **kw)))
        self.stack.enter_context(mock.patch.object(Path, "read_text", lambda path, *a, **kw: self.read_text(path, *a, **kw)))
        self.stack.enter_context(mock.patch.object(media_binaries.os, "access", self.access))
        return self

    def __exit__(self, *exception):
        return self.stack.__exit__(*exception)


class MediaBinaryTrustTests(unittest.TestCase):
    def test_accepts_only_default_or_exact_candidate_for_both_tools(self):
        with SyntheticTrustTree() as tree:
            self.assertEqual(media_binaries.PACKAGE_LIST.as_posix(), tree.PACKAGE)
            for name in ("ffmpeg", "ffprobe"):
                with self.subTest(name=name):
                    expected = "/usr/bin/" + name
                    self.assertEqual(media_binaries.resolve_media_binary(name), expected)
                    self.assertEqual(media_binaries.resolve_media_binary(name, candidate=expected), expected)
                    self.assertIn((expected, 4), tree.magic_reads)
                    self.assertIn(mock.call(Path(expected), os.X_OK), tree.access.call_args_list)
            self.assertEqual(len(tree.read_text_calls), 4)

    def test_rejects_unknown_tool_before_any_filesystem_access(self):
        with SyntheticTrustTree() as tree:
            for name in ("", "FFMPEG", "ffmpeg.exe", "ffprobe.exe", "/usr/bin/ffmpeg", "python", None):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    media_binaries.resolve_media_binary(name)
            self.assertEqual(tree.stat_calls, [])
            tree.access.assert_not_called()

    def test_rejects_unlisted_candidates_without_normalizing_or_falling_back(self):
        with SyntheticTrustTree() as tree:
            for name in ("ffmpeg", "ffprobe"):
                candidates = (name, "/bin/" + name, "/usr/local/bin/" + name,
                              "/usr/bin/../bin/" + name, "/usr/bin/" + name + "/",
                              "/usr/bin/" + name + ".cmd", "/usr/bin/" + name + ".bat",
                              "/usr/bin/ffprobe" if name == "ffmpeg" else "/usr/bin/ffmpeg")
                for candidate in candidates:
                    with self.subTest(name=name, candidate=candidate), self.assertRaises(PermissionError):
                        media_binaries.resolve_media_binary(name, candidate=candidate)
            self.assertEqual(tree.stat_calls, [])

    def test_non_linux_platform_fails_with_explicit_container_guidance(self):
        with SyntheticTrustTree() as tree:
            for platform in ("win32", "darwin"):
                with self.subTest(platform=platform), mock.patch.object(media_binaries.sys, "platform", platform):
                    with self.assertRaisesRegex(RuntimeError, "Linux containers.*Docker Desktop"):
                        media_binaries.resolve_media_binary("ffmpeg")
            self.assertEqual(tree.stat_calls, [])

    def test_path_is_ignored_and_missing_fixed_binary_never_searches_or_runs(self):
        with mock.patch.object(shutil, "which", side_effect=AssertionError("PATH search prohibited")), \
                mock.patch.object(subprocess, "run", side_effect=AssertionError("Resolver cannot run processes")):
            for value in ("", "/synthetic/untrusted;PATH"):
                with self.subTest(path=value), SyntheticTrustTree() as tree, \
                        mock.patch.object(media_binaries.os, "environ", {"PATH": value}):
                    self.assertEqual(media_binaries.resolve_media_binary("ffmpeg"), "/usr/bin/ffmpeg")
                    tree.metadata["/usr/bin/ffmpeg"] = FileNotFoundError("SYNTHETIC missing fixed path")
                    with self.assertRaises(FileNotFoundError):
                        media_binaries.resolve_media_binary("ffmpeg")

    def test_missing_binary_or_any_parent_fails_closed(self):
        for path in ("/", "/usr", "/usr/bin", "/usr/bin/ffmpeg"):
            with self.subTest(path=path), SyntheticTrustTree() as tree:
                tree.metadata[path] = FileNotFoundError("SYNTHETIC absent: " + path)
                with self.assertRaises(FileNotFoundError):
                    media_binaries.resolve_media_binary("ffmpeg")
                self.assertEqual(tree.open_calls, [])

    def test_binary_must_be_regular_not_link_directory_or_special_file(self):
        for kind in (stat.S_IFLNK, stat.S_IFDIR, stat.S_IFIFO, stat.S_IFSOCK, stat.S_IFCHR):
            with self.subTest(kind=kind), SyntheticTrustTree() as tree:
                tree.metadata["/usr/bin/ffmpeg"] = tree.record(kind | 0o755)
                with self.assertRaises(PermissionError):
                    media_binaries.resolve_media_binary("ffmpeg")
                self.assertEqual(tree.open_calls, [])

    def test_each_binary_parent_must_be_directory_without_symlink(self):
        for path in ("/", "/usr", "/usr/bin"):
            for kind in (stat.S_IFLNK, stat.S_IFREG, stat.S_IFIFO):
                with self.subTest(path=path, kind=kind), SyntheticTrustTree() as tree:
                    tree.metadata[path] = tree.record(kind | 0o755)
                    with self.assertRaises(PermissionError):
                        media_binaries.resolve_media_binary("ffmpeg")

    def test_binary_and_each_parent_require_root_owner(self):
        for path in ("/", "/usr", "/usr/bin", "/usr/bin/ffmpeg"):
            with self.subTest(path=path), SyntheticTrustTree() as tree:
                tree.metadata[path] = tree.record(tree.metadata[path].st_mode, uid=1001)
                with self.assertRaises(PermissionError):
                    media_binaries.resolve_media_binary("ffmpeg")

    def test_group_or_other_write_rejected_at_each_binary_component(self):
        for path in ("/", "/usr", "/usr/bin", "/usr/bin/ffmpeg"):
            for writable in (0o020, 0o002, 0o022):
                with self.subTest(path=path, writable=oct(writable)), SyntheticTrustTree() as tree:
                    tree.metadata[path] = tree.record(tree.metadata[path].st_mode | writable)
                    with self.assertRaises(PermissionError):
                        media_binaries.resolve_media_binary("ffmpeg")

    def test_setuid_or_setgid_binary_is_rejected(self):
        for special in (stat.S_ISUID, stat.S_ISGID, stat.S_ISUID | stat.S_ISGID):
            with self.subTest(special=special), SyntheticTrustTree() as tree:
                tree.metadata["/usr/bin/ffmpeg"] = tree.record(stat.S_IFREG | 0o755 | special)
                with self.assertRaises(PermissionError):
                    media_binaries.resolve_media_binary("ffmpeg")

    def test_execution_access_is_required_for_current_identity(self):
        with SyntheticTrustTree() as tree:
            tree.access.return_value = False
            with self.assertRaisesRegex(PermissionError, "not executable by this identity"):
                media_binaries.resolve_media_binary("ffmpeg")
            tree.access.assert_called_once_with(Path("/usr/bin/ffmpeg"), os.X_OK)
            self.assertEqual(tree.open_calls, [])

    def test_native_elf_magic_required_including_truncated_and_script_headers(self):
        for value in (b"", b"\x7fEL", b"ELF\x7f", b"#!/bin/sh\n", b"MZsynthetic-windows", b"\x00ELF"):
            with self.subTest(value=value), SyntheticTrustTree() as tree:
                tree.magic["/usr/bin/ffmpeg"] = value
                with self.assertRaisesRegex(PermissionError, "native Linux ELF"):
                    media_binaries.resolve_media_binary("ffmpeg")
                self.assertEqual(tree.read_text_calls, [])

    def test_missing_package_record_or_ancestors_fails_closed(self):
        for path in ("/var", "/var/lib", "/var/lib/dpkg", "/var/lib/dpkg/info", SyntheticTrustTree.PACKAGE):
            with self.subTest(path=path), SyntheticTrustTree() as tree:
                tree.metadata[path] = FileNotFoundError("SYNTHETIC missing package path")
                with self.assertRaises(FileNotFoundError):
                    media_binaries.resolve_media_binary("ffmpeg")
                self.assertEqual(tree.read_text_calls, [])

    def test_package_record_and_ancestors_require_trusted_types_owner_and_modes(self):
        paths = ("/var", "/var/lib", "/var/lib/dpkg", "/var/lib/dpkg/info", SyntheticTrustTree.PACKAGE)
        for path in paths:
            for defect in ("link", "wrong_type", "owner", "group_write", "other_write"):
                with self.subTest(path=path, defect=defect), SyntheticTrustTree() as tree:
                    old = tree.metadata[path].st_mode
                    wrong = stat.S_IFDIR if path == tree.PACKAGE else stat.S_IFREG
                    mode = {"link": stat.S_IFLNK | 0o755, "wrong_type": wrong | 0o755,
                            "owner": old, "group_write": old | 0o020, "other_write": old | 0o002}[defect]
                    tree.metadata[path] = tree.record(mode, uid=1001 if defect == "owner" else 0)
                    with self.assertRaises(PermissionError):
                        media_binaries.resolve_media_binary("ffmpeg")
                    self.assertEqual(tree.read_text_calls, [])
        for special in (stat.S_ISUID, stat.S_ISGID):
            with self.subTest(package_special=special), SyntheticTrustTree() as tree:
                tree.metadata[tree.PACKAGE] = tree.record(stat.S_IFREG | 0o644 | special)
                with self.assertRaises(PermissionError):
                    media_binaries.resolve_media_binary("ffmpeg")

    def test_package_membership_requires_exact_tool_line(self):
        for value in ("", "/usr/bin/ffprobe\n", "/usr/bin/ffmpeg-untrusted\n",
                      "prefix/usr/bin/ffmpeg\n", " /usr/bin/ffmpeg\n", "/usr/bin/ffmpeg \n"):
            with self.subTest(package=value), SyntheticTrustTree() as tree:
                tree.package = value
                with self.assertRaisesRegex(PermissionError, "not recorded in the Debian ffmpeg package"):
                    media_binaries.resolve_media_binary("ffmpeg")

    def test_trust_is_revalidated_after_previous_success_without_cached_bypass(self):
        with SyntheticTrustTree() as tree:
            self.assertEqual(media_binaries.resolve_media_binary("ffmpeg"), "/usr/bin/ffmpeg")
            tree.metadata["/usr/bin/ffmpeg"] = tree.record(stat.S_IFREG | 0o777)
            with self.assertRaises(PermissionError):
                media_binaries.resolve_media_binary("ffmpeg")

    def test_read_failures_propagate_instead_of_accepting_unverified_binary(self):
        for source in ("magic", "package"):
            error = PermissionError("SYNTHETIC unreadable trust input")
            with self.subTest(source=source), SyntheticTrustTree() as tree:
                if source == "magic":
                    tree.magic["/usr/bin/ffmpeg"] = error
                else:
                    tree.package = error
                with self.assertRaises(PermissionError) as raised:
                    media_binaries.resolve_media_binary("ffmpeg")
                self.assertIs(raised.exception, error)


class MediaBinaryCallerTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="clipforge-sec04-callers-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.input = self.root / "input ; $(SYNTHETIC).mp4"
        self.input.write_bytes(b"SYNTHETIC non-media bytes; subprocess always mocked")
        self.output = self.root / "output ; SYNTHETIC.mp4"

    def test_audio_uses_selected_absolute_binary_and_separate_arguments(self):
        def create_output(command, **kwargs):
            self.output.write_bytes(b"SYNTHETIC output")
            return subprocess.CompletedProcess(command, 0, "", "")

        with mock.patch.object(audio_check, "resolve_media_binary", return_value="/usr/bin/ffmpeg") as resolve, \
                mock.patch.object(audio_check.subprocess, "run", side_effect=create_output) as run:
            audio_check.make_test_mp4(self.input, self.output)
        resolve.assert_called_once_with("ffmpeg")
        run.assert_called_once_with([
            "/usr/bin/ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y",
            "-f", "lavfi", "-i", "color=c=black:s=160x90:r=5", "-i", str(self.input),
            "-t", "1", "-map", "0:v:0", "-map", "1:a:0", "-c:v", "libx264", "-threads", "1",
            "-preset", "ultrafast", "-pix_fmt", "yuv420p", "-c:a", "aac", str(self.output),
        ], capture_output=True, text=True, errors="replace", timeout=30)

    def test_audio_preserves_nonzero_timeout_and_trust_failures_without_output(self):
        timeout = subprocess.TimeoutExpired(["/usr/bin/ffmpeg"], 30)
        for failure in ("nonzero", "timeout", "untrusted"):
            with self.subTest(failure=failure), \
                    mock.patch.object(audio_check, "resolve_media_binary", return_value="/usr/bin/ffmpeg") as resolve, \
                    mock.patch.object(audio_check.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, "", "SYNTHETIC failure")) as run:
                if failure == "timeout":
                    run.side_effect = timeout
                    expected = subprocess.TimeoutExpired
                elif failure == "untrusted":
                    resolve.side_effect = PermissionError("SYNTHETIC untrusted tool")
                    expected = PermissionError
                else:
                    expected = RuntimeError
                with self.assertRaises(expected) as raised:
                    audio_check.make_test_mp4(self.input, self.output)
                if failure == "nonzero":
                    self.assertEqual(str(raised.exception), "FFmpeg test fixture failed: SYNTHETIC failure")
                elif failure == "timeout":
                    self.assertIs(raised.exception, timeout)
                else:
                    run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_render_preserves_selected_binary_argv_and_execution_controls(self):
        arguments = ("-i", self.input, "-vf", "scale=16:16;SYNTHETIC", "-t", 1.5, self.output)
        with mock.patch.object(render, "resolve_media_binary", return_value="/usr/bin/ffmpeg") as resolve, \
                mock.patch.object(render.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, "", "")) as run:
            render.run_ffmpeg(*arguments)
        resolve.assert_called_once_with("ffmpeg")
        run.assert_called_once_with([
            "/usr/bin/ffmpeg", "-nostdin", "-hide_banner", "-loglevel", "error", "-y", *map(str, arguments),
        ], capture_output=True, text=True, errors="replace", timeout=1800)
        self.assertFalse(self.output.exists())

    def test_render_preserves_nonzero_timeout_and_trust_failure_contracts(self):
        timeout = subprocess.TimeoutExpired(["/usr/bin/ffmpeg"], 1800)
        for failure in ("nonzero", "timeout", "untrusted"):
            with self.subTest(failure=failure), \
                    mock.patch.object(render, "resolve_media_binary", return_value="/usr/bin/ffmpeg") as resolve, \
                    mock.patch.object(render.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, "", "SYNTHETIC failure")) as run:
                if failure == "timeout":
                    run.side_effect = timeout
                elif failure == "untrusted":
                    resolve.side_effect = PermissionError("SYNTHETIC untrusted tool")
                with self.assertRaises(PermissionError if failure == "untrusted" else RuntimeError) as raised:
                    render.run_ffmpeg("-i", self.input, self.output)
                if failure == "nonzero":
                    self.assertEqual(str(raised.exception), "FFmpeg falló (7): SYNTHETIC failure")
                elif failure == "timeout":
                    self.assertEqual(str(raised.exception), "FFmpeg superó el límite de 1800 segundos por clip")
                    self.assertIs(raised.exception.__cause__, timeout)
                else:
                    run.assert_not_called()
                self.assertFalse(self.output.exists())

    def test_probe_uses_selected_absolute_binary_and_keeps_path_one_argument(self):
        payload = {"format": {"duration": "2.5", "format_name": "mp4"}, "streams": []}
        with mock.patch.object(media, "resolve_media_binary", return_value="/usr/bin/ffprobe") as resolve, \
                mock.patch.object(media.subprocess, "run", return_value=subprocess.CompletedProcess([], 0, json.dumps(payload), "")) as run:
            result = media.probe_media(self.input)
        resolve.assert_called_once_with("ffprobe")
        run.assert_called_once_with([
            "/usr/bin/ffprobe", "-v", "error", "-protocol_whitelist", "file,pipe", "-show_entries",
            "format=duration,format_name:stream=index,codec_type,codec_name,duration,sample_rate,channels,width,height:stream_disposition=attached_pic",
            "-of", "json", str(self.input.resolve()),
        ], capture_output=True, text=True, errors="replace", timeout=30)
        self.assertEqual(result["duration_seconds"], 2.5)
        self.assertEqual(self.input.read_bytes(), b"SYNTHETIC non-media bytes; subprocess always mocked")

    def test_probe_preserves_nonzero_timeout_and_trust_failure_categories(self):
        timeout = subprocess.TimeoutExpired(["/usr/bin/ffprobe"], 30)
        for failure in ("nonzero", "timeout", "untrusted"):
            with self.subTest(failure=failure), \
                    mock.patch.object(media, "resolve_media_binary", return_value="/usr/bin/ffprobe") as resolve, \
                    mock.patch.object(media.subprocess, "run", return_value=subprocess.CompletedProcess([], 7, "", "SYNTHETIC failure")) as run:
                if failure == "timeout":
                    run.side_effect = timeout
                elif failure == "untrusted":
                    resolve.side_effect = PermissionError("SYNTHETIC untrusted tool")
                with self.assertRaises(PermissionError if failure == "untrusted" else media.MediaValidationError) as raised:
                    media.probe_media(self.input)
                if failure == "nonzero":
                    self.assertEqual(raised.exception.code, "INVALID_MEDIA")
                elif failure == "timeout":
                    self.assertEqual(raised.exception.code, "PROBE_TIMEOUT")
                    self.assertIs(raised.exception.__cause__, timeout)
                else:
                    run.assert_not_called()
                self.assertEqual(self.input.read_bytes(), b"SYNTHETIC non-media bytes; subprocess always mocked")


if __name__ == "__main__":
    unittest.main()
