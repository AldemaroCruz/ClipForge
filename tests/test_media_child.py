"""Real Linux process-lifetime regressions using synthetic media commands."""
import errno
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock

from app import media_child


PARENT_SCRIPT = r"""
import os,subprocess,sys,time
from pathlib import Path
pidfile,ready,gate,mode=sys.argv[1:]
if mode=='active':
    media="import os,sys,time;from pathlib import Path;Path(sys.argv[1]).write_text(str(os.getpid()));time.sleep(60)"
    command=[sys.executable,'-m','app.media_child',str(os.getpid()),sys.executable,'-c',media,ready]
else:
    deferred=""" + repr("import os,sys,time\nfrom pathlib import Path\ngate,parent,marker=sys.argv[1:]\nwhile not Path(gate).exists(): time.sleep(.01)\ncode='from pathlib import Path;import sys;Path(sys.argv[1]).write_text(\"unexpected execution\")'\nos.execv(sys.executable,[sys.executable,'-m','app.media_child',parent,sys.executable,'-c',code,marker])") + r"""
    command=[sys.executable,'-c',deferred,gate,str(os.getpid()),ready]
child=subprocess.Popen(command,start_new_session=True,stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
Path(pidfile).write_text(str(child.pid))
time.sleep(60)
"""


def process_info(pid):
    try:
        # /proc stat command names can contain spaces and parentheses. Remaining
        # fields begin at state (field3), ppid(field4), starttime(field22).
        data = Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
        return {"state": data[0], "parent": int(data[1]), "start": data[19]}
    except FileNotFoundError:
        return None


def wait_until(predicate, timeout=5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return True
        time.sleep(.01)
    return False


def process_stopped(pid):
    info = process_info(pid)
    return info is None or info["state"] == "Z"


@unittest.skipUnless(sys.platform == "linux", "Parent-death media supervision is Linux only")
class MediaChildProcessTests(unittest.TestCase):
    def _read_pid(self, path):
        def ready():
            try:
                return path.read_text().isdigit()
            except FileNotFoundError:
                return False
        self.assertTrue(wait_until(ready), "Synthetic process did not become ready")
        return int(path.read_text())

    def _cleanup(self, parent, child_pid, identity):
        if parent.poll() is None:
            parent.kill()
        parent.wait(timeout=5)
        if child_pid:
            current = process_info(child_pid)
            if current and current["state"] != "Z" and identity and current["start"] == identity["start"]:
                # The process is our exclusively created session leader. Never
                # select or terminate a process by name or a broad pattern.
                if os.getsid(child_pid) != child_pid:
                    raise AssertionError("Synthetic child session identity changed")
                os.killpg(child_pid, signal.SIGKILL)
                self.assertTrue(wait_until(lambda: process_stopped(child_pid)))
            try:
                os.waitpid(child_pid, os.WNOHANG)
            except ChildProcessError:
                pass

    def test_parent_death_kills_exec_process_in_its_own_session(self):
        for death_signal in (signal.SIGTERM, signal.SIGKILL):
            with self.subTest(signal=death_signal), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                parent = subprocess.Popen([sys.executable, "-c", PARENT_SCRIPT, str(root/"pid"), str(root/"ready"), str(root/"gate"), "active"],
                                          stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                child_pid, identity = None, None
                try:
                    child_pid = self._read_pid(root/"pid")
                    identity = process_info(child_pid)
                    self.assertEqual(self._read_pid(root/"ready"), child_pid)
                    self.assertEqual(os.getsid(child_pid), child_pid)
                    self.assertEqual(process_info(child_pid)["parent"], parent.pid)
                    os.kill(parent.pid, death_signal)
                    parent.wait(timeout=5)
                    self.assertTrue(wait_until(lambda: process_stopped(child_pid)),
                                    "Media process survived its parent in a separate session")
                finally:
                    self._cleanup(parent, child_pid, identity)

    def test_parent_already_dead_before_launcher_exec_cannot_start_media(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            parent = subprocess.Popen([sys.executable, "-c", PARENT_SCRIPT, str(root/"pid"), str(root/"unexpected"), str(root/"gate"), "deferred"],
                                      stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            child_pid, identity = None, None
            try:
                child_pid = self._read_pid(root/"pid")
                identity = process_info(child_pid)
                parent.kill()
                parent.wait(timeout=5)
                self.assertTrue(wait_until(lambda: process_info(child_pid)["parent"] != parent.pid))
                (root/"gate").touch()
                self.assertTrue(wait_until(lambda: process_stopped(child_pid)))
                self.assertFalse((root/"unexpected").exists(), "Launcher executed media with an already dead parent")
            finally:
                self._cleanup(parent, child_pid, identity)

    def test_exec_preserves_normal_command_exit_status(self):
        result = subprocess.run([sys.executable, "-m", "app.media_child", str(os.getpid()), sys.executable, "-c", "raise SystemExit(7)"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
        self.assertEqual(result.returncode, 7, result.stderr.decode(errors="replace"))


class MediaChildValidationTests(unittest.TestCase):
    def test_non_linux_invalid_parent_and_relative_commands_do_not_exec(self):
        cases = [("win32", ["12", "/usr/bin/ffmpeg"]),
                 ("linux", ["0", "/usr/bin/ffmpeg"]), ("linux", ["-1", "/usr/bin/ffmpeg"]),
                 ("linux", ["2147483648", "/usr/bin/ffmpeg"]), ("linux", ["12", "ffmpeg"])]
        for platform, arguments in cases:
            with self.subTest(platform=platform, arguments=arguments), mock.patch.object(media_child.sys, "platform", platform), \
                    mock.patch.object(media_child.os, "execv") as execute, mock.patch.object(media_child.sys, "stderr"):
                self.assertEqual(media_child.main(arguments), 70)
                execute.assert_not_called()

    def test_parent_change_during_prctl_prevents_exec(self):
        libc = mock.MagicMock()
        libc.prctl.return_value = 0
        with mock.patch.object(media_child.os, "getppid", side_effect=[321, 1]), mock.patch.object(media_child.ctypes, "CDLL", return_value=libc), \
                mock.patch.object(media_child.signal, "SIGKILL", 9, create=True):
            with self.assertRaises(media_child.MediaChildError):
                media_child._arm_parent_death(321)
        libc.prctl.assert_called_once_with(media_child.PR_SET_PDEATHSIG, 9, 0, 0, 0)

    def test_file_capabilities_or_privileged_mode_are_rejected(self):
        for mode, capability in ((stat.S_IFREG | 0o4755, b""), (stat.S_IFREG | 0o2755, b""), (stat.S_IFREG | 0o755, b"capability")):
            with self.subTest(mode=mode, capability=capability), mock.patch.object(media_child.os, "stat", return_value=SimpleNamespace(st_mode=mode)), \
                    mock.patch.object(media_child.os, "getxattr", return_value=capability, create=True):
                with self.assertRaises(media_child.MediaChildError):
                    media_child._validate_command(["/usr/bin/ffmpeg"])
        with mock.patch.object(media_child.os, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o755)), \
                mock.patch.object(media_child.os, "getxattr", side_effect=OSError(errno.EACCES, "fixture"), create=True):
            with self.assertRaises(media_child.MediaChildError):
                media_child._validate_command(["/usr/bin/ffmpeg"])


if __name__ == "__main__":
    unittest.main()
