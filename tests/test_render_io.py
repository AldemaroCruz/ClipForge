"""Exercise real subprocess pipes without loading media or operator files."""
import os
import subprocess
import sys
import time
import tracemalloc
import unittest
from unittest import mock

from app import render


@unittest.skipUnless(os.name == "posix", "Supported runtime uses Linux containers")
class RenderIOTests(unittest.TestCase):
    def child(self, script, timeout=5):
        return render._bounded_ffmpeg([sys.executable, "-c", script], timeout)

    def test_large_both_pipes_are_drained_with_bounded_memory(self):
        script = ("import os\n"
                  "for _ in range(512):\n"
                  " os.write(1,b'x'*65536);os.write(2,b'y'*65536)\n"
                  "os.write(2,b'END-DIAGNOSTIC');raise SystemExit(7)")
        tracemalloc.start()
        try:
            code, tail = self.child(script)
            _, peak = tracemalloc.get_traced_memory()
        finally:
            tracemalloc.stop()
        self.assertEqual(code, 7)
        self.assertTrue(tail.endswith("END-DIAGNOSTIC"))
        self.assertLessEqual(len(tail.encode()), render.STDERR_LIMIT)
        self.assertLess(peak, 2 * 1024 * 1024)

    def test_partial_utf8_and_nonzero_are_reported_without_decode_failure(self):
        code, diagnostic = self.child("import os;os.write(2,b'\\xe2\\x82\\xac\\xf0\\x9f');raise SystemExit(9)")
        self.assertEqual(code, 9)
        self.assertEqual(diagnostic, "€�")

    def test_normal_exit_with_no_output(self):
        self.assertEqual(self.child("pass"), (0, ""))

    def test_timeout_kills_and_reaps_child(self):
        original = subprocess.Popen
        children = []
        def capture(*args, **kwargs):
            child = original(*args, **kwargs)
            children.append(child)
            return child
        started = time.monotonic()
        with mock.patch.object(render.subprocess, "Popen", side_effect=capture):
            with self.assertRaises(subprocess.TimeoutExpired):
                self.child("import os,time;os.write(2,b'waiting');time.sleep(30)", timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)
        self.assertIsNotNone(children[0].returncode)
        with self.assertRaises(ChildProcessError):
            os.waitpid(children[0].pid, os.WNOHANG)

    def test_descendant_holding_stderr_does_not_defeat_timeout(self):
        script = "import os,time\nif os.fork()==0: time.sleep(30)\nelse: os._exit(0)"
        started = time.monotonic()
        with self.assertRaises(subprocess.TimeoutExpired):
            self.child(script, timeout=0.15)
        self.assertLess(time.monotonic() - started, 3)


if __name__ == "__main__":
    unittest.main()
