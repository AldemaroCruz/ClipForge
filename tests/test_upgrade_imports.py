"""Real Python subprocess regressions for the v0.4.2 helper-import hotfix.

Uses synthetic data and stdlib only. Does not run PowerShell, Docker or a model.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

SOURCE_ROOT = Path(__file__).resolve().parents[1]
PROJECT_ID = "a" * 32


class UpgradeImportTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge upgrade import ")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "tools"
        (self.root / "app").mkdir(parents=True)
        (self.root / "scripts").mkdir()
        for name in ("__init__.py", "backup.py", "lease.py"):
            shutil.copy2(SOURCE_ROOT / "app" / name, self.root / "app" / name)
        for name in ("check_idle.py", "capture_runtime.py", "verify_runtime.py"):
            shutil.copy2(SOURCE_ROOT / "scripts" / name, self.root / "scripts" / name)
        self.data = Path(self.temp.name) / "data"
        folder = self.data / PROJECT_ID
        folder.mkdir(parents=True)
        self.job = folder / "job.json"
        self.job.write_text(json.dumps({"status": "completed", "private_text": "DO_NOT_PRINT_ME"}))
        (folder / "input.mp4").write_bytes(b"synthetic fixture, not a decoded video")

    def env(self, import_root: Path | None = None) -> dict[str, str]:
        result = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
        result["PYTHONDONTWRITEBYTECODE"] = "1"
        if import_root is not None:
            result["PYTHONPATH"] = str(import_root)
        return result

    def run_python(self, *args: str, import_root: Path | None = None,
                   cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        # -S deliberately excludes site-packages: these helper operations need stdlib only.
        return subprocess.run([sys.executable, "-S", *args], cwd=cwd or self.root,
                              env=self.env(import_root), capture_output=True, text=True,
                              timeout=20, check=False)

    def idle(self, import_root: Path | None = None) -> subprocess.CompletedProcess[str]:
        return self.run_python("scripts/check_idle.py", "--data", str(self.data),
                               import_root=import_root or self.root)

    def snapshot(self) -> dict[str, tuple[str, int]]:
        return {str(p.relative_to(self.data)): (hashlib.sha256(p.read_bytes()).hexdigest(),
                                               p.stat().st_mtime_ns)
                for p in self.data.rglob("*") if p.is_file()}

    def test_reproduces_missing_app_with_original_direct_launch(self) -> None:
        original = self.root / "scripts" / "original_check_idle.py"
        original.write_text("from pathlib import Path\nfrom app.backup import inventory, assert_quiescent\n"
                            "files,_=inventory(Path('/data'))\nassert_quiescent(files)\n")
        result = self.run_python("scripts/original_check_idle.py")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("ModuleNotFoundError: No module named 'app'", result.stderr)

    def test_cwd_alone_does_not_fix_direct_launch(self) -> None:
        result = self.run_python("scripts/check_idle.py", "--data", str(self.data))
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("No module named 'app'", result.stderr)

    def test_scoped_pythonpath_resolves_actual_imports_and_preserves_data(self) -> None:
        before = self.snapshot()
        result = self.idle()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("Upgrade imports OK", result.stdout)
        self.assertIn("No active persisted", result.stdout)
        self.assertEqual(before, self.snapshot())
        self.assertFalse((self.data / ".clipforge-runtime.lock").exists())
        self.assertNotIn("DO_NOT_PRINT_ME", result.stdout + result.stderr)

    def test_all_active_states_are_rejected_without_writes(self) -> None:
        for state in ("queued", "validating", "transcribing", "rendering", "running"):
            with self.subTest(state=state):
                self.job.write_text(json.dumps({"status": state}))
                before = self.snapshot()
                result = self.idle()
                self.assertNotEqual(result.returncode, 0)
                self.assertIn("Hay estados activos", result.stderr)
                self.assertEqual(before, self.snapshot())

    def test_missing_data_is_not_created(self) -> None:
        shutil.rmtree(self.data)
        result = self.idle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("data/ debe ser", result.stderr)
        self.assertFalse(self.data.exists())

    def test_unknown_file_is_not_silently_ignored(self) -> None:
        (self.data / "unknown.txt").write_text("private fixture")
        result = self.idle()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("Ruta desconocida", result.stderr)
        self.assertNotIn("private fixture", result.stdout + result.stderr)

    def test_old_app_shadowing_is_detected(self) -> None:
        other = Path(self.temp.name) / "old_image"
        shutil.copytree(self.root / "app", other / "app")
        result = self.idle(import_root=other)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("wrong app package", result.stderr)

    def test_failure_states_remain_readable_and_unchanged(self) -> None:
        for state in ("failed", "interrupted", "completed"):
            with self.subTest(state=state):
                self.job.write_text(json.dumps({"status": state}))
                before = self.snapshot()
                result = self.idle()
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(before, self.snapshot())

    def test_cli_capture_imports_without_requesting_model(self) -> None:
        result = self.run_python("scripts/capture_runtime.py", "--help", import_root=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("--output", result.stdout)

    def test_sibling_import_in_verify_runtime_still_works(self) -> None:
        result = self.run_python("scripts/verify_runtime.py", "--help", import_root=self.root)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("lock", result.stdout)

    def test_module_backup_roundtrip_with_scoped_pythonpath(self) -> None:
        before = self.snapshot()
        archive = Path(self.temp.name) / "backups" / "test.zip"
        restored = Path(self.temp.name) / "restored"
        for args in (
            ("-m", "app.backup", "create", "--data", str(self.data), "--output", str(archive)),
            ("-m", "app.backup", "verify", str(archive)),
            ("-m", "app.backup", "restore", str(archive), "--destination", str(restored)),
        ):
            result = self.run_python(*args, import_root=self.root)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)["status"], "ok")
        for relative, (sha, mtime) in before.items():
            actual = restored / relative
            self.assertEqual(hashlib.sha256(actual.read_bytes()).hexdigest(), sha)
            self.assertEqual(actual.stat().st_mtime_ns, mtime)
            self.assertEqual(hashlib.sha256((self.data / relative).read_bytes()).hexdigest(), sha)

    def test_prepare_scopes_path_to_helpers_and_keeps_prior_fixes(self) -> None:
        text = (SOURCE_ROOT / "scripts/Prepare-Upgrade.ps1").read_text()
        self.assertIn("'--env','PYTHONPATH=/tools'", text)
        self.assertIn("'--env','PYTHONDONTWRITEBYTECODE=1'", text)
        self.assertNotIn("$env:PYTHONPATH", text)
        self.assertIn('"./${RelDir}:/release:ro"', text)
        self.assertIn("$HuggingFaceHome", text)
        self.assertNotIn("$Home =", text)
        for line in text.splitlines():
            if "Docker-Checked (" in line and ("$Offline" in line or "@('run'" in line):
                self.assertIn("$Tools", line)

    def test_checkonly_returns_before_stop_and_new_directories(self) -> None:
        text = (SOURCE_ROOT / "scripts/Prepare-Upgrade.ps1").read_text()
        begin = text.index("if ($CheckOnly)")
        end = text.index("\n}", begin)
        self.assertIn("return", text[begin:end])
        self.assertLess(end, text.index("New-Item -ItemType Directory"))
        self.assertLess(end, text.index("@('stop','clipforge')"))
        self.assertLess(text.index("scripts/check_idle.py"), begin)


if __name__ == "__main__":
    unittest.main(verbosity=2)
