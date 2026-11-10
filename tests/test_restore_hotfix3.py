"""Recovery on a precision-capable filesystem; NOT Docker/Windows tests.

Timestamp rounding is simulated only in the regression that reproduces the failure.
No PowerShell execution is claimed by the static command checks.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

from app.backup import create_backup, restore_backup, verify_backup
from scripts.verify_restore import verify_restored

ROOT = Path(__file__).resolve().parents[1]
JOB = 'a' * 32
NANO = 1793368800123456789  # Not representable at 100ns resolution.


class RestoreVerificationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.source = self.base / 'data'
        self.folder = self.source / JOB
        self.folder.mkdir(parents=True)
        (self.folder / 'input.mp4').write_bytes(b'Fixture bytes, not a playable video.')
        (self.folder / 'job.json').write_text(json.dumps({'id': JOB, 'status': 'completed', 'clips': []}))
        (self.folder / 'transcript.json').write_text('[{"start":0,"end":25,"text":"test only"}]')
        self.selection = self.folder / 'selections' / ('b'*32) / 'selection.json'
        self.selection.parent.mkdir(parents=True)
        self.selection.write_text(json.dumps({'status': 'completed', 'source_fingerprint': {'source_size': 35, 'source_mtime_ns': NANO}}))
        for idx, p in enumerate(sorted(self.source.rglob('*'))):
            if p.is_file():
                os.utime(p, ns=(NANO + idx, NANO + idx))
        os.utime(self.folder/'input.mp4', ns=(NANO,NANO))
        self.archive = self.base / 'backup.zip'
        self.summary = create_backup(self.source, self.archive)
        self.sha = self.summary['sha256']
        self.dest = self.base / 'restored'

    def restore(self):
        return restore_backup(self.archive, self.dest, self.sha)

    def test_reproduces_rounding_error_without_corrupting_archive(self):
        original = os.utime
        def rounded(path, *, ns):
            return original(path, ns=tuple(n // 100 * 100 for n in ns))
        with patch('app.backup.os.utime', side_effect=rounded):
            with self.assertRaisesRegex(ValueError, 'precisión temporal'):
                self.restore()
        self.assertFalse(self.dest.exists())
        self.assertEqual(list(self.base.glob('.restore-*')), [])
        self.assertEqual(verify_backup(self.archive, self.sha)['status'], 'ok')
        self.assertEqual((self.folder/'input.mp4').stat().st_mtime_ns, NANO)

    def test_precise_restore_and_verification_real_io(self):
        self.restore()
        result = verify_restored(self.archive, self.dest, self.sha)
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['files'], 4)
        self.assertTrue(result['hashes_match'])
        self.assertTrue(result['timestamps_match'])
        self.assertFalse(result['content_reviewed'])
        self.assertEqual((self.dest/JOB/'input.mp4').stat().st_mtime_ns, NANO)

    def test_source_and_selection_json_unchanged(self):
        paths = [p for p in self.source.rglob('*') if p.is_file()]
        before = {str(p): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in paths}
        self.restore(); verify_restored(self.archive, self.dest, self.sha)
        after = {str(p): (hashlib.sha256(p.read_bytes()).hexdigest(), p.stat().st_mtime_ns) for p in paths}
        self.assertEqual(before, after)
        self.assertEqual(self.selection.read_bytes(), (self.dest/self.selection.relative_to(self.source)).read_bytes())

    def test_wrong_archive_hash_rejected(self):
        self.restore()
        with self.assertRaisesRegex(ValueError, 'SHA-256 externo'):
            verify_restored(self.archive, self.dest, '0'*64)

    def test_malformed_archive_hash_rejected(self):
        self.restore()
        with self.assertRaises(ValueError):
            verify_restored(self.archive, self.dest, 'not-a-hash')

    def test_same_size_changed_bytes_same_time_rejected(self):
        self.restore(); path = self.dest/JOB/'input.mp4'
        raw = path.read_bytes(); path.write_bytes(b'X' + raw[1:])
        os.utime(path,ns=(NANO,NANO))
        with self.assertRaisesRegex(ValueError, 'contenido restaurado'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_smaller_file_rejected(self):
        self.restore(); (self.dest/JOB/'input.mp4').write_bytes(b'x')
        with self.assertRaisesRegex(ValueError, 'contenido restaurado'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_timestamp_difference_rejected_even_if_bytes_match(self):
        self.restore(); path = self.dest/JOB/'input.mp4'
        os.utime(path,ns=(NANO+100,NANO+100))
        with self.assertRaisesRegex(ValueError, 'delta_ns=100'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_no_repair_of_bad_timestamp(self):
        self.restore(); path = self.dest/JOB/'input.mp4'
        os.utime(path,ns=(NANO+1,NANO+1))
        with self.assertRaises(ValueError): verify_restored(self.archive,self.dest,self.sha)
        self.assertEqual(path.stat().st_mtime_ns,NANO+1)

    def test_missing_file_rejected(self):
        self.restore(); (self.dest/JOB/'transcript.json').unlink()
        with self.assertRaisesRegex(ValueError, 'inventario'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_extra_allowed_file_rejected(self):
        self.restore(); (self.dest/JOB/'clip_01.srt').write_text('')
        with self.assertRaisesRegex(ValueError, 'inventario'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_unknown_file_rejected(self):
        self.restore(); (self.dest/JOB/'unknown.txt').write_text('x')
        with self.assertRaises(ValueError): verify_restored(self.archive,self.dest,self.sha)

    def test_secret_file_not_silently_ignored(self):
        self.restore(); (self.dest/'.env.ai').write_text('fixture-secret')
        with self.assertRaisesRegex(ValueError, 'inventario'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_runtime_lock_rejected(self):
        self.restore(); (self.dest/'.clipforge-runtime.lock').write_text('')
        with self.assertRaisesRegex(ValueError, 'lock'):
            verify_restored(self.archive,self.dest,self.sha)

    def test_symlink_file_rejected(self):
        self.restore(); p = self.dest/JOB/'input.mp4'
        p.unlink(); p.symlink_to(self.folder/'input.mp4')
        with self.assertRaises(ValueError): verify_restored(self.archive,self.dest,self.sha)

    def test_symlink_root_rejected(self):
        self.restore(); link = self.base/'alias'; link.symlink_to(self.dest, target_is_directory=True)
        with self.assertRaisesRegex(ValueError, 'directorio real'):
            verify_restored(self.archive,link,self.sha)

    def test_missing_root_rejected_without_creation(self):
        with self.assertRaisesRegex(ValueError, 'directorio real'):
            verify_restored(self.archive,self.dest,self.sha)
        self.assertFalse(self.dest.exists())

    def test_existing_destination_untouched(self):
        self.dest.mkdir(); (self.dest/'keep').write_text('keep')
        with self.assertRaises(FileExistsError): self.restore()
        self.assertEqual((self.dest/'keep').read_text(),'keep')

    def test_corrupt_archive_rejected_before_restore(self):
        with zipfile.ZipFile(self.archive,'a') as z: z.writestr('extra','bad')
        with self.assertRaises(ValueError): self.restore()
        self.assertFalse(self.dest.exists())

    def test_cli_outside_project_real_subprocess(self):
        self.restore()
        result = subprocess.run([sys.executable,str(ROOT/'scripts/verify_restore.py'),
            '--archive',str(self.archive),'--root',str(self.dest),'--sha256',self.sha],
            env={**os.environ,'PYTHONPATH':str(ROOT)},cwd=self.base,text=True,capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)
        self.assertTrue(json.loads(result.stdout)['timestamps_match'])

    def test_cli_failure_exit_and_no_false_success(self):
        self.restore()
        result = subprocess.run([sys.executable,str(ROOT/'scripts/verify_restore.py'),
            '--archive',str(self.archive),'--root',str(self.dest),'--sha256','0'*64],
            env={**os.environ,'PYTHONPATH':str(ROOT)},cwd=self.base,text=True,capture_output=True)
        self.assertEqual(result.returncode,1)
        self.assertFalse(result.stdout.strip())
        self.assertEqual(json.loads(result.stderr)['status'],'failed')


class PowerShellStaticContractTests(unittest.TestCase):
    def setUp(self): self.script=(ROOT/'scripts/Test-Restore.ps1').read_text()

    def test_no_service_mutation_commands(self):
        import re
        self.assertNotRegex(self.script, r'(?im)^\s*&\s+docker\s+[^\n]*(?:\bstop\b|\bdown\b|\bup\b|\bbuild\b|\bprune\b)')
        self.assertNotIn('--volumes-from',self.script)
        self.assertNotIn('target=/data',self.script)
        self.assertNotIn('--env-file',self.script)

    def test_explicit_volume_and_unique_no_reuse(self):
        self.assertIn('[switch]$UseDockerVolume',self.script)
        self.assertIn('[guid]::NewGuid()',self.script)
        self.assertIn("if ($Existing) { throw",self.script)
        self.assertIn('volume-nocopy',self.script)

    def test_readonly_archive_and_second_readonly_container(self):
        self.assertIn("target=/backup.zip,readonly",self.script)
        self.assertIn("$ReadMount = $WriteMount + ',readonly'",self.script)
        self.assertIn("--env','PYTHONPATH=/app'",self.script)
        self.assertIn("$Image,'-m','app.backup','restore'",self.script)
        self.assertEqual(self.script.count("'--network','none'"),2)
        self.assertEqual(self.script.count("'--pull','never'"),2)

    def test_no_dangerous_scoped_interpolation(self):
        self.assertNotRegex(self.script,r'\$[A-Za-z_][A-Za-z_0-9]*:/')


if __name__=='__main__': unittest.main()
