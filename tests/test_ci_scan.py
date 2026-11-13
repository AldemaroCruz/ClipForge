"""Tracked-source scan privacy regressions; authored temporary fixtures only."""
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

from scripts import prepare_ci_scan as scan


class CIScanTests(unittest.TestCase):
    def test_int_sources_are_explicitly_scannable(self):
        names = ["Dockerfile.int", "Dockerfile.int.dockerignore", "requirements-int.lock",
                 "config/postgres-ci-security.Dockerfile", "app/cloud/router.py",
                 ".github/workflows/int-e2e-apply.yml"]
        self.assertEqual(scan.validate_paths(names), sorted(names))

    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-ci-scan-")
        self.addCleanup(self.temporary.cleanup)
        self.base = Path(self.temporary.name)
        self.source = self.base / "source"
        self.source.mkdir()
        self.paths = self.base / "tracked-paths.nul"
        self.destination = self.base / "snapshot"
        self.names = ["README.md", "docs/CI.md", ".github/workflows/ci.yml",
                      ".github/workflows/gcp-auth-check.yml",
                      ".github/workflows/tf-int-plan.yml", "infra/gcp/int-base/main.tf",
                      "infra/gcp/int-base/.terraform.lock.hcl", "infra/gcp/int-base/postgres-install.sh",
                      ".env.ai.example", "app/main.py", "compose.ai.yaml"]
        for name in self.names:
            output = self.source / name
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_text("# explicitly authored harmless fixture\n", encoding="utf-8")
        self.write_paths(self.names)

    def write_paths(self, names):
        self.paths.write_bytes(b"".join(name.encode("utf-8") + b"\0" for name in names))

    def prepare(self):
        return scan.prepare_scan(self.source, self.paths, self.destination)

    def test_copies_docs_workflow_and_only_authorized_root_env_example(self):
        report = self.prepare()
        self.assertEqual(report["files"], len(self.names))
        manifest = json.loads((self.destination / scan.MANIFEST).read_text())
        self.assertEqual(manifest["schema"], scan.SCHEMA)
        self.assertEqual({item["path"] for item in manifest["files"]}, set(self.names))
        for item in manifest["files"]:
            value = (self.destination / item["path"]).read_bytes()
            self.assertEqual(value, (self.source / item["path"]).read_bytes())
            self.assertEqual(hashlib.sha256(value).hexdigest(), item["sha256"])
            self.assertEqual(len(value), item["bytes"])

    def test_all_forced_private_names_reject_before_any_source_content_is_read(self):
        private = [".env", ".env.ai", ".env.production", ".ENV.AI.EXAMPLE", "docs/.env.ai.example",
                   "data/project/job.json", "cache/model.json", "backups/backup.py",
                   "release/runtime-lock.json", "evidence/check.json", "test-evidence/check.json",
                   "restore-check-synthetic/app.py", "restores/app.py", ".ci-local/check.json",
                   "ci-results/result.json", ".aws/config", "docs/credentials.json",
                   "docs/secrets.md", "infra/main.tfstate", "infra/default.tfvars",
                   "terraform/plan.tfplan", "docs/private.pem", "docs/private.key",
                   "docs/example.mp4", "docs/example.wav", "compose.runtime.yaml",
                   "compose.rollback.yaml", "docs/model-lock.json",
                   "gha-creds-synthetic.json", "docs/gha-creds-synthetic.json",
                   ".github/workflows/gha-creds-synthetic.json"]
        private += ["infra/gcp/int-base/terraform.tfstate", "infra/gcp/int-base/private.tfplan",
                    "infra/gcp/int-base/.terraform/terraform.tfstate"]
        for name in private:
            with self.subTest(name=name):
                self.write_paths(["README.md", name])
                with mock.patch.object(scan.context, "_stream_record", side_effect=AssertionError("must never read source")) as reader:
                    with self.assertRaises((scan.ScanError, scan.context.ContextError)):
                        self.prepare()
                reader.assert_not_called()
                self.assertFalse(self.destination.exists())

    def test_exact_policy_is_scanned_without_extending_the_build_context(self):
        name = ".gitleaks.toml"
        (self.source / name).write_text("# authored snapshot-name fixture\n", encoding="utf-8")
        self.write_paths([*self.names, name])
        self.prepare()
        manifest = json.loads((self.destination / scan.MANIFEST).read_text())
        self.assertIn(name, {item["path"] for item in manifest["files"]})
        self.assertEqual((self.destination / name).read_bytes(), (self.source / name).read_bytes())
        self.assertNotIn(name, scan.context.ROOT_FILES)
        for unapproved in (".GITLEAKS.TOML", ".gitleaks.local.toml", "gitleaks.toml"):
            with self.subTest(name=unapproved), self.assertRaises(scan.ScanError):
                scan.validate_paths([unapproved])

    def test_name_preflight_does_not_stat_a_forced_secret(self):
        self.write_paths(["README.md", ".env.ai"])
        original = scan.context._checked_stat

        def guard(path):
            self.assertFalse(Path(path) == self.source or self.source in Path(path).parents)
            return original(path)

        with mock.patch.object(scan.context, "_checked_stat", side_effect=guard):
            with self.assertRaises(scan.ScanError):
                self.prepare()

    def test_auth01_exact_dev_sources_allowed_but_private_and_unknown_names_rejected(self):
        names = ['Dockerfile.dev', 'Dockerfile.dev.dockerignore', 'compose.dev.yaml',
                 'app/auth.py', 'app/auth_models.py', 'app/auth_db.py',
                 'app/auth_migrations.py', 'scripts/auth_admin.py', 'scripts/auth_migrate.py']
        self.assertEqual(scan.validate_paths(names), sorted(names))
        for name in ['compose.dev.local.yaml', '.env.dev', 'dev-data/project/job.json',
                     'dev-postgres/PG_VERSION', 'dev-secrets/database-password',
                     'scripts/credentials.dev.py', '.ci-local/auth01-result.json']:
            with self.subTest(name=name):
                self.write_paths(['README.md', name])
                with mock.patch.object(scan.context, '_stream_record') as reader:
                    with self.assertRaises((scan.ScanError, scan.context.ContextError)):
                        self.prepare()
                reader.assert_not_called()

    def test_unlisted_secret_is_never_opened_or_enumerated(self):
        (self.source / ".env.ai").write_text("authored synthetic private sentinel", encoding="utf-8")
        private = self.source / "data"
        private.mkdir()
        (private / "private.json").write_text("authored private sentinel", encoding="utf-8")
        original = scan.context._stream_record

        def guard(path, destination=None):
            self.assertNotEqual(Path(path), self.source / ".env.ai")
            self.assertNotIn(private, Path(path).parents)
            return original(path, destination)

        with mock.patch.object(scan.context, "_stream_record", side_effect=guard), mock.patch.object(scan.os, "scandir", wraps=os.scandir) as listing:
            self.prepare()
        self.assertTrue(all(Path(call.args[0]) != self.source for call in listing.call_args_list))
        self.assertFalse((self.destination / ".env.ai").exists())

    def test_rejects_absolute_traversal_noncanonical_and_non_source_names(self):
        for name in ("/etc/passwd", "C:/private.txt", "../README.md", "docs/../README.md",
                     "docs//CI.md", "./README.md", "docs\\CI.md", "docs/CON.md",
                     "docs/title.md ", "unknown/README.md", "docs/font.ttf", "README.md\n"):
            with self.subTest(name=name), self.assertRaises(scan.ScanError):
                scan.validate_paths([name])

    def test_empty_and_duplicate_or_case_colliding_names_rejected(self):
        for names in ([], [""], ["README.md", "README.md"], ["README.md", "readme.md"]):
            with self.subTest(names=names), self.assertRaises(scan.ScanError):
                scan.validate_paths(names)

    def test_missing_nul_and_invalid_utf8_lists_rejected(self):
        for value in (b"", b"README.md", b"README.md\0\0", b"docs/\xff.md\0"):
            with self.subTest(value=value):
                self.paths.write_bytes(value)
                with self.assertRaises(scan.ScanError):
                    self.prepare()

    def test_existing_destination_is_preserved_without_source_reads(self):
        self.destination.mkdir()
        marker = self.destination / "keep"
        marker.write_bytes(b"preserved")
        with mock.patch.object(scan.context, "_stream_record", side_effect=AssertionError("unexpected read")):
            with self.assertRaises(FileExistsError):
                self.prepare()
        self.assertEqual(marker.read_bytes(), b"preserved")

    def test_destination_inside_source_and_list_inside_source_rejected(self):
        with self.assertRaises(scan.context.ContextError):
            scan.prepare_scan(self.source, self.paths, self.source / "snapshot")
        with self.assertRaises(scan.context.ContextError):
            scan.prepare_scan(self.source, self.source / "tracked.nul", self.destination)

    def test_all_source_metadata_checked_before_first_content_read(self):
        bad = self.source / self.names[-1]
        bad.unlink()
        bad.mkdir()
        with mock.patch.object(scan.context, "_stream_record", side_effect=AssertionError("unexpected source read")) as reader:
            with self.assertRaises(scan.ScanError):
                self.prepare()
        reader.assert_not_called()

    def test_hard_link_metadata_rejected_before_source_read(self):
        original = scan.context._checked_stat
        target = self.source / "README.md"

        def metadata(path):
            value = original(path)
            if Path(path) == target:
                return SimpleNamespace(st_mode=value.st_mode, st_nlink=2, st_size=value.st_size)
            return value

        with mock.patch.object(scan.context, "_checked_stat", side_effect=metadata), mock.patch.object(scan.context, "_stream_record") as reader:
            with self.assertRaises(scan.ScanError):
                self.prepare()
        reader.assert_not_called()

    def test_source_symlink_metadata_is_rejected_before_reading(self):
        target = self.source / "README.md"
        original = scan.context.os.lstat

        def metadata(path):
            if Path(path) == target:
                return SimpleNamespace(st_mode=stat.S_IFLNK, st_file_attributes=0)
            return original(path)

        with mock.patch.object(scan.context.os, "lstat", side_effect=metadata), mock.patch.object(scan.context, "_stream_record") as reader:
            with self.assertRaises(scan.context.ContextError):
                self.prepare()
        reader.assert_not_called()

    def test_parent_windows_reparse_point_is_rejected_before_reading(self):
        target = self.source / "docs"
        original = scan.context.os.lstat

        def metadata(path):
            if Path(path) == target:
                return SimpleNamespace(st_mode=stat.S_IFDIR, st_file_attributes=0x400)
            return original(path)

        with mock.patch.object(scan.context.os, "lstat", side_effect=metadata), mock.patch.object(scan.context, "_stream_record") as reader:
            with self.assertRaises(scan.context.ContextError):
                self.prepare()
        reader.assert_not_called()

    def test_failed_copy_does_not_publish_manifest(self):
        with mock.patch.object(scan.context, "_stream_record", side_effect=OSError("synthetic read failure")):
            with self.assertRaises(OSError):
                self.prepare()
        self.assertFalse((self.destination / scan.MANIFEST).exists())

    def test_copy_hash_mismatch_rejected(self):
        original = scan.context._stream_record

        def altered(path, destination=None):
            value = original(path, destination)
            if destination is None and self.destination in Path(path).parents:
                return {"bytes": value["bytes"], "sha256": "0" * 64}
            return value

        with mock.patch.object(scan.context, "_stream_record", side_effect=altered):
            with self.assertRaises(scan.ScanError):
                self.prepare()
        self.assertFalse((self.destination / scan.MANIFEST).exists())


if __name__ == "__main__":
    unittest.main()
