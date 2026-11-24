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
        for name in (*ci.ROOT_FILES, *ci.SUPPORT_FILES):
            (self.source / name).parent.mkdir(parents=True, exist_ok=True)
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

    def test_public_contract_hcl_workflow_and_scanner_sources_are_explicit_and_complete(self):
        expected = {"config/int-db01-noble-read-iam.json", "config/int-db01-noble-write-iam.json",
                    "config/int-foundation-contract.json", "config/int-foundation-recovery.json",
                    "config/int-hito-a-bandit-acceptance.json",
                    "config/int-foundation-history/5800b4c-recovery-contract.json",
                    "infra/gcp/int-base/versions.tf", "infra/gcp/int-base/postgres-install.sh",
                    ".github/workflows/ci.yml", ".gitleaks.toml",
                    ".github/workflows/int-db01-noble-apply.yml", ".github/workflows/int-db01-noble-observe.yml",
                    ".github/workflows/int-db01-noble-plan.yml", ".github/workflows/int-db01-noble-postverify.yml",
                    "tests/fixtures/int_foundation_close/d67e581-sast-review.json"}
        self.assertTrue(expected <= ci.SUPPORT_FILES)
        self.prepare()
        names = {row["path"] for row in json.loads(self.manifest.read_bytes())["files"]}
        self.assertTrue(ci.SUPPORT_FILES <= names)
        for name in ci.SUPPORT_FILES:
            self.assertEqual((self.destination / name).read_bytes(), (self.source / name).read_bytes())

    def test_noble_workflows_keep_manual_environment_and_exact_plan_binding(self):
        workflows = Path(__file__).resolve().parents[1] / ".github" / "workflows"
        plan = (workflows / "int-db01-noble-plan.yml").read_text(encoding="utf-8")
        apply = (workflows / "int-db01-noble-apply.yml").read_text(encoding="utf-8")
        observe = (workflows / "int-db01-noble-observe.yml").read_text(encoding="utf-8")
        postverify = (workflows / "int-db01-noble-postverify.yml").read_text(encoding="utf-8")
        for source in (plan, observe, postverify):
            self.assertIn("on:\n  workflow_dispatch:", source)
            self.assertIn("    environment: int\n", source)
            self.assertIn("cancel-in-progress: false", source)
            self.assertIn("github.repository == 'AldemaroCruz/ClipForge'", source)
            self.assertIn("github.ref == 'refs/heads/ci/bootstrap-sec03'", source)
            self.assertIn("github.event_name == 'workflow_dispatch'", source)
        self.assertIn("on:\n  workflow_call:", apply)
        self.assertNotIn("on:\n  workflow_dispatch:", apply)
        self.assertIn("name: DEPRECATED -", apply)
        self.assertIn("    environment: int\n", apply)
        self.assertIn("    if: ${{ false }}", apply)
        for source in (plan, apply, postverify):
            self.assertIn("group: clipforge-int-terraform-state", source)
            self.assertIn("service_account: ${{ vars.GCP_TERRAFORM_SA }}", source)
            self.assertIn("workload_identity_provider: ${{ vars.GCP_WIF_PROVIDER }}", source)
        self.assertIn("DB01_NOBLE_STABLE_WRITE_RECEIPT: ${{ inputs.stable_write_receipt }}", plan)
        self.assertIn("DB01_NOBLE_PLAN_MANIFEST: ${{ inputs.plan_manifest }}", apply)
        self.assertIn("DB01_NOBLE_OWNER_DECISION: ${{ inputs.owner_decision }}", apply)
        self.assertIn('[[ "$DB01_NOBLE_PRODUCER_COMMIT" =~ ^[0-9a-f]{40}$ ]]', apply)
        self.assertIn("ref: ${{ steps.binding.outputs.producer }}", apply)
        self.assertIn("service_account: ${{ vars.GCP_DEPLOY_SA }}", observe)

    def test_missing_public_contract_is_rejected_instead_of_silently_omitted(self):
        (self.source / "config/int-foundation-contract.json").unlink()
        with self.assertRaises(FileNotFoundError):
            self.prepare()
        self.assertFalse(self.manifest.exists())

    def test_personal_sql_payloads_are_copied_by_exact_name(self):
        names = {"scripts/personal_sql/20-personal-inspection.sql",
                 "scripts/personal_sql/29-verify-personal-acl.sql",
                 "scripts/personal_sql/90-revoke-personal.sql"}
        self.assertTrue(names <= ci.SUPPORT_FILES)
        sibling = "scripts/personal_sql/private-export.sql"
        (self.source / sibling).write_bytes(b"synthetic, unlisted SQL")
        self.prepare()
        self.verify()
        self.assertFalse((self.destination / sibling).exists())
        for name in names:
            self.assertEqual((self.destination / name).read_bytes(), (self.source / name).read_bytes())

    def test_unlisted_config_credentials_state_and_fixture_trees_are_not_read(self):
        rejected = ("config/gha-creds-synthetic.json", "config/private-unreviewed.json",
                    "infra/gcp/int-base/default.tfstate", "infra/gcp/int-base/private.tfvars",
                    "tests/fixtures/unlisted/private.json")
        for name in rejected:
            path = self.source / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("synthetic credential sentinel", encoding="utf-8")
        reader = ci._stream_record
        def checked(path, destination=None):
            base = self.source if path.is_relative_to(self.source) else self.destination
            self.assertNotIn(path.relative_to(base).as_posix(), rejected)
            return reader(path, destination)
        with mock.patch.object(ci, "_stream_record", side_effect=checked):
            self.prepare()
        self.assertTrue(all(not (self.destination / name).exists() for name in rejected))
        (self.destination / "config/gha-creds-synthetic.json").write_text("never read")
        with self.assertRaisesRegex(ci.ContextError, "unlisted public-source"):
            self.verify()

    def test_private_trees_and_files_are_not_entered_or_copied(self):
        private = ("data", "cache", "backups", "release", "evidence", "test-evidence", "restore-check-fixture")
        for name in private:
            directory = self.source / name
            directory.mkdir()
            (directory / "private.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / ".env.ai").write_text("SYNTHETIC_ONLY=never-copy", encoding="utf-8")
        (self.source / "scripts/.env.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / "scripts/credentials.py").write_text("synthetic private sentinel", encoding="utf-8")
        (self.source / "gha-creds-synthetic.json").write_text("synthetic OIDC sentinel", encoding="utf-8")
        (self.source / "scripts/gha-creds-synthetic.json").write_text("synthetic OIDC sentinel", encoding="utf-8")
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
        self.assertNotIn("gha-creds-synthetic.json", actual)
        self.assertNotIn("scripts/gha-creds-synthetic.json", actual)
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

    def test_auth01_context_contains_exact_dev_recipes_without_dev_storage(self):
        for name in ('Dockerfile.dev', 'Dockerfile.dev.dockerignore', 'compose.dev.yaml'):
            self.assertIn(name, ci.ROOT_FILES)
        for name in ('dev-data', 'dev-postgres', 'dev-secrets'):
            (self.source / name).mkdir()
            (self.source / name / 'private.py').write_text('# synthetic private fixture')
        (self.source / 'compose.dev.local.yaml').write_text('# unlisted fixture')
        self.prepare()
        for name in ('Dockerfile.dev', 'Dockerfile.dev.dockerignore', 'compose.dev.yaml'):
            self.assertTrue((self.destination / name).is_file())
        for name in ('dev-data', 'dev-postgres', 'dev-secrets', 'compose.dev.local.yaml'):
            self.assertFalse((self.destination / name).exists())

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
