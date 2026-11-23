"""Directed controls for the one nominated GitHub-hosted image."""

from datetime import datetime, timezone
from hashlib import sha256
import json
import lzma
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_demo_a_hosted_trial as trial


COMMIT = "1" * 40
NOW = datetime(2026, 11, 23, 17, tzinfo=timezone.utc)


def context(root, image=trial.IMAGE, **overrides):
    env = {"ImageVersion": image, "RUNNER_TEMP": str(root.resolve()), "GITHUB_ACTIONS": "true",
           "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24", "GITHUB_REPOSITORY": trial.preparation.REPO,
           "GITHUB_REF": trial.preparation.BRANCH, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
           "GITHUB_WORKFLOW_REF": f"{trial.preparation.REPO}/.github/workflows/int-demo-a-wif-read.yml@{trial.preparation.BRANCH}",
           "GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": "22", "GITHUB_JOB": "docker-preparation-without-federation",
           "INT_DOCKER_PREP_SELECTOR": "docker_prepare"}
    return {**env, **overrides}


def boot(release):
    return {"distribution": {"id": "ubuntu", "version": "24.04", "architecture": "amd64"},
            "boot_id": "11111111-2222-3333-4444-555555555555", "release": release}


def archive(release):
    family, version, _, _ = trial.KERNELS[release]
    records, installed = [], {}
    for kind, source in (("image", f"linux-signed-{family}-7.0"), ("modules", f"linux-{family}-7.0")):
        package = f"linux-{kind}-{release}"
        installed[package] = version
        records.append(f"Package: {package}\nArchitecture: amd64\nVersion: {version}\nSource: {source}\n"
                       f"Filename: pool/main/l/{source}/{package}_{version}_amd64.deb\nSize: 313\nSHA256: {'a' * 64}\n")
    compressed = lzma.compress("\n".join(records).encode())
    checksum = sha256(compressed).hexdigest()
    metadata = ("Origin: Ubuntu\nSuite: noble-updates\nCodename: noble\nDate: Sun, 22 Nov 2026 12:00:00 +0000\n"
                f"SHA256:\n {checksum} {len(compressed)} {trial.INDEX_PATH}\n")
    return installed, compressed, metadata


class HostedTrial(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.output = self.root.resolve() / trial.REPORT

    def run_trial(self, env):
        status = trial.main(["--report", str(self.output), "--approved-commit", COMMIT], env=env)
        return status, json.loads(self.output.read_text(encoding="utf-8"))

    def test_previous_image_keeps_native_boot_and_blocks_archive_and_installation(self):
        old = "20261116.376.1"
        version = "7.0.0-1017.17~24.04.1"
        with patch.object(trial.preparation, "boot_identity", return_value=boot("7.0.0-1017-azure")), \
                patch.object(trial.docker, "bounded_text", return_value=f"Ubuntu {version}-azure 7.0.9"), \
                patch.object(trial.docker, "package_identity", return_value=version), \
                patch.object(trial, "native_packages") as packages, patch.object(trial, "archive_provenance") as provenance:
            status, receipt = self.run_trial(context(self.root, old))
        self.assertEqual(status, 1)
        self.assertEqual(receipt["image_observed"], old)
        self.assertEqual(receipt["boot"]["release"], "7.0.0-1017-azure")
        self.assertEqual(receipt["running_version_signature"], f"Ubuntu {version}-azure 7.0.9")
        self.assertEqual(receipt["installed_packages"]["linux-image-7.0.0-1017-azure"], version)
        self.assertEqual(receipt["error_code"], "hosted_trial_image_not_nominated")
        packages.assert_not_called()
        provenance.assert_not_called()

    def test_oidc_and_google_credentials_block_before_host_observation(self):
        for name in ("ACTIONS_ID_TOKEN_REQUEST_URL", "GOOGLE_APPLICATION_CREDENTIALS"):
            self.output.unlink(missing_ok=True)
            with self.subTest(name=name), patch.object(trial.preparation, "boot_identity") as observe:
                status, receipt = self.run_trial(context(self.root, **{name: "not-for-report"}))
                observe.assert_not_called()
            self.assertEqual(status, 1)
            self.assertNotIn("not-for-report", json.dumps(receipt))

    def test_aws_reaches_preparation_but_azure_remains_review_only(self):
        for release, kernel in trial.KERNELS.items():
            self.output.unlink(missing_ok=True)
            family, version, _, floor = kernel
            proof = {"noble-updates": {"packages": {}}}
            with self.subTest(family=family), patch.object(trial.preparation, "boot_identity", return_value=boot(release)), \
                    patch.object(trial.docker, "bounded_text", return_value=f"Ubuntu {version}-{family} 7.0.9"), \
                    patch.object(trial, "native_packages", return_value={"example": version}), \
                    patch.object(trial, "archive_provenance", return_value=proof) as provenance:
                status, receipt = self.run_trial(context(self.root))
                provenance.assert_called_once()
            self.assertEqual(receipt["signed_package_index"], proof)
            self.assertEqual(receipt["advisory"]["fixed_package_version"], floor)
            self.assertFalse(receipt["publication_authorized"])
            self.assertEqual(status, int(family != "aws"))
            if family == "azure":
                self.assertEqual(receipt["error_code"], "hosted_trial_azure_requires_admission")

    def test_boot_build_revision_and_packages_must_both_match(self):
        release = "7.0.0-1018-aws"
        with patch.object(trial.preparation, "boot_identity", return_value=boot(release)), \
                patch.object(trial.docker, "bounded_text", return_value="Ubuntu 7.0.0-1018.18~24.04.1-aws 7.0.9"), \
                patch.object(trial, "native_packages") as packages:
            status, receipt = self.run_trial(context(self.root))
        self.assertEqual(status, 1)
        self.assertEqual(receipt["error_code"], "hosted_trial_boot_package_version")
        packages.assert_not_called()
        version = trial.KERNELS[release][1]
        with patch.object(trial.docker, "run", return_value=f"installed\tlinux-image-{release}\t{version}\tamd64"):
            with self.assertRaisesRegex(ValueError, "hosted_trial_missing_installed_kernel_package"):
                trial.native_packages(release, version, self.root)

    def test_archive_index_is_bound_to_release_and_exact_package_records(self):
        release = "7.0.0-1018-aws"
        installed, compressed, metadata = archive(release)
        identity = trial.signed_index_entry(metadata, "noble-updates", NOW)
        self.assertEqual((identity["size"], identity["sha256"]), (len(compressed), sha256(compressed).hexdigest()))
        with self.assertRaisesRegex(ValueError, "hosted_trial_archive_suite"):
            trial.signed_index_entry(metadata, "noble-security", NOW)
        observed = trial.matching_packages(compressed, installed, "aws")
        self.assertEqual(set(observed), set(installed))
        self.assertEqual(observed["linux-image-" + release]["source_package"], "linux-signed-aws-7.0")
        with self.assertRaisesRegex(ValueError, "hosted_trial_archive_package_identity"):
            trial.matching_packages(compressed, installed, "azure")

    def test_untrusted_archive_signer_or_changed_index_cannot_reach_preparation(self):
        installed, compressed, metadata = archive("7.0.0-1018-aws")
        for bad_signer in (True, False):
            with self.subTest(bad_signer=bad_signer):
                signer = "unexpected" if bad_signer else trial.SIGNER
                with patch.object(trial, "read_https", side_effect=[b"fixture signed release", compressed[:-1] + b"x"]), \
                        patch.object(trial.docker, "run", return_value=f"[GNUPG:] VALIDSIG {signer} fixture {signer}"), \
                        patch.object(trial.docker, "bounded_text", return_value=metadata):
                    expected = "hosted_trial_archive_signer" if bad_signer else "hosted_trial_archive_index_hash"
                    with self.assertRaisesRegex(ValueError, expected):
                        trial.archive_provenance(self.root, installed, "aws", now=NOW)


if __name__ == "__main__":
    unittest.main()
