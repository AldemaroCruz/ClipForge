"""Fixture-only regression for the authentic Noble bootstrap to secret receipt handoff."""

from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from zipfile import ZipFile

from scripts import int_demo_a_secrets as secrets
from scripts import int_noble_bootstrap_db as bootstrap


COMMIT = "a" * 40
OPERATION = "b" * 32
OUTCOME = "configured_guest_verified_external_acceptance_pending"
CLEANUP = {"schema": "clipforge-int-guest-cleanup-1", "status": "key_already_absent"}


def sha(raw):
    return sha256(raw).hexdigest()


def archive(report, cleanup=CLEANUP, *, report_name="db01-result.json"):
    raw = BytesIO()
    with ZipFile(raw, "w") as bundle:
        bundle.writestr(report_name, report)
        bundle.writestr("cleanup.json", secrets.transport.canonical(cleanup))
    return raw.getvalue()


class ReceiptScope(unittest.TestCase):
    def setUp(self):
        self.ca = "synthetic fixture CA bytes\n"
        self.report = {"schema": "clipforge-int-noble-bootstrap-result-1", "status": OUTCOME, "runtime_authorized": False,
                       "migrations_applied": False, "external_client_acceptance": False, "operation_id": OPERATION,
                       "guest_receipt": {"status": OUTCOME, "approved_commit": COMMIT, "disk_id": "7382984635240536620",
                                         "operation_id": OPERATION, "exit_code": 0}, "cleanup": CLEANUP,
                       "ca_certificate_sha256": sha(self.ca.encode("ascii"))}

    def test_consumer_refuses_a_missing_or_other_ca_hash_in_the_producer_receipt(self):
        raw = secrets.transport.canonical(self.report)
        inputs = {"bootstrap_controls": COMMIT, "bootstrap_run": "101", "bootstrap_artifact": "202",
                  "bootstrap_artifact_sha256": sha(archive(raw)), "bootstrap_receipt_sha256": sha(raw),
                  "ca_certificate_sha256": self.report["ca_certificate_sha256"]}
        with patch.object(secrets.preflight, "json_bytes", return_value=self.report):
            self.assertEqual(secrets.prerequisite(Path("fixture"), inputs), self.report)
            with self.assertRaisesRegex(ValueError, "demo_a_bootstrap_ca_mismatch"):
                secrets.prerequisite(Path("fixture"), {**inputs, "ca_certificate_sha256": "0" * 64})
            del self.report["ca_certificate_sha256"]
            with self.assertRaisesRegex(ValueError, "demo_a_bootstrap_ca_mismatch"):
                secrets.prerequisite(Path("fixture"), inputs)

    def test_receipt_must_be_in_the_authenticated_exact_zip_with_cleanup(self):
        original = secrets.transport.canonical(self.report)
        payload = archive(original)
        secrets.verify_bootstrap_archive(payload, sha(payload), sha(original))
        with self.assertRaisesRegex(ValueError, "demo_a_bootstrap_artifact_bytes"):
            secrets.verify_bootstrap_archive(payload + b"changed", sha(payload), sha(original))
        with self.assertRaisesRegex(ValueError, "demo_a_bootstrap_receipt_not_in_artifact"):
            secrets.verify_bootstrap_archive(payload, sha(payload), sha(original + b" "))
        for changed, reason in ((archive(original, report_name="nested/db01-result.json"), "members"),
                                (archive(original, {**CLEANUP, "status": "cleanup_unconfirmed_TTL_pending"}), "cleanup"),
                                (b"malformed ZIP", "zip_invalid")):
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, "demo_a_bootstrap_artifact_" + reason):
                secrets.verify_bootstrap_archive(changed, sha(changed), sha(original))

    def test_github_metadata_cannot_authorize_a_local_receipt_absent_from_the_archive(self):
        raw = secrets.transport.canonical(self.report)
        payload = archive(raw)
        inputs = {"bootstrap_controls": COMMIT, "bootstrap_run": "101", "bootstrap_artifact": "202",
                  "bootstrap_artifact_sha256": sha(payload), "bootstrap_receipt_sha256": sha(raw)}
        metadata = {"id": 202, "name": f"int-db01-noble-bootstrap-{COMMIT}-101-1", "expired": False,
                    "digest": "sha256:" + sha(payload), "workflow_run": {"id": 101, "head_sha": COMMIT}}
        with (patch.object(secrets.github, "verify_github_run") as run,
              patch.object(secrets.github, "read_github", return_value=metadata),
              patch.object(secrets, "read_bootstrap_archive", return_value=payload) as read):
            secrets.bootstrap_provenance(inputs, "actions-fixture")
            run.assert_called_once_with("101", COMMIT, "actions-fixture", bootstrap.WORKFLOW, "success")
            read.assert_called_once_with("artifacts/202", "actions-fixture")
            with self.assertRaisesRegex(ValueError, "demo_a_bootstrap_receipt_not_in_artifact"):
                secrets.bootstrap_provenance({**inputs, "bootstrap_receipt_sha256": "b" * 64}, "actions-fixture")

    def test_download_follows_only_verified_artifact_storage_without_github_bearer(self):
        signed = "https://example.blob.core.windows.net/actions/fixture?signature=fixture"
        first = Mock()
        first.open.side_effect = HTTPError("https://api.github.com/", 302, "redirect", {"Location": signed}, BytesIO())
        second = Mock()
        second.open.return_value = BytesIO(b"fixture")
        with patch.object(secrets, "build_opener", side_effect=(first, second)):
            self.assertEqual(secrets.read_bootstrap_archive("artifacts/202", "actions-fixture"), b"fixture")
        self.assertEqual(first.open.call_args.args[0].get_header("Authorization"), "Bearer actions-fixture")
        self.assertEqual(second.open.call_args.args[0].full_url, signed)
        self.assertIsNone(second.open.call_args.args[0].get_header("Authorization"))
        first.open.side_effect = HTTPError("https://api.github.com/", 302, "redirect", {"Location": "https://unrelated.example/archive"}, BytesIO())
        with (patch.object(secrets, "build_opener", return_value=first) as factory,
              self.assertRaisesRegex(ValueError, "demo_a_bootstrap_artifact_redirect")):
            secrets.read_bootstrap_archive("artifacts/202", "actions-fixture")
        factory.assert_called_once()

    def test_producer_exports_only_the_exact_public_ca_digest_after_verified_result(self):
        env = {"GITHUB_SHA": COMMIT, "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_RUN_ID": "101",
               "GITHUB_RUN_ATTEMPT": "1", "GCP_ACCESS_TOKEN": "fixture-does-not-leave-process"}
        decision = {"operation_id": OPERATION, "proposal_sha256": "c" * 64}
        ready = {"decision": decision, "decision_raw": b"fixture", "noble_iam_receipt_sha256": "d" * 64,
                 "summary": {"candidate": {}}, "baseline_proof": {}, "pin": {"known_hosts_line": "fixture"},
                 "baseline": {"guest": {"base_inventory": {"inventory": {"kernel": "fixture"}}}}, "operator": b"fixture"}
        linked = ready["baseline"]
        fresh = {"guest_boot_id": "fixture", "guest_read_receipt_sha256": "e" * 64, "guest_read_source_sha256": "f" * 64}
        client, processes, operator = Mock(profile_name="fixture"), Mock(), Mock()
        client.import_key.return_value = {"username": "fixture", "fingerprint": "fixture"}
        processes.run.side_effect = ((0, b'{"Google Cloud SDK":"582.0.0"}', b""), (0, b"", b""), (0, b"observe", b""))
        processes.invoke_once.return_value = (0, b"{}", b"")
        operator.validate_receipt.return_value = {"status": OUTCOME}
        values = {"ca_cert": self.ca, "server_key": "fixture-unused-key", "app_password": "fixture-unused-password"}
        with TemporaryDirectory() as path:
            work = Path(path)
            for candidate in (work / "id_ed25519", work / "id_ed25519.pub"):
                candidate.write_bytes(b"fixture")
                candidate.chmod(0o600)
            with (patch.object(bootstrap, "check_cloud", return_value=({}, client, {})), patch.object(bootstrap.first, "snapshot", return_value={}),
                  patch.object(bootstrap.payloads, "operator_contract", return_value=operator), patch.object(bootstrap.guest, "payload_bytes", return_value=b""),
                  patch.object(bootstrap, "NobleProcesses", return_value=processes), patch.object(bootstrap.shutil, "which", return_value="/usr/bin/gcloud"),
                  patch.object(bootstrap.first.int_vm_hostkey_guest, "public_key", return_value=("fixture", "fixture")),
                  patch.object(bootstrap, "check_tls", return_value=values), patch.object(bootstrap, "proof", return_value=(linked, fresh)),
                  patch.object(bootstrap, "check_window"), patch.object(bootstrap, "token_margin"), patch.object(bootstrap.legacy, "phase"),
                  patch.object(bootstrap.legacy, "same_disk_identity"), patch.object(bootstrap.legacy, "checked_guest_result"),
                  patch.object(bootstrap.legacy, "cleanup", return_value=CLEANUP)):
                result = bootstrap.launch(env, ready, work, work)
            self.assertEqual(result["status"], OUTCOME)
            self.assertEqual(result["ca_certificate_sha256"], sha(self.ca.encode("ascii")))
            emitted = (work / "db01-result.json").read_bytes()
            for material in values.values():
                self.assertNotIn(material.encode(), emitted)

    def test_protected_secret_validation_requests_live_runner_matching(self):
        preflight = secrets.preflight
        at = datetime(2026, 11, 23, tzinfo=timezone.utc)
        digest = "d" * 64
        env = {"GITHUB_REPOSITORY": preflight.REPO, "GITHUB_REF": "refs/heads/" + preflight.BRANCH,
               "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ID": "101", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_SHA": COMMIT, "INT_APPROVED_COMMIT": COMMIT, "RUNNER_ENVIRONMENT": "github-hosted",
               "GITHUB_WORKFLOW_REF": f"{preflight.REPO}/{secrets.WORKFLOW}@refs/heads/{preflight.BRANCH}",
               "INT_DEMO_A_PROTECTED_DECISION_SHA256": digest, "INT_DEMO_A_PROTECTED_GATE_MODE": "demo-a"}
        decision = {"schema": preflight.SCHEMA, "status": "authorized_one_operation", "owner": "admin@ixbalam.studio",
                    "repository": preflight.REPO, "branch": preflight.BRANCH, "environment": "int",
                    "project": preflight.PROJECT, "control_commit": COMMIT, "operation": secrets.OPERATION,
                    "operation_id": OPERATION, "issued_utc": at.isoformat(),
                    "expires_utc": (at + timedelta(minutes=10)).isoformat(), "gate_mode": "demo-a",
                    "review_sha256": digest, "binding_sha256": digest, "inputs": {}}
        for protected in (False, True):
            with (self.subTest(protected=protected),
                  patch.object(preflight, "json_bytes", side_effect=(decision, {})),
                  patch.object(preflight.gate, "main", return_value=0) as gate):
                preflight.local_decision(Path("fixture"), digest, secrets.OPERATION, secrets.WORKFLOW, env,
                                         protected=protected, now=at)
                self.assertEqual("--match-credential-runner" in gate.call_args.args[0], protected)
