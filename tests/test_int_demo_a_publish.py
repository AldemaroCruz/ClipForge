from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path, PurePosixPath
import tarfile
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.error import HTTPError
from urllib.parse import parse_qs, quote, urlsplit

from scripts import int_demo_a_publish as publish
from scripts import int_demo_a_receipts as receipts


def descriptor(raw, media_type):
    return {"digest": "sha256:" + sha256(raw).hexdigest(), "size": len(raw), "mediaType": media_type}


def write_oci(path, *, nested=False):
    layer = b"known-compressed-blob"
    config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["known"]}}).encode()
    layer_ref = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
    config_ref = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = json.dumps({"schemaVersion": 2, "mediaType": publish.MANIFEST, "config": config_ref, "layers": [layer_ref]}).encode()
    manifest_ref = descriptor(manifest, "application/vnd.oci.image.index.v1+json" if nested else publish.MANIFEST)
    objects = {"index.json": json.dumps({"manifests": [manifest_ref]}).encode(), "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
               **{"blobs/sha256/" + row["digest"][7:]: blob for row, blob in
                  ((layer_ref, layer), (config_ref, config), (manifest_ref, manifest))}}
    with tarfile.open(path, "x:") as archive:
        for name, raw in objects.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            archive.addfile(entry, BytesIO(raw))
    return manifest_ref["digest"], publish.digest_file(path)


class RestrictedPublisher(unittest.TestCase):
    def test_other_build_receipt_is_rejected_before_loading_the_image(self):
        with self.assertRaisesRegex(ValueError, "demo_a_exact_publisher_build_receipt"):
            publish.verify_build(Path("/fixture"), {"build_sha256": "0" * 64}, {})

    def test_source_never_changes_and_all_staged_entries_have_the_publisher_identity(self):
        with TemporaryDirectory() as folder:
            source, staged = (Path(folder) / name for name in ("source.tar", "staged.tar"))
            pins = write_oci(source)
            expected = publish.archive_inventory(source, pins)
            publish.verified_staging_archive(source, staged, expected, 12345, 23456)
            self.assertEqual(publish.digest_file(source), pins[1])
            with tarfile.open(staged) as archive:
                self.assertEqual({(member.uid, member.gid) for member in archive}, {(12345, 23456)})
                self.assertTrue(archive.getmember("blobs").isdir())
                self.assertTrue(archive.getmember("blobs/sha256").isdir())
            with self.assertRaises(FileExistsError):
                publish.verified_staging_archive(source, staged, expected, 12345, 23456)

    def test_rejects_nested_index_before_staging(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "index.tar"
            pins = write_oci(source, nested=True)
            with self.assertRaisesRegex(ValueError, "demo_a_index_or_platform_fanout_not_authorized"):
                publish.archive_inventory(source, pins)

    def test_copy_keeps_source_readonly_and_tls_enforced(self):
        argv = publish.copy_args("sha256:" + "a" * 64, PurePosixPath("/tmp/layout.tar"), PurePosixPath("/tmp/auth.json"),
                                 "registry/lab/repo@sha256:" + "b" * 64, user="12345:23456")
        self.assertIn("--mount=type=bind,source=/tmp/layout.tar,target=/input/image.oci.tar,readonly", argv)
        self.assertIn("--mount=type=bind,source=/tmp/auth.json,target=/authorization/auth.json,readonly", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--preserve-digests", argv)
        self.assertIn("--dest-tls-verify=true", argv)
        self.assertNotIn("--all", argv)


class DeployCustody(unittest.TestCase):
    def setUp(self):
        self.env = {"GITHUB_SHA": "c" * 40, "GITHUB_RUN_ID": "12", "GITHUB_RUN_ATTEMPT": "1"}
        self.decision_id = "d" * 32
        self.names = receipts.producer_names(self.env, "publish", self.decision_id)
        self.intent = self.names["publication-runtime-intent.json"]
        self.store = receipts.Custody("x" * 32, names=self.names.values())

    def test_immutable_create_reads_exact_generation_and_verifies_hash(self):
        raw = b'{"status":"fixture"}'
        response = json.dumps({"name": self.intent, "size": str(len(raw)), "generation": "123"}).encode()
        network = Mock()
        network.open.side_effect = [BytesIO(response), BytesIO(raw)]
        with patch.object(receipts, "build_opener", return_value=network):
            reference = self.store.create_bytes(self.intent, raw)
        self.assertEqual(reference, {"name": self.intent, "size": len(raw), "generation": "123", "sha256": sha256(raw).hexdigest()})
        post, get = [call.args[0] for call in network.open.call_args_list]
        self.assertEqual(post.method, "POST")
        self.assertEqual(post.data, raw)
        self.assertEqual(parse_qs(urlsplit(post.full_url).query), {"uploadType": ["media"], "name": [self.intent],
                                                                 "ifGenerationMatch": ["0"], "fields": ["name,generation,size"]})
        self.assertEqual(get.method, "GET")
        self.assertIsNone(get.data)
        self.assertTrue(urlsplit(get.full_url).path.endswith("/o/" + quote(self.intent, safe="")))
        self.assertEqual(parse_qs(urlsplit(get.full_url).query), {"alt": ["media"], "generation": ["123"], "ifGenerationMatch": ["123"]})
        network.open.side_effect = [BytesIO(response), BytesIO(raw.replace(b"fixt", b"FAIL"))]
        with patch.object(receipts, "build_opener", return_value=network), self.assertRaisesRegex(ValueError, "demo_a_custody_verified_bytes"):
            self.store.create_bytes(self.intent, raw)

    def test_operation_bound_names_exclude_backend_other_producers_runs_and_retries(self):
        secrets = receipts.producer_names(self.env, "secrets", self.decision_id)
        retry = {**self.env, "GITHUB_RUN_ID": "13"}
        other_run = receipts.producer_names(retry, "publish", self.decision_id)
        self.assertEqual(other_run["publication-runtime-intent.json"], self.intent)
        self.assertNotEqual(other_run["publication-runtime.json"], self.names["publication-runtime.json"])
        with self.assertRaisesRegex(ValueError, "demo_a_custody_producer_scope"):
            receipts.producer_names({**self.env, "GITHUB_RUN_ATTEMPT": "2"}, "publish", self.decision_id)
        with patch.object(receipts, "build_opener") as network:
            for name in (secrets["secret-versions.json"], other_run["publication-runtime.json"],
                         "terraform/int/tf-int-01/default.tfstate", "private-plans/int/other/manifest.json"):
                with self.subTest(name=name), self.assertRaises(ValueError):
                    self.store.request("GET", name, generation="123")
            network.assert_not_called()

    def test_existing_intent_conflict_preserves_evidence_without_replacing_or_fetching(self):
        network = Mock()
        network.open.side_effect = HTTPError("https://storage.googleapis.com/", 412, "fixture", {}, BytesIO())
        with patch.object(receipts, "build_opener", return_value=network), self.assertRaises(receipts.transport.Failure) as raised:
            self.store.create(self.intent, {"status": "fixture"})
        self.assertEqual(raised.exception.receipt["http_status"], 412)
        network.open.assert_called_once()

    def test_jobs_have_exactly_ten_distinct_known_slots(self):
        names = {name for phase, actions in receipts.JOB_OPERATIONS.items() for action in actions
                 for name in receipts.job_names(phase, action).values()}
        self.assertEqual(len(names), 10)
        self.assertTrue(all(name.startswith(receipts.PREFIX + "jobs/") and receipts.NAME.fullmatch(name) for name in names))
        with self.assertRaisesRegex(ValueError, "demo_a_custody_job_scope"):
            receipts.job_names("admin", "create")


class PublicationHostGate(unittest.TestCase):
    def test_stage_binds_gate_to_docker_receipt_and_verifies_live_before_docker_load(self):
        digest = "a" * 64
        decision = {"inputs": {"publisher": {}, "targets": list(publish.TARGETS), "docker_toolchain_sha256": digest},
                    "review_sha256": "b" * 64}
        report = {"schema": publish.docker_identity.SCHEMA}
        subject = {"identity": "sha256:" + "c" * 64}
        review = {"subjects": {"credential_toolchain": subject}}
        steps = Mock()
        with patch.dict(publish.os.environ, {}, clear=True), patch.object(publish.preflight, "local_decision", return_value=decision), \
                patch.object(publish.preflight, "json_bytes", side_effect=lambda _, name, *args, **kwargs:
                             {"docker-toolchain.json": report, "review.json": review}[name]), \
                patch.object(publish.docker_identity, "verify_maintained", steps.maintained), \
                patch.object(publish.docker_identity, "verify", steps.live), \
                patch.object(publish, "verify_tool", return_value={"config": "fixture"}), \
                patch.object(publish, "archive_inventory", return_value={}), patch.object(publish, "stage", steps.stage), \
                patch.object(publish, "execute", steps.execute), patch("builtins.print"):
            args = ["stage", "--bundle", "fixture", "--decision-sha256", "d" * 64]
            self.assertEqual(publish.main(args), 1)
            self.assertFalse(steps.mock_calls)
            subject["identity"] = "sha256:" + digest
            self.assertEqual(publish.main(args), 0)
            self.assertEqual([call[0] for call in steps.mock_calls], ["maintained", "live", "stage"])
            steps.reset_mock()
            steps.live.side_effect = publish.docker_identity.ToolchainBlocked("docker_credentialed_toolchain_differs")
            self.assertEqual(publish.main(args), 1)
            self.assertEqual([call[0] for call in steps.mock_calls], ["maintained", "live"])

    def test_stage_rejects_ambient_google_credentials_without_exercising_the_host(self):
        with patch.dict(publish.os.environ, {"GOOGLE_APPLICATION_CREDENTIALS": "fixture"}, clear=True), \
                patch.object(publish.preflight, "local_decision") as local, patch.object(publish, "stage") as stage, patch("builtins.print"):
            self.assertEqual(publish.main(["stage", "--bundle", "fixture", "--decision-sha256", "d" * 64]), 1)
            local.assert_not_called()
            stage.assert_not_called()


if __name__ == "__main__":
    unittest.main()
