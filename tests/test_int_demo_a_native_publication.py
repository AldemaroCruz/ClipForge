from datetime import datetime, timedelta, timezone
from hashlib import sha256
from io import BytesIO
from pathlib import Path
import signal
import tarfile
from tempfile import TemporaryDirectory
import time
import unittest
from unittest.mock import patch
from urllib.parse import parse_qs, unquote, urlsplit

from scripts import check_int_demo_a as gate
from scripts import int_demo_a_native_publication as publisher
from scripts import int_demo_a_publication_host as host
from scripts import int_demo_a_publication_input as custody_input
from scripts import int_demo_a_publish_common as common
from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport


COMMIT = "a" * 40
OPERATION = "b" * 32
APPROVAL = "c" * 64
TOKEN = "synthetic-always-discarded-bearer"
RUN = "123456"


def private_pointer(body=b"test bytes"):
    now = datetime.now(timezone.utc)
    return {"schema": custody_input.SCHEMA, "commit": COMMIT, "operation_id": OPERATION,
            "gate_mode": "demo-a", "decision_sha256": APPROVAL, "host": {}, "issued_utc": (now - timedelta(seconds=10)).isoformat(),
            "expires_utc": (now + timedelta(minutes=10)).isoformat(),
            "input": {"name": custody_input.name(COMMIT, OPERATION), "generation": "1700000000000000",
                      "size": len(body), "sha256": sha256(body).hexdigest()}}


class PublicationInputTests(unittest.TestCase):
    def test_canonical_pin_and_exact_input_object(self):
        pointer = private_pointer()
        encoded = transport.canonical(pointer).decode("ascii")
        valid = custody_input.pointer(encoded, transport.sha(encoded.encode()), COMMIT, APPROVAL)
        self.assertEqual(valid, pointer)
        changed = dict(pointer, input=dict(pointer["input"], name="terraform/int/tf-int-01/default.tfstate"))
        bad = transport.canonical(changed)
        with self.assertRaisesRegex(transport.Blocked, "input_reference"):
            custody_input.pointer(bad.decode(), transport.sha(bad), COMMIT, APPROVAL)
        with self.assertRaisesRegex(transport.Blocked, "pointer_scope_or_sha"):
            custody_input.pointer(encoded, "e" * 64, COMMIT, APPROVAL)
        expired = transport.canonical(dict(pointer, issued_utc="2026-01-01T00:00:00+00:00", expires_utc="2026-01-01T00:59:00+00:00"))
        with self.assertRaisesRegex(transport.Blocked, "pointer_expired"):
            custody_input.pointer(expired.decode(), transport.sha(expired), COMMIT, APPROVAL)

    def test_fetch_pins_method_destination_generation_and_hash(self):
        class Response(BytesIO):
            headers = {}

        raw = b"synthetic bundle fixture bytes"
        pointer = private_pointer(raw)
        with TemporaryDirectory() as tmp, patch.object(custody_input, "build_opener") as opener:
            opener.return_value.open.return_value = Response(raw)
            target = Path(tmp) / "payload.tar"
            custody_input.download(pointer["input"], TOKEN, target)
            request = opener.return_value.open.call_args.args[0]
            url = urlsplit(request.full_url)
            generation = pointer["input"]["generation"]
            self.assertEqual((request.method, url.scheme, url.netloc), ("GET", "https", "storage.googleapis.com"))
            self.assertEqual(unquote(url.path), f"/storage/v1/b/{receipts.BUCKET}/o/{pointer['input']['name']}")
            self.assertEqual(parse_qs(url.query), {"alt": ["media"], "generation": [generation], "ifGenerationMatch": [generation]})
            self.assertEqual(request.headers["Authorization"], "Bearer " + TOKEN)
            self.assertEqual(target.read_bytes(), raw)
            opener.return_value.open.return_value = Response(b"X" * len(raw))
            with self.assertRaisesRegex(transport.Blocked, "input_digest"):
                custody_input.download(pointer["input"], TOKEN, Path(tmp) / "wrong.tar")

    def test_bundle_roundtrip_and_rejects_unsafe_archive_members(self):
        with TemporaryDirectory() as tmp:
            root = Path(tmp).resolve()
            source = root / "source"
            source.mkdir()
            for name in custody_input.ESSENTIAL:
                (source / name).write_bytes(b"synthetic fixture")
            output = root / "package.tar"
            custody_input.pack(source, list(custody_input.ESSENTIAL), output)
            unpacked = root / "unpacked"
            custody_input.unpack(output, unpacked)
            self.assertEqual({path.name for path in unpacked.iterdir()}, custody_input.ESSENTIAL)
            for name, kind in (("../decision.json", tarfile.REGTYPE), ("fake.json", tarfile.SYMTYPE)):
                with self.subTest(name=name):
                    bad = root / "untrusted.tar"
                    record = tarfile.TarInfo(name)
                    record.type = kind
                    record.size = 1 if kind == tarfile.REGTYPE else 0
                    with tarfile.open(bad, "w") as archive:
                        archive.addfile(record, BytesIO(b"x"))
                    with self.assertRaisesRegex(transport.Blocked, r"bundle_member"):
                        custody_input.unpack(bad, root / ("blocked-" + str(kind[0])))


class NativePublicationTests(unittest.TestCase):
    def test_native_kernel_uses_boot_revision_and_legacy_floor(self):
        with self.assertRaisesRegex(host.HostBlocked, "below_reviewable_floor"):
            host.kernel("7.0.0-1017-azure", "Ubuntu 7.0.0-1017.17~24.04.1-azure 7.0.0", "7.0.0-1017.17~24.04.1")
        with self.assertRaisesRegex(host.HostBlocked, "revision_mismatch"):
            host.kernel("7.0.0-1020-azure", "Ubuntu 7.0.0-1017.17~24.04.1-azure 7.0.0", "7.0.0-1020.21~24.04.2")
        self.assertEqual(host.kernel("7.0.0-1020-azure", "Ubuntu 7.0.0-1020.21~24.04.2-azure 7.0.0",
                                     "7.0.0-1020.21~24.04.2")["package"], "linux-image-7.0.0-1020-azure")
        self.assertIn("pinned_docker_engine_runner", gate.role_contract("oci_publication", "credential_toolchain")[1])
        self.assertIn("native_runner_and_skopeo_continuity",
                      gate.role_contract("oci_publication", "credential_toolchain", "native-skopeo")[1])

    def test_requires_same_boot_and_live_expected_projection(self):
        expected = {"sha": "reviewed"}
        before = {"host": expected, "boot_id": "old"}
        with (patch.object(host, "snapshot", return_value=({"host": expected, "boot_id": "new"}, [])),
              patch.object(host, "checked")):
            with self.assertRaisesRegex(host.HostBlocked, "boot_or_context_changed"):
                host.verify({}, expected, before)

    def test_host_block_precedes_wif_read_and_publication_credential_use(self):
        pointer = private_pointer()
        with (patch.object(publisher, "input_checkpoint", side_effect=host.HostBlocked("fixture_host")),
              patch.object(custody_input, "download") as download):
            with self.assertRaisesRegex(host.HostBlocked, "fixture_host"):
                publisher.fetch_bundle(Path("/fixture"), {}, pointer)
            download.assert_not_called()
        with (patch.object(publisher, "verify_checkpoint", side_effect=host.HostBlocked("fixture_host")),
              patch.object(publisher.preflight, "deploy_after_wif") as wif):
            with self.assertRaisesRegex(host.HostBlocked, "fixture_host"):
                publisher.execute(Path("/fixture"), Path("/fixture"), {}, {}, APPROVAL, {}, {}, {})
            wif.assert_not_called()

    def test_two_copy_receipts_follow_intent_and_independent_bytes(self):
        images = {key: {"manifest": pin[0], "archive_sha256": pin[1], "config": ("sha256:" + "d" * 64, 2),
                        "layers": [("sha256:" + "e" * 64, 3)]} for key, pin in common.TARGETS.items()}
        decision = {"operation_id": OPERATION, "expires_utc": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat()}
        env = {"GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1",
               "INT_DEMO_A_AUTH_STARTED_EPOCH": str(int(time.time()))}
        events = []

        def create(name, document):
            events.append((document["status"], name))
            return {"name": name, "generation": "123", "sha256": "f" * 64, "size": 4}

        def copy(_staged_tool, archive, auth, _destination):
            self.assertEqual(auth.stat().st_mode & 0o777, 0o400)
            events.append(("copy", archive.name))
            return 0 if archive.name == "runtime.oci.tar" else 9

        with (TemporaryDirectory() as tmp, patch.object(publisher, "verify_checkpoint"),
              patch.object(publisher.preflight, "deploy_after_wif", return_value=TOKEN),
              patch.object(receipts, "Custody") as storage, patch.object(common, "check_staging_archive"),
              patch.object(publisher.skopeo, "copy", side_effect=copy),
              patch.object(common, "verify_registry", side_effect=lambda *args, **kwargs: events.append(("readback", args[0]))),
              patch.object(common, "digest_file", return_value=common.TARGETS["runtime"][1])):
            storage.return_value.create.side_effect = create
            result = publisher.execute(Path(tmp), Path(tmp), env, decision, APPROVAL, {},
                                       {"manifest": "sha256:" + publisher.skopeo.MANIFEST}, images)
            self.assertFalse((Path(tmp) / "publisher-auth.json").exists())
        self.assertEqual([row[0] for row in events],
                         ["copy_intended", "copy", "readback", "published_and_verified", "copy_intended", "copy"])
        self.assertEqual(result["native_exit"], {"runtime": 0, "db01-noble-client": 9})
        self.assertEqual(result["status"], "copy_outcome_requires_reconciliation")
        public = publisher.public_result(result)
        self.assertEqual(public["receipts_verified"], ["runtime"])
        self.assertNotIn(receipts.PREFIX, repr(public))

    def test_workflow_separates_observe_read_scope_and_write_identity(self):
        workflow = (Path(__file__).resolve().parents[1] / common.WORKFLOW).read_text()
        _, observation = workflow.split("  observe-host:", 1)
        observation, rest = observation.split("  local-preflight:", 1)
        self.assertNotIn("id-token:", observation)
        self.assertNotIn("google-github-actions/auth", observation)
        self.assertNotIn("download-artifact@", rest)
        required_order = ("native_publication preauth", "auth/devstorage.read_only", "native_publication fetch",
                          "native_publication stage", "auth/cloud-platform", "native_publication execute")
        self.assertEqual(sorted(required_order, key=rest.index), list(required_order))
        self.assertIn("environment: int", rest)
        self.assertIn("secrets.INT_DEMO_A_PUBLISH_POINTER_JSON", rest)

    def test_budget_blocks_owner_expiry_even_with_fresh_wif(self):
        with self.assertRaisesRegex(transport.Blocked, "owner_decision_expired"):
            publisher.credential_budget({"INT_DEMO_A_AUTH_STARTED_EPOCH": str(int(time.time()))},
                                        {"expires_utc": "2026-01-01T00:00:00+00:00"})

    def test_budget_covers_full_intent_and_copy_deadlines_at_the_boundary(self):
        decision = {"expires_utc": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}
        started = 1700000000
        env = {"INT_DEMO_A_AUTH_STARTED_EPOCH": str(started)}
        with patch.object(publisher.time, "time", return_value=started + 600):
            with self.assertRaisesRegex(transport.Blocked, "credential_margin"):
                publisher.credential_budget(env, decision)
        self.assertEqual((publisher.INTENT_BUDGET_SECONDS, publisher.COPY_BUDGET_SECONDS), (735, 615))
        for minimum, check in (
            (publisher.INTENT_BUDGET_SECONDS, lambda: publisher.credential_budget(env, decision)),
            (publisher.COPY_BUDGET_SECONDS, lambda: publisher.credential_budget(
                env, decision, required=publisher.COPY_BUDGET_SECONDS)),
        ):
            with self.subTest(minimum=minimum), patch.object(publisher.time, "time") as now:
                now.return_value = started + 900 - minimum
                check()
                now.return_value += 1
                with self.assertRaisesRegex(transport.Blocked, "credential_margin"):
                    check()
                now.return_value = started + 600
                with self.assertRaisesRegex(transport.Blocked, "credential_margin"):
                    check()
        with patch.object(publisher.skopeo, "_run_copy") as adapter:
            publisher.skopeo.copy("fixture/tool", "fixture/source", "fixture/auth", next(iter(publisher.skopeo.TARGETS)))
        self.assertEqual(adapter.call_args.kwargs["timeout"], publisher.COPY_SECONDS)

    def test_budget_shortfall_before_second_intent_preserves_first_receipt(self):
        started = 1700000000
        decision = {"operation_id": OPERATION, "expires_utc": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}
        env = {"GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1",
               "INT_DEMO_A_AUTH_STARTED_EPOCH": str(started)}
        images = {key: {"manifest": pin[0], "archive_sha256": pin[1], "config": ("sha256:" + "d" * 64, 2),
                        "layers": [("sha256:" + "e" * 64, 3)]} for key, pin in common.TARGETS.items()}
        with (TemporaryDirectory() as tmp, patch.object(publisher, "verify_checkpoint"),
              patch.object(publisher.time, "time", return_value=started) as now,
              patch.object(publisher.preflight, "deploy_after_wif", return_value=TOKEN) as credential,
              patch.object(receipts, "Custody") as storage, patch.object(common, "check_staging_archive"),
              patch.object(publisher.skopeo, "copy", return_value=0) as copy,
              patch.object(common, "verify_registry"),
              patch.object(common, "digest_file",
                           side_effect=lambda path: common.TARGETS[path.name.removesuffix(".oci.tar")][1])):
            def create(_name, document):
                if document["status"] == "published_and_verified":
                    now.return_value = started + 166
                return {"generation": "123", "sha256": "f" * 64, "size": 4}

            write = storage.return_value.create
            write.side_effect = create
            result = publisher.execute(Path(tmp), Path(tmp), env, decision, APPROVAL, {},
                                       {"manifest": "sha256:" + publisher.skopeo.MANIFEST}, images)
            self.assertFalse((Path(tmp) / "publisher-auth.json").exists())
        self.assertEqual([item.args[1]["status"] for item in write.call_args_list],
                         ["copy_intended", "published_and_verified"])
        self.assertEqual((result["phase"], result["status"], result.get("error_code")),
                         ("db01-noble-client", "publication_pending", "native_publication_credential_margin"))
        self.assertEqual(publisher.public_result(result)["receipts_verified"], ["runtime"])
        self.assertEqual(publisher.public_result(result)["intents_verified"], ["runtime"])
        copy.assert_called_once()
        credential.assert_called_once()

    def test_readback_deadline_preserves_uncertain_copy_and_prevents_retry(self):
        started = 1700000000
        decision = {"operation_id": OPERATION, "expires_utc": (datetime.now(timezone.utc) + timedelta(minutes=10)).isoformat()}
        env = {"GITHUB_SHA": COMMIT, "GITHUB_RUN_ID": RUN, "GITHUB_RUN_ATTEMPT": "1",
               "INT_DEMO_A_AUTH_STARTED_EPOCH": str(started)}
        images = {key: {"manifest": pin[0], "archive_sha256": pin[1], "config": ("sha256:" + "d" * 64, 2),
                        "layers": [("sha256:" + "e" * 64, 3)]} for key, pin in common.TARGETS.items()}
        previous = signal.getsignal(signal.SIGALRM)
        with (TemporaryDirectory() as tmp, patch.object(publisher, "verify_checkpoint"),
              patch.object(publisher.time, "time", return_value=started),
              patch.object(publisher.preflight, "deploy_after_wif", return_value=TOKEN) as credential,
              patch.object(receipts, "Custody") as storage, patch.object(common, "check_staging_archive"),
              patch.object(publisher.skopeo, "copy", return_value=0) as copy,
              patch.object(publisher, "READBACK_SECONDS", 0.02, create=True),
              patch.object(common, "digest_file",
                           side_effect=lambda path: common.TARGETS[path.name.removesuffix(".oci.tar")][1]),
              patch.object(common, "verify_registry", side_effect=lambda *args, **kwargs: time.sleep(1))):
            storage.return_value.create.return_value = {"generation": "123", "sha256": "f" * 64, "size": 4}
            result = publisher.execute(Path(tmp), Path(tmp), env, decision, APPROVAL, {},
                                       {"manifest": "sha256:" + publisher.skopeo.MANIFEST}, images)
            self.assertFalse((Path(tmp) / "publisher-auth.json").exists())
        self.assertEqual((result["status"], result.get("error_code")),
                         ("copy_outcome_requires_reconciliation", "native_publication_readback_deadline"))
        self.assertEqual(result["native_exit"], {"runtime": 0})
        self.assertEqual(set(result["intent"]), {"runtime"})
        self.assertEqual(result["references"], {})
        self.assertEqual(signal.getitimer(signal.ITIMER_REAL), (0.0, 0.0))
        self.assertEqual(signal.getsignal(signal.SIGALRM), previous)
        storage.return_value.create.assert_called_once()
        copy.assert_called_once()
        credential.assert_called_once()


if __name__ == "__main__":
    unittest.main()
