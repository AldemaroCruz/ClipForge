"""Directed offline contracts for the Noble first observation and SCA handoff."""

from copy import deepcopy
from io import BytesIO
import json
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch
from urllib.parse import parse_qs, urlsplit

from scripts import int_guest_inventory as transport
from scripts import int_noble_first_observation as observer
from scripts import int_noble_hostkey as host
from tests import test_int_noble_guest as fixtures


CONTROLS = "a" * 40
PRODUCER = "c302dcc366ed450f91c1693072eb9008e7975e4c"
PLAN_RUN = "90"
RUN = "91"
POSTVERIFY_RUN = "93"


def summary_fixture(*, producer=PRODUCER, image_name="ubuntu-2404-noble-amd64-v20261105", image_id="1892012953239034119"):
    vm, boot, data, project, approval = fixtures.native_gets()
    target = {**observer.CANDIDATE_CONSTANTS,
              **{key: approval[key] for key in (*observer.CANDIDATE_IDS, *observer.CANDIDATE_TIMES, "startup_sha256")},
              "hostkey_nonce": fixtures.NONCE, "image_name": image_name, "image_id": image_id}
    boot.update(sourceImage=observer.API + observer.guest.IMAGE_PATH + image_name, sourceImageId=image_id)
    manifest = {"name": f"private-plans/int/{producer}/{PLAN_RUN}-1/manifest.json",
                "generation": "101", "sha256": "f" * 64, "size": 200}
    summary = {"schema": observer.CREATION_SCHEMA, "status": "created_verified", "producer_commit": producer,
               "producer_run": PLAN_RUN, "controls_commit": CONTROLS, "apply_run_id": RUN, "candidate": target,
               "approval": {"observation": True, "plan_manifest": manifest},
               "native_apply_completed": True, "debian_preserved": True,
               "state": {**observer.STATE_PIN, "generation": "111", "serial": 8, "managed_address_count": 53,
                         "preserved_address_count": 42, "current_lock_absent": True},
               "receipt": {"name": f"private-plans/int/{CONTROLS}/{RUN}-1/foundation-state.json",
                           "generation": "100", "sha256": "e" * 64, "size": 1500}}
    record = {**fixtures.host_record(), "script_sha256": observer.PUBLISHER_SHA256}
    readings = dict(zip(observer.SNAPSHOT_ROUTES, (vm, boot, data, project)))
    readings[observer.SERIAL] = fixtures.serial(record)
    summary["control_plane"] = observer.snapshot(readings.__getitem__, target)
    return summary, readings


class NobleFirstObservation(unittest.TestCase):
    def test_source_apply_run_requires_protected_workflow_first_attempt_and_success(self):
        identity = {"id": int(RUN), "run_attempt": 1, "path": observer.APPLY_PATH,
                    "head_sha": CONTROLS, "head_branch": "ci/bootstrap-sec03", "event": "workflow_dispatch",
                    "status": "completed", "conclusion": "success", "repository": {"full_name": "AldemaroCruz/ClipForge"}}
        with patch.object(observer, "build_opener") as opener:
            opener.return_value.open.return_value = BytesIO(transport.canonical(identity))
            observer.checked_apply_run(RUN, CONTROLS, "synthetic-test-header")
            req = opener.return_value.open.call_args.args[0]
            self.assertEqual(req.full_url, f"https://api.github.com/repos/AldemaroCruz/ClipForge/actions/runs/{RUN}")
            for change in ({"head_sha": PRODUCER}, {"run_attempt": 2}, {"conclusion": "failure"}):
                opener.return_value.open.return_value = BytesIO(transport.canonical({**identity, **change}))
                with self.subTest(change=change), self.assertRaisesRegex(ValueError, "NOBLE_APPLY_RUN_UNVERIFIED"):
                    observer.checked_apply_run(RUN, CONTROLS, "synthetic-test-header")

    def test_postverification_requires_its_own_verified_run_and_exact_original(self):
        token = "synthetic-test-header"
        with (patch.object(observer, "checked_apply_run") as successful_apply,
              patch.object(observer.postverify, "verify_postverify_run") as verified_run,
              patch.object(observer.postverify, "verify_original_run") as original_run):
            actual_original = observer.postverify.ORIGINAL_RUN
            observer.checked_creation_runs(actual_original, CONTROLS, token, POSTVERIFY_RUN)
            verified_run.assert_called_once_with(POSTVERIFY_RUN, CONTROLS, token)
            original_run.assert_called_once_with(token)
            successful_apply.assert_not_called()
            for bad_run, verifier in ((RUN, POSTVERIFY_RUN), (actual_original, actual_original), (actual_original, "x")):
                with self.subTest(run=bad_run, verifier=verifier), self.assertRaisesRegex(ValueError, "NOBLE_POSTVERIFY_RUN_ID"):
                    observer.checked_creation_runs(bad_run, CONTROLS, token, verifier)
            self.assertEqual(verified_run.call_count, 1)
            self.assertEqual(original_run.call_count, 1)
            original_run.reset_mock()
            verified_run.side_effect = ValueError("NOBLE_POSTVERIFY_RUN_UNVERIFIED")
            with self.assertRaisesRegex(ValueError, "NOBLE_POSTVERIFY_RUN_UNVERIFIED"):
                observer.checked_creation_runs(actual_original, CONTROLS, token, POSTVERIFY_RUN)
            original_run.assert_not_called()
            successful_apply.assert_not_called()

    def test_postverification_pin_binds_exact_handoff_and_separate_immutable_receipt(self):
        source, readings = summary_fixture()
        original = observer.postverify.ORIGINAL_RUN
        receipt = {**source["receipt"], "name": f"private-plans/int/{CONTROLS}/{POSTVERIFY_RUN}-1/foundation-state.json"}
        envelope = {
            "schema": "clipforge-db01-noble-postverification-receipt-1", "status": "creation_postverified",
            "verifier": {"run_id": POSTVERIFY_RUN}, "original_apply": {"run_id": original, "conclusion": "failure"},
            "plan": {"producer_commit": PRODUCER, "producer_run": PLAN_RUN},
            "creation": {key: source[key] for key in ("state", "candidate", "control_plane")},
            "receipt": receipt,
        }
        raw = transport.canonical(envelope)
        digest = host.sha(raw)
        with patch.object(observer.postverify, "verify_envelope") as validator:
            parsed, bound = observer.creation_handoff(raw, digest, CONTROLS, original, POSTVERIFY_RUN)
            validator.assert_called_once_with(envelope, CONTROLS, POSTVERIFY_RUN)
            self.assertEqual(parsed, envelope)
            self.assertEqual(bound["apply_run_id"], original)
            self.assertEqual(bound["receipt"], receipt)
            with self.assertRaisesRegex(ValueError, "NOBLE_APPLY_SUMMARY_HASH"):
                observer.creation_handoff(raw + b" ", digest, CONTROLS, original, POSTVERIFY_RUN)
            with self.assertRaisesRegex(ValueError, "NOBLE_APPLY_SUMMARY_ORIGIN"):
                observer.creation_handoff(raw, digest, CONTROLS, original)
            with self.assertRaisesRegex(ValueError, "NOBLE_POSTVERIFY_ORIGINAL_APPLY"):
                observer.creation_handoff(raw, digest, CONTROLS, RUN, POSTVERIFY_RUN)
        proof = {key: value for key, value in envelope.items() if key != "receipt"}
        with patch.object(observer.custody, "fetch_verified", return_value=transport.canonical(proof)) as fetch:
            observer.verify_creation_receipt(parsed)
            fetch.assert_called_once_with(receipt)
            fetch.return_value = transport.canonical({**proof, "status": "forged"})
            with self.assertRaisesRegex(ValueError, "NOBLE_CREATED_RECEIPT_ORIGIN"):
                observer.verify_creation_receipt(parsed)
        pin = observer.make_pin(bound, digest, readings.__getitem__)
        self.assertEqual(pin["schema"], observer.POSTVERIFY_PIN_SCHEMA)
        self.assertEqual(pin["postverify_run_id"], POSTVERIFY_RUN)
        self.assertEqual(pin["apply_run_id"], original)
        raw_pin = transport.canonical(pin)
        observer.check_pin(raw_pin, host.sha(raw_pin), bound, digest)
        for change in ({"postverify_run_id": "94"}, {"receipt": source["receipt"]}, {"controls_commit": PRODUCER}):
            with self.subTest(change=change), self.assertRaisesRegex(ValueError, "NOBLE_PIN_APPLY_BINDING"):
                observer.check_pin(raw_pin, host.sha(raw_pin), {**bound, **change}, digest)

    def test_actual_postverification_contract_rejects_tampered_artifact_even_with_its_new_hash(self):
        source, _ = summary_fixture()
        postverify = observer.postverify
        exact_ids = {"instance_id": postverify.EXPECTED_INSTANCE, "boot_disk_id": postverify.EXPECTED_BOOT_DISK,
                     "data_disk_id": postverify.EXPECTED_DATA_DISK}
        evidence = {
            "schema": postverify.SCHEMA, "status": postverify.STATUS,
            "verifier": {"controls_commit": CONTROLS, "run_id": POSTVERIFY_RUN, "attempt": "1",
                         "workflow": postverify.WORKFLOW},
            "original_apply": {**postverify.original_apply_binding(), "intent_at_utc": "2026-11-20T15:18:25Z",
                               "operation_completed_at_utc": "2026-11-20T15:20:04Z"},
            "plan": {"producer_commit": postverify.apply.PRODUCER, "producer_run": postverify.apply.PLAN_RUN,
                     **postverify.apply.PLAN},
            "creation": {"state": postverify.EXPECTED_STATE,
                         "candidate": {**source["candidate"], **exact_ids},
                         "control_plane": {**source["control_plane"], **exact_ids},
                         "debian_preserved": True, "bootstrap_authorized": False, "application_authorized": False,
                         "guest_access_performed": False, "checks": postverify.observed_checks()},
        }
        sealed = transport.canonical(evidence)
        receipt = {"name": f"private-plans/int/{CONTROLS}/{POSTVERIFY_RUN}-1/foundation-state.json",
                   "generation": "996", "size": len(sealed), "sha256": host.sha(sealed)}
        report = {**evidence, "receipt": receipt}
        raw = transport.canonical(report)
        _, bound = observer.creation_handoff(raw, host.sha(raw), CONTROLS, postverify.ORIGINAL_RUN, POSTVERIFY_RUN)
        self.assertEqual(bound["candidate"]["instance_id"], postverify.EXPECTED_INSTANCE)
        changed = deepcopy(report)
        changed["creation"]["candidate"]["hostkey_nonce"] = "b" * 64
        forged = transport.canonical(changed)
        with self.assertRaisesRegex(ValueError, "receipt was altered"):
            observer.creation_handoff(forged, host.sha(forged), CONTROLS, postverify.ORIGINAL_RUN, POSTVERIFY_RUN)

    def test_compute_project_request_includes_self_link_validated_by_snapshot(self):
        fields = parse_qs(urlsplit(observer.PROJECT).query)["fields"]
        self.assertEqual(fields, ["name,id,selfLink,commonInstanceMetadata"])

    def test_custodied_first_boot_pin_binds_exact_run_and_host(self):
        summary, readings = summary_fixture()
        raw = transport.canonical(summary)
        digest = host.sha(raw)
        self.assertEqual(observer.exact_summary(raw, digest, CONTROLS, RUN), summary)
        reader = Mock(side_effect=readings.__getitem__)
        pin = observer.make_pin(summary, digest, reader)
        self.assertEqual([entry.args[0] for entry in reader.call_args_list],
                         [*observer.SNAPSHOT_ROUTES, observer.SERIAL, *observer.SNAPSHOT_ROUTES])
        raw_pin = transport.canonical(pin)
        checked = observer.check_pin(raw_pin, host.sha(raw_pin), summary, digest)
        self.assertEqual(checked["record"]["guest_boot_id"], fixtures.BOOT_ID)
        self.assertTrue(checked["known_hosts_line"].startswith(host.INSTANCE + "." + fixtures.ID + " "))
        self.assertNotIn(b'"contents"', raw_pin)
        with self.assertRaisesRegex(ValueError, "NOBLE_PIN_APPLY_BINDING"):
            observer.check_pin(raw_pin, host.sha(raw_pin), {**summary, "apply_run_id": "92"}, digest)

    def test_renewed_plan_on_same_commit_binds_new_exact_image_and_producer(self):
        summary, readings = summary_fixture(producer=CONTROLS, image_name="ubuntu-2404-noble-amd64-v20261118a",
                                            image_id="1892012953239034118")
        raw = transport.canonical(summary)
        digest = host.sha(raw)
        self.assertEqual(observer.exact_summary(raw, digest, CONTROLS, RUN), summary)
        pin = observer.make_pin(summary, digest, readings.__getitem__)
        self.assertEqual(pin["producer_commit"], CONTROLS)
        readings[observer.BOOT]["sourceImageId"] = "1892012953239034119"
        with self.assertRaisesRegex(ValueError, "NOBLE_OBSERVER_IMAGE_OR_DATA_SOURCE"):
            observer.make_pin(summary, digest, readings.__getitem__)

    def test_restarted_vm_or_missing_serial_record_blocks(self):
        summary, readings = summary_fixture()
        vm_calls = 0
        def restart(route):
            nonlocal vm_calls
            if route == observer.VM:
                vm_calls += 1
                if vm_calls == 2:
                    return {**readings[route], "lastStartTimestamp": "2026-11-20T09:00:01Z"}
            return readings[route]
        with self.assertRaisesRegex(ValueError, "NOBLE_OBSERVER_FIRST_BOOT"):
            observer.make_pin(summary, "b" * 64, restart)
        readings[observer.SERIAL] = {"start": "0", "next": "10", "contents": "boot only\n"}
        with self.assertRaisesRegex(ValueError, "NOBLE_SERIAL_RECORD_NOT_UNIQUE_COMPLETE"):
            observer.make_pin(summary, "b" * 64, readings.__getitem__)

    def test_unapproved_handoff_or_old_image_cannot_enter(self):
        summary, _ = summary_fixture()
        variants = (
            {**summary, "status": "partial"},
            {**summary, "approval": {"observation": False}},
            {**summary, "producer_run": RUN},
            {**summary, "producer_run": "99"},
            {**summary, "producer_commit": "ci/bootstrap-sec03"},
            {**summary, "candidate": {**summary["candidate"], "image_name": "debian-13-fixture"}},
            {**summary, "candidate": {**summary["candidate"], "image_id": "name-not-id"}},
            {**summary, "receipt": {**summary["receipt"], "name": "private-plans/int/unrelated"}},
            {**summary, "state": {**summary["state"], "managed_address_count": 52}},
        )
        for value in variants:
            raw = transport.canonical(value)
            with self.subTest(value=value["status"]), self.assertRaises(ValueError):
                observer.exact_summary(raw, host.sha(raw), CONTROLS, RUN)

    def test_noble_process_policy_keeps_historical_defaults_and_strict_remote_command(self):
        with TemporaryDirectory() as temp:
            work = Path(temp)
            (work / "known_hosts").write_text("fixture", encoding="ascii")
            name, port, program, payload = "sa_fixture", 4321, str(work / "gcloud"), b"read only"
            noble = observer.ssh_builder(fixtures.ID)
            args = noble(work, name, port)
            self.assertIn(f"-oHostKeyAlias={host.INSTANCE}.{fixtures.ID}", args)
            for option in ("-oStrictHostKeyChecking=yes", "-oHostKeyAlgorithms=ssh-ed25519",
                           "-oUpdateHostKeys=no", "-oPasswordAuthentication=no", "-oClearAllForwardings=yes"):
                self.assertIn(option, args)
            self.assertEqual(args[-2:], ["127.0.0.1", "/usr/bin/sudo -n /usr/bin/python3 -I -"])
            self.assertEqual(observer.noble_tunnel(program, port)[3:5], [host.INSTANCE, "22"])
            historical = transport.ProcessRunner(work, program, payload, "fixture")
            historical.username = name
            self.assertEqual(historical._kind(transport.ssh_command(work, name, port), payload), "ssh")
            with self.assertRaises(transport.Blocked):
                historical._kind(args, payload)
            constrained = transport.ProcessRunner(work, program, payload, "fixture", ssh_builder=noble,
                                                  tunnel_builder=observer.noble_tunnel)
            constrained.username = name
            self.assertEqual(constrained._kind(args, payload), "ssh")
            with self.assertRaises(transport.Blocked):
                constrained._kind([*args[:-1], "unreviewed"], payload)

    def test_changed_control_plane_does_not_import_any_key(self):
        summary, readings = summary_fixture()
        evidence = observer.make_pin(summary, "b" * 64, readings.__getitem__)["pin"]
        readings[observer.VM]["metadata"]["fingerprint"] = "changed"
        env = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_RUN_ID": "92", "GITHUB_RUN_ATTEMPT": "1",
               "GITHUB_SHA": CONTROLS}
        client = Mock(http_receipts=[])
        with TemporaryDirectory() as temp, patch.object(transport, "cleanup", return_value={"status": "no_registered_key"}):
            root = Path(temp)
            reports = root / "reports"
            reports.mkdir()
            work = root / "work"
            work.mkdir()
            result = observer.collect(env, work, reports, summary, evidence, reader=readings.__getitem__, client=client)
            journal = json.loads((work / "cleanup-journal.json").read_bytes())
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["error_code"], "NOBLE_FIRST_BOOT_OR_METADATA_CHANGED_BEFORE_SSH")
        self.assertFalse(journal["import_attempted"])
        client.profile.assert_not_called()

    def test_native_sca_requires_observed_ubuntu_binary_and_source_coverage(self):
        observed = fixtures.guest_report()
        data = {"schema": "clipforge-int-db01-noble-evidence-1", "guest": observed, "runtime_authorized": False,
                "payload_sha256": observer.PAYLOAD_SHA256, "read_only": True,
                "target": {"project": host.PROJECT, "project_number": host.PROJECT_NUMBER, "zone": host.ZONE, "name": host.INSTANCE},
                "workflow_commit": CONTROLS, "control_plane": {"instance_id": fixtures.ID, "snapshot_sha256": "f" * 64},
                "guest_sha256": host.sha(transport.canonical(observed) + b"\n")}
        raw = transport.canonical(data)
        digest = host.sha(raw)
        sbom, receipt = observer.noble_sbom(raw, digest)
        packages = [{"Identifier": {"PURL": component["purl"]}, "SrcName": component["properties"][0]["value"],
                     "SrcVersion": component["properties"][1]["value"]} for component in sbom["components"]]
        native = {"SchemaVersion": 2, "ArtifactType": "cyclonedx", "Metadata": {"OS": {"Family": "ubuntu", "Name": "24.04"}},
                  "Results": [{"Class": "os-pkgs", "Type": "ubuntu", "Packages": packages, "Vulnerabilities": [{"Severity": "HIGH"}]}]}
        metadata = transport.canonical({"Version": 2, "UpdatedAt": datetime.now(timezone.utc).isoformat()})
        checked = observer.verify_sca(raw, digest, transport.canonical(native), metadata, "e" * 64)
        self.assertEqual(checked["native_findings_by_severity"], {"HIGH": 1})
        self.assertEqual(checked["status"], "findings_review_pending")
        self.assertTrue(checked["pgdg_packages"])
        self.assertEqual(receipt["installed_binary_count"], len(packages))
        self.assertEqual(observer.noble_purl_identity(observer.package_purl(
            {"binary_name": "foo:amd64", "binary_version": "2:1.0-3", "architecture": "amd64"})),
            ("foo", "2:1.0-3", "amd64", "ubuntu-24.04"))
        invalid = deepcopy(native)
        invalid["Results"][0]["Packages"].pop()
        with self.assertRaisesRegex(ValueError, "NOBLE_SCA_NATIVE_PACKAGE_OR_SOURCE_DIFFERENCE"):
            observer.verify_sca(raw, digest, transport.canonical(invalid), metadata, "e" * 64)


if __name__ == "__main__":
    unittest.main()
