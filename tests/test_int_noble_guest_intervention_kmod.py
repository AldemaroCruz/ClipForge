from copy import deepcopy
from datetime import datetime, timedelta, timezone
import os
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import int_noble_guest_intervention_kmod_contract as bridge_contract
from scripts import int_noble_guest_intervention_kmod as payload
from scripts import int_noble_guest_intervention_kmod_render as render


SHA = "a" * 64
COMMIT = "b" * 40
MODULES = payload.probe.kernel.MODULES


def observation(*, after=False):
    kernel = payload.probe.kernel
    return {"schema": payload.probe.SCHEMA, "limitations": list(payload.probe.LIMITATIONS),
            "kernel": {"schema": kernel.SCHEMA, "boot_id": payload.IDENTITY["boot_id"], "release": payload.IDENTITY["release"],
                       "virtualization": "google", "modules": {name: {"disk": "module_file", "loaded": False, "sysfs": False}
                                                                for name in MODULES},
                       "units": {name: {"load": "not-found", "active": "inactive", "file": "absent"} for name in kernel.UNIT_NAMES},
                       "mounts": dict.fromkeys(kernel.FILESYSTEMS, 0), "exports": {"active": None, "configured": 0},
                       "listeners": {name: dict.fromkeys(map(str, kernel.PORTS), 0) for name in ("tcp", "tcp6", "udp", "udp6")},
                       "autoload": {"modules_load": dict.fromkeys(MODULES, 0), "modprobe": {
                           name: dict.fromkeys(kernel.AUTO_DIRECTIVES, 0) | {"aliases": 1, "blacklist": int(after),
                                                                           "install": "deny" if after else "default"}
                           for name in MODULES}}, "limitations": list(kernel.LIMITATIONS)},
            "xen": {"private_nic_driver": "gve", "backend_vifs": 0},
            "ceph": {"pid1_mounts": 0, "fstab_mounts": 0, "pid1_canonical_remote_sockets": 0, "named_processes": 0,
                     "packages": dict.fromkeys(payload.probe.CEPH_PACKAGES, False), "data_disk_relation": "expected_device_unmounted"},
            "kmod": {"modules_disabled": False, "helper": "standard", "scope_rule": "reviewed" if after else "absent",
                     "boot_blacklist": dict.fromkeys(MODULES, False), "dry_run": {
                         name: {"direct": "deny_install" if after else "would_insert",
                                "aliases": ["no_action_reported" if after else "would_insert"]} for name in MODULES}}}


def baseline(snapshot, before):
    return {"schema": payload.OBSERVATION, "initial_observation_run_id": "44772950030", "controls_commit": "c" * 40,
            "payload_sha256": payload.OBSERVATION_SHA256, "control_plane": snapshot,
            "guest": before, "risk_accepted": False, "runtime_authorized": False}


def wrapped(operation, snapshot, evidence, *, executable_sha256=SHA, expiry=None):
    authority = {"schema": payload.AUTHORIZATION, **payload.IDENTITY, "pin_sha256": payload.PIN_SHA256,
                 "rule_sha256": payload.RULE_SHA256, "payload_sha256": executable_sha256,
                 "evidence_sha256": payload.object_sha(evidence), "operation": operation,
                 "operation_id": "reviewed-kmod-fixture-" + operation, "approved_commit": COMMIT,
                 "snapshot_sha256": payload.object_sha(snapshot),
                 "expires_utc": (expiry or datetime.now(timezone.utc) + timedelta(minutes=5)).isoformat()}
    return {"schema": payload.INPUT, "authority": authority, "authority_sha256": payload.object_sha(authority), "evidence": evidence}


class FixtureTests(unittest.TestCase):
    def setUp(self):
        self.snapshot = {key: payload.IDENTITY[key] for key in ("instance_id", "boot_disk_id", "data_disk_id")} | {"metadata_fingerprint": "fixture"}
        self.before = observation()
        self.after = observation(after=True)
        self.evidence = baseline(self.snapshot, self.before)


class ContractTests(FixtureTests):
    def test_archive_and_transport_are_bound_to_the_exact_source(self):
        scripts = Path(payload.probe.__file__).parent
        executable = render.payload_bytes(scripts)
        self.assertEqual(len(payload.RULE), payload.RULE_BYTES)
        self.assertEqual(payload.digest(payload.RULE), payload.RULE_SHA256)
        self.assertEqual(render.payload_bytes(scripts), executable)
        command = bridge_contract.command(executable, payload.digest(executable))
        self.assertTrue(command.startswith("/usr/bin/sudo -n /usr/bin/python3 -I -c "))
        self.assertLess(len(command), 131072)
        with patch.dict(sys.modules):
            namespace = {"__name__": "payload_fixture"}
            exec(compile(executable, "<fixture payload>", "exec"), namespace)
            self.assertEqual(namespace["RULE"], payload.RULE)
            self.assertEqual(namespace["probe"].SCHEMA, payload.probe.SCHEMA)

    def test_scoped_request_checks_sha_identity_and_expiry_before_mutation(self):
        packet = wrapped("apply", self.snapshot, self.evidence)
        raw = payload.canonical(packet)
        self.assertEqual(payload.request(raw, SHA), (packet["authority"], packet["authority_sha256"], self.evidence))
        with self.assertRaisesRegex(ValueError, "kmod_authority_scope"):
            payload.request(raw, "b" * 64)
        expired = wrapped("apply", self.snapshot, self.evidence, expiry=datetime.now(timezone.utc) - timedelta(seconds=1))
        with self.assertRaisesRegex(ValueError, "kmod_authority_expired"):
            payload.request(payload.canonical(expired), SHA)

    def test_pre_and_post_do_not_allow_ambiguous_aliases_or_consumers(self):
        payload.expected_transition(self.before, self.after)
        for target, change, reason in (
            (self.before, lambda report: report["kmod"]["dry_run"]["ceph"].update(aliases=None), "kmod_unproven_baseline"),
            (self.after, lambda report: report["kmod"]["dry_run"]["ceph"].update(aliases=["would_insert"]), "kmod_unproven_postcheck"),
            (self.after, lambda report: report["xen"].update(private_nic_driver="xen_netfront"), "kmod_xen_consumer"),
            (self.after, lambda report: report["ceph"].update(pid1_mounts=1), "kmod_ceph_or_disk"),
        ):
            drifted = deepcopy(target)
            change(drifted)
            with self.subTest(reason=reason), self.assertRaisesRegex(ValueError, reason):
                payload.expected_transition(drifted if target is self.before else self.before,
                                            drifted if target is self.after else self.after)

    def test_bridge_rejects_old_pin_or_metadata_and_native_failure(self):
        pin = b"proof fixture"
        executable = b"exact executable fixture"
        with (patch.object(payload, "PIN_SHA256", payload.digest(pin)),
              patch.object(bridge_contract.observer, "checked_inputs", return_value=({}, {"control_plane": self.snapshot}))):
            packet = wrapped("apply", self.snapshot, self.evidence, executable_sha256=payload.digest(executable))
            kwargs = {"protected_authority_sha256": packet["authority_sha256"], "protected_payload_sha256": payload.digest(executable),
                      "controls_commit": COMMIT, "handoff": b"fixture", "pin_bytes": pin}
            self.assertEqual(bridge_contract.admit(payload.canonical(packet), executable, snapshot=self.snapshot, **kwargs), packet["authority"])
            with self.assertRaisesRegex(ValueError, "kmod_protected_snapshot_drift"):
                bridge_contract.admit(payload.canonical(packet), executable, snapshot={**self.snapshot, "metadata_fingerprint": "altered"}, **kwargs)
            with self.assertRaisesRegex(ValueError, "kmod_primary_failure"):
                bridge_contract.accept_success(b"fixture", 255, self.snapshot, self.snapshot, packet["authority"], packet["authority_sha256"])


@unittest.skipUnless(os.name == "posix", "isolated rule tests require POSIX filesystem operations")
class FilesystemTests(FixtureTests):
    def setUp(self):
        super().setUp()
        scratch = self.enterContext(TemporaryDirectory(prefix="clipforge-kmod-fixture-"))
        self.root = Path(scratch)
        self.conf = self.root / "modprobe.d"
        self.conf.mkdir(mode=0o755)
        self.journal = self.root / "journal"
        self.rule = self.conf / payload.RULE_PATH.name
        self.enterContext(patch.multiple(payload, JOURNAL=self.journal, RULE_PATH=self.rule))
        self.enterContext(patch.object(payload.guest, "guest_identity", return_value=payload.IDENTITY["boot_id"]))
        self.enterContext(patch.object(payload, "live_report", side_effect=lambda: self.after if self.rule.exists() else self.before))
        owner = self.root.stat()
        if (owner.st_uid, owner.st_gid) != (0, 0):
            # Present the fixture owner as root without bypassing file identity, unlink, link or fsync checks.
            def root_owned(info):
                self.assertEqual((info.st_uid, info.st_gid), (owner.st_uid, owner.st_gid))
                fields = {name: getattr(info, name) for name in dir(info) if name.startswith("st_")}
                return SimpleNamespace(**(fields | {"st_uid": 0, "st_gid": 0}))

            native_lstat = Path.lstat

            def fixture_lstat(path, *args, **kwargs):
                info = native_lstat(path, *args, **kwargs)
                return root_owned(info) if path.is_relative_to(self.root) else info

            self.enterContext(patch.object(payload, "os", SimpleNamespace(**(vars(os) | {"fstat": lambda fd: root_owned(os.fstat(fd))}))))
            self.enterContext(patch.object(Path, "lstat", fixture_lstat))

    def run_action(self, action, evidence):
        packet = wrapped(action, self.snapshot, evidence)
        outcome = payload.execute(payload.canonical(packet), SHA)
        return packet, outcome

    def test_apply_and_withdraw_exact_real_files_and_preserve_foreign_config(self):
        foreign = self.conf / "previous-rule.conf"
        foreign.write_bytes(b"preserve it\n")
        packet, applied = self.run_action("apply", self.evidence)
        self.assertEqual(applied["status"], "applied_verified", applied)
        self.assertEqual(bridge_contract.accept_success(payload.canonical(applied), 0, self.snapshot, self.snapshot,
                                                       packet["authority"], packet["authority_sha256"]), applied)
        self.assertEqual(self.rule.read_bytes(), payload.RULE)
        self.assertEqual(payload.rule_record(), applied["file"])
        self.assertEqual(self.run_action("apply", self.evidence)[1]["status"], "prior_intent_requires_reconciliation")
        packet, withdrawn = self.run_action("withdraw", applied)
        self.assertEqual(withdrawn["status"], "withdrawn_verified", withdrawn)
        self.assertEqual(bridge_contract.accept_success(payload.canonical(withdrawn), 0, self.snapshot, self.snapshot,
                                                       packet["authority"], packet["authority_sha256"]), withdrawn)
        self.assertFalse(self.rule.exists())
        self.assertEqual(foreign.read_bytes(), b"preserve it\n")
        self.assertEqual(self.run_action("withdraw", applied)[1]["status"], "prior_intent_requires_reconciliation")

    def test_foreign_identical_bytes_cannot_be_withdrawn(self):
        _, applied = self.run_action("apply", self.evidence)
        self.assertEqual(applied["status"], "applied_verified", applied)
        replacement = self.conf / "replacement"
        replacement.write_bytes(payload.RULE)
        replacement.chmod(0o644)
        os.replace(replacement, self.rule)
        _, blocked = self.run_action("withdraw", applied)
        self.assertEqual(blocked["error"], "kmod_withdraw_state_drift")
        self.assertEqual(self.rule.read_bytes(), payload.RULE)
        self.assertFalse((self.journal / "withdraw.intent.json").exists())

    def test_atomic_publication_does_not_overwrite_an_existing_destination(self):
        self.rule.write_bytes(b"foreign content\n")
        with self.assertRaises(FileExistsError):
            payload.install_rule()
        self.assertEqual(self.rule.read_bytes(), b"foreign content\n")
        self.assertEqual(list(self.conf.iterdir()), [self.rule])

    def test_failed_postcheck_preserves_intent_and_guard_against_replay(self):
        with patch.object(payload, "live_report", side_effect=[self.before, self.before, self.before]):
            _, outcome = self.run_action("apply", self.evidence)
        self.assertEqual(outcome["status"], "apply_outcome_unknown_reconcile")
        self.assertTrue((self.journal / "apply.intent.json").exists())
        self.assertFalse((self.journal / "apply.receipt.json").exists())
        self.assertEqual(self.rule.read_bytes(), payload.RULE)
        self.assertEqual(self.run_action("apply", self.evidence)[1]["status"], "prior_intent_requires_reconciliation")


if __name__ == "__main__":
    unittest.main()
