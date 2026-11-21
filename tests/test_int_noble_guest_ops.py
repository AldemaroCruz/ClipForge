"""Directed regressions for Noble's package, serial and human-access operators."""
import base64
from contextlib import ExitStack, contextmanager
import os
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from scripts import int_noble_guest_apt as apt
from scripts import int_noble_guest_kernel_recovery as kernel_recovery
from scripts import int_noble_human_access as human
from scripts import int_noble_serial_recovery as serial


SIMULATED = ("exited", 0, "1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
             "Inst linux-tools-common [6.8.0-149.149] (6.8.0-151.151 local-deb [all])\n"
             "Conf linux-tools-common (6.8.0-151.151 local-deb [all])\n", "")
VALUE = {"operation_id": "reviewed-noble-operation", "approved_commit": "a" * 40, "owner_decision_sha256": "b" * 64}
OTHER = "c" * 64
OLD = (apt.apt_checks.CURRENT, OTHER)
NEW = (apt.apt_checks.TARGET, OTHER)
HOST_KEY = (b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + b"a" * 32)
PUBLIC, KEY_SHA, FINGERPRINT = human.key_line(b"ssh-ed25519 " + base64.b64encode(HOST_KEY) + b" comment\n")


@contextmanager
def disposable_apt_scratch(_package):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / apt.DEB
        path.write_bytes(b"synthetic fixture")
        yield path, {"APT_CONFIG": "fixture"}


class AptTests(unittest.TestCase):
    def test_bound_request_rejects_historical_disk(self):
        operator = "e" * 64
        complete = {**VALUE, "schema": apt.INPUT, "operation": "upgrade_reviewed_linux_tools_common_once",
                    "instance_id": apt.INSTANCE, "boot_disk_id": apt.BOOT_DISK, "data_disk_id": apt.DATA_DISK,
                    "boot_id": apt.GUEST_BOOT, "readiness_sha256": apt.READINESS, "operator_sha256": operator,
                    "signed_index_sha256": apt.SIGNED_INDEX, "package_sha256": apt.DIGEST}
        self.assertEqual(apt.request(apt.canonical(complete), operator), complete)
        with self.assertRaisesRegex(apt.Blocked, "input_scope"):
            apt.request(apt.canonical({**complete, "data_disk_id": "6427691858848206684"}), operator)

    def test_exact_plan_before_one_write_and_audit(self):
        intent, terminal = Mock(), Mock()
        def native(argv, **kwargs):
            self.assertEqual(kwargs["environment"], {"APT_CONFIG": "fixture"})
            if "-s" in argv:
                self.assertIn("--only-upgrade", argv)
                self.assertIn("--no-download", argv)
                intent.assert_not_called()
                return SIMULATED
            intent.assert_called_once()
            self.assertEqual(argv[:2], ["/usr/bin/dpkg", "--install"])
            self.assertEqual(len(argv), 3)
            return "exited", 0, "", ""
        with (patch.object(apt, "guest_identity") as checked, patch.object(apt.os.path, "lexists", return_value=False),
              patch.object(apt, "observed_packages", side_effect=[OLD, OLD, NEW]), patch.object(apt, "package_bytes"),
              patch.object(apt, "apt_scratch", disposable_apt_scratch), patch.object(apt, "save_intent", intent),
              patch.object(apt, "save_record", terminal),
              patch.object(apt, "DIGEST", apt.sha256(b"synthetic fixture").hexdigest()),
              patch.object(apt.apt_checks, "run_diagnostic", side_effect=native) as runner):
            receipt = apt.execute(VALUE)
        self.assertEqual(receipt["status"], "updated_exact_package")
        self.assertTrue(receipt["temp_released"])
        self.assertTrue(receipt["postcheck"]["other_package_states_equal"])
        self.assertEqual(intent.call_args.args[0]["other_package_states_sha256"], OTHER)
        self.assertEqual(receipt["postcheck"]["other_package_states_sha256"], OTHER)
        self.assertEqual(receipt["intent_sha256"], apt.sha256(apt.canonical(intent.call_args.args[0]) + b"\n").hexdigest())
        terminal.assert_called_once_with(apt.RECEIPT, receipt)
        self.assertEqual(checked.call_count, 2)
        self.assertEqual(runner.call_count, 2)

    def test_scope_mismatch_and_replay_never_install(self):
        with (patch.object(apt, "guest_identity"), patch.object(apt.os.path, "lexists", side_effect=[False, False, True]),
              patch.object(apt, "observed_packages", return_value=OLD), patch.object(apt, "package_bytes") as fetch,
              patch.object(apt, "apt_scratch", disposable_apt_scratch), patch.object(apt, "save_intent") as intent,
              patch.object(apt.apt_checks, "run_diagnostic", return_value=("exited", 0, SIMULATED[2] + "Remv other\n", "")) as run):
            self.assertEqual(apt.execute(VALUE)["error"], "apt_scope_not_exact")
            self.assertEqual(apt.execute(VALUE)["error"], "apt_intent_exists_reconcile")
        fetch.assert_called_once()
        intent.assert_not_called()
        run.assert_called_once()

    def test_uncertain_native_exit_is_not_success_and_leaves_receipt(self):
        with (patch.object(apt, "guest_identity"), patch.object(apt.os.path, "lexists", return_value=False),
              patch.object(apt, "observed_packages", return_value=OLD), patch.object(apt, "package_bytes"),
              patch.object(apt, "apt_scratch", disposable_apt_scratch), patch.object(apt, "save_intent"),
              patch.object(apt, "DIGEST", apt.sha256(b"synthetic fixture").hexdigest()),
              patch.object(apt.apt_checks, "run_diagnostic", side_effect=[SIMULATED, ("timeout", None, "", "")])):
            receipt = apt.execute(VALUE)
        self.assertEqual(receipt["status"], "install_outcome_unknown_reconcile")
        self.assertTrue(receipt["launch_intent"])
        self.assertTrue(receipt["temp_released"])

    def test_lost_terminal_write_keeps_intent_and_refuses_replay(self):
        intent = Mock()
        with (patch.object(apt, "guest_identity"), patch.object(apt.os.path, "lexists", side_effect=[False, False, True]),
              patch.object(apt, "observed_packages", side_effect=[OLD, OLD, NEW]), patch.object(apt, "package_bytes"),
              patch.object(apt, "apt_scratch", disposable_apt_scratch), patch.object(apt, "save_intent", intent),
              patch.object(apt, "save_record", side_effect=OSError("fixture terminal write lost")),
              patch.object(apt, "DIGEST", apt.sha256(b"synthetic fixture").hexdigest()),
              patch.object(apt.apt_checks, "run_diagnostic", side_effect=[SIMULATED, ("exited", 0, "", "")]) as native):
            outcome = apt.execute(VALUE)
            replay = apt.execute(VALUE)
        self.assertEqual(outcome["status"], "install_outcome_unknown_reconcile")
        self.assertEqual(outcome["error"], "OSError")
        self.assertEqual(replay["error"], "apt_intent_exists_reconcile")
        self.assertEqual(intent.call_args.args[0]["other_package_states_sha256"], OTHER)
        self.assertEqual(native.call_count, 2)


class HumanTests(unittest.TestCase):
    def test_rejects_malformed_or_multiple_public_keys(self):
        bad_blob = b"\x00\x00\x00\x07ssh-rsa" + b"x" * 50
        with self.assertRaises(human.Blocked):
            human.key_line(b"ssh-ed25519 " + base64.b64encode(bad_blob))
        with self.assertRaises(human.Blocked):
            human.key_line((PUBLIC + "\n" + PUBLIC).encode())

    def test_existing_profile_key_is_never_updated(self):
        profile = {"name": "users/owner-1", "sshPublicKeys": {"google-verified-fingerprint": {"key": PUBLIC}}}
        client = Mock()
        with patch.object(human, "preflight", return_value=({}, profile)):
            with self.assertRaisesRegex(human.Blocked, "already_present"):
                human.register(client, Path("intent"), PUBLIC, KEY_SHA, "b" * 64)
        client.request.assert_not_called()

    def test_refuses_unreviewed_resource_before_network_io(self):
        with patch.object(human, "build_opener") as transport:
            with self.assertRaisesRegex(human.Blocked, "unreviewed_api"):
                human.Client("fixture-token").request("POST", human.VM_ROUTE.replace("noble", "legacy") + "/testIamPermissions", {})
        transport.assert_not_called()

    def test_remove_only_the_returned_owned_fingerprint_and_verify_absence(self):
        client = Mock()
        with patch.object(human, "owned_key", side_effect=[("fingerprint/original", "123"), None]):
            result = human.remove(client, Path("intent"), KEY_SHA, "b" * 64)
        self.assertEqual(result["status"], "owned_key_removed_absence_verified")
        client.request.assert_called_once_with("DELETE", human.PROFILE + "/sshPublicKeys/fingerprint%2Foriginal")

    def test_prefers_connection_outcome_only_after_the_approved_key(self):
        raw = b"Server accepts key: " + FINGERPRINT.encode() + b"\nAuthenticated to exact using publickey.\n"
        refused = b"channel 0: open failed: connect failed: Connection refused\n"
        denied = b"channel 0: open failed: administratively prohibited: open failed\n"
        with (patch.object(human, "scoped_json", return_value=b"known pin"), patch.object(human, "NOBLE_PIN", human.sha(b"known pin")),
              patch.object(Path, "is_file", return_value=True), patch.object(Path, "is_symlink", return_value=False),
              patch.object(human.subprocess, "run", side_effect=[Mock(stderr=raw + refused, returncode=255),
                           Mock(stderr=raw + denied, returncode=255), Mock(stderr=refused, returncode=255)]) as command):
            self.assertEqual(human.ssh_probe("ssh.exe", "gcloud.cmd", Path("identity"), Path("known"), FINGERPRINT)["status"],
                             "forwarding_allowed_target_not_listening")
            self.assertEqual(human.ssh_probe("ssh.exe", "gcloud.cmd", Path("identity"), Path("known"), FINGERPRINT)["status"],
                             "forwarding_denied")
            self.assertEqual(human.ssh_probe("ssh.exe", "gcloud.cmd", Path("identity"), Path("known"), FINGERPRINT)["status"],
                             "human_forwarding_indeterminate")
        argv = command.call_args.args[0]
        self.assertEqual(argv[argv.index("-W") + 1], "127.0.0.1:5432")
        self.assertIn("StrictHostKeyChecking=yes", argv)


class SerialTests(unittest.TestCase):
    def test_cas_body_changes_only_the_serial_port(self):
        client = Mock()
        foreign = [{"key": "startup-script", "value": "fixture original bytes"}]
        with (patch.object(serial, "wait_operation", return_value="operation-exact"), patch.object(human, "checked_target"),
              patch.object(serial, "metadata", return_value=("verified", "TRUE", foreign))):
            self.assertEqual(serial.update(client, "bound-etag", foreign, "TRUE", "id"), "operation-exact")
        client.request.assert_called_once_with("POST", human.VM_ROUTE + "/setMetadata?requestId=id",
                                               {"fingerprint": "bound-etag", "items": [*foreign, {"key": "serial-port-enable", "value": "TRUE"}]})

    def test_restore_zero_writes_if_already_disabled(self):
        client = Mock()
        with patch.object(serial, "owned_state", return_value=("etag", "FALSE", [])):
            self.assertEqual(serial.restore(client, Path("intent"), "b" * 64)["status"], "serial_disabled_verified")
        client.request.assert_not_called()

    def test_foreign_policy_drift_blocks_restore(self):
        client = Mock()
        row = {"schema": serial.SERIAL_INTENT, "authorization_sha256": "b" * 64, "instance_id": human.INSTANCE_ID,
               "original_value": "FALSE", "enabled_value": "TRUE", "other_metadata_sha256": human.sha(human.canonical([]))}
        with (patch.object(human, "scoped_json", return_value=human.canonical(row)), patch.object(serial, "guard"),
              patch.object(serial, "metadata", return_value=("etag", "TRUE", [{"key": "other", "value": "drift"}]))):
            with self.assertRaisesRegex(human.Blocked, "foreign_metadata_drift"):
                serial.restore(client, Path("intent"), "b" * 64)
        client.request.assert_not_called()

    def test_serial_transport_is_distinct_from_iap_and_has_pinned_port(self):
        argv = serial.serial_argv("ssh.exe", Path("known"), Path("private"))
        self.assertEqual(argv[argv.index("-p") + 1], "9600")
        self.assertEqual(argv[-1], "us-central1-ssh-serialport.googleapis.com")
        self.assertIn("clipforgebeta2.us-central1-a.clipforge-int-db01-noble.admin_ixbalam_studio.port=1.replay-lines=40", argv)
        self.assertIn("StrictHostKeyChecking=yes", argv)
        self.assertNotIn("-L", argv)


class RecoveryTests(unittest.TestCase):
    def test_refuses_shared_grub_or_drop_in_drift_before_restoration(self):
        candidate = {"operation_id": "reviewed-noble-operation"}
        record = {"operation_id": candidate["operation_id"], "owner_decision_sha256": "b" * 64,
                  "original_boot_id": apt.GUEST_BOOT, "drop_ins_originally_absent": True,
                  "original_cfg_mode": 0o644, "original_cfg_sha256": kernel_recovery.BASELINE_CFG}
        with (patch.object(apt, "guest_identity", return_value="other-boot"),
              patch.object(Path, "lstat", return_value=Mock(st_mode=0o40700, st_uid=0)),
              patch.object(kernel_recovery, "file_bytes", side_effect=[(apt.canonical(record), 0o600),
                           (b"original", 0o644), (b"foreign-change", 0o644)]),
              patch.object(kernel_recovery, "write_exclusive") as write):
            with self.assertRaisesRegex(apt.Blocked, "grub_drift"):
                kernel_recovery.restore(candidate, "b" * 64, "d" * 64)
        write.assert_not_called()

    @unittest.skipUnless(os.name == "posix", "boot-file restoration uses POSIX filesystem operations")
    def test_capture_and_restore_exact_files_without_rewriting_the_environment(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            backups = root / "backups"
            grub, env, drop = (root / name for name in ("grub.cfg", "grubenv", "kmod.conf"))
            base, rendered, drop_in = b"original fixture grub", b"rendered fixture grub", b"owned fixture drop-in"
            grub.write_bytes(base)
            env.write_bytes(b"e" * 1024)
            candidate = {"operation_id": "reviewed-noble-operation"}
            with ExitStack() as fixtures:
                fixtures.enter_context(patch.object(apt, "guest_identity", side_effect=[apt.GUEST_BOOT, "new-boot-fixture"]))
                fixtures.enter_context(patch.multiple(kernel_recovery, BOOT_CFG=grub, BOOT_ENV=env, RECOVERY=backups,
                                                      BASELINE_CFG=kernel_recovery.digest(base),
                                                      EXACT_DROP_INS={drop: kernel_recovery.digest(drop_in)}))
                owner = root.stat()
                if (owner.st_uid, owner.st_gid) != (0, 0):
                    def root_owned(info):
                        self.assertEqual((info.st_uid, info.st_gid), (owner.st_uid, owner.st_gid))
                        fields = list(info)
                        fields[4:6] = (0, 0)
                        return os.stat_result(fields)

                    # The non-root fixture presents root ownership only to the recovery checks.
                    # Files, byte comparisons, exclusive opens, chmod, fsync and replacement stay real.
                    recovery_os = SimpleNamespace(**vars(os))
                    recovery_os.fstat = lambda fd: root_owned(os.fstat(fd))
                    real_lstat = Path.lstat

                    def owned_backup_lstat(path, *args, **options):
                        info = real_lstat(path, *args, **options)
                        return root_owned(info) if path == backups else info

                    fixtures.enter_context(patch.object(kernel_recovery, "os", recovery_os))
                    fixtures.enter_context(patch.object(Path, "lstat", owned_backup_lstat))
                self.assertEqual(kernel_recovery.capture(candidate, "b" * 64)["status"], "original_boot_files_preserved")
                grub.write_bytes(rendered)
                env.write_bytes(b"f" * 1024)
                drop.write_bytes(drop_in)
                receipt = kernel_recovery.restore(candidate, "b" * 64, kernel_recovery.digest(rendered))
            self.assertFalse(receipt["bootstrap_authorized"])
            self.assertEqual(grub.read_bytes(), base)
            self.assertEqual(env.read_bytes(), b"f" * 1024)
            self.assertFalse(drop.exists())


if __name__ == "__main__":
    unittest.main()
