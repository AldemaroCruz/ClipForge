"""DB-01 authored fixtures, private temporary files and mocked native processes.

No VM, block device, SQL server, cloud, SSH or privileged container is used.
"""
from contextlib import ExitStack
import copy
from datetime import datetime, timedelta, timezone
import io
import json
from pathlib import Path
import stat
import tempfile
import threading
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import int_bootstrap_vm as vm
REAL_POPEN = vm.subprocess.Popen


SOURCE = "a" * 64
NOW = datetime(2026, 11, 19, 1, 0, tzinfo=timezone.utc)
BOOT = "12345678-1234-1234-1234-123456789abc"
UUID = "87654321-4321-4321-4321-cba987654321"


def input_value():
    graphic = "".join(chr(65 + index % 26) for index in range(48))
    certificate = "-----BEGIN CERTIFICATE-----\nfixture-not-a-real-certificate\n-----END CERTIFICATE-----\n"
    return {"schema": "clipforge-db01-bootstrap-input-1", "operation_id": "b" * 32, "approved_commit": "c" * 40,
            "proposal_sha256": "d" * 64, "operator_sha256": SOURCE, "confirmation": "INITIALIZE_NEW_DISK_" + vm.DISK_ID,
            "disk_proof": {"project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a",
                "instance_id": vm.INSTANCE_ID, "boot_timestamp": (NOW - timedelta(hours=1)).isoformat(),
                "disk_id": vm.DISK_ID, "disk_name": "clipforge-int-base-postgres-data", "device_name": "clipforge-pg-data",
                "size_bytes": vm.SIZE_BYTES, "disk_type": "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard", "interface": "SCSI", "index": 1, "mode": "READ_WRITE",
                "boot": False, "auto_delete": False, "observed_utc": NOW.isoformat(), "guest_major_minor": "8:16",
                "guest_serial": "authored-disk-serial", "guest_by_id": vm.DEVICE, "guest_read_receipt_sha256": "e" * 64,
                "guest_read_source_sha256": "f" * 64, "guest_boot_id": BOOT},
            "secrets": {"app_password": graphic, "migrator_password": graphic[::-1], "server_cert": certificate,
                "ca_cert": certificate, "server_key": "-----BEGIN PRIVATE KEY-----\nfixture-not-a-key\n-----END PRIVATE KEY-----\n"}}


def native_row(operation, raw=b"", *, status="ok", exit_code=0):
    return {"operation": operation, "exit_code": exit_code, "status": status, "duration_ms": 1,
            "stdout_bytes": len(raw), "stderr_bytes": 0, "messages": [], "unclassified_stderr_lines": 0}


class GuestBootstrap(unittest.TestCase):
    def setUp(self):
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        temporary = self.stack.enter_context(tempfile.TemporaryDirectory(prefix="clipforge-db01-unit-"))
        self.root = Path(temporary)
        self.stack.enter_context(mock.patch.object(vm, "ROOT", self.root))
        self.stack.enter_context(mock.patch.object(vm, "JOURNAL_DIR", self.root / "db01"))
        self.stack.enter_context(mock.patch.object(vm, "build_opener", side_effect=AssertionError("network forbidden")))
        self.stack.enter_context(mock.patch.object(vm.subprocess, "Popen", side_effect=AssertionError("native processes forbidden")))

    def operator(self, runner=None):
        return vm.Operator(input_value(), SOURCE, runner=runner or mock.Mock(side_effect=AssertionError("unexpected command")), now=lambda: NOW)

    def fixture_files(self):
        # Windows boundary mocks only; actual x/create/replace/fsync file I/O remains.
        self.stack.enter_context(mock.patch.object(vm, "_parents"))
        self.stack.enter_context(mock.patch.object(vm, "read_bytes", side_effect=lambda path, *args, **kwargs: Path(path).read_bytes()))
        self.stack.enter_context(mock.patch.object(vm, "_fsync_dir"))
        self.stack.enter_context(mock.patch.object(vm.os, "fchown", create=True))
        self.stack.enter_context(mock.patch.object(vm.os, "fchmod", create=True))

    def test_closed_input_exact_target_and_observed_proof(self):
        value = input_value()
        self.assertIs(vm.validate_input(value, SOURCE, now=NOW), value)
        variants = [
            lambda x: x.update(extra="private"),
            lambda x: x.update(operator_sha256="f" * 64),
            lambda x: x["disk_proof"].update(disk_id="1"),
            lambda x: x["disk_proof"].update(size_bytes=vm.SIZE_BYTES + 1),
            lambda x: x["disk_proof"].update(index=True),
            lambda x: x["disk_proof"].update(disk_type="pd-standard"),
            lambda x: x["disk_proof"].update(auto_delete=True),
            lambda x: x["disk_proof"].update(guest_major_minor=None),
            lambda x: x["disk_proof"].update(guest_serial=""),
            lambda x: x["disk_proof"].update(guest_by_id="/dev/sdb"),
            lambda x: x["disk_proof"].update(guest_read_receipt_sha256="pending"),
            lambda x: x["disk_proof"].update(observed_utc=(NOW - timedelta(seconds=301)).isoformat()),
            lambda x: x["disk_proof"].update(observed_utc=(NOW + timedelta(seconds=1)).isoformat()),
            lambda x: x["secrets"].update(app_password=x["secrets"]["migrator_password"]),
            lambda x: x["secrets"].update(ca_cert=x["secrets"]["ca_cert"] + x["secrets"]["server_key"] + x["secrets"]["ca_cert"]),
        ]
        for mutate in variants:
            row = copy.deepcopy(value)
            mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(vm.Blocked):
                vm.validate_input(row, SOURCE, now=NOW)

    def test_duplicate_or_oversized_json_never_becomes_input(self):
        for raw in (b'{"schema":1,"schema":2}', b"x" * (vm.INPUT_LIMIT + 1), b"[]"):
            with self.subTest(raw_length=len(raw)), self.assertRaises(vm.Blocked):
                value = vm.decode(raw)
                vm.validate_input(value, SOURCE, now=NOW)

    def test_any_signature_filesystem_partition_or_mount_blocks(self):
        blank = {"blockdevices": [{"type": "disk", "fstype": None, "children": [], "mountpoints": []}]}
        vm.blank_disk_contract(vm.DISK_ID, "INITIALIZE_NEW_DISK_" + vm.DISK_ID, [], blank)
        for key, item in (("fstype", "ext4"), ("children", [{"name": "partition"}]), ("mountpoints", ["/"])):
            row = copy.deepcopy(blank)
            row["blockdevices"][0][key] = item
            with self.subTest(key=key), self.assertRaises(vm.Blocked):
                vm.blank_disk_contract(vm.DISK_ID, "INITIALIZE_NEW_DISK_" + vm.DISK_ID, [], row)
        with self.assertRaises(vm.Blocked):
            vm.blank_disk_contract(vm.DISK_ID, "INITIALIZE_NEW_DISK_" + vm.DISK_ID, [{"type": "ext4"}], blank)

    def test_tls_checks_seven_day_ca_leaf_ip_chain_and_pair_before_journal(self):
        self.fixture_files()
        seen = []
        def runner(operation, argv, payload, timeout):
            seen.append((operation, argv))
            raw = b"authored-public-key" if operation in {"tls_cert_public", "tls_key_public"} else b""
            return raw, native_row(operation, raw)
        operator = self.operator(runner)
        operator.tls()
        self.assertTrue(operator.receipt["checks"]["tls_inputs_verified"])
        self.assertEqual([item[0] for item in seen], ["tls_chain", "tls_leaf_lifetime", "tls_ca_lifetime", "tls_ip", "tls_cert_public", "tls_key_public"])
        self.assertTrue(all(str(604800) in argv for operation, argv in seen if operation.endswith("lifetime")))
        self.assertIn("sslserver", seen[0][1])
        self.assertFalse((self.root / "db01").exists())
        self.assertEqual(list(self.root.iterdir()), [])

    def test_invalid_tls_native_exit_stops_and_private_temporaries_removed(self):
        self.fixture_files()
        calls = []
        def runner(operation, argv, payload, timeout):
            calls.append(operation)
            return b"", native_row(operation, status="nonzero_exit", exit_code=1)
        operator = self.operator(runner)
        with self.assertRaises(vm.NativeFailure):
            operator.tls()
        self.assertEqual(calls, ["tls_chain"])
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertFalse(operator.receipt["checks"]["tls_inputs_verified"])

    def test_tls_mismatched_public_keys_never_mark_verified(self):
        self.fixture_files()
        def runner(operation, argv, payload, timeout):
            raw = operation.encode() if operation in {"tls_cert_public", "tls_key_public"} else b""
            return raw, native_row(operation, raw)
        operator = self.operator(runner)
        with self.assertRaisesRegex(vm.Blocked, "key_pair"):
            operator.tls()
        self.assertFalse(operator.receipt["checks"]["tls_inputs_verified"])

    def test_atomic_fstab_keeps_foreign_lines_and_refuses_changed_preimage(self):
        self.fixture_files()
        path = self.root / "fstab"
        initial = b"# authored unrelated mount\nUUID=foreign /srv/other ext4 defaults 0 2\n"
        path.write_bytes(initial)
        successor = initial + b"UUID=own /srv/own ext4 nodev,nosuid,noexec 0 2\n"
        vm.atomic_file(path, successor, expected=initial)
        self.assertEqual(path.read_bytes(), successor)
        path.write_bytes(successor + b"# later foreign edit\n")
        with self.assertRaisesRegex(vm.Blocked, "changed_concurrently"):
            vm.atomic_file(path, initial, expected=successor)
        self.assertTrue(path.read_bytes().endswith(b"# later foreign edit\n"))

    def test_native_failure_receipt_preserves_exit_without_raw_output(self):
        raw = b"authored private bytes"
        operator = self.operator(lambda *args: (raw, native_row("mkfs", raw, status="nonzero_exit", exit_code=7)))
        with self.assertRaisesRegex(vm.NativeFailure, "native_mkfs_nonzero_exit"):
            operator.call("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE])
        self.assertEqual(operator.receipt["native_operations"][0]["exit_code"], 7)
        self.assertNotIn("authored private bytes", json.dumps(operator.receipt))

    def test_spawn_and_total_time_budget_fail_closed(self):
        operator = self.operator(mock.Mock(side_effect=OSError("authored-private-path")))
        with self.assertRaises(vm.NativeFailure):
            operator.call("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE])
        self.assertIsNone(operator.receipt["native_operations"][0]["exit_code"])
        self.assertNotIn("authored-private", json.dumps(operator.receipt))
        operator = self.operator()
        operator.deadline = 0
        with self.assertRaisesRegex(vm.Blocked, "time_budget"):
            operator.call("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE])
        operator.runner.assert_not_called()

    def test_journal_is_durable_before_mkfs_and_old_run_never_replays(self):
        self.fixture_files()
        calls = []
        operator = self.operator()
        for name in ("identity", "safety", "disk", "tls", "fstab_preflight"):
            self.stack.enter_context(mock.patch.object(operator, name))
        def failing_mount():
            operator.phase("mkfs_intent")
            saved = json.loads((self.root / "db01/operation.json").read_bytes())
            self.assertEqual(saved["phase"], "mkfs_intent")
            self.assertNotIn("secrets", saved)
            calls.append("sole_mkfs_attempt")
            raise vm.NativeFailure("native_mkfs_timeout")
        self.stack.enter_context(mock.patch.object(operator, "mount", side_effect=failing_mount))
        self.stack.enter_context(mock.patch.object(vm.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(vm.os, "geteuid", return_value=0, create=True))
        result = operator.run()
        self.assertEqual((result["status"], result["exit_code"], result["phase"]), ("partial_preserved", 3, "mkfs_intent"))
        self.assertEqual(calls, ["sole_mkfs_attempt"])
        original = (self.root / "db01/operation.json").read_bytes()
        second = self.operator()
        for name in ("identity", "safety", "disk", "tls", "fstab_preflight", "mount"):
            self.stack.enter_context(mock.patch.object(second, name))
        repeat = second.run()
        self.assertEqual(repeat["error_code"], "prior_operation_blocks_retry")
        second.mount.assert_not_called()
        self.assertEqual((self.root / "db01/operation.json").read_bytes(), original)

    def test_invalid_tls_never_creates_journal_or_calls_mkfs(self):
        operator = self.operator()
        self.stack.enter_context(mock.patch.object(vm.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(vm.os, "geteuid", return_value=0, create=True))
        for name in ("identity", "safety", "disk", "mount"):
            self.stack.enter_context(mock.patch.object(operator, name))
        self.stack.enter_context(mock.patch.object(operator, "tls", side_effect=vm.Blocked("tls_key_pair_mismatch")))
        result = operator.run()
        self.assertEqual((result["status"], result["exit_code"]), ("blocked", 2))
        self.assertFalse((self.root / "db01").exists())
        operator.mount.assert_not_called()

    def test_success_receipt_cannot_omit_checks_or_claim_external_acceptance(self):
        operator = self.operator()
        receipt = operator.receipt
        receipt["finished_utc"] = receipt["started_utc"]
        vm.validate_receipt(receipt)
        for mutate in (lambda r: r.update(exit_code=False), lambda r: r["flags"].update(runtime_authorized=True),
                       lambda r: r.update(private="sentinel"), lambda r: r.update(status="configured_guest_verified_external_acceptance_pending", exit_code=0)):
            row = copy.deepcopy(receipt)
            mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(vm.Blocked):
                vm.validate_receipt(row)

    def disk_case(self, *, serial=None, sectors=None, holders=(), root_on_target=False, mounted=False, signatures=None,
                  sysfs_missing=False, sysfs_denied=False, lsblk_serial="authored-disk-serial", udev_serial="authored-disk-serial"):
        rows = {"mounts": {"filesystems": [{"target": "/", "maj:min": "8:1"}]},
                "lsblk": {"blockdevices": [{"name": "sdb", "kname": "sdb", "type": "disk", "size": vm.SIZE_BYTES,
                                            "fstype": None, "mountpoints": [], "maj:min": "8:16", "serial": lsblk_serial}]},
                "wipefs": {"signatures": [] if signatures is None else signatures},
                "udev": b"DEVTYPE=disk\n" + (b"" if udev_serial is None else ("ID_SERIAL_SHORT=" + udev_serial + "\n").encode())}
        if mounted:
            rows["mounts"]["filesystems"].append({"target": "/unrelated/existing", "maj:min": "8:16"})
        calls = []
        def runner(operation, argv, payload, timeout):
            calls.append(operation)
            raw = rows[operation] if operation == "udev" else vm.canonical(rows[operation])
            return raw, native_row(operation, raw)
        operator = self.operator(runner)
        def lstat(path):
            mode = stat.S_IFLNK | 0o777 if str(path).replace("\\", "/") == vm.DEVICE else stat.S_IFDIR | 0o755
            return SimpleNamespace(st_mode=mode, st_uid=0)
        def open_metadata(path, *args, **kwargs):
            if path.name == "serial":
                if sysfs_missing:
                    raise FileNotFoundError("authored missing sysfs serial")
                if sysfs_denied:
                    raise PermissionError("authored unreadable sysfs serial")
                return io.BytesIO((serial if serial is not None else "authored-disk-serial").encode())
            if path.name == "size":
                return io.BytesIO((sectors if sectors is not None else str(vm.SIZE_BYTES // 512)).encode())
            raise AssertionError("unexpected file read")
        def realpath(path):
            normalized = str(path).replace("\\", "/")
            if normalized == vm.DEVICE:
                return "/dev/sdb"
            if normalized.endswith("/8:1"):
                return "/sys/devices/author/block/sdb/sdb1" if root_on_target else "/sys/devices/author/block/sda/sda1"
            if normalized.endswith("/8:16"):
                return "/sys/devices/author/block/sdb"
            raise AssertionError("unexpected path resolution")
        scan = mock.MagicMock()
        scan.__enter__.return_value = iter(holders)
        with mock.patch.object(Path, "lstat", lstat), mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_mode=stat.S_IFBLK, st_rdev=123)), \
             mock.patch.object(Path, "open", open_metadata), mock.patch.object(vm.os, "major", return_value=8, create=True), \
             mock.patch.object(vm.os, "minor", return_value=16, create=True), mock.patch.object(vm.os, "scandir", return_value=scan), \
             mock.patch.object(vm.os.path, "realpath", side_effect=realpath):
            operator.disk()
        return operator, calls

    def test_disk_correlates_observed_serial_major_size_and_native_blank_metadata(self):
        operator, calls = self.disk_case()
        self.assertEqual(calls, ["mounts", "lsblk", "udev", "wipefs"])
        self.assertTrue(operator.receipt["checks"]["disk_blank_verified"])

    def test_disk_stops_on_serial_size_holders_root_mount_or_signatures(self):
        for kwargs, code in (({"serial": "foreign-disk"}, "serial_or_size"), ({"sectors": "1"}, "serial_or_size"),
                             ({"holders": ["holder"]}, "has_holders"), ({"root_on_target": True}, "root_disk"),
                             ({"mounted": True}, "device_mounted"), ({"signatures": [{"type": "ext4"}]}, "signatures_present")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(vm.Blocked, code):
                self.disk_case(**kwargs)

    def test_serial_fallback_is_explicit_and_disagreement_or_access_denial_blocks(self):
        for kwargs in ({"sysfs_missing": True}, {"sysfs_missing": True, "lsblk_serial": None},
                       {"sysfs_missing": True, "udev_serial": None}):
            with self.subTest(kwargs=kwargs):
                self.assertTrue(self.disk_case(**kwargs)[0].receipt["checks"]["disk_blank_verified"])
        for kwargs in ({"sysfs_missing": True, "lsblk_serial": None, "udev_serial": None},
                       {"udev_serial": "Google_prefixed_foreign"}, {"lsblk_serial": "different-serial"}):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(vm.Blocked, "serial_or_size"):
                self.disk_case(**kwargs)
        with self.assertRaises(PermissionError):
            self.disk_case(sysfs_denied=True)

    def test_mount_verification_requires_exact_uuid_device_target_and_options(self):
        row = {"uuid": UUID, "target": str(vm.MOUNT), "source": "/dev/sdb", "fstype": "ext4",
               "options": "rw,nodev,nosuid,noexec,relatime", "maj:min": "8:16"}
        def attempt(item):
            raw = vm.canonical({"filesystems": [item]})
            operator = self.operator(lambda *args: (raw, native_row("mounted", raw)))
            operator.filesystem_uuid = UUID
            with mock.patch.object(Path, "stat", return_value=SimpleNamespace(st_rdev=123)):
                operator.verify_mount()
            return operator
        self.assertTrue(attempt(row).receipt["checks"]["mount_verified"])
        for key, item in (("uuid", BOOT), ("target", "/"), ("maj:min", "8:0"), ("fstype", "xfs"), ("options", "rw,nodev,nosuid")):
            wrong = {**row, key: item}
            with self.subTest(key=key), self.assertRaises(vm.Blocked):
                attempt(wrong)

    def test_receipt_success_requires_exact_native_trace_and_not_only_true_flags(self):
        receipt = self.operator().receipt
        receipt.update(status="configured_guest_verified_external_acceptance_pending", exit_code=0, phase="guest_verified",
                       operation_id="b" * 32, approved_commit="c" * 40, proposal_sha256="d" * 64,
                       guest_boot_id=BOOT, journal_path=str(vm.JOURNAL_DIR / "operation.json"), journal_sha256="e" * 64,
                       filesystem_uuid=UUID, fstab_before_sha256="f" * 64, fstab_after_sha256="1" * 64,
                       disk_proof_sha256="3" * 64, guest_read_receipt_sha256="4" * 64, guest_read_source_sha256="5" * 64,
                       effective_config_sha256="2" * 64, finished_utc=receipt["started_utc"],
                       parent_permissions_before={"uid": 0, "gid": 0, "mode": "0700"},
                       parent_permissions_after={"uid": 0, "gid": 106, "mode": "0710"},
                       checks={key: True for key in vm.CHECK_KEYS},
                       native_operations=[native_row(operation) for operation in vm.SUCCESS_OPERATIONS])
        vm.validate_receipt(receipt)
        for mutate in (lambda r: r.update(native_operations=[]), lambda r: r["native_operations"].pop(0),
                       lambda r: r["native_operations"].reverse(), lambda r: r["native_operations"][0].update(exit_code=False),
                       lambda r: r["native_operations"][0].update(status="nonzero_exit", exit_code=5)):
            row = copy.deepcopy(receipt)
            mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(vm.Blocked):
                vm.validate_receipt(row)

    def fake_native(self, chunks, *, timeout=False, exit_code=0, interrupt_after_reads=None, capture_interrupt=False):
        reads = [0]
        class Stream:
            def __init__(self, number):
                self.number, self.closed = number, False
            def fileno(self):
                return self.number
            def close(self):
                self.closed = True
        class Selector:
            def __init__(self):
                self.rows = {}
            def register(self, stream, events, label):
                self.rows[stream] = SimpleNamespace(fileobj=stream, data=label)
            def unregister(self, stream):
                del self.rows[stream]
            def get_map(self):
                return self.rows
            def select(self, timeout):
                if interrupt_after_reads is not None and reads[0] >= interrupt_after_reads:
                    raise vm.Blocked("operator_interrupted")
                return [(next(iter(self.rows.values())), 1)]
            def close(self):
                self.rows.clear()
        process = SimpleNamespace(pid=123456, stdout=Stream(10), stderr=Stream(11), stdin=None,
                                  poll=lambda: None if timeout or interrupt_after_reads is not None or len(chunks.get(10, [])) else exit_code,
                                  wait=mock.Mock(return_value=-9 if timeout or interrupt_after_reads is not None else exit_code),
                                  returncode=-9 if timeout or interrupt_after_reads is not None else exit_code)
        def read(number, count):
            reads[0] += 1
            sequence = chunks.get(number, [])
            return sequence.pop(0) if sequence else b""
        with mock.patch.object(vm, "_trusted_binary"), mock.patch.object(vm.subprocess, "Popen", return_value=process), \
             mock.patch.object(vm.selectors, "DefaultSelector", Selector), mock.patch.object(vm.os, "set_blocking", create=True), \
             mock.patch.object(vm.os, "read", side_effect=read), mock.patch.object(vm.signal, "SIGKILL", 9, create=True), \
             mock.patch.object(vm.os, "killpg", create=True) as kill:
            if timeout:
                with mock.patch.object(vm.time, "monotonic", side_effect=[0, 121, 121]):
                    result = vm.native("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE], None, 120)
            else:
                try:
                    result = vm.native("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE], None, 120)
                except vm.NativeInterruption as error:
                    if not capture_interrupt:
                        raise
                    result = error
            return result, kill.call_args_list

    def test_native_stdout_stderr_caps_and_timeout_stop_only_own_group(self):
        for descriptor, expected, cap in ((10, "stdout_limit", vm.OUTPUT_LIMIT), (11, "stderr_limit", vm.ERROR_LIMIT)):
            chunks = {10: [] if descriptor == 11 else [b"x" * 8192] * 9,
                      11: [b"y" * 8192] * 2 if descriptor == 11 else []}
            (raw, row), _ = self.fake_native(chunks)
            self.assertEqual(row["status"], expected)
            self.assertLessEqual(len(raw), vm.OUTPUT_LIMIT)
            self.assertLessEqual(row["stdout_bytes"], vm.OUTPUT_LIMIT)
            self.assertLessEqual(row["stderr_bytes"], vm.ERROR_LIMIT)
        (_, row), killed = self.fake_native({10: [], 11: []}, timeout=True)
        self.assertEqual(row["status"], "timeout")
        self.assertEqual(killed, [mock.call(123456, 9)])

    def test_native_stderr_preserves_only_actual_allowed_fragments_and_counts_unknown(self):
        (_, row), _ = self.fake_native({10: [], 11: [b"Permission denied authored-private-value\nunknown-private-value\n", b""]}, exit_code=7)
        self.assertEqual((row["exit_code"], row["status"]), (7, "nonzero_exit"))
        self.assertEqual(row["messages"], ["Permission denied"])
        self.assertEqual(row["unclassified_stderr_lines"], 1)
        self.assertNotIn("private-value", json.dumps(row))

    def test_signal_preserves_observed_exit_bytes_and_diagnostic_before_propagation(self):
        failure, killed = self.fake_native({10: [b"public marker\n", b""],
                                            11: [b"Permission denied private fixture\n", b""]},
                                           interrupt_after_reads=3, capture_interrupt=True)
        self.assertIsInstance(failure, vm.NativeInterruption)
        self.assertEqual(failure.native_receipt["exit_code"], -9)
        self.assertEqual(failure.native_receipt["status"], "interrupted")
        self.assertEqual(killed, [mock.call(123456, 9)])
        operator = self.operator(mock.Mock(side_effect=failure))
        with self.assertRaisesRegex(vm.Blocked, "operator_interrupted"):
            operator.call("mkfs", ["/usr/sbin/mkfs.ext4", vm.DEVICE])
        row = operator.receipt["native_operations"][0]
        self.assertEqual(row["operation"], "mkfs")
        self.assertEqual(row["stdout_bytes"], len(b"public marker\n"))
        self.assertEqual(row["stderr_bytes"], len(b"Permission denied private fixture\n"))
        self.assertEqual(row["messages"], ["Permission denied"])
        self.assertNotIn("private fixture", json.dumps(operator.receipt))

    @unittest.skipUnless(vm.sys.platform == "linux", "Real own-process SIGTERM probe requires Linux")
    def test_linux_real_sigterm_reaps_own_child_and_records_native_receipt(self):
        spawned = []
        def launch(*args, **kwargs):
            process = REAL_POPEN(*args, **kwargs)
            spawned.append(process)
            return process
        def interrupted(signum, frame):
            raise vm.Blocked("operator_interrupted")
        previous = vm.signal.signal(vm.signal.SIGTERM, interrupted)
        timer = threading.Timer(0.25, lambda: vm.os.kill(vm.os.getpid(), vm.signal.SIGTERM))
        operator = self.operator(vm.native)
        try:
            with mock.patch.object(vm.subprocess, "Popen", side_effect=launch):
                timer.start()
                with self.assertRaisesRegex(vm.Blocked, "operator_interrupted"):
                    # Fixed synthetic child only; no disk/package/SQL command.
                    operator.call("packages", ["/usr/bin/sh", "-c",
                        "printf 'public-marker\\n'; printf 'Permission denied fixture\\n' >&2; exec /usr/bin/sleep 20"])
        finally:
            timer.cancel()
            timer.join(timeout=2)
            vm.signal.signal(vm.signal.SIGTERM, previous)
        self.assertEqual(len(spawned), 1)
        self.assertEqual(spawned[0].poll(), -9)
        self.assertTrue(spawned[0].stdout.closed and spawned[0].stderr.closed)
        row = operator.receipt["native_operations"][0]
        self.assertEqual((row["status"], row["exit_code"]), ("interrupted", -9))
        self.assertEqual(row["stdout_bytes"], len(b"public-marker\n"))
        self.assertEqual(row["stderr_bytes"], len(b"Permission denied fixture\n"))
        self.assertEqual(row["messages"], ["Permission denied"])

    def postcheck_case(self, *, bad_config=False, bad_roles=False, changed_file=False, bad_handshake=False):
        config = {"version": "170012", "data_directory": str(vm.MOUNT / "pgdata"), "listen": "10.80.1.2", "port": "5432",
                  "ssl": "on", "ssl_min": "TLSv1.2", "password_encryption": "scram-sha-256",
                  "cert": str(vm.CONFIG / "server.crt"), "key": str(vm.CONFIG / "server.key"), "ca": str(vm.CONFIG / "root.crt"),
                  "encoding": "UTF8", "lc_collate": "C.UTF-8", "lc_ctype": "C.UTF-8",
                  "config_errors": 0, "hba_errors": 0}
        role_rows = [{"name": name, "login": True, "super": False, "createdb": False, "createrole": False,
                      "replication": False, "bypassrls": False, "scram": True} for name in ("clipforge_app", "clipforge_migrator")]
        roles = {"roles": role_rows, "owner": "clipforge_migrator", "app_connect": True, "app_db_create": False,
                 "app_temp": False, "app_schema_use": True, "app_schema_create": False, "migrator_schema_create": True,
                 "memberships": 0, "defaults": [{"kind": "S", "privileges": ["SELECT", "USAGE"]},
                                               {"kind": "r", "privileges": ["DELETE", "INSERT", "SELECT", "UPDATE"]}]}
        if bad_config:
            config["ssl_min"] = "TLSv1"
        if bad_roles:
            role_rows[0]["createdb"] = True
        calls = []
        outputs = {"sql_config": vm.canonical(config), "sql_role_check": vm.canonical(roles),
                   "service_active": b"active\n", "clusters": ("17 main 5432 online postgres " + str(vm.MOUNT / "pgdata") + " logfile\n").encode(),
                   "tls_handshake": b"", "enable": b"", "enabled": b"enabled\n"}
        def runner(operation, argv, payload, timeout):
            calls.append(operation)
            if operation == "sql_config":
                # Native PostgreSQL17 rejects these nonexistent GUCs. Model that
                # boundary so an authored successful JSON cannot hide the defect.
                if b"current_setting('lc_collate')" in payload or b"current_setting('lc_ctype')" in payload:
                    return b"", native_row(operation, status="nonzero_exit", exit_code=1)
            raw = outputs[operation]
            if bad_handshake and operation == "tls_handshake":
                return raw, native_row(operation, raw, status="nonzero_exit", exit_code=1)
            return raw, native_row(operation, raw)
        operator = self.operator(runner)
        operator.expected_files = {vm.CONFIG / "pg_hba.conf": b"fixed closed HBA"}
        operator.receipt["parent_permissions_after"] = {"uid": 0, "gid": 106, "mode": "0710"}
        reader = lambda path, *args, **kwargs: b"foreign changed HBA" if changed_file else (b"manual\n" if Path(path).name == "start.conf" else b"fixed closed HBA")
        with mock.patch.object(operator, "verify_mount"), mock.patch.object(vm, "read_bytes", side_effect=reader), \
             mock.patch.object(vm, "atomic_file") as writer, \
             mock.patch.object(Path, "lstat", return_value=SimpleNamespace(st_mode=stat.S_IFDIR | 0o710, st_uid=0, st_gid=106)), \
             mock.patch.object(vm, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=103, pw_gid=106))):
            operator.postchecks()
            writer.assert_called_once()
        return operator, calls

    def test_effective_guest_postchecks_require_config_roles_cluster_and_verified_tls(self):
        operator, calls = self.postcheck_case()
        self.assertEqual(calls, ["sql_config", "sql_role_check", "service_active", "clusters", "tls_handshake", "enable", "enabled"])
        for key in ("configuration_verified", "roles_verified", "local_tls_handshake_verified", "boot_persistence_configured"):
            self.assertTrue(operator.receipt["checks"][key])
        self.assertEqual(operator.receipt["flags"], vm.FLAGS)

    def test_postchecks_refuse_bad_effective_config_role_foreign_file_or_tls(self):
        for kwargs, code in (({"bad_config": True}, "configuration_mismatch"), ({"bad_roles": True}, "role_boundaries"),
                             ({"changed_file": True}, "config_files_changed"), ({"bad_handshake": True}, "tls_handshake")):
            with self.subTest(kwargs=kwargs), self.assertRaisesRegex(vm.Blocked, code):
                self.postcheck_case(**kwargs)

    def test_role_creation_keeps_plain_passwords_and_verifiers_out_of_argv_and_receipt(self):
        calls = []
        def runner(operation, argv, payload, timeout):
            calls.append((operation, argv, payload))
            return b"", native_row(operation)
        operator = self.operator(runner)
        operator.roles()
        self.assertEqual([row[0] for row in calls], ["sql_roles", "sql_database", "sql_grants"])
        self.assertIn(b"SCRAM-SHA-256$4096:", calls[0][2])
        for secret in operator.value["secrets"].values():
            self.assertNotIn(secret, json.dumps(operator.receipt))
            self.assertNotIn(secret, json.dumps([row[1] for row in calls]))
        self.assertNotIn("SCRAM-SHA-256", json.dumps(operator.receipt))
        self.assertTrue(all(row[1][0] == "/usr/sbin/runuser" for row in calls))

    def test_postgres_parent_requires_execute_only_group_without_relaxing_private_children(self):
        good = SimpleNamespace(st_mode=stat.S_IFDIR | 0o710, st_uid=0, st_gid=106)
        self.assertEqual(vm.parent_permissions(good, 106), {"uid": 0, "gid": 106, "mode": "0710"})
        for mode, owner, group in ((0o700, 0, 106), (0o750, 0, 106), (0o711, 0, 106), (0o710, 103, 106), (0o710, 0, 0)):
            with self.subTest(mode=oct(mode), owner=owner, group=group), self.assertRaises(vm.Blocked):
                vm.parent_permissions(SimpleNamespace(st_mode=stat.S_IFDIR | mode, st_uid=owner, st_gid=group), 106)
        # Its only permission operation is on ROOT; the journal remains its own0700child.
        self.fixture_files()
        operator = self.operator()
        operator.journal()
        with mock.patch.object(vm.os, "chown", create=True) as chown, mock.patch.object(vm.os, "chmod") as chmod:
            postgres = SimpleNamespace(pw_uid=103, pw_gid=106)
            states = iter([SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0), good])
            with mock.patch.object(vm, "pwd", SimpleNamespace(getpwnam=lambda name: postgres)), \
                 mock.patch.object(Path, "lstat", side_effect=lambda *args: next(states)), \
                 mock.patch.object(operator, "verify_mount", side_effect=vm.Blocked("stop_fixture_before_cluster")):
                with self.assertRaisesRegex(vm.Blocked, "stop_fixture"):
                    operator.configure()
            chown.assert_called_once_with(vm.ROOT, 0, 106)
            chmod.assert_called_once_with(vm.ROOT, 0o710)

    def test_locale_preflight_requires_explicit_utf8_alias_and_cluster_encoding(self):
        for raw in (b"C\nC.utf8\nPOSIX\n", b"C\nC.UTF-8\nPOSIX\n"):
            vm.require_utf8_locale(raw)
        for raw in (b"", b"C\nPOSIX\n", b"en_US.UTF-8\n", b"c.utf8\n"):
            with self.subTest(raw=raw), self.assertRaises(vm.Blocked):
                vm.require_utf8_locale(raw)
        self.fixture_files()
        calls = []
        def runner(operation, argv, payload, timeout):
            calls.append((operation, argv))
            return b"", native_row(operation)
        operator = self.operator(runner)
        states = iter([SimpleNamespace(st_mode=stat.S_IFDIR | 0o700, st_uid=0, st_gid=0),
                       SimpleNamespace(st_mode=stat.S_IFDIR | 0o710, st_uid=0, st_gid=106)])
        with mock.patch.object(vm, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=103, pw_gid=106))), \
             mock.patch.object(Path, "lstat", side_effect=lambda *args: next(states)), \
             mock.patch.object(vm.os, "chown", create=True), mock.patch.object(vm.os, "chmod"), \
             mock.patch.object(operator, "verify_mount"), mock.patch.object(vm, "read_bytes", return_value=b"authored default configuration"), \
             mock.patch.object(vm, "atomic_file"):
            operator.configure()
        create = calls[0]
        self.assertEqual(create[0], "cluster_create")
        self.assertIn("--encoding=UTF8", create[1])
        self.assertIn("--locale=C.UTF-8", create[1])
        self.assertEqual([row[0] for row in calls], ["cluster_create", "unmask", "start"])

    def test_postgres_os_user_cannot_alias_root(self):
        for uid, gid in ((0, 106), (103, 0), (True, 106)):
            with self.subTest(uid=uid, gid=gid), \
                 mock.patch.object(vm, "pwd", SimpleNamespace(getpwnam=lambda name: SimpleNamespace(pw_uid=uid, pw_gid=gid))), \
                 self.assertRaises(vm.Blocked):
                vm.postgres_account()

    def test_fstab_preflight_rejects_existing_target_and_format_never_runs_after_change(self):
        self.fixture_files()
        path = self.root / "fstab"
        self.stack.enter_context(mock.patch.object(vm, "FSTAB", path))
        operator = self.operator()
        path.write_bytes(b"# existing foreign mount retained\nUUID=foreign /srv/other ext4 defaults 0 2\n")
        operator.fstab_preflight()
        self.assertEqual(operator.fstab_preimage, path.read_bytes())
        path.write_bytes(path.read_bytes() + b"# concurrent foreign edit\n")
        with mock.patch.object(operator, "identity"), mock.patch.object(operator, "disk"), \
             self.assertRaisesRegex(vm.Blocked, "fstab_changed_before_format"):
            operator.mount()
        operator.runner.assert_not_called()
        for raw in ((vm.DEVICE + " /srv/other ext4 defaults 0 2\n").encode(),
                    ("UUID=foreign " + str(vm.MOUNT) + " ext4 defaults 0 2\n").encode(), b"bad\x00fstab"):
            path.write_bytes(raw)
            with self.subTest(raw=raw), self.assertRaises(vm.Blocked):
                operator.fstab_preflight()

    def test_failed_journal_update_does_not_replace_native_failure(self):
        operator = self.operator()
        self.stack.enter_context(mock.patch.object(vm.sys, "platform", "linux"))
        self.stack.enter_context(mock.patch.object(vm.os, "geteuid", return_value=0, create=True))
        for name in ("identity", "safety", "disk", "tls", "fstab_preflight", "journal"):
            self.stack.enter_context(mock.patch.object(operator, name))
        self.stack.enter_context(mock.patch.object(operator, "phase"))
        self.stack.enter_context(mock.patch.object(operator, "mount", side_effect=vm.NativeFailure("native_mkfs_timeout")))
        self.stack.enter_context(mock.patch.object(operator, "save", side_effect=OSError("authored private journal failure")))
        result = operator.run()
        self.assertEqual(result["error_code"], "native_mkfs_timeout")
        self.assertEqual(result["journal_error_code"], "journal_update_unconfirmed")
        self.assertEqual((result["status"], result["exit_code"]), ("partial_preserved", 3))
        self.assertNotIn("authored private", json.dumps(result))


if __name__ == "__main__":
    unittest.main()
