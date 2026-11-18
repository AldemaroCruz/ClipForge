"""Host-key proposal: synthetic metadata/operations only; no cloud, VM or SSH."""
import base64
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
from types import SimpleNamespace
import stat
import tempfile
import unittest
from unittest import mock

from scripts import int_vm_hostkey as op, int_vm_hostkey_guest as guest

NONCE = "ab" * 32
PUBLIC = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode("ascii")
LINK = "https://www.googleapis.com"


def fixture():
    _, _, original = op.sources()
    metadata = {**op.SECURITY, "startup-script": original, "foreign-metadata": "keep-this-value"}
    vm = {"id": op.IDENTITY["instance_id"], "name": "clipforge-int-base-postgres", "selfLink": LINK + op.VM,
          "zone": LINK + op.ZONE, "creationTimestamp": op.IDENTITY["creation_timestamp"], "status": "RUNNING",
          "lastStartTimestamp": "2026-11-18T00:31:42.000Z", "metadata": {"fingerprint": "first-fingerprint",
              "items": [{"key": key, "value": value} for key, value in metadata.items()]},
          "networkInterfaces": [{"networkIP": "10.80.1.2", "accessConfigs": [], "ipv6AccessConfigs": []}],
          "disks": [{"boot": True, "autoDelete": False, "source": LINK + op.ZONE + "/disks/clipforge-int-base-postgres"},
                    {"boot": False, "autoDelete": False, "source": LINK + op.ZONE + "/disks/clipforge-int-base-postgres-data"}]}
    disks = {}
    for name, disk_id in (("clipforge-int-base-postgres", op.IDENTITY["boot_disk_id"]),
                          ("clipforge-int-base-postgres-data", op.IDENTITY["data_disk_id"])):
        disks[op.ZONE + "/disks/" + name] = {"id": disk_id, "name": name, "status": "READY",
                    "selfLink": LINK + op.ZONE + "/disks/" + name, "users": [LINK + op.VM],
                    "sourceImageId": op.IDENTITY["image_id"]}
    return vm, {"id": op.IDENTITY["compute_project_id"], "name": "clipforgebeta2", "selfLink": LINK + op.PROJECT,
                "commonInstanceMetadata": {"items": []}}, disks


class FakeTime:
    def __init__(self):
        self.value = 0

    def now(self):
        return self.value

    def sleep(self, seconds):
        self.value += seconds


class FakeCompute:
    def __init__(self):
        self.vm, self.project, self.disks = fixture()
        self.calls, self.operations = [], {}
        self.fail_type = None
        self.timeout_type = None
        self.unknown_type = None
        self.serial = ""
        self.serial_factory = None
        self.counter = 0
        self.inject_foreign = False
        self.start_effect = True

    def request(self, method, path, payload=None):
        self.calls.append((method, path, copy.deepcopy(payload)))
        base = path.split("?", 1)[0]
        if method == "GET":
            if base == op.VM:
                return copy.deepcopy(self.vm)
            if base == op.PROJECT:
                return copy.deepcopy(self.project)
            if base in self.disks:
                return copy.deepcopy(self.disks[base])
            if base.startswith(op.ZONE + "/operations/"):
                return copy.deepcopy(self.operations[base.rsplit("/", 1)[-1]])
            if base == op.VM + "/serialPort":
                if self.serial_factory:
                    self.serial = self.serial_factory()
                return {"contents": self.serial, "next": str(len(self.serial.encode("utf-8"))), "start": "0"}
            raise AssertionError("Unexpected synthetic read")
        if method != "POST":
            raise AssertionError("Unexpected synthetic method")
        kind = base.rsplit("/", 1)[-1]
        self.counter += 1
        name = "operation-" + str(self.counter)
        request_id = path.split("requestId=", 1)[1]
        result = {"name": name, "id": str(100 + self.counter), "operationType": kind,
                  "targetId": op.IDENTITY["instance_id"], "targetLink": LINK + op.VM,
                  "zone": LINK + op.ZONE, "clientOperationId": request_id, "status": "DONE"}
        if kind == self.fail_type:
            result["error"] = {"errors": [{"code": "SYNTHETIC_DENIAL", "message": "do-not-publish-this-body"}]}
        elif kind == self.timeout_type:
            result["status"] = "RUNNING"
        elif kind == "setMetadata":
            if payload["fingerprint"] != self.vm["metadata"]["fingerprint"]:
                raise op.Blocked("compute_http_412")
            self.vm["metadata"] = {"fingerprint": "changed-" + str(self.counter), "items": copy.deepcopy(payload["items"])}
        elif kind == "stop":
            self.vm["status"] = "TERMINATED"
        elif kind == "start" and self.start_effect:
            self.vm["status"] = "RUNNING"
            self.vm["lastStartTimestamp"] = "2026-11-18T01:31:42.000Z"
            if self.inject_foreign:
                self.vm["metadata"]["items"].append({"key": "new-foreign", "value": "preserve-new"})
        self.operations[name] = result
        if kind == self.unknown_type:
            raise op.Blocked("compute_transport_unknown")
        return copy.deepcopy(result)


class HostkeyOperatorTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-hostkey-unit-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.api = FakeCompute()
        self.proposal = op.inspect(self.api, self.work, NONCE)
        self.proposal, self.journal, self.publisher = op.load(self.work)
        self.clock = FakeTime()
        self.engine = op.Recovery(self.api, self.work, self.proposal, self.journal, self.publisher,
                                  clock=self.clock.now, sleep=self.clock.sleep, timeout=5)
        self.api.serial_factory = lambda: guest.MARKER + json.dumps(self.valid_record()) + "\n"

    def valid_record(self):
        key, fingerprint = guest.public_key(PUBLIC.encode("ascii"))
        return {"schema": "clipforge-int-hostkey-record-1", **guest.IDENTITY, "nonce": NONCE,
                "guest_source_sha256": self.proposal["guest_source_sha256"],
                "script_sha256": self.proposal["publisher_sha256"], "public_key": key, "fingerprint": fingerprint}

    def posts(self):
        return [path.split("?", 1)[0].rsplit("/", 1)[-1] for method, path, _ in self.api.calls if method == "POST"]

    def test_success_has_one_cycle_polls_restores_preserves_foreign_and_pins(self):
        self.api.inject_foreign = True
        self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start", "setMetadata"])
        self.assertEqual(self.journal["phase"], "complete")
        metadata = op.metadata_items(self.api.vm["metadata"])
        self.assertEqual(metadata["startup-script"], self.journal["original_startup"])
        self.assertEqual(metadata["new-foreign"], "preserve-new")
        self.assertEqual(metadata["foreign-metadata"], "keep-this-value")
        self.assertEqual((self.work / "known_hosts").read_text().strip(),
                         "clipforge-int-base-postgres.1670495097211408131 " + PUBLIC)
        options = op.ssh_options(self.work / "known_hosts")
        for expected in ("-oStrictHostKeyChecking=yes", "-oUpdateHostKeys=no", "-oBatchMode=yes", "-oHostKeyAlgorithms=ssh-ed25519"):
            self.assertIn(expected, options)
        with self.assertRaisesRegex(op.Blocked, "no_execute_replay"):
            self.engine.execute()
        self.assertEqual(len(self.posts()), 4)

    def test_shutdown_and_startup_urls_in_both_scopes_block_before_writes(self):
        for scope in ("instance", "project"):
            for key in ("shutdown-script", "shutdown-script-url", "startup-script-url"):
                with self.subTest(scope=scope, key=key):
                    api = FakeCompute()
                    target = api.vm["metadata"] if scope == "instance" else api.project["commonInstanceMetadata"]
                    target["items"].append({"key": key, "value": ""})
                    with self.assertRaisesRegex(op.Blocked, "startup_or_shutdown_hook"):
                        op.snapshot(api)
                    self.assertFalse(any(method == "POST" for method, _, _ in api.calls))

    def test_non_successful_install_operation_stops(self):
        self.api.fail_type = "setMetadata"
        with self.assertRaisesRegex(op.Blocked, "operation_failed"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata"])

    def test_inspection_metadata_is_sanitized_and_changes_require_new_review(self):
        self.assertEqual(self.proposal["metadata_checks"], op.metadata_flags({}, {}))
        self.assertNotIn("keep-this-value", json.dumps(self.proposal))
        self.assertNotIn(self.journal["original_startup"], json.dumps(self.proposal))
        self.api.vm["metadata"]["items"].append({"key": "later-metadata", "value": "preserve-later"})
        with self.assertRaisesRegex(op.Blocked, "prepared_snapshot_changed"):
            self.engine.execute()
        self.assertEqual(self.posts(), [])

    def test_metadata_fingerprint_conflict_never_retries_or_stops(self):
        original = self.api.request
        def request(method, path, payload=None):
            if method == "POST":
                self.api.vm["metadata"]["fingerprint"] = "concurrent-change"
            return original(method, path, payload)
        self.api.request = request
        with self.assertRaisesRegex(op.Blocked, "compute_http_412"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata"])

    def test_shutdown_added_after_publisher_install_blocks_before_stop(self):
        original = self.api.request
        def request(method, path, payload=None):
            value = original(method, path, payload)
            if method == "POST" and "/setMetadata?" in path:
                self.api.project["commonInstanceMetadata"]["items"].append({"key": "shutdown-script", "value": "foreign"})
            return value
        self.api.request = request
        with self.assertRaisesRegex(op.Blocked, "startup_or_shutdown_hook"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata"])

    def test_foreign_boot_or_status_change_after_install_never_starts_another_cycle(self):
        cases = (("setMetadata", "lastStartTimestamp", "2026-11-18T01:35:42.000Z"),
                 ("setMetadata", "status", "TERMINATED"),
                 ("stop", "lastStartTimestamp", "2026-11-18T01:35:42.000Z"))
        for operation, field, changed in cases:
            with self.subTest(operation=operation, field=field):
                work = self.work / (operation + "-" + field)
                work.mkdir()
                api = FakeCompute()
                op.inspect(api, work, NONCE)
                proposal, journal, publisher = op.load(work)
                clock = FakeTime()
                engine = op.Recovery(api, work, proposal, journal, publisher,
                                     clock=clock.now, sleep=clock.sleep, timeout=5)
                api.serial_factory = lambda: guest.MARKER + json.dumps(self.valid_record()) + "\n"
                original = api.request
                def request(method, path, payload=None):
                    result = original(method, path, payload)
                    if method == "POST" and ("/" + operation + "?") in path:
                        api.vm[field] = changed
                    return result
                api.request = request
                with self.assertRaises(op.Blocked):
                    engine.execute()
                posts = [path.split("?", 1)[0].rsplit("/", 1)[-1]
                         for method, path, _ in api.calls if method == "POST"]
                expected = ["setMetadata"] if operation == "setMetadata" else ["setMetadata", "stop"]
                self.assertEqual(posts, expected)
                self.assertEqual(set(journal["operations"]), {"install"} if operation == "setMetadata" else {"install", "stop"})
                self.assertTrue(journal["operations"]["install"]["done_success"])
                self.assertNotIn(journal["phase"], {"complete", "restored_before_cycle_no_pin"})
                self.assertEqual(api.vm[field], changed)
                self.assertEqual(op.metadata_items(api.vm["metadata"])["startup-script"], publisher)
                self.assertFalse((work / "known_hosts").exists())

    def test_stop_timeout_never_starts_or_restores(self):
        self.api.timeout_type = "stop"
        with self.assertRaisesRegex(op.Blocked, "operation_timeout_preserve_publisher"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata", "stop"])
        self.assertEqual(op.metadata_items(self.api.vm["metadata"])["startup-script"], self.publisher)
        with self.assertRaisesRegex(op.Blocked, "stopped_or_stop_unknown_preserve_publisher"):
            self.engine.recover()
        self.assertEqual(len(self.posts()), 2)

    def test_unknown_start_recovery_requires_exact_completed_operation_no_second_cycle(self):
        self.api.unknown_type = "start"
        with self.assertRaisesRegex(op.Blocked, "compute_transport_unknown"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])
        with self.assertRaisesRegex(op.Blocked, "operation_name_unknown"):
            self.engine.recover()
        self.assertEqual(op.metadata_items(self.api.vm["metadata"])["startup-script"], self.publisher)
        self.engine.recover("operation-3")
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start", "setMetadata"])
        self.assertEqual(self.journal["phase"], "complete")

    def test_unknown_start_without_publication_preserves_startup(self):
        self.api.unknown_type = "start"
        self.api.serial_factory = None
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        with self.assertRaisesRegex(op.Blocked, "publication_timeout"):
            self.engine.recover("operation-3")
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])
        self.assertEqual(op.metadata_items(self.api.vm["metadata"])["startup-script"], self.publisher)

    def test_successful_operation_without_new_running_boot_cannot_restore(self):
        self.api.start_effect = False
        with self.assertRaisesRegex(op.Blocked, "new_running_boot_unconfirmed"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])

    def test_boot_timestamp_change_between_publication_reads_blocks_restore(self):
        original = self.api.request
        def request(method, path, payload=None):
            value = original(method, path, payload)
            if "/serialPort?" in path:
                self.api.vm["lastStartTimestamp"] = "2026-11-18T01:32:42.000Z"
            return value
        self.api.request = request
        with self.assertRaisesRegex(op.Blocked, "boot_changed_during_recovery"):
            self.engine.execute()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])

    def test_partial_serial_record_waits_without_losing_marker(self):
        complete = guest.MARKER + json.dumps(self.valid_record()) + "\n"
        attempts = iter((complete[:120], complete))
        self.api.serial_factory = lambda: next(attempts)
        self.engine.execute()
        self.assertEqual(self.journal["phase"], "complete")

    def test_serial_truncated_or_unknown_start_blocks_even_with_valid_record(self):
        self.api.unknown_type = "start"
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        original = self.api.request
        for offset in ("1", 4096, None, "-1", False, "not-an-offset"):
            with self.subTest(offset=offset):
                def request(method, path, payload=None):
                    result = original(method, path, payload)
                    if "/serialPort?" in path:
                        result["start"] = offset
                    return result
                self.api.request = request
                with self.assertRaisesRegex(op.Blocked, "serial_buffer_truncated_or_start_unknown"):
                    self.engine.recover("operation-3")
                self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])
                self.assertEqual(op.metadata_items(self.api.vm["metadata"])["startup-script"], self.publisher)
                self.assertFalse((self.work / "known_hosts").exists())

    def test_changed_startup_is_never_overwritten(self):
        self.api.unknown_type = "start"
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        for item in self.api.vm["metadata"]["items"]:
            if item["key"] == "startup-script":
                item["value"] = "foreign-owner-change"
        with self.assertRaisesRegex(op.Blocked, "current_startup_not_own"):
            self.engine.recover("operation-3")
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])
        self.assertEqual(op.metadata_items(self.api.vm["metadata"])["startup-script"], "foreign-owner-change")

    def test_precycle_metadata_unknown_can_restore_without_boot(self):
        self.api.unknown_type = "setMetadata"
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        self.api.unknown_type = None
        self.engine.recover("operation-1")
        self.assertEqual(self.posts(), ["setMetadata", "setMetadata"])
        self.assertEqual(self.journal["phase"], "restored_before_cycle_no_pin")
        self.assertFalse((self.work / "known_hosts").exists())

    def assert_precycle_final_change_blocks(self, key, value):
        self.api.unknown_type = "setMetadata"
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        self.api.unknown_type = None
        original = self.api.request
        def request(method, path, payload=None):
            result = original(method, path, payload)
            if method == "POST" and "/setMetadata?" in path:
                self.api.vm[key] = value
            return result
        self.api.request = request
        with self.assertRaisesRegex(op.Blocked, "precycle_restore_final_boot_unconfirmed"):
            self.engine.recover("operation-1")
        self.assertEqual(self.posts(), ["setMetadata", "setMetadata"])
        self.assertEqual(self.journal["phase"], "restore_requested")
        self.assertFalse((self.work / "known_hosts").exists())

    def test_precycle_restore_final_timestamp_changed_is_not_reported_complete(self):
        self.assert_precycle_final_change_blocks("lastStartTimestamp", "2026-11-18T01:35:42.000Z")

    def test_precycle_restore_final_vm_stopped_is_not_reported_complete(self):
        self.assert_precycle_final_change_blocks("status", "TERMINATED")

    def test_completed_recovery_checks_current_metadata_without_writes(self):
        self.engine.execute()
        for item in self.api.vm["metadata"]["items"]:
            if item["key"] == "startup-script":
                item["value"] = "later-owner-change"
        with self.assertRaisesRegex(op.Blocked, "completed_startup_changed"):
            self.engine.recover()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start", "setMetadata"])

    def test_restore_response_unknown_recovery_observes_existing_operation_only(self):
        original = self.api.request
        def request(method, path, payload=None):
            if method == "POST" and "/setMetadata?" in path and self.api.counter >= 3:
                self.api.unknown_type = "setMetadata"
            return original(method, path, payload)
        self.api.request = request
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        self.engine.recover("operation-4")
        self.assertEqual(self.journal["phase"], "complete")
        self.assertEqual(self.posts().count("start"), 1)
        self.assertEqual(self.posts().count("setMetadata"), 2)

    def test_operation_target_type_request_or_numeric_id_changes_block(self):
        self.api.timeout_type = "start"
        with self.assertRaises(op.Blocked):
            self.engine.execute()
        original = copy.deepcopy(self.api.operations["operation-3"])
        for key, value in (("targetId", "123"), ("operationType", "reset"), ("clientOperationId", "other"), ("id", "9999")):
            with self.subTest(key=key):
                self.api.operations["operation-3"] = {**original, key: value, "status": "DONE"}
                with self.assertRaises(op.Blocked):
                    self.engine.recover()
        self.assertEqual(self.posts(), ["setMetadata", "stop", "start"])

    def test_wrong_vm_disk_or_image_identity_blocks(self):
        for where, key, value in (("vm", "id", "123"), ("boot", "id", "123"), ("data", "id", "123"),
                                   ("boot", "sourceImageId", "123")):
            with self.subTest(where=where, key=key):
                api = FakeCompute()
                target = api.vm if where == "vm" else api.disks[op.ZONE + "/disks/clipforge-int-base-postgres" + ("-data" if where == "data" else "")]
                target[key] = value
                with self.assertRaises(op.Blocked):
                    op.snapshot(api)

    def test_compute_project_id_is_distinct_from_resource_manager_number(self):
        self.assertEqual(op.IDENTITY["compute_project_id"], "4183880808888199084")
        self.assertEqual(op.IDENTITY["project_number"], "816643438938")
        self.assertNotEqual(op.IDENTITY["compute_project_id"], op.IDENTITY["project_number"])
        op.snapshot(self.api)
        for key, value in (("id", op.IDENTITY["project_number"]), ("id", "123"), ("name", "other-project"),
                           ("selfLink", LINK + "/compute/v1/projects/other-project")):
            with self.subTest(key=key, value=value):
                api = FakeCompute()
                api.project[key] = value
                with self.assertRaises(op.Blocked):
                    op.snapshot(api)
                self.assertFalse(any(method == "POST" for method, _, _ in api.calls))

    def test_serial_rejects_nonce_source_key_hash_and_duplicates(self):
        good = self.valid_record()
        for key, value in (("instance_id", "123"), ("script_sha256", "00" * 32), ("fingerprint", "SHA256:wrong"),
                           ("public_key", PUBLIC + "\nmalicious knownhosts")):
            with self.subTest(key=key):
                with self.assertRaises((op.Blocked, ValueError)):
                    op.serial_records(guest.MARKER + json.dumps({**good, key: value}) + "\n", self.proposal)
        self.assertEqual(op.serial_records(guest.MARKER + json.dumps({**good, "nonce": "cd" * 32}) + "\n", self.proposal), [])
        with self.assertRaisesRegex(op.Blocked, "serial_duplicate"):
            op.serial_records((guest.MARKER + json.dumps(good) + "\n") * 2, self.proposal)

    def test_owner_guard_hash_window_decision_and_proposal_are_exact(self):
        now = datetime.now(timezone.utc)
        value = {"schema": op.AUTHORIZATION, "decision": "authorize_hostkey_recovery_once", "authorized_by": op.OWNER,
                 "authorization_id": "synthetic-owner-review", "approved_at": (now - timedelta(minutes=1)).isoformat(),
                 "expires_at": (now + timedelta(minutes=15)).isoformat(), "proposal": self.proposal}
        raw = op.canonical(value)
        self.assertEqual(op.authorization(raw, op.sha(raw), self.proposal, now), value)
        for change in ({"decision": "pending"}, {"expires_at": (now - timedelta(seconds=1)).isoformat()},
                       {"proposal": {**self.proposal, "nonce": "00" * 32}}, {"authorized_by": "somebody-else"}):
            raw = op.canonical({**value, **change})
            with self.assertRaises(op.Blocked):
                op.authorization(raw, op.sha(raw), self.proposal, now)
        with self.assertRaises(op.Blocked):
            op.authorization(raw, "00" * 32, self.proposal, now)

    def test_default_check_never_constructs_cloud_or_gcloud(self):
        with mock.patch.object(op, "GcloudUser", side_effect=AssertionError("no auth")), \
             mock.patch.object(op, "Compute", side_effect=AssertionError("no HTTP")), \
             mock.patch("sys.stdout", new_callable=io.StringIO) as output:
            op.main([])
        self.assertEqual(json.loads(output.getvalue())["status"], "offline_check_only")

    def test_raw_transport_denies_unauthorized_post_and_foreign_hosts_paths(self):
        api = op.Compute("synthetic-not-an-authentication-credential")
        with mock.patch.object(op.http.client, "HTTPSConnection", side_effect=AssertionError("no network")):
            for method, path in (("POST", op.VM + "/start"), ("GET", "https://foreign.example/"),
                                 ("POST", op.VM + "/reset"), ("GET", op.PROJECT + "/aggregated/instances")):
                with self.subTest(path=path):
                    with self.assertRaises(op.Blocked):
                        api.request(method, path)

    def test_private_scratch_checks_own_acl_and_rejects_source_tree(self):
        if os.name == "nt":
            # Ordinary Windows Temp may inherit broad grants. Exercise the
            # directory dispatch with a simulated reviewed DACL; a separate
            # negative check below ensures ACL rejection is not bypassed.
            with mock.patch.object(op, "windows_private") as acl:
                self.assertEqual(op.private_directory(self.work), self.work)
                acl.assert_called_once_with(self.work)
            with mock.patch.object(op, "windows_private", side_effect=op.Blocked("private_acl_broad")):
                with self.assertRaisesRegex(op.Blocked, "private_acl_broad"):
                    op.private_directory(self.work)
        else:
            self.assertEqual(op.private_directory(self.work), self.work)
        with self.assertRaisesRegex(op.Blocked, "scratch_inside_source_tree"):
            op.private_directory(op.ROOT)


class GuestPublisherTests(unittest.TestCase):
    def test_public_key_is_canonical_and_only_public_fields_are_emitted(self):
        template = op.read_file(op.GUEST)
        source = op.render(template, NONCE)
        binding = {**guest.IDENTITY, "nonce": NONCE, "guest_source_sha256": hashlib.sha256(template).hexdigest()}
        metadata = {"project/project-id": "clipforgebeta2", "project/numeric-project-id": "816643438938",
                    "instance/id": "1670495097211408131", "instance/zone": "projects/816643438938/zones/us-central1-a"}
        value = guest.record(binding, (PUBLIC + " harmless-comment\n").encode("ascii"), source, metadata.__getitem__)
        self.assertEqual(value["public_key"], PUBLIC)
        self.assertEqual(value["script_sha256"], op.sha(source))
        metadata["instance/id"] = "foreign"
        with self.assertRaisesRegex(ValueError, "metadata_identity"):
            guest.record(binding, PUBLIC.encode(), source, metadata.__getitem__)

    def test_public_file_and_directories_require_root_no_group_writes_no_links(self):
        for directory in (False, True):
            mode = (stat.S_IFDIR if directory else stat.S_IFREG) | 0o644
            info = SimpleNamespace(st_mode=mode, st_uid=0, st_nlink=1)
            guest.trusted(info, directory)
            for changed in ({"st_uid": 1000}, {"st_mode": mode | 0o020},
                            {"st_mode": stat.S_IFLNK | 0o777}):
                with self.subTest(directory=directory, changed=changed):
                    with self.assertRaises(ValueError):
                        guest.trusted(SimpleNamespace(**{**vars(info), **changed}), directory)
        with self.assertRaises(ValueError):
            guest.trusted(SimpleNamespace(st_mode=stat.S_IFREG | 0o644, st_uid=0, st_nlink=2))

    def test_serial_requires_actual_ttys0_character_device(self):
        with mock.patch.object(guest.os, "open", return_value=42), mock.patch.object(guest.os, "close"), \
             mock.patch.object(guest.os, "O_NOCTTY", 0x100, create=True), \
             mock.patch.object(guest.os, "O_NOFOLLOW", 0x200, create=True), \
             mock.patch.object(guest.os, "O_NONBLOCK", 0x400, create=True), \
             mock.patch.object(guest.os, "fstat", return_value=SimpleNamespace(st_mode=stat.S_IFREG | 0o600, st_uid=0)), \
             mock.patch.object(guest.os, "write") as write:
            with self.assertRaisesRegex(ValueError, "serial_device"):
                guest.write_serial({"synthetic": True})
            write.assert_not_called()

    def test_unbound_template_and_non_linux_cannot_run(self):
        with mock.patch.object(guest.sys, "platform", "win32"), mock.patch.object(guest, "write_serial") as write:
            with self.assertRaisesRegex(ValueError, "publisher_platform"):
                guest.main()
            write.assert_not_called()
        with self.assertRaisesRegex(ValueError, "publisher_binding"):
            guest.record(None, PUBLIC.encode(), b"synthetic-source", lambda key: "not-read")
        with mock.patch.object(guest.sys, "platform", "linux"), \
             mock.patch.object(guest.os, "geteuid", return_value=0, create=True), \
             mock.patch.object(guest, "read_public_key", side_effect=AssertionError("no file read")):
            with self.assertRaisesRegex(ValueError, "publisher_binding"):
                guest.main()


if __name__ == "__main__":
    unittest.main()
