"""Directed synthetic checks of the Noble read-only GUEST and first-boot receipt."""
import base64
import copy
import json
import unittest
from unittest.mock import Mock, mock_open, patch

from scripts import int_noble_guest_observation as guest
from scripts import int_noble_hostkey as host
from scripts import int_vm_hostkey_guest as legacy
from tests import test_int_guest_db_observe as disk_fixture
from tests import test_int_guest_inventory_guest as fixture


NONCE = "a" * 64
BOOT_ID = "11111111-1111-1111-1111-111111111111"
ID = "4123"
SOURCE = b"reviewed test publisher source\n"
KEY = b"ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(32))
API = "https://www.googleapis.com/compute/v1/"


def host_record():
    return host.record(NONCE, SOURCE, instance_id=ID, guest_boot_id=BOOT_ID, public_key=KEY,
                       parse_public_key=legacy.public_key)


def serial(value=None):
    line = host.MARKER + json.dumps(value or host_record()) + "\n"
    return {"start": "0", "next": str(len(line)), "contents": line}


def native_gets():
    startup = "#!/bin/bash\n# reviewed fixture\n"
    approved = {"instance_id": ID, "boot_disk_id": "4124", "data_disk_id": "4125", "image_id": "4126",
                "image_name": "ubuntu-2404-noble-amd64-v20261118", "startup_sha256": host.sha(startup.encode()),
                "creation_timestamp": "2026-11-19T09:00:00Z", "first_boot_timestamp": "2026-11-19T09:00:01Z"}
    vm_link = API + guest.INSTANCE_PATH
    zone_link = API + guest.ZONE_PATH
    metadata = [{"key": k, "value": v} for k, v in {**guest.SECURITY_METADATA, "startup-script": startup}.items()]
    vm = {"name": host.INSTANCE, "id": ID, "selfLink": vm_link, "status": "RUNNING", "zone": zone_link,
          "machineType": zone_link + "/machineTypes/e2-small", "deletionProtection": True, "canIpForward": False,
          "shieldedInstanceConfig": dict(guest.SHIELDED), "creationTimestamp": approved["creation_timestamp"],
          "lastStartTimestamp": approved["first_boot_timestamp"], "metadata": {"items": metadata, "fingerprint": "test"},
          "serviceAccounts": [{"email": guest.GUEST_EMAIL, "scopes": [guest.SCOPE]}], "disks": [],
          "networkInterfaces": [{"networkIP": guest.PRIVATE_IP, "network": API + guest.NETWORK_PATH,
                                 "subnetwork": API + guest.SUBNET_PATH, "stackType": "IPV4_ONLY"}]}
    disks = []
    for i, name, key, device, size in ((0, guest.BOOT_DISK, "boot_disk_id", "clipforge-noble-pg-boot", 10),
                                        (1, guest.DATA_DISK, "data_disk_id", guest.DEVICE_NAME, 20)):
        source = zone_link + "/disks/" + name
        vm["disks"].append({"deviceName": device, "source": source, "boot": i == 0, "autoDelete": False,
                            "index": i, "interface": "SCSI", "mode": "READ_WRITE"})
        disks.append({"name": name, "id": approved[key], "selfLink": source, "status": "READY", "zone": zone_link,
                      "type": zone_link + "/diskTypes/pd-standard", "sizeGb": str(size), "users": [vm_link]})
    disks[0].update(sourceImage=API + guest.IMAGE_PATH + approved["image_name"], sourceImageId=approved["image_id"])
    project = {"name": host.PROJECT, "id": guest.COMPUTE_PROJECT_ID, "selfLink": API + guest.PROJECT_PATH,
               "commonInstanceMetadata": {}}
    return vm, disks[0], disks[1], project, approved


def guest_report(changes=None, *, versions=None, serial_name=guest.DEVICE_NAME):
    module = {"__name__": "synthetic_noble_guest"}
    exec(compile(guest.payload_bytes(), "synthetic_noble_guest", "exec"), module)
    base, observer = module["base"], module["observer"]

    def runner(outputs):
        def query(key, **_bounds):
            return base.CommandResult(0, outputs[key], duration_ms=1)
        return query

    packages = versions if versions is not None else guest.PACKAGE_VERSIONS
    raw_packages = "".join(f"{name}\t{version}\tinstalled\tamd64\n" for name, version in packages.items()).encode()
    raw_sources = "".join(f"{name}\t{version}\t{name}\t{version}\tamd64\tinstall ok installed\tii \n"
                          for name, version in packages.items()).encode()
    base_outputs = {**fixture.outputs(), "packages": raw_packages, **(changes or {})}
    extra = {k: v.replace(b"clipforge-pg-data", serial_name.encode()) for k, v in disk_fixture.extra_outputs().items()}
    extra["packages_source"] = raw_sources
    disk = {**disk_fixture.disk_metadata(), "by_id": guest.BY_ID, "serial": serial_name}
    return observer.collect(base_runner=runner(base_outputs), runner=runner(extra), disk_reader=lambda: disk,
                            clock=lambda: 10.0, boot_reader=lambda: BOOT_ID,
                            base_metadata_reader=lambda **_: fixture.path_rows(),
                            base_release_reader=lambda **_: {"ID": "ubuntu", "VERSION_CODENAME": "noble", "VERSION_ID": "24.04"})


class NobleGuest(unittest.TestCase):
    def test_publisher_reads_existing_key_and_emits_one_bound_record(self):
        metadata = {"project/project-id": host.PROJECT, "project/numeric-project-id": host.PROJECT_NUMBER,
                    "instance/zone": f"projects/{host.PROJECT_NUMBER}/zones/{host.ZONE}", "instance/id": ID}
        inherited = {"metadata": Mock(side_effect=metadata.__getitem__), "read_public_key": Mock(return_value=KEY),
                     "public_key": legacy.public_key, "write_serial": Mock()}
        with (patch.object(host.sys, "platform", "linux"),
              patch.object(host.os, "geteuid", return_value=0, create=True),
              patch.object(host, "instance_name", return_value=host.INSTANCE),
              patch.object(host.Path, "open", mock_open(read_data=BOOT_ID.encode() + b"\n"))):
            host.publish(NONCE, SOURCE, inherited)
        inherited["read_public_key"].assert_called_once_with()
        inherited["write_serial"].assert_called_once_with(host_record())

    def test_exact_pubkey_from_first_boot(self):
        snapshot = guest.control_snapshot(*native_gets())
        evidence = guest.host_receipt(serial(), before=snapshot, after=snapshot, nonce=NONCE, publisher_sha256=host.sha(SOURCE))
        self.assertEqual(evidence["record"]["guest_boot_id"], BOOT_ID)
        self.assertEqual(evidence["known_hosts_line"], host.INSTANCE + "." + ID + " " + KEY.decode() + "\n")
        self.assertNotIn("contents", evidence)

    def test_control_snapshot_checks_compute_project_identity_in_its_own_namespace(self):
        args = native_gets()
        project = args[3]
        project.update(id="4183880808888199084", selfLink=API + guest.PROJECT_PATH)
        self.assertEqual(guest.control_snapshot(*args)["instance_id"], ID)
        for field, value in (("id", host.PROJECT_NUMBER), ("selfLink", API + "projects/another-project")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "NOBLE_OBSERVER_STARTUP_OR_METADATA"):
                guest.control_snapshot(*args[:3], {**project, field: value}, args[4])

    def test_stale_duplicate_truncated_or_malformed_serial_blocks(self):
        normal = serial()
        wrong = serial({**host_record(), "instance_id": "99"})
        duplicate_field = dict(normal, contents=normal["contents"].replace('"schema":', '"schema":"other","schema":', 1))
        for response in (wrong, duplicate_field, serial({**host_record(), "nonce": "c" * 64}),
                         dict(normal, start="1"), dict(normal, next="0"), dict(normal, next=True),
                         dict(normal, contents=normal["contents"][:-1]), dict(normal, contents=normal["contents"] * 2)):
            with self.subTest(response=response), self.assertRaises(ValueError):
                host.serial_record(response, instance_id=ID, nonce=NONCE, publisher_sha256=host.sha(SOURCE))

    def test_boot_drift_scope_and_data_attachments_block(self):
        for mutation in (
            lambda vm, boot, data, project, expected: vm.update(lastStartTimestamp="2026-11-19T09:00:02Z"),
            lambda vm, boot, data, project, expected: boot.update(sourceImageId="9999"),
            lambda vm, boot, data, project, expected: data.update(sourceSnapshot="foreign"),
            lambda vm, boot, data, project, expected: vm["networkInterfaces"][0].update(accessConfigs=[{}]),
            lambda vm, boot, data, project, expected: vm["serviceAccounts"][0]["scopes"].append("foreign"),
            lambda vm, boot, data, project, expected: expected.update(data_disk_id="6427691858848206684"),
            lambda vm, boot, data, project, expected: vm["disks"][1].update(autoDelete=True),
        ):
            arguments = native_gets()
            mutation(*arguments)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                guest.control_snapshot(*arguments)

    def test_control_fingerprint_must_remain_stable_until_host_pin(self):
        before = guest.control_snapshot(*native_gets())
        arguments = native_gets()
        arguments[0]["metadata"]["fingerprint"] = "changed"
        after = guest.control_snapshot(*arguments)
        with self.assertRaisesRegex(ValueError, "CONTROL_PLANE_CHANGED"):
            guest.host_receipt(serial(), before=before, after=after, nonce=NONCE, publisher_sha256=host.sha(SOURCE))

    def test_rendered_payload_does_not_allow_unreviewed_legacy_bytes(self):
        with patch.object(guest.Path, "read_bytes", return_value=b"foreign content"):
            with self.assertRaisesRegex(ValueError, "LEGACY_BYTES_CHANGED"):
                guest.payload_bytes()

    def test_inventory_refuses_database_activity_and_constituent_changes(self):
        blocked = guest_report({"clusters": b"17 main 5432 down postgres data log\n"})
        digest = host.sha(guest.payload_bytes())
        parsed = guest.validate_guest(json.dumps(blocked).encode(), 2, host_record=host_record(), expected_payload_sha256=digest)
        self.assertEqual(parsed["error_code"], "BASELINE_UNSAFE_OR_INCOMPLETE")
        self.assertEqual(parsed["commands"], [])
        bad_version = {**guest.PACKAGE_VERSIONS, "libxml2": "0.1"}
        for value, error in ((guest_report(versions=bad_version), "PACKAGE_CHANGED"),
                             (guest_report(serial_name="foreign"), "ATTACHMENT_SERIAL")):
            with self.subTest(error=error), self.assertRaisesRegex(ValueError, error):
                guest.validate_guest(json.dumps(value).encode(), 0, host_record=host_record(), expected_payload_sha256=digest)

    def test_observation_is_linked_to_boot_pin_and_guest_disk_without_authority(self):
        snap = guest.control_snapshot(*native_gets())
        pin = guest.host_receipt(serial(), before=snap, after=snap, nonce=NONCE, publisher_sha256=host.sha(SOURCE))
        raw = json.dumps(guest_report()).encode()
        options = {"before": snap, "after": snap, "pin_receipt": pin, "workflow_commit": "b" * 40,
                   "expected_payload_sha256": host.sha(guest.payload_bytes())}
        linked = guest.linked_observation(raw, 0, **options)
        self.assertFalse(linked["runtime_authorized"])
        self.assertEqual(linked["control_plane"]["data_disk_id"], "4125")
        self.assertEqual(linked["guest"]["disk"]["before"]["major_minor"], "8:16")
        stale_pin = copy.deepcopy(pin)
        stale_pin["record"]["guest_boot_id"] = "22222222-2222-2222-2222-222222222222"
        with self.assertRaisesRegex(ValueError, "RELEASE_OR_BOOT"):
            guest.linked_observation(raw, 0, **{**options, "pin_receipt": stale_pin})


if __name__ == "__main__":
    unittest.main()
