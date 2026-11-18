"""Authored disk/package observations and mocked transport; no live guest I/O."""
import base64
import copy
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import int_guest_db_observe as d
from scripts import int_guest_inventory as transport
from tests import test_int_guest_inventory_guest as base


def disk_metadata():
    return {"by_id": d.DEVICE, "device": "/dev/sdb", "major_minor": "8:16",
            "sysfs": "/sys/devices/authored/block/sdb", "serial": "clipforge-pg-data", "size_sectors": "41943040",
            "holders": [], "root_major_minor": "8:1", "root_sysfs": "/sys/devices/authored/block/sda/sda1"}


def extra_outputs():
    package = (b"base-files\t13.8+deb13u1\tbase-files\t13.8+deb13u1\tamd64\tinstall ok installed\tii \n"
               b"postgresql-17\t17.12-0+deb13u1\tpostgresql-17\t17.12-0+deb13u1\tamd64\tinstall ok installed\tii \n"
               b"postgresql-client-17\t17.12-0+deb13u1\tpostgresql-17\t17.12-0+deb13u1\tamd64\tinstall ok installed\tii \n")
    return {"packages_source": package,
            "disk_lsblk": d.g.encoded({"blockdevices": [{"name": "sdb", "kname": "sdb", "type": "disk", "size": d.SIZE,
                "fstype": None, "mountpoints": [None], "maj:min": "8:16", "serial": "clipforge-pg-data"}]}),
            "disk_signatures": b'{"signatures":[]}\n',
            "disk_udev": b"DEVNAME=/dev/sdb\nDEVTYPE=disk\nMAJOR=8\nMINOR=16\nID_SERIAL_SHORT=clipforge-pg-data\nUNRELATED_VALUE=not copied\n"}


def report(*, changes=None, disks=None, baseline=None):
    runner = base.AuthoredRunner(extra_outputs())
    runner.values.update(changes or {})
    result = d.collect(base_runner=baseline or base.AuthoredRunner(), runner=runner,
        disk_reader=disks or disk_metadata, boot_reader=lambda: "11111111-1111-1111-1111-111111111111", clock=lambda: 10,
        base_metadata_reader=lambda **_: base.path_rows(), base_release_reader=lambda **_: {
            "ID": "debian", "VERSION_ID": "13", "VERSION_CODENAME": "trixie"})
    return result, runner


def plane_snapshot(case):
    vm, boot, data = case.snapshot()
    vm["disks"][1].update(deviceName="clipforge-pg-data", interface="SCSI", index=1, mode="READ_WRITE")
    data.update(sizeGb="20", type="https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard")
    return vm, boot, data


class DBObservation(unittest.TestCase):
    def test_fixed_readonly_commands_and_complete_observation(self):
        value, runner = report()
        self.assertEqual(d.validate_report(value), value)
        self.assertEqual((value["status"], value["exit_code"]), ("observation_complete", 0))
        self.assertEqual([key for key, _ in runner.calls], list(d.EXTRA))
        self.assertEqual(value["packages_source"][2]["source_name"], "postgresql-17")
        self.assertEqual(value["packages_source"][0]["status_abbrev"], "ii ")
        self.assertNotIn("UNRELATED_VALUE", value["disk"]["udev"])
        self.assertIn("--no-act", d.EXTRA["disk_signatures"])
        self.assertFalse(any(word in " ".join(args) for args in d.EXTRA.values() for word in ("mkfs", "apt-get", "pg_createcluster", "systemctl start")))

    def test_full_dpkg_status_is_observed_not_reconstructed(self):
        raw = extra_outputs()["packages_source"]
        self.assertEqual(d.parse_packages(raw)[0]["status"], "install ok installed")
        for wrong in (raw.replace(b"ii ", b"iiR"), raw.replace(b"install ok installed", b"hold ok installed"), raw + raw.splitlines(keepends=True)[0], raw.replace(b"\tamd64\t", b"\tnot_an_arch\t")):
            with self.subTest(wrong=wrong), self.assertRaises(ValueError):d.parse_packages(wrong)
        missing = raw.replace(b"\tbase-files\t13.8+deb13u1\t", b"\t\t\t")
        self.assertEqual(d.parse_packages(missing)[0]["source_name"], "")

    def test_package_change_between_queries_blocks_without_disk_reads(self):
        read = mock.Mock(side_effect=AssertionError("disk should not be read"))
        value, runner = report(changes={"packages_source": extra_outputs()["packages_source"].replace(b"17.12-0+deb13u1", b"17.13-0+deb13u1")}, disks=read)
        self.assertEqual(value["error_code"], "PACKAGES_CHANGED_DURING_CAPTURE")
        self.assertEqual([key for key, _ in runner.calls], ["packages_source"]);read.assert_not_called()
        d.validate_report(value)

    def test_pg_signal_stops_all_additional_observations(self):
        baseline = base.AuthoredRunner({"clusters": b"17 main 5432 down postgres data log\n"})
        value, runner = report(baseline=baseline)
        self.assertEqual(value["error_code"], "BASELINE_UNSAFE_OR_INCOMPLETE")
        self.assertEqual(runner.calls, []);d.validate_report(value)

    def test_disk_signatures_partitions_mounts_root_holders_and_identity_block(self):
        original, _ = report()
        mutations = [lambda x:x["before"].update(holders=["dm-0"]),
                     lambda x:x["before"].update(root_major_minor="8:16"),
                     lambda x:x["before"].update(root_sysfs=x["before"]["sysfs"]+"/sdb1"),
                     lambda x:x["before"].update(size_sectors="1"),
                     lambda x:x["before"].update(by_id="/dev/disk/by-id/google-other"),
                     lambda x:x["lsblk"]["blockdevices"][0].update(fstype="ext4"),
                     lambda x:x["lsblk"]["blockdevices"][0].update(mountpoints=["/mnt"]),
                     lambda x:x["lsblk"]["blockdevices"][0].update(children=[{}]),
                     lambda x:x["lsblk"]["blockdevices"][0].update(serial="foreign"),
                     lambda x:x["signatures"].update(signatures=[{"type":"ext4"}]),
                     lambda x:x["udev"].update(MINOR="1"),lambda x:x["udev"].update(DEVNAME="/dev/sda")]
        for mutate in mutations:
            disk=copy.deepcopy(original["disk"]);mutate(disk)
            # Synchronize before/after for tests of an unsafe stable device.
            disk["after"]=copy.deepcopy(disk["before"])
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):d.validate_disk(disk)

    def test_metadata_change_mid_capture_preserves_queries_and_stops(self):
        changed=disk_metadata();changed["serial"]="changed"
        reader=mock.Mock(side_effect=[disk_metadata(),changed])
        value, runner=report(disks=reader)
        self.assertEqual(value["status"],"observation_blocked")
        self.assertEqual(value["error_code"],"DISK_CHANGED")
        self.assertEqual(len(runner.calls),4);d.validate_report(value)

    def test_absent_sysfs_serial_is_explicit_and_udev_is_observed(self):
        original,_=report()
        disk=original["disk"]
        disk["before"]["serial"]=disk["after"]["serial"]=None
        d.validate_disk(disk)
        self.assertIsNone(disk["before"]["serial"])
        disk["lsblk"]["blockdevices"][0]["serial"]=None
        disk["udev"].pop("ID_SERIAL_SHORT")
        with self.assertRaisesRegex(ValueError,"SERIAL_DISCORDANCE"):d.validate_disk(disk)

    def test_process_budgets_preserve_inventory_default_and_are_not_arbitrary(self):
        with tempfile.TemporaryDirectory() as directory:
            regular=transport.ProcessRunner(directory,"/usr/bin/gcloud",b"authored source","authored")
            self.assertEqual(regular.maximum_process_seconds,180)
            with mock.patch.object(transport.subprocess,"Popen",side_effect=AssertionError("process forbidden")) as start:
                with self.assertRaisesRegex(transport.Blocked,"local_process_bounds"):
                    regular.run(regular.keygen_command(),timeout=181)
                start.assert_not_called()
            self.assertEqual(transport.ProcessRunner(directory,"/usr/bin/gcloud",b"authored source","authored",maximum_process_seconds=600).maximum_process_seconds,600)
            for value in (0,True,181,601):
                with self.subTest(value=value),self.assertRaises(transport.Blocked):
                    transport.ProcessRunner(directory,"/usr/bin/gcloud",b"authored source","authored",maximum_process_seconds=value)

    def test_real_transport_records_status_time_without_body_or_credential(self):
        response=mock.MagicMock()
        response.__enter__.return_value.status=200
        response.__enter__.return_value.read.return_value=b'{"private_metadata":"authored-withheld"}'
        opener=mock.Mock();opener.open.return_value=response
        client=transport.Client(lambda:"authored-short-lived-token")
        with mock.patch.object(transport,"build_opener",return_value=opener):client.request("GET",transport.VM_URL)
        self.assertEqual(client.http_receipts[0]["http_status"],200)
        self.assertEqual(client.http_receipts[0]["operation"],"Compute.get")
        self.assertNotIn("authored-withheld",str(client.http_receipts))
        self.assertNotIn("authored-short-lived-token",str(client.http_receipts))

    def test_tool_denial_preserves_nonzero_and_does_not_install(self):
        value, runner=report(changes={"disk_signatures":d.g.CommandResult(1,b"",b"Permission denied\n",1,"nonzero_exit","NONZERO_EXIT")})
        self.assertEqual(value["error_code"],"READ_QUERY_FAILED")
        self.assertEqual(value["commands"][-1]["exit_code"],1)
        self.assertEqual(value["commands"][-1]["stderr_diagnostic"]["messages"],["Permission denied"])
        self.assertEqual([key for key,_ in runner.calls],list(d.EXTRA)[:3]);d.validate_report(value)

    def test_closed_report_rejects_extra_data_changed_package_and_invented_status(self):
        original,_=report()
        for mutate in (lambda x:x.update(unapproved="data"),lambda x:x["packages_source"][0].update(status="invented"),
                       lambda x:x["packages_source"][0].update(binary_version="99"),lambda x:x.update(exit_code=2),
                       lambda x:x["commands"][0].update(stdout_bytes=9999999)):
            value=copy.deepcopy(original);mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):d.validate_report(value)

    def test_mode_payload_is_exact_composition_and_cannot_select_other_source(self):
        # POSIX ownership/mode checks have their own tests; source bytes here are public.
        with mock.patch.object(transport,"_local_bytes",side_effect=lambda path,*_:Path(path).read_bytes()):
            raw=transport.readonly_payload("db01-observe")
            compile(raw,"authored-composition-check","exec")
            self.assertIn(b"_clipforge_readonly_base",raw)
            self.assertIn(base64.b64encode(Path(d.__file__).read_bytes()),raw)
            self.assertEqual(transport.readonly_payload(),Path(d.g.__file__).read_bytes())
            with self.assertRaises(transport.Blocked):transport.readonly_payload("bootstrap")
        with self.assertRaises(ValueError):transport.parse_inventory(d.g.encoded(report()[0]),3,inspection_mode="db01-observe")

    def test_control_plane_and_source_bind_the_observed_disk_without_new_identity_claim(self):
        from tests import test_int_guest_inventory as fixtures
        case=fixtures.GuestInventoryRunner("runTest");case.setUp();self.addCleanup(case.doCleanups)
        vm,boot,data=plane_snapshot(case)
        evidence=d.make_evidence(report()[0],vm,boot,data,observed_utc="2026-11-18T23:00:00+00:00",commit="a"*40,payload_sha256="b"*64)
        proof=d.disk_proof(evidence)
        self.assertEqual(proof["disk_id"],"6427691858848206684")
        self.assertEqual(proof["guest_major_minor"],"8:16")
        for mutate in (lambda x:x["control_plane"].update(disk_id="1"),lambda x:x["control_plane"]["attachment"].update(boot=True),
                       lambda x:x.update(guest_report_sha256="0"*64),lambda x:x["source"].update(commit="main")):
            value=copy.deepcopy(evidence);mutate(value)
            with self.subTest(mutate=mutate),self.assertRaises(ValueError):d.disk_proof(value)

    def test_real_orchestration_new_mode_keeps_cleanup_and_never_requeries_uid(self):
        from tests import test_int_guest_inventory as fixtures
        case=fixtures.GuestInventoryRunner("runTest");case.setUp();self.addCleanup(case.doCleanups)
        original=case.snapshot
        def snapshot():
            vm,boot,data=original()
            vm["disks"][1].update(deviceName="clipforge-pg-data",interface="SCSI",index=1,mode="READ_WRITE")
            data.update(sizeGb="20",type="https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard")
            return vm,boot,data
        with mock.patch.object(case,"snapshot",side_effect=snapshot):
            result,client,processes,output=case.orchestration(guest_report=report()[0],inspection_mode="db01-observe")
        case.assert_own_cleanup(result,client,processes)
        self.assertEqual(result["status"],"observation_complete")
        self.assertFalse(any(url==transport.HISTORICAL_PROFILE_URL for _,url,_ in client.calls))
        evidence=d.g._json((output/"inventory.json").read_bytes())
        self.assertEqual(d.disk_proof(evidence)["disk_id"],"6427691858848206684")


if __name__=="__main__":unittest.main()
