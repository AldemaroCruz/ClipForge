"""Authored inventory/SCA fixtures; no scanner, VM or network calls."""
import copy
import unittest

from scripts import db01_guest_sca as sca
from tests import test_int_guest_inventory_guest as authored


class GuestSCA(unittest.TestCase):
    def document(self, packages=None):
        changes = {} if packages is None else {"packages": packages}
        return authored.collect(authored.AuthoredRunner(changes))

    def prepare(self, value=None):
        raw = sca.encoded(self.document() if value is None else value)
        return sca.prepare(raw, sca.sha256(raw))

    def test_preserves_observed_fields_without_dpkg_or_source_fabrication(self):
        value = self.document()
        bom, manifest = self.prepare(value)
        self.assertEqual((manifest["package_components"], manifest["observed_status_counts"]), (3, {"installed": 3}))
        self.assertFalse(manifest["dpkg_database_reconstructed"])
        self.assertFalse(manifest["source_fields_observed"])
        self.assertFalse(manifest["complete_filesystem_sca"])
        self.assertEqual(bom["metadata"]["component"]["type"], "operating-system")
        self.assertEqual(len(bom["dependencies"][0]["dependsOn"]), 3)
        self.assertNotIn("aquasecurity", sca.encoded(bom).decode())
        self.assertNotIn("install ok installed", sca.encoded(bom).decode())
        for row in bom["components"]:
            self.assertIn("?arch=amd64&distro=debian-13", row["purl"])

    def test_binary_arch_and_epoch_are_encoded_without_losing_observed_name(self):
        bom, _ = self.prepare(self.document(b"libexample:amd64\t2:1.0+deb13u1\tinstalled\tamd64\n"))
        component = bom["components"][0]
        self.assertEqual(component["name"], "libexample")
        self.assertIn("@2%3A1.0%2Bdeb13u1?arch=amd64", component["purl"])
        self.assertEqual(component["properties"][0]["value"], "libexample:amd64")

    def test_custody_and_incomplete_inventory_fail_closed(self):
        raw = sca.encoded(self.document())
        with self.assertRaisesRegex(sca.InvalidEvidence, "custody"):
            sca.prepare(raw, sca.sha256(raw + b" "))
        bad = self.document(); bad.update(status="inventory_incomplete", exit_code=3)
        with self.assertRaises(ValueError):
            self.prepare(bad)
        with self.assertRaisesRegex(sca.InvalidEvidence, "duplicate"):
            sca.decode(b'{"one":1,"one":2}')

    def test_never_silently_marks_noninstalled_as_installed(self):
        for status in (b"config-files", b"unpacked", b"half-configured"):
            with self.subTest(status=status), self.assertRaisesRegex(sca.InvalidEvidence, "observed_installed"):
                self.prepare(self.document(b"libexample\t1.0\t" + status + b"\tamd64\n"))
        with self.assertRaisesRegex(sca.InvalidEvidence, "architecture_mismatch"):
            self.prepare(self.document(b"libexample:arm64\t1.0\tinstalled\tamd64\n"))

    def native(self):
        bom, manifest = self.prepare()
        report = {"SchemaVersion": 2, "ArtifactType": "cyclonedx", "Metadata": {"OS": {"Family": "debian", "Name": "13"}},
                  "Results": [{"Class": "os-pkgs", "Type": "debian", "Packages": [{"Identifier": {"PURL": row["purl"]}} for row in bom["components"]],
                    "Vulnerabilities": [{"VulnerabilityID": "CVE-AUTHORED-1", "PkgName": "base-files", "InstalledVersion": "13.8+deb13u1", "Severity": "HIGH", "FixedVersion": ""}]}]}
        return bom, manifest, report

    def test_native_results_counted_only_after_exact_package_coverage(self):
        bom, manifest, report = self.native()
        result = sca.summarize(report, bom, manifest)
        self.assertEqual((result["packages_recognized"], result["finding_rows"], result["severity_counts"]["HIGH"]), (3, 1, 1))
        self.assertFalse(result["security_accepted"])
        self.assertTrue(result["limitations"])

    def test_empty_or_wrong_native_scope_cannot_be_reported_clean(self):
        bom, manifest, report = self.native()
        changes = [lambda x: x["Results"][0].pop("Packages"), lambda x: x["Results"][0]["Packages"].pop(),
                   lambda x: x["Metadata"]["OS"].update(Family="ubuntu"), lambda x: x.update(Results=[]),
                   lambda x: x["Results"][0].update(Type="python")]
        for change in changes:
            altered = copy.deepcopy(report); change(altered)
            with self.subTest(altered=altered), self.assertRaises(sca.InvalidEvidence):
                sca.summarize(altered, bom, manifest)

    def test_native_purl_escape_normalization_keeps_arch_distro_and_version_exact(self):
        original = "pkg:deb/debian/libexample@2%3A1.0%2Bdeb13u1?arch=amd64&distro=debian-13"
        normalized = "pkg:deb/debian/libexample@2:1.0%2Bdeb13u1?distro=debian-13&arch=amd64"
        self.assertEqual(sca.package_identity(original), sca.package_identity(normalized))
        for invalid in (original.replace("debian-13", "debian-12"), original + "&arch=arm64",
                        original.replace("libexample", "other%2Flibexample"), original.replace("amd64", "")):
            with self.subTest(invalid=invalid), self.assertRaises(sca.InvalidEvidence):
                sca.package_identity(invalid)
        self.assertNotEqual(sca.package_identity(original), sca.package_identity(original.replace("amd64", "arm64")))

    def observation(self, packages=None):
        base = self.document(packages)
        rows = [{"binary_name": name, "binary_version": version, "source_name": "authored-source-" + name.split(":")[0],
                 "source_version": version.removesuffix("+b1"), "architecture": arch,
                 "status": "install ok " + status, "status_abbrev": "ii "}
                for name, version, status, arch in base["inventory"]["packages"]]
        return {"schema": "clipforge-int-db01-observation-1", "base_inventory": base, "packages_source": rows}

    def prepare_sources(self, observation=None):
        raw = sca.encoded(self.evidence(self.observation() if observation is None else observation))
        return sca.prepare_observation(raw, sca.sha256(raw))

    def evidence(self, observation):
        from scripts import int_guest_db_observe as reader
        report = copy.deepcopy(observation)
        before = {"by_id": reader.DEVICE, "device": "/dev/sdb", "major_minor": "8:16", "sysfs": "/sys/devices/authored-data",
            "serial": "authored-synthetic-disk", "size_sectors": str(reader.SIZE // 512), "holders": [],
            "root_major_minor": "8:1", "root_sysfs": "/sys/devices/authored-root/partition1"}
        report.update(status="observation_complete", exit_code=0, observed_utc="2026-11-18T23:30:00+00:00",
            guest_boot_id="12345678-1234-1234-1234-123456789abc", read_only=True, error_code=None,
            disk={"before": before, "after": copy.deepcopy(before), "lsblk": {"blockdevices": [{"name": "sdb", "kname": "sdb",
                "type": "disk", "size": reader.SIZE, "fstype": None, "mountpoints": [None], "maj:min": "8:16", "serial": before["serial"]}]},
                "signatures": {"signatures": []}, "udev": {"DEVNAME": "/dev/sdb", "DEVTYPE": "disk", "MAJOR": "8", "MINOR": "16"}, "identity_confirmed": True},
            commands=[{"key": key, "status": "ok", "exit_code": 0, "stdout_bytes": 0, "stdout_sha256": sca.sha256(b""),
                "stderr_bytes": 0, "stderr_sha256": sca.sha256(b""), "stderr_diagnostic": {"messages": [], "unclassified_lines": 0}, "duration_ms": 1} for key in reader.EXTRA])
        zone = "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
        return {"schema": reader.EVIDENCE_SCHEMA, "guest": report, "guest_report_sha256": sca.sha256(reader.g.encoded(report) + b"\n"),
            "control_plane": {"project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a",
                "instance_id": "1670495097211408131", "boot_timestamp": "2026-11-18T21:30:00Z", "disk_id": "6427691858848206684",
                "disk_name": "clipforge-int-base-postgres-data", "disk_type": zone + "diskTypes/pd-standard", "size_bytes": reader.SIZE,
                "observed_utc": "2026-11-18T23:30:00Z", "attachment": {"deviceName": "clipforge-pg-data", "source": zone + "disks/clipforge-int-base-postgres-data",
                    "interface": "SCSI", "index": 1, "mode": "READ_WRITE", "boot": False, "autoDelete": False}},
            "source": {"commit": "a" * 40, "payload_sha256": sca.sha256(b"authored synthetic read-only payload")}}

    def source_native(self):
        bom, manifest = self.prepare_sources(self.observation(b"libexample-bin:amd64\t2:1.0-3+b1\tinstalled\tamd64\n"))
        properties = {row["name"]: row["value"] for row in bom["components"][0]["properties"]}
        report = {"SchemaVersion": 2, "ArtifactType": "cyclonedx", "Metadata": {"OS": {"Family": "debian", "Name": "13"}},
            "Results": [{"Class": "os-pkgs", "Type": "debian", "Packages": [{"Identifier": {"PURL": bom["components"][0]["purl"]},
                "SrcName": properties["aquasecurity:trivy:SrcName"], "SrcVersion": properties["aquasecurity:trivy:SrcVersion"]}],
                "Vulnerabilities": []}]}
        return bom, manifest, report

    def test_source_fields_and_full_status_are_observed_not_filled_from_binary(self):
        bom, manifest, report = self.source_native()
        props = {row["name"]: row["value"] for row in bom["components"][0]["properties"]}
        self.assertEqual(props["aquasecurity:trivy:SrcName"], "authored-source-libexample-bin")
        self.assertEqual(props["aquasecurity:trivy:SrcVersion"], "2:1.0-3")
        self.assertEqual(props["clipforge:observed-dpkg-status"], "install ok installed")
        self.assertEqual(props["clipforge:observed-dpkg-status-abbrev"], "ii ")
        self.assertTrue(manifest["source_fields_observed"])
        self.assertFalse(manifest["generated_by_trivy"])
        self.assertEqual((manifest["source_name_aliases_observed"], manifest["source_version_differences_observed"]), (1, 1))
        self.assertNotIn('"group":"aquasecurity"', sca.encoded(bom).decode())
        self.assertEqual(sca.summarize(report, bom, manifest)["schema"], "clipforge-db01-guest-sca-summary-2")

    def test_source_coverage_and_native_source_aliases_are_required(self):
        bom, manifest, report = self.source_native()
        cases = [lambda x: x["Results"][0]["Packages"][0].pop("SrcName"),
                 lambda x: x["Results"][0]["Packages"][0].update(SrcName="libexample-bin"),
                 lambda x: x["Results"][0]["Packages"][0].update(SrcVersion="2:1.0-3+b1"),
                 lambda x: x["Results"][0]["Packages"][0].update(SrcEpoch=2),
                 lambda x: x["Results"][0]["Packages"].clear()]
        for change in cases:
            bad = copy.deepcopy(report); change(bad)
            with self.subTest(change=change), self.assertRaises(sca.InvalidEvidence):
                sca.summarize(bad, bom, manifest)
        normalized = copy.deepcopy(report)
        normalized["Results"][0]["Packages"][0].update(SrcEpoch=2, SrcVersion="1.0", SrcRelease="3")
        self.assertTrue(sca.summarize(normalized, bom, manifest)["source_fields_observed"])

    def test_observation_mutations_missing_source_and_status_mismatch_fail_closed(self):
        changes = [lambda x: x["packages_source"][0].update(source_name=""),
                   lambda x: x["packages_source"][0].update(source_version=""),
                   lambda x: x["packages_source"][0].update(binary_version="0.1"),
                   lambda x: x["packages_source"][0].update(architecture="arm64"),
                   lambda x: x["packages_source"][0].update(status_abbrev="ii"),
                   lambda x: x["packages_source"][0].update(status="install reinstreq installed", status_abbrev="iiR"),
                   lambda x: x["packages_source"][0].update(unobserved="invented"),
                   lambda x: x["packages_source"].append(copy.deepcopy(x["packages_source"][0])),
                   lambda x: x["packages_source"].pop()]
        for change in changes:
            value = self.observation(); change(value)
            with self.subTest(change=change), self.assertRaises(sca.InvalidEvidence):
                self.prepare_sources(value)
        raw = sca.encoded(self.evidence(self.observation()))
        with self.assertRaisesRegex(sca.InvalidEvidence, "custody"):
            sca.prepare_observation(raw, "0" * 64)

    def test_source_conversion_requires_disk_and_nested_guest_byte_custody(self):
        evidence = self.evidence(self.observation())
        raw = sca.encoded(evidence)
        _bom, manifest = sca.prepare_observation(raw, sca.sha256(raw))
        self.assertEqual(manifest["evidence_sha256"], sca.sha256(raw))
        self.assertEqual(manifest["guest_report_sha256"], evidence["guest_report_sha256"])
        for change in (lambda x: x.update(guest_report_sha256="0" * 64),
                       lambda x: x["control_plane"].update(disk_id="1"),
                       lambda x: x["guest"]["disk"]["before"].update(holders=["unreviewed-holder"]),
                       lambda x: x.update(unexpected_private_field="authored sentinel")):
            value = copy.deepcopy(evidence); change(value); altered = sca.encoded(value)
            with self.subTest(change=change), self.assertRaises(sca.InvalidEvidence):
                sca.prepare_observation(altered, sca.sha256(altered))

    def test_held_installed_is_scanned_and_residual_configuration_is_preserved(self):
        value = self.observation(b"libexample\t1.0\tinstalled\tamd64\nresidual\t1.0\tconfig-files\tamd64\n")
        value["packages_source"][0].update(status="hold ok installed", status_abbrev="hi ")
        value["packages_source"][1].update(status="deinstall ok config-files", status_abbrev="rc ", source_name="", source_version="")
        bom, manifest = self.prepare_sources(value)
        self.assertEqual(len(bom["components"]), 1)
        self.assertEqual(manifest["observed_status_counts"], {"hold ok installed": 1, "deinstall ok config-files": 1})
        self.assertEqual(manifest["excluded_noninstalled_or_error_rows"][0]["binary_name"], "residual")


if __name__ == "__main__":
    unittest.main()
