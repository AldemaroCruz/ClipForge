"""Synthetic metadata regressions; actual runtime capture is separate evidence."""
import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest

from scripts import capture_int_runtime as runtime


class ComparisonTests(unittest.TestCase):
    def fixture(self):
        local_id, oci_id = "sha256:" + "a" * 64, "sha256:" + "b" * 64
        diff = "sha256:" + "c" * 64
        config = {"rootfs": {"type": "layers", "diff_ids": [diff]}, "config": {"Env": ["PUBLIC_TEST=1"]}}
        targets = [{"Class": "os-pkgs", "Type": "debian", "Packages": [{"Name": "ffmpeg", "Version": "7.1.3"}]},
                   {"Class": "lang-pkgs", "Type": "python-pkg", "Packages": [{"Name": "av", "Version": "16.0.1"}]}]
        inventory = {"schema": runtime.SCHEMA, "local_tested_image_id": local_id, "os": {"family": "debian", "version": "13.7"},
            "targets": targets, "python_native_binaries": [{"path": "/synthetic/av.libs/library.so", "bytes": 32, "sha256": "d" * 64, "vendored_library": True}],
            "av_library_versions": {"libavcodec": [62, 11, 100]}, "native_sca_limit": "Synthetic native coverage limitation", "node": {"present": False}}
        sca = {"ArtifactType": "container_image", "Metadata": {"ImageID": oci_id, "DiffIDs": [diff], "ImageConfig": config}, "Results": copy.deepcopy(targets)}
        sca["Results"][0]["Vulnerabilities"] = [{"VulnerabilityID": "CVE-2099-0001", "Severity": "HIGH", "PkgName": "ffmpeg", "InstalledVersion": "7.1.3"}]
        sbom = {"bomFormat": "CycloneDX", "metadata": {"component": {"properties": [
            {"name": "aquasecurity:trivy:ImageID", "value": oci_id}, {"name": "aquasecurity:trivy:DiffID", "value": diff}]}},
            "components": [{"type": "operating-system", "name": "debian", "version": "13.7"},
                {"type": "library", "name": "ffmpeg", "version": "7.1.3", "purl": "pkg:deb/debian/ffmpeg@7.1.3?arch=amd64"},
                {"type": "library", "name": "av", "version": "16.0.1", "purl": "pkg:pypi/av@16.0.1"}]}
        return inventory, sbom, sca, {"local_tested_image_id": local_id, "oci_config_digest": oci_id}, config

    def check(self, values):
        inventory, sbom, sca, equivalence, config = values
        return runtime.compare(inventory, sbom, sca, equivalence=equivalence, image_config=config)

    def test_exact_os_python_scope_passes_without_inventing_node(self):
        result = self.check(self.fixture())
        self.assertTrue(result["package_sets_equal"])
        self.assertFalse(result["node_present"])
        self.assertEqual([target["packages"] for target in result["targets"]], [1, 1])
        self.assertEqual(result["targets"][0]["findings"]["HIGH"], 1)
        self.assertIn("native coverage", result["native_sca_limit"])

    def test_same_counts_with_different_packages_cannot_pass(self):
        for report in ("sbom", "sca"):
            values = self.fixture()
            if report == "sbom":
                values[1]["components"][1].update(name="wrong", purl="pkg:deb/debian/wrong@7.1.3")
            else:
                values[2]["Results"][0]["Packages"][0]["Name"] = "wrong"
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.check(values)

    def test_missing_additional_duplicate_and_incomplete_targets_fail(self):
        for mutation in (lambda targets: targets.pop(),
                         lambda targets: targets.append(copy.deepcopy(targets[0])),
                         lambda targets: targets.append({"Class": "lang-pkgs", "Type": "node-pkg", "Packages": [{"Name": "node", "Version": "1"}]}),
                         lambda targets: targets[0].update(Packages=[]),
                         lambda targets: targets[0]["Packages"][0].pop("Version")):
            values = self.fixture()
            mutation(values[2]["Results"])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(values)

    def test_python_normalization_does_not_hide_version_changes(self):
        values = self.fixture()
        values[0]["targets"][1]["Packages"][0]["Name"] = "Some_Package"
        values[2]["Results"][1]["Packages"][0]["Name"] = "some.package"
        values[1]["components"][2].update(name="some-package", purl="pkg:pypi/some-package@16.0.1")
        self.assertTrue(self.check(values)["package_sets_equal"])
        values[2]["Results"][1]["Packages"][0]["Version"] = "16.0.2"
        with self.assertRaises(ValueError):
            self.check(values)

    def test_sca_and_sbom_image_identity_must_both_match(self):
        for report in ("sca", "sbom", "rootfs", "config", "inventory"):
            values = self.fixture()
            if report == "sca":
                values[2]["Metadata"]["ImageID"] = "sha256:" + "f" * 64
            elif report == "sbom":
                values[1]["metadata"]["component"]["properties"][0]["value"] = "sha256:" + "f" * 64
            elif report == "rootfs":
                values[2]["Metadata"]["DiffIDs"] = []
            elif report == "config":
                values[2]["Metadata"]["ImageConfig"] = {"rootfs": values[4]["rootfs"]}
            else:
                values[0]["local_tested_image_id"] = "sha256:" + "f" * 64
            with self.subTest(report=report), self.assertRaises(ValueError):
                self.check(values)

    def test_findings_must_reference_exact_installed_packages(self):
        for change in ({"PkgName": "not-installed"}, {"InstalledVersion": "8.0"}, {"Severity": "accepted"}):
            values = self.fixture()
            values[2]["Results"][0]["Vulnerabilities"][0].update(change)
            with self.subTest(change=change), self.assertRaises(ValueError):
                self.check(values)

    def test_native_library_versions_and_fingerprints_are_required(self):
        for mutation in (lambda value: value.update(av_library_versions={}),
                         lambda value: value.update(python_native_binaries=[]),
                         lambda value: value["python_native_binaries"][0].pop("sha256")):
            values = self.fixture()
            mutation(values[0])
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(values)

    def test_sbom_package_url_must_agree_with_component_metadata(self):
        values = self.fixture()
        values[1]["components"][1]["purl"] = "pkg:deb/debian/ffmpeg@8.0"
        with self.assertRaises(ValueError):
            self.check(values)

    def test_trivy_debian_epoch_is_reconstructed_and_mismatches_rejected(self):
        values = self.fixture()
        values[0]["targets"][0]["Packages"][0]["Version"] = "7:7.1.3"
        values[2]["Results"][0]["Packages"][0]["Version"] = "7:7.1.3"
        values[2]["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = "7:7.1.3"
        values[1]["components"][1].update(version="7:7.1.3", purl="pkg:deb/debian/ffmpeg@7.1.3?arch=amd64&epoch=7")
        self.assertTrue(self.check(values)["package_sets_equal"])
        for qualifier in ("", "&epoch=8", "&epoch=7&epoch=7", "&epoch=invalid"):
            changed = copy.deepcopy(values)
            changed[1]["components"][1]["purl"] = "pkg:deb/debian/ffmpeg@7.1.3?arch=amd64" + qualifier
            with self.subTest(qualifier=qualifier), self.assertRaises(ValueError):
                self.check(changed)

    def test_structured_binary_epoch_and_release_match_exact_installed_version(self):
        values = self.fixture()
        complete = "7:7.1.3-1+b1"
        values[0]["targets"][0]["Packages"][0]["Version"] = complete
        values[2]["Results"][0]["Packages"][0].update(Version="7.1.3", Epoch=7, Release="1+b1", ID="ffmpeg@" + complete,
            SrcVersion="7.1.3", SrcRelease="1")
        values[2]["Results"][0]["Vulnerabilities"][0]["InstalledVersion"] = complete
        values[1]["components"][1].update(version=complete, purl="pkg:deb/debian/ffmpeg@7.1.3-1%2Bb1?arch=amd64&epoch=7")
        self.assertTrue(self.check(values)["package_sets_equal"])
        for mutation in ({"Release": "1"}, {"Epoch": 8}, {"ID": "ffmpeg@wrong"}):
            changed = copy.deepcopy(values)
            changed[2]["Results"][0]["Packages"][0].update(mutation)
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                self.check(changed)


class ImageEquivalenceTests(unittest.TestCase):
    def fixture(self, directory, *, changed=False):
        root = Path(directory)
        layout = root / "oci"
        blobs = layout / "blobs/sha256"
        blobs.mkdir(parents=True)
        base = {"architecture": "amd64", "os": "linux", "config": {"Env": ["PUBLIC_TEST=1"]},
                "rootfs": {"type": "layers", "diff_ids": ["sha256:" + "d" * 64]}, "history": [{"created_by": "synthetic"}]}
        local = json.dumps(base, separators=(",", ":")).encode()
        scanned = copy.deepcopy(base)
        if changed:
            scanned["history"][0]["created_by"] = "different"
        converted = json.dumps(scanned, indent=2, sort_keys=True).encode()
        local_hash, oci_hash = (hashlib.sha256(value).hexdigest() for value in (local, converted))
        (blobs / oci_hash).write_bytes(converted)
        manifest = {"schemaVersion": 2, "config": {"digest": "sha256:" + oci_hash}, "layers": [{"digest": "sha256:" + "e" * 64}]}
        raw = json.dumps(manifest).encode()
        manifest_hash = hashlib.sha256(raw).hexdigest()
        (blobs / manifest_hash).write_bytes(raw)
        (layout / "index.json").write_text(json.dumps({"schemaVersion": 2, "manifests": [{"digest": "sha256:" + manifest_hash}]}))
        archive_path = root / "local.tar"
        with tarfile.open(archive_path, "w") as archive:
            for name, data in (("manifest.json", json.dumps([{"Config": "blobs/sha256/" + local_hash, "Layers": ["layer.tar"]}]).encode()),
                               ("blobs/sha256/" + local_hash, local)):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                archive.addfile(info, io.BytesIO(data))
        return layout, archive_path, "sha256:" + local_hash, "sha256:" + manifest_hash

    def test_full_config_json_equivalence_allows_serialization_difference(self):
        with tempfile.TemporaryDirectory() as directory:
            layout, archive, local_id, manifest = self.fixture(directory)
            proof, config = runtime.image_equivalence(layout, archive, local_id, expected_manifest=manifest)
        self.assertNotEqual(proof["local_tested_image_id"], proof["oci_config_digest"])
        self.assertTrue(proof["complete_config_json_equal"])
        self.assertTrue(proof["rootfs_diff_ids_equal"])
        self.assertEqual(proof["layer_count"], 1)

    def test_matching_rootfs_cannot_hide_other_config_difference(self):
        with tempfile.TemporaryDirectory() as directory:
            layout, archive, local_id, manifest = self.fixture(directory, changed=True)
            with self.assertRaises(ValueError):
                runtime.image_equivalence(layout, archive, local_id, expected_manifest=manifest)

    def test_tampered_blob_unexpected_manifest_and_other_local_image_fail(self):
        for mutation in ("blob", "manifest", "local"):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as directory:
                layout, archive, local_id, manifest = self.fixture(directory)
                if mutation == "blob":
                    (layout / "blobs/sha256" / manifest.split(":")[1]).write_text("{}")
                elif mutation == "manifest":
                    manifest = "sha256:" + "f" * 64
                else:
                    local_id = "sha256:" + "f" * 64
                with self.assertRaises(ValueError):
                    runtime.image_equivalence(layout, archive, local_id, expected_manifest=manifest)

    def test_duplicate_json_keys_are_rejected_before_comparison(self):
        with self.assertRaises(ValueError):
            runtime.json_bytes(b'{"public":1,"public":2}')

    def test_debian_inventory_excludes_removed_packages_and_keeps_exact_versions(self):
        status = "Package: installed\nStatus: install ok installed\nVersion: 1:2.0-3\n\nPackage: removed\nStatus: deinstall ok config-files\nVersion: 1.0\n"
        self.assertEqual(runtime.debian_packages(status), [{"Name": "installed", "Version": "1:2.0-3"}])


if __name__ == "__main__":
    unittest.main()
