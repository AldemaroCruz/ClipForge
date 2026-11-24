import copy
from datetime import datetime, timedelta, timezone
import gzip
import hashlib
from io import BytesIO
import json
from pathlib import Path
from types import SimpleNamespace
import tarfile
import tempfile
import unittest

from scripts import int_hito_a_scan as scan


AT = datetime(2026, 11, 24, 18, 0, tzinfo=timezone.utc)


def encoded(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def digest(raw):
    return "sha256:" + hashlib.sha256(raw).hexdigest()


def add_bytes(archive, name, raw):
    info = tarfile.TarInfo(name)
    info.size = len(raw)
    info.mode = 0o644
    archive.addfile(info, BytesIO(raw))


class Fixture:
    def __init__(self, root, *, suffix="", extra=None):
        self.root = Path(root)
        self.suffix = suffix
        self.created = AT - timedelta(minutes=5)
        status = (
            "Package: base-files\nVersion: 1.0-1\nStatus: install ok installed\n\n"
            "Package: ca-certificates\nVersion: 2026.1\nStatus: install ok installed\n"
        ).encode()
        files = {
            "etc/os-release": b'ID=ubuntu\nVERSION_ID="24.04"\n',
            "var/lib/dpkg/status": status,
            "opt/clipforge/venv/lib/python3.12/site-packages/fastapi-0.133.0.dist-info/METADATA":
                b"Metadata-Version: 2.4\nName: fastapi\nVersion: 0.133.0\n",
            "opt/clipforge/venv/lib/python3.12/site-packages/uvicorn-0.34.2.dist-info/METADATA":
                b"Metadata-Version: 2.4\nName: uvicorn\nVersion: 0.34.2\n",
            **(extra or {}),
        }
        layer_tar = BytesIO()
        with tarfile.open(fileobj=layer_tar, mode="w") as archive:
            for name, raw in files.items():
                add_bytes(archive, name, raw)
        uncompressed = layer_tar.getvalue()
        layer = gzip.compress(uncompressed, mtime=0)
        self.layer_digest = digest(layer)
        self.diff_id = digest(uncompressed)
        self.config = {
            "architecture": "amd64",
            "os": "linux",
            "rootfs": {"type": "layers", "diff_ids": [self.diff_id]},
            "history": [{"created_by": "fixture"}],
            "config": {
                "User": "10001:10001",
                "WorkingDir": "/app",
                "Env": ["PATH=/opt/clipforge/venv/bin:/usr/bin", "CLIPFORGE_RUNTIME_PROFILE=int-demo-a"],
            },
        }
        config_raw = encoded(self.config)
        self.config_digest = digest(config_raw)
        manifest = {
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "config": {"mediaType": "application/vnd.oci.image.config.v1+json",
                       "digest": self.config_digest, "size": len(config_raw)},
            "layers": [{"mediaType": "application/vnd.oci.image.layer.v1.tar+gzip",
                        "digest": self.layer_digest, "size": len(layer)}],
        }
        manifest_raw = encoded(manifest)
        self.manifest_digest = digest(manifest_raw)
        index = {"schemaVersion": 2, "manifests": [{
            "mediaType": "application/vnd.oci.image.manifest.v1+json",
            "digest": self.manifest_digest,
            "size": len(manifest_raw),
        }]}
        self.archive = self.root / ("runtime" + suffix + ".oci.tar")
        with tarfile.open(self.archive, "w") as outer:
            add_bytes(outer, "oci-layout", encoded({"imageLayoutVersion": "1.0.0"}))
            add_bytes(outer, "index.json", encoded(index))
            add_bytes(outer, "blobs/sha256/" + self.manifest_digest[7:], manifest_raw)
            add_bytes(outer, "blobs/sha256/" + self.config_digest[7:], config_raw)
            add_bytes(outer, "blobs/sha256/" + self.layer_digest[7:], layer)

        self.os_packages = [
            {"Name": "base-files", "Version": "1.0", "Release": "1", "Epoch": 0,
             "ID": "base-files@1.0-1",
             "Identifier": {"PURL": "pkg:deb/ubuntu/base-files@1.0-1?arch=amd64"}},
            {"Name": "ca-certificates", "Version": "2026.1", "Release": "", "Epoch": 0,
             "ID": "ca-certificates@2026.1",
             "Identifier": {"PURL": "pkg:deb/ubuntu/ca-certificates@2026.1?arch=all"}},
        ]
        self.python_packages = [
            {"Name": "fastapi", "Version": "0.133.0",
             "Identifier": {"PURL": "pkg:pypi/fastapi@0.133.0"}},
            {"Name": "uvicorn", "Version": "0.34.2",
             "Identifier": {"PURL": "pkg:pypi/uvicorn@0.34.2"}},
        ]
        self.trivy_value = {
            "SchemaVersion": 2,
            "CreatedAt": self.created.isoformat().replace("+00:00", "Z"),
            "ArtifactType": "container_image",
            "Trivy": {"Version": scan.TRIVY_VERSION},
            "Metadata": {
                "ImageID": self.config_digest,
                "DiffIDs": [self.diff_id],
                "ImageConfig": self.config,
                "OS": {"Family": "ubuntu", "Name": "24.04"},
            },
            "Results": [
                {"Target": "Ubuntu 24.04", "Class": "os-pkgs", "Type": "ubuntu",
                 "Packages": self.os_packages, "Vulnerabilities": []},
                {"Target": "Python packages", "Class": "lang-pkgs", "Type": "python-pkg",
                 "Packages": self.python_packages, "Vulnerabilities": [{
                     "VulnerabilityID": "TEST-LOW-1", "Severity": "LOW", "PkgName": "fastapi",
                     "InstalledVersion": "0.133.0",
                     "PkgIdentifier": {"PURL": "pkg:pypi/fastapi@0.133.0"},
                     "Fingerprint": "synthetic-low-fastapi",
                 }]},
            ],
        }
        self.trivy = self.root / ("trivy" + suffix + ".json")
        self.write_json(self.trivy, self.trivy_value)
        properties = [{"name": "aquasecurity:trivy:ImageID", "value": self.config_digest},
                      {"name": "aquasecurity:trivy:DiffID", "value": self.diff_id}]
        self.sbom_value = {
            "bomFormat": "CycloneDX",
            "specVersion": "1.6",
            "metadata": {"timestamp": self.created.isoformat().replace("+00:00", "Z"),
                         "tools": {"components": [{"type": "application", "group": "aquasecurity",
                                                    "name": "trivy", "version": scan.TRIVY_VERSION}]},
                         "component": {"type": "container", "bom-ref": "runtime", "properties": properties}},
            "components": [
                {"type": "operating-system", "name": "ubuntu", "version": "24.04", "bom-ref": "os"},
                {"type": "library", "name": "base-files", "version": "1.0-1", "bom-ref": "deb-1",
                 "purl": "pkg:deb/ubuntu/base-files@1.0-1?arch=amd64"},
                {"type": "library", "name": "ca-certificates", "version": "2026.1", "bom-ref": "deb-2",
                 "purl": "pkg:deb/ubuntu/ca-certificates@2026.1?arch=all"},
                {"type": "library", "name": "fastapi", "version": "0.133.0", "bom-ref": "py-1",
                 "purl": "pkg:pypi/fastapi@0.133.0"},
                {"type": "library", "name": "uvicorn", "version": "0.34.2", "bom-ref": "py-2",
                 "purl": "pkg:pypi/uvicorn@0.34.2"},
            ],
        }
        self.sbom = self.root / ("sbom" + suffix + ".json")
        self.write_json(self.sbom, self.sbom_value)
        self.db = self.root / ("trivy" + suffix + ".db")
        self.db.write_bytes(b"synthetic-trivy-db-fixture")
        self.db_metadata = self.root / ("metadata" + suffix + ".json")
        self.metadata_value = {
            "Version": 2,
            "UpdatedAt": (AT - timedelta(hours=1)).isoformat().replace("+00:00", "Z"),
            "DownloadedAt": (AT - timedelta(minutes=10)).isoformat().replace("+00:00", "Z"),
            "NextUpdate": (AT + timedelta(hours=12)).isoformat().replace("+00:00", "Z"),
        }
        self.write_json(self.db_metadata, self.metadata_value)

    @staticmethod
    def write_json(path, value):
        Path(path).write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")

    def args(self):
        return SimpleNamespace(
            archive=self.archive.resolve(),
            expected_manifest=self.manifest_digest,
            trivy=self.trivy.resolve(),
            sbom=self.sbom.resolve(),
            db=self.db.resolve(),
            db_metadata=self.db_metadata.resolve(),
        )


class HitoAScanTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-hito-a-scan-")
        self.root = Path(self.temporary.name)
        self.fixture = Fixture(self.root)

    def tearDown(self):
        self.temporary.cleanup()

    def test_exact_oci_inventory_trivy_sbom_and_database_pass(self):
        receipt = scan.verify(self.fixture.args(), at=AT)
        self.assertEqual(receipt["status"], "passed")
        self.assertEqual(receipt["manifest_digest"], self.fixture.manifest_digest)
        self.assertEqual(receipt["config_digest"], self.fixture.config_digest)
        self.assertEqual(receipt["inventory"]["packages"], {
            "lang-pkgs/python-pkg": 2, "os-pkgs/ubuntu": 2,
        })
        self.assertEqual(receipt["trivy"]["findings"]["LOW"], 1)
        self.assertEqual(receipt["trivy"]["findings"]["UNKNOWN"], 0)
        self.assertEqual(receipt["database"]["sha256"], hashlib.sha256(self.fixture.db.read_bytes()).hexdigest())
        self.assertTrue(all(receipt["gates"].values()))

    def test_unknown_high_and_critical_all_block(self):
        for index, severity in enumerate(("UNKNOWN", "HIGH", "CRITICAL"), start=1):
            fixture = Fixture(self.root, suffix="-severity-" + str(index))
            value = copy.deepcopy(fixture.trivy_value)
            value["Results"][1]["Vulnerabilities"][0]["Severity"] = severity
            fixture.write_json(fixture.trivy, value)
            with self.subTest(severity=severity), self.assertRaisesRegex(
                    scan.ScanBlocked, "trivy_blocking_finding"):
                scan.verify(fixture.args(), at=AT)

    def test_incomplete_trivy_or_sbom_package_inventory_blocks(self):
        trivy = copy.deepcopy(self.fixture.trivy_value)
        trivy["Results"][1]["Packages"].pop()
        self.fixture.write_json(self.fixture.trivy, trivy)
        with self.assertRaisesRegex(scan.ScanBlocked, "trivy_inventory_mismatch"):
            scan.verify(self.fixture.args(), at=AT)

        fixture = Fixture(self.root, suffix="-sbom-missing")
        sbom = copy.deepcopy(fixture.sbom_value)
        sbom["components"] = [row for row in sbom["components"] if row.get("name") != "uvicorn"]
        fixture.write_json(fixture.sbom, sbom)
        with self.assertRaisesRegex(scan.ScanBlocked, "sbom_inventory_mismatch"):
            scan.verify(fixture.args(), at=AT)

    def test_trivy_config_or_sbom_diffid_from_another_image_blocks(self):
        trivy = copy.deepcopy(self.fixture.trivy_value)
        trivy["Metadata"]["DiffIDs"] = ["sha256:" + "0" * 64]
        self.fixture.write_json(self.fixture.trivy, trivy)
        with self.assertRaisesRegex(scan.ScanBlocked, "trivy_oci_identity"):
            scan.verify(self.fixture.args(), at=AT)

        fixture = Fixture(self.root, suffix="-sbom-diff")
        sbom = copy.deepcopy(fixture.sbom_value)
        sbom["metadata"]["component"]["properties"][1]["value"] = "sha256:" + "1" * 64
        fixture.write_json(fixture.sbom, sbom)
        with self.assertRaisesRegex(scan.ScanBlocked, "sbom_oci_identity"):
            scan.verify(fixture.args(), at=AT)

    def test_compressed_layer_digest_and_uncompressed_diffid_are_not_interchangeable(self):
        source = self.fixture.archive
        replacement = self.root / "tampered.oci.tar"
        with tarfile.open(source, "r") as incoming, tarfile.open(replacement, "w") as outgoing:
            for member in incoming.getmembers():
                stream = incoming.extractfile(member)
                raw = stream.read() if stream is not None else b""
                if member.name.endswith(self.fixture.layer_digest[7:]):
                    raw = bytes([raw[0] ^ 1]) + raw[1:]
                add_bytes(outgoing, member.name, raw)
        args = self.fixture.args()
        args.archive = replacement.resolve()
        with self.assertRaisesRegex(scan.ScanBlocked, "layer_digest"):
            scan.verify(args, at=AT)

    def test_expired_or_reidentified_database_blocks_and_hash_is_recorded(self):
        metadata = copy.deepcopy(self.fixture.metadata_value)
        metadata["NextUpdate"] = (AT - timedelta(seconds=1)).isoformat().replace("+00:00", "Z")
        self.fixture.write_json(self.fixture.db_metadata, metadata)
        with self.assertRaisesRegex(scan.ScanBlocked, "trivy_db_freshness"):
            scan.verify(self.fixture.args(), at=AT)

        fixture = Fixture(self.root, suffix="-db-version")
        metadata = copy.deepcopy(fixture.metadata_value)
        metadata["Version"] = 1
        fixture.write_json(fixture.db_metadata, metadata)
        with self.assertRaisesRegex(scan.ScanBlocked, "trivy_db_metadata_version"):
            scan.verify(fixture.args(), at=AT)

    def test_demo_profile_rejects_ffmpeg_node_and_python_av(self):
        cases = {
            "ffmpeg": {"usr/bin/ffmpeg": b"fixture"},
            "node": {"usr/bin/node": b"fixture"},
            "av": {"opt/clipforge/venv/lib/python3.12/site-packages/av-14.0.dist-info/METADATA":
                   b"Metadata-Version: 2.4\nName: av\nVersion: 14.0\n"},
            "av-module-without-metadata": {
                "opt/clipforge/venv/lib/python3.12/site-packages/av/__init__.py": b"# fixture\n"
            },
            "vendored-libav": {"opt/clipforge/venv/lib/libavcodec.so.62": b"fixture"},
        }
        for index, (name, extra) in enumerate(cases.items(), start=1):
            fixture = Fixture(self.root, suffix="-profile-" + str(index), extra=extra)
            pattern = "demo_media_python_package" if name == "av" else "demo_forbidden_executable_or_node_metadata"
            with self.subTest(component=name), self.assertRaisesRegex(scan.ScanBlocked, pattern):
                scan.verify(fixture.args(), at=AT)

    def test_unreferenced_oci_file_and_duplicate_json_keys_block(self):
        replacement = self.root / "extra.oci.tar"
        with tarfile.open(self.fixture.archive, "r") as incoming, tarfile.open(replacement, "w") as outgoing:
            for member in incoming.getmembers():
                raw = incoming.extractfile(member).read()
                add_bytes(outgoing, member.name, raw)
            add_bytes(outgoing, "unreferenced.txt", b"not published")
        args = self.fixture.args()
        args.archive = replacement.resolve()
        with self.assertRaisesRegex(scan.ScanBlocked, "oci_unreferenced_file"):
            scan.verify(args, at=AT)

        fixture = Fixture(self.root, suffix="-duplicate-json")
        fixture.trivy.write_text('{"SchemaVersion":2,"SchemaVersion":2}\n', encoding="utf-8")
        with self.assertRaisesRegex(scan.ScanBlocked, "duplicate_json_key"):
            scan.verify(fixture.args(), at=AT)


if __name__ == "__main__":
    unittest.main()
