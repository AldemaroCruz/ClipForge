from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import tarfile
from tempfile import TemporaryDirectory
import unittest

from scripts import int_demo_a_publish as publish


def descriptor(raw, media_type):
    return {"digest": "sha256:" + sha256(raw).hexdigest(), "size": len(raw), "mediaType": media_type}


def write_oci(path, *, nested=False):
    layer = b"known-compressed-blob"
    config = json.dumps({"os": "linux", "architecture": "amd64", "rootfs": {"type": "layers", "diff_ids": ["known"]}}).encode()
    layer_ref = descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")
    config_ref = descriptor(config, "application/vnd.oci.image.config.v1+json")
    manifest = json.dumps({"schemaVersion": 2, "mediaType": publish.MANIFEST, "config": config_ref, "layers": [layer_ref]}).encode()
    manifest_ref = descriptor(manifest, "application/vnd.oci.image.index.v1+json" if nested else publish.MANIFEST)
    objects = {"index.json": json.dumps({"manifests": [manifest_ref]}).encode(), "oci-layout": b'{"imageLayoutVersion":"1.0.0"}',
               **{"blobs/sha256/" + row["digest"][7:]: blob for row, blob in
                  ((layer_ref, layer), (config_ref, config), (manifest_ref, manifest))}}
    with tarfile.open(path, "x:") as archive:
        for name, raw in objects.items():
            entry = tarfile.TarInfo(name)
            entry.size = len(raw)
            archive.addfile(entry, BytesIO(raw))
    return manifest_ref["digest"], publish.digest_file(path)


class RestrictedPublisher(unittest.TestCase):
    def test_other_build_receipt_is_rejected_before_loading_the_image(self):
        with self.assertRaisesRegex(ValueError, "demo_a_exact_publisher_build_receipt"):
            publish.verify_build(Path("/fixture"), {"build_sha256": "0" * 64}, {})

    def test_source_never_changes_and_all_staged_entries_have_the_publisher_identity(self):
        with TemporaryDirectory() as folder:
            source, staged = (Path(folder) / name for name in ("source.tar", "staged.tar"))
            pins = write_oci(source)
            expected = publish.archive_inventory(source, pins)
            publish.verified_staging_archive(source, staged, expected, 12345, 23456)
            self.assertEqual(publish.digest_file(source), pins[1])
            with tarfile.open(staged) as archive:
                self.assertEqual({(member.uid, member.gid) for member in archive}, {(12345, 23456)})
                self.assertTrue(archive.getmember("blobs").isdir())
                self.assertTrue(archive.getmember("blobs/sha256").isdir())
            with self.assertRaises(FileExistsError):
                publish.verified_staging_archive(source, staged, expected, 12345, 23456)

    def test_rejects_nested_index_before_staging(self):
        with TemporaryDirectory() as folder:
            source = Path(folder) / "index.tar"
            pins = write_oci(source, nested=True)
            with self.assertRaisesRegex(ValueError, "demo_a_index_or_platform_fanout_not_authorized"):
                publish.archive_inventory(source, pins)

    def test_copy_keeps_source_readonly_and_tls_enforced(self):
        argv = publish.copy_args("sha256:" + "a" * 64, Path("/tmp/layout.tar"), Path("/tmp/auth.json"),
                                 "registry/lab/repo@sha256:" + "b" * 64, user="12345:23456")
        self.assertIn("--mount=type=bind,source=/tmp/layout.tar,target=/input/image.oci.tar,readonly", argv)
        self.assertIn("--mount=type=bind,source=/tmp/auth.json,target=/authorization/auth.json,readonly", argv)
        self.assertIn("--cap-drop=ALL", argv)
        self.assertIn("--preserve-digests", argv)
        self.assertIn("--dest-tls-verify=true", argv)
        self.assertNotIn("--all", argv)


if __name__ == "__main__":
    unittest.main()
