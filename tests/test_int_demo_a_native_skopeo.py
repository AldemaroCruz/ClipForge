import os
from pathlib import Path
import struct
import subprocess
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_demo_a_native_skopeo as native
from scripts import int_guest_inventory as transport


TEMPLATE = b'{"default":[{"type":"reject"}],"transports":{"oci-archive":{"/input/image.oci.tar":[{"type":"insecureAcceptAnything"}]}}}'


class NativeSkopeoTests(unittest.TestCase):
    def test_production_ref_only_accepts_the_two_exact_manifests(self):
        with patch.object(native, "_run_copy", return_value=19) as run:
            for dest in native.TARGETS:
                self.assertEqual(native.copy("/work/native", "/work/image.oci.tar", "/work/auth.json", dest), 19)
            for dest in ("example.invalid/runtime@" + "sha256:" + "a" * 64,
                         "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime:latest"):
                with self.assertRaisesRegex(transport.Blocked, "destination_not_approved"):
                    native.copy("/work/native", "/work/image.oci.tar", "/work/auth.json", dest)
            self.assertEqual(run.call_count, 2)

    def test_args_fix_privilege_tls_and_registry_policy(self):
        root = Path("/work/native")
        target = sorted(native.TARGETS)[0]
        result = native._args(root, Path("/work/input.oci.tar"), Path("/work/auth.json"), target, root / "certs.d", "/work/tmp")
        self.assertEqual(result[:5], ["/usr/bin/setpriv", "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--"])
        self.assertEqual(result[-2:], ["oci-archive:/work/input.oci.tar", "docker://" + target])
        for option in ("--retry-times=0", "--preserve-digests", "--dest-tls-verify=true", "--policy=/work/tmp/policy.json",
                       "--registries.d=/work/native/registries.d", "--dest-cert-dir=/work/native/certs.d",
                       "--dest-authfile=/work/auth.json"):
            self.assertIn(option, result)

    def test_copy_uses_clean_environment_and_propagates_native_exit(self):
        with TemporaryDirectory() as temp:
            root = Path(temp) / "native"
            root.mkdir()
            (root / "tmp").mkdir()
            (root / "policy.json").write_bytes(TEMPLATE)
            source = root.parent / "archive.oci.tar"
            source.write_bytes(b"fixture")
            source.chmod(0o400)
            auth = root.parent / "auth.json"
            auth.write_bytes(b"fixture auth")
            auth.chmod(0o400)
            with patch.object(native, "verify"), patch.object(native.subprocess, "run") as run, patch.dict(
                os.environ, {"GCP_ACCESS_TOKEN": "fixture", "DOCKER_HOST": "fixture", "HTTPS_PROXY": "fixture"}
            ):
                run.return_value.returncode = 23
                self.assertEqual(native.copy(root, source, auth, sorted(native.TARGETS)[0]), 23)
            kwargs = run.call_args.kwargs
            self.assertFalse({"GCP_ACCESS_TOKEN", "DOCKER_HOST", "HTTPS_PROXY"} & set(kwargs["env"]))
            self.assertEqual(kwargs["env"]["SSL_CERT_FILE"], str(root / "ca.pem"))
            self.assertEqual(kwargs["env"]["CONTAINERS_REGISTRIES_CONF"], str(root / "registries.conf"))
            self.assertNotIn("CONTAINERS_REGISTRIES_CONF_OVERRIDE", kwargs["env"])
            self.assertEqual(kwargs["timeout"], 360)
            self.assertEqual(kwargs["stderr"], subprocess.DEVNULL)
            self.assertFalse(Path(kwargs["cwd"]).exists())

    def test_policy_rebinds_exactly_one_oci_path_and_never_the_default(self):
        target = Path("/work/runtime.oci.tar")
        policy = transport.decode(native.native_policy(TEMPLATE, target))
        self.assertEqual(policy["default"], [{"type": "reject"}])
        self.assertEqual(policy["transports"], {"oci-archive": {str(target): [{"type": "insecureAcceptAnything"}]}})
        with self.assertRaisesRegex(transport.Blocked, "policy_exact_source_only"):
            native.native_policy(TEMPLATE.replace(b'"reject"', b'"insecureAcceptAnything"'), target)

    def test_rejects_substituted_archive_before_staging_any_file(self):
        with TemporaryDirectory() as temp:
            archive = Path(temp) / "publisher.oci.tar"
            with archive.open("wb") as out:
                out.truncate(native.ARCHIVE_BYTES)
            root = Path(temp) / "native"
            with patch.object(native, "verify_privilege"), self.assertRaisesRegex(transport.Blocked, "publisher_archive"):
                native.stage(archive, root)
            self.assertFalse(root.exists())

    def test_rejects_a_dynamic_loader(self):
        with TemporaryDirectory() as temp:
            binary = Path(temp) / "skopeo"
            header = bytearray(64 + 56)
            header[:7] = b"\x7fELF\x02\x01\x01"
            struct.pack_into("<HH", header, 16, 2, 62)
            struct.pack_into("<Q", header, 32, 64)
            struct.pack_into("<HH", header, 54, 56, 1)
            struct.pack_into("<I", header, 64, 3)
            binary.write_bytes(header)
            with self.assertRaisesRegex(transport.Blocked, "dynamic_loader"):
                native.verify_static_elf(binary)


if __name__ == "__main__":
    unittest.main()
