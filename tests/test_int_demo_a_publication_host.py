import json
from pathlib import Path
import sys
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import int_demo_a_publication_host as host


ENV = {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40, "GITHUB_JOB": "observe-host",
       "ImageVersion": "20261116.133.1", "ImageOS": "ubuntu24", "RUNNER_ENVIRONMENT": "github-hosted"}
BOOT_ID = "530bddf3-81bd-4467-bcb7-5f9f4c376396"


class PublicationHostObservation(unittest.TestCase):
    def observe_fixture(self, *, family="aws", abi="1018", revision="19", release_override=None,
                        version_override=None, read_failure=None, worker_error=None):
        release = release_override or f"7.0.0-{abi}-{family}"
        version = version_override or f"7.0.0-{abi}.{revision}~24.04.1"
        signature = f"Ubuntu {version}-{family} 7.0.0"
        packages = [[f"linux-image-{release}", version, f"linux-signed-{family}-7.0", version],
                    [f"linux-modules-{release}", version, f"linux-{family}-7.0", version]]
        files = {
            "/proc/version_signature": signature,
            "/proc/sys/kernel/random/boot_id": BOOT_ID,
            "/proc/self/status": "CapEff:\t0000000000000000\nCapBnd:\t0000003fffffffff\nNoNewPrivs:\t0\n",
            "/proc/modules": "ib_core 1 0 - Live 0x0\n",
            f"/boot/config-{release}": "CONFIG_RDMA_SIW=m\nCONFIG_INFINIBAND=y\n# CONFIG_INFINIBAND_USER_ACCESS is not set\n",
            f"/lib/modules/{release}/modules.builtin": "kernel/drivers/infiniband/core/ib_core.ko\n",
            f"/lib/modules/{release}/modules.dep": "kernel/drivers/infiniband/sw/siw/siw.ko.zst:\n",
            **{path: "0\n" for path in host.CONTROL_PATHS.values()},
        }

        def read(path, limit):
            if str(path) == read_failure:
                raise PermissionError("raw read error must not be in receipt")
            return files[str(path)]

        def worker():
            if worker_error:
                raise worker_error
            return {"runner_worker": Path("/fixture/Runner.Worker"), "node24": Path("/fixture/node")}

        with (TemporaryDirectory() as tmp, patch.object(host.os, "uname",
                  return_value=SimpleNamespace(release=release, machine="x86_64")),
              patch.object(host.os, "getuid", return_value=1001), patch.object(host.os, "geteuid", return_value=1001),
              patch.object(host.os, "getgid", return_value=1001), patch.object(host.os, "getgroups", return_value=[1001]),
              patch.object(host, "SYSTEM_FILES", {**host.SYSTEM_FILES, "python": sys.executable}),
              patch.object(host, "bounded_text", side_effect=read), patch.object(host, "package_inventory", return_value=packages),
              patch.object(host, "runner_executables", side_effect=worker), patch.object(host, "ssl_dependencies",
                  return_value={name: Path("/fixture/" + name) for name in ("libc", "libssl", "libcrypto")}),
              patch.object(host, "file_identity", return_value={"sha256": "b" * 64, "bytes": 100}),
              patch.object(host, "rdma_devices", return_value={"present": False, "count": 0}),
              patch.object(host, "docker_socket", return_value=None), patch("builtins.print")):
            output = Path(tmp) / "host.json"
            result = host.observe(ENV, output)
            self.assertTrue(output.is_file())
            return result, json.loads(output.read_bytes())

    def test_aws_keeps_full_observation_and_requires_review(self):
        code, report = self.observe_fixture()
        self.assertEqual(code, 0)
        self.assertEqual(report["status"], "host_observed_review_required")
        self.assertEqual(report["host"]["family"], "aws")
        self.assertEqual(report["boot_id"], BOOT_ID)
        self.assertEqual(report["host"]["kernel"]["abi"], "1018")
        self.assertEqual(report["host"]["kernel"]["version"], "7.0.0-1018.19~24.04.1")
        self.assertEqual(report["host"]["kernel"]["packages"], report["binary_source_packages"])
        self.assertEqual(report["host"]["module_evidence"]["packaged"], ["siw"])
        self.assertEqual(report["host"]["module_evidence"]["loaded"], ["ib_core"])
        self.assertFalse(report["activation_authorized"])
        host.checked(report["host"])

    def test_azure_and_aws_have_independent_floors(self):
        code, report = self.observe_fixture(family="azure", abi="1020", version_override="7.0.0-1020.21~24.04.2")
        self.assertEqual(code, 0)
        self.assertEqual(report["host"]["family"], "azure")
        self.assertFalse(report["activation_authorized"])
        for family, abi, version in [("azure", "1018", "7.0.0-1018.19~24.04.1"),
                                     ("aws", "1014", "7.0.0-1014.14~24.04.1")]:
            with self.subTest(family=family):
                code, old = self.observe_fixture(family=family, abi=abi, version_override=version)
                self.assertEqual(code, 1)
                self.assertEqual(old["reason"], "native_publication_kernel_below_reviewable_floor")
                self.assertEqual(old["host"]["kernel"]["version"], version)
                self.assertFalse(old["activation_authorized"])

    def test_unknown_family_retains_boot_inventory_and_tools(self):
        code, report = self.observe_fixture(family="generic")
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "host_rejected")
        self.assertEqual(report["reason"], "native_publication_kernel_family_unsupported")
        self.assertEqual(report["host"]["family"], "unknown")
        self.assertEqual(report["host"]["kernel"]["release"], "7.0.0-1018-generic")
        self.assertEqual(report["boot_id"], BOOT_ID)
        self.assertIn("bash", report["host"]["tools"])
        self.assertEqual(len(report["binary_source_packages"]), 2)
        self.assertFalse(report["activation_authorized"])
        with self.assertRaises(host.HostBlocked):
            host.checked(report["host"])

    def test_failed_proc_and_worker_reads_keep_independent_evidence(self):
        code, report = self.observe_fixture(read_failure="/proc/version_signature",
                                            worker_error=PermissionError("worker proc path"))
        self.assertEqual(code, 1)
        self.assertEqual(report["status"], "host_rejected")
        self.assertEqual(report["errors"], {"kernel_signature": "PermissionError", "runner_executables": "PermissionError"})
        self.assertIsNone(report["host"]["kernel"]["signature"])
        self.assertEqual(report["host"]["kernel"]["version"], "7.0.0-1018.19~24.04.1")
        self.assertEqual(report["boot_id"], BOOT_ID)
        self.assertIn("libssl", report["host"]["tools"])
        self.assertNotIn("worker proc path", repr(report))
        self.assertFalse(report["activation_authorized"])
        with patch.object(host, "snapshot", return_value=(report, report["binary_source_packages"])):
            with self.assertRaises(host.HostBlocked):
                host.verify({}, report["host"])

    def test_related_kernel_package_revision_must_match(self):
        _, report = self.observe_fixture()
        report["host"]["kernel"]["packages"][1][1] = "7.0.0-1017.18~24.04.1"
        with self.assertRaisesRegex(host.HostBlocked, "native_publication_running_kernel_packages_mismatch"):
            host.checked(report["host"])


if __name__ == "__main__":
    unittest.main()
