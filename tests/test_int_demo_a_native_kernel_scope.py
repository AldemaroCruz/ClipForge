import unittest

from scripts import check_int_demo_a as gate


class NativeKernelScan(unittest.TestCase):
    revision = "7.0.0-1017.18~24.04.1"
    release = "7.0.0-1017-aws"

    def test_exact_running_image_and_modules_must_be_covered(self):
        names = [f"linux-image-{self.release}", f"linux-modules-{self.release}"]
        boot = {"packages": [[f"{name}:amd64", self.revision, "linux-aws-7.0", self.revision] for name in names]}
        image, modules = [f"pkg:deb/ubuntu/{name}@{self.revision.replace('~', '%7E')}?arch=amd64" for name in names]
        gate.verify_native_running_kernel_scan(boot, ["aws"], {"aws": [image, modules]})
        for packages in ([image], [image, modules.replace("1017.18", "1017.17")]):
            with self.subTest(packages=packages), self.assertRaisesRegex(ValueError, "running_kernel_scan_missing"):
                gate.verify_native_running_kernel_scan(boot, ["aws"], {"aws": packages})


if __name__ == "__main__":
    unittest.main()
