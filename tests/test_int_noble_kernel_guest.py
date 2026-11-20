from contextlib import redirect_stdout
import io
import json
import os
import unittest
from unittest.mock import patch

from scripts import int_noble_kernel_guest as k


BOOT = "01234567-1234-1234-1234-0123456789ab"
OTHER = "11234567-1234-1234-1234-0123456789ab"
KERNEL = "7.0.0-1017-gcp"


class NobleKernelGuestTests(unittest.TestCase):
    def report(self):
        with (patch.object(k, "identity", return_value=(BOOT, KERNEL)),
              patch.object(k, "run", return_value=(None, "")),
              patch.object(k, "read", side_effect=PermissionError),
              patch.object(k, "sysfs_module", side_effect=PermissionError),
              patch.object(k, "configured_module_loads", side_effect=PermissionError),
              patch.object(k, "configured_exports", side_effect=PermissionError)):
            return k.collect()

    def test_unknown_sections_remain_explicit_and_do_not_prevent_observation(self):
        report = self.report()
        self.assertEqual(k.validate(json.dumps(report).encode("ascii"), BOOT), report)
        self.assertTrue(all(value is None for value in report["listeners"].values()))
        self.assertTrue(all(value is None for value in report["units"].values()))
        self.assertEqual(report["modules"]["nfsd"], {"disk": None, "loaded": None, "sysfs": None})
        self.assertEqual(report["exports"], {"active": None, "configured": None})

    def test_report_rejects_changed_boot_large_duplicate_and_extra_fields(self):
        report = self.report()
        raw = json.dumps(report).encode()
        with self.assertRaisesRegex(ValueError, "invalid_identity"):
            k.validate(raw, OTHER)
        with self.assertRaisesRegex(ValueError, "invalid_payload_size"):
            k.validate(b" " * (k.MAX_OUTPUT + 1), BOOT)
        with self.assertRaisesRegex(ValueError, "duplicate_field"):
            k.validate(raw[:-1] + b', "boot_id":"other"}', BOOT)
        report["listeners"]["tcp"] = {str(port): 0 for port in k.PORTS} | {"remote_address": 42}
        with self.assertRaisesRegex(ValueError, "unexpected_fields"):
            k.validate(json.dumps(report).encode(), BOOT)

    def test_report_rejects_non_boolean_loaded_and_unbounded_numeric_counts(self):
        report = self.report()
        report["modules"]["xen_netback"]["loaded"] = 1
        with self.assertRaisesRegex(ValueError, "invalid_module_result"):
            k.validate(json.dumps(report).encode(), BOOT)
        report["modules"]["xen_netback"]["loaded"] = False
        report["exports"]["active"] = 262145
        with self.assertRaisesRegex(ValueError, "invalid_count"):
            k.validate(json.dumps(report).encode(), BOOT)

    def test_modprobe_inventory_does_not_evaluate_or_export_directives(self):
        rule = "\n".join(("install xen-netback /usr/bin/false", "blacklist xen-netback",
                          "alias private_bus_value xen-netback", "softdep ceph pre: nfsd",
                          "options ceph private_parameter=private_value", "remove nfsd arbitrary_command"))
        with patch.object(k, "run", return_value=(0, rule)) as run:
            result = k.modprobe_config()
        run.assert_called_once_with(["/usr/sbin/modprobe", "--showconfig"], limit=4*1024*1024)
        self.assertEqual(result["xen_netback"]["install"], "deny")
        self.assertEqual(result["xen_netback"]["blacklist"], 1)
        self.assertEqual(result["xen_netback"]["aliases"], 1)
        self.assertEqual(result["nfsd"]["dependencies"], 1)
        self.assertEqual(result["ceph"]["options"], 1)
        self.assertEqual(result["nfsd"]["remove_directives"], 1)
        self.assertNotIn("private", json.dumps(result))
        self.assertNotIn("arbitrary_command", json.dumps(result))

    def test_listeners_return_specific_port_counts_and_discard_addresses(self):
        sockets = ("sl local_address remote_address st\n"
                   "0: 998A04C0:0801 00000000:0000 0A\n"
                   "1: 998A04C0:0801 12345678:53AA 01\n"
                   "2: 998A04C0:FFFF 00000000:0000 0A\n")
        with patch.object(k, "read", return_value=sockets) as read:
            result = k.port_counts("/proc/net/tcp6", True)
        read.assert_called_once_with("/proc/net/tcp6", 262144)
        self.assertEqual(result, {"111":0, "2049":1, "3300":0, "6789":0})

    def test_main_keeps_identity_diagnostic_without_exception_text(self):
        with (patch.object(k, "collect", side_effect=OSError("an untrusted sensitive detail")),
              patch.object(k.sys, "argv", ["observer"]), redirect_stdout(io.StringIO()) as out):
            self.assertEqual(k.main(), 2)
        self.assertEqual(json.loads(out.getvalue()), {"error": "identity_or_protocol_unavailable", "schema": k.SCHEMA})

    @unittest.skipUnless(os.name == "posix", "selector subprocess pipes require POSIX")
    def test_runner_reads_bounded_ascii_with_real_subprocess(self):
        self.assertEqual(k.run(["/usr/bin/printf", "guest"]), (0, "guest"))
        self.assertEqual(k.run(["/usr/bin/printf", "guest"], limit=1), (None, ""))
        self.assertEqual(k.run(["/usr/bin/sleep", "1"], budget=0.01), (None, ""))


if __name__ == "__main__":
    unittest.main()
