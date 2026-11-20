import hashlib
import json
import sys
import unittest
from unittest.mock import call, patch

from scripts import int_noble_kernel_consumers_guest as probe
from scripts import int_noble_kernel_observation as observer
from tests import test_int_noble_kernel_guest as baseline_tests


BOOT = baseline_tests.BOOT
KERNEL = baseline_tests.KERNEL
OTHER = baseline_tests.OTHER


class ConsumerTests(unittest.TestCase):
    def test_legacy_payloads_and_exact_new_runner_scope(self):
        previous = {"kernel": "8563467b6bd43dcf74820b98a937e936892bcd61e64a53018fa06eedce3e33d6",
                    "demo-readiness": "972eee8c5fe832f07e4b3a2ff529f5cdfd5352141336a2dad34b8bca155bca38"}
        for scope, expected in previous.items():
            self.assertEqual(hashlib.sha256(observer.payload_bytes(scope)).hexdigest(), expected)
        with patch.dict(sys.modules):
            namespace = {"__name__": "guest_fixture"}
            exec(compile(observer.payload_bytes(observer.CONSUMERS_SCOPE), "<guest fixture>", "exec"), namespace)
            self.assertEqual(namespace["SCHEMA"], probe.SCHEMA)
            self.assertEqual(namespace["kernel"].MODULES, probe.kernel.MODULES)
        with (patch.object(observer.first, "checked_creation_runs"),
              patch.object(observer.postverify, "verify_github_run") as observation):
            observer.verify_handoff("fixture", observer.CONSUMERS_SCOPE)
        self.assertEqual(observation.call_args_list[-1], call(observer.KERNEL_RUN, observer.KERNEL_CONTROLS,
                                                              "fixture", observer.WORKFLOW, "success"))

    def test_alias_and_direct_kmod_queries_are_dry_and_sanitized(self):
        empty, install = (0, ""), (0, "install /bin/false\n")
        with patch.object(probe.kernel, "run", side_effect=[(0, "fs-ceph\n"), empty, install]) as run:
            self.assertEqual(probe.module_aliases(KERNEL, "ceph"), ["no_action_reported"])
            self.assertEqual(probe.dry_run("ceph"), "deny_install")
        self.assertEqual(run.call_args_list, [
            call(["/usr/sbin/modinfo", "-k", KERNEL, "-F", "alias", "ceph"], limit=4096),
            call(["/usr/sbin/modprobe", "--dry-run", "--verbose", "--use-blacklist", "--", "fs-ceph"], limit=16384),
            call(["/usr/sbin/modprobe", "--dry-run", "--verbose", "--", "ceph"], limit=16384),
        ])
        with patch.object(probe.kernel, "run", return_value=(0, "xen-backend:*\n")):
            self.assertIsNone(probe.kernel.optional(lambda: probe.module_aliases(KERNEL, "xen_netback")))
        with patch.object(probe.kernel, "run", return_value=(0, "install /bin/false private-command\n")):
            self.assertEqual(probe.dry_run("ceph"), "other")

    def test_ceph_selects_known_packages_and_remote_established_or_opening_connections(self):
        inventory = "ceph-common\tconfig-files\nlibcephfs2:amd64\tinstalled\nother-package\tinstalled\n"
        sockets = ("sl local_address rem_address st\n"
                   "0: 0100007F:1000 0100007F:0CE4 01\n"
                   "1: 0100007F:1A85 00000000:0000 0A\n"
                   "2: 0100007F:1000 0100007F:1A85 02\n"
                   "3: 0100007F:1000 0100007F:0CE4 06\n")
        with patch.object(probe.kernel, "commands_output", return_value=inventory):
            self.assertEqual(probe.ceph_packages(), {"ceph-common": False, "ceph-fuse": False,
                                                    "libcephfs2": True, "rbd-nbd": False})
        with patch.object(probe.kernel, "read", side_effect=[sockets, PermissionError]):
            self.assertIsNone(probe.kernel.optional(probe.ceph_remote_sockets))
        with patch.object(probe.kernel, "read", return_value=sockets):
            self.assertEqual(probe.ceph_remote_sockets(), 4)

    def test_cmdline_reports_only_the_reviewed_effective_kernel_flags(self):
        args = "root=private-uuid module_blacklist=xen-netback,ceph -- module_blacklist=nfsd"
        with patch.object(probe.kernel, "read", return_value=args):
            self.assertEqual(probe.boot_blacklist(), {"xen_netback": True, "ceph": True, "nfsd": False})
        with patch.object(probe.kernel, "read", return_value="module_blacklist=xen_netback module_blacklist=nfsd"):
            self.assertIsNone(probe.kernel.optional(probe.boot_blacklist))

    def test_private_ip_selects_one_nic_and_reports_only_its_driver_class(self):
        value = json.dumps([{"ifname": "ens4", "addr_info": [{"local": probe.PRIVATE_IP}]},
                            {"ifname": "ens5", "addr_info": [{"local": "192.0.2.1"}]}])
        with (patch.object(probe.kernel, "commands_output", return_value=value),
              patch.object(probe.os, "readlink", return_value="../../../bus/pci/drivers/gve") as link):
            self.assertEqual(probe.nic_driver(), "gve")
        self.assertEqual(link.call_args.args[0].parts[-3:], ("ens4", "device", "driver"))

    def test_indeterminate_results_remain_null_and_scope_is_closed(self):
        baseline = baseline_tests.NobleKernelGuestTests().report()
        with (patch.object(probe.kernel, "collect", return_value=baseline),
              patch.object(probe.kernel, "identity", return_value=(BOOT, KERNEL)),
              patch.object(probe.kernel, "run", return_value=(None, "")),
              patch.object(probe.kernel, "read", side_effect=PermissionError),
              patch.object(probe, "kmod_rule_state", side_effect=PermissionError),
              patch.object(probe.os, "scandir", side_effect=PermissionError)):
            actual = probe.collect()
        raw = json.dumps(actual).encode("ascii")
        self.assertEqual(observer.check_guest(raw, 0, BOOT, observer.CONSUMERS_SCOPE), actual)
        self.assertIsNone(actual["xen"]["backend_vifs"])
        self.assertIsNone(actual["ceph"]["pid1_mounts"])
        self.assertIsNone(actual["ceph"]["packages"])
        self.assertIsNone(actual["kmod"]["scope_rule"])
        self.assertIsNone(actual["kmod"]["dry_run"]["ceph"]["aliases"])
        with self.assertRaisesRegex(ValueError, "invalid_identity"):
            probe.validate(raw, OTHER)
        with self.assertRaisesRegex(ValueError, "duplicate_consumer_field"):
            probe.validate(raw[:-1] + b', "schema":"duplicate"}', BOOT)
        actual["ceph"]["remote_address"] = "private"
        with self.assertRaisesRegex(ValueError, "unexpected_fields"):
            probe.validate(json.dumps(actual).encode(), BOOT)


if __name__ == "__main__":
    unittest.main()
