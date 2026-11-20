"""Offline regressions for the subsequent bounded INT readiness query."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import int_noble_demo_preflight_guest as demo
from scripts import int_noble_kernel_observation as observation


BOOT = "e1a4fb53-1970-490b-af37-5cccbbc99f32"


class ReadinessTests(unittest.TestCase):
    def test_nfs_absence_requires_host_namespace_and_unregistered_kernel_server(self):
        same = SimpleNamespace(st_dev=1, st_ino=42)
        another = SimpleNamespace(st_dev=1, st_ino=43)
        with (patch.object(demo.os, "stat", side_effect=[same, same, same, another]),
              patch.object(demo.kernel, "read", return_value="nodev\tproc\n"),
              patch.object(demo.kernel, "module_loaded_names", return_value=set()),
              patch.object(demo.kernel, "sysfs_module", return_value=False),
              patch.object(demo.kernel, "filesystem_counts", return_value={"nfsd": 0}),
              patch.object(demo.kernel, "active_exports", side_effect=FileNotFoundError),
              patch.object(demo.kernel, "configured_exports", return_value=0)):
            first = demo.nfs_exports()
            self.assertEqual(first["state"], "server_unregistered_in_host_mount_namespace")
            self.assertEqual(first["active_count"], 0)
            self.assertIsNone(demo.nfs_exports()["active_count"])

    def test_signed_target_simulation_requires_only_the_exact_upgrade(self):
        change = "Inst linux-tools-common [6.8.0-149.149] (6.8.0-151.151 Ubuntu:24.04/noble-updates [all])\n"
        with (patch.object(demo.kernel, "commands_output", return_value=demo.CURRENT + "\tinstalled\n"),
              patch.object(demo.kernel, "run", side_effect=[(0, change), (0, change + "Remv unrelated\n"), (100, "")]) as runner):
            self.assertTrue(demo.package_scope()["single_upgrade"])
            self.assertFalse(demo.package_scope()["single_upgrade"])
            self.assertEqual(demo.package_scope()["simulate_exit"], 100)
            self.assertIn("-s", runner.call_args.args[0])
            self.assertIn("--no-download", runner.call_args.args[0])

    def test_forwarding_uses_openssh_test_mode_and_closed_human_context(self):
        with patch.object(demo.kernel, "commands_output", return_value=(
                "allowtcpforwarding local\ndisableforwarding no\npermitopen 127.0.0.1:5432\n")) as query:
            self.assertEqual(demo.forwarding(demo.SAMPLES[0]), {"local_forwarding": True, "loopback_5432_allowed": True})
        command = query.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/sbin/sshd", "-T", "-C"])
        self.assertIn("user=admin_ixbalam_studio,", command[3])
        self.assertIn("laddr=10.80.1.3,lport=22", command[3])

    def test_unknown_stays_unknown_and_forged_absence_is_rejected(self):
        value = {"schema": demo.SCHEMA, "boot_id": BOOT, "release": "7.0.0-1017-gcp", "exports": None,
                 "ssh_samples": {k: None for k in demo.SAMPLES}, "package": None, "grub": None}
        self.assertEqual(demo.validate(json.dumps(value).encode(), BOOT), value)
        value["exports"] = {"host_mount_namespace": False, "registered_filesystem": False, "module_loaded": False,
                            "nfsd_mounts": 0, "active_count": 0, "configured_count": 0,
                            "state": "server_unregistered_in_host_mount_namespace"}
        with self.assertRaisesRegex(ValueError, "absence_unproven"):
            demo.validate(json.dumps(value).encode(), BOOT)

    def test_payload_scope_and_prior_kernel_run_are_pinned(self):
        prior = observation.payload_bytes()
        current = observation.payload_bytes(observation.DEMO_SCOPE)
        self.assertNotEqual(prior, current)
        compile(current, "<fixture>", "exec")
        with self.assertRaisesRegex(ValueError, "NOBLE_READ_SCOPE"):
            observation.payload_bytes("unreviewed")
        with (patch.object(observation.first, "checked_creation_runs"),
              patch.object(observation.postverify, "verify_github_run") as runs):
            observation.verify_handoff("fixture", observation.DEMO_SCOPE)
        runs.assert_any_call("44789936845", observation.KERNEL_CONTROLS, "fixture", observation.WORKFLOW, "success")


if __name__ == "__main__":
    unittest.main()
