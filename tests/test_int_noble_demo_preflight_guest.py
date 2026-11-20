"""Offline regressions for the subsequent bounded INT readiness query."""
import json
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import int_noble_demo_preflight_guest as demo
from scripts import int_noble_kernel_observation as observation


BOOT = "e1a4fb53-1970-490b-af37-5cccbbc99f32"
OK = ("exited", 0, "", "")
APT_PLAN = ("1 upgraded, 0 newly installed, 0 to remove and 0 not upgraded.\n"
            "Inst linux-tools-common [6.8.0-149.149] (6.8.0-151.151 local-deb [all])\n"
            "Conf linux-tools-common (6.8.0-151.151 local-deb [all])\n")


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
        self.assertTrue(demo.upgrade(("exited", 0, APT_PLAN, ""), demo.CURRENT)["exact_upgrade"])
        for output in (APT_PLAN + "Remv unrelated\n", APT_PLAN.replace("0 newly installed", "1 newly installed")):
            self.assertFalse(demo.upgrade(("exited", 0, output, ""), demo.CURRENT)["exact_upgrade"])
        self.assertFalse(demo.upgrade(("exited", 100, APT_PLAN, ""), demo.CURRENT)["exact_upgrade"])

    def test_original_apt_failure_retains_exit_and_closed_stderr(self):
        dpkg = ("exited", 0, demo.CURRENT + "\tinstalled\n", "")
        policy = ("exited", 0, "  Candidate: 6.8.0-149.149\n", "")
        err = "E: Version '6.8.0-151.151' for 'linux-tools-common' was not found\nunknown omitted diagnostic\n"
        with patch.object(demo, "run_diagnostic", side_effect=[dpkg, policy, ("exited", 100, "", err)]) as runner:
            report = demo.package_scope()
            self.assertEqual(report["original_simulation"]["command"], {"process": "exited", "exit": 100,
                              "stderr_markers": ["target_version_not_found"], "unclassified_stderr_lines": 1})
            self.assertFalse(report["apt_index_target_present"])
            self.assertNotIn("unknown omitted", json.dumps(report))
            self.assertIn("-s", runner.call_args.args[0])
            self.assertIn("--no-download", runner.call_args.args[0])
            demo.check_package(report)

    def test_forwarding_uses_openssh_test_mode_and_closed_human_context(self):
        output = "allowtcpforwarding local\ndisableforwarding no\npermitopen 127.0.0.1:5432\nusedns no\n"
        with patch.object(demo, "run_diagnostic", return_value=("exited", 0, output, "")) as query:
            row = demo.forwarding(demo.SAMPLES[0])
        self.assertEqual(row["state"], "evaluated")
        self.assertEqual(row["allowtcpforwarding"], "local")
        self.assertFalse(row["disableforwarding"])
        self.assertTrue(row["loopback_5432_allowed"])
        command = query.call_args.args[0]
        self.assertEqual(command[:3], ["/usr/sbin/sshd", "-T", "-C"])
        self.assertIn("user=admin_ixbalam_studio,", command[3])
        self.assertIn("laddr=10.80.1.3,lport=22", command[3])

    def test_forwarding_distinguishes_missing_host_keys_from_policy(self):
        failure = ("exited", 1, "", "Unable to load host key: /ignored/private/path\nsshd: no hostkeys available -- exiting.\n")
        with patch.object(demo, "run_diagnostic", side_effect=[failure, OK]):
            refused = demo.forwarding(demo.SAMPLES[0])
            incomplete = demo.forwarding(demo.SAMPLES[1])
        self.assertEqual(refused["state"], "command_failed")
        self.assertEqual(refused["command"]["exit"], 1)
        self.assertEqual(refused["command"]["stderr_markers"], ["host_key_unavailable"])
        self.assertIsNone(refused["loopback_5432_allowed"])
        self.assertNotIn("/ignored/private/path", json.dumps(refused))
        self.assertEqual(incomplete["state"], "unexpected_output")

    def test_unknown_stays_unknown_and_forged_absence_is_rejected(self):
        with (patch.object(demo.kernel, "identity", return_value=(BOOT, "7.0.0-1017-gcp")),
              patch.object(demo, "run_diagnostic", return_value=("timeout", None, "", "")),
              patch.object(demo, "nfs_exports", return_value=None), patch.object(demo, "grub_scope", return_value=None)):
            value = demo.collect()
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
