import json
from pathlib import Path
import unittest

from scripts import int_demo_a_docker as docker
from scripts import int_demo_a_docker_apparmor as probe


class LocalCommands:
    home = Path("/tmp/clipforge-test")

    def __init__(self, label=probe.ENFORCED):
        self.label = label
        self.calls = []
        self.identifier = "a" * 64
        self.image = "sha256:" + "b" * 64

    def run(self, label, argv, **options):
        self.calls.append((label, argv))
        if label.endswith("_container_start"):
            return 0, self.identifier
        if label.endswith("_container_inspect"):
            return 0, "\n".join(json.dumps(item) for item in (self.identifier, self.image, 621, probe.PROFILE))
        if label.endswith("_kernel_label"):
            return 0, self.label
        if label.endswith("_proc_status"):
            return 0, "Pid:\t621\nNoNewPrivs:\t1\nSeccomp:\t2"
        if label.endswith("_loaded_profiles"):
            return 0, probe.ENFORCED
        return 0, ""


class AppArmorTests(unittest.TestCase):
    def setUp(self):
        self.common = ["name=seccomp,profile=builtin", "name=cgroupns"]
        self.before = [probe.OLD, *self.common]
        self.after = [probe.NEW, *self.common]
        sample = {"kernel_label": probe.ENFORCED, "loaded": True, "seccomp_mode": 2, "no_new_privileges": True}
        self.native = {"before": dict(sample), "after": dict(sample)}

    def test_recorded_option_delta_requires_native_enforcement(self):
        with self.assertRaisesRegex(docker.ToolchainBlocked, "apparmor_enforcement_unverified"):
            probe.enforce_options(self.before, self.after, {})
        probe.enforce_options(self.before, self.after, self.native)

    def test_custom_or_missing_protection_is_not_admitted(self):
        for after in (self.common, ["name=apparmor,profile=unconfined", *self.common], [probe.NEW, self.common[0]]):
            with self.subTest(after=after), self.assertRaisesRegex(docker.ToolchainBlocked, "effective_protections_regressed"):
                probe.enforce_options(self.before, after, self.native)

    def test_default_profile_is_bound_to_actual_process_and_removes_owned_probe(self):
        commands = LocalCommands()
        report = probe.confinement(commands, commands.image, "after")
        self.assertEqual(report["pid"], 621)
        calls = {key: argv for key, argv in commands.calls}
        self.assertIn("/proc/621/attr/apparmor/current", calls["apparmor_after_kernel_label"])
        self.assertNotIn("apparmor=unconfined", calls["apparmor_after_container_start"])
        self.assertTrue(calls["apparmor_after_cleanup"][-1].startswith("clipforge-hosted-aa-"))
        self.assertEqual([key for key, _ in commands.calls].count("apparmor_after_container_inspect"), 2)

    def test_kernel_complain_mode_still_blocks_and_cleans(self):
        commands = LocalCommands(label="docker-default (complain)")
        with self.assertRaisesRegex(docker.ToolchainBlocked, "apparmor_enforcement_unverified"):
            probe.confinement(commands, commands.image, "after")
        self.assertEqual(commands.calls[-1][0], "apparmor_after_cleanup")


if __name__ == "__main__":
    unittest.main()
