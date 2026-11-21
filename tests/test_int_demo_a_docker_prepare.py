"""Exercise only preparation guardrails with native request fixtures."""

from copy import deepcopy
from hashlib import sha256
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import Mock, patch

from scripts import int_demo_a_docker_prepare as preparation
from tests.test_int_demo_a_docker import fixture_receipt


COMMIT = "a" * 40


def hosted(profile):
    return {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24", "ImageVersion": "20261116.133.1",
            "GITHUB_REPOSITORY": preparation.REPO, "GITHUB_REF": preparation.BRANCH, "GITHUB_EVENT_NAME": "workflow_dispatch",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_RUN_ID": "42", "GITHUB_SHA": COMMIT,
            "GITHUB_WORKFLOW_REF": f"{preparation.REPO}/.github/workflows/{preparation.WORKFLOWS[profile]}@{preparation.BRANCH}"}


def row(name, version="2.39", depends="", provides=""):
    return {"name": name, "version": version, "architecture": "amd64", "status": "installed", "depends": depends,
            "pre_depends": "", "provides": provides}


def old_state():
    return {"docker-ce": row("docker-ce", "5:28.0.4-1~ubuntu.24.04~noble"),
            "docker-ce-cli": row("docker-ce-cli", "5:28.0.4-1~ubuntu.24.04~noble"),
            "containerd.io": row("containerd.io", preparation.TARGETS["containerd.io"].version,
                                 "libc6 (>= 2.38), libseccomp2 (>= 2.5.0)", "containerd, runc"),
            "libc6:amd64": row("libc6", "2.39-0ubuntu8.7", "libgcc1 | libgcc-s1 (>= 4.2)"),
            "libgcc-s1:amd64": row("libgcc-s1", "14.2.0", provides="libgcc1 (= 14.2.0)"),
            "libseccomp2:amd64": row("libseccomp2", "2.5.5"), "iptables": row("iptables", "1.8.10"),
            "nftables": row("nftables", "1.0.9"), "libsystemd0:amd64": row("libsystemd0", "255.4"),
            "init-system-helpers": row("init-system-helpers", "1.66ubuntu1")}


def target_state(old):
    return {**old, **{pkg.name: {**old[pkg.name], "version": pkg.version, "depends": pkg.depends, "pre_depends": pkg.pre_depends,
                                "provides": pkg.provides} for pkg in preparation.REVIEWED}}


def apt_text(changes):
    lines = [f"{len(changes)} upgraded, 0 newly installed, 0 to remove and 31 not upgraded."]
    for name, entry in changes.items():
        lines += [f"Inst {name} [{entry['before']}] ({entry['after']} local-deb [amd64])",
                  f"Conf {name} ({entry['after']} local-deb [amd64])"]
    return "\n".join(lines) + "\n"


def native_snapshot(status, *, prepared=False):
    toolchain = fixture_receipt()
    boot = {"distribution": {"id": "ubuntu", "version": "24.04", "architecture": "amd64"},
            "boot_id": toolchain["observation"]["boot_id"], "release": toolchain["kernel"]["release"]}
    engine = "29.10.0" if prepared else "28.0.4"
    toolchain["native"]["client"]["version"] = toolchain["native"]["server"]["version"] = toolchain["components"]["Engine"]["Version"] = engine
    toolchain["engine_settings"]["security"].insert(0, "name=apparmor")
    toolchain["packages"] = {name: status[name]["version"] for name in preparation.TARGETS}
    for path, (size, digest) in preparation.BINARIES.items():
        toolchain["files"][path].update(bytes=size, sha256=digest)
        toolchain["observation"]["files"][path]["bytes"] = size
    for index, (unit, path) in enumerate(preparation.SERVICES.items(), 101):
        toolchain["services"][unit] = deepcopy(toolchain["files"][path])
        process = toolchain["observation"]["processes"][unit]
        process.update(pid=str(index + (int(prepared) * 10)), executable=preparation.docker.live_from_file(toolchain["observation"]["files"][path]))
    return {"boot": boot, "toolchain": toolchain, "target_packages": toolchain["packages"]}


class DockerPrepareTests(unittest.TestCase):
    def test_context_separates_evaluation_and_protected_oidc_without_cloud_credentials(self):
        first = {**hosted("evaluate"), "INT_DOCKER_PREP_SELECTOR": "docker_prepare"}
        preparation.hosted(first, "evaluate", COMMIT)
        for changes in ({"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture"}, {"INT_DOCKER_PREP_SELECTOR": "full"},
                        {"RUNNER_ENVIRONMENT": "self-hosted"}, {"GITHUB_RUN_ATTEMPT": "2"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preparation.hosted({**first, **changes}, "evaluate", COMMIT)
        second = {**hosted("protected"), "INT_DOCKER_PREP_ENVIRONMENT": "int", "ACTIONS_ID_TOKEN_REQUEST_TOKEN": "fixture"}
        preparation.hosted(second, "protected", COMMIT)
        for changes in ({"GOOGLE_APPLICATION_CREDENTIALS": "fixture"}, {"REGISTRY_AUTH_FILE": "fixture"}, {"INT_DOCKER_PREP_ENVIRONMENT": "prod"}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                preparation.hosted({**second, **changes}, "protected", COMMIT)

    def test_only_exact_local_upgrades_no_unreviewed_install_removal_or_version(self):
        delta = preparation.requested_changes(old_state())
        raw = apt_text(delta)
        self.assertEqual(set(preparation.check_simulation(raw, delta)["Inst"]), {"docker-ce", "docker-ce-cli"})
        for invalid in (raw + "Remv dkms [3.0]\n", raw + "Inst extra (2.0 local-deb [amd64])\n", raw.replace("29.10.0", "29.9.3"),
                        raw.replace("0 to remove", "1 to remove"), raw + next(line for line in raw.splitlines() if line.startswith("Inst"))):
            with self.subTest(invalid=invalid), self.assertRaises(ValueError):
                preparation.check_simulation(invalid, delta)

    def test_dependency_closure_lists_installed_versions_and_actual_providers(self):
        target = target_state(old_state())
        with patch.object(preparation, "compare", return_value=True):
            closure = preparation.dependency_closure(target, Mock())
        self.assertEqual(closure["libc6:amd64"]["requirements"]["libgcc1 | libgcc-s1 (>= 4.2)"], ["libgcc-s1:amd64"])
        self.assertEqual(closure["libgcc-s1:amd64"]["version"], "14.2.0")
        self.assertEqual(len(closure), len(target))
        del target["libseccomp2:amd64"]
        with patch.object(preparation, "compare", return_value=True), self.assertRaisesRegex(ValueError, "dependency_not_installed"):
            preparation.dependency_closure(target, Mock())

    def test_portable_comparison_retains_build_kernel_and_protections_not_pid_or_boot_id(self):
        first = native_snapshot(target_state(old_state()), prepared=True)
        changed = deepcopy(first)
        observed = changed["toolchain"]["observation"]
        changed["boot"]["boot_id"] = observed["boot_id"] = "11111111-1111-1111-1111-111111111111"
        observed["run"] = "73"
        observed["socket"]["gid"] = 198
        observed["processes"]["docker.service"]["pid"] = "412"
        self.assertEqual(preparation.portable(first), preparation.portable(changed))
        changed["toolchain"]["runner_image"] = "20261116.133.1"
        self.assertNotEqual(preparation.portable(first), preparation.portable(changed))
        changed["toolchain"]["runner_image"] = first["toolchain"]["runner_image"]
        changed["toolchain"]["engine_settings"]["security"].pop(0)
        self.assertNotEqual(preparation.portable(first), preparation.portable(changed))

    def test_dpkg_and_restarts_use_only_fixed_sudo_commands(self):
        commands = Mock()
        apt_path = Path("/private-scratch/docker-ce-reviewed.deb")
        preparation.install_reviewed(commands, [apt_path])
        rows = [call.args for call in commands.run.call_args_list]
        self.assertEqual([stage for stage, _ in rows], ["stop_docker", "stop_containerd", "dpkg_install_reviewed",
                                                        "systemd_reload", "restart_containerd", "restart_docker"])
        self.assertEqual(rows[2][-1][-3:], [preparation.DPKG, "--install", str(apt_path)])
        self.assertTrue(all(argv[:3] == preparation.SUDO for _, argv in rows))

    def test_recipe_uses_only_bounded_environment_even_in_protected_job(self):
        report = {}
        command = preparation.Commands(Path("/private-scratch/home"), report)
        with patch.object(preparation, "run_diagnostic", return_value=("exited", 1, "", "native dpkg failure")) as native:
            with self.assertRaisesRegex(ValueError, "fixture"):
                command.run("fixture", [preparation.DPKG], extra={"APT_CONFIG": "/fixture/apt.conf"})
        self.assertEqual(set(native.call_args.kwargs["environment"]), {"PATH", "LC_ALL", "HOME", "APT_CONFIG"})
        self.assertEqual(report["commands"][0]["exit"], 1)
        self.assertEqual(report["commands"][0]["stderr_excerpt"], "native dpkg failure")

    def test_protected_mismatch_cannot_reach_install_and_evaluate_verifies_full_receipt(self):
        before, after = old_state(), target_state(old_state())
        initial, current = native_snapshot(before), native_snapshot(after, prepared=True)
        controls = {pkg.filename: f"Package: {pkg.name}\nArchitecture: amd64\nVersion: {pkg.version}\nDepends: {pkg.depends}\n"
                    f"Pre-Depends: {pkg.pre_depends}\nProvides: {pkg.provides}" for pkg in preparation.REVIEWED}
        delta = preparation.requested_changes(before)

        def run(stage, argv, **_):
            if stage == "architecture":
                return 0, "amd64"
            if stage == "deb_control":
                return 0, controls[Path(argv[-1]).name]
            if stage == "apt_simulation":
                return 0, apt_text(delta)
            return 0, ""

        for expected in ({"apt": {}, "after": {}}, None):
            with self.subTest(expected=expected), TemporaryDirectory() as directory:
                work = Path(directory)
                report = {"status": "blocked_before_install"}
                journal = work / "intent.json"
                commands = Mock()
                commands.run.side_effect = run
                with (patch.object(preparation, "Commands", return_value=commands), patch.object(preparation, "compare", return_value=True),
                      patch.object(preparation, "dpkg_state", side_effect=[before, before, after]),
                      patch.object(preparation, "snapshot", side_effect=[initial, current]), patch.object(preparation, "require_idle"),
                      patch.object(preparation, "download", side_effect=lambda scratch, pkg, _opener: scratch / pkg.filename),
                      patch.object(preparation, "verify_file"), patch.object(preparation, "boot_identity", return_value=initial["boot"]),
                      patch.object(preparation, "install_reviewed") as install):
                    if expected:
                        with self.assertRaisesRegex(ValueError, "expected_apt_closure_changed"):
                            preparation.prepare(hosted("protected"), work, journal, report, expected)
                        install.assert_not_called()
                        self.assertFalse(journal.exists())
                    else:
                        preparation.prepare(hosted("evaluate"), work, journal, report, expected)
                        self.assertEqual(report["status"], "prepared_verified")
                        self.assertEqual(report["publication_eligibility"], "eligible")
                        install.assert_called_once()
                        self.assertTrue(journal.exists())
                        self.assertEqual(set(report["comparison"]), {"apt", "after"})

    def test_vendor_deb_bytes_are_hash_and_size_checked_before_use(self):
        bytes_ = b"synthetic private file"
        pkg = preparation.Package("fixture", "1.1", len(bytes_), sha256(bytes_).hexdigest())
        with TemporaryDirectory() as directory:
            path = Path(directory) / "fixture.deb"
            path.write_bytes(bytes_)
            preparation.verify_file(path, pkg)
            path.write_bytes(b"x" * len(bytes_))
            with self.assertRaisesRegex(ValueError, "deb_hash"):
                preparation.verify_file(path, pkg)
            path.write_bytes(b"x")
            with self.assertRaisesRegex(ValueError, "deb_size"):
                preparation.verify_file(path, pkg)


if __name__ == "__main__":
    unittest.main()
