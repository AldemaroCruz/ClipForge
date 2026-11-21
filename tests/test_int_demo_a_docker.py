from copy import deepcopy
from pathlib import Path
import stat
import unittest
from unittest.mock import patch

from scripts import int_demo_a_docker as docker


def fixture_receipt():
    files, metadata = {}, {}
    for index, (name, package) in enumerate(docker.BINARY_PACKAGES.items(), 1):
        reserved = {"bytes": 2048, "mode": stat.S_IFREG | 0o755, "uid": 0, "gid": 0}
        files[name] = {"path": name, "package": package, "sha256": f"{index:064x}", **reserved}
        metadata[name] = {"device": 23, "inode": index, "mtime_ns": 1000000000, "ctime_ns": 1000000000, **reserved}
    services = {name: deepcopy(files[path]) for name, path in docker.SERVICE_BINARIES.items()}
    processes = {name: {"pid": str(index), "start_ticks": "120", "executable": docker.live_from_file(metadata[path])}
                 for index, (name, path) in enumerate(docker.SERVICE_BINARIES.items(), 102)}
    native = {"version": "29.10.0", "apiversion": "1.54", "gitcommit": "review-fixture", "os": "linux", "arch": "amd64"}
    socket = {"device": 14, "inode": 555, "mtime_ns": 1000000000, "ctime_ns": 1000000000,
              "bytes": 0, "mode": stat.S_IFSOCK | 0o660, "uid": 0, "gid": 992}
    package = "linux-image-7.0.0-1017-aws"
    return {"schema": docker.SCHEMA, "runner_image": "20261116.376.1", "image_os": "ubuntu24",
            "platform": {"distribution": "ubuntu", "version": "24.04", "architecture": "amd64", "kernel_family": "aws"},
            "context": {"name": "default", "endpoint": "unix:///run/docker.sock"}, "packages": dict(docker.PACKAGE_VERSIONS),
            "socket": docker.SOCKET, "socket_security": {"mode": socket["mode"], "uid": 0, "group": "docker"},
            "files": files, "services": services, "native": {"client": dict(native), "server": dict(native)},
            "components": {name: {"Name": name, "Version": version} for name, version in (("Engine", "29.10.0"), ("containerd", "v2.4.2"), ("runc", "1.5.3"))},
            "engine_settings": {"driver": "overlayfs", "snapshotter": "io.containerd.snapshotter.v1", "security": ["name=seccomp,profile=builtin"],
                                "default_runtime": "runc", "cgroup_version": "2"},
            "kernel": {"release": "7.0.0-1017-aws", "package": package, "version": "7.0.0-1017.18~24.04.1"},
            "observation": {"repository": "AldemaroCruz/ClipForge", "source_commit": "f" * 40, "run": "11", "attempt": "1", "job": "fixture",
                            "boot_id": "11111111-2222-3333-4444-555555555555", "observed_utc": "2026-11-20T14:00:00+00:00",
                            "files": metadata, "socket": socket, "processes": processes}}


class DockerToolchain(unittest.TestCase):
    def test_publisher_uses_only_the_fixed_executable_and_local_socket(self):
        self.assertEqual(docker.endpoint(Path("/fixture")), ["/usr/bin/docker", "--config", str(Path("/fixture")),
                                                             "--host", "unix:///run/docker.sock"])

    def test_changed_runner_daemon_or_socket_is_rejected(self):
        expected = fixture_receipt()
        self.assertEqual(docker.verify(expected, inspect=lambda: deepcopy(expected)), expected)
        for field, value, error in (("runner_image", "20261120.1.1", "docker_credentialed_toolchain_differs"),
                                    ("socket", "tcp://remote", "docker_context_changed"), ("files", {}, "docker_receipt_executable_inventory")):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, error):
                docker.verify(expected, inspect=lambda: {**expected, field: value})

    def test_fresh_hosts_match_by_security_projection_and_retain_full_run_evidence(self):
        reviewed = fixture_receipt()
        current = deepcopy(reviewed)
        observed = current["observation"]
        observed.update(boot_id="99999999-8888-7777-6666-555555555555", run="12", job="publication", observed_utc="2026-11-20T14:30:00+00:00")
        observed["socket"].update(device=33, inode=909, gid=999)
        for item in observed["files"].values():
            item.update(device=24, inode=item["inode"] + 500, mtime_ns=2000000000)
        for index, (name, path) in enumerate(docker.SERVICE_BINARIES.items(), 201):
            observed["processes"][name] = {"pid": str(index), "start_ticks": "300", "executable": docker.live_from_file(observed["files"][path])}
        self.assertNotEqual(reviewed, current)
        self.assertEqual(docker.projection_sha256(reviewed), docker.projection_sha256(current))
        self.assertEqual(docker.verify(reviewed, inspect=lambda: current)["observation"], observed)
        with self.assertRaisesRegex(ValueError, "docker_credentialed_host_observation_changed"):
            docker.verify_same_host(reviewed, current)

    def test_same_host_allows_observation_time_but_blocks_restarted_service(self):
        staged = fixture_receipt()
        current = deepcopy(staged)
        current["observation"]["observed_utc"] = "2026-11-20T14:01:00+00:00"
        docker.verify_same_host(staged, current)
        current["observation"]["processes"]["containerd.service"]["start_ticks"] = "130"
        docker.verify(staged, inspect=lambda: current)
        with self.assertRaisesRegex(ValueError, "docker_credentialed_host_observation_changed"):
            docker.verify_same_host(staged, current)

    def test_projection_refuses_missing_processes_and_changes_in_security_facts(self):
        expected = fixture_receipt()
        changed = deepcopy(expected)
        del changed["observation"]["processes"]["containerd.service"]
        with self.assertRaisesRegex(ValueError, "docker_host_observation_incomplete"):
            docker.stable_projection(changed)
        changed = deepcopy(expected)
        changed["services"]["containerd.service"]["sha256"] = "6" * 64
        with self.assertRaisesRegex(ValueError, "docker_live_services_unbound"):
            docker.stable_projection(changed)
        changed["files"]["/usr/bin/containerd"]["sha256"] = "6" * 64
        with self.assertRaisesRegex(ValueError, "docker_credentialed_toolchain_differs"):
            docker.verify(expected, inspect=lambda: changed)
        for field, value in (("driver", "overlay2"), ("snapshotter", "different"), ("security", ["name=apparmor"])):
            changed = deepcopy(expected)
            changed["engine_settings"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "docker_credentialed_toolchain_differs"):
                docker.verify(expected, inspect=lambda: changed)
        changed = deepcopy(expected)
        changed["socket_security"]["group"] = "root"
        with self.assertRaisesRegex(ValueError, "docker_credentialed_toolchain_differs"):
            docker.verify(expected, inspect=lambda: changed)

    def test_containerd_live_file_cannot_be_substituted_by_installed_path(self):
        report = fixture_receipt()
        path = "/usr/bin/containerd"
        file, info = report["files"][path], report["observation"]["files"][path]
        live = docker.live_from_file(info)
        stat_output = " ".join(f"{live[key]:x}" if key == "mode" else str(live[key]) for key in docker.LIVE_FIELDS)
        proc = "321 (containerd) " + " ".join(["R"] + ["0"] * 18 + ["200"])
        correct = ["321", stat_output, path, file["sha256"] + "  /proc/321/exe", stat_output, "321"]
        with patch.object(docker, "bounded_text", return_value=proc), patch.object(docker, "run", side_effect=correct) as run:
            result, observation = docker.live_service("containerd.service", file, info, Path("/fixture"))
        self.assertEqual(result, file)
        self.assertEqual(observation, {"pid": "321", "start_ticks": "200", "executable": live})
        self.assertEqual([call.args[0][0] for call in run.call_args_list], ["/usr/bin/systemctl"] + ["/usr/bin/sudo"] * 4 + ["/usr/bin/systemctl"])
        self.assertIn("/proc/321/exe", run.call_args_list[3].args[0])
        changed = correct.copy()
        changed[3] = "a" * 64 + "  /proc/321/exe"
        with patch.object(docker, "bounded_text", return_value=proc), patch.object(docker, "run", side_effect=changed), \
                self.assertRaisesRegex(ValueError, "docker_running_executable_digest_changed"):
            docker.live_service("containerd.service", file, info, Path("/fixture"))

    def test_native_docker_versions_are_canonical_across_client_server_json_casing(self):
        cli = {"Version": "29.0.0", "ApiVersion": "1.52", "GitCommit": "hash", "Os": "linux", "Arch": "amd64"}
        server = {"Version": "29.0.0", "APIVersion": "1.52", "GitCommit": "hash", "OS": "linux", "Arch": "amd64",
                  "Components": [{"Name": name, "Version": "1.2.3"} for name in ("Engine", "containerd", "runc")]}
        versions, components = docker.native_versions({"Client": cli, "Server": server})
        self.assertEqual(versions["client"], versions["server"])
        self.assertEqual(set(components), {"Engine", "containerd", "runc"})
        with self.assertRaisesRegex(ValueError, "docker_native_ambiguous_version"):
            docker.native_versions({"Client": cli, "Server": {**server, "ApiVersion": "1.51"}})

    def test_engine_settings_bind_runtime_and_report_only_the_snapshotter_type(self):
        info = {"driver": "overlayfs", "driver_status": [["driver-type", "io.containerd.snapshotter.v1"], ["private", "/ignored"]],
                "security": ["name=seccomp,profile=builtin"], "default_runtime": "runc", "cgroup_version": "2"}
        settings = docker.engine_settings(info)
        self.assertEqual(settings["snapshotter"], "io.containerd.snapshotter.v1")
        self.assertNotIn("/ignored", str(settings))
        with self.assertRaisesRegex(ValueError, "docker_engine_security_settings"):
            docker.engine_settings({**info, "default_runtime": "different"})

    def test_publication_requires_maintained_engine_components_and_booted_noble_aws_package(self):
        expected = fixture_receipt()
        docker.verify_maintained(expected)
        old = deepcopy(expected)
        old["native"]["client"]["version"] = old["native"]["server"]["version"] = old["components"]["Engine"]["Version"] = "28.0.4"
        with self.assertRaisesRegex(ValueError, "docker_engine_publication_maintenance_floor"):
            docker.verify_maintained(old)
        old["native"]["client"]["version"] = "29.10.0"
        with self.assertRaisesRegex(ValueError, "docker_client_server_engine_version_mismatch"):
            docker.verify_maintained(old)
        for package in ("linux-image-7.0.0-1014-aws", "linux-image-7.0.0-1017-gcp"):
            changed = {**expected, "kernel": {**expected["kernel"], "package": package}}
            with self.subTest(package=package), self.assertRaisesRegex(ValueError, "docker_receipt_kernel"):
                docker.verify_maintained(changed)
        old = {**expected, "kernel": {"release": "7.0.0-1014-aws", "package": "linux-image-7.0.0-1014-aws",
                                      "version": "7.0.0-1014.14~24.04.1"}}
        with self.assertRaisesRegex(ValueError, "docker_noble_aws_kernel_security_floor"):
            docker.verify_maintained(old)
        for family in ("azure", "gcp"):
            changed = deepcopy(expected)
            changed["platform"]["kernel_family"] = family
            changed["kernel"] = {"release": f"7.0.0-9999-{family}", "package": f"linux-image-7.0.0-9999-{family}", "version": "7.0.0-9999.99~24.04.1"}
            self.assertEqual(docker.stable_projection(changed)["platform"]["kernel_family"], family)
            with self.subTest(family=family), self.assertRaisesRegex(ValueError, "docker_noble_aws_kernel_security_floor"):
                docker.verify_maintained(changed)
        expected["components"]["runc"]["Version"] = "1.5.2"
        with self.assertRaisesRegex(ValueError, "docker_component_publication_maintenance_floor"):
            docker.verify_maintained(expected)
