from copy import deepcopy
from pathlib import Path
import unittest

from scripts import int_demo_a_docker as docker


class DockerToolchain(unittest.TestCase):
    def test_publisher_uses_only_the_fixed_executable_and_local_socket(self):
        self.assertEqual(docker.endpoint(Path("/fixture")), ["/usr/bin/docker", "--config", str(Path("/fixture")),
                                                             "--host", "unix:///run/docker.sock"])

    def test_changed_runner_daemon_or_socket_is_rejected(self):
        expected = {"runner_image": "20261116.376.1", "socket": "/run/docker.sock",
                    "files": {"/usr/bin/dockerd": {"sha256": "a" * 64}}}
        docker.verify(expected, inspect=lambda: deepcopy(expected))
        for field, value in (("runner_image", "20261120.1.1"), ("socket", "tcp://remote"), ("files", {})):
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, "docker_credentialed_toolchain_differs"):
                docker.verify(expected, inspect=lambda: {**expected, field: value})

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
        expected = {
            "image_os": "ubuntu24",
            "native": {"client": {"version": "29.10.0"}, "server": {"version": "29.10.0"}},
            "components": {"Engine": {"Version": "29.10.0"}, "containerd": {"Version": "v2.4.2"}, "runc": {"Version": "1.5.3"}},
            "kernel": {"release": "7.0.0-1017-aws", "package": "linux-image-7.0.0-1017-aws", "version": "7.0.0-1017.18~24.04.1"},
        }
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
            with self.subTest(package=package), self.assertRaisesRegex(ValueError, "docker_noble_aws_kernel_security_floor"):
                docker.verify_maintained(changed)
        old = {**expected, "kernel": {"release": "7.0.0-1014-aws", "package": "linux-image-7.0.0-1014-aws",
                                      "version": "7.0.0-1014.14~24.04.1"}}
        with self.assertRaisesRegex(ValueError, "docker_noble_aws_kernel_security_floor"):
            docker.verify_maintained(old)
        expected["components"]["runc"]["Version"] = "1.5.2"
        with self.assertRaisesRegex(ValueError, "docker_component_publication_maintenance_floor"):
            docker.verify_maintained(expected)
