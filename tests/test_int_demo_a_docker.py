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
