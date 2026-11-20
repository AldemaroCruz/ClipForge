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
