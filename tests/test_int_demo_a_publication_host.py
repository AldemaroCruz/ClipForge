import json
from pathlib import Path
from tempfile import TemporaryDirectory
from types import SimpleNamespace
import unittest
from unittest.mock import mock_open, patch

from scripts import int_demo_a_publication_host as host


class PublicationHostObservation(unittest.TestCase):
    def test_preserves_live_release_and_signature_when_kernel_family_is_rejected(self):
        # Synthetic values exercise reporting, not the identity of a hosted run.
        env = {"GITHUB_RUN_ID": "10", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "a" * 40,
               "ImageVersion": "20261116.133.1"}
        machine = SimpleNamespace(release="7.0.0-1001-aws", machine="x86_64")
        signature = "Ubuntu 7.0.0-1001.1-aws 7.0.0"
        real_open = Path.open

        def select_open(path, *args, **kwargs):
            if str(path) == "/proc/version_signature":
                return mock_open(read_data=signature)()
            return real_open(path, *args, **kwargs)

        with (TemporaryDirectory() as tmp,
              patch.object(host, "snapshot", side_effect=host.HostBlocked("native_publication_azure_kernel_family")),
              patch.object(host.os, "uname", return_value=machine),
              patch.object(Path, "open", select_open),
              patch("builtins.print")):
            output = Path(tmp) / "host.json"
            self.assertEqual(host.observe(env, output), 1)
            proof = json.loads(output.read_bytes())
            self.assertEqual(proof["reason"], "native_publication_azure_kernel_family")
            self.assertEqual(proof["kernel_release"], machine.release)
            self.assertEqual(proof["kernel_signature"], signature)
            self.assertFalse(proof["activation_authorized"])


if __name__ == "__main__":
    unittest.main()
