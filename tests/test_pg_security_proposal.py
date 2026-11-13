"""Synthetic parser regressions; real candidate scans are separate artifacts."""
import base64
import hashlib
import unittest

from scripts import new_pg_security_inventory as proposal
from scripts import capture_postgres_inventory as original
from scripts import validate_ci_reports as gates
from tests.test_postgres_inventory import fixture_sections, fixture_go_binary, encoded


def candidate_sections():
    parts = fixture_sections()
    modules = ("path\tgithub.com/tianon/gosu\nmod\tgithub.com/tianon/gosu\t" + proposal.GOSU_MODULE_VERSION + "\t" + proposal.SOURCE_MODULE_CHECKSUM + "\n"
               "dep\tgithub.com/moby/sys/user\tv0.4.1\th1:" + "a" * 43 + "=\n"
               "dep\tgolang.org/x/sys\tv0.1.0\th1:" + "b" * 43 + "=\n"
               "build\tGOOS=linux\nbuild\tGOARCH=amd64\n")
    binary = fixture_go_binary(modules).replace(b"go1.24.6", b"go1.27.4")
    parts["gosu-binary"] = base64.b64encode(binary)
    parts["gosu-stat"] = f"0 0 755 {len(binary)} regular file\n".encode()
    parts["gosu-sha256"] = (hashlib.sha256(binary).hexdigest() + "  /usr/local/bin/gosu\n").encode()
    parts["gosu-version"] = b"1.20 (go1.27.4 on linux/amd64; gc)\n"
    parts["dpkg-status"] += ("\nPackage: zlib1g\nStatus: install ok installed\nArchitecture: amd64\nVersion: " + proposal.ZLIB_VERSION + "\n\n").encode()
    return parts


class SecurityProposalInventoryTests(unittest.TestCase):
    def parse(self, parts=None, reference="clipforge-pg-security:synthetic"):
        return proposal.parse_candidate(encoded(parts or candidate_sections()),
            image_id="sha256:" + "a" * 64, image_reference=reference)

    def test_complete_candidate_preserves_real_module_identity_and_both_targets(self):
        result = self.parse()
        self.assertEqual(result["schema"], proposal.SCHEMA)
        self.assertEqual(result["dpkg"]["installed_package_count"], 4)
        self.assertEqual({target["Type"] for target in result["targets"]}, {"debian", "gobinary"})
        go = result["go_binaries"][0]
        self.assertEqual(go["main_module"]["Version"], proposal.GOSU_MODULE_VERSION)
        self.assertEqual(go["go_version"], "go1.27.4")
        self.assertEqual(len(go["packages"]), 4)
        self.assertEqual(result["scope"]["ci_integration"], "pending_producer_and_validator_review")

    def test_old_gosu_or_old_zlib_is_rejected(self):
        for key, replacement in (("gosu-version", b"1.19 (go1.27.4 on linux/amd64; gc)\n"),
                                 ("dpkg-status", candidate_sections()["dpkg-status"].replace(proposal.ZLIB_VERSION.encode(), b"1:1.3.dfsg+really1.3.1-1"))):
            parts = candidate_sections()
            parts[key] = replacement
            with self.subTest(key=key), self.assertRaises(original.InventoryError):
                self.parse(parts)

    def test_wrong_image_reference_and_forged_binary_hash_are_rejected(self):
        with self.assertRaises(original.InventoryError):
            self.parse(reference=original.POSTGRES_IMAGE)
        parts = candidate_sections()
        parts["gosu-sha256"] = b"f" * 64 + b"  /usr/local/bin/gosu\n"
        with self.assertRaises(original.InventoryError):
            self.parse(parts)

    def test_existing_ci_validator_still_rejects_the_independent_candidate(self):
        result = self.parse()
        with self.assertRaises(gates.ValidationError):
            gates.validate_postgres_inventory(result, result["image_id"], result["image_reference"])

    def test_historical_producer_still_requires_reviewed_original_gosu(self):
        with self.assertRaises(original.InventoryError):
            original.parse_probe(encoded(candidate_sections()), image_id="sha256:" + "a" * 64,
                                 image_reference=original.POSTGRES_IMAGE)


if __name__ == "__main__":
    unittest.main()
