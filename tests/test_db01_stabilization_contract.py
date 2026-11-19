"""Readonly public contracts; no owner authorization or cloud/guest operations."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import unittest

from scripts import int_bootstrap_containment as containment
from scripts import int_db_acceptance as client
from scripts.prepare_ci_scan import validate_paths

ROOT = Path(__file__).resolve().parents[1]
# Derived once from the immutable native C2 report (SHA 3c0aed53...); public data.
FROZEN_VM_RELATIONSHIP_SHA256 = "d359623e80ca256b3c942fd648d5b995c098277a6c238b6977d808fdedb386e8"


def public_json(name):
    validate_paths([name])
    raw = (ROOT / name).read_bytes()
    if len(raw) > 1024 * 1024:
        raise ValueError("public contract size limit")
    return json.loads(raw)


class StabilizationContractTests(unittest.TestCase):
    def test_public_source_closure_and_current_preparation_authority_are_consistent(self):
        proposal = public_json("config/db01-bootstrap-proposal.json")
        records = proposal["source_sha256"]
        validate_paths([row["path"] for row in records])
        hashes = {}
        for row in records:
            self.assertNotIn(row["path"], hashes)
            hashes[row["path"]] = hashlib.sha256((ROOT / row["path"]).read_bytes()).hexdigest()
            self.assertEqual(hashes[row["path"]], row["sha256"])
        active = proposal["status"] == "authorized_single_guest_initialization"
        self.assertIn(proposal["status"], {"preparation_only_blocked_before_activation", "authorized_single_guest_initialization"})
        for key in ("execution_authorized", "cloud_writes_authorized", "VM_operations_authorized", "SQL_on_INT_authorized"):
            self.assertIs(proposal[key], active)
        self.assertIs(proposal["format_operation"]["authorized"], active)
        self.assertEqual(proposal["format_operation"]["argv"], ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", "/dev/disk/by-id/google-clipforge-pg-data"])
        self.assertEqual(proposal["containment"], containment.containment_policy(
            hashes["scripts/int_bootstrap_containment.py"], hashes["scripts/int_bootstrap_vm.py"], authorized=active))
        # This consistency test grants no authority: runtime still verifies the
        # separate original owner decision, expiry, source, state and int review.

    def test_all_frozen_native_relationships_and_severities_remain_visible(self):
        value = public_json("config/db01-remediation-proposal.json")
        review = value["individual_review"]
        rows = sorted([[finding["cve"], finding["source_name"], row["binary_name"], row["binary_version"],
                        row["architecture"], row["source_version"], row["severity"], row["severity_source"]]
                       for finding in review["individual_findings"] for row in finding["binary_relationships"]])
        raw = json.dumps(rows, separators=(",", ":"), ensure_ascii=True).encode()
        self.assertEqual(hashlib.sha256(raw).hexdigest(), FROZEN_VM_RELATIONSHIP_SHA256)
        self.assertEqual(len(rows), 215)
        self.assertEqual(len({r[0] for r in rows}), 69)
        self.assertEqual(len({r[1] for r in rows}), 20)
        self.assertEqual(Counter(r[6] for r in rows), {"CRITICAL": 7, "HIGH": 208})
        self.assertTrue(all(row["risk_accepted"] is False and row["scanner_exception"] is False
                            for row in review["individual_findings"]))
        self.assertIs(review["full_filesystem_or_kernel_vulnerability_coverage_claimed"], False)

    def test_client_immutable_source_and_pending_versions_do_not_become_execution(self):
        value = public_json("config/db01-migration-client-proposal.json")
        self.assertRegex(value["image"], r"^us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/runtime@sha256:[a-f0-9]{64}$")
        self.assertEqual(value["image"].rsplit("@", 1)[1], value["local_image"]["manifest_digest"])
        self.assertRegex(value["local_image"]["config_digest"], r"^sha256:[a-f0-9]{64}$")
        self.assertTrue(value["local_image"]["same_config_and_uncompressed_diff_ids_as_scanned_image"])
        hashes = client.source_records(value["app_sources"])
        for name, expected in hashes.items():
            self.assertEqual(hashlib.sha256((ROOT / name).read_bytes()).hexdigest(), expected)
        if value["image_published"] is False:
            self.assertIs(value["resource_creation_authorized"], False)
            self.assertIs(value["execution_authorized"], False)
        pending = public_json("config/db01-activation-preparation.json")
        if pending["status"] == "prepared_for_review_no_go_until_specific_decisions":
            self.assertIs(pending["bootstrap_authorized"], False)
            self.assertIs(pending["cloud_writes_authorized"], False)
            self.assertTrue(all(row["authorized"] is False for row in pending["future_write_groups"]))
        if any(item is None for item in value["secret_versions"].values()):
            with self.assertRaises(ValueError):
                client.job_spec("migrate", value["image"], value["secret_versions"], value["app_sources"])


if __name__ == "__main__":unittest.main()
