"""Image-candidate configuration checks grant no deployment authorization."""
import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_int_foundation as f, check_tf_int as c, int_release as r


class PlanningCandidate(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-candidate-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = self.root / "module"
        self.module.mkdir()
        for name in c.FILES:
            target = self.module / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(("synthetic candidate source " + name).encode())
        (self.root / "config").mkdir()
        (self.root / "config/tf-int01-costs.json").write_text(json.dumps({"region": c.REGION, "hours_per_month": 730}))
        (self.root / ".gitleaks.toml").write_bytes(b"synthetic policy identity fixture")
        image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "a" * 64
        binding = r.source_binding(self.module, {"GITHUB_SHA": "b" * 40, "RUNTIME_IMAGE": image})
        self.contract = {"plan": {**binding, "configuration_sha256": "c" * 64,
                                  "manifest": {"name": "synthetic-baseline-reference"},
                                  "managed_addresses": sorted(c.FOUNDATION_ADDRESSES)},
                         "scope": {"module_files": list(c.FILES)},
                         "unchanged_gitleaks_policy_sha256": hashlib.sha256((self.root / ".gitleaks.toml").read_bytes()).hexdigest(),
                         "planning_candidate": {"purpose": "comparative_plan_only", "apply_authorized": False,
                             "configuration_sha256": binding["configuration_sha256"],
                             "baseline_configuration_sha256": "c" * 64,
                             "baseline_manifest": {"name": "synthetic-baseline-reference"},
                             "image": {"project": "debian-cloud", "name": "debian-13-trixie-v20261116",
                                       "image_id": "5913446147369107523", "status": "READY"}}}

    def check(self):
        # The real HCL contract/native tests run separately. These fixtures test
        # the candidate authorization boundary, without a real checkout/config.
        with mock.patch.object(c, "source_contract", return_value={}):
            return f.check_static(self.root, self.module, self.contract)

    def test_explicit_candidate_configuration_is_valid_for_comparison_only(self):
        self.check()
        self.assertFalse(self.contract["planning_candidate"]["apply_authorized"])

    def test_candidate_cannot_rebind_history_identity_or_approve_apply(self):
        original = copy.deepcopy(self.contract)
        for field, changed in (("purpose", "apply"), ("apply_authorized", True),
                               ("baseline_configuration_sha256", "d" * 64),
                               ("baseline_manifest", {}), ("configuration_sha256", "e" * 64),
                               ("image", {"project": "other-project", "name": "mobile-family"})):
            with self.subTest(field=field):
                self.contract = copy.deepcopy(original)
                self.contract["planning_candidate"][field] = changed
                with self.assertRaises(ValueError):
                    self.check()

    def test_unrelated_module_provider_and_inputs_drift_still_blocks(self):
        for name in ("main.tf", "postgres-install.sh", ".terraform.lock.hcl"):
            target = self.module / name
            before = target.read_bytes()
            target.write_bytes(before + b" changed")
            with self.subTest(name=name), self.assertRaises(ValueError):
                self.check()
            target.write_bytes(before)
        self.contract["plan"]["inputs"]["machine_type"] = "e2-small"
        with self.assertRaises(ValueError):
            self.check()

    def test_no_candidate_does_not_relax_historical_bindings(self):
        del self.contract["planning_candidate"]
        with self.assertRaises(ValueError):
            self.check()

    def test_even_an_approved_looking_decision_cannot_apply_candidate(self):
        with self.assertRaisesRegex(ValueError, "separate explicit review"):
            f.verify_owner_decision({"apply_decision": "approve_exact_foundation_binary_once"}, "", {}, self.contract)
        with self.assertRaisesRegex(ValueError, "cannot authorize"):
            f.verify_plan_bridge({}, self.module, {}, {}, self.contract)


if __name__ == "__main__":
    unittest.main()
