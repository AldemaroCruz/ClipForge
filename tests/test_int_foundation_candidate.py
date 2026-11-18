"""Image-candidate configuration checks grant no deployment authorization."""
import copy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_int_foundation as f, check_tf_int as c, int_release as r
from tests.test_int_foundation import acceptance_fixture


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

    def activated_fixture(self):
        """Synthetic data transition, retaining the entire previous contract."""
        active = copy.deepcopy(self.contract)
        candidate = active.pop("planning_candidate")
        active["history"] = copy.deepcopy(self.contract)
        plan = active["plan"]
        now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        plan.update(configuration_sha256=candidate["configuration_sha256"], run_id="456", created_utc=(now - timedelta(hours=1)).isoformat(),
                    actions={"create": 42}, backend={"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
                    "lineage": "synthetic-lineage", "serial": 1, "state_generation": "123", "state_sha256": "d" * 64})
        prefix = "private-plans/int/" + plan["commit"] + "/456-1/"
        for key, filename in (("manifest", "manifest.json"), ("binary", "int.tfplan"), ("json", "int.json")):
            plan[key] = {"name": prefix + filename, "generation": "123", "sha256": "d" * 64, "size": 100}
        active["owner_risk_acceptance"] = acceptance_fixture(plan, (now + timedelta(hours=2)).isoformat())
        active["owner_risk_acceptance_sha256"] = r.sha256(r.canonical(active["owner_risk_acceptance"]))
        return active, now

    def test_exact_activation_uses_new_configuration_and_retains_previous_contract(self):
        previous = copy.deepcopy(self.contract)
        active, now = self.activated_fixture()
        f.verify_activation(active, now=now)
        self.assertEqual(active["history"], previous)
        self.assertEqual(self.contract, previous)
        self.assertNotEqual(active["plan"]["configuration_sha256"], previous["plan"]["configuration_sha256"])
        self.assertNotEqual(active["plan"]["manifest"], previous["plan"]["manifest"])
        self.assertNotIn("planning_candidate", active)

    def test_candidate_flag_removal_or_resealed_unapproved_record_is_insufficient(self):
        active, now = self.activated_fixture()
        del active["owner_risk_acceptance"]
        with self.assertRaises(ValueError): f.verify_activation(active, now=now)
        active, now = self.activated_fixture()
        active["owner_risk_acceptance"]["effective_apply_contract_activated"] = False
        active["owner_risk_acceptance_sha256"] = r.sha256(r.canonical(active["owner_risk_acceptance"]))
        with self.assertRaises(ValueError): f.verify_activation(active, now=now)
        active, now = self.activated_fixture()
        active["plan"]["manifest"] = copy.deepcopy(active["history"]["plan"]["manifest"])
        with self.assertRaises(ValueError): f.verify_activation(active, now=now)

    def test_rebinding_an_expired_original_does_not_create_a_new_lifetime(self):
        active, now = self.activated_fixture()
        active["plan"]["created_utc"] = "2026-11-13T23:39:17+00:00"
        active["owner_risk_acceptance"] = acceptance_fixture(active["plan"], "2026-11-14T23:39:17+00:00")
        active["owner_risk_acceptance_sha256"] = r.sha256(r.canonical(active["owner_risk_acceptance"]))
        with self.assertRaisesRegex(ValueError, "expired"):
            f.verify_activation(active, now=now)


if __name__ == "__main__":
    unittest.main()
