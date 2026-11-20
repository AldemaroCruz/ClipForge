from copy import deepcopy
import json
from pathlib import Path
import unittest
from unittest.mock import Mock

from scripts import int_demo_a_noble_policy as policy


class NobleReadPolicy(unittest.TestCase):
    def setUp(self):
        self.config = json.loads((Path(__file__).resolve().parents[1] / policy.CONFIG).read_bytes())
        prior = self.config["prior"]
        changes = {}
        for target, role in self.config["read_roles"].items():
            before = deepcopy(prior[target])
            bindings = [*deepcopy(before["bindings"]), {"role": role["name"], "members": [policy.PRINCIPAL]}]
            changes[target] = {"role": role["name"], "role_definition": deepcopy(role["definition"]), "before": before,
                               "after": {**before, "etag": f"fixture-new-{target}", "bindings": bindings}}
        self.receipt = {"schema": "clipforge-int-demo-a-noble-policy-receipt-2", "status": "applied_and_verified",
                        "approval_sha256": "a" * 64, "policies": changes}

    def test_exact_addition_preserves_old_member_and_condition(self):
        expected = policy.expected_policy(self.config, self.receipt)
        self.assertEqual(expected["account"]["etag"], "fixture-new-account")
        self.assertTrue(all(len(value["bindings"]) == 2 for value in expected.values()))
        self.assertEqual([row["condition"]["expression"] for row in expected["tunnel"]["bindings"] if "condition" in row],
                         ["destination.port == 22"])

    def test_changed_baseline_role_members_or_conditions_are_rejected(self):
        for field in ("baseline", "etag", "member", "extra", "condition", "role", "missing_policy"):
            receipt = deepcopy(self.receipt)
            change = receipt["policies"]["tunnel"]
            if field == "baseline":
                change["before"]["etag"] = "unreviewed"
            elif field == "etag":
                change["after"]["etag"] = change["before"]["etag"]
            elif field == "member":
                change["after"]["bindings"][0]["members"] = ["user:unexpected@example.invalid"]
            elif field == "extra":
                change["after"]["bindings"].append({"role": "roles/owner", "members": [policy.PRINCIPAL]})
            elif field == "condition":
                change["after"]["bindings"][0]["condition"]["expression"] = "true"
            elif field == "role":
                change["role_definition"]["includedPermissions"] = ["iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.accessViaIAP"]
            else:
                del receipt["policies"]["account"]
            with self.subTest(field=field), self.assertRaises(ValueError):
                policy.expected_policy(self.config, receipt)

    def test_live_checks_bind_exact_http_contracts_and_report_denial_or_drift(self):
        expected = policy.expected_policy(self.config, self.receipt)
        reader = Mock(side_effect=[expected["instance"], policy.iam.CloudError(403), {**expected["tunnel"], "etag": "other"}])
        self.assertEqual(policy.verify_live(expected, "fixture", reader=reader), [
            {"operation": "getIamPolicy", "resource": "account", "http_status": 403},
            {"operation": "getIamPolicy", "resource": "tunnel", "reason": "full_policy_or_etag_drift"},
        ])
        self.assertEqual([call.args[2] for call in reader.call_args_list], ["GET", "POST", "POST"])
        self.assertEqual([call.args[3] for call in reader.call_args_list], [None, None, {"options": {"requestedPolicyVersion": 3}}])
        self.assertIn("/instances/7365414160255801909:getIamPolicy", reader.call_args_list[2].args[0])
        self.assertTrue(reader.call_args_list[1].args[0].endswith("?options.requestedPolicyVersion=3"))
