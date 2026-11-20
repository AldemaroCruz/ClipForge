import copy
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import int_db01_noble_read_iam as iam


def policy():
    return {
        "version": 3,
        "etag": "old-etag",
        "bindings": [{"role": "roles/browser", "members": ["user:prior@example.test", "user:second@example.test"]},
                     {"role": "roles/logging.viewer", "members": ["user:prior@example.test"],
                      "condition": {"title": "historical", "expression": "request.time < timestamp('2026-11-18T18:00:00Z')"}}],
        "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}],
    }


class StableReadIAMTests(unittest.TestCase):
    def test_versioned_scope_is_exact_and_role_names_are_fixed(self):
        profile, digest = iam.load_profile()
        self.assertEqual(digest, iam.digest(profile))
        self.assertEqual(len(profile["roles"]), 9)
        self.assertEqual(len(profile["policies"]), 6)
        self.assertEqual(sum(len(row["add_bindings"]) for row in profile["policies"].values()), 11)
        self.assertEqual([role for role, spec in profile["roles"].items() if spec["mode"] == "create"], [iam.NEW_ROLE])
        self.assertNotIn("request.time", json.dumps([row["add_bindings"] for row in profile["policies"].values()]))
        self.assertEqual(iam.custody.object_name(iam.proof_name("8" * 40)), iam.proof_name("8" * 40))

    def test_profile_rejects_new_member_extended_role_and_relaxed_scope(self):
        profile, _ = iam.load_profile()
        mutations = (
            lambda p: p["policies"][iam.IAP]["add_bindings"][0]["members"].append("user:other@example.test"),
            lambda p: p["roles"][iam.NEW_ROLE]["definition"]["includedPermissions"].append("iap.tunnelInstances.setIamPolicy"),
            lambda p: p["policies"][iam.PROJECT]["add_bindings"][0].pop("condition"),
        )
        for change in mutations:
            profile_copy = copy.deepcopy(profile)
            change(profile_copy)
            with self.subTest(change=change), tempfile.TemporaryDirectory() as temp:
                path = Path(temp) / iam.PROFILE
                path.parent.mkdir()
                path.write_text(json.dumps(profile_copy), encoding="utf-8")
                with self.assertRaises(ValueError):
                    iam.load_profile(Path(temp))

    def test_policy_comparison_allows_reordering_and_refuses_foreign_drift(self):
        profile, _ = iam.load_profile()
        before = policy()
        additions = profile["policies"][iam.PROJECT]["add_bindings"]
        after = {**before, "etag": "server-post-etag", "bindings": list(reversed([*before["bindings"], *additions]))}
        iam.check_policy_delta(before, after, additions)
        mutated = copy.deepcopy(after)
        mutated["bindings"][-1]["members"].reverse()
        iam.check_policy_delta(before, mutated, additions)
        mutated["bindings"][-1]["members"].append("user:unreviewed@example.test")
        with self.assertRaises(ValueError):
            iam.check_policy_delta(before, mutated, additions)
        mutated = copy.deepcopy(after)
        mutated["auditConfigs"][0]["auditLogConfigs"][0]["logType"] = "DATA_WRITE"
        with self.assertRaises(ValueError):
            iam.check_policy_delta(before, mutated, additions)
        mutated = copy.deepcopy(after)
        mutated["bindings"].append(mutated["bindings"][0])
        with self.assertRaises(ValueError):
            iam.check_policy_delta(before, mutated, additions)

    def test_policy_write_uses_original_etag_and_only_fixed_mutation_endpoints(self):
        with patch.object(iam, "request_json", return_value=policy()) as request:
            iam.set_policy(iam.IAP, policy(), "test-only")
            iam.set_policy(iam.PROJECT, policy(), "test-only")
            with self.assertRaises(ValueError):
                iam.set_policy("projects/an-unreviewed-project", policy(), "test-only")
        first, second = request.call_args_list
        self.assertEqual(first.args[0], "https://iap.googleapis.com/v1/" + iam.IAP + ":setIamPolicy")
        self.assertEqual(first.args[3], {"policy": policy()})
        self.assertEqual(second.args[3], {"policy": policy(), "updateMask": "bindings,etag"})

    def test_rollback_reconciles_partial_application_then_uses_latest_etag(self):
        profile, _ = iam.load_profile()
        original = policy()
        profile = {**profile, "policies": {key: {
            **spec, "baseline_policy_sha256": iam.digest(original), "baseline_etag_sha256": iam.digest(original["etag"]),
        } for key, spec in profile["policies"].items()}}
        before = {key: original for key in profile["policies"]}
        additions = profile["policies"][iam.PROJECT]["add_bindings"]
        intended = {**original, "bindings": [*original["bindings"], *additions]}
        landed = {**intended, "etag": "fresh-etag"}
        restored = {**original, "etag": "rollback-etag"}
        with tempfile.TemporaryDirectory() as temp:
            directory = Path(temp)
            iam.write_new(directory / "00-grant-intent.json", {"target": iam.PROJECT, "policy": intended})
            with patch.object(iam, "get_policy", side_effect=[landed, restored]), patch.object(
                iam, "set_policy", return_value=restored
            ) as write:
                count = iam.rollback_delta(profile, before, "test-only", directory, directory)
            self.assertEqual(count, 1)
            write.assert_called_once_with(iam.PROJECT, {**original, "etag": "fresh-etag"}, "test-only")
            self.assertTrue((directory / "00-rollback-readback.json").is_file())

    def test_mutation_entry_points_require_owner_approval_before_authentication(self):
        _, sha = iam.load_profile()
        options = ["--reviewed-commit", "1" * 40, "--package-sha256", sha, "--receipt-dir", "synthetic"]
        with patch.object(iam, "verify_checkout"), patch.object(iam, "verify_receipt_location"), patch.object(
            iam, "admin_token"
        ) as admin, patch("builtins.print"):
            for operation in ("apply", "rollback"):
                self.assertEqual(iam.main([operation, *options]), 1)
        admin.assert_not_called()

    def test_owner_decision_is_bound_to_exact_profile_commit_and_source(self):
        _, profile_sha = iam.load_profile()
        commit = "1" * 40
        decision = {"schema": iam.APPROVAL_SCHEMA, "decision": iam.APPROVAL_DECISION, "reviewed_commit": commit,
                    "package_sha256": profile_sha, "source_observation": iam.SOURCE, "approval_ref": "synthetic"}
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "owner-decision.json"
            path.write_text(json.dumps(decision), encoding="utf-8")
            self.assertEqual(iam.approval_digest(path, commit, profile_sha), iam.digest(decision))
            for key, value in (("decision", "only_profiles"), ("package_sha256", "2" * 64), ("reviewed_commit", "2" * 40),
                               ("source_observation", {**iam.SOURCE, "attempt": 2})):
                with self.subTest(key=key):
                    path.write_text(json.dumps({**decision, key: value}), encoding="utf-8")
                    with self.assertRaises(ValueError):
                        iam.approval_digest(path, commit, profile_sha)
