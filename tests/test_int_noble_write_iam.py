from copy import deepcopy
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import call, patch

from scripts import int_noble_write_iam as write


CONTROLS = "a" * 40
TOKEN = "fixture-only"


class NobleWriteIAMTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.digest = write.load_profile()
        policy = {"version": 3, "etag": "project-original", "bindings": [
            {"role": "roles/browser", "members": ["user:retained@example.test"]},
        ], "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]}
        baselines = {write.PROJECT: policy, write.ZONE: {"etag": "zone-original"}}
        self.temporal = {
            "schema": write.TEMPORAL_SCHEMA, "producer_commit": write.READ_PRODUCER,
            "controls_commit": write.TEMPORAL_CONTROL, "profile_sha256": write.TEMPORAL_PROFILE_SHA,
            "issued_utc": "2020-01-01T00:00:00+00:00", "policies": {},
        }
        for target, before in baselines.items():
            spec = self.profile["policies"][target]
            spec["baseline_policy_sha256"] = write.iam.digest(before)
            temporal = [{"role": binding["role"], "members": binding["members"], "condition": {
                "title": "archive", "expression": 'request.time < timestamp("2020-01-02T00:00:00Z")',
            }} for binding in spec["add_bindings"]]
            after = {**write.requested_policy(target, before, temporal), "etag": "temporal-" + before["etag"]}
            self.temporal["policies"][target] = {"before": before, "after": after}
        self.read_proof = {"policies": {write.PROJECT: {"after": policy}}}
        self.live = {target: row["after"] for target, row in self.temporal["policies"].items()}
        exact = write.iam.custody.canonical(self.temporal)
        ref = {**write.TEMPORAL_RECEIPT, "size": len(exact), "sha256": write.iam.custody.sha256(exact)}
        self.enterContext(patch.object(write, "TEMPORAL_RECEIPT", ref))
        self.journal = Path(self.enterContext(TemporaryDirectory()))

    def set_policy(self, target, desired, _token):
        self.assertEqual(desired["etag"], self.live[target]["etag"])
        self.live[target] = updated = {**desired, "etag": "next-" + desired["etag"]}
        return updated

    def test_manifest_has_only_reviewed_bindings_without_a_window(self):
        profile, digest = write.load_profile()
        self.assertEqual(digest, write.iam.digest(profile))
        self.assertEqual(set(profile["policies"]), {write.PROJECT, write.ZONE})
        bindings = [binding for spec in profile["policies"].values() for binding in spec["add_bindings"]]
        conditional = [binding for binding in bindings if "condition" in binding]
        self.assertEqual(len(bindings), 4)
        self.assertEqual(conditional, [{"role": write.iam.ROLE_PREFIX + write.SA_POLICY_SETTER,
                                        "members": [write.iam.MEMBER], "condition": write.SA_POLICY_CONDITION}])
        self.assertNotIn("request.time", write.iam.custody.canonical(profile).decode())
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / write.PROFILE_PATH
            path.parent.mkdir()
            for key, value in (("condition", {"title": "unreviewed", "expression": "true"}),
                               ("members", ["user:other@example.test"]), ("role", "roles/owner")):
                changed = deepcopy(profile)
                changed["policies"][write.PROJECT]["add_bindings"][1][key] = value
                path.write_bytes(write.iam.custody.canonical(changed))
                with self.subTest(changed=key), self.assertRaisesRegex(ValueError, "binding"):
                    write.load_profile(Path(tmp))
            changed = deepcopy(profile)
            changed["policies"][write.ZONE]["add_bindings"].append(changed["policies"][write.PROJECT]["add_bindings"].pop())
            path.write_bytes(write.iam.custody.canonical(changed))
            with self.assertRaisesRegex(ValueError, "binding"):
                write.load_profile(Path(tmp))

    def test_idempotent_migration_reuses_exact_roles_and_verified_receipt(self):
        def upload(name, raw):
            return {"name": name, "generation": "1", "size": len(raw), "sha256": write.iam.custody.sha256(raw)}

        with (patch.object(write, "get_policy", side_effect=lambda target, _: self.live[target]),
              patch.object(write, "set_policy", side_effect=self.set_policy) as setter,
              patch.object(write.iam.custody, "upload", side_effect=upload) as publish,
              patch.object(write.iam.custody, "fetch_verified",
                           side_effect=lambda _: write.iam.custody.canonical(
                               write.load_journal(self.journal / "stable-receipt.json")))):
            result = write.migrate(self.profile, self.temporal, self.read_proof, TOKEN, self.journal, CONTROLS)
            active = self.live[write.PROJECT]
            self.live[write.PROJECT] = {**active, "bindings": list(reversed(active["bindings"]))}
            self.assertEqual(result, write.migrate(self.profile, self.temporal, self.read_proof, TOKEN, self.journal, CONTROLS))
        self.assertEqual(setter.call_count, 2)
        self.assertEqual(publish.call_count, 1)
        receipt = write.load_journal(self.journal / "stable-receipt.json")
        write.verify_stable_reference(result)
        write.verify_stable_reference(result, receipt)
        with self.assertRaisesRegex(ValueError, "receipt reference"):
            write.verify_stable_reference(result, {**receipt, "controls_commit": "b" * 40})
        write.verify_stable_receipt(self.profile, receipt, self.temporal, self.read_proof)
        with patch.object(write.iam, "request_json", side_effect=[
                {"name": role, **spec["definition"]} for role, spec in self.profile["roles"].items()
        ]) as request:
            write.verify_roles(self.profile["roles"], TOKEN)
        self.assertEqual(request.call_args_list, [
            call("https://iam.googleapis.com/v1/" + role, TOKEN) for role in self.profile["roles"]
        ])

    def test_recovers_first_write_from_exact_intent_without_repeating_it(self):
        changes = write.planned_migration(self.profile, self.temporal)
        before, desired = changes[write.PROJECT]
        write.iam.write_new(self.journal / "0-intent.json", {
            "target": write.PROJECT, "before": before, "requested": desired,
        })
        first = self.set_policy(write.PROJECT, desired, TOKEN)
        with (patch.object(write, "get_policy", side_effect=lambda target, _: self.live[target]),
              patch.object(write, "set_policy", side_effect=self.set_policy) as setter):
            policies = write.transition_policies(changes, TOKEN, self.journal)
            self.assertEqual(policies[write.PROJECT]["after"], first)
            setter.assert_called_once_with(write.ZONE, changes[write.ZONE][1], TOKEN)

    def test_policy_drift_blocks_every_write_even_if_first_scope_is_valid(self):
        changes = write.planned_migration(self.profile, self.temporal)
        self.live[write.ZONE] = {**self.live[write.ZONE], "etag": "unrecorded-etag"}
        with (patch.object(write, "get_policy", side_effect=lambda target, _: self.live[target]),
              patch.object(write, "set_policy") as setter):
            with self.assertRaisesRegex(ValueError, "without a matching"):
                write.transition_policies(changes, TOKEN, self.journal)
            setter.assert_not_called()

    def test_full_policies_reject_audit_changes_unrelated_members_and_unattributed_etags(self):
        changes = write.planned_migration(self.profile, self.temporal)
        before, desired = changes[write.PROJECT]
        for bad in ({**desired, "auditConfigs": []}, {**desired, "bindings": [
                *desired["bindings"], {"role": "roles/editor", "members": ["user:other@example.test"]},
        ]}):
            with self.assertRaisesRegex(ValueError, "approved transition"):
                write.verify_transition(write.PROJECT, before, {**bad, "etag": "after"}, desired)
        with self.assertRaisesRegex(ValueError, "approved transition"):
            write.verify_transition(write.PROJECT, before, desired, desired)

    def test_revocation_restores_complete_read_baseline_with_current_etags(self):
        changes = write.planned_migration(self.profile, self.temporal)
        stable = {"issued_utc": "2020-01-03T00:00:00+00:00", "policies": {}}
        for target, (before, desired) in changes.items():
            after = self.set_policy(target, desired, TOKEN)
            stable["policies"][target] = {"before": before, "after": after}
        with (patch.object(write, "get_policy", side_effect=lambda target, _: self.live[target]),
              patch.object(write, "set_policy", side_effect=self.set_policy) as setter):
            results = write.revoke(stable, self.temporal, TOKEN, self.journal)
            self.assertEqual(results, write.revoke(stable, self.temporal, TOKEN, self.journal))
            self.assertEqual(setter.call_count, 2)
        for target, delta in results.items():
            baseline = self.temporal["policies"][target]["before"]
            self.assertEqual(write.semantics(target, delta["after"]), write.semantics(target, baseline))
            self.assertEqual(delta["before"]["etag"], stable["policies"][target]["after"]["etag"])
            self.assertNotIn("request.time", write.iam.custody.canonical(delta["after"]).decode())

    def test_partial_revocation_uses_exact_source_intent_and_leaves_other_scope_untouched(self):
        source = self.journal / "source"
        source.mkdir()
        write.iam.write_new(source / "approval.json", {
            "schema": write.APPROVAL_SCHEMA, "decision": write.APPROVAL_DECISION, "owner_approval_ref": "test-authority",
            "controls_commit": CONTROLS, "profile_sha256": write.iam.digest(self.profile),
            "temporary_receipt": write.TEMPORAL_RECEIPT,
        })
        target = write.PROJECT
        before, desired = write.planned_migration(self.profile, self.temporal)[target]
        write.iam.write_new(source / "0-intent.json", {"target": target, "before": before, "requested": desired})
        self.set_policy(target, desired, TOKEN)
        untouched = self.live[write.ZONE]
        approval = {"migration_controls_commit": CONTROLS}
        with (patch.object(write, "get_policy", side_effect=lambda scope, _: self.live[scope]),
              patch.object(write, "set_policy", side_effect=self.set_policy) as setter):
            actions = write.revoke_partial(self.profile, self.temporal, approval, TOKEN, source, self.journal)
            self.assertEqual(actions, write.revoke_partial(self.profile, self.temporal, approval, TOKEN, source, self.journal))
        self.assertEqual(set(actions), {target})
        self.assertEqual(setter.call_count, 1)
        self.assertEqual(self.live[write.ZONE], untouched)
        self.assertEqual(write.semantics(target, self.live[target]),
                         write.semantics(target, self.temporal["policies"][target]["before"]))

    def test_only_exact_policy_urls_and_current_etag_reach_setter(self):
        payload = {"etag": "current", "version": 3, "bindings": []}
        with patch.object(write.iam, "request_json") as request:
            write.set_policy(write.ZONE, payload, TOKEN)
            write.set_policy(write.PROJECT, payload, TOKEN)
            with self.assertRaises(ValueError):
                write.set_policy("projects/unreviewed", payload, TOKEN)
        self.assertEqual(request.call_args_list, [
            call(write.POLICY_ENDPOINTS[write.ZONE] + ":setIamPolicy", TOKEN, "POST", {"policy": payload}),
            call(write.POLICY_ENDPOINTS[write.PROJECT] + ":setIamPolicy", TOKEN, "POST",
                 {"policy": payload, "updateMask": "bindings,etag"}),
        ])

    def test_unapproved_migration_fails_before_admin_token_or_private_writes(self):
        with (patch.object(write.iam, "verify_checkout"), patch.object(write.iam, "verify_receipt_location"),
              patch.object(write.iam, "admin_token") as admin, patch("builtins.print"),
              patch.object(write, "migrate") as migrate):
            result = write.main(["migrate", "--controls-commit", CONTROLS, "--profile-sha256", self.digest,
                                 "--receipt-dir", "synthetic"])
        self.assertEqual(result, 1)
        admin.assert_not_called()
        migrate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
