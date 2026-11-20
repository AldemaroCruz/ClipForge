from copy import deepcopy
from datetime import datetime, timedelta
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_noble_write_iam as write


class NobleWriteIAMTests(unittest.TestCase):
    def setUp(self):
        self.profile, self.digest = write.load_profile()

    def test_manifest_has_only_four_scoped_temporary_bindings(self):
        self.assertEqual(self.digest, write.iam.digest(self.profile))
        self.assertEqual(set(self.profile["policies"]), {write.PROJECT, write.ZONE})
        self.assertEqual(sum(len(row["add_bindings"]) for row in self.profile["policies"].values()), 4)
        changed = deepcopy(self.profile)
        changed["policies"][write.PROJECT]["add_bindings"][1]["condition"]["expression"] = "true"
        with TemporaryDirectory() as tmp:
            path = Path(tmp) / write.PROFILE_PATH
            path.parent.mkdir()
            path.write_bytes(write.iam.custody.canonical(changed))
            with self.assertRaisesRegex(ValueError, "binding"):
                write.load_profile(Path(tmp))

    def test_grant_respects_inclusive_start_and_exclusive_end(self):
        start = datetime.fromisoformat(self.profile["not_before_utc"])
        end = datetime.fromisoformat(self.profile["expires_utc"])
        tick = timedelta(seconds=1)
        self.assertEqual(end - start, timedelta(hours=2))
        with patch.object(write, "datetime", wraps=datetime) as clock:
            for now in (start - tick, end):
                clock.now.return_value = now
                with self.subTest(now=now), self.assertRaisesRegex(ValueError, "Outside approved WRITE window"):
                    write.check_grant_window()
            for now in (start, end - tick):
                clock.now.return_value = now
                with self.subTest(now=now):
                    self.assertEqual(write.check_grant_window(), now.isoformat())

    def test_iap_empty_baseline_is_fully_preserved_except_exact_grants(self):
        original = {"etag": "empty-etag"}
        additions = self.profile["policies"][write.ZONE]["add_bindings"]
        desired = write.requested_policy(write.ZONE, original, additions)
        self.assertEqual(desired["version"], 3)
        self.assertEqual(desired["etag"], original["etag"])
        after = {**desired, "etag": "new-etag"}
        write.verify_delta(write.ZONE, original, after, additions)
        with self.assertRaises(ValueError):
            write.verify_delta(write.ZONE, original, {**after, "bindings": []}, additions)
        with self.assertRaises(ValueError):
            write.requested_policy(write.PROJECT, original, [])

    def test_project_comparison_rejects_changes_to_audit_and_other_members(self):
        original = {"version": 3, "etag": "prior", "bindings": [
            {"role": "roles/browser", "members": ["user:retained@example.test"]}],
            "auditConfigs": [{"service": "storage.googleapis.com", "auditLogConfigs": [{"logType": "DATA_READ"}]}]}
        additions = self.profile["policies"][write.PROJECT]["add_bindings"]
        after = {**write.requested_policy(write.PROJECT, original, additions), "etag": "post"}
        write.verify_delta(write.PROJECT, original, after, additions)
        with self.assertRaises(ValueError):
            write.verify_delta(write.PROJECT, original, {**after, "auditConfigs": []}, additions)
        bad = deepcopy(after)
        bad["bindings"][0]["members"] = ["user:other@example.test"]
        with self.assertRaises(ValueError):
            write.verify_delta(write.PROJECT, original, bad, additions)

    def test_only_exact_policy_urls_and_current_etag_reach_setter(self):
        payload = {"etag": "post", "version": 3, "bindings": []}
        with patch.object(write.iam, "request_json") as request:
            write.set_policy(write.ZONE, payload, "fixture-token")
            write.set_policy(write.PROJECT, payload, "fixture-token")
            with self.assertRaises(ValueError):
                write.set_policy("projects/unreviewed", payload, "fixture-token")
        self.assertEqual(request.call_args_list[0].args[3], {"policy": payload})
        self.assertEqual(request.call_args_list[1].args[3], {"policy": payload, "updateMask": "bindings,etag"})

    def test_unapproved_grant_fails_before_admin_token_or_private_writes(self):
        with (patch.object(write.iam, "verify_checkout"), patch.object(write.iam, "verify_receipt_location"),
              patch.object(write.iam, "admin_token") as admin, patch("builtins.print"),
              patch.object(write, "grant") as grant):
            result = write.main(["grant", "--controls-commit", "1" * 40, "--profile-sha256", self.digest,
                                 "--receipt-dir", "synthetic"])
        self.assertEqual(result, 1)
        admin.assert_not_called()
        grant.assert_not_called()

    def test_owner_decision_must_match_existing_grant_before_any_storage_call(self):
        with TemporaryDirectory() as tmp:
            journal = Path(tmp)
            write.iam.write_new(journal / "write-receipt-reference.json", {"generation": "1"})
            with (patch.object(write.iam.custody, "fetch_verified") as fetch,
                  patch.object(write.iam.custody, "upload") as upload):
                with self.assertRaisesRegex(ValueError, "authorized WRITE"):
                    write.publish_decision(self.profile, "1" * 40, {"owner_approval_ref": "reviewed"},
                                           {"owner_approval_ref": "unreviewed", "write_receipt": {"generation": "1"}},
                                           journal)
            fetch.assert_not_called()
            upload.assert_not_called()

    def test_full_retirement_uses_fresh_zonal_etag_and_checks_before_any_write(self):
        target = write.ZONE
        before, project = {"etag": "old-iap"}, {"etag": "old-project", "version": 3, "bindings": []}
        for scope, raw in ((target, before), (write.PROJECT, project)):
            self.profile["policies"][scope]["baseline_policy_sha256"] = write.iam.digest(raw)
        adds = self.profile["policies"][target]["add_bindings"]
        payload = write.requested_policy(target, before, adds)
        live = {**payload, "etag": "live"}
        restored = {"etag": "restored"}
        with TemporaryDirectory() as tmp:
            journal = Path(tmp)
            retirement = journal / "withdrawal"
            retirement.mkdir()
            write.iam.write_new(journal / "before.json", {target: before, write.PROJECT: project})
            write.iam.write_new(journal / "1-intent.json", {"target": target, "policy": payload})
            with (patch.object(write, "get_policy", side_effect=[live, live, restored]),
                  patch.object(write, "set_policy", return_value=restored) as setter):
                self.assertEqual(write.withdraw(self.profile, "fixture-token", journal, retirement), 1)
            setter.assert_called_once_with(target, {"etag": "live", "version": 3, "bindings": []}, "fixture-token")


if __name__ == "__main__":
    unittest.main()
