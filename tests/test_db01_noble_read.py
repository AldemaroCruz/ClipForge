import io
import json
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from scripts import db01_noble_read as read


class NobleReadTest(unittest.TestCase):
    def test_targets_are_fixed_metadata_or_policy_reads(self):
        self.assertEqual(len({target[3] for target in read.PROBES}), len(read.PROBES))
        for permission, _, method, url, body in read.PROBES:
            with self.subTest(permission=permission):
                self.assertTrue(url.startswith("https://"))
                self.assertNotIn("/versions", url)
                self.assertNotIn("setIamPolicy", url)
                self.assertIn(method, {"GET", "POST"})
                if method == "POST":
                    self.assertIn(":getIamPolicy", url)
                    self.assertIn(body, (None, read.POLICY_BODY))

    def test_denial_is_bound_to_one_fixed_read_and_errors_are_independent(self):
        target = next(row for row in read.PROBES if row[0] == "logging.buckets.get")
        denied = {"error": {"message": "Permission 'logging.buckets.get' denied", "details": [
            {"reason": "IAM_PERMISSION_DENIED", "metadata": {"permission": target[0], "private": "response marker"}}
        ]}}
        scope = {"error": {"message": "Request had insufficient authentication scopes"}}
        errors = [HTTPError(target[3], 403, "", {}, io.BytesIO(json.dumps(body).encode())) for body in (denied, scope)]
        with patch.object(read, "build_opener") as opener:
            opener.return_value.open.side_effect = [*errors, OSError()]
            rows = [read.probe(target, "test-only", "DB01 test") for _ in range(3)]
        self.assertEqual([row["result"] for row in rows], ["denied", "http_error", "unverified"])
        self.assertEqual(rows[0]["permission"], target[0])
        self.assertEqual(rows[0]["resource"], target[1])
        self.assertNotIn("response marker", json.dumps(rows))

    def test_state_postcheck_reuses_identity_and_confirms_live_inventory(self):
        identity = {**read.noble.foundation.STATE_PIN, "current_lock_absent": True}
        item = {key: str(identity[key]) for key in ("name", "generation", "size")}
        lock = {"name": read.DRIVER.LOCK_NAME, "generation": "1", "size": "1"}
        with patch.object(read.noble, "state_identity", return_value=identity), patch.object(
            read.DRIVER, "metadata", side_effect=[{"items": [item]}, {"items": [item, lock]}, {"nextPageToken": "second"}]
        ):
            verified, raced, incomplete = [read.state_postcheck() for _ in range(3)]
        self.assertEqual(verified["result"], "verified")
        self.assertEqual(verified["sha256"], identity["sha256"])
        self.assertIs(verified["current_lock_absent"], True)
        self.assertEqual(raced["result"], "unverified")
        self.assertIs(raced["current_lock_absent"], False)
        self.assertEqual(incomplete["result"], "unverified")
        self.assertNotIn("current_lock_absent", incomplete)
