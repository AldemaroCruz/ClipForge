import io
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch
from urllib.error import HTTPError

from scripts import db01_noble_read as read


class NobleReadTest(unittest.TestCase):
    def test_stable_precheck_runs_only_the_eleven_known_blockers_and_blocks_on_denial(self):
        environment = {
            "GITHUB_SHA": "a" * 40,
            "DB01_NOBLE_APPROVED_COMMIT": "a" * 40,
            "GITHUB_RUN_ID": "1234",
            "GITHUB_RUN_ATTEMPT": "1",
            "GITHUB_WORKFLOW_REF": "AldemaroCruz/ClipForge/.github/workflows/int-db01-noble-plan.yml@refs/heads/ci/bootstrap-sec03",
            "GCP_ACCESS_TOKEN": "synthetic-token",
        }
        checked = {(perm, resource, method) for perm, resource, method, _, _ in read.STABLE_PROBES}
        self.assertEqual(len(checked), 11)
        self.assertEqual(len({row[0] for row in checked}), 9)
        self.assertEqual(len({row[1] for row in checked}), 8)

        def outcome(target, _token, _reason):
            result = "denied" if target[0] == "iam.roles.get" else "allowed"
            return {"result": result, "required_for_refresh": True, "permission": target[0]}

        with TemporaryDirectory() as scratch:
            destination = Path(scratch) / "preflight.json"
            with (patch.dict(os.environ, environment | {"DB01_NOBLE_READ_REPORT": str(destination)}),
                  patch.object(read.noble.custody, "hosted_context"),
                  patch.object(read.C, "validate_variables"),
                  patch.object(read, "state_postcheck") as state,
                  patch.object(read, "probe", side_effect=outcome) as operation):
                self.assertEqual(read.main(["stable-precheck"]), 1)
            state.assert_not_called()
            self.assertEqual({call.args[0][:4] for call in operation.call_args_list},
                             {target[:4] for target in read.STABLE_PROBES})
            result = json.loads(destination.read_text(encoding="utf-8"))
        self.assertEqual(len(result["reads"]), 11)
        self.assertFalse(result["plan_executed"])
        self.assertNotIn("state_postcheck", result)

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
