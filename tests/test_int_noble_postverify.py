import base64
import copy
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import int_noble_postverify as post


CONTROLS = "a" * 40
RUN = "44880012345"
STARTED = datetime.fromisoformat("2026-11-20T15:18:00+00:00")
ATTEMPTED = datetime.fromisoformat("2026-11-20T15:18:10+00:00")
COMPLETED = datetime.fromisoformat("2026-11-20T15:19:25+00:00")
MANIFEST = {"created_utc": "2026-11-20T01:05:19.179283+00:00", "expires_utc": post.apply.PLAN_EXPIRY}


def verified_body():
    ids = {"instance_id": post.EXPECTED_INSTANCE, "boot_disk_id": post.EXPECTED_BOOT_DISK, "data_disk_id": post.EXPECTED_DATA_DISK}
    return {
        "schema": post.SCHEMA, "status": post.STATUS,
        "verifier": {"controls_commit": CONTROLS, "run_id": RUN, "attempt": "1", "workflow": post.WORKFLOW},
        "original_apply": {**copy.deepcopy(post.original_apply_binding()), "intent_at_utc": ATTEMPTED.isoformat(),
                           "operation_completed_at_utc": COMPLETED.isoformat()},
        "plan": {"producer_commit": post.apply.PRODUCER, "producer_run": post.apply.PLAN_RUN, **copy.deepcopy(post.apply.PLAN)},
        "creation": {"state": dict(post.EXPECTED_STATE), "candidate": dict(ids),
                     "control_plane": dict(ids), "debian_preserved": True,
                     "bootstrap_authorized": False, "application_authorized": False, "guest_access_performed": False,
                     "checks": post.observed_checks()},
    }


def reference(raw):
    return {"name": post.apply.producer_prefix(CONTROLS, RUN) + "foundation-state.json",
            "generation": "1801", "size": len(raw), "sha256": post.custody.sha256(raw)}


def native_log(raw):
    return {"schema": "clipforge-db01-noble-apply-native-log-1", "encoding": "base64", "size": len(raw),
            "sha256": post.custody.sha256(raw), "output": base64.b64encode(raw).decode("ascii")}


class NoblePostverification(unittest.TestCase):
    def test_plan_lifetime_is_compared_to_the_original_execution(self):
        # There is deliberately no reference to the clock when this postcheck runs.
        post.verify_execution_window(MANIFEST, STARTED, ATTEMPTED, COMPLETED)
        too_late = datetime.fromisoformat(post.apply.PLAN_EXPIRY)
        with self.assertRaisesRegex(ValueError, "plan_expired"):
            post.verify_execution_window(MANIFEST, STARTED, ATTEMPTED, too_late)
        with self.assertRaisesRegex(ValueError, "outside"):
            post.verify_execution_window(MANIFEST, STARTED, STARTED - timedelta(seconds=1), COMPLETED)

    def test_native_log_rejects_unknown_or_partial_outcomes(self):
        final = b"Apply complete! Resources: 11 added, 0 changed, 0 destroyed.\n"
        post.verify_native_log(native_log(final))
        for raw in (b"", b"Error: apply aborted\n", final + final, final.replace(b"0 changed", b"1 changed"),
                    b"Wrapped message: " + final):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                post.verify_native_log(native_log(raw))
        with self.assertRaisesRegex(ValueError, "altered or truncated"):
            post.verify_native_log({**native_log(final), "size": 1})

    def test_completion_only_accepts_the_historical_attempt_and_reviewed_step(self):
        original = {"id": int(post.ORIGINAL_RUN), "run_attempt": 1, "head_sha": post.ORIGINAL_CONTROLS,
                    "head_branch": post.apply.WORKFLOW_BRANCH, "event": "workflow_dispatch", "status": "completed",
                    "path": post.apply.WORKFLOW, "conclusion": "failure", "repository": {"full_name": post.apply.REPOSITORY}}
        job = {"name": "create-noble", "status": "completed", "conclusion": "failure", "steps": [
            {"name": "Authenticate existing Terraform identity through protected WIF", "conclusion": "success"},
            {"name": "Verify authorization, apply saved Noble binary once, and reconcile by read", "conclusion": "failure",
             "started_at": STARTED.isoformat(), "completed_at": COMPLETED.isoformat()},
            {"name": "Retain only the sanitized creation or reconciliation summary", "conclusion": "success"},
        ]}
        jobs = {"total_count": 1, "jobs": [job]}
        with patch.object(post, "read_github", side_effect=[original, jobs]):
            self.assertEqual(post.verify_original_run("placeholder"), (STARTED, COMPLETED))
        with patch.object(post, "read_github", return_value={**original, "run_attempt": 2}):
            with self.assertRaisesRegex(ValueError, "run provenance"):
                post.verify_original_run("placeholder")
        with patch.object(post, "read_github", side_effect=[original, {**jobs, "jobs": [{**job, "steps": job["steps"][:2]}]}]):
            with self.assertRaisesRegex(ValueError, "postcheck step"):
                post.verify_original_run("placeholder")

    def test_preservation_requires_the_exact_live_intent_generation(self):
        marker = {"name": post.ORIGINAL_INTENT["name"], "generation": post.ORIGINAL_INTENT["generation"],
                  "size": str(post.ORIGINAL_INTENT["size"])}
        with patch.object(post.driver, "metadata", return_value={"items": [marker]}) as read:
            post.verify_live_intent()
            self.assertEqual(read.call_args.args[1]["prefix"], marker["name"])
        for listing in ({}, {"items": [marker], "nextPageToken": "other"},
                        {"items": [{**marker, "generation": "wrong"}]}):
            with self.subTest(listing=listing), patch.object(post.driver, "metadata", return_value=listing):
                with self.assertRaisesRegex(ValueError, "one-shot marker"):
                    post.verify_live_intent()

    def test_envelope_binds_state_original_outcome_and_readback(self):
        body = verified_body()
        report = {**body, "receipt": reference(post.custody.canonical(body))}
        post.verify_envelope(report, CONTROLS, RUN)
        with self.assertRaisesRegex(ValueError, "was altered"):
            post.verify_envelope({**report, "receipt": {**report["receipt"], "sha256": "0" * 64}}, CONTROLS, RUN)
        for section, key, value in (("original_apply", "conclusion", "success"),
                                    ("creation", "state", {**post.EXPECTED_STATE, "generation": "10"}),
                                    ("creation", "application_authorized", True),
                                    ("creation", "candidate", {"instance_id": "987"}),
                                    ("verifier", "workflow", post.apply.WORKFLOW)):
            changed = copy.deepcopy(body)
            changed[section][key] = value
            with self.subTest(section=section, key=key), self.assertRaises(ValueError):
                post.verify_envelope({**changed, "receipt": reference(post.custody.canonical(changed))}, CONTROLS, RUN)

    def test_controller_creates_and_reads_only_its_own_receipt_after_checks(self):
        raw = post.custody.canonical(verified_body())
        ref = reference(raw)
        with TemporaryDirectory() as directory:
            reports = Path(directory)
            with (patch.object(post.driver, "private_paths", return_value=(reports, reports)),
                  patch.object(post.os, "umask"),
                  patch.object(post, "verify_only", return_value=verified_body()),
                  patch.object(post.custody, "upload", return_value=ref) as upload,
                  patch.object(post.custody, "fetch_verified", return_value=raw) as fetch,
                  patch.object(post.driver, "run") as terraform,
                  patch.object(post.sys, "stdout", io.StringIO())):
                self.assertEqual(post.main(["verify"]), 0)
                upload.assert_called_once_with(ref["name"], raw)
                fetch.assert_called_once_with(ref)
                terraform.assert_not_called()
            post.verify_envelope(json.loads((reports / "summary.json").read_bytes()), CONTROLS, RUN)

    def test_a_failed_read_never_creates_a_receipt_or_exposes_error_payload(self):
        with TemporaryDirectory() as directory:
            reports = Path(directory)
            with (patch.object(post.driver, "private_paths", return_value=(reports, reports)),
                  patch.object(post.os, "umask"),
                  patch.object(post, "verify_only", side_effect=ValueError("synthetic private diagnostic")),
                  patch.object(post.custody, "upload") as upload,
                  patch.object(post.sys, "stderr", io.StringIO()) as stderr):
                self.assertEqual(post.main(["verify"]), 1)
                upload.assert_not_called()
                self.assertNotIn("synthetic private diagnostic", stderr.getvalue())
            report = json.loads((reports / "summary.json").read_bytes())
            self.assertEqual(report["status"], "postverification_blocked")
            self.assertNotIn("receipt", report)


if __name__ == "__main__":
    unittest.main()
