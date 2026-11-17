"""Synthetic review/custody regressions; no cloud, real plans or repository config."""
from copy import deepcopy
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scripts import int_release as custody, check_tf_int as c, tf_int_plan as driver
from scripts import review_int_foundation_plan as review
from tests.test_int_foundation_comparison import documents, bind, resource


class FoundationPlanReview(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-candidate-review-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.module = Path(self.temp.name) / "module"
        self.module.mkdir()
        for name in c.FILES:
            target = self.module / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("Synthetic candidate source " + name)
        self.old, self.old_manifest = documents()
        self.old_manifest.update(commit=review.BASELINE, backend={"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
            "lineage": driver.INITIAL_STATE["lineage"], "serial": 1, "state_generation": driver.INITIAL_STATE["generation"],
            "state_sha256": driver.INITIAL_STATE["sha256"]})
        self.env = {"GITHUB_SHA": "f" * 40, "GITHUB_RUN_ID": "44199999999", "GITHUB_RUN_ATTEMPT": "1",
                    "INT_STAGE": "foundation", "RUNTIME_IMAGE": self.old_manifest["inputs"]["runtime_image"]}
        binding = custody.source_binding(self.module, self.env)
        self.old_manifest["provider_lock_sha256"] = binding["provider_lock_sha256"]
        self.new, self.new_manifest = deepcopy(self.old), deepcopy(self.old_manifest)
        now = datetime.now(timezone.utc).isoformat()
        self.new_manifest.update(**binding, run_id=self.env["GITHUB_RUN_ID"], run_attempt="1", created_utc=now)
        self.new["timestamp"] = now
        for plan, image in ((self.old, "debian-13-trixie-v20261109"), (self.new, review.IMAGE)):
            values = {"boot_disk": [{"initialize_params": [{"image": "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/" + image}]}]}
            resource(plan, "google_compute_instance.postgres")["change"]["after"].update(values)
            next(row for row in plan["planned_values"]["root_module"]["resources"] if row["address"] == "google_compute_instance.postgres")["values"].update(values)
        self.raw_old = bind(self.old, self.old_manifest)
        self.raw_new = bind(self.new, self.new_manifest)
        self.old_ref, self.old_manifest_bytes = self.manifest_ref(self.old_manifest)
        self.new_ref, self.new_manifest_bytes = self.manifest_ref(self.new_manifest)
        self.contract = {"plan": {**deepcopy(self.old_manifest), "manifest": self.old_ref}, "cost_usd_month": {"foundation_example": 13.93}}
        self.summary = {"status": "planned", "full_plan_retained": True, "private_plan": {
            "bucket": c.BUCKET, "manifest": self.new_ref, "binary": self.new_manifest["binary"], "json": self.new_manifest["json"]},
            "backend": {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "classification": "recognized_initial_state",
                "initial_lineage": driver.INITIAL_STATE["lineage"], "initial_state_sha256": driver.INITIAL_STATE["sha256"],
                "live": [{"name": driver.STATE_NAME, "generation": driver.INITIAL_STATE["generation"], "size": driver.INITIAL_STATE["size"]}],
                "private_sentinel": "never-publish-state-attributes"},
            "cost": {"foundation_monthly_usd": 13.93, "monthly_usd": 17.13, "assumptions": ["Synthetic cost assumption"], "sources": []}}
        self.blobs = {self.old_ref["name"]: self.old_manifest_bytes, self.new_ref["name"]: self.new_manifest_bytes,
                      self.old_manifest["json"]["name"]: self.raw_old, self.new_manifest["json"]["name"]: self.raw_new,
                      self.new_manifest["binary"]["name"]: b"authored synthetic binary"}
        binary = self.new_manifest["binary"]
        binary.update(size=len(self.blobs[binary["name"]]), sha256=custody.sha256(self.blobs[binary["name"]]))
        self.refresh_candidate_manifest()
        self.reads = []

    @staticmethod
    def manifest_ref(manifest):
        raw = custody.canonical(manifest)
        name = "private-plans/int/" + manifest["commit"] + "/" + manifest["run_id"] + "-" + manifest["run_attempt"] + "/manifest.json"
        return {"name": name, "generation": "123", "sha256": custody.sha256(raw), "size": len(raw)}, raw

    def refresh_candidate_manifest(self):
        binary = self.new_manifest["binary"]
        if binary["name"] in self.blobs:
            raw = self.blobs[binary["name"]]
            binary.update(size=len(raw), sha256=custody.sha256(raw))
        self.new_ref, self.new_manifest_bytes = self.manifest_ref(self.new_manifest)
        self.summary["private_plan"].update(manifest=self.new_ref, binary=self.new_manifest["binary"], json=self.new_manifest["json"])
        self.blobs[self.new_ref["name"]] = self.new_manifest_bytes

    def cloud_read(self, url, limit, operation, name):
        self.reads.append(name)
        query = parse_qs(urlsplit(url).query)
        self.assertEqual(query["generation"], query["ifGenerationMatch"])
        self.assertEqual(query["alt"], ["media"])
        return self.blobs[name]

    def run_review(self):
        with mock.patch.dict(review.os.environ, {"GCP_ACCESS_TOKEN": "synthetic-no-credentials"}), mock.patch.object(review, "read_private", side_effect=self.cloud_read):
            return review.review(self.summary, self.contract, self.module, self.env,
                                 image_reader=lambda: {"name": review.IMAGE, "id": review.IMAGE_ID, "status": "READY"})

    def test_complete_comparison_keeps_pin_delta_blocked_and_never_approves_apply(self):
        before = deepcopy((self.old, self.new, self.old_manifest, self.new_manifest))
        result = self.run_review()
        self.assertEqual(result["status"], "candidate_requires_owner_review")
        self.assertEqual(result["comparison"]["status"], "blocked_input_change")
        self.assertEqual(result["comparison"]["guards"], [])
        self.assertTrue(result["comparison"]["differences"])
        self.assertTrue(result["configuration_sha_changed"])
        self.assertFalse(result["apply_authorized"])
        self.assertFalse(result["security_approved"])
        self.assertEqual(result["configuration_commit"], self.env["GITHUB_SHA"])
        self.assertEqual(result["controls_commit"], self.env["GITHUB_SHA"])
        self.assertIn(self.new_manifest["binary"]["name"], self.reads)
        self.assertNotIn(driver.STATE_NAME, self.reads)
        self.assertNotIn("never-publish-state-attributes", json.dumps(result))
        self.assertEqual(before, (self.old, self.new, self.old_manifest, self.new_manifest))

    def test_additional_effective_deltas_are_preserved_in_full(self):
        resource(self.new, "google_compute_firewall.postgres")["change"]["after"]["priority"] = 999
        raw = bind(self.new, self.new_manifest)
        self.blobs[self.new_manifest["json"]["name"]] = raw
        self.refresh_candidate_manifest()
        result = self.run_review()
        self.assertTrue(any(row["category"] == "network" for row in result["comparison"]["differences"]))
        self.assertFalse(result["apply_authorized"])

    def test_current_generation_state_hash_lineage_lock_and_schema_guards_stop_review(self):
        for field, value in (("classification", "unconfirmed"), ("initial_lineage", "other"), ("initial_state_sha256", "0" * 64)):
            original = self.summary["backend"][field]
            self.summary["backend"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): self.run_review()
            self.summary["backend"][field] = original
        self.summary["backend"]["live"].append({"name": driver.LOCK_NAME, "generation": "99", "size": "100"})
        with self.assertRaises(ValueError): self.run_review()

    def test_source_commit_and_original_ttl_are_not_rebound(self):
        with self.assertRaises(ValueError): review.review(self.summary, self.contract, self.module, {**self.env, "GITHUB_SHA": "e" * 40}, fetcher=lambda ref: self.blobs[ref["name"]])
        self.new_manifest["created_utc"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
        self.refresh_candidate_manifest()
        with self.assertRaises(ValueError): self.run_review()

    def test_raw_bytes_are_verified_against_immutable_custody(self):
        self.blobs[self.new_manifest["json"]["name"]] += b" "
        with self.assertRaisesRegex(ValueError, "verification failed"): self.run_review()

    def test_same_count_cannot_hide_missing_or_unknown_addresses(self):
        self.new["resource_changes"][0]["address"] = "google_compute_instance.unreviewed"
        raw = bind(self.new, self.new_manifest)
        self.blobs[self.new_manifest["json"]["name"]] = raw
        self.refresh_candidate_manifest()
        with self.assertRaisesRegex(ValueError, "comparison guards"): self.run_review()

    def test_image_metadata_checks_real_numeric_identity_status_and_deprecation(self):
        value = {"name": review.IMAGE, "id": review.IMAGE_ID, "status": "READY", "architecture": "X86_64"}
        with mock.patch.object(review, "read_private", return_value=custody.canonical(value)):
            self.assertEqual(review.image_metadata()["id"], review.IMAGE_ID)
        for field, changed in (("id", "123"), ("status", "PENDING"), ("deprecated", {"state": "DEPRECATED"}),
                               ("deprecated", {"state": "ACTIVE", "obsolete": "2026-12-01"}), ("deprecated", False)):
            with self.subTest(field=field), mock.patch.object(review, "read_private", return_value=custody.canonical({**value, field: changed})), self.assertRaises(ValueError):
                review.image_metadata()


if __name__ == "__main__":
    unittest.main()
