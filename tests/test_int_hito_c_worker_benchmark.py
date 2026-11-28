"""Validate matched work, approval scope, and restoration without cloud access."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from unittest import TestCase

from scripts import int_hito_b_capacity_browser as capacity
from scripts import int_hito_c_worker_benchmark_receipt as receipt


BASE = "a" * 40
CANDIDATE = "b" * 40
PUBLIC = {"commit": BASE, "frontend_revision": "clipforge-int-beta-00053-abc",
          "api_revision": "clipforge-int-beta-api-00054-def"}
FIXTURE = {"sha256": "1" * 64, "duration_seconds": 600, "bytes": 140_000_000}
START = datetime(2026, 11, 27, 21, tzinfo=timezone.utc)
WORKER = {"image": "accepted-digest", "source": BASE, "cpu": "2", "memory": "4Gi",
          "generation": 41, "observed_generation": 41, "configuration_sha256": "2" * 64}


class WorkerBenchmarkEvidenceTests(TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.save("baseline", {"schema": "clipforge-int-worker-benchmark-1", "public": PUBLIC,
                              "worker": WORKER, "target_commit": CANDIDATE,
                              "target_worker": "candidate-digest", "fixture": FIXTURE})
        self.save("restored", {"status": "passed", "worker": {
            **WORKER, "generation": 44, "observed_generation": 44,
        }})
        for cpu, minute in ((2, 0), (4, 10)):
            scope = {"schema": capacity.SCHEMA, "status": "passed", "run_id": "123", "run_attempt": "1",
                     "commit": BASE, "editorial_model": "",
                     "revisions": {"frontend": PUBLIC["frontend_revision"], "api": PUBLIC["api_revision"]},
                     "benchmark": {"cpu": cpu, "sha256": FIXTURE["sha256"]},
                     "synthetic_account_ids": [f"{cpu * 10 + index:032x}" for index in range(3)]}
            for phase in ("benchmark", "setup", "cleanup"):
                self.save(f"cpu{cpu}-{phase}", {
                    **scope, "phase": phase, "phase_started_utc": (START + timedelta(minutes=minute)).isoformat(),
                    "phase_finished_utc": (START + timedelta(minutes=minute + 5)).isoformat(),
                    "synthetic_accounts_deactivated": True, "creators_logged_in": 3, "benchmark_fixture": FIXTURE,
                    "cases": {
                        name: {"synthetic_job_id": f"{cpu * 30 + index:032x}", "bytes": FIXTURE["bytes"],
                               "status": "passed", "clips": {str(item): {"sha256": "9" * 64} for item in range(5)},
                               "automatic_captions_verified": True,
                               "portal_publication": {"first_and_all_observed_atomically": True}}
                        for index, name in enumerate(sorted(receipt.CASE_NAMES))
                    },
                })
            worker = {**WORKER, "image": "candidate-digest", "source": CANDIDATE, "cpu": str(cpu),
                      "generation": 41 + cpu // 2, "observed_generation": 41 + cpu // 2}
            for phase in ("before", "after"):
                self.save(f"cpu{cpu}-{phase}", worker)

    def path(self, name):
        return self.root / f"worker-benchmark-{name}.json"

    def save(self, name, value):
        self.path(name).write_text(json.dumps(value), encoding="utf-8")

    def mutate(self, name, **change):
        value = receipt.read_json(self.path(name))
        self.save(name, {**value, **change})

    def study(self):
        return receipt.study(self.root, CANDIDATE, "123", "1")

    def test_scope_matches_only_six_synthetic_jobs_and_their_native_events(self):
        base, rollback, groups, jobs, start, end = self.study()
        self.assertEqual(base["public"], PUBLIC)
        self.assertEqual(rollback["worker"]["cpu"], "2")
        self.assertEqual(set(groups), {2, 4})
        self.assertEqual(len(jobs), 6)
        selected = receipt.filter_for(jobs, start, end)
        self.assertEqual(selected.count("jsonPayload.job_id="), 6)
        self.assertEqual(selected.count("jsonPayload.event="), 4)

    def test_mismatched_fixture_and_rollback_are_rejected(self):
        self.mutate("cpu4-benchmark", benchmark_fixture={**FIXTURE, "sha256": "3" * 64})
        with self.assertRaisesRegex(ValueError, "Browser comparison scope"):
            self.study()
        self.mutate("cpu4-benchmark", benchmark_fixture=FIXTURE)
        self.mutate("restored", worker={**WORKER, "cpu": "4"})
        with self.assertRaisesRegex(ValueError, "Verified worker restoration"):
            self.study()

    def test_execution_resources_must_match_the_measured_cohort(self):
        execution_name = "clipforge-int-worker-abcde"
        task = {"task_id": "f" * 32, "execution": execution_name, "fence": 1}
        at = lambda seconds: START + timedelta(seconds=seconds)
        events = {
            "worker_claim": (at(6), {**task, "worker_started_epoch": at(5).timestamp()}),
            "worker_results_published": (at(35), {**task, "kind": "process"}),
            "worker_finish": (at(36), {**task, "status": "succeeded"}),
            "worker_resources": (at(37), {
                **task, "kind": "process", "status": "succeeded", "stage_seconds": {key: 1 for key in receipt.STAGES},
                "clip_renders": [{"render_seconds": 1, "seconds_since_recorder_start": i} for i in range(10, 15)],
                "child_rss_max_sampled_bytes": 100, "cgroup_memory_peak_bytes_execution": None,
                "cgroup_memory_max_sampled_bytes": None, "scratch_max_sampled_bytes": 200,
            }),
        }
        case = {"state_observations": [{"at_utc": at(3).isoformat(), "seconds_after_activation": 3}],
                "upload_seconds": 2, "portal_publication": {"first_and_all_observed_atomically": True}}
        executions = {execution_name: {
            **WORKER, "created_at": at(1).isoformat(), "start_at": at(3).isoformat(),
        }}
        values = receipt.measurements(case, WORKER, events, executions)
        self.assertEqual(values["claim_to_atomic_publication_seconds"], 29)
        self.assertEqual(len(values["per_clip_render"]), 5)
        self.assertIsNone(values["container_memory_peak_bytes"])
        executions[execution_name]["cpu"] = "4"
        with self.assertRaisesRegex(ValueError, "Actual execution resources"):
            receipt.measurements(case, WORKER, events, executions)

    def test_browser_checkpoint_cannot_be_read_as_the_other_cohort(self):
        setup = receipt.read_json(self.path("cpu2-setup"))
        setup["url"] = capacity.PUBLIC
        setup["checks"] = []
        setup["phase_receipts"] = {}
        setup.pop("benchmark_fixture")
        setup.pop("synthetic_accounts_deactivated")
        self.save("cpu2-setup", setup)
        self.path("cpu2-setup").chmod(0o600)
        identity = capacity.checkpoint_identity(setup)
        matched = capacity.load_checkpoint(self.path("cpu2-setup"), "setup", identity)
        self.assertEqual(len(matched["synthetic_account_ids"]), 3)
        with self.assertRaisesRegex(capacity.BrowserAcceptanceError, "capacity_checkpoint_identity"):
            capacity.load_checkpoint(
                self.path("cpu2-setup"), "setup", {**identity, "benchmark": {"cpu": 4, "sha256": FIXTURE["sha256"]}},
            )
