from statistics import median
from unittest import TestCase

from scripts import int_hito_c_worker_profile as profile
from tests import test_int_hito_c_worker_benchmark as benchmark


class WorkerProfileEvidenceTests(TestCase):
    def setUp(self):
        self.fixture = benchmark.WorkerBenchmarkEvidenceTests()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        self.registry_image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:" + "9" * 64
        self.fixture.mutate("baseline", target_worker=self.registry_image)
        for cpus in (2, 4):
            for phase in ("before", "after"):
                self.fixture.mutate(f"cpu{cpus}-{phase}", image=self.registry_image)
            report_path = self.fixture.path(f"cpu{cpus}-benchmark")
            cases = profile.read_json(report_path)["cases"]
            for number, row in enumerate(cases.values(), 1):
                row["portal_publication"]["upload_to_first_and_all_seconds"] = 290 - cpus * 10 + number
            self.fixture.mutate(f"cpu{cpus}-benchmark", cases=cases)
        self.run_metadata = {"id": 123, "run_attempt": 1, "head_sha": benchmark.CANDIDATE,
                             "status": "completed", "conclusion": "success", "path": profile.WORKFLOW,
                             "head_branch": "ci/bootstrap-sec03", "event": "workflow_dispatch"}
        self.artifact = {"id": 987, "name": "worker-benchmark-123-1", "expired": False,
                         "digest": "sha256:" + "e" * 64, "workflow_run": {"id": 123, "head_sha": benchmark.CANDIDATE}}
        base, rollback, groups, *_ = self.fixture.study()
        measured = {"schema": "clipforge-int-worker-benchmark-comparison-1", "public": base["public"],
                    "fixture": base["fixture"], "comparison_commit": benchmark.CANDIDATE,
                    "restored_worker": rollback["worker"], "cohorts": {}}
        for cpus, (browser, worker) in groups.items():
            cases = {
                name: {"execution": f"clipforge-int-worker-{cpus}{index:04d}", "provider_calls": 0,
                       "claim_to_atomic_publication_seconds": 210 - cpus * 10 + index,
                       "portal_publication": result["portal_publication"]}
                for index, (name, result) in enumerate(browser["cases"].items())
            }
            measured["cohorts"][str(cpus)] = {
                "worker": worker, "cases": cases,
                "median_claim_to_atomic_publication_seconds": median(
                    case["claim_to_atomic_publication_seconds"] for case in cases.values()),
                "median_upload_to_first_and_all_seconds": median(
                    case["portal_publication"]["upload_to_first_and_all_seconds"] for case in cases.values()),
            }
        self.decision = {"schema": profile.SCHEMA, "reason": "Synthetic test selection evidence only.",
                         "comparison": profile.comparison_ref(self.run_metadata, self.artifact),
                         "reports": {name: profile.file_sha(self.root / name) for name in profile.FILES},
                         "measurement": measured}

    def verify(self, cpu=4):
        return profile.verify({**self.decision, "worker_cpu": cpu}, self.root, self.run_metadata, self.artifact)

    def test_both_allowed_resources_use_the_exact_same_tested_digest(self):
        for cpus in (2, 4):
            result = self.verify(cpus)
            self.assertEqual(result["tested_worker"]["image"], self.registry_image)
            self.assertEqual(result["tested_worker"]["cpu"], str(cpus))
            self.assertEqual(result["tested_worker"]["memory"], "4Gi")
            self.assertEqual(result["previous_worker"]["cpu"], "2")

    def test_hashed_native_receipt_and_github_artifact_must_match(self):
        original = self.artifact["digest"]
        self.artifact["digest"] = "sha256:" + "3" * 64
        with self.assertRaisesRegex(ValueError, "artifact identity"):
            self.verify()
        self.artifact["digest"] = original
        path = self.fixture.path("cpu2-before")
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "receipt bytes changed"):
            self.verify()

    def test_measurement_must_match_the_cohort_and_observed_times(self):
        measured = self.decision["measurement"]["cohorts"]["4"]
        measured["median_claim_to_atomic_publication_seconds"] += 1
        with self.assertRaisesRegex(ValueError, "measured medians"):
            self.verify()
        measured["worker"] = {**measured["worker"], "image": "wrong image"}
        with self.assertRaisesRegex(ValueError, "cohort is incomplete"):
            self.verify()
