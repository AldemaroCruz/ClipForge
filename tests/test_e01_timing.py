from unittest import TestCase

from scripts.int_hito_e01_timing import compare


def task(kind, token, *, activated, dispatch, entry, claim, render):
    stages = {"prepare": 1, "download": 0.1, "render": render, "publish": 0.4}
    if kind == "process":
        stages.update(model_load=0.2, transcription=12)
    return {
        "schema": 1, "task_id": token * 32, "fence": 1, "kind": kind,
        "timestamps": {
            "activated_epoch": activated, "dispatch_ack_epoch": dispatch,
            "worker_entry_epoch": entry, "claim_epoch": claim,
            "upload_complete_observed_epoch": claim + sum(stages.values()),
        },
        "stage_seconds": stages, "container_peak_bytes_through_upload": 1024**3,
    }


class E01TimingTests(TestCase):
    def report(self):
        return {
            "phase": "e01", "status": "passed", "commit": "f" * 40,
            "processing_receipts": {
                "process": task("process", "a", activated=100, dispatch=101, entry=117, claim=120, render=5),
                "static_export": task("export", "b", activated=145, dispatch=147, entry=170, claim=171, render=0.8),
                "highlight_export": task("export", "c", activated=181, dispatch=None, entry=170, claim=182, render=1.06),
            },
        }

    def test_queue_breakdown_separates_worker_durations_and_allows_reused_worker(self):
        actual = compare(self.report())
        self.assertAlmostEqual(actual["render_delta_seconds"], 0.26)
        self.assertFalse(actual["separate_worker_entries"])
        self.assertEqual(actual["cases"]["process"]["wait_seconds"], {
            "activation_to_claim": 20, "activation_to_dispatch_ack": 1,
            "dispatch_ack_to_worker_entry": 16, "worker_entry_to_claim": 3,
        })
        self.assertIsNone(actual["cases"]["highlight_export"]["wait_seconds"]["dispatch_ack_to_worker_entry"])

    def test_unrelated_or_invalid_receipt_is_rejected(self):
        report = self.report()
        report["processing_receipts"]["highlight_export"]["task_id"] = "b" * 32
        with self.assertRaises(ValueError):
            compare(report)
        report = self.report()
        report["processing_receipts"]["highlight_export"]["timestamps"]["claim_epoch"] = 120
        with self.assertRaises(ValueError):
            compare(report)
