from datetime import datetime, timezone
from unittest import TestCase

from scripts.int_hito_e02_startup import case, filter_log, matching_claim

EXECUTION = "clipforge-int-worker-ab123"
NATIVE = "projects/816643438938/locations/us-central1/jobs/clipforge-int-worker/executions/" + EXECUTION
OPERATION = "projects/clipforgebeta2/locations/us-central1/operations/" + "a" * 32


def iso(stamp):
    return datetime.fromtimestamp(stamp, timezone.utc).isoformat()


def source(new=True):
    data = {"job_id": "a" * 32, "receipt": {"schema": 1, "task_id": "b" * 32, "fence": 1,
            "timestamps": {"activated_epoch": 100, "dispatch_ack_epoch": 101,
                           "worker_entry_epoch": 172.5, "claim_epoch": 173}}}
    if new:
        data["receipt"]["startup"] = {"execution": EXECUTION, "dispatch_operation": OPERATION,
                                      "module_entry_epoch": 172, "imports_end_epoch": 172.4}
    return data


def claim(data, execution=EXECUTION, fence=1):
    return {"jsonPayload": {"event": "worker_claim", "job_id": data["job_id"],
                           "task_id": data["receipt"]["task_id"], "fence": fence,
                           "execution": execution, "worker_started_epoch": 172.5}}


class StartupCaseTests(TestCase):
    def test_current_imports_and_control_plane_are_distinct(self):
        data = source()
        dispatch = {"jsonPayload": {"event": "worker_dispatch_ack", "task_id": data["receipt"]["task_id"],
                                    "operation": OPERATION, "request_epoch": 100.8}}
        execution = {"name": NATIVE, "createTime": iso(103), "startTime": iso(106)}
        task = {"execution": NATIVE, "createTime": iso(104), "scheduledTime": iso(110),
                "startTime": iso(171), "index": 0}
        operation = {"name": OPERATION, "response": {"name": NATIVE}}
        receipt = case(data, EXECUTION, OPERATION, execution, {"tasks": [task]}, operation, [], [dispatch], {})
        self.assertTrue(receipt["dispatch_matches_claimed_execution"])
        measures = receipt["interval_seconds"]
        self.assertEqual(measures["dispatch_request_to_ack"], 0.2)
        self.assertEqual(measures["dispatch_ack_to_execution_creation"], 2)
        self.assertEqual(measures["task_creation_to_scheduled"], 6)
        self.assertEqual(measures["task_scheduled_to_started"], 61)
        self.assertEqual(measures["task_started_to_python_module_entry"], 1)
        self.assertEqual(measures["python_module_entry_to_imports_complete"], 0.4)
        self.assertEqual(measures["worker_supervisor_entry_to_claim"], 0.5)

    def test_historical_claim_requires_same_exact_fence_and_known_time(self):
        data = source(new=False)
        wrong = claim(data, fence=2)
        good = claim(data)
        self.assertEqual(matching_claim(data, [wrong, good]), EXECUTION)
        self.assertEqual(matching_claim(data, [wrong]), "")
        self.assertEqual(matching_claim(data, [good, good]), "")
        self.assertIn(data["receipt"]["task_id"], filter_log(data, "claim"))
        receipt = case(data, EXECUTION, "", {"name": NATIVE}, {}, {}, [good], [],
                       {"dispatch_log": "permission_denied"})
        self.assertEqual(receipt["interval_seconds"]["dispatch_ack_to_worker_supervisor_entry"], 71.5)
        self.assertIsNone(receipt["interval_seconds"]["python_module_entry_to_imports_complete"])
        self.assertIsNone(receipt["interval_seconds"]["dispatch_request_to_ack"])

    def test_an_operation_for_a_different_execution_does_not_join_timelines(self):
        data = source()
        operation = {"name": OPERATION, "metadata": {"name": NATIVE.replace("ab123", "cd456")}}
        receipt = case(data, EXECUTION, OPERATION, {"name": NATIVE}, {}, operation, [], [], {})
        self.assertFalse(receipt["dispatch_matches_claimed_execution"])
        self.assertNotIn("dispatch_ack_to_execution_creation", receipt["interval_seconds"])
