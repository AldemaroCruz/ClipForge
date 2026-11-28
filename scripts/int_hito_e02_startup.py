"""Correlate content-free task receipts with narrow Cloud Run metadata."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re


EXECUTION = re.compile(r"clipforge-int-worker-[a-z0-9]{5,12}")
IDENTITY = re.compile(r"[a-f0-9]{32}")
JOB_PATH = r"projects/(?:clipforgebeta2|816643438938)/locations/us-central1/jobs/clipforge-int-worker"
OPERATION = re.compile(r"projects/(?:clipforgebeta2|816643438938)/locations/us-central1/operations/[a-z0-9-]{8,80}")


def epoch(value):
    if type(value) in (float, int) and math.isfinite(value) and value > 0:
        return value
    if isinstance(value, str):
        try:
            stamp = datetime.fromisoformat(value)
            return stamp.timestamp() if stamp.tzinfo is not None else None
        except (ValueError, OverflowError):
            return None
    return None


def diff(left, right):
    a, b = epoch(left), epoch(right)
    return round(b - a, 6) if a is not None and b is not None else None


def subject(data):
    if not isinstance(data, dict) or not isinstance(data.get("job_id"), str) or not IDENTITY.fullmatch(data["job_id"]):
        raise ValueError("Missing authorized synthetic timing subject")
    receipt = data["receipt"]
    task = receipt["task_id"]
    if not (receipt["schema"] == 1 and isinstance(task, str) and IDENTITY.fullmatch(task)
            and type(receipt["fence"]) is int and receipt["fence"] > 0):
        raise ValueError("Invalid fenced timing receipt")
    return data


def filter_log(data, kind):
    data = subject(data)
    receipt = data["receipt"]
    stamps = receipt["timestamps"]
    if kind == "claim":
        name, resource, label, value, timestamp = (
            "worker_claim", "cloud_run_job", "job_name", "clipforge-int-worker", stamps["claim_epoch"],
        )
    else:
        name, resource, label, value, timestamp = (
            "worker_dispatch_ack", "cloud_run_revision", "service_name", "clipforge-int-beta-api",
            stamps["dispatch_ack_epoch"],
        )
    moment = epoch(timestamp)
    if moment is None:
        return ""
    center = datetime.fromtimestamp(moment, timezone.utc)
    start, end = (center + timedelta(seconds=offset) for offset in (-30, 30))
    return (f'resource.type="{resource}" AND resource.labels.{label}="{value}" '
            f'AND timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" '
            f'AND jsonPayload.event="{name}" AND jsonPayload.task_id="{receipt["task_id"]}"')


def matching_claim(data, rows):
    values = data["receipt"]
    entry = values["timestamps"]["worker_entry_epoch"]
    output = []
    for row in rows:
        log = row.get("jsonPayload", {})
        execution = log.get("execution", "")
        observed = epoch(log.get("worker_started_epoch"))
        if (log.get("event") == "worker_claim" and log.get("job_id") == data["job_id"]
                and log.get("task_id") == values["task_id"] and log.get("fence") == values["fence"]
                and observed is not None and abs(observed - entry) <= 0.01 and EXECUTION.fullmatch(execution)):
            output.append(execution)
    return output[0] if len(output) == 1 else ""


def dispatch_timestamp(data, rows, operation):
    if not operation:
        return None
    values = data["receipt"]
    ack = epoch(values["timestamps"].get("dispatch_ack_epoch"))
    output = []
    for row in rows:
        log = row.get("jsonPayload", {})
        request = epoch(log.get("request_epoch"))
        if (log.get("event") == "worker_dispatch_ack" and log.get("task_id") == values["task_id"]
                and log.get("operation") == operation and ack is not None
                and request is not None and 0 <= ack - request <= 30):
            output.append(request)
    return output[0] if len(output) == 1 else None


def execution_name(payload):
    name = payload.get("name", "")
    match = re.fullmatch(JOB_PATH + r"/executions/([a-z0-9-]+)", name) if isinstance(name, str) else None
    return match.group(1) if match and EXECUTION.fullmatch(match.group(1)) else ""


def case(data, execution, operation, execution_data, task_data, operation_data, claims, dispatches, statuses):
    data = subject(data)
    values = data["receipt"]
    stamps = values["timestamps"]
    startup = values.get("startup", {})
    previous = not bool(startup)
    effective_execution = startup.get("execution", "") or matching_claim(data, claims)
    if execution != effective_execution or not EXECUTION.fullmatch(execution):
        execution = ""
    match = execution and execution_name(execution_data) == execution
    same_tasks = [task for task in task_data.get("tasks", [])
                  if re.fullmatch(JOB_PATH + "/executions/" + re.escape(execution), task.get("execution", ""))
                  and task.get("index", 0) == 0 and task.get("retried", 0) == 0]
    task = same_tasks[0] if match and len(same_tasks) == 1 else {}
    execution_data = execution_data if match else {}
    operation_execution = ""
    if operation and operation_data.get("name") == operation:
        for candidate in (operation_data.get("response", {}), operation_data.get("metadata", {})):
            operation_execution = execution_name(candidate)
            if operation_execution:
                break
    dispatch = dispatch_timestamp(data, dispatches, operation)
    module = startup.get("module_entry_epoch")
    imports = startup.get("imports_end_epoch")
    entry, claim = (stamps[key] for key in ("worker_entry_epoch", "claim_epoch"))
    captured = {
        "activation": stamps["activated_epoch"], "dispatch_request": dispatch,
        "dispatch_ack": stamps.get("dispatch_ack_epoch"), "execution_created": epoch(execution_data.get("createTime")),
        "execution_started": epoch(execution_data.get("startTime")), "task_created": epoch(task.get("createTime")),
        "task_scheduled": epoch(task.get("scheduledTime")), "task_started": epoch(task.get("startTime")),
        "python_module_entry": module, "application_imports_complete": imports,
        "worker_supervisor_entry": entry, "claim": claim,
    }
    pairs = {
        "activation_to_dispatch_ack": ("activation", "dispatch_ack"),
        "dispatch_request_to_ack": ("dispatch_request", "dispatch_ack"),
        "dispatch_ack_to_worker_supervisor_entry": ("dispatch_ack", "worker_supervisor_entry"),
        "execution_creation_to_task_creation": ("execution_created", "task_created"),
        "task_creation_to_scheduled": ("task_created", "task_scheduled"),
        "task_scheduled_to_started": ("task_scheduled", "task_started"),
        "task_started_to_python_module_entry": ("task_started", "python_module_entry"),
        "python_module_entry_to_imports_complete": ("python_module_entry", "application_imports_complete"),
        "imports_complete_to_worker_supervisor_entry": ("application_imports_complete", "worker_supervisor_entry"),
        "worker_supervisor_entry_to_claim": ("worker_supervisor_entry", "claim"),
    }
    if operation_execution and operation_execution == execution:
        pairs["dispatch_ack_to_execution_creation"] = ("dispatch_ack", "execution_created")
    return {"job_id": data["job_id"], "task_id": values["task_id"], "fence": values["fence"],
            "execution": execution or None, "dispatch_operation": operation or None,
            "dispatch_execution": operation_execution or None,
            "dispatch_matches_claimed_execution": (operation_execution == execution if operation_execution and execution else None),
            "stamps_epoch": captured, "interval_seconds": {key: diff(captured[a], captured[b]) for key, (a, b) in pairs.items()},
            "cloud_reads": statuses, "historical_e01": previous}


def read(path, default=None):
    if not path.is_file():
        return default
    if path.is_symlink() or path.stat().st_size > 1024 * 1024:
        raise ValueError("Invalid startup evidence input")
    with path.open(encoding="utf-8") as stream:
        return json.load(stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("claim-filter", "dispatch-filter", "execution", "operation", "summarize"))
    parser.add_argument("subject", type=Path)
    parser.add_argument("inputs", type=Path)
    args = parser.parse_args()
    data = subject(read(args.subject))
    startup = data["receipt"].get("startup", {})
    if args.action in {"claim-filter", "dispatch-filter"}:
        print(filter_log(data, args.action.removesuffix("-filter")))
        return
    claims = read(args.inputs / "claims.json", [])
    dispatch = read(args.inputs / "dispatch.json", [])
    operation = startup.get("dispatch_operation", "")
    operation = operation if OPERATION.fullmatch(operation) else ""
    execution = startup.get("execution", "") or matching_claim(data, claims)
    execution = execution if EXECUTION.fullmatch(execution) else ""
    if args.action == "execution":
        print(execution)
    elif args.action == "operation":
        print(operation)
    else:
        payload = case(data, execution, operation, read(args.inputs / "execution.json", {}),
                       read(args.inputs / "tasks.json", {}), read(args.inputs / "operation.json", {}),
                       claims, dispatch, read(args.inputs / "http.json", {}))
        print(json.dumps(payload, ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
