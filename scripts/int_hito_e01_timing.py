"""Verify correlation of the protected E01 render comparison and task timings."""

import argparse
import json
import math
from pathlib import Path
import re

STAGES = {"prepare", "download", "probe", "validation", "model_load", "transcription", "selection", "render", "publish"}
CASES = {"process": "process", "static_export": "export", "highlight_export": "export"}
EPOCHS = {"activated_epoch", "dispatch_ack_epoch", "worker_entry_epoch", "claim_epoch", "upload_complete_observed_epoch"}


def number(value):
    return type(value) in (int, float) and math.isfinite(value) and value >= 0


def duration(start, end):
    if not number(start) or not number(end) or end < start:
        return None
    return round(end - start, 6)


def compare(browser):
    if browser["phase"] != "e01" or browser["status"] != "passed":
        raise ValueError("E01 browser evidence did not complete")
    receipts = browser["processing_receipts"]
    if not CASES.keys() <= receipts.keys():
        raise ValueError("Required processing receipts unavailable")
    result = {}
    task_ids = set()
    for case, kind in CASES.items():
        receipt = receipts[case]
        task_id = receipt["task_id"]
        timestamps = receipt["timestamps"]
        stages = receipt["stage_seconds"]
        required_stages = {"prepare", "download", "render", "publish"}
        if kind == "process":
            required_stages |= {"model_load", "transcription"}
        memory = [receipt.get(key) for key in ("container_peak_bytes_through_upload",
                                                "worker_process_peak_rss_bytes", "largest_child_peak_rss_bytes")]
        if (receipt["schema"] != 1 or receipt["kind"] != kind or type(receipt["fence"]) is not int
                or receipt["fence"] < 1 or not re.fullmatch(r"[a-f0-9]{32}", task_id) or task_id in task_ids
                or set(timestamps) != EPOCHS or not all(number(value) for key, value in timestamps.items()
                                                         if key != "dispatch_ack_epoch")
                or (timestamps["dispatch_ack_epoch"] is not None and not number(timestamps["dispatch_ack_epoch"]))
                or not required_stages <= stages.keys() <= STAGES or not all(map(number, stages.values()))
                or any(value is not None and (type(value) is not int or not 0 <= value <= 4 * 1024**3)
                       for value in memory)):
            raise ValueError("Invalid fenced worker timing receipt")
        task_ids.add(task_id)
        activated = timestamps["activated_epoch"]
        dispatched = timestamps["dispatch_ack_epoch"]
        entry = timestamps["worker_entry_epoch"]
        claimed = timestamps["claim_epoch"]
        uploaded = timestamps["upload_complete_observed_epoch"]
        if not max(activated, entry) <= claimed <= uploaded:
            raise ValueError("Worker and database clocks are not ordered")
        result[case] = {
            **receipt,
            "wait_seconds": {"activation_to_claim": duration(activated, claimed),
                             "activation_to_dispatch_ack": duration(activated, dispatched),
                             "dispatch_ack_to_worker_entry": duration(dispatched, entry),
                             "worker_entry_to_claim": duration(entry, claimed)},
            "worker_seconds": {"claim_to_upload_completion_observed": duration(claimed, uploaded)},
        }
    static, highlight = (result[case] for case in ("static_export", "highlight_export"))
    return {
        "schema": "clipforge-int-e01-processing-1", "status": "passed", "commit": browser["commit"],
        "subjects": browser.get("timing_subjects", {}), "cases": result,
        "render_delta_seconds": round(highlight["stage_seconds"]["render"] - static["stage_seconds"]["render"], 6),
        "separate_worker_entries": (
            highlight["timestamps"]["worker_entry_epoch"] != static["timestamps"]["worker_entry_epoch"]
        ),
        "memory_scope": {
            "container_peak_bytes_through_upload": "Execution high-water mark, including earlier tasks if any",
            "worker_process_peak_rss_bytes": "Media worker subprocess high-water RSS through upload",
            "largest_child_peak_rss_bytes": "Largest reaped child high-water RSS (normally FFmpeg), measured independently",
        },
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("browser", type=Path)
    parser.add_argument("receipt", type=Path)
    args = parser.parse_args()
    with args.browser.open(encoding="utf-8") as source:
        report = compare(json.load(source))
    with args.receipt.open("x", encoding="utf-8") as target:
        json.dump(report, target, indent=2)
        target.write("\n")


if __name__ == "__main__":
    main()
