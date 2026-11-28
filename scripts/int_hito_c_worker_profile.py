"""Bind an INT worker resource decision to its successful protected comparison."""

import argparse
import hashlib
import json
import math
from pathlib import Path
import re
from statistics import median

from scripts.int_hito_c_worker_benchmark_receipt import CASE_NAMES, EXECUTION, FULL_SHA, read_json, require, study


POLICY = Path("config/int-worker-profile.json")
SCHEMA = "clipforge-int-worker-profile-1"
ID = re.compile(r"[1-9][0-9]{0,19}")
SHA256 = re.compile(r"[a-f0-9]{64}")
WORKFLOW = ".github/workflows/int-hito-b.yml"
FILES = {"worker-benchmark-baseline.json", "worker-benchmark-restored.json"} | {
    f"worker-benchmark-cpu{cpu}-{phase}.json"
    for cpu in (2, 4) for phase in ("setup", "benchmark", "before", "after", "cleanup")
}


def file_sha(path):
    read_json(path)
    with path.open("rb") as source:
        return hashlib.file_digest(source, "sha256").hexdigest()


def comparison_ref(run, artifact):
    commit = run["head_sha"]
    run_id, attempt, artifact_id = (str(item) for item in (run["id"], run["run_attempt"], artifact["id"]))
    require(FULL_SHA.fullmatch(commit) and all(ID.fullmatch(value) for value in (run_id, attempt, artifact_id))
            and run["status"] == "completed" and run["conclusion"] == "success"
            and run["path"].split("@")[0] == WORKFLOW and run["head_branch"] == "ci/bootstrap-sec03"
            and run["event"] == "workflow_dispatch", "Expected successful protected worker comparison")
    require(artifact["name"] == f"worker-benchmark-{run_id}-{attempt}" and artifact["expired"] is False
            and str(artifact["workflow_run"]["id"]) == run_id and artifact["workflow_run"]["head_sha"] == commit
            and re.fullmatch(r"sha256:[a-f0-9]{64}", artifact["digest"]), "Expected native comparison artifact")
    return {"commit": commit, "run_id": run_id, "attempt": attempt,
            "artifact_id": artifact_id, "artifact_digest": artifact["digest"]}


def decision(path):
    value = read_json(path)
    require(set(value) == {"schema", "worker_cpu", "reason", "comparison", "reports", "measurement"}
            and value["schema"] == SCHEMA and type(value["worker_cpu"]) is int and value["worker_cpu"] in (2, 4)
            and isinstance(value["reason"], str) and 20 <= len(value["reason"].strip()) <= 500,
            "An observed worker profile decision is required")
    ref = value["comparison"]
    require(set(ref) == {"commit", "run_id", "attempt", "artifact_id", "artifact_digest"}
            and FULL_SHA.fullmatch(ref["commit"])
            and all(ID.fullmatch(ref[key]) for key in ("run_id", "attempt", "artifact_id"))
            and re.fullmatch(r"sha256:[a-f0-9]{64}", ref["artifact_digest"])
            and set(value["reports"]) == FILES and all(SHA256.fullmatch(sha) for sha in value["reports"].values()),
            "Exact comparison artifact and file identities are required")
    return value


def verify(value, reports, run, artifact):
    ref = comparison_ref(run, artifact)
    require(ref == value["comparison"] and
            set(value["reports"]) == FILES and all(file_sha(reports / name) == value["reports"][name] for name in FILES),
            "Comparison artifact identity or receipt bytes changed")
    base, rollback, groups, *_ = study(reports, ref["commit"], ref["run_id"], ref["attempt"])
    measurement = value["measurement"]
    require(measurement["schema"] == "clipforge-int-worker-benchmark-comparison-1"
            and measurement["public"] == base["public"] and measurement["fixture"] == base["fixture"]
            and measurement["comparison_commit"] == ref["commit"]
            and measurement["restored_worker"] == rollback["worker"] and set(measurement["cohorts"]) == {"2", "4"},
            "The measured comparison does not describe the pinned trial")
    identities = set()
    for cpus, (browser, worker) in groups.items():
        measured = measurement["cohorts"][str(cpus)]
        cases = measured["cases"]
        require(measured["worker"] == worker and set(cases) == CASE_NAMES, "The measured cohort is incomplete")
        for name, case in cases.items():
            elapsed = case["claim_to_atomic_publication_seconds"]
            name_in_cloud = case["execution"]
            require(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 < elapsed <= 1200
                    and EXECUTION.fullmatch(name_in_cloud) and name_in_cloud not in identities
                    and case["portal_publication"] == browser["cases"][name]["portal_publication"]
                    and case["provider_calls"] == 0, "The operator receipt does not match its synthetic case")
            identities.add(name_in_cloud)
        require(measured["median_claim_to_atomic_publication_seconds"] ==
                median(case["claim_to_atomic_publication_seconds"] for case in cases.values())
                and measured["median_upload_to_first_and_all_seconds"] ==
                median(case["portal_publication"]["upload_to_first_and_all_seconds"] for case in cases.values()),
                "The measured medians do not match their cases")
    worker = groups[value["worker_cpu"]][1]
    require(re.fullmatch(r"us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/beta-worker@sha256:[a-f0-9]{64}",
                         worker["image"]) and worker["memory"] == "4Gi", "Selected worker digest")
    return {"schema": "clipforge-int-worker-profile-verified-1", "status": "passed",
            "public": base["public"], "previous_worker": rollback["worker"], "tested_worker": worker,
            "comparison": ref, "worker_cpu": value["worker_cpu"]}


def write_json(path, value):
    with path.open("x", encoding="utf-8") as result:
        json.dump(value, result, indent=2, sort_keys=True)
        result.write("\n")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("refs", "bind", "verify"))
    parser.add_argument("--policy", type=Path, default=POLICY)
    parser.add_argument("--reports", type=Path)
    parser.add_argument("--run-metadata", type=Path)
    parser.add_argument("--artifact-metadata", type=Path)
    parser.add_argument("--measurement", type=Path)
    parser.add_argument("--cpu", type=int, choices=(2, 4))
    parser.add_argument("--reason")
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    if args.action == "refs":
        print(json.dumps(decision(args.policy)["comparison"], sort_keys=True))
        return
    run, artifact = read_json(args.run_metadata), read_json(args.artifact_metadata)
    if args.action == "bind":
        require(args.cpu in (2, 4) and args.reason and 20 <= len(args.reason.strip()) <= 500,
                "Select the measured CPU and record a reason")
        value = {"schema": SCHEMA, "worker_cpu": args.cpu, "reason": args.reason.strip(),
                 "comparison": comparison_ref(run, artifact), "reports": {name: file_sha(args.reports / name) for name in FILES},
                 "measurement": read_json(args.measurement)}
        verify(value, args.reports, run, artifact)
        write_json(args.policy, value)
    else:
        write_json(args.output, verify(decision(args.policy), args.reports, run, artifact))


if __name__ == "__main__":
    main()
