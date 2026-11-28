"""Bind a protected INT worker comparison to native browser and Cloud Run evidence."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import math
from pathlib import Path
import re
from statistics import median


CASE_NAMES = {"creator_1", "creator_2", "creator_3"}
SUBJECT_EVENTS = {"worker_claim", "worker_results_published", "worker_resources", "worker_finish"}
STAGES = {"download", "probe", "validation", "model_load", "transcription", "selection", "render", "publish"}
EXECUTION = re.compile(r"clipforge-int-worker-[a-z0-9]{5}")
FULL_SHA = re.compile(r"[a-f0-9]{40}")
ID = re.compile(r"[a-f0-9]{32}")


def require(value, message):
    if not value:
        raise ValueError(message)


def read_json(path):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 2 * 1024 * 1024,
            "Invalid comparison evidence file")
    with path.open("rb") as source:
        return json.load(source)


def instant(text):
    value = datetime.fromisoformat(text)
    require(value.tzinfo is not None, "Timestamp must include UTC offset")
    return value.astimezone(timezone.utc)


def settings(worker):
    return {key: value for key, value in worker.items() if key not in {"generation", "observed_generation"}}


def study(root, commit, run_id, attempt):
    def report(name):
        return read_json(root / f"worker-benchmark-{name}.json")

    base = report("baseline")
    require(base["schema"] == "clipforge-int-worker-benchmark-1" and FULL_SHA.fullmatch(commit)
            and base["target_commit"] == commit and FULL_SHA.fullmatch(base["public"]["commit"])
            and base["public"]["commit"] != commit, "Comparison commit")
    rollback = report("restored")
    require(rollback["status"] == "passed" and settings(rollback["worker"]) == settings(base["worker"])
            and rollback["worker"]["generation"] == rollback["worker"]["observed_generation"]
            and rollback["worker"]["generation"] > base["worker"]["generation"], "Verified worker restoration")
    fixture = base["fixture"]
    require(re.fullmatch(r"[a-f0-9]{64}", fixture["sha256"]) and fixture["duration_seconds"] == 600
            and 8 * 1024 * 1024 <= fixture["bytes"] <= 300 * 1024 * 1024, "Matched fixture")
    public = base["public"]
    groups = {}
    all_jobs = set()
    all_owners = set()
    for cpu in (2, 4):
        prefix = f"cpu{cpu}"
        browser, setup, cleanup = [report(f"{prefix}-{phase}") for phase in ("benchmark", "setup", "cleanup")]
        before, after = [report(f"{prefix}-{phase}") for phase in ("before", "after")]
        require(before == after and before["image"] == base["target_worker"] and before["source"] == commit
                and before["cpu"] == str(cpu) and before["memory"] == base["worker"]["memory"] == "4Gi"
                and before["generation"] == before["observed_generation"]
                and before["configuration_sha256"] == base["worker"]["configuration_sha256"], "Cohort worker identity")
        owners = set(browser["synthetic_account_ids"])
        require(len(owners) == 3 and all(ID.fullmatch(owner) for owner in owners) and owners.isdisjoint(all_owners),
                "Different synthetic cohort owners")
        all_owners |= owners
        for receipt, phase in zip((browser, setup, cleanup), ("benchmark", "setup", "cleanup"), strict=True):
            require(receipt["schema"] == "clipforge-int-hito-b-capacity-1" and receipt["status"] == "passed"
                    and receipt["phase"] == phase and receipt["run_id"] == run_id and receipt["run_attempt"] == attempt
                    and receipt["commit"] == public["commit"] and receipt["editorial_model"] == ""
                    and receipt["revisions"] == {"frontend": public["frontend_revision"], "api": public["api_revision"]}
                    and receipt["benchmark"] == {"cpu": cpu, "sha256": fixture["sha256"]}
                    and set(receipt["synthetic_account_ids"]) == owners, "Protected browser receipt identity")
        require(browser["benchmark_fixture"] == fixture and set(browser["cases"]) == CASE_NAMES
                and browser["creators_logged_in"] == 3 and cleanup["synthetic_accounts_deactivated"] is True,
                "Browser comparison scope")
        for case in browser["cases"].values():
            job = case["synthetic_job_id"]
            require(ID.fullmatch(job) and job not in all_jobs and case["status"] == "passed"
                    and case["bytes"] == fixture["bytes"] and len(case["clips"]) == 5
                    and case["automatic_captions_verified"] is True
                    and case["portal_publication"]["first_and_all_observed_atomically"] is True, "Measured creator output")
            all_jobs.add(job)
        groups[cpu] = (browser, before)
    start, end = (instant(groups[2][0]["phase_started_utc"]), instant(groups[4][0]["phase_finished_utc"]))
    require(start <= instant(groups[2][0]["phase_finished_utc"]) <= instant(groups[4][0]["phase_started_utc"]) <= end
            and end - start <= timedelta(minutes=65), "Ordered comparison phases")
    return base, rollback, groups, all_jobs, start, end


def filter_for(jobs, start, end):
    subjects = " OR ".join(f"jsonPayload.job_id={json.dumps(job)}" for job in sorted(jobs))
    events = " OR ".join(f"jsonPayload.event={json.dumps(event)}" for event in sorted(SUBJECT_EVENTS))
    return ('resource.type="cloud_run_job" AND resource.labels.job_name="clipforge-int-worker" '
            f'AND timestamp>="{start.isoformat()}" AND timestamp<="{end.isoformat()}" AND ({subjects}) AND ({events})')


def native_logs(path, jobs):
    entries = read_json(path)
    require(isinstance(entries, list) and len(entries) == len(jobs) * len(SUBJECT_EVENTS), "Complete native event inventory")
    groups = {job: {} for job in jobs}
    for row in entries:
        payload = row["jsonPayload"]
        job, event = payload["job_id"], payload["event"]
        require(job in jobs and event in SUBJECT_EVENTS and event not in groups[job]
                and EXECUTION.fullmatch(payload["execution"]), "Cloud log source")
        groups[job][event] = (instant(row["timestamp"]), payload)
    return groups


def seconds(value):
    require(type(value) in {int, float} and 0 <= value <= 3600 and math.isfinite(value), "Invalid worker phase duration")
    return round(value, 3)


def measurements(case, worker, events, executions):
    claim_at, claim = events["worker_claim"]
    publish_at, published = events["worker_results_published"]
    finish_at, finished = events["worker_finish"]
    resource_at, resources = events["worker_resources"]
    names = ("task_id", "execution", "fence")
    require(all(tuple(payload[key] for key in names) == tuple(claim[key] for key in names)
                for payload in (published, finished, resources)) and published["kind"] == resources["kind"] == "process"
            and finished["status"] == resources["status"] == "succeeded", "Single fenced processing task")
    execution = executions[claim["execution"]]
    require(execution["image"] == worker["image"] and execution["source"] == worker["source"]
            and execution["cpu"] == worker["cpu"] and execution["memory"] == worker["memory"], "Actual execution resources")
    create_at, launch_at = instant(execution["created_at"]), instant(execution["start_at"])
    ready_at = datetime.fromtimestamp(claim["worker_started_epoch"], tz=timezone.utc)
    first_seen = case["state_observations"][0]
    activated_at = instant(first_seen["at_utc"]) - timedelta(seconds=first_seen["seconds_after_activation"])
    require(activated_at <= create_at <= launch_at <= ready_at <= claim_at <= publish_at <= finish_at <= resource_at,
            "Worker and browser event order")
    durations = resources["stage_seconds"]
    require(set(durations) in (STAGES, STAGES | {"prepare"}) and len(resources["clip_renders"]) == 5,
            "Complete media stage metrics")
    clips = [{key: seconds(item[key]) for key in ("render_seconds", "seconds_since_recorder_start")}
             for item in resources["clip_renders"]]
    public = case["portal_publication"]
    return {
        "execution": claim["execution"], "upload_seconds": seconds(case["upload_seconds"]),
        "activation_to_cloud_creation_seconds": seconds((create_at - activated_at).total_seconds()),
        "cloud_creation_to_start_seconds": seconds((launch_at - create_at).total_seconds()),
        "cloud_start_to_worker_entry_seconds": seconds((ready_at - launch_at).total_seconds()),
        "worker_entry_to_claim_seconds": seconds((claim_at - ready_at).total_seconds()),
        "claim_to_atomic_publication_seconds": seconds((publish_at - claim_at).total_seconds()),
        "portal_publication": public, "stage_seconds": {key: seconds(value) for key, value in durations.items()},
        "per_clip_render": clips, "provider_calls": 0,
        "process_rss_max_sampled_bytes": resources["child_rss_max_sampled_bytes"],
        "container_memory_peak_bytes": resources["cgroup_memory_peak_bytes_execution"],
        "container_memory_max_sampled_bytes": resources["cgroup_memory_max_sampled_bytes"],
        "scratch_max_sampled_bytes": resources["scratch_max_sampled_bytes"],
    }


def summarize(base, rollback, groups, native, executions):
    runs = {}
    all_artifacts = []
    for cpu, (browser, worker) in groups.items():
        cases = {}
        for name, case in browser["cases"].items():
            cases[name] = measurements(case, worker, native[case["synthetic_job_id"]], executions)
            all_artifacts.append({file: clip["sha256"] for file, clip in case["clips"].items()})
        executions_in_group = {case["execution"] for case in cases.values()}
        require(len(executions_in_group) == 3, "Three Cloud Run worker executions are required")
        runs[str(cpu)] = {
            "worker": worker, "cases": cases,
            "median_upload_to_first_and_all_seconds": median(
                case["portal_publication"]["upload_to_first_and_all_seconds"] for case in cases.values()),
            "median_claim_to_atomic_publication_seconds": median(
                case["claim_to_atomic_publication_seconds"] for case in cases.values()),
        }
    return {
        "schema": "clipforge-int-worker-benchmark-comparison-1", "public": base["public"],
        "fixture": base["fixture"], "comparison_commit": base["target_commit"],
        "same_output_mp4_bytes_for_all_cases": all(bundle == all_artifacts[0] for bundle in all_artifacts),
        "cohorts": runs, "restored_worker": rollback["worker"],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("scope", "executions", "summary"))
    parser.add_argument("--reports", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--attempt", required=True)
    parser.add_argument("--log", type=Path)
    parser.add_argument("--executions", type=Path)
    args = parser.parse_args()
    base, rollback, groups, jobs, start, end = study(args.reports, args.commit, args.run_id, args.attempt)
    if args.action == "scope":
        print(filter_for(jobs, start, end))
        return
    native = native_logs(args.log, jobs)
    names = sorted({rows["worker_claim"][1]["execution"] for rows in native.values()})
    require(len(names) == 6, "Separate Cloud Run executions for both cohorts are required")
    if args.action == "executions":
        print("\n".join(names))
        return
    executions = read_json(args.executions)
    require(set(executions) == set(names), "Execution metadata does not match native Cloud Logging")
    print(json.dumps(summarize(base, rollback, groups, native, executions), ensure_ascii=True, indent=2))


if __name__ == "__main__":
    main()
