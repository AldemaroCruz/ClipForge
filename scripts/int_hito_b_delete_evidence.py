"""Verify the exact INT deletion and prior creator acceptance artifacts."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys

from scripts.int_hito_a_browser import BrowserAcceptanceError, require
from scripts.int_hito_b_browser import ID, PRIVATE, PUBLIC
from scripts.int_hito_b_capacity_browser import PARALLEL_CASES, SCHEMA as CAPACITY_SCHEMA, load_provider_evidence


SCHEMA = "clipforge-int-hito-b-delete-evidence-1"
BROWSER_SCHEMA = "clipforge-int-hito-b-browser-1"
MODEL = "gpt-6-luna"
DELETION_COMMIT = "18924d0cafddaaa30c986e52bb4cfc3776c06059"
ACCEPTED_COMMIT = "8f3875ff6e428a4a24bdec6d51646d9bbb18df41"
DELETION_HASHES = {
    "browser-prepare.json": "dbfc7c6565b3ea73c4221e496f2f81910ba9379441833adbaa391fcd9bc32181",
    "browser-verify.json": "a4701049d8427ac9b3eb3cd2153da224b5fe5d2f325f551c4ff952c15c3980c5",
    "browser-capacity.json": "25a0281b627cad4d2fc2b3a5119aa11a8b1feea6f64a1c617f61447f51f0cda9",
    "after-rollout.json": "5959af9a2ff0895da6d6f8655c33d5b33d4aae5ea2329c88759d6a76c2e4b500",
}
ACCEPTED_HASHES = {
    "browser-capacity.json": "6258286f90fed018eedca569abffa65dd2bf34e42642110ffa99ddb81ba62a90",
    "browser-verify.json": "c0953265ad6faa36b3bb696fbb7538dfaeccc94d17ee470c2b22ba27c1949b6d",
}
SHA256 = re.compile(r"[a-f0-9]{64}")
MAX_BYTES = 128 * 1024


def read_report(path, digest):
    require(path.is_file() and not path.is_symlink(), "evidence_file")
    with path.open("rb") as source:
        file_info = os.fstat(source.fileno())
        require(stat.S_ISREG(file_info.st_mode) and 0 < file_info.st_size <= MAX_BYTES, "evidence_size")
        raw = source.read(MAX_BYTES + 1)
    require(0 < len(raw) <= MAX_BYTES and hashlib.sha256(raw).hexdigest() == digest, "evidence_digest")
    return json.loads(raw)


def passed_checks(report, expected):
    checks = {check["name"] for check in report["checks"] if check["status"] == "passed"}
    require(checks.issuperset(expected), "evidence_checks")


def browser_identity(report, commit, phase):
    require(report["schema"] == BROWSER_SCHEMA and report["url"] == PUBLIC
            and report["commit"] == commit and report["phase"] == phase and report["status"] == "passed",
            "evidence_browser_identity")


def deletion_results(verify):
    passed_checks(verify, {
        "project_deletion_owner_and_csrf", "deletion_did_not_affect_existing_other_project",
        "deletion_visible_across_owner_sessions_and_reload", "deletion_completed_queued_active_and_idempotent",
    })
    outcomes = verify["project_deletion"]
    require(set(outcomes) == {"queued", "active", "completed"}
            and all(item["status"] == "deleted" and ID.fullmatch(item["id"]) for item in outcomes.values())
            and len({item["id"] for item in outcomes.values()}) == 3
            and outcomes["active"]["phase_at_deletion"] in {"transcribing", "rendering"},
            "evidence_deletion_cases")
    elapsed = outcomes["completed"]["click_to_removal_seconds"]
    require(type(elapsed) in {float, int} and 0 < elapsed <= 1, "evidence_deletion_latency")
    return {"queued": "passed", "active": "passed", "completed": "passed", "click_to_removal_seconds": elapsed}


def capacity_results(report, commit, revisions):
    require(report["schema"] == CAPACITY_SCHEMA and report["url"] == PUBLIC
            and report["commit"] == commit and report["revisions"] == revisions
            and report["creators_logged_in"] == report["limits"]["worker_concurrency"] == 3
            and report["synthetic_accounts_deactivated"] is True, "evidence_capacity_identity")
    expected = {"3m": 180, "5m": 300, "10m": 600, "20m": 1200, **dict.fromkeys(PARALLEL_CASES, 1200)}
    require(set(report["cases"]) == set(expected), "evidence_capacity_cases")
    for name, seconds in expected.items():
        item = report["cases"][name]
        require(item["status"] == "passed" and item["input_seconds"] == item["analysis_seconds"] == seconds
                and item["automatic_captions_verified"] is True, "evidence_capacity_case")
    passed_checks(report, {
        "three_processing_jobs_and_responsive_login_navigation_status_download",
        "three_twenty_minute_videos_automatic_mp4_srt_webvtt_and_late_sync",
        "three_way_owner_isolation",
    })
    return expected


def historical_exports(capacity, provider):
    require(capacity["status"] == "passed" and capacity["editorial"]["provider_evidence"] == provider,
            "evidence_historical_provider_link")
    passed_checks(capacity, {"three_twenty_minute_jobs_and_subtitled_exports"})
    for name in PARALLEL_CASES:
        export = capacity["editorial"][name]["export"]
        files = export["files"]
        require(set(files) == {"mp4", "srt", "vtt"} and all(SHA256.fullmatch(value) for value in files.values())
                and export["cues"] > 0 and export["burned_pixels"]["matching_pixels"] > 0
                and 60 < export["source_start"] < export["source_end"] <= 1200, "evidence_historical_export")


def artifact_link(run_id, artifact_id):
    return f"https://github.com/AldemaroCruz/ClipForge/actions/runs/{run_id}/artifacts/{artifact_id}"


def verify_evidence(deletion_dir, provider_report, accepted_capacity, model):
    require(model == MODEL, "evidence_model")
    evidence = {name: read_report(deletion_dir / name, digest) for name, digest in DELETION_HASHES.items()}
    prepare, verify = evidence["browser-prepare.json"], evidence["browser-verify.json"]
    capacity, rollout = evidence["browser-capacity.json"], evidence["after-rollout.json"]
    browser_identity(prepare, DELETION_COMMIT, "prepare")
    browser_identity(verify, DELETION_COMMIT, "verify")
    revisions = {"api": rollout["api_revision"], "frontend": rollout["frontend_revision"]}
    require(rollout["commit"] == DELETION_COMMIT and rollout["public_url"] == PUBLIC and rollout["api_url"] == PRIVATE
            and verify["revisions"] == revisions and verify["replaced"] == prepare["revisions"]
            and revisions != prepare["revisions"], "evidence_rollout_identity")
    images = {kind: rollout[kind + "_image"] for kind in ("web", "worker")}
    for kind, image in images.items():
        prefix = f"us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/beta-{kind}@sha256:"
        require(image.startswith(prefix) and SHA256.fullmatch(image.removeprefix(prefix)), "evidence_rollout_image")
    passed_checks(prepare, {"automatic_burned_mp4_srt_webvtt_without_editor", "editorial_late_range_color_size_and_edited_sidecars"})
    deletions = deletion_results(verify)
    cases = capacity_results(capacity, DELETION_COMMIT, revisions)
    require(capacity["status"] == "failed" and capacity["step"] == "three_editorial_requests_submitted"
            and capacity["failure"] == "editorial_selection_http_429"
            and set(capacity["editorial"]) == {"planned_provider_calls", "submission_skew_seconds"}
            and capacity["editorial"]["planned_provider_calls"] == dict.fromkeys(PARALLEL_CASES, 1),
            "evidence_capacity_stop")

    provider = load_provider_evidence(provider_report, model)
    accepted = read_report(accepted_capacity, ACCEPTED_HASHES["browser-capacity.json"])
    accepted_verify = read_report(accepted_capacity.with_name("browser-verify.json"), ACCEPTED_HASHES["browser-verify.json"])
    browser_identity(accepted_verify, ACCEPTED_COMMIT, "verify")
    capacity_results(accepted, ACCEPTED_COMMIT, accepted_verify["revisions"])
    historical_exports(accepted, provider)
    return {
        "schema": SCHEMA, "status": "passed", "commit": DELETION_COMMIT, "url": PUBLIC,
        "revisions": revisions, "images": images, "deletion": deletions,
        "capacity": {"media_cases_seconds": cases, "parallel_creators": 3,
                     "historical_stop": capacity["failure"], "historical_stop_step": capacity["step"]},
        "provider": {"model": model, "real_calls": 3, "parallel_overlap_seconds": provider["provider_overlap"]["three_way_seconds"],
                     "historical_exports": 3},
        "artifacts": {
            "deletion": {"url": artifact_link(45826832751, 15124621636), "commit": DELETION_COMMIT, "sha256": DELETION_HASHES},
            "provider": {"url": artifact_link(45732776974, 15080003495), "commit": provider["source_commit"], "sha256": provider["sha256"]},
            "accepted_capacity": {"url": artifact_link(45739556524, 15082324504), "commit": ACCEPTED_COMMIT,
                                  "sha256": ACCEPTED_HASHES},
        },
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--deletion-dir", type=Path, required=True)
    parser.add_argument("--provider-report", type=Path, required=True)
    parser.add_argument("--accepted-capacity", type=Path, required=True)
    parser.add_argument("--model", required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        receipt = verify_evidence(args.deletion_dir, args.provider_report, args.accepted_capacity, args.model)
        with args.receipt.open("x", encoding="utf-8") as output:
            json.dump(receipt, output, indent=2)
            output.write("\n")
    except BrowserAcceptanceError as exc:
        print(f"INT evidence rejected ({exc})", file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError):
        print("INT evidence could not be validated or the receipt could not be written", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
