"""Measure the INT creator workload in real browser sessions.

The caller generates four synthetic MP4s, including speech near each end.
Keep fixtures and downloads in protected scratch. The report records measured
durations and media receipts without accounts, job IDs, URLs, or media text.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
from time import monotonic
from typing import Any

from app.media import probe_media
from scripts import int_hito_a_acceptance as shared_http
from scripts import int_hito_b_browser as browser_test
from scripts.int_hito_a_browser import BROWSER_ENV_ALLOWLIST, BrowserAcceptanceError, require, resolve_browser


SCHEMA = "clipforge-int-hito-b-capacity-1"
MINUTES = (3, 5, 10, 20)
ACTIVE = frozenset({"transcribing", "rendering"})
OBSERVED_STATES = ACTIVE | {"queued", "validating", "completed", "failed"}
PUBLIC = browser_test.PUBLIC
START_PATH = re.compile(re.escape(PUBLIC) + r"/beta/uploads/([a-f0-9]{32})/start$")
UPLOAD_TIMEOUT = 720
POLL_MS = 1_000


@dataclass(frozen=True)
class Fixture:
    path: Path
    size: int
    duration: float


@dataclass
class Case:
    label: str
    fixture: Fixture
    page: Any
    transfer: list[int]
    upload_key: str = ""
    reservation_body: dict = field(default_factory=dict)
    job_id: str = ""
    activation: Any = None
    upload_start: float = 0
    held_at: float = 0
    activated_at: float = 0
    events: list[dict] = field(default_factory=list)
    last_job: dict = field(default_factory=dict)
    results: dict = field(default_factory=dict)
    completed_at: float = 0


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


def elapsed(start):
    return round(monotonic() - start, 3)


def facts(page, path):
    response = browser_test.browser_get(page, path)
    require(response["status"] == 200 and isinstance(response["body"], dict), "portal_read_failed")
    return response["body"]


def fixtures(directory, limits):
    require(directory.is_absolute() and directory.is_dir() and not directory.is_symlink(), "fixture_directory")
    result = {}
    for minutes in MINUTES:
        path = directory / f"{minutes}m.mp4"
        require(path.is_file() and not path.is_symlink(), f"fixture_{minutes}m_missing")
        size = path.stat().st_size
        meta = probe_media(path, pilot=True)
        duration = meta["duration_seconds"]
        require(meta["video_codec"] == "h264" and meta["audio_codec"] == "aac"
                and 0 < size <= limits["max_bytes"]
                and type(duration) in {int, float} and math.isfinite(duration)
                and abs(duration - minutes * 60) <= .25
                and duration <= limits["max_duration_seconds"]
                and max(meta["width"], meta["height"]) <= limits["max_dimension"],
                f"fixture_{minutes}m_outside_limits")
        result[minutes] = Fixture(path, size, duration)
    return result


def upload_hooks(case):
    def remember(request):
        if request.url == PUBLIC + "/beta/uploads" and request.method == "POST":
            case.upload_key = request.headers.get("idempotency-key", "")
            case.reservation_body = request.post_data_json

    def hold(route):
        match = START_PATH.fullmatch(route.request.url)
        if route.request.method != "POST" or not match:
            route.abort()
            return
        case.job_id = match.group(1)
        case.activation = route
        case.held_at = monotonic()

    return remember, hold


def wait_for_uploads(cases, report):
    """Release each authenticated POST only after every browser uploaded its video."""
    hooks = []
    try:
        for case in cases:
            case.transfer.clear()
            remember, hold = upload_hooks(case)
            case.page.on("request", remember)
            case.page.route(START_PATH, hold)
            hooks.append((case.page, remember, hold))
        for case in cases:
            report["case"] = case.label
            case.page.locator("#upload-video").set_input_files(str(case.fixture.path))
            case.upload_start = monotonic()
            case.page.locator("#upload-submit").click()
        deadline = monotonic() + UPLOAD_TIMEOUT
        while not all(case.activation for case in cases):
            require(monotonic() < deadline, "browser_upload_timeout")
            for case in cases:
                report["case"] = case.label
                if not case.activation:
                    require(case.page.locator("#upload-submit").is_disabled(), "browser_upload_stopped")
            cases[0].page.wait_for_timeout(250)
        del report["case"]
        require(len({case.job_id for case in cases}) == len(cases), "different_jobs_expected")
        release_times = []
        for case in cases:
            require(bool(case.upload_key)
                    and case.reservation_body.get("bytes") == case.fixture.size, "browser_reservation_contract")
            require(any(status in {200, 201} for status in case.transfer), "direct_storage_upload_missing")
            if case.fixture.size > browser_test.CHUNK_BYTES:
                require(308 in case.transfer, "resumable_multichunk_not_observed")
            case.activated_at = monotonic()
            release_times.append(case.activated_at)
            case.activation.fallback()
        for case in cases:
            case.page.wait_for_function("""id =>
                new URL(location.href).searchParams.get('job') === id &&
                document.querySelector('#upload-status').textContent.includes('Video guardado')
            """, arg=case.job_id, timeout=60_000)
        return round(max(release_times) - min(release_times), 3)
    finally:
        for page, remember, hold in hooks:
            page.remove_listener("request", remember)
            page.unroute(START_PATH, hold)


def sample(cases, report):
    """Collect status of each owned project through its authenticated browser."""
    states = {}
    began = utc()
    for case in cases:
        report["case"] = case.label
        job = case.last_job if case.completed_at else facts(case.page, "/jobs/" + case.job_id)
        state = job.get("status")
        require(job.get("id") == case.job_id and state in OBSERVED_STATES, "job_state_unrecognized")
        if not case.events or case.events[-1]["state"] != state:
            case.events.append({"state": state, "at_utc": utc(), "seconds_after_activation": elapsed(case.activated_at)})
        case.last_job = job
        states[case.label] = state
        if state == "completed" and not case.completed_at:
            case.completed_at = monotonic()
        if state == "failed":
            code = job.get("error_code", "")
            if isinstance(code, str) and re.fullmatch(r"[A-Z_]{1,35}", code):
                report["worker_error_code"] = code
            raise BrowserAcceptanceError("capacity_worker_failed")
    del report["case"]
    return {"began_utc": began, "ended_utc": utc(), "states": states}


def wait_for_completion(cases, report, timeout):
    deadline = min(case.activated_at for case in cases) + timeout
    while not all(case.completed_at for case in cases):
        require(monotonic() < deadline, "capacity_worker_timeout")
        sample(cases, report)
        if not all(case.completed_at for case in cases):
            cases[0].page.wait_for_timeout(POLL_MS)


def within_response_budget(seconds, limit):
    require(all(value <= limit for value in seconds.values()), "portal_response_budget_exceeded")


def load_probe(browser, account, args, current, saved, report):
    """Measure completed-clip access while all three new jobs remain active."""
    filename, artifact = next(iter(saved.results.items()))
    expected = artifact["sha256"]
    measured = {}
    report["response_seconds"] = measured
    with browser_test.browser_page(browser) as page:
        started = monotonic()
        browser_test.login(page, account, args.commit)
        measured["login"] = elapsed(started)
        started = monotonic()
        page.get_by_role("link", name=re.compile("^Mi cuenta")).click()
        page.wait_for_function("() => document.querySelector('#account-role')?.textContent === 'Usuario'")
        measured["account_navigation"] = elapsed(started)
        started = monotonic()
        job = facts(page, "/jobs/" + current.job_id)
        require(job.get("status") in ACTIVE, "owned_job_not_active_during_status_probe")
        measured["job_status"] = elapsed(started)
        started = monotonic()
        browser_test.open_saved_job(page, saved.job_id)
        measured["saved_job_navigation"] = elapsed(started)
        started = monotonic()
        label = "Clip " + str(int(filename[5:7]))
        with page.expect_download(timeout=args.response_budget * 1000) as event:
            page.get_by_role("link", name="Descargar " + label + " en MP4").click()
        with tempfile.TemporaryDirectory(prefix="beta-capacity-load-", dir=args.report.parent) as temporary:
            file = Path(temporary) / "resultado.mp4"
            event.value.save_as(file)
            measured["clip_download"] = elapsed(started)
            with file.open("rb") as stream:
                require(hashlib.file_digest(stream, "sha256").hexdigest() == expected,
                        "download_bytes_changed_under_load")
        event.value.delete()
    within_response_budget(measured, args.response_budget)


def observe_overlap(cases, browser, accounts, saved, args, report):
    deadline = min(case.activated_at for case in cases) + args.case_timeout
    while True:
        initial = sample(cases, report)
        states = initial["states"].values()
        if all(state in ACTIVE for state in states):
            break
        require("completed" not in states, "three_way_overlap_not_observed")
        require(monotonic() < deadline, "three_way_overlap_timeout")
        cases[0].page.wait_for_timeout(POLL_MS)
    report["overlap"] = {"begin": initial}
    started = monotonic()
    load_probe(browser, accounts[0], args, cases[0], saved, report["overlap"])
    final = sample(cases, report)
    report["overlap"]["end"] = final
    report["overlap"]["probed_seconds"] = elapsed(started)
    require(all(state in ACTIVE for state in final["states"].values()), "load_probe_outside_three_way_overlap")
    browser_test.check(report, "three_processing_jobs_and_responsive_login_navigation_status_download")


def project_ids(page):
    projects = facts(page, "/projects")
    require(not projects.get("has_more"), "unexpected_acceptance_project_pagination")
    return sorted(item["id"] for item in projects["projects"])


def finish_case(case, args, report):
    report["case"] = case.label
    started = report["cases"][case.label]
    job = browser_test.open_saved_job(case.page, case.job_id)
    analysis, speech = job.get("analysis_seconds"), job.get("speech_until_seconds")
    require(type(analysis) in {int, float} and type(speech) in {int, float}
            and math.isfinite(analysis) and math.isfinite(speech), "analysis_duration_missing")
    started.update(analysis_seconds=analysis, speech_until_seconds=speech)
    require(abs(analysis - case.fixture.duration) <= 1
            and case.fixture.duration - 45 <= speech <= case.fixture.duration + 1,
            "full_length_and_tail_speech_not_observed")
    require(job.get("selection_mode") == "heuristic_voice" and job.get("clips"), "worker_clips_missing")
    case.results = browser_test.results(case.page, job, args.report.parent)
    ids = project_ids(case.page)
    require(case.job_id in ids, "completed_project_not_listed")
    replay = browser_test.browser_post(case.page, "/beta/uploads", case.reservation_body, case.upload_key)
    repeated = browser_test.browser_post(case.page, f"/beta/uploads/{case.job_id}/start", {})
    require(replay == {"status": 201, "id": case.job_id, "upload": False}
            and repeated["status"] == 202 and repeated["id"] == case.job_id
            and project_ids(case.page) == ids
            and facts(case.page, "/jobs/" + case.job_id)["clips"] == job["clips"],
            "capacity_replay_duplicated")
    started.update(status="passed", clips=case.results, idempotent=True)
    del report["case"]


def check_isolation(cases, report):
    for case in cases:
        for foreign in cases:
            if case is foreign:
                continue
            clip = next(iter(foreign.results))
            base = "/jobs/" + foreign.job_id
            for suffix in ("", "/source", "/clips/" + clip, "/clips/" + clip + "?inline=true"):
                require(browser_test.browser_get(case.page, base + suffix)["status"] in {403, 404},
                        "other_creator_media_visible")
            require(browser_test.browser_post(case.page, f"/beta/uploads/{foreign.job_id}/start", {})["status"]
                    in {403, 404}, "other_creator_mutation_allowed")
    browser_test.check(report, "three_way_owner_isolation")


def run_batch(cases, args, report, overlap=None):
    report["step"] = "upload"
    skew = wait_for_uploads(cases, report)
    for case in cases:
        report["cases"][case.label] = {"status": "running", "input_seconds": case.fixture.duration,
                                       "bytes": case.fixture.size, "upload_http_statuses": case.transfer.copy(),
                                       "upload_seconds": round(case.held_at - case.upload_start, 3),
                                       "state_observations": case.events}
    report["step"] = "parallel" if overlap else "processing"
    if overlap:
        observe_overlap(cases, *overlap, args, report)
        report["overlap"]["activation_skew_seconds"] = skew
    wait_for_completion(cases, report, args.case_timeout)
    report["step"] = "verify_output"
    for case in cases:
        report["cases"][case.label]["processing_wall_seconds"] = round(case.completed_at - case.activated_at, 3)
        finish_case(case, args, report)


def deactivate(browser, args, admin, accounts, report):
    with browser_test.browser_page(browser) as page:
        browser_test.login(page, admin, args.commit)
        active = {user["username"] for user in facts(page, "/auth/users")["users"] if user["is_active"]}
        browser_test.deactivate_accounts(page, [account for account in accounts if account["username"] in active])
        browser_test.logout(page)
    report["synthetic_accounts_deactivated"] = True


def acceptance(browser, args, admin, report):
    accounts = [{"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
                for _ in range(3)]
    attempted = []
    try:
        report["step"] = "create_normal_accounts"
        with browser_test.browser_page(browser) as page:
            browser_test.login(page, admin, args.commit)
            page.goto(PUBLIC + "/account", wait_until="domcontentloaded")
            for account in accounts:
                attempted.append(account)
                browser_test.create_account(page, account)
            browser_test.logout(page)
        with ExitStack() as stack:
            transfers = [[] for _ in accounts]
            pages = [stack.enter_context(browser_test.browser_page(browser, storage=True, transfer=transfer))
                     for transfer in transfers]
            report["step"] = "creator_login_and_capacity_limits"
            for index, (page, account) in enumerate(zip(pages, accounts, strict=True)):
                browser_test.login(page, account, args.commit)
                require(browser_test.browser_get(page, "/auth/users")["status"] == 403, "creator_admin_access")
                require(project_ids(page) == [], "new_account_has_existing_projects")
                report["creators_logged_in"] = index + 1
            limits = facts(pages[0], "/beta/limits")
            require(limits["worker_concurrency"] == 3 and limits["max_duration_seconds"] >= 1_200
                    and limits["active_jobs_per_user"] == 1 and limits["queue_capacity"] >= 3
                    and limits["formats"] == ["MP4 (H.264 + AAC)"], "capacity_limits_unexpected")
            report["limits"] = {key: limits[key] for key in (
                "worker_concurrency", "active_jobs_per_user", "queue_capacity", "max_duration_seconds",
                "max_bytes", "max_dimension", "formats",
            )}
            ready = fixtures(args.fixture_dir, limits)
            for page in pages:
                page.wait_for_function("() => !document.querySelector('#upload-submit').disabled")
            warm = [Case(f"{minutes}m", ready[minutes], page, transfer)
                    for minutes, page, transfer in zip(MINUTES[:3], pages, transfers, strict=True)]
            run_batch(warm, args, report)
            run_batch([Case("20m", ready[20], pages[0], transfers[0])], args, report)
            parallel = [Case(f"20m_parallel_{index}", ready[20], page, transfer)
                        for index, (page, transfer) in enumerate(zip(pages, transfers, strict=True), 1)]
            run_batch(parallel, args, report, (browser, accounts, warm[0]))
            report["step"] = "creator_isolation"
            check_isolation(parallel, report)
            for page in pages:
                browser_test.logout(page)
    finally:
        if attempted:
            try:
                deactivate(browser, args, admin, attempted, report)
            except Exception:
                # Mark cleanup as pending without putting app responses in public evidence.
                report["synthetic_accounts_deactivated"] = False
    require(report.get("synthetic_accounts_deactivated") is True, "synthetic_account_cleanup_failed")


def arguments(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--frontend-revision", required=True)
    parser.add_argument("--api-revision", required=True)
    parser.add_argument("--fixture-dir", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--case-timeout", type=int, default=1_800, help="seconds for each worker batch")
    parser.add_argument("--response-budget", type=int, default=30, help="seconds per portal operation under load")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    report = {"schema": SCHEMA, "url": PUBLIC, "status": "failed", "cases": {}, "checks": [], "step": "preflight"}
    try:
        require(browser_test.COMMIT.fullmatch(args.commit), "commit_shape")
        require(300 <= args.case_timeout <= 7_200 and 5 <= args.response_budget <= 120, "time_budget_shape")
        shared_http.private_file(args.report, must_exist=False)
        report["commit"] = args.commit
        report["revisions"] = browser_test.cloud_revisions(args.frontend_revision, args.api_revision)
        admin = shared_http.validate_admin(json.loads(os.environ.pop("INT_BOOTSTRAP_ADMIN_JSON", "")))
        transport = shared_http.HTTP()
        require(transport.request("GET", browser_test.PRIVATE + "/health").status in {401, 403},
                "private_api_direct_request_allowed")
        require(shared_http.json_body(transport.request("GET", PUBLIC + "/health"), 200, "public_health")
                == {"status": "ok", "profile": "int-beta"}, "public_database_health")
        executable = resolve_browser({"INT_HITO_A_BROWSER_EXECUTABLE":
                                      os.environ.get("INT_HITO_B_BROWSER_EXECUTABLE", "")})
        from playwright.sync_api import sync_playwright
        child_env = {key: value for key, value in os.environ.items()
                     if key in BROWSER_ENV_ALLOWLIST or key.upper() in {"SYSTEMROOT", "USERPROFILE", "TEMP", "TMP"}}
        os.environ.clear()
        os.environ.update(child_env)
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(executable), env=child_env, headless=True)
            try:
                acceptance(browser, args, admin, report)
            finally:
                browser.close()
        report["status"] = "passed"
        report.pop("step")
    except (BrowserAcceptanceError, shared_http.AcceptanceError) as error:
        code = str(error)
        report["failure"] = code if re.fullmatch(r"[a-z0-9_]{1,100}", code) else "capacity_acceptance_failed"
    except Exception as error:
        report["failure"] = "capacity_acceptance_failed"
        report["failure_type"] = type(error).__name__
    try:
        shared_http.write_new(args.report, report)
    except (OSError, shared_http.AcceptanceError):
        print("Could not write the capacity report.")
        return 1
    print("ClipForge INT capacity acceptance " + report["status"] + ".")
    return 0 if report["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
