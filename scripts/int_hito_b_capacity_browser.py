"""Measure the INT creator workload in real browser sessions.

The caller generates four synthetic MP4s, including speech near each end.
Keep fixtures and downloads in protected scratch. The report records measured
durations and media receipts without accounts, job IDs, URLs, or media text.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack, contextmanager
from dataclasses import dataclass, field
from datetime import datetime, timezone
import hashlib
from itertools import product
import json
import math
import os
from pathlib import Path
import re
import secrets
import stat
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
REUSED_PROVIDER_COMMIT = "9f644e4c73318d9115d88168905cf07c72711c3c"
REUSED_PROVIDER_SHA256 = "663d16e3667df49394a3cf78379f74346b80eceea1db597f61bd0c4edfc2f04e"
REUSED_PROVIDER_MAX_BYTES = 128 * 1024
PARALLEL_CASES = tuple(f"20m_parallel_{index}" for index in range(1, 4))


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
                    and case.reservation_body.get("burn_subtitles") is True
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
    began_inspection = monotonic()
    case.results = browser_test.results(case.page, job, args.report.parent)
    started.update(automatic_captions_verified=True, subtitle_inspection_seconds=elapsed(began_inspection))
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
            for suffix in ("", "/source", "/clips/" + clip, "/clips/" + clip + "?inline=true",
                           "/clips/" + clip + "/subtitles/srt", "/clips/" + clip + "/subtitles/vtt"):
                require(browser_test.browser_get(case.page, base + suffix)["status"] in {403, 404},
                        "other_creator_media_visible")
            require(browser_test.browser_post(case.page, f"/beta/uploads/{foreign.job_id}/start", {})["status"]
                    in {403, 404}, "other_creator_mutation_allowed")
    browser_test.check(report, "three_way_owner_isolation")


@contextmanager
def hold_selection(page, path):
    url = PUBLIC + path
    requests, responses = [], []

    def hold(route):
        if route.request.method == "POST":
            requests.append(route)
        else:
            route.fallback()

    def capture(response):
        if response.url == url and response.request.method == "POST":
            responses.append(response)

    page.route(url, hold)
    page.on("response", capture)
    try:
        yield requests, responses
    finally:
        page.remove_listener("response", capture)
        page.unroute(url, hold)
        for route in requests:
            route.abort()


def start_parallel_selections(cases, model, report):
    """Finish all previews and consent before dispatching any selection."""
    report["step"] = "three_editorial_previews"
    previews = []
    for case in cases:
        report["case"] = case.label
        previews.append(browser_test.prepare_selection(case.page, case.job_id, model))
    report["editorial"]["planned_provider_calls"] = {
        case.label: calls for case, (_, calls) in zip(cases, previews, strict=True)
    }
    with ExitStack() as stack:
        pending = [stack.enter_context(hold_selection(case.page, path))
                   for case, (path, _) in zip(cases, previews, strict=True)]
        report["step"] = "three_editorial_requests_submitted"
        for case in cases:
            report["case"] = case.label
            case.page.locator("#editorial-run").click()
        del report["case"]
        deadline = monotonic() + 30
        while not all(requests for requests, _ in pending):
            require(monotonic() < deadline, "editorial_submission_barrier_timeout")
            cases[0].page.wait_for_timeout(100)
        require(all(len(requests) == 1 for requests, _ in pending), "editorial_submission_count")
        released = []
        for requests, _ in pending:
            released.append(monotonic())
            requests.pop().fallback()
        report["editorial"]["submission_skew_seconds"] = round(max(released) - min(released), 3)
        deadline = monotonic() + 60
        while not all(responses for _, responses in pending):
            require(monotonic() < deadline, "editorial_submission_response_timeout")
            cases[0].page.wait_for_timeout(100)
        require(all(len(responses) == 1 for _, responses in pending), "editorial_submission_response_count")
        return [browser_test.selection_receipt(responses[0], case.job_id, calls, began)
                for case, (_, calls), (_, responses), began in zip(cases, previews, pending, released, strict=True)]


def provider_overlap(selections):
    """Measure the largest intersection of one successful call per account."""
    intervals = (selection["provider_call_intervals"] for selection in selections)
    maximum = max(
        min(call["finished_at"] for call in group) - max(call["started_at"] for call in group)
        for group in product(*intervals)
    )
    seconds = round(max(0, maximum), 3)
    return {"status": "observed" if seconds else "not_observed", "three_way_seconds": seconds}


def load_provider_evidence(path, model):
    """Admit the exact report that recorded the three calls before an unrelated 429."""
    require(browser_test.MODEL.fullmatch(model), "reused_provider_requires_model")
    require(path.is_absolute() and not path.is_symlink(), "reused_provider_report_path")
    with path.open("rb") as source:
        info = os.fstat(source.fileno())
        require(stat.S_ISREG(info.st_mode) and 0 < info.st_size <= REUSED_PROVIDER_MAX_BYTES,
                "reused_provider_report_size")
        if os.name == "posix":
            require(info.st_uid == os.getuid() and info.st_mode & 0o077 == 0, "reused_provider_report_permissions")
        raw = source.read(REUSED_PROVIDER_MAX_BYTES + 1)
    require(0 < len(raw) <= REUSED_PROVIDER_MAX_BYTES, "reused_provider_report_size")
    digest = hashlib.sha256(raw).hexdigest()
    require(digest == REUSED_PROVIDER_SHA256, "reused_provider_report_digest")
    report = json.loads(raw)
    require(report["schema"] == SCHEMA and report["url"] == PUBLIC
            and report["commit"] == REUSED_PROVIDER_COMMIT and report["creators_logged_in"] == 3
            and report["status"] == "failed" and report["step"] == "three_editorial_save_subtitle_style"
            and report["failure"] == "editorial_request_http_429_nonjson", "reused_provider_report_scope")
    editorial = report["editorial"]
    require(set(editorial["planned_provider_calls"]) == set(PARALLEL_CASES),
            "reused_provider_cases")
    receipts = {}
    for case in PARALLEL_CASES:
        workload = report["cases"][case]
        item = editorial[case]["selection"]
        windows = item["analysis_windows"]
        require(workload["status"] == "passed" and workload["input_seconds"] == 1200
                and workload["analysis_seconds"] == 1200
                and workload["automatic_captions_verified"] is True and item["provider"] == "openai"
                and item["model"] == model and item["models_received"] == [model]
                and item["provider_calls"] == item["provider_responses"] == editorial["planned_provider_calls"][case] == 1
                and len(windows) == 1 and windows[0]["start"] == 0 and windows[0]["end"] == 1200
                and 1 <= item["proposals"] <= 5 and item["last_transcript_end"] >= 1155,
                "reused_provider_case_receipt")
        receipts[case] = {
            "provider": item["provider"], "model": item["model"], "proposals": item["proposals"],
            "provider_calls": item["provider_calls"], "provider_responses": item["provider_responses"],
            "provider_call_intervals": browser_test.provider_call_intervals(item),
        }
    overlap = provider_overlap(receipts.values())
    require(overlap["status"] == "observed" and overlap == editorial["provider_overlap"],
            "reused_provider_overlap")
    return {"mode": "reused", "source_commit": REUSED_PROVIDER_COMMIT, "sha256": digest,
            "provider_overlap": overlap, "cases": receipts}


EMPTY_SELECTION_BRIEF = (
    "Elige un solo range_id del catálogo con una frase clara sobre el huerto, el maíz, "
    "el riego o el trabajo de los vecinos. Basta que el fragmento mencione una de esas acciones "
    "de la historia del huerto comunitario. Explica en qué momento se escucha."
)


def editorial_capacity(cases, args, report, reused_provider=None):
    editorial = {}
    report["editorial"] = editorial
    fresh_provider = bool(args.editorial_model) and reused_provider is None
    if reused_provider is not None:
        report["step"] = "three_live_editorial_provider_configs"
        for case in cases:
            config = facts(case.page, "/ai/config")
            require(config.get("provider") == "openai" and config.get("configured") is True
                    and config.get("model") == args.editorial_model, "reused_provider_live_configuration")
        editorial.update(provider_evidence=reused_provider, live_provider_config_verified=len(cases),
                         live_inference_phase="protected_browser_prepare")
    if fresh_provider:
        pending = start_parallel_selections(cases, args.editorial_model, report)
        report["step"] = "three_real_editorial_selections"
        selections = []
        for case, receipt in zip(cases, pending, strict=True):
            report["case"] = case.label
            selection = browser_test.finish_selection(
                case.page, case.job_id, receipt, args.editorial_model, 1200, allow_empty=True,
            )
            selections.append(selection)
            editorial[case.label] = {"selection": {key: value for key, value in selection.items() if key != "id"}}
        editorial["provider_overlap"] = provider_overlap(selections)
        for index, (case, initial) in enumerate(zip(cases, selections, strict=True)):
            if initial["proposals"]:
                continue
            report["case"] = case.label
            report["step"] = "retry_empty_editorial_selection_with_consent"
            receipt = browser_test.start_selection(case.page, case.job_id, args.editorial_model,
                                                   brief=EMPTY_SELECTION_BRIEF)
            require(receipt[0] != initial["id"], "editorial_retry_reused_empty_selection")
            retry = browser_test.finish_selection(case.page, case.job_id, receipt, args.editorial_model, 1200)
            row = editorial[case.label]
            row["concurrent_selection"] = row["selection"]
            row["selection"] = {key: value for key, value in retry.items() if key != "id"}
            selections[index] = retry
        del report["case"]
    else:
        selections = [None] * len(cases)
    drafts = []
    for case, selection in zip(cases, selections, strict=True):
        report["case"] = case.label
        report["step"] = "three_editorial_open_late_draft"
        browser_test.open_late_draft(case.page, case.job_id, 1166, 1195, generated=selection is not None,
                                     analysis_id=selection["id"] if selection is not None else None)
        report["step"] = "three_editorial_save_subtitle_style"
        drafts.append(browser_test.save_style(case.page, case.job_id, 52, "#FF0000",
                                             "Edición y acción.\nCorazón y mañana."))
    queued = []
    for case, draft in zip(cases, drafts, strict=True):
        report["case"] = case.label
        report["step"] = "three_editorial_approve_export"
        queued.append((draft, browser_test.start_editorial_export(case.page, case.job_id, draft)))
    del report["case"]
    report["step"] = "three_editorial_exports_processing"
    ready = {}
    while len(ready) < len(cases):
        for case, (_, (export_id, activated, _)) in zip(cases, queued, strict=True):
            if case.label in ready:
                continue
            variants = facts(case.page, f"/jobs/{case.job_id}/exports")["exports"]
            variant = next((item for item in variants if item["id"] == export_id), None)
            require(variant is not None and variant["status"] in {"queued", "rendering", "completed"},
                    "parallel_editorial_export_failed")
            if variant["status"] == "completed":
                ready[case.label] = elapsed(activated)
            else:
                require(monotonic() - activated < 480, "parallel_editorial_export_timeout")
        if len(ready) < len(cases):
            cases[0].page.wait_for_timeout(POLL_MS)
    report["step"] = "three_editorial_exports_downloaded"
    for case, selection, (draft, receipt) in zip(cases, selections, queued, strict=True):
        output = browser_test.fetch_editorial_export(case.page, case.job_id, draft, receipt, args.report.parent,
                                                     ready_seconds=ready[case.label])
        editorial.setdefault(case.label, {})["export"] = output
        denied = [f"/drafts/{draft['id']}", f"/exports/{receipt[0]}/files/clip.mp4"]
        if selection:
            denied.append(f"/selections/{selection['id']}")
        for other in cases:
            if case is not other:
                path = f"/jobs/{case.job_id}"
                for suffix in denied:
                    require(browser_test.browser_get(other.page, path + suffix)["status"] in {403, 404},
                            "other_creator_editorial_result_visible")
    if reused_provider is not None:
        editorial["status"] = "passed_with_reused_provider_evidence"
    else:
        editorial["status"] = "passed" if fresh_provider else "subtitles_passed_provider_not_configured"
    editorial["real_provider_called"] = bool(fresh_provider)
    browser_test.check(report, "three_twenty_minute_jobs_and_subtitled_exports")


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
        row = report["cases"][case.label]
        row["processing_wall_seconds"] = round(case.completed_at - case.activated_at, 3)
        row["upload_to_automatic_captioned_clips_seconds"] = round(case.completed_at - case.upload_start, 3)
        finish_case(case, args, report)
    if overlap:
        late = max((clip["captions"] for case in cases for clip in case.results.values()),
                   key=lambda item: item["source_start"])
        require(late["source_start"] >= 180 and
                0 <= late["first_caption_local"] < late["last_caption_local"] <= late["source_end"] - late["source_start"] + .001,
                "late_automatic_clip_subtitles_not_observed")
        report["late_automatic_caption"] = late
        browser_test.check(report, "three_twenty_minute_videos_automatic_mp4_srt_webvtt_and_late_sync")


def deactivate(browser, args, admin, accounts, report):
    with browser_test.browser_page(browser) as page:
        browser_test.login(page, admin, args.commit)
        active = {user["username"] for user in facts(page, "/auth/users")["users"] if user["is_active"]}
        browser_test.deactivate_accounts(page, [account for account in accounts if account["username"] in active])
        browser_test.logout(page)
    report["synthetic_accounts_deactivated"] = True


def acceptance(browser, args, admin, report, reused_provider=None):
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
            parallel = [Case(name, ready[20], page, transfer)
                        for name, page, transfer in zip(PARALLEL_CASES, pages, transfers, strict=True)]
            run_batch(parallel, args, report, (browser, accounts, warm[0]))
            report["step"] = "creator_isolation"
            check_isolation(parallel, report)
            editorial_capacity(parallel, args, report, reused_provider)
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
    parser.add_argument("--editorial-model", default="")
    parser.add_argument("--reuse-provider-report", type=Path,
                        help="reuse the exact reviewed INT three-account provider report")
    parser.add_argument("--case-timeout", type=int, default=1_800, help="seconds for each worker batch")
    parser.add_argument("--response-budget", type=int, default=30, help="seconds per portal operation under load")
    return parser.parse_args(argv)


def main(argv=None):
    args = arguments(argv)
    report = {"schema": SCHEMA, "url": PUBLIC, "status": "failed", "cases": {}, "checks": [], "step": "preflight"}
    try:
        require(browser_test.COMMIT.fullmatch(args.commit), "commit_shape")
        require(not args.editorial_model or browser_test.MODEL.fullmatch(args.editorial_model), "editorial_model_shape")
        require(300 <= args.case_timeout <= 7_200 and 5 <= args.response_budget <= 120, "time_budget_shape")
        shared_http.private_file(args.report, must_exist=False)
        reused_provider = (load_provider_evidence(args.reuse_provider_report, args.editorial_model)
                           if args.reuse_provider_report else None)
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
                acceptance(browser, args, admin, report, reused_provider)
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
