"""Browser acceptance for the public ClipForge INT beta.

Run prepare before replacing the Cloud Run revisions and verify afterwards.
Keep the state file, fixture and temporary downloads in private scratch.
The JSON reports contain check results and measured timings without credentials.
"""
from __future__ import annotations

import argparse
from contextlib import contextmanager
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import tempfile
from time import monotonic
from urllib.parse import urlsplit

from app.cloud.config import BETA_MAX_BYTES, BETA_MAX_DIMENSION, BETA_MAX_SECONDS, BETA_WORKER_CONCURRENCY
from app.media import probe_media
from scripts import int_hito_a_acceptance as shared_http
from scripts.int_hito_a_browser import (
    BROWSER_ENV_ALLOWLIST, BrowserAcceptanceError, require, resolve_browser,
)


PUBLIC = "https://clipforge-int-beta-816643438938.us-central1.run.app"
PRIVATE = "https://clipforge-int-beta-api-816643438938.us-central1.run.app"
STORAGE = "https://storage.googleapis.com"
COMMIT = re.compile(r"[0-9a-f]{40}")
ID = re.compile(r"[0-9a-f]{32}")
CLIP = re.compile(r"clip_[0-9]{2}[.]mp4")
SHA256 = re.compile(r"[0-9a-f]{64}")
ACCOUNT = re.compile(r"qa_beta_[0-9a-f]{20}")
CHUNK_BYTES = 8 * 1024 * 1024
MAX_CLIP_BYTES = 200 * 1024 * 1024
TIMEOUT = 30_000
SCHEMA = "clipforge-int-hito-b-browser-1"


def cloud_revisions(frontend, api):
    require(shared_http.REVISION.fullmatch(frontend) and shared_http.REVISION.fullmatch(api)
            and re.fullmatch(r"clipforge-int-beta-[a-z0-9-]+", frontend)
            and not frontend.startswith("clipforge-int-beta-api-")
            and re.fullmatch(r"clipforge-int-beta-api-[a-z0-9-]+", api), "cloud_revision_shape")
    return {"frontend": frontend, "api": api}


def origin(url):
    parsed = urlsplit(url)
    if parsed.scheme == "https" and not parsed.username and not parsed.password and parsed.port is None:
        return "https://" + (parsed.hostname or "")
    return None


def check(report, name):
    report["checks"].append({"name": name, "status": "passed"})


@contextmanager
def browser_page(browser, *, storage=False, transfer=None):
    context = browser.new_context(accept_downloads=True, service_workers="block")
    context.set_default_timeout(TIMEOUT)
    outside = []

    def keep_routes(route):
        target = origin(route.request.url)
        if target == PUBLIC or (storage and target == STORAGE and route.request.method in {"PUT", "OPTIONS"}):
            route.continue_()
        else:
            outside.append(True)
            route.abort()

    context.route("**/*", keep_routes)
    page = context.new_page()
    errors = []
    page.on("pageerror", lambda _error: errors.append(True))
    if transfer is not None:
        def upload_response(response):
            if origin(response.url) == STORAGE and response.request.method == "PUT":
                transfer.append(response.status)
        page.on("response", upload_response)
    try:
        yield page
        require(not outside, "unexpected_browser_origin")
        require(not errors, "browser_script_error")
    finally:
        context.close()


def login(page, account, commit):
    page.goto(PUBLIC + "/login", wait_until="domcontentloaded")
    require(page.locator("#login-form").is_visible(), "public_login_form")
    page.locator("#username").fill(account["username"])
    page.locator("#password").fill(account["password"])
    page.locator("#login-form button[type=submit]").click()
    page.wait_for_url(PUBLIC + "/", wait_until="domcontentloaded")
    page.wait_for_function("""([user, commit]) =>
        document.querySelector('[data-auth-user]')?.textContent === user &&
        document.querySelector('#environment-badge')?.title === commit &&
        document.querySelector('#beta-workspace')?.hidden === false
    """, arg=[account["username"], commit])
    signed = next((item for item in page.context.cookies(PUBLIC)
                   if re.fullmatch(r"clipforge_(?:[a-z0-9_]+_)?session", item["name"])), None)
    require(signed is not None and signed["secure"] and signed["httpOnly"] and
            signed["sameSite"] == "Strict" and signed["path"] == "/", "session_cookie_attributes")


def logout(page):
    page.locator("[data-auth-logout]").click()
    page.wait_for_url(PUBLIC + "/login", wait_until="domcontentloaded")
    require(browser_get(page, "/auth/me")["status"] == 401, "logout_session_still_valid")


def browser_get(page, path):
    return page.evaluate("""async (path) => {
        const response = await fetch(path, {credentials: 'same-origin', redirect: 'error'});
        const type = response.headers.get('Content-Type') || '';
        return {status: response.status, body: type.includes('application/json') ? await response.json() : null};
    }""", path)


def browser_post(page, path, body, key=None, *, csrf=True):
    return page.evaluate("""async ({path, body, key, csrf}) => {
        const auth = window.ClipForgeAuth;
        const options = auth.payload(body);
        if (key) options.headers['Idempotency-Key'] = key;
        const response = csrf ? await auth.fetch(path, options) : await fetch(path, options);
        const data = await response.json();
        return {status: response.status, id: data.id || null, upload: Boolean(data.upload_url)};
    }""", {"path": path, "body": body, "key": key, "csrf": csrf})


def create_account(page, account):
    # The form's previous submission clears its password in finally before
    # enabling the button. Do not fill the next account while it is busy.
    ready = "() => !document.querySelector('#create-user-form button[type=submit]').disabled"
    page.wait_for_function(ready)
    page.locator("#new-username").fill(account["username"])
    page.locator("#user-password").fill(account["password"])
    with page.expect_response(lambda item: item.url == PUBLIC + "/auth/users"
                              and item.request.method == "POST") as result:
        page.locator("#create-user-form button[type=submit]").click()
    response = result.value
    require(response.status == 201, "creator_account_creation_http_" + str(response.status))
    created = response.json()["user"]
    require(created["username"] == account["username"] and created["is_admin"] is False
            and created["is_active"] is True,
            "creator_account_creation_identity")
    page.wait_for_function(ready)


def deactivate_accounts(page, accounts):
    page.goto(PUBLIC + "/account", wait_until="domcontentloaded")
    page.on("dialog", lambda dialog: dialog.accept())
    for account in accounts:
        button = page.get_by_role("button", name="Desactivar a " + account["username"], exact=True)
        button.click()
        page.get_by_text(account["username"] + " · Desactivada", exact=True).wait_for()


def check_normal_permissions(page, report):
    require(browser_get(page, "/auth/users")["status"] == 403, "normal_has_administration_access")
    unsigned = browser_post(page, "/beta/uploads", {"filename": "csrf.mp4", "bytes": 1024}, csrf=False)
    require(unsigned["status"] == 403, "csrf_missing_accepted")
    page.get_by_role("link", name=re.compile("^Mi cuenta")).click()
    page.wait_for_function("() => document.querySelector('#account-role')?.textContent === 'Usuario'")
    require(page.locator("#users-panel").is_hidden(), "normal_user_management_visible")
    page.goto(PUBLIC + "/", wait_until="domcontentloaded")
    page.locator("#upload-video").wait_for()
    check(report, "normal_user_role_and_csrf")


def check_feedback_removed(page, report):
    require(page.locator("#feedback-form, #admin-feedback, #feedback-history").count() == 0,
            "feedback_controls_still_present")
    for path in ("/beta/feedback", "/beta/admin/feedback"):
        require(browser_get(page, path)["status"] == 404, "feedback_read_route_still_present")
    require(browser_post(page, "/beta/feedback", {})["status"] == 404, "feedback_write_route_still_present")
    check(report, "feedback_controls_and_routes_removed")


def upload_video(page, path, report, transfer):
    report["step"] = "limits"
    page.locator("#upload-video").wait_for(state="visible")
    page.wait_for_function("() => !document.querySelector('#upload-submit').disabled")
    response = browser_get(page, "/beta/limits")
    limits = response["body"]
    require(response["status"] == 200 and isinstance(limits, dict), "pilot_limits_unavailable")
    require(limits["selection_mode"] == "heuristic_voice" and limits["worker_concurrency"] == BETA_WORKER_CONCURRENCY
            and limits["active_jobs_per_user"] == 1 and
            limits["formats"] == ["MP4 (H.264 + AAC)"] and limits["max_bytes"] == BETA_MAX_BYTES
            and limits["min_duration_seconds"] == 20 and limits["max_duration_seconds"] == BETA_MAX_SECONDS
            and limits["max_dimension"] == BETA_MAX_DIMENSION, "pilot_limits_unexpected")
    report["limits"] = {key: limits[key] for key in (
        "selection_mode", "worker_concurrency", "active_jobs_per_user", "formats", "max_bytes",
        "min_duration_seconds", "max_duration_seconds", "max_dimension",
    )}
    require(f"{BETA_MAX_BYTES // (1024 * 1024)} MiB" in page.locator("#upload-limits").inner_text(),
            "pilot_limits_hidden")
    page.locator("#upload-video").evaluate("""(input, bytes) => {
      const data = new DataTransfer();
      const unit = new Blob([new Uint8Array(1024 * 1024)]);
      data.items.add(new File([...Array(Math.floor(bytes / unit.size)).fill(unit), unit.slice(0, bytes % unit.size)],
        'over-limit.mp4', {type: 'video/mp4'}));
      input.files = data.files;
      input.dispatchEvent(new Event('change', {bubbles: true}));
    }""", limits["max_bytes"] + 1)
    require("supera el máximo" in page.locator("#upload-status").inner_text(), "oversize_browser_message")
    bad = browser_post(page, "/beta/uploads", {"filename": "over-limit.mp4", "bytes": limits["max_bytes"] + 1},
                       secrets.token_hex(24))
    require(bad["status"] == 413 and not bad["upload"], "oversize_reservation_accepted")
    check(report, "limits_visible_and_oversize_rejected")

    report["step"] = "fixture"
    meta = probe_media(path, pilot=True)
    size = path.stat().st_size
    require(meta["video_codec"] == "h264" and meta["audio_codec"] == "aac"
            and size <= limits["max_bytes"]
            and limits["min_duration_seconds"] <= meta["duration_seconds"] <= limits["max_duration_seconds"]
            and max(meta["width"], meta["height"]) <= limits["max_dimension"], "fixture_outside_pilot_limits")
    report["fixture"] = {"bytes": size, "duration_seconds": meta["duration_seconds"],
                         "video_codec": meta["video_codec"], "audio_codec": meta["audio_codec"]}
    report["step"] = "browser_upload"
    page.locator("#upload-video").set_input_files(str(path))
    start = monotonic()
    with page.expect_request(lambda request: request.url == PUBLIC + "/beta/uploads" and request.method == "POST") as sent:
        page.locator("#upload-submit").click()
    request = sent.value
    request_key = request.headers.get("idempotency-key")
    require(request_key, "upload_idempotency_key_missing")
    page.wait_for_function("""() => /Video guardado/.test(document.querySelector('#upload-status').textContent)
        || !document.querySelector('#upload-submit').disabled""", timeout=360_000)
    report["upload_http_statuses"] = transfer.copy()
    require("Video guardado" in page.locator("#upload-status").inner_text(), "upload_or_start_reported_failure")
    report["upload_seconds"] = round(monotonic() - start, 2)
    require(any(status in {200, 201} for status in transfer), "direct_storage_upload_missing")
    if size > CHUNK_BYTES:
        require(308 in transfer, "resumable_multichunk_not_observed")
    check(report, "browser_direct_upload")
    report["step"] = "worker"
    page.wait_for_function("() => new URL(location.href).searchParams.has('job')")
    job_id = page.evaluate("() => new URL(location.href).searchParams.get('job')")
    require(ID.fullmatch(job_id), "job_selection_shape")
    page.wait_for_function("""() =>
      /^Completado/.test(document.querySelector('#job-status').textContent) ||
      document.querySelector('#job-status').textContent === 'Fallido'
    """, timeout=1_200_000)
    job = browser_get(page, "/jobs/" + job_id)["body"]
    if job["status"] == "failed":
        error_code = job.get("error_code", "")
        if isinstance(error_code, str) and re.fullmatch(r"[A-Z_]{1,32}", error_code):
            raise BrowserAcceptanceError("worker_failed_" + error_code)
    require(job["status"] == "completed" and job["selection_mode"] == "heuristic_voice" and job["clips"],
            "worker_did_not_generate_clips")
    report["video_to_clips_seconds"] = round(monotonic() - start, 2)
    check(report, "worker_completed_heuristic_selection")

    report["step"] = "idempotency"
    reservation = browser_post(page, "/beta/uploads", request.post_data_json, request_key)
    repeated = browser_post(page, "/beta/uploads/" + job_id + "/start", {})
    require(reservation == {"status": 201, "id": job_id, "upload": False}
            and repeated["status"] == 202 and repeated["id"] == job_id, "repeated_submission_changed_job")
    projects = browser_get(page, "/projects")["body"]
    after = browser_get(page, "/jobs/" + job_id)["body"]
    require([item["id"] for item in projects["projects"]] == [job_id] and after["clips"] == job["clips"],
            "repeated_submission_changed_results")
    check(report, "idempotent_upload_and_start")
    require(page.evaluate("""() => !Object.values(localStorage).concat(Object.values(sessionStorage))
        .some(value => value.includes('storage.googleapis.com'))"""), "upload_authorization_persisted")
    return job


def results(page, job, scratch):
    files = [clip["file"] for clip in job["clips"]]
    require(1 <= len(files) <= 10 and len(set(files)) == len(files) and all(CLIP.fullmatch(file) for file in files),
            "clip_manifest_shape")
    result = {}
    with tempfile.TemporaryDirectory(prefix="beta-clips-", dir=scratch) as temporary:
        for file in files:
            label = "Clip " + str(int(file[5:7]))
            player = page.locator("video[aria-label='" + label + "']")
            player.wait_for(state="visible")
            player.click(position={"x": 8, "y": 8})
            player.evaluate("el => { el.muted = false; return el.play(); }")
            page.wait_for_function("""label => {
              const video = [...document.querySelectorAll('video')].find(el => el.getAttribute('aria-label') === label);
              return video?.videoWidth > 0 && video.currentTime > .25 && !video.error && !video.muted &&
                (video.webkitAudioDecodedByteCount === undefined || video.webkitAudioDecodedByteCount > 0);
            }""", arg=label)
            player.evaluate("el => el.pause()")
            with page.expect_download(timeout=120_000) as event:
                page.get_by_role("link", name="Descargar " + label + " en MP4").click()
            download = event.value
            require(download.suggested_filename == file, "clip_download_filename")
            target = Path(temporary) / file
            download.save_as(target)
            length = target.stat().st_size
            require(0 < length <= MAX_CLIP_BYTES, "clip_download_size")
            media = probe_media(target, pilot=True)
            require("mp4" in media["format_name"].split(",") and media["video_codec"] == "h264"
                    and media["audio_codec"] == "aac" and media["audio_streams"] == 1 and
                    media["video_streams"] == 1 and media["duration_seconds"] > 0, "clip_media_unplayable")
            with target.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            result[file] = {"sha256": digest, "bytes": length, "duration_seconds": media["duration_seconds"],
                            "video_codec": media["video_codec"], "audio_codec": media["audio_codec"]}
            download.delete()
    return result


def open_saved_job(page, job_id):
    url = PUBLIC + "/?job=" + job_id
    if page.url == url:
        page.reload(wait_until="domcontentloaded")
    else:
        page.goto(url, wait_until="domcontentloaded")
    page.wait_for_function("""id => document.querySelector('#project-list a[aria-current=true]')?.href.endsWith(id)
        && /^Completado/.test(document.querySelector('#job-status')?.textContent)
    """, arg=job_id)
    observed = browser_get(page, "/jobs/" + job_id)["body"]
    require(observed["id"] == job_id and observed["status"] == "completed", "saved_job_not_completed")
    return observed


def check_manual_export(page, job_id, scratch, report):
    panel = page.get_by_text("Elegir fragmento del original", exact=True)
    panel.click()
    original = page.locator("#mvp-source")
    original.wait_for()
    page.wait_for_function("() => document.querySelector('#mvp-source').videoWidth > 0")
    page.locator("#mvp-start").fill("5")
    page.locator("#mvp-end").fill("25")
    path = f"/jobs/{job_id}/editor/exports"
    with page.expect_response(lambda item: item.url == PUBLIC + path
                              and item.request.method == "POST") as response:
        page.get_by_role("button", name="Generar clip manual").click()
    result = response.value
    require(result.status == 202, "manual_export_rejected")
    item = result.json()
    require(ID.fullmatch(item["id"]) and item["start"] == 5 and item["end"] == 25, "manual_export_range")
    link = page.get_by_role("link", name="Descargar clip manual", exact=True)
    link.wait_for(timeout=480_000)
    replay = browser_post(page, path, {"start": 5, "end": 25},
                          result.request.headers["idempotency-key"])
    require(replay["status"] == 202 and replay["id"] == item["id"], "manual_export_duplicated")
    with page.expect_download(timeout=60_000) as download:
        link.click()
    with tempfile.TemporaryDirectory(prefix="beta-manual-", dir=scratch) as directory:
        filename = Path(directory) / "manual.mp4"
        download.value.save_as(filename)
        media = probe_media(filename, pilot=True)
        require(media["video_codec"] == "h264" and media["audio_codec"] == "aac"
                and 19.8 <= media["duration_seconds"] <= 20.2, "manual_export_media")
        report["manual_clip_seconds"] = media["duration_seconds"]
    download.value.delete()
    check(report, "original_preview_manual_range_and_idempotent_export")


def verify_isolation(browser, account, commit, job_id, clip, report):
    with browser_page(browser) as page:
        login(page, account, commit)
        own_projects = browser_get(page, "/projects")
        require(own_projects["status"] == 200 and not own_projects["body"]["projects"],
                "other_user_projects_visible")
        for path in ("/jobs/" + job_id, f"/jobs/{job_id}/source", f"/jobs/{job_id}/clips/{clip}",
                     f"/jobs/{job_id}/clips/{clip}?inline=true", f"/jobs/{job_id}/exports"):
            require(browser_get(page, path)["status"] in {403, 404}, "other_user_content_visible")
        logout(page)
    check(report, "second_user_job_original_clip_and_exports_denied")


def prepare(browser, args, admin, report, revisions):
    accounts = [{"username": "qa_beta_" + secrets.token_hex(10),
                 "password": secrets.token_urlsafe(36)} for _ in range(2)]
    report["step"] = "creator_accounts"
    with browser_page(browser) as page:
        report["step"] = "administrator_sign_in"
        login(page, admin, args.commit)
        check_feedback_removed(page, report)
        page.goto(PUBLIC + "/account", wait_until="domcontentloaded")
        for index, account in enumerate(accounts, start=1):
            report["step"] = "creator_account_create_" + str(index)
            create_account(page, account)
        report["step"] = "administrator_sign_out"
        logout(page)
    check(report, "public_browser_login_logout_and_account_creation")
    transfer = []
    with browser_page(browser, storage=True, transfer=transfer) as page:
        report["step"] = "creator_permissions"
        login(page, accounts[0], args.commit)
        check_normal_permissions(page, report)
        check_feedback_removed(page, report)
        job = upload_video(page, args.video, report, transfer)
        job = open_saved_job(page, job["id"])
        report["step"] = "browser_playback_and_download"
        observed = results(page, job, args.state.parent)
        report["clips"] = observed
        check(report, "browser_video_and_download_mp4_audio_video")
        first = next(iter(observed))
        report["step"] = "manual_export"
        check_manual_export(page, job["id"], args.state.parent, report)
        logout(page)
    report["step"] = "isolation"
    verify_isolation(browser, accounts[1], args.commit, job["id"], first, report)
    shared_http.write_new(args.state, {"schema": SCHEMA, "origin": PUBLIC, "commit": args.commit,
                                      "revisions": revisions, "accounts": accounts, "job": job["id"],
                                      "clips": observed})


def load_state(args, revisions):
    state = json.loads(shared_http.read_private(args.state))
    require(state["schema"] == SCHEMA and state["origin"] == PUBLIC and state["commit"] == args.commit
            and set(state["revisions"]) == {"frontend", "api"} and
            all(state["revisions"][name] != revisions[name] for name in revisions)
            and ID.fullmatch(state["job"]), "replacement_state_identity")
    cloud_revisions(**state["revisions"])
    accounts = state["accounts"]
    require(len(accounts) == 2 and all(
        ACCOUNT.fullmatch(account["username"]) and 32 <= len(account["password"]) <= 128 for account in accounts
    ) and accounts[0]["username"] != accounts[1]["username"], "replacement_state_accounts")
    require(1 <= len(state["clips"]) <= 10 and all(CLIP.fullmatch(name) and SHA256.fullmatch(clip["sha256"])
            for name, clip in state["clips"].items()), "replacement_state_clips")
    return state


def verify(browser, args, admin, report, revisions):
    state = load_state(args, revisions)
    creator, other = state["accounts"]
    first = next(iter(state["clips"]))
    report["step"] = "creator_persistence"
    with browser_page(browser) as page:
        login(page, creator, args.commit)
        job = open_saved_job(page, state["job"])
        observed = results(page, job, args.state.parent)
        require(observed == state["clips"], "clip_bytes_changed_after_replacement")
        report["clips"] = observed
        check_feedback_removed(page, report)
        logout(page)
    check(report, "saved_job_and_identical_clip_bytes_after_replacement")
    report["step"] = "isolation"
    verify_isolation(browser, other, args.commit, state["job"], first, report)
    with browser_page(browser) as page:
        login(page, admin, args.commit)
        check_feedback_removed(page, report)
        report["step"] = "synthetic_account_deactivation"
        deactivate_accounts(page, state["accounts"])
        logout(page)
    check(report, "synthetic_accounts_deactivated")
    report["replaced"] = state["revisions"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=["prepare", "verify"])
    parser.add_argument("--commit", required=True)
    parser.add_argument("--frontend-revision", required=True)
    parser.add_argument("--api-revision", required=True)
    parser.add_argument("--video", type=Path)
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": SCHEMA, "phase": args.mode, "url": PUBLIC, "checks": []}
    stage = "browser_prerequisites"
    try:
        require(COMMIT.fullmatch(args.commit), "commit_shape")
        revisions = cloud_revisions(args.frontend_revision, args.api_revision)
        report.update(commit=args.commit, revisions=revisions)
        shared_http.private_file(args.state, must_exist=args.mode == "verify")
        require(args.report != args.state, "report_and_state_paths_must_differ")
        shared_http.private_file(args.report, must_exist=False)
        require((args.mode == "prepare" and args.video is not None and args.video.is_absolute()
                 and args.video.is_file() and args.video.suffix.lower() == ".mp4") or
                (args.mode == "verify" and args.video is None), "fixture_argument")
        admin = shared_http.validate_admin(json.loads(os.environ.pop("INT_BOOTSTRAP_ADMIN_JSON", "")))
        from playwright.sync_api import sync_playwright

        executable = resolve_browser({"INT_HITO_A_BROWSER_EXECUTABLE": os.environ.get(
            "INT_HITO_B_BROWSER_EXECUTABLE", "")})
        # The driver and browser receive only the environment needed to run.
        child_env = {key: value for key, value in os.environ.items()
                     if key in BROWSER_ENV_ALLOWLIST or key.upper() in {"SYSTEMROOT", "USERPROFILE", "TEMP", "TMP"}}
        os.environ.clear()
        os.environ.update(child_env)
        stage = "unauthenticated_api_boundary"
        http = shared_http.HTTP()
        require(http.request("GET", PRIVATE + "/health").status in {401, 403}, "private_api_direct_request_allowed")
        require(shared_http.json_body(http.request("GET", PUBLIC + "/health"), 200, "public_health")
                == {"status": "ok", "profile": "int-beta"}, "public_database_health")
        check(report, "private_api_invoker_required_and_public_database_healthy")
        stage = "remote_browser_" + args.mode
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=str(executable), env=child_env, headless=True)
            try:
                action = prepare if args.mode == "prepare" else verify
                action(browser, args, admin, report, revisions)
            finally:
                browser.close()
        report["status"] = "passed"
        report.pop("step", None)
        shared_http.write_new(args.report, report)
        print("ClipForge INT beta browser " + args.mode + " passed.")
        return 0
    except (BrowserAcceptanceError, shared_http.AcceptanceError) as error:
        code = str(error)
    except Exception as error:
        # Browser and subprocess exceptions can contain temporary upload URLs,
        # credentials or local paths. Limit diagnostics to this stage code.
        code = report.get("step", stage)
        report["failure_type"] = type(error).__name__
    report.update(status="failed", failure=code)
    try:
        if args.report != args.state:
            shared_http.write_new(args.report, report)
    except (OSError, shared_http.AcceptanceError):
        print("Could not write the browser acceptance report.")
    print("ClipForge INT beta browser " + args.mode + " failed (" + code + ").")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
