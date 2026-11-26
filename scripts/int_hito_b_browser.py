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
import math
import os
from pathlib import Path
import re
import secrets
import tempfile
from time import monotonic
from urllib.parse import urlsplit

from app.check_presentation import caption_color_stats
from app.cloud.config import BETA_MAX_BYTES, BETA_MAX_DIMENSION, BETA_MAX_SECONDS, BETA_WORKER_CONCURRENCY
from app.media import probe_media
from app.subtitles import to_srt, to_vtt, validate_cues
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
MODEL = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,119}")
EDITORIAL_BRIEF = (
    "Elige un fragmento del catálogo que cuente cómo los vecinos recuperaron el huerto comunitario. "
    "Puede mostrar cualquiera de estas acciones: guardar semillas de maíz, turnarse para regar "
    "o enseñar a las escuelas. Una acción clara basta para proponer un clip."
)


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
    require(request.post_data_json.get("burn_subtitles") is True
            and page.locator("#upload-burn-subtitles").is_checked(), "automatic_caption_default_disabled")
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


def close_preview(player):
    player.evaluate("el => { el.pause(); el.removeAttribute('src'); el.load(); }")


def save_download(page, link, target, *, timeout=120_000):
    with page.expect_download(timeout=timeout) as event:
        link.click()
    download = event.value
    try:
        download.save_as(target)
        require(0 < target.stat().st_size <= MAX_CLIP_BYTES, "clip_download_size")
        return download.suggested_filename
    finally:
        download.delete()


def caption_receipt(page, card, target, item, output, *, verify_pixels=True):
    duration = round(item["end"] - item["start"], 3)
    cues = validate_cues(item["cues"], duration)
    require(cues and output.get("burn_subtitles") is True and
            0 <= cues[0]["start"] < cues[-1]["end"] <= duration, "relative_clip_cues_missing")
    digests = {}
    for suffix, label, expected in (("srt", "SRT", to_srt(cues)), ("vtt", "WebVTT", to_vtt(cues))):
        link = card.get_by_role("link", name="Descargar " + label, exact=True)
        require(link.get_attribute("href") == output.get(suffix), "caption_sidecar_link")
        sidecar = target.with_suffix("." + suffix)
        save_download(page, link, sidecar)
        require(sidecar.read_text(encoding="utf-8") == expected, "clip_sidecar_contents_or_timing")
        digests[suffix] = digest_of(sidecar)
    position = item["options"].get("subtitle_position", "bottom")
    color = item["options"]["subtitle_color"]
    observed = {"source_start": item["start"], "source_end": item["end"], "cues": len(cues),
                "first_caption_local": cues[0]["start"], "last_caption_local": cues[-1]["end"],
                "size": item["options"]["subtitle_font_size"], "color": color, "position": position,
                "sidecars": digests}
    if verify_pixels:
        cue = max(cues, key=lambda value: value["end"] - value["start"])
        seconds = (cue["start"] + cue["end"]) / 2
        pixels = caption_color_stats(target, color, seconds=seconds, position=position)
        require(pixels["matching_pixels"] >= 75, "automatic_or_custom_caption_pixels_missing")
        if position == "top":
            below = caption_color_stats(target, color, seconds=seconds)["matching_pixels"]
            require(below <= 10, "top_caption_also_visible_at_bottom")
            pixels["opposite_position_matching_pixels"] = below
        observed["burned_pixels"] = pixels
    return observed


def results(page, job, scratch):
    files = [clip["file"] for clip in job["clips"]]
    require(1 <= len(files) <= 10 and len(set(files)) == len(files) and all(CLIP.fullmatch(file) for file in files),
            "clip_manifest_shape")
    result = {}
    with tempfile.TemporaryDirectory(prefix="beta-clips-", dir=scratch) as temporary:
        for clip in job["clips"]:
            file = clip["file"]
            label = "Clip " + str(int(file[5:7]))
            card = page.locator(f'#clip-list [data-clip-file="{file}"]')
            player = card.locator("video")
            player.wait_for(state="visible")
            caption = clip.get("captions", {})
            output = caption.get("output", {})
            original = f'/jobs/{job["id"]}/clips/{file}'
            require(caption.get("status") == "completed" and isinstance(output, dict) and output.get("mp4") == original
                    and clip.get("caption_rendered") is True, "automatic_caption_manifest_missing")
            require(player.get_attribute("src") == original + "?inline=true", "automatic_caption_preview_url")
            player.click(position={"x": 8, "y": 8})
            player.evaluate("el => { el.muted = false; return el.play(); }")
            page.wait_for_function("""label => {
              const video = [...document.querySelectorAll('video')].find(el => el.getAttribute('aria-label') === label);
              return video?.videoWidth > 0 && video.currentTime > .25 && !video.error && !video.muted &&
                (video.webkitAudioDecodedByteCount === undefined || video.webkitAudioDecodedByteCount > 0);
            }""", arg=label)
            close_preview(player)
            target = Path(temporary) / file
            link = card.get_by_role("link", name="Descargar " + label + " en MP4", exact=True)
            require(save_download(page, link, target) == file, "clip_download_filename")
            length = target.stat().st_size
            media = probe_media(target, pilot=True)
            require("mp4" in media["format_name"].split(",") and media["video_codec"] == "h264"
                    and media["audio_codec"] == "aac" and media["audio_streams"] == 1 and
                    media["video_streams"] == 1 and media["duration_seconds"] > 0, "clip_media_unplayable")
            with target.open("rb") as stream:
                digest = hashlib.file_digest(stream, "sha256").hexdigest()
            require(abs(media["duration_seconds"] - (clip["end"] - clip["start"])) < .2,
                    "automatic_clip_duration_mismatch")
            result[file] = {"sha256": digest, "bytes": length, "duration_seconds": media["duration_seconds"],
                            "video_codec": media["video_codec"], "audio_codec": media["audio_codec"],
                            "captions": caption_receipt(page, card, target, clip, output)}
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


def read_caption(page, job_id, file):
    result = browser_get(page, f"/jobs/{job_id}/clips/{file}/captions")
    require(result["status"] == 200 and isinstance(result["body"], dict), "clip_caption_read")
    return result["body"]


def caption_output(page, job_id, file, previous, *, timeout=540):
    began = monotonic()
    while True:
        state = read_caption(page, job_id, file)
        output = state.get("output")
        if state.get("status") == "completed" and output and output["id"] != previous:
            require(ID.fullmatch(output["id"])
                    and output.get("mp4") == f'/jobs/{job_id}/exports/{output["id"]}/files/clip.mp4',
                    "clip_caption_variant_identity")
            return state
        require(state.get("status") != "failed", "clip_caption_render_failed")
        require(monotonic() - began < timeout, "clip_caption_render_timeout")
        page.wait_for_timeout(2000)


def read_caption_variant(page, job_id, file, state, scratch, *, check_pixels=True):
    card = page.locator(f'#clip-list [data-clip-file="{file}"]')
    output = state["output"]
    page.wait_for_function("""([file, url]) =>
        document.querySelector('#clip-list [data-clip-file="' + file + '"] video')
          ?.getAttribute('src') === url + '?inline=true'""", arg=[file, output["mp4"]])
    link = card.get_by_role("link", name="Descargar Clip " + str(int(file[5:7])) + " en MP4", exact=True)
    require(link.get_attribute("href") == output["mp4"], "custom_clip_download_variant")
    with tempfile.TemporaryDirectory(prefix="beta-caption-variant-", dir=scratch) as directory:
        media = Path(directory) / file
        save_download(page, link, media)
        duration = probe_media(media, pilot=True)["duration_seconds"]
        require(abs(duration - state["duration"]) < .2, "custom_clip_duration_changed")
        receipt = caption_receipt(page, card, media, {**state, "options": state["style"]},
                                  output, verify_pixels=check_pixels)
        receipt["sha256"] = digest_of(media)
    return receipt


def prepare_clip_styles(page, job, original, scratch, report):
    """Edit a rendered clip and then replace only presentation across its project."""
    report["step"] = "generated_clip_personalization"
    job_id = job["id"]
    file = max(original, key=lambda item: original[item]["captions"]["source_start"])
    initial = {clip["file"]: clip["captions"]["output"]["id"] for clip in job["clips"]}
    baseline = {name: read_caption(page, job_id, name)["cues"] for name in initial}
    card = page.locator(f'#clip-list [data-clip-file="{file}"]')
    card.get_by_role("button", name="Editar subtítulos", exact=True).click()
    editor = page.locator("#clip-caption-form")
    editor.wait_for()
    index = next((offset for offset, cue in enumerate(baseline[file])
                  if cue["end"] - cue["start"] >= .25), None)
    require(index is not None, "clip_personalization_fixture_cue")
    new_start = round(baseline[file][index]["start"] + .125, 3)
    text = "Subtítulo editado del recorte."
    editor.locator('[data-field="text"]').nth(index).fill(text)
    editor.locator('[data-field="start"]').nth(index).fill(str(new_start))
    page.locator("#clip-caption-size").fill("76")
    page.locator("#clip-caption-color").fill("#ff0000")
    page.locator("#clip-caption-position").select_option("top")
    page.locator("#clip-caption-edge").fill("6")
    path = f"/jobs/{job_id}/clips/{file}/captions"
    with page.expect_response(lambda item: item.url == PUBLIC + path and item.request.method == "PUT") as saved:
        page.locator("#clip-caption-save").click()
    require(saved.value.ok, "clip_personalization_http_" + str(saved.value.status))
    edited = caption_output(page, job_id, file, initial[file])
    require(edited["cues"][index]["start"] == new_start and edited["cues"][index]["text"] == text
            and edited["style"]["subtitle_outline"] == 6, "clip_personalization_not_persisted")
    interim = browser_get(page, "/jobs/" + job_id)["body"]
    require(all(clip["captions"]["output"]["id"] == initial[clip["file"]] for clip in interim["clips"]
                if clip["file"] != file), "individual_caption_change_affected_other_clips")
    single = read_caption_variant(page, job_id, file, edited, scratch)
    require((single["color"], single["position"], single["size"]) == ("#FF0000", "top", 76),
            "individual_caption_style_changed")
    page.wait_for_function("""url => document.querySelector('#clip-caption-preview')
        ?.getAttribute('src') === url + '?inline=true'""", arg=edited["output"]["mp4"])
    with tempfile.TemporaryDirectory(prefix="beta-caption-original-", dir=scratch) as directory:
        target = Path(directory) / file
        save_download(page, card.get_by_role("link", name="MP4 inicial", exact=True), target)
        require(digest_of(target) == original[file]["sha256"], "caption_edit_changed_initial_mp4")
    check(report, "existing_clip_caption_edit_without_upload_or_retranscription")

    report["step"] = "project_caption_style"
    page.locator("#clip-caption-size").fill("88")
    page.locator("#clip-caption-color").fill("#0000ff")
    confirmations = []

    def approve(dialog):
        confirmations.append(dialog.message)
        dialog.accept()

    page.once("dialog", approve)
    with page.expect_response(lambda item: item.url == PUBLIC + f"/jobs/{job_id}/captions"
                              and item.request.method == "PUT") as all_saved:
        page.locator("#clip-caption-apply-all").click()
    require(all_saved.value.ok and confirmations and "reemplazará" in confirmations[0], "project_style_confirmation")
    saved_project = all_saved.value.json()
    project = {key: saved_project[key] for key in ("style", "revision")}
    initial[file] = edited["output"]["id"]
    after = {name: caption_output(page, job_id, name, previous) for name, previous in initial.items()}
    require(all(item["style"] == project["style"] for item in after.values())
            and all(after[name]["cues"] == (edited["cues"] if name == file else baseline[name]) for name in after),
            "project_style_did_not_preserve_text_or_replace_overrides")
    latest = read_caption_variant(page, job_id, file, after[file], scratch)
    require(latest["sha256"] != single["sha256"] and latest["color"] == "#0000FF"
            and latest["size"] == 88 and latest["position"] == "top"
            and latest["sidecars"] == single["sidecars"], "project_style_not_reflected_in_mp4")
    report["caption_customization"] = {"individual": single, "project": latest, "updated_clips": len(after)}
    check(report, "project_caption_style_applied_to_all_with_individual_timing_preserved")
    return {"file": file, "project": project,
            "clips": {name: caption_state_digest(item) for name, item in after.items()}, "receipt": latest}


def caption_state_digest(item):
    persisted = {key: item.get(key) for key in ("style", "cues", "start", "end", "revision", "status", "output")}
    return shared_http.digest(shared_http.canonical(persisted))


def verify_clip_styles(page, job, saved, original, scratch, report):
    require(job["caption_style"] == saved["project"], "project_caption_style_lost_after_replacement")
    job_id = job["id"]
    states = {name: read_caption(page, job_id, name) for name in saved["clips"]}
    for name, item in states.items():
        require(caption_state_digest(item) == saved["clips"][name], "clip_caption_state_lost_after_replacement")
    file = saved["file"]
    observed = read_caption_variant(page, job_id, file, states[file], scratch, check_pixels=False)
    expected = {key: value for key, value in saved["receipt"].items() if key != "burned_pixels"}
    require(observed == expected, "clip_caption_files_changed_after_replacement")
    with tempfile.TemporaryDirectory(prefix="beta-caption-originals-", dir=scratch) as directory:
        for name, before in original.items():
            card = page.locator(f'#clip-list [data-clip-file="{name}"]')
            target = Path(directory) / name
            save_download(page, card.get_by_role("link", name="MP4 inicial", exact=True), target)
            require(digest_of(target) == before["sha256"], "initial_clip_bytes_changed_after_replacement")
    check(report, "automatic_clips_and_saved_caption_versions_after_replacement")


def check_manual_export(page, job_id, scratch, report):
    panel = page.get_by_text("Elegir fragmento del original", exact=True)
    panel.click()
    original = page.locator("#mvp-source")
    original.wait_for()
    page.wait_for_function("""path => document.querySelector('#mvp-source')?.getAttribute('src') === path""",
                           arg=f"/jobs/{job_id}/source")
    with page.expect_response(lambda response: response.url == PUBLIC + f"/jobs/{job_id}/source"
                              and response.request.method == "GET", timeout=60_000) as preview:
        original.click(position={"x": 8, "y": 8})
        original.evaluate("el => el.play()")
    require(preview.value.status in {200, 206}, "manual_source_preview_response")
    page.wait_for_function("""() => {
        const source = document.querySelector('#mvp-source');
        return source?.videoWidth > 0 && source.currentTime > .25 && !source.error;
    }""")
    close_preview(original)
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


def click_response(page, control, path, method, status, *, failing_prerequisite=None):
    def match(response):
        return response.request.method == method and (
            response.url.startswith(PUBLIC + path)
            or (failing_prerequisite and response.url == PUBLIC + failing_prerequisite and response.status >= 400)
        )

    with page.expect_response(match) as event:
        control.click()
    response = event.value
    if response.status != status:
        stage = "prerequisite" if failing_prerequisite and response.url == PUBLIC + failing_prerequisite else "request"
        kind = "json" if "application/json" in response.headers.get("content-type", "") else "nonjson"
        raise BrowserAcceptanceError(f"editorial_{stage}_http_{response.status}_{kind}")
    return response


def open_editorial(page):
    panel = page.locator("#editorial-details")
    if panel.get_attribute("open") is None:
        page.locator("#editorial-heading").click()


def prepare_selection(page, job, model, *, brief=EDITORIAL_BRIEF):
    config = browser_get(page, "/ai/config")
    require(config["status"] == 200 and config["body"].get("provider") == "openai"
            and config["body"].get("model") == model and config["body"].get("configured") is True,
            "expected_real_editorial_provider")
    open_editorial(page)
    page.locator("#editorial-brief").fill(brief)
    path = f"/jobs/{job}/selections"
    preview = click_response(page, page.locator("#editorial-preview-button"), path + "/preview", "POST", 200).json()
    calls = preview.get("budget", {}).get("provider_calls")
    require(type(calls) is int and calls > 0, "editorial_preview_call_budget")
    page.locator("#editorial-consent").check()
    return path, calls


def selection_receipt(response, job, planned_calls, began):
    require(response.status == 202, f"editorial_selection_http_{response.status}")
    selection = response.json()
    body = response.request.post_data_json
    require(ID.fullmatch(selection.get("id", "")) and selection.get("job_id") == job
            and selection.get("provider_calls_planned") == planned_calls
            and isinstance(body, dict) and body.get("consent") is True, "editorial_run_identity")
    return selection["id"], body, began


def start_selection(page, job, model, *, brief=EDITORIAL_BRIEF):
    path, planned_calls = prepare_selection(page, job, model, brief=brief)
    began = monotonic()
    response = click_response(page, page.locator("#editorial-run"), path, "POST", 202)
    return selection_receipt(response, job, planned_calls, began)


def provider_call_intervals(selection):
    intervals = selection.get("provider_call_intervals")
    require(isinstance(intervals, list) and len(intervals) == selection["provider_responses"],
            "editorial_provider_interval_count")
    observed = []
    previous_end = 0
    for interval in intervals:
        require(isinstance(interval, dict), "editorial_provider_interval_shape")
        start, end = interval.get("started_at"), interval.get("finished_at")
        require(type(start) in {int, float} and type(end) in {int, float}
                and math.isfinite(start) and math.isfinite(end)
                and 0 < start < end and start >= previous_end, "editorial_provider_interval_bounds")
        observed.append({"started_at": start, "finished_at": end})
        previous_end = end
    return observed


def finish_selection(page, job, receipt, model, duration, *, allow_empty=False):
    identity, body, began = receipt
    path = f"/jobs/{job}/selections/{identity}"
    while True:
        response = browser_get(page, path)
        require(response["status"] == 200, "editorial_selection_read")
        selection = response["body"]
        state = selection.get("status")
        if state == "completed":
            break
        if state == "failed":
            error = selection.get("error_code", "")
            raise BrowserAcceptanceError(error if re.fullmatch(r"AI_[A-Z_]{1,40}", error)
                                         else "editorial_selection_failed")
        require(state in {"queued", "running", "processing"} and monotonic() - began < 540,
                "editorial_real_selection_did_not_complete")
        page.wait_for_timeout(1_000)
    candidates = selection.get("candidates")
    windows = selection.get("analysis_windows", [])
    models = selection.get("provider_models_received", [])
    require(selection.get("provider") == "openai" and selection.get("model") == model
            and selection.get("provider_response_received") is True
            and 1 <= selection.get("provider_responses", 0) <= selection.get("provider_calls", 0),
            "real_provider_response_receipt")
    require(isinstance(models, list) and models
            and all(isinstance(value, str) and MODEL.fullmatch(value) for value in models),
            "real_provider_model_receipt")
    require(isinstance(candidates, list) and len(candidates) <= 5 and windows
            and (allow_empty or candidates), "real_provider_proposal_receipt")
    require(abs(windows[0]["start"]) <= .1 and windows[-1]["end"] >= duration - .1
            and selection.get("last_transcript_end", 0) >= duration - 45,
            "editorial_selection_did_not_cover_full_video")
    unique_ids = {item["range_id"] for item in candidates}
    ordered = sorted(candidates, key=lambda item: item["start"])
    theme = re.compile(r"semill|maíz|huert|cosech|vecin|escuel|cultiv", re.IGNORECASE)
    require(len(unique_ids) == len(candidates)
            and all(item.get("origin") == "llm" and item.get("title") and item.get("reason")
                    and item.get("start", -1) >= 0 and item.get("end", duration + 1) <= duration
                    and 19.999 <= item["end"] - item["start"] <= 60.001 for item in candidates)
            and all(left["end"] <= right["start"] for left, right in zip(ordered, ordered[1:])),
            "editorial_candidate_integrity")
    if candidates:
        require(any(theme.search(item["title"] + " " + item["reason"])
                    and theme.search(item.get("transcript_excerpt", "")) for item in candidates),
                "editorial_synthetic_topic_missing")
    replay = browser_post(page, f"/jobs/{job}/selections", body)
    require(replay["status"] in {200, 202} and replay["id"] == identity
            and browser_get(page, path)["body"]["provider_calls"] == selection["provider_calls"],
            "editorial_replay_called_provider")
    return {"id": identity, "provider": "openai", "model": model, "models_received": models, "proposals": len(candidates),
            "provider_calls": selection["provider_calls"], "provider_responses": selection["provider_responses"],
            "provider_call_intervals": provider_call_intervals(selection),
            "analysis_windows": windows, "last_transcript_end": selection["last_transcript_end"],
            "provider_seconds": selection.get("provider_elapsed_seconds"),
            "worker_seconds": selection.get("elapsed_seconds"), "wall_seconds": round(monotonic() - began, 3)}


def open_late_draft(page, job, start, end, *, generated, expected_style=None, analysis_id=None):
    if generated:
        if analysis_id is not None:
            page.wait_for_function("id => document.querySelector('#editorial-runs').value === id", arg=analysis_id)
        candidates = page.locator("#editorial-candidates")
        candidates.get_by_role("button", name="Reproducir intervalo").first.click()
        source = page.locator("#editorial-source")
        page.wait_for_function("""() => {
            const video = document.querySelector('#editorial-source');
            return video.videoWidth > 0 && !video.paused && !video.seeking && !video.error;
        }""", timeout=60_000)
        close_preview(source)
        create = candidates.get_by_role("button", name="Crear / abrir borrador").first
        selection_path = f"/jobs/{job}/selections/"
        if analysis_id is not None:
            selection_path += f"{analysis_id}/candidates/"
        observed = click_response(page, create, selection_path, "POST", 201).json()
        if analysis_id is not None:
            require(observed.get("selection_origin", {}).get("analysis_id") == analysis_id,
                    "editorial_draft_used_a_different_selection")
        if expected_style is not None:
            require(all(observed["options"].get(key) == value for key, value in expected_style.items()),
                    "editorial_candidate_did_not_inherit_project_caption_style")
        page.locator("#editorial-save").wait_for()
        if (observed["start"], observed["end"]) != (start, end):
            page.locator("#editorial-start").fill(str(start))
            page.locator("#editorial-end").fill(str(end))
            click_response(page, page.locator("#editorial-apply-range"), f"/jobs/{job}/editor/range", "POST", 200)
    else:
        details = page.locator("#mvp-editor-details")
        if details.get_attribute("open") is None:
            details.locator("summary").click()
        page.locator("#mvp-start").fill(str(start))
        page.locator("#mvp-end").fill(str(end))
        draft_path = f"/jobs/{job}/drafts"
        click_response(page, page.locator("#mvp-edit-draft"), draft_path, "POST", 201,
                       failing_prerequisite=f"/jobs/{job}/editor/range")
    page.locator("#editorial-save").wait_for()


def save_style(page, job, size, color, text):
    page.locator("#editorial-burn").check()
    page.locator("#editorial-size").fill(str(size))
    page.locator("#editorial-color").fill(color.lower())
    rows = page.locator("#editorial-cues .editorial-cue")
    require(rows.count() > 0, "editorial_persisted_transcript_cues_missing")
    for index in reversed(range(1, rows.count())):
        row = rows.nth(index)
        if float(row.locator('[data-field="start"]').input_value()) < 1.6:
            row.get_by_role("button", name="Quitar subtítulo").click()
    rows.first.locator('[data-field="start"]').fill("0.15")
    rows.first.locator('[data-field="end"]').fill("1.6")
    rows.first.locator('[data-field="text"]').fill(text)
    item = click_response(page, page.locator("#editorial-save"), f"/jobs/{job}/drafts/", "PUT", 200).json()
    require(ID.fullmatch(item.get("id", "")) and item["options"]["burn_subtitles"]
            and item["options"]["subtitle_font_size"] == size and item["options"]["subtitle_color"] == color
            and text in [part["text"] for part in item["cues"]], "editorial_draft_style_persisted")
    return item


def start_editorial_export(page, job, draft):
    path = f"/jobs/{job}/drafts/{draft['id']}/exports"
    activated = monotonic()
    response = click_response(page, page.locator("#editorial-export"), path, "POST", 202)
    item = response.json()
    require(ID.fullmatch(item.get("id", "")) and item["draft_id"] == draft["id"], "editorial_export_identity")
    return item["id"], activated, response.request.headers["idempotency-key"]


def digest_of(path):
    with path.open("rb") as handle:
        return hashlib.file_digest(handle, "sha256").hexdigest()


def fetch_editorial_export(page, job, draft, receipt, scratch, *, check_pixels=True, ready_seconds=None):
    export_id, activated, key = receipt
    row = page.locator(f'#editorial-exports article[data-export-id="{export_id}"]')
    mp4 = row.get_by_role("link", name="Descargar MP4 editado")
    mp4.wait_for(timeout=480_000)
    if ready_seconds is None:
        ready_seconds = round(monotonic() - activated, 3)
    player = row.locator("video")
    player.click(position={"x": 8, "y": 8})
    player.evaluate("el => { el.muted = false; return el.play(); }")
    page.wait_for_function("""id => {
        const player = document.querySelector('#editorial-exports [data-export-id="' + id + '"] video');
        return player?.videoWidth > 0 && player.currentTime > .25 && !player.error && !player.muted &&
          (player.webkitAudioDecodedByteCount === undefined || player.webkitAudioDecodedByteCount > 0);
    }""", arg=export_id)
    close_preview(player)
    with tempfile.TemporaryDirectory(prefix="beta-editorial-", dir=scratch) as directory:
        root = Path(directory)
        files = {}
        for ext, link in (("mp4", mp4), ("srt", row.get_by_role("link", name="Descargar SRT")),
                          ("vtt", row.get_by_role("link", name="Descargar VTT"))):
            with page.expect_download(timeout=60_000) as download:
                link.click()
            target = root / f"clip.{ext}"
            download.value.save_as(target)
            download.value.delete()
            require(0 < target.stat().st_size <= MAX_CLIP_BYTES, "editorial_export_size")
            files[ext] = digest_of(target)
        duration = draft["end"] - draft["start"]
        media = probe_media(root / "clip.mp4", pilot=True)
        cues = validate_cues(draft["cues"], duration)
        require(media["video_codec"] == "h264" and media["audio_codec"] == "aac"
                and abs(media["duration_seconds"] - duration) < .2 and cues,
                "editorial_download_media")
        require((root / "clip.srt").read_text(encoding="utf-8") == to_srt(cues)
                and (root / "clip.vtt").read_text(encoding="utf-8") == to_vtt(cues),
                "editorial_sidecar_contents_or_timing")
        pixels = caption_color_stats(root / "clip.mp4", draft["options"]["subtitle_color"],
                                    position=draft["options"].get("subtitle_position", "bottom")) if check_pixels else {}
        require(not check_pixels or pixels["matching_pixels"] >= 75, "editorial_pixels_not_burned")
    if key:
        replay = browser_post(page, f"/jobs/{job}/drafts/{draft['id']}/exports", {"revision": draft["revision"]}, key)
        require(replay["status"] == 202 and replay["id"] == export_id, "editorial_export_duplicated")
    return {"files": files, "media_seconds": media["duration_seconds"], "cues": len(cues),
            "first_caption_local": cues[0]["start"], "last_caption_local": cues[-1]["end"],
            "source_start": draft["start"], "source_end": draft["end"],
            "size": draft["options"]["subtitle_font_size"], "burned_pixels": pixels, "wall_seconds": ready_seconds}


def prepare_editorial(page, job, args, report, style):
    editorial = {}
    selection = None
    if args.editorial_model:
        report["step"] = "real_provider_selection"
        started = start_selection(page, job, args.editorial_model)
        selection = finish_selection(page, job, started, args.editorial_model, 120)
        editorial["selection"] = {key: value for key, value in selection.items() if key != "id"}
    else:
        config = browser_get(page, "/ai/config")
        require(config["status"] == 200 and config["body"]["configured"] is False
                and config["body"]["provider"] == "disabled" and config["body"].get("reason"),
                "editorial_disabled_state")
        editorial["selection"] = {"provider": "disabled", "real_provider_called": False,
                                  "status": "provider_not_configured"}
    report["editorial"] = editorial
    report["step"] = "editorial_draft_and_burned_subtitles"
    open_late_draft(page, job, 86, 109, generated=selection is not None, expected_style=style)
    exports = []
    variants = (
        ("Edición y acción.\nCorazón y mañana.", 32, "#FF0000"),
        ("Edición y canción.\nCorazón y mañana.", 88, "#0000FF"),
    )
    for text, size, color in variants:
        draft = save_style(page, job, size, color, text)
        require((draft["start"], draft["end"]) == (86, 109), "editorial_late_range_changed")
        receipt = start_editorial_export(page, job, draft)
        inspected = fetch_editorial_export(page, job, draft, receipt, args.state.parent)
        require(abs(inspected["first_caption_local"] - .15) < .001
                and inspected["last_caption_local"] <= inspected["media_seconds"] + .1,
                "editorial_relative_caption_timing")
        exports.append({"id": receipt[0], "draft": draft, "receipt": inspected})
    first, second = exports
    require(first["id"] != second["id"] and first["draft"]["id"] == second["draft"]["id"]
            and first["draft"]["revision"] < second["draft"]["revision"]
            and all(first["receipt"]["files"][ext] != second["receipt"]["files"][ext] for ext in ("mp4", "srt", "vtt"))
            and second["receipt"]["burned_pixels"]["height"] > first["receipt"]["burned_pixels"]["height"],
            "editorial_revision_or_style_not_reflected")
    editorial["exports"] = [item["receipt"] for item in exports]
    check(report, "editorial_late_range_color_size_and_edited_sidecars")
    return {"selection_id": selection["id"] if selection else None, "exports": exports}


def verify_editorial(page, job, state, scratch, report):
    open_editorial(page)
    for item in state["exports"]:
        require(ID.fullmatch(item["id"]), "editorial_replacement_state")
        observed = fetch_editorial_export(page, job, item["draft"], (item["id"], monotonic(), None),
                                          scratch, check_pixels=False)
        require(observed["files"] == item["receipt"]["files"], "editorial_files_changed_after_replacement")
    draft = state["exports"][-1]["draft"]
    saved = browser_get(page, f"/jobs/{job}/drafts/{draft['id']}")
    require(saved["status"] == 200 and all(saved["body"][key] == draft[key]
                for key in ("revision", "start", "end", "options", "cues")), "editorial_draft_lost_after_replacement")
    if state["selection_id"]:
        saved_run = browser_get(page, f"/jobs/{job}/selections/{state['selection_id']}")
        require(saved_run["status"] == 200 and saved_run["body"]["status"] == "completed"
                and saved_run["body"]["candidates"], "editorial_proposals_lost_after_replacement")
    check(report, "editorial_draft_and_identical_downloads_after_replacement")


def verify_isolation(browser, account, commit, job_id, clip, report):
    with browser_page(browser) as page:
        login(page, account, commit)
        own_projects = browser_get(page, "/projects")
        require(own_projects["status"] == 200 and not own_projects["body"]["projects"],
                "other_user_projects_visible")
        for path in ("/jobs/" + job_id, f"/jobs/{job_id}/source", f"/jobs/{job_id}/clips/{clip}",
                     f"/jobs/{job_id}/clips/{clip}?inline=true", f"/jobs/{job_id}/exports",
                     f"/jobs/{job_id}/drafts", f"/jobs/{job_id}/selections", f"/jobs/{job_id}/selections/context"):
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
        check(report, "automatic_burned_mp4_srt_webvtt_without_editor")
        first = next(iter(observed))
        report["step"] = "manual_export"
        check_manual_export(page, job["id"], args.state.parent, report)
        captions = prepare_clip_styles(page, job, observed, args.state.parent, report)
        editorial_state = prepare_editorial(page, job["id"], args, report, captions["project"]["style"])
        logout(page)
    report["step"] = "isolation"
    verify_isolation(browser, accounts[1], args.commit, job["id"], first, report)
    state = {"schema": SCHEMA, "origin": PUBLIC, "commit": args.commit,
             "revisions": revisions, "accounts": accounts, "job": job["id"],
             "clips": {name: {"sha256": item["sha256"]} for name, item in observed.items()},
             "captions": captions, "editorial": editorial_state}
    require(len(json.dumps(state, indent=2, ensure_ascii=False).encode("utf-8")) + 1 <= shared_http.MAX_SECRET,
            "browser_replacement_state_exceeds_private_limit")
    shared_http.write_new(args.state, state)


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
        verify_clip_styles(page, job, state["captions"], state["clips"], args.state.parent, report)
        report["clips"] = state["clips"]
        check_feedback_removed(page, report)
        report["step"] = "editorial_persistence"
        verify_editorial(page, state["job"], state["editorial"], args.state.parent, report)
        logout(page)
    check(report, "saved_job_and_identical_clip_bytes_after_replacement")
    report["step"] = "isolation"
    verify_isolation(browser, other, args.commit, state["job"], first, report)
    from scripts.int_hito_b_deletion_browser import acceptance as deletion_acceptance
    deletion_acceptance(browser, args, state, report)
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
    parser.add_argument("--editorial-model", default="")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    args = parser.parse_args()
    report = {"schema": SCHEMA, "phase": args.mode, "url": PUBLIC, "checks": []}
    stage = "browser_prerequisites"
    try:
        require(COMMIT.fullmatch(args.commit), "commit_shape")
        require(not args.editorial_model or MODEL.fullmatch(args.editorial_model), "editorial_model_shape")
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
