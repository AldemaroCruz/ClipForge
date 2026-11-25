"""Verify owner-scoped project deletion through the protected INT portal."""
from pathlib import Path
import re
from time import monotonic

from scripts import int_hito_b_browser as portal

START_PATH = re.compile(re.escape(portal.PUBLIC) + r"/beta/uploads/[a-f0-9]{32}/start")


def deletion_path(job):
    portal.require(portal.ID.fullmatch(job), "synthetic_deletion_scope")
    return f"/jobs/{job}/deletion"


def queue_video(page, fixture):
    page.locator("#upload-video").set_input_files(str(fixture))
    with (
        page.expect_response(lambda event: event.url == portal.PUBLIC + "/beta/uploads"
                             and event.request.method == "POST", timeout=360_000) as reserved,
        page.expect_response(lambda event: START_PATH.fullmatch(event.url)
                             and event.request.method == "POST", timeout=360_000) as started,
    ):
        page.locator("#upload-submit").click()
    upload = reserved.value
    response = started.value
    item = response.json()
    portal.require(upload.status == 201 and response.status == 202 and item.get("status") == "queued",
                   "deletion_fixture_queue")
    job = item["id"]
    deletion_path(job)
    return job, upload.request.post_data_json, upload.request.headers.get("idempotency-key")


def start_deletion(page, job, *, confirm_in_portal=False):
    path = deletion_path(job)
    if confirm_in_portal:
        page.locator("#delete-project").click()
        confirmation = page.locator("#project-delete-dialog")
        scope = confirmation.locator("#project-delete-scope").inner_text().lower()
        title = confirmation.locator("#project-delete-title").inner_text()
        portal.require(confirmation.is_visible() and title.strip()
                       and all(phrase in scope for phrase in ("original", "transcripción", "propuestas", "borradores",
                                                             "clips", "exportaciones", "pendientes", "activos")),
                       "deletion_confirmation_scope")
        return portal.click_response(page, confirmation.locator("#project-delete-confirm"), path, "POST", 202).json()
    return page.evaluate("""async path => {
      const auth = window.ClipForgeAuth;
      const response = await auth.fetch(path, auth.payload({}));
      return response.status === 202 ? await response.json() : {};
    }""", path)


def finish_deletion(page, job, first):
    path = deletion_path(job)
    portal.require(first.get("id") == job and first.get("status") in {"deleting", "deleted"},
                   "deletion_was_not_accepted")
    repeated = portal.browser_post(page, path, {})
    portal.require(repeated["status"] == 202 and repeated["id"] == job, "deletion_repeat_not_idempotent")
    portal.require(portal.browser_post(page, f"/beta/uploads/{job}/start", {})["status"] == 404,
                   "deletion_accepted_late_upload_start")
    deadline = monotonic() + 420
    while True:
        response = portal.browser_get(page, path)
        status = response["body"] or {}
        portal.require(response["status"] == 200 and status.get("id") == job, "deletion_status_lost")
        if status.get("status") == "deleted":
            break
        portal.require(status.get("status") in {"deleting", "delete_error"} and monotonic() < deadline,
                       "deletion_cleanup_did_not_finish")
        page.wait_for_timeout(1_000)
    for suffix in ("", "/source", "/workspace", "/selections", "/drafts", "/exports"):
        portal.require(portal.browser_get(page, f"/jobs/{job}{suffix}")["status"] == 404,
                       "deleted_project_results_remained_available")
    projects = portal.browser_get(page, "/projects")["body"]["projects"]
    portal.require(all(item["id"] != job for item in projects), "deleted_project_reappeared")
    return {key: value for key, value in status.items() if key in {"status", "cancelled_queued",
                                                                   "cancelled_active", "attempts"}}


def wait_active(page, job):
    deadline = monotonic() + 240
    while True:
        item = portal.browser_get(page, f"/jobs/{job}")["body"]
        if item.get("status") in {"transcribing", "rendering"}:
            return item["status"]
        portal.require(item.get("status") in {"queued", "validating"} and monotonic() < deadline,
                       "deletion_fixture_did_not_run")
        page.wait_for_timeout(750)


def acceptance(browser, args, state, report):
    """Only synthetic projects created by this workflow are deletion targets."""
    fixture = Path(args.state.parent / "fixture.mp4")
    portal.require(fixture.is_file() and not fixture.is_symlink(), "deletion_video_fixture")
    creator, outsider = state["accounts"]
    portal.require(all(portal.ACCOUNT.fullmatch(account["username"]) for account in (creator, outsider)),
                   "deletion_requires_run_created_accounts")
    completed = state["job"]
    deletion_path(completed)
    output = report["project_deletion"] = {}
    with portal.browser_page(browser, storage=True) as page, portal.browser_page(browser) as foreign:
        portal.login(page, creator, args.commit)
        portal.login(foreign, outsider, args.commit)
        path = deletion_path(completed)
        portal.require(portal.browser_post(foreign, path, {})["status"] == 404
                       and portal.browser_get(foreign, path)["status"] == 404,
                       "foreign_account_could_delete_project")
        portal.require(portal.browser_post(page, path, {}, csrf=False)["status"] == 403,
                       "deletion_without_csrf")
        portal.check(report, "project_deletion_owner_and_csrf")
        report["step"] = "project_deletion_queued"
        queued, payload, key = queue_video(page, fixture)
        pending = start_deletion(page, queued)
        portal.require(pending.get("cancelled_queued", 0) == 1 and pending.get("cancelled_active", 0) == 0,
                       "queued_cancellation_not_observed")
        output["queued"] = {"id": queued, **finish_deletion(page, queued, pending)}
        replay = portal.browser_post(page, "/beta/uploads", payload, key)
        portal.require(replay["status"] == 404 and not replay["upload"], "deleted_upload_replayed")
        portal.open_saved_job(page, completed)
        report["step"] = "project_deletion_active"
        active, _, _ = queue_video(page, fixture)
        active_state = wait_active(page, active)
        pending = start_deletion(page, active)
        portal.require(pending.get("cancelled_active", 0) == 1, "active_cancellation_not_observed")
        output["active"] = {"id": active, "phase_at_deletion": active_state,
                            **finish_deletion(page, active, pending)}
        portal.open_saved_job(page, completed)
        clip = next(iter(state["clips"]))
        portal.require(portal.browser_get(page, f"/jobs/{completed}/clips/{clip}")["status"] == 200,
                       "unrelated_completed_job_damaged")
        portal.check(report, "deletion_did_not_affect_existing_other_project")
        report["step"] = "project_deletion_completed"
        pending = start_deletion(page, completed, confirm_in_portal=True)
        output["completed"] = {"id": completed, **finish_deletion(page, completed, pending)}
        page.reload(wait_until="domcontentloaded")
        path = deletion_path(completed)
        portal.require(portal.browser_get(page, path)["body"]["status"] == "deleted"
                       and portal.browser_get(page, f"/jobs/{completed}")["status"] == 404,
                       "deleted_project_reappeared_after_reload")
        portal.logout(page)
        portal.logout(foreign)
    portal.check(report, "deletion_completed_queued_active_and_idempotent")
