"""Verify owner-scoped project deletion through the protected INT portal."""
from pathlib import Path
import re
from time import monotonic

from scripts import int_hito_b_browser as portal

START_PATH = re.compile(re.escape(portal.PUBLIC) + r"/beta/uploads/[a-f0-9]{32}/start")
REMOVED_MESSAGE = "Proyecto eliminado de tu cuenta"


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


def request_deletion(page, job):
    result = page.evaluate("""async path => {
      const auth = window.ClipForgeAuth;
      const response = await auth.fetch(path, auth.payload({}));
      return {status: response.status, body: response.status === 202 ? await response.json() : null};
    }""", deletion_path(job))
    portal.require(result == {"status": 202, "body": {"id": job, "status": "deleted"}},
                   "deletion_post_did_not_confirm_immediate_removal")


def confirm_deletion(page, job):
    page.locator("#delete-project").click()
    confirmation = page.locator("#project-delete-dialog")
    scope = confirmation.locator("#project-delete-scope").inner_text().lower()
    title = confirmation.locator("#project-delete-title").inner_text()
    portal.require(confirmation.is_visible() and title.strip()
                   and all(phrase in scope for phrase in ("original", "transcripción", "propuestas", "borradores",
                                                         "clips", "exportaciones", "pendientes", "activos")),
                   "deletion_confirmation_scope")
    confirm = confirmation.locator("#project-delete-confirm")
    confirm.evaluate("""(button, [id, message]) => button.addEventListener('click', () => {
        performance.mark('project-deletion-confirmed');
        const observer = new MutationObserver(() => {
            if (document.querySelector('#project-delete-dialog').open
                || document.querySelector(`#project-list a[href='/?job=${id}']`)
                || new URLSearchParams(location.search).has('job')
                || document.querySelector('#job-status').textContent !== message) return;
            performance.measure('project-deletion-removed', 'project-deletion-confirmed');
            observer.disconnect();
        });
        observer.observe(document.querySelector('#beta-workspace'), {childList: true, subtree: true});
    }, {capture: true, once: true})""", [job, REMOVED_MESSAGE])
    response = portal.click_response(page, confirm, deletion_path(job), "POST", 202)
    portal.require(response.json() == {"id": job, "status": "deleted"}, "deletion_confirmation_receipt")
    elapsed = page.wait_for_function("""() =>
        performance.getEntriesByName('project-deletion-removed', 'measure')[0]?.duration
    """).json_value()
    portal.require(page.locator("#editorial").is_hidden() and page.locator("#clip-list article").count() == 0,
                   "deleted_project_results_remained_in_portal")
    return round(elapsed / 1000, 3)


def check_removed(page, job, *, artifacts=()):
    receipt = portal.browser_get(page, deletion_path(job))
    portal.require(receipt == {"status": 200, "body": {"id": job, "status": "deleted"}}, "deletion_status_lost")
    for suffix in ("", "/source", "/workspace", "/selections", "/drafts", "/exports", *artifacts):
        portal.require(portal.browser_get(page, f"/jobs/{job}{suffix}")["status"] == 404,
                       "deleted_project_results_remained_available")
    projects = portal.browser_get(page, "/projects")["body"]["projects"]
    portal.require(all(item["id"] != job for item in projects), "deleted_project_reappeared")
    matching = portal.browser_get(page, f"/projects?q={job}&limit=1")
    portal.require(matching["status"] == 200 and matching["body"]["projects"] == []
                   and matching["body"]["total"] == 0 and matching["body"]["has_more"] is False,
                   "deleted_project_counted_in_search")


def finish_deletion(page, job):
    check_removed(page, job)
    request_deletion(page, job)
    portal.require(portal.browser_post(page, f"/beta/uploads/{job}/start", {})["status"] == 404,
                   "deletion_accepted_late_upload_start")
    return {"id": job, "status": "deleted"}


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
    with (portal.browser_page(browser, storage=True) as page, portal.browser_page(browser) as foreign,
          portal.browser_page(browser) as second_session):
        portal.login(page, creator, args.commit)
        portal.login(foreign, outsider, args.commit)
        portal.login(second_session, creator, args.commit)
        portal.open_saved_job(second_session, completed)
        path = deletion_path(completed)
        portal.require(portal.browser_post(foreign, path, {})["status"] == 404
                       and portal.browser_get(foreign, path)["status"] == 404,
                       "foreign_account_could_delete_project")
        portal.require(portal.browser_post(page, path, {}, csrf=False)["status"] == 403,
                       "deletion_without_csrf")
        portal.check(report, "project_deletion_owner_and_csrf")
        report["step"] = "project_deletion_queued"
        queued, payload, key = queue_video(page, fixture)
        request_deletion(page, queued)
        output["queued"] = finish_deletion(page, queued)
        replay = portal.browser_post(page, "/beta/uploads", payload, key)
        portal.require(replay["status"] == 404 and not replay["upload"], "deleted_upload_replayed")
        portal.open_saved_job(page, completed)
        report["step"] = "project_deletion_active"
        active, _, _ = queue_video(page, fixture)
        active_state = wait_active(page, active)
        request_deletion(page, active)
        output["active"] = {"id": active, "phase_at_deletion": active_state,
                            **finish_deletion(page, active)}
        portal.open_saved_job(page, completed)
        clip = next(iter(state["clips"]))
        portal.require(portal.browser_get(page, f"/jobs/{completed}/clips/{clip}")["status"] == 200,
                       "unrelated_completed_job_damaged")
        portal.check(report, "deletion_did_not_affect_existing_other_project")
        report["step"] = "project_deletion_completed"
        elapsed = confirm_deletion(page, completed)
        output["completed"] = {**finish_deletion(page, completed), "click_to_removal_seconds": elapsed}
        export = state["editorial"]["exports"][0]["id"]
        draft = state["editorial"]["exports"][0]["draft"]["id"]
        portal.require(portal.ID.fullmatch(export) and portal.ID.fullmatch(draft), "deletion_artifact_identity")
        check_removed(second_session, completed, artifacts=(f"/clips/{clip}", f"/clips/{clip}/captions",
                                                            f"/drafts/{draft}", f"/exports/{export}/files/clip.mp4"))
        portal.require(portal.browser_get(foreign, path)["status"] == 404
                       and portal.browser_post(foreign, path, {})["status"] == 404,
                       "foreign_account_can_access_deletion_receipt")
        page.reload(wait_until="domcontentloaded")
        check_removed(page, completed)
        portal.check(report, "deletion_visible_across_owner_sessions_and_reload")
        portal.logout(page)
        portal.logout(foreign)
        portal.logout(second_session)
    portal.check(report, "deletion_completed_queued_active_and_idempotent")
