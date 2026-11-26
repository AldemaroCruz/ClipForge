"""Verify owner-scoped project deletion through the protected INT portal."""
from pathlib import Path
import re
import secrets
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


def reserve_project(page):
    fixture = {"filename": "synthetic-deletion-recheck.mp4", "bytes": 1024}
    key = secrets.token_hex(16)
    receipt = portal.browser_post(page, "/beta/uploads", fixture, key)
    job = receipt.get("id")
    portal.require(receipt["status"] == 201 and receipt["upload"] and isinstance(job, str)
                   and portal.ID.fullmatch(job), "deletion_recheck_reservation")
    return job, fixture, key


def recheck_reservations(browser, args, accounts, report):
    output = report["project_deletion"] = {"scope": "synthetic_reservation"}
    with portal.browser_page(browser) as owner, portal.browser_page(browser) as other:
        portal.login(owner, accounts[0], args.commit)
        portal.login(other, accounts[1], args.commit)
        for page in (owner, other):
            me = portal.browser_get(page, "/auth/me")
            portal.require(me["status"] == 200 and me["body"]["user"]["is_admin"] is False,
                           "deletion_recheck_requires_normal_account")
        report["step"] = "deletion_recheck_reservations"
        pending = []
        try:
            job, fixture, key = reserve_project(owner)
            pending.append((owner, job))
            control, _, _ = reserve_project(other)
            pending.append((other, control))
            portal.require(control != job, "deletion_recheck_projects_not_distinct")
            path = deletion_path(job)
            portal.require(portal.browser_post(other, path, {})["status"] == 404
                           and portal.browser_get(other, f"/jobs/{job}")["status"] == 404
                           and portal.browser_post(owner, path, {}, csrf=False)["status"] == 403,
                           "deletion_recheck_ownership_or_csrf")
            portal.check(report, "project_deletion_owner_and_csrf")

            search = f"/projects?q={job}&limit=1"
            result = portal.browser_get(owner, search + "&offset=0")
            following = portal.browser_get(owner, search + "&offset=1")
            portal.require(result["status"] == 200 and result["body"]["total"] == 1
                           and [p["id"] for p in result["body"]["projects"]] == [job]
                           and result["body"]["has_more"] is False
                           and following["status"] == 200 and following["body"]["total"] == 1
                           and following["body"]["projects"] == [], "deletion_recheck_initial_search")
            owner.goto(portal.PUBLIC + f"/?job={job}", wait_until="domcontentloaded")
            owner.locator(f'#project-list a[href="/?job={job}"][aria-current=true]').wait_for()
            original = portal.browser_get(owner, f"/jobs/{job}")
            portal.require(original["status"] == 200 and original["body"]["status"] == "awaiting_upload",
                           "deletion_recheck_project_not_reserved")
            report["step"] = "deletion_recheck_confirm"
            elapsed = confirm_deletion(owner, job)
            output["reservation"] = {**finish_deletion(owner, job), "click_to_removal_seconds": elapsed}
            replay = portal.browser_post(owner, "/beta/uploads", fixture, key)
            portal.require(replay["status"] == 404 and not replay["upload"], "deleted_upload_replayed")
            pending.remove((owner, job))
            control_status = portal.browser_get(other, f"/jobs/{control}")
            portal.require(control_status["status"] == 200 and control_status["body"]["status"] == "awaiting_upload"
                           and portal.browser_get(other, path)["status"] == 404,
                           "deletion_recheck_unrelated_project_or_receipt")
            portal.check(report, "deletion_did_not_affect_existing_other_project")
            portal.check(report, "deletion_confirmed_and_idempotent_on_synthetic_reservation")

            report["step"] = "deletion_recheck_sign_in_again"
            portal.logout(owner)
            portal.login(owner, accounts[0], args.commit)
            owner.goto(portal.PUBLIC + f"/?job={job}", wait_until="domcontentloaded")
            owner.wait_for_function("""id => !new URLSearchParams(location.search).has('job')
                && !document.querySelector(`#project-list a[href='/?job=${id}']`)""", arg=job)
            check_removed(owner, job)
            following = portal.browser_get(owner, search + "&offset=1")
            portal.require(following["status"] == 200 and following["body"]["total"] == 0
                           and following["body"]["projects"] == [] and following["body"]["has_more"] is False,
                           "deleted_project_counted_on_later_page")
            config_result = portal.browser_get(owner, "/ai/config")
            config = config_result["body"] or {}
            portal.require(config_result["status"] == 200 and config.get("provider") == "openai"
                           and config.get("model") == args.editorial_model and config.get("configured") is True
                           and config.get("enabled") is True
                           and config.get("destination") == "https://api.openai.com/v1/responses",
                           "deletion_recheck_openai_config_changed")
            report["editorial"] = {"provider": "openai", "model": args.editorial_model, "configured": True,
                                   "real_provider_called": False}
            portal.check(report, "deletion_visible_after_relogin_and_absent_from_search_pages")
            portal.check(report, "configured_openai_model_preserved_without_inference")
        finally:
            report["synthetic_projects_removed"] = True
            for page, job in pending:
                try:
                    request_deletion(page, job)
                except Exception:
                    report["synthetic_projects_removed"] = False
        portal.require(report["synthetic_projects_removed"], "deletion_recheck_project_cleanup")
        portal.logout(owner)
        portal.logout(other)


def recheck(browser, args, admin, report):
    accounts = [{"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
                for _ in range(2)]
    attempted = []
    try:
        report["step"] = "deletion_recheck_accounts"
        with portal.browser_page(browser) as page:
            portal.login(page, admin, args.commit)
            page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
            for account in accounts:
                attempted.append(account)
                portal.create_account(page, account)
            portal.logout(page)
        recheck_reservations(browser, args, accounts, report)
    finally:
        if attempted:
            try:
                with portal.browser_page(browser) as page:
                    portal.login(page, admin, args.commit)
                    result = portal.browser_get(page, "/auth/users")
                    portal.require(result["status"] == 200, "deletion_recheck_accounts_lookup")
                    active = {u["username"] for u in result["body"]["users"] if u["is_active"]}
                    portal.deactivate_accounts(page, [account for account in attempted if account["username"] in active])
                    portal.logout(page)
                report["synthetic_accounts_deactivated"] = True
            except Exception:
                report["synthetic_accounts_deactivated"] = False
    portal.require(report.get("synthetic_accounts_deactivated") is True, "deletion_recheck_account_cleanup")
    portal.check(report, "synthetic_accounts_deactivated")
