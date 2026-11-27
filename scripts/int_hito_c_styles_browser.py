"""Focused C04 acceptance using synthetic projects and normal accounts on INT."""
import math
import secrets

from scripts import int_hito_b_browser as portal


STYLES = "/caption-styles"
FONT = "DejaVu Sans Bold"
NAME = "Estilo de prueba C04"
APPEARANCE = {
    "subtitle_font_size": 76, "subtitle_color": "#FF0000",
    "subtitle_position": "bottom", "subtitle_outline": 8,
}


def editor_for(page, filename):
    card = page.locator(f'#clip-list [data-clip-file="{filename}"]')
    card.get_by_role("button", name="Editar subtítulos", exact=True).click()
    editor = page.locator('#clip-caption-editor[data-mode="full"]')
    panel = editor.locator("#clip-caption-styles")
    panel.get_by_text("Estilos guardados", exact=True).wait_for()
    if panel.get_attribute("open") is None:
        panel.locator("summary").click()
    page.wait_for_function("() => document.querySelector('#clip-caption-styles-select')?.disabled === false")
    return editor, panel


def button(panel, label):
    return panel.get_by_role("button", name=label, exact=True)


def pick(panel, style_id):
    select = panel.get_by_role("combobox", name="Estilo guardado", exact=True)
    select.select_option(style_id)
    return select


def expect_dialog(page, control, path, method, status):
    messages = []

    def accept(dialog):
        messages.append(dialog.message)
        dialog.accept()

    page.on("dialog", accept)
    try:
        response = portal.click_response(page, control, path, method, status)
    finally:
        page.remove_listener("dialog", accept)
    portal.require(len(messages) == 1, "style_confirmation_missing")
    return response, messages[0]


def preset_snapshot(template):
    return {key: template[key] for key in ("id", "revision", "font")}


def require_appearance(state, template):
    portal.require(state["style_template"] == preset_snapshot(template)
                   and all(state["style"][key] == value for key, value in template["style"].items()),
                   "caption_style_snapshot")


def inspect_preview(page, editor, panel, scratch, template):
    preview = editor.get_by_role("region", name="Vista previa del subtítulo", exact=True)
    frame = preview.locator(".caption-frame")
    preview.get_by_role("heading", name="Vista previa del subtítulo", exact=True).wait_for()
    fields = editor.get_by_role("textbox", name="Texto del subtítulo", exact=True)
    fields.first.focus()
    portal.require(frame.locator("span").text_content() == fields.first.input_value(),
                   "preset_preview_current_cue")
    sizes = []
    for width, height, label in ((1280, 900, "desktop"), (390, 844, "mobile")):
        page.set_viewport_size({"width": width, "height": height})
        sample = frame.evaluate("""async frame => {
           const text = frame.firstElementChild;
           await document.fonts.load('700 16px "ClipForge Caption"');
           const rect = frame.getBoundingClientRect();
           const css = getComputedStyle(text);
           return {width: rect.width, height: rect.height, font: css.fontFamily, color: css.color,
                   size: parseFloat(css.fontSize), stroke: parseFloat(css.webkitTextStrokeWidth),
                   bottom: parseFloat(css.bottom), pageWidth: document.documentElement.scrollWidth};
        }""")
        portal.require(sample["color"] == "rgb(255, 0, 0)" and "ClipForge Caption" in sample["font"]
                       and sample["height"] > 0 and sample["pageWidth"] <= width + 1
                       and math.isclose(sample["width"] / sample["height"], 1080 / 1920, abs_tol=.001)
                       and math.isclose(sample["size"] / sample["height"], 76 * 2048 / 2384 / 1920, abs_tol=.0001)
                       and math.isclose(sample["stroke"] / sample["width"], 16 / 1080, abs_tol=.0001)
                       and math.isclose(sample["bottom"] / sample["height"],
                                        template["style"]["subtitle_margin_v"] / 1920, abs_tol=.0001),
                       "preset_viewport_appearance")
        filename = f"styles-{label}.png"
        panel.screenshot(path=scratch / filename, animations="disabled")
        sizes.append({"viewport": [width, height], "frame": [sample["width"], sample["height"]],
                      "screenshot": filename})
    page.set_viewport_size({"width": 1280, "height": 900})
    return sizes


def deny_other_creator(browser, account, commit, template):
    path = f'{STYLES}/{template["id"]}'
    with portal.browser_page(browser) as page:
        portal.login(page, account, commit)
        listing = portal.browser_get(page, STYLES)
        portal.require(listing["status"] == 200 and listing["body"]["styles"] == [],
                       "style_leaked_in_other_creator_list")
        portal.require(portal.browser_get(page, path)["status"] == 404, "style_leaked_to_other_creator")
        seen = page.evaluate("""async ({path, revision, font, style}) => {
            const auth = window.ClipForgeAuth;
            const update = {...auth.payload({name: 'No autorizado', revision, font, style}), method: 'PUT'};
            const a = await auth.fetch(path, update);
            const b = await auth.fetch(path + '?revision=' + revision, {method: 'DELETE'});
            return [a.status, b.status];
        }""", {"path": path, **preset_snapshot(template), "style": template["style"]})
        portal.require(seen == [404, 404], "style_other_creator_mutation")
        portal.logout(page)


def cleanup(browser, args, admin, accounts, jobs, report):
    deleted = 0
    try:
        if jobs:
            with portal.browser_page(browser) as page:
                portal.login(page, accounts[0], args.commit)
                for job_id in jobs:
                    path = "/jobs/" + job_id
                    if (portal.browser_post(page, path + "/deletion", {})["status"] == 202
                            and portal.browser_get(page, path)["status"] == 404):
                        deleted += 1
                portal.logout(page)
    finally:
        report["synthetic_projects_logically_deleted"] = deleted
        if accounts:
            with portal.browser_page(browser) as page:
                portal.login(page, admin, args.commit)
                portal.deactivate_accounts(page, accounts)
                portal.logout(page)
        report["synthetic_accounts_deactivated"] = len(accounts)
    portal.require(deleted == len(jobs), "style_acceptance_project_cleanup")


def creator_flow(browser, args, accounts, jobs, report):
    owner, other = accounts
    transfer = []
    with portal.browser_page(browser, storage=True, transfer=transfer) as page:
        portal.login(page, owner, args.commit)
        portal.check_normal_permissions(page, report)
        portal.check_feedback_removed(page, report)
        config = portal.browser_get(page, "/ai/config")
        portal.require(config["status"] == 200 and config["body"]["provider"] == "openai"
                       and config["body"]["model"] == args.editorial_model
                       and config["body"]["configured"] is True and config["body"]["daily_limit"] == 100,
                       "style_acceptance_editorial_config")
        job = portal.upload_video(page, args.video, report, transfer, track_reservation=jobs.append)
        job_id = job["id"]
        portal.open_saved_job(page, job_id)
        files = [item["file"] for item in job["clips"]]
        portal.require(len(files) >= 2 and all(portal.CLIP.fullmatch(file) for file in files),
                       "style_acceptance_two_source_clips")
        original_clips = {file: portal.read_caption(page, job_id, file) for file in files}
        file = next((name for name in files if original_clips[name]["cues"]), None)
        portal.require(file is not None, "style_acceptance_clip_has_cues")
        report["step"] = "style_create"
        editor, panel = editor_for(page, file)
        editor.locator("#clip-caption-size").fill("76")
        editor.locator("#clip-caption-color").fill("#ff0000")
        editor.locator("#clip-caption-position").select_option("bottom")
        editor.locator("#clip-caption-edge").fill("8")
        panel.get_by_role("textbox", name="Nombre del estilo", exact=True).fill(NAME)
        template = portal.click_response(page, button(panel, "Guardar como estilo nuevo"), STYLES, "POST", 201).json()
        portal.require(portal.ID.fullmatch(template["id"]) and template["revision"] == 1
                       and template["name"] == NAME and template["font"] == FONT
                       and all(template["style"][key] == value for key, value in APPEARANCE.items()),
                       "preset_created_values")
        portal.require(portal.read_caption(page, job_id, file) == original_clips[file], "preset_create_changed_clip")
        portal.logout(page)
        portal.login(page, owner, args.commit)
        portal.open_saved_job(page, job_id)
        editor, panel = editor_for(page, file)
        pick(panel, template["id"])
        portal.require(portal.browser_get(page, f'{STYLES}/{template["id"]}')["body"] == template,
                       "preset_lost_after_relogin")
        portal.check(report, "normal_creator_style_persisted_after_relogin")
        deny_other_creator(browser, other, args.commit, template)
        portal.check(report, "normal_other_creator_cannot_list_same_style_or_read_mutate_it")

        report["step"] = "style_set_default"
        portal.click_response(page, button(panel, "Usar en trabajos nuevos"), STYLES + "/default", "PUT", 200)
        portal.require(portal.browser_get(page, f'{STYLES}/{template["id"]}')["body"]["is_default"] is True,
                       "preset_default_not_saved")
        path = f"/jobs/{job_id}/clips/{file}/captions"
        report["step"] = "style_apply_single_without_render"
        applied = portal.click_response(page, button(panel, "Aplicar estilo"), path, "PUT", 202)
        portal.require(applied.request.post_data_json["render"] is False, "preset_single_queued_render")
        single = portal.read_caption(page, job_id, file)
        require_appearance(single, template)
        portal.require(single["cues"] == original_clips[file]["cues"]
                       and single["status"] == "draft"
                       and all(portal.read_caption(page, job_id, name) == original_clips[name] for name in files if name != file),
                       "preset_single_changed_other_clips_or_rendered")
        report["viewports"] = inspect_preview(page, editor, panel, args.report.parent, template)
        portal.check(report, "style_preview_matches_saved_values_desktop_and_mobile")

        report["step"] = "style_apply_project"
        applied, message = expect_dialog(page, button(panel, "Aplicar estilo a todos"),
                                         f"/jobs/{job_id}/captions", "PUT", 202)
        portal.require("reemplaz" in message.lower() and str(len(files)) in message
                       and applied.request.post_data_json["render"] is False,
                       "project_style_scope_or_unexpected_render")
        for name in files:
            state = portal.read_caption(page, job_id, name)
            require_appearance(state, template)
            portal.require(state["cues"] == original_clips[name]["cues"]
                           and state["status"] == "draft", "project_style_changed_cues_or_rendered")
        portal.check(report, "confirmed_project_style_applied_to_all_preserving_each_cue")

        report["step"] = "style_export"
        portal.click_response(page, editor.locator("#clip-caption-save"), path, "PUT", 202)
        exported = portal.caption_output(page, job_id, file, original_clips[file]["output"]["id"])
        require_appearance(exported, template)
        rendered = portal.read_caption_variant(page, job_id, file, exported, args.state.parent)
        portal.require(rendered["color"] == APPEARANCE["subtitle_color"]
                       and rendered["size"] == APPEARANCE["subtitle_font_size"]
                       and rendered["position"] == APPEARANCE["subtitle_position"], "style_render_appearance")
        report["export"] = rendered
        portal.check(report, "style_in_export_and_caption_sidecars")

        report["step"] = "style_default_on_new_work"
        page.goto(portal.PUBLIC + "/", wait_until="domcontentloaded")
        transfer.clear()
        default_report = {"checks": []}
        new_job = portal.upload_video(page, args.video, default_report, transfer, existing_projects=(job_id,),
                                      track_reservation=jobs.append)
        require_appearance(new_job["caption_style"], template)
        require_appearance(portal.read_caption(page, new_job["id"], new_job["clips"][0]["file"]), template)
        portal.check(report, "default_style_snapshotted_on_new_work_and_render")

        report["step"] = "style_update_and_delete"
        portal.open_saved_job(page, job_id)
        editor, panel = editor_for(page, file)
        pick(panel, template["id"])
        editor.locator("#clip-caption-size").fill("65")
        panel.get_by_role("textbox", name="Nombre del estilo", exact=True).fill(NAME + " revisado")
        template_path = f'{STYLES}/{template["id"]}'
        updated = portal.click_response(page, button(panel, "Actualizar con los ajustes del editor"),
                                        template_path, "PUT", 200).json()
        portal.require(updated["revision"] == template["revision"] + 1 and updated["name"] == NAME + " revisado"
                       and updated["style"]["subtitle_font_size"] == 65, "preset_revision_not_updated")
        expect_dialog(page, button(panel, "Eliminar estilo"), template_path, "DELETE", 200)
        listing = portal.browser_get(page, STYLES)
        portal.require(listing["status"] == 200 and listing["body"]["styles"] == [], "deleted_template_still_visible")
        persisted = portal.read_caption(page, job_id, file)
        portal.require(persisted == exported and portal.read_caption_variant(
            page, job_id, file, persisted, args.state.parent) == rendered, "preset_change_modified_previous_export")
        require_appearance(portal.browser_get(page, f'/jobs/{new_job["id"]}')["body"]["caption_style"], template)
        final_job = portal.browser_get(page, "/jobs/" + job_id)["body"]
        portal.require(all(final_job[key] == job[key] for key in ("media", "analysis_seconds", "speech_until_seconds"))
                       and [(clip["file"], clip["start"], clip["end"]) for clip in final_job["clips"]]
                       == [(clip["file"], clip["start"], clip["end"]) for clip in job["clips"]],
                       "style_changed_source_or_clip_boundaries")
        portal.check(report, "template_update_and_delete_preserve_applied_values_and_export_bytes")
        portal.logout(page)


def acceptance(browser, args, admin, report):
    accounts, jobs = [], []
    report["synthetic_owners"] = []
    report["step"] = "style_create_synthetic_accounts"
    try:
        with portal.browser_page(browser) as page:
            portal.login(page, admin, args.commit)
            page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
            for _ in range(2):
                account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
                created = portal.create_account(page, account)
                accounts.append(account)
                portal.require(portal.ID.fullmatch(created["id"]), "style_synthetic_owner_shape")
                report["synthetic_owners"].append(created["id"])
            portal.logout(page)
        creator_flow(browser, args, accounts, jobs, report)
        report["step"] = "style_cleanup"
    finally:
        report["synthetic_projects"] = jobs.copy()
        cleanup(browser, args, admin, accounts, jobs, report)
