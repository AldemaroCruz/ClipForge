"""Follow caption color from the real INT editors through the downloaded MP4."""

import json
import re
import secrets
import tempfile
from pathlib import Path

from app.check_presentation import caption_color_stats
from app.media import probe_media
from app.render import run_ffmpeg
from app.subtitles import to_srt, to_vtt
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_styles_browser as styles


RED = "#FF0000"
BLUE = "#0000FF"
WHITE = "#FFFFFF"
NATIVE_RGB = {RED: "rgb(255, 0, 0)", BLUE: "rgb(0, 0, 255)", WHITE: "rgb(255, 255, 255)"}
NAME = "Rojo preciso de prueba"
FRAGMENT = (6, 12)


def read_state(path, *, prepared=True):
    state = json.loads(portal.shared_http.read_private(path, 4096))
    portal.require(type(state) is dict and set(state) == {"account", "owner_id", "job_id"},
                   "caption_color_fixture_checkpoint")
    account = portal.shared_http.validate_admin(state["account"])
    portal.require(portal.ACCOUNT.fullmatch(account["username"]) and portal.ID.fullmatch(state["owner_id"])
                   and ((not prepared and state["job_id"] is None)
                        or isinstance(state["job_id"], str) and portal.ID.fullmatch(state["job_id"])),
                   "caption_color_fixture_identity")
    return state


def owned_session(page, state, commit):
    portal.login(page, state["account"], commit)
    active = portal.browser_get(page, "/auth/me")
    portal.require(active["status"] == 200 and active["body"]["user"]["id"] == state["owner_id"]
                   and active["body"]["user"]["is_admin"] is False, "caption_color_owner_session")


def update_checkpoint(path, state):
    portal.shared_http.private_file(path)
    with tempfile.TemporaryDirectory(prefix="caption-color-state-", dir=path.parent) as directory:
        new = Path(directory) / "state.json"
        portal.shared_http.write_new(new, state)
        new.replace(path)


def prepare(browser, args, admin, report):
    """Upload the existing fixture via the portal while holding its process request locally."""
    report["step"] = "caption_color_create_synthetic_owner"
    account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
    with portal.browser_page(browser) as page:
        portal.login(page, admin, args.commit)
        page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
        created = portal.create_account(page, account)
        portal.require(portal.ID.fullmatch(created["id"]), "caption_color_created_owner")
        state = {"account": account, "owner_id": created["id"], "job_id": None}
        portal.shared_http.write_new(args.state, state)
        report["synthetic_owners"] = [state["owner_id"]]
        portal.logout(page)

    report["step"] = "caption_color_reserve_and_upload_without_processing"
    meta = probe_media(args.video, pilot=True)
    portal.require(meta["video_codec"] == "h264" and meta["audio_codec"] == "aac"
                   and 20 <= meta["duration_seconds"] <= 1200, "caption_color_fixture_media")
    transfer, held = [], []
    start_route = re.compile(re.escape(portal.PUBLIC) + r"/beta/uploads/([a-f0-9]{32})/start$")

    def hold_start(route):
        match = start_route.fullmatch(route.request.url)
        if route.request.method != "POST" or not match:
            route.abort()
            return
        held.append(match.group(1))
        route.fulfill(status=409, json={"detail": "Carga preparada para la verificación de color."})

    with portal.browser_page(browser, storage=True, transfer=transfer) as page:
        owned_session(page, state, args.commit)
        page.route(start_route, hold_start)
        page.locator("#upload-video").set_input_files(str(args.video))
        with page.expect_response(lambda item: item.request.method == "POST"
                                  and item.url == portal.PUBLIC + "/beta/uploads") as sent:
            page.locator("#upload-submit").click()
        reserved = sent.value
        portal.require(reserved.status == 201, "caption_color_fixture_reservation")
        state["job_id"] = reserved.json()["id"]
        portal.require(portal.ID.fullmatch(state["job_id"]), "caption_color_fixture_project")
        update_checkpoint(args.state, state)
        report["synthetic_projects"] = [state["job_id"]]
        page.get_by_text("Carga preparada para la verificación de color.", exact=True).wait_for(timeout=360_000)
        job = portal.browser_get(page, "/jobs/" + state["job_id"])
        portal.require(held == [state["job_id"]] and any(status in {200, 201} for status in transfer)
                       and job["status"] == 200 and job["body"]["status"] == "awaiting_upload",
                       "caption_color_fixture_uploaded_without_process_task")
        portal.logout(page)
    report["fixture"] = {"bytes": args.video.stat().st_size, "duration_seconds": meta["duration_seconds"],
                         "sha256": portal.digest_of(args.video), "upload_http_statuses": transfer}
    portal.check(report, "existing_test_video_uploaded_without_enqueuing_transcription")


def open_clip(page, filename):
    card = page.locator(f'#clip-list [data-clip-file="{filename}"]')
    card.get_by_role("button", name="Editar subtítulos", exact=True).click()
    editor = page.locator('#clip-caption-editor[data-mode="full"]')
    editor.locator("#clip-caption-color").wait_for()
    return editor


def sample(page, prefix):
    return page.locator(f"#{prefix}-sample .caption-frame span")


def watch_native(picker):
    picker.evaluate("""element => {
        element.colorAcceptanceEvents = [];
        for (const type of ["click", "input", "change"]) {
          element.addEventListener(type, event => element.colorAcceptanceEvents.push({
            type, value: element.value, trusted: event.isTrusted
          }));
        }
    }""")


def activate_native(page, picker):
    before = picker.input_value()
    picker.click()
    page.keyboard.press("Escape")
    events = picker.evaluate("element => element.colorAcceptanceEvents")
    portal.require(any(event["type"] == "click" and event["trusted"] for event in events)
                   and picker.input_value() == before, "caption_color_native_control_activation")


def observe_color(page, picker, prefix):
    text = sample(page, prefix)
    return {"selector": picker.input_value().upper(), "preview_visible": text.is_visible(),
            "preview_rgb": text.evaluate("element => getComputedStyle(element).color")}


def assert_color(page, prefix, color):
    field = page.locator(f"#{prefix}-color")
    preview = sample(page, prefix)
    page.wait_for_function("""([selector, rgb]) => {
        const text = document.querySelector(selector);
        return text && !text.hidden && getComputedStyle(text).color === rgb;
    }""", arg=[f"#{prefix}-sample .caption-frame span", NATIVE_RGB[color]])
    observed = observe_color(page, field, prefix)
    portal.require(observed == {"selector": color, "preview_visible": True, "preview_rgb": NATIVE_RGB[color]}
                   and page.locator(f"#{prefix}-color-hex").input_value().upper() == color,
                   "caption_color_picker_hex_preview_sync")
    return observed


def baseline(browser, args, _admin, report):
    """Record what the accepted portal does with an explicitly committed color."""
    state = read_state(args.state)
    report["step"] = "legacy_caption_style_and_native_color"
    with portal.browser_page(browser) as page:
        owned_session(page, state, args.commit)
        job = portal.open_saved_job(page, state["job_id"])
        editor = open_clip(page, job["clips"][0]["file"])
        panel = editor.locator("#clip-caption-styles")
        old_save = panel.locator('[data-style-action="create"]')
        old_controls = {"panel_closed": panel.get_attribute("open") is None,
                        "save_visible_while_closed": old_save.is_visible(),
                        "direct_save_visible": editor.locator("#clip-caption-save-style").is_visible()}
        panel.locator("summary").click()
        old_save.wait_for()
        old_controls["save_visible_when_open"] = old_save.is_visible()
        panel.screenshot(path=args.report.parent / "caption-color-before-save.png", animations="disabled")
        picker = editor.locator("#clip-caption-color")
        watch_native(picker)
        old_color = {"before": observe_color(page, picker, "clip-caption")}
        activate_native(page, picker)
        old_color["after_open_and_cancel"] = observe_color(page, picker, "clip-caption")
        editor.locator("#clip-caption-burn").check()
        for color in (RED, BLUE):
            picker.fill(color.lower())
            old_color[color] = observe_color(page, picker, "clip-caption")
        editor.locator("#clip-caption-burn").uncheck()
        old_color["while_burn_unchecked"] = observe_color(page, picker, "clip-caption")
        old_color["events"] = picker.evaluate("element => element.colorAcceptanceEvents")
        report["baseline_observations"] = {"style_controls": old_controls, "color": old_color}
        portal.check(report, "observed_prior_panel_visibility_confirmed_colors_and_burn_preview")
        portal.logout(page)


def save_new_style(page, prefix, name, color):
    shortcut = page.locator(f"#{prefix}-save-style")
    portal.require(shortcut.is_visible() and shortcut.inner_text().strip() == "Guardar como estilo",
                   "caption_save_shortcut_visible")
    shortcut.click()
    panel = page.locator(f"#{prefix}-styles")
    select = panel.locator('[data-style-field="select"]')
    name_field = panel.locator('[data-style-field="name"]')
    portal.require(panel.get_attribute("open") is not None and select.input_value() == "",
                   "caption_save_shortcut_opens_new_style")
    name_field.fill(name)
    sent = portal.click_response(page, panel.locator('[data-style-action="create"]'), styles.STYLES, "POST", 201)
    panel.get_by_text("Estilo guardado.", exact=True).wait_for()
    payload = sent.request.post_data_json
    portal.require(payload["name"] == name and payload["style"]["subtitle_color"] == color,
                   "caption_color_value_sent_in_template")
    identity = select.input_value()
    portal.require(portal.ID.fullmatch(identity) and name in select.locator("option:checked").inner_text(),
                   "new_caption_style_selected_immediately")
    result = portal.browser_get(page, f"{styles.STYLES}/{identity}")
    portal.require(result["status"] == 200 and result["body"]["style"]["subtitle_color"] == color,
                   "caption_color_template_readback")
    return result["body"]


def caption_editor(page, report, scratch, job):
    first, second = job["clips"][:2]
    editor = open_clip(page, first["file"])
    panel = editor.locator("#clip-caption-styles")
    portal.require(panel.get_attribute("open") is None, "caption_fixture_initial_panel_closed")
    picker = editor.locator("#clip-caption-color")
    watch_native(picker)
    activate_native(page, picker)
    burn = editor.locator("#clip-caption-burn")
    burn.uncheck()
    picker.fill(RED.lower())
    observed = assert_color(page, "clip-caption", RED)
    portal.require(not burn.is_checked(), "preview_does_not_toggle_export_option")
    for label, width, height in (("desktop", 1280, 900), ("mobile", 390, 844)):
        page.set_viewport_size({"width": width, "height": height})
        portal.require(editor.locator("#clip-caption-save-style").is_visible()
                       and page.evaluate("() => document.documentElement.scrollWidth") <= width + 1,
                       "caption_style_visible_at_supported_width")
        editor.locator("#clip-caption-advanced").screenshot(
            path=scratch / f"caption-color-{label}.png", animations="disabled")
    template = save_new_style(page, "clip-caption", NAME, RED)
    # Commit a deliberate second color through the real input, then use the HEX
    # field to check the reverse direction and preservation across focus changes.
    picker.fill(BLUE.lower())
    assert_color(page, "clip-caption", BLUE)
    cues = editor.locator("#clip-caption-cues [data-field=text]")
    portal.require(cues.count() >= 2, "caption_fixture_contains_multiple_segments")
    cues.nth(1).focus()
    assert_color(page, "clip-caption", BLUE)
    portal.require(sample(page, "clip-caption").inner_text() == cues.nth(1).input_value(),
                   "caption_color_kept_when_switching_subtitle_segment")
    field = editor.locator("#clip-caption-color-hex")
    field.fill("#GG1122")
    error = editor.locator("#clip-caption-color-error")
    error.wait_for()
    portal.require("seis dígitos hexadecimales" in error.inner_text()
                   and picker.input_value().upper() == BLUE
                   and sample(page, "clip-caption").evaluate("element => getComputedStyle(element).color") == NATIVE_RGB[BLUE],
                   "invalid_hex_explained_without_losing_last_color")
    field.fill(RED.lower())
    error.wait_for(state="hidden")
    assert_color(page, "clip-caption", RED)
    events = picker.evaluate("element => element.colorAcceptanceEvents")
    portal.require(all(any(event["type"] == kind and event["value"].upper() == color for event in events)
                       for color in (RED, BLUE) for kind in ("input", "change")),
                   "caption_color_native_input_and_confirmation_events")
    report["clip_preview"] = {"initial_red": observed, "selector_events": events, "segment_switch": "kept_blue",
                              "new_template_id": template["id"], "invalid_hex_example": "#GG1122"}
    page.set_viewport_size({"width": 1280, "height": 900})
    portal.check(report, "save_visible_desktop_and_mobile_color_synchronized_without_burn")
    portal.check(report, "color_persists_on_segment_change_and_invalid_hex_is_explained")
    return template, second["file"]


def apply_other_clip(page, job_id, name, template):
    before = portal.read_caption(page, job_id, name)
    _, panel = styles.editor_for(page, name)
    styles.pick(panel, template["id"])
    path = f"/jobs/{job_id}/clips/{name}/captions"
    saved = portal.click_response(page, styles.button(panel, "Aplicar estilo"), path, "PUT", 202)
    portal.require(saved.request.post_data_json["render"] is False, "caption_template_did_not_enqueue_export")
    portal.require(saved.json()["style"]["subtitle_color"] == RED, "caption_template_apply_response")
    after = portal.read_caption(page, job_id, name)
    portal.require(after["style_template"] == styles.preset_snapshot(template)
                   and after["style"]["subtitle_color"] == RED
                   and all(after[key] == before[key] for key in ("cues", "start", "end", "duration")),
                   "style_applied_to_other_clip_without_rewriting_text_or_timing")
    assert_color(page, "clip-caption", RED)


def manual_cues(page):
    rows = page.locator("#editorial-cues .editorial-cue")
    portal.require(rows.count() == 0, "caption_fixture_uses_no_new_transcript")
    for index, (start, end, text) in enumerate((
        (0.3, 2.3, "Prueba de color primera"),
        (3.2, 5.7, "Prueba de color segunda"),
    )):
        page.locator("#editorial-add-cue").click()
        row = rows.nth(index)
        row.locator('[data-field="start"]').fill(str(start))
        row.locator('[data-field="end"]').fill(str(end))
        row.locator('[data-field="text"]').fill(text)


def save_draft_color(page, job_id, draft_id, color):
    path = f"/jobs/{job_id}/drafts/{draft_id}"
    response = portal.click_response(page, page.locator("#editorial-save"), path, "PUT", 200,
                                     retry_draft_capacity=True)
    payload = response.request.post_data_json
    portal.require(payload["options"]["subtitle_color"] == color
                   and payload["options"]["burn_subtitles"] is True, "editorial_color_value_sent_to_server")
    saved = response.json()
    result = portal.browser_get(page, path)
    portal.require(result["status"] == 200 and result["body"] == saved and saved["options"]["subtitle_color"] == color,
                   "editorial_color_durable_readback")
    return saved


def download_export(page, job_id, draft, color, scratch, evidence):
    portal.close_preview(page.locator("#editorial-source"))
    export_id, _, _ = portal.start_editorial_export(page, job_id, draft)
    root = f"/jobs/{job_id}/exports/{export_id}/files"
    row = page.locator(f'#editorial-exports article[data-export-id="{export_id}"]')
    mp4 = row.get_by_role("link", name="Descargar MP4 editado", exact=True)
    mp4.wait_for(timeout=480_000)
    with tempfile.TemporaryDirectory(prefix="caption-color-export-", dir=scratch) as directory:
        files = {ext: Path(directory) / f"clip.{ext}" for ext in ("mp4", "srt", "vtt")}
        for ext, link in (("mp4", mp4), ("srt", row.get_by_role("link", name="Descargar SRT", exact=True)),
                          ("vtt", row.get_by_role("link", name="Descargar VTT", exact=True))):
            portal.require(link.get_attribute("href") == f"{root}/clip.{ext}", "caption_color_download_identity")
            portal.save_download(page, link, files[ext])
        media = probe_media(files["mp4"], pilot=True)
        portal.require((media["width"], media["height"], media["video_codec"], media["audio_codec"])
                       == (1080, 1920, "h264", "aac")
                       and abs(media["duration_seconds"] - (draft["end"] - draft["start"])) < .2,
                       "caption_color_mp4_format_and_duration")
        portal.require(files["srt"].read_text(encoding="utf-8") == to_srt(draft["cues"])
                       and files["vtt"].read_text(encoding="utf-8") == to_vtt(draft["cues"]),
                       "caption_color_sidecar_text_and_times")
        cue = draft["cues"][0]
        second = (cue["start"] + cue["end"]) / 2
        other = next(value for value in (RED, BLUE) if value != color)
        expected = caption_color_stats(files["mp4"], color, seconds=second)
        opposite = caption_color_stats(files["mp4"], other, seconds=second)
        portal.require(expected["matching_pixels"] >= 75 and opposite["matching_pixels"] <= 10,
                       "downloaded_mp4_keeps_red_blue_distinct")
        run_ffmpeg("-ss", second, "-i", files["mp4"], "-frames:v", 1, "-threads", 1, "-update", 1, evidence)
        return {"export_id": export_id, "draft_revision": draft["revision"], "cue_sample_seconds": second,
                "matching_pixels": expected["matching_pixels"], "opposite_pixels": opposite["matching_pixels"],
                "files": {ext: portal.digest_of(path) for ext, path in files.items()}, "screenshot": evidence.name}


def editorial_flow(page, state, args, report):
    job_id = state["job_id"]
    portal.open_late_draft(page, job_id, *FRAGMENT, generated=False)
    page.wait_for_function("() => /^[a-f0-9]{32}$/.test(document.querySelector('#editorial-drafts')?.value)")
    draft_id = page.locator("#editorial-drafts").input_value()
    portal.require(portal.ID.fullmatch(draft_id), "caption_color_manual_draft_identity")
    header = page.locator("#editorial-save-style")
    portal.require(header.is_visible(), "editorial_style_shortcut_visible")
    manual_cues(page)
    picker = page.locator("#editorial-color")
    watch_native(picker)
    activate_native(page, picker)
    picker.fill(RED.lower())
    assert_color(page, "editorial", RED)
    page.locator("#editorial-burn").check()
    page.locator("#editorial-size").fill("74")
    red = save_draft_color(page, job_id, draft_id, RED)
    portal.require((red["start"], red["end"]) == FRAGMENT and len(red["cues"]) == 2,
                   "caption_color_manual_same_source_range")
    red_export = download_export(page, job_id, red, RED, args.state.parent,
                                 args.report.parent / "caption-color-red.png")
    page.locator("#editorial-color-hex").fill(BLUE.lower())
    assert_color(page, "editorial", BLUE)
    blue = save_draft_color(page, job_id, draft_id, BLUE)
    portal.require(all(red[key] == blue[key] for key in ("id", "start", "end", "cues"))
                   and blue["revision"] > red["revision"]
                   and {k: v for k, v in red["options"].items() if k != "subtitle_color"}
                   == {k: v for k, v in blue["options"].items() if k != "subtitle_color"},
                   "both_exports_use_identical_fragment_except_caption_color")
    portal.logout(page)
    owned_session(page, state, args.commit)
    portal.open_saved_job(page, job_id)
    portal.open_editorial(page)
    page.locator("#editorial-drafts").select_option(draft_id)
    reopen = portal.browser_get(page, f"/jobs/{job_id}/drafts/{draft_id}")
    portal.require(reopen["status"] == 200 and reopen["body"] == blue, "editorial_draft_keeps_color_after_relogin")
    assert_color(page, "editorial", BLUE)
    blue_export = download_export(page, job_id, blue, BLUE, args.state.parent,
                                  args.report.parent / "caption-color-blue.png")
    portal.require(red_export["files"]["mp4"] != blue_export["files"]["mp4"]
                   and all(red_export["files"][kind] == blue_export["files"][kind] for kind in ("srt", "vtt")),
                   "red_blue_exports_different_pixels_with_the_same_sidecars")
    report["exports"] = {"range": list(FRAGMENT), "red": red_export, "blue": blue_export}
    portal.check(report, "manual_editor_hex_and_native_value_preserved_after_reopen")
    portal.check(report, "two_downloaded_mp4s_show_distinct_caption_colors_with_identical_sidecars")


def acceptance(browser, args, _admin, report):
    state = read_state(args.state)
    job_id = state["job_id"]
    report["synthetic_owners"] = [state["owner_id"]]
    report["synthetic_projects"] = [job_id]
    with portal.browser_page(browser) as page:
        owned_session(page, state, args.commit)
        portal.check_normal_permissions(page, report)
        job = portal.open_saved_job(page, job_id)
        portal.require(len(job["clips"]) == 2 and all(portal.CLIP.fullmatch(item["file"]) for item in job["clips"]),
                       "caption_color_exact_synthetic_fixture_clips")
        report["step"] = "caption_color_save_template_and_synchronize_controls"
        template, other = caption_editor(page, report, args.report.parent, job)
        portal.logout(page)
        owned_session(page, state, args.commit)
        portal.open_saved_job(page, job_id)
        report["step"] = "caption_color_recover_and_apply_saved_template"
        library = portal.browser_get(page, styles.STYLES)
        portal.require(library["status"] == 200 and template in library["body"]["styles"],
                       "stored_red_template_recovered_after_relogin")
        apply_other_clip(page, job_id, other, template)
        portal.check(report, "template_recovered_and_applied_to_another_clip_with_cues_unchanged")
        report["step"] = "caption_color_manual_draft_and_two_mp4s"
        editorial_flow(page, state, args, report)
        analyses = portal.browser_get(page, f"/jobs/{job_id}/selections")
        portal.require(analyses["status"] == 200 and analyses["body"]["analyses"] == [],
                       "caption_color_did_not_request_editorial_ai")
        portal.check(report, "focused_color_acceptance_without_ia")
        portal.logout(page)


def cleanup(browser, args, admin, report):
    if not args.state.exists():
        return
    state = read_state(args.state, prepared=False)
    jobs = [state["job_id"]] if state["job_id"] else []
    report["synthetic_owners"] = [state["owner_id"]]
    report["synthetic_projects"] = jobs
    styles.cleanup(browser, args, admin, [state["account"]], jobs, report)
