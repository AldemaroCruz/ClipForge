"""Creator logo acceptance from the public portal using only synthetic accounts."""
from pathlib import Path
import secrets
import struct
from tempfile import TemporaryDirectory
import zlib

from app.check_presentation import caption_color_stats
from app.media import probe_media
from app.render import run_ffmpeg
from app.subtitles import to_srt, to_vtt
from scripts import int_hito_b_browser as portal
from scripts import int_hito_b_deletion_browser as deletion
from scripts import int_hito_c_styles_browser as styles
from scripts.int_hito_c_framing_browser import crop_controls, preview_color
from scripts.int_hito_c_zip_browser import verify_archive


LIBRARY = "/creator-logos"
NAME = "Logo transparente de prueba"
TEMPLATE = "Estilo con logo de prueba"
PLACEMENT = {"position": "top-right", "size": 20, "opacity": 50, "margin": 8}
CAPTION_COLOR = "#FFFF00"
WIDTH, HEIGHT = 1080, 1920


def png(path, color):
    right = bytes((*color, 255)) * 20
    half = bytes((*color, 128)) * 20
    left = bytes((*color, 0)) * 20
    pixels = (b"\0" + left + right) * 40 + (b"\0" + left + half) * 40

    def chunk(kind, data):
        return struct.pack("!I", len(data)) + kind + data + struct.pack("!I", zlib.crc32(kind + data))

    path.write_bytes(b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack("!IIBBBBB", 40, 80, 8, 6, 0, 0, 0))
                     + chunk(b"IDAT", zlib.compress(pixels)) + chunk(b"IEND", b""))


def open_panel(page, selector):
    panel = page.locator(selector)
    if panel.get_attribute("open") is None:
        panel.locator("summary").click()
    return panel


def upload_logo(page, path):
    library = open_panel(page, "#creator-logo-library")
    library.locator("#creator-logo-name").fill(NAME)
    library.locator("#creator-logo-file").set_input_files(str(path))
    portal.click_response(page, library.get_by_role("button", name="Cargar logo", exact=True),
                          LIBRARY + "?", "POST", 201)
    library.get_by_text("Logo guardado.", exact=True).wait_for()
    item = saved_logo(page, library.locator("#creator-logo-library-select").input_value())
    portal.require(portal.ID.fullmatch(item["id"]) and item["revision"] == 1 and item["name"] == NAME
                   and [item["width"], item["height"]] == [40, 80], "logo_uploaded_transparent_png")
    return item


def saved_logo(page, identity):
    library = portal.browser_get(page, LIBRARY)
    portal.require(library["status"] == 200 and portal.ID.fullmatch(identity), "owned_logo_library_available")
    items = [logo for logo in library["body"]["logos"] if logo["id"] == identity]
    portal.require(len(items) == 1, "owned_logo_found_once")
    return items[0]


def set_placement(page, logo):
    controller = open_panel(page, "#clip-caption-logos")
    controller.locator("[data-logo-field=enabled]").check()
    controller.locator("[data-logo-field=select]").select_option(f'{logo["id"]}:{logo["revision"]}')
    controller.locator("[data-logo-field=position]").select_option(PLACEMENT["position"])
    for field in ("size", "opacity", "margin"):
        controller.locator(f"[data-logo-field={field}]").fill(str(PLACEMENT[field]))


def content_digest(page, path):
    return page.evaluate("""async path => {
        const response = await fetch(path, {credentials: 'same-origin', redirect: 'error'});
        if (response.status !== 200) return null;
        const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', await response.arrayBuffer()));
        return [...digest].map(byte => byte.toString(16).padStart(2, '0')).join('');
    }""", path)


def private_library(browser, args, outsider, logo, template):
    with portal.browser_page(browser) as page:
        portal.login(page, outsider, args.commit)
        portal.require(portal.browser_get(page, LIBRARY) == {"status": 200, "body": {"logos": []}}
                       and portal.browser_get(page, logo["url"])["status"] == 404,
                       "foreign_creator_logo_disclosed")
        payload = {key: template[key] for key in ("name", "font", "style", "logo")}
        portal.require(portal.browser_post(page, styles.STYLES, payload)["status"] == 404,
                       "foreign_creator_logo_usable")
        portal.logout(page)


def preview_geometry(page, frame, logo):
    image = frame.locator("img.creator-logo-preview")
    image.wait_for()
    page.wait_for_function("""(url) => [...document.querySelectorAll('img.creator-logo-preview')].some(
        img => !img.hidden && img.getAttribute('src') === url && img.complete && img.naturalWidth === 40)
    """, arg=f'{LIBRARY}/{logo["id"]}/{logo["revision"]}')
    measured = image.evaluate("""img => {
        const image = img.getBoundingClientRect(), frame = img.parentElement.getBoundingClientRect();
        const map = 1080 / frame.width;
        return {dimensions: [frame.width, frame.height], rect: [
            (image.left-frame.left)*map, (image.top-frame.top)*map, image.width*map, image.height*map],
            opacity: Number(getComputedStyle(img).opacity), screen: document.documentElement.scrollWidth};
    }""")
    width, height = measured["dimensions"]
    portal.require(abs(width * 16 / 9 - height) <= 2
                   and all(abs(actual - expected) <= 4 for actual, expected in zip(
                       measured["rect"], [886, 86, 108, 216]))
                   and abs(measured["opacity"] - .5) <= .005, "preview_same_logo_geometry_and_alpha")
    return measured


def frame_pixels(path, scratch, *, screenshot=None):
    pixels = scratch / "decoded.rgb"
    png_frame = ["-update", 1, screenshot] if screenshot else []
    if png_frame:
        run_ffmpeg("-ss", "1", "-i", path, "-frames:v", 1, "-threads", 1, *png_frame)
    run_ffmpeg("-ss", "1", "-i", path, "-frames:v", 1, "-pix_fmt", "rgb24",
               "-f", "rawvideo", "-threads", 1, pixels)
    data = pixels.read_bytes()
    portal.require(len(data) == WIDTH * HEIGHT * 3, "logo_downloaded_frame_dimensions")

    def point(x, y):
        start = (y * WIDTH + x) * 3
        return list(data[start:start + 3])

    # Extent is x=886..993 and y=86..301. The backing video or black
    # letterbox is constant across these points in the accepted fixture.
    background, clear = point(1010, 140), point(910, 140)
    solid, half = point(965, 140), point(965, 250)
    delta = solid[2] - background[2]
    portal.require(max(abs(a-b) for a, b in zip(clear, background)) <= 16
                   and 95 <= delta <= 155 and delta * .30 <= half[2] - background[2] <= delta * .70
                   and max(abs(a-b) for a, b in zip(point(965, 72), background)) <= 16
                   and max(abs(a-b) for a, b in zip(point(965, 310), background)) <= 16,
                   "mp4_logo_position_scale_and_transparency")
    return {"background": background, "transparent": clear, "opaque_region": solid, "half_alpha_region": half}


def download_variant(page, links, expected, cues, duration, scratch, label):
    with TemporaryDirectory(prefix="clipforge-logo-export-", dir=scratch) as directory:
        current = Path(directory)
        files = {}
        for ext, link in links.items():
            portal.require(link.get_attribute("href") == expected[ext], "ui_download_uses_the_visible_variant")
            files[ext] = current / f"clip.{ext}"
            portal.save_download(page, link, files[ext])
        media = probe_media(files["mp4"], pilot=True)
        portal.require((media["width"], media["height"], media["video_codec"], media["audio_codec"])
                       == (WIDTH, HEIGHT, "h264", "aac") and abs(media["duration_seconds"] - duration) < .2,
                       "logo_mp4_preserves_video_profile_and_range")
        portal.require(files["srt"].read_text(encoding="utf-8") == to_srt(cues)
                       and files["vtt"].read_text(encoding="utf-8") == to_vtt(cues), "logo_sidecars_preserved")
        result = frame_pixels(files["mp4"], current, screenshot=scratch / f"logos-{label}-export.png")
        cue = max(cues, key=lambda row: row["end"] - row["start"])
        at = (cue["start"] + cue["end"]) / 2
        captions = caption_color_stats(files["mp4"], CAPTION_COLOR, seconds=at)
        portal.require(captions["matching_pixels"] >= 40, "subtitles_visible_below_logo_in_mp4")
        return {"pixels": result, "caption_pixels": captions["matching_pixels"],
                "files": {ext: portal.digest_of(path) for ext, path in files.items()}}


def clip_export(page, args, job_id, file, before, logo, state):
    portal.require(state.get("logo") == logo and state["cues"] == before
                   and state["output"].get("logo") == logo, "auto_clip_logo_snapshot")
    card = page.locator(f'#clip-list [data-clip-file="{file}"]')
    card_video = card.locator("video")
    output = state["output"]
    page.wait_for_function("""([name, url]) => document.querySelector(
        '#clip-list [data-clip-file="' + name + '"] video')?.getAttribute('src') === url + '?inline=true'
    """, arg=[file, output["mp4"]])
    portal.require(card_video.get_attribute("src") == output["mp4"] + "?inline=true", "auto_logo_preview_variant")
    links = {"mp4": card.get_by_role("link", name="Descargar Clip " + str(int(file[5:7])) + " en MP4 con logo", exact=True),
             "srt": card.locator(f'a[href="{output["srt"]}"]'),
             "vtt": card.locator(f'a[href="{output["vtt"]}"]')}
    checked = download_variant(page, links, output, before, state["duration"], args.report.parent, "caption")
    files = checked["files"]
    archived = verify_archive(page, [(file, state["revision"], output["id"])],
                              {file: {"sha256": files["mp4"], "captions": {
                                  "sidecars": {ext: files[ext] for ext in ("srt", "vtt")}}}},
                              args.state.parent)
    scope = page.locator("#clip-zip-scope").inner_text().lower()
    portal.require("automático" in scope and "logo" in scope and "borradores" in scope,
                   "archive_scope_visible_with_edited_logo_version")
    return checked, archived


def editorial_export(page, args, job_id, template, logo, report):
    with page.expect_response(lambda response: response.request.method == "POST" and response.status == 201
                              and response.url == f"{portal.PUBLIC}/jobs/{job_id}/drafts") as created:
        portal.open_late_draft(page, job_id, 5, 21, generated=False)
    draft_id = created.value.json()["id"]
    page.wait_for_function("""id => document.querySelector('#editorial-drafts')?.value === id
        && document.querySelector('#editorial-save')?.disabled === false""", arg=draft_id)
    path = f"/jobs/{job_id}/drafts/{draft_id}"
    panel = open_panel(page, "#editorial-styles")
    styles.pick(panel, template["id"])
    portal.click_response(page, styles.button(panel, "Aplicar estilo"), f"/jobs/{job_id}/drafts/", "PUT", 200,
                          retry_draft_capacity=True)
    page.locator("#editorial-burn").check()
    page.locator("#editorial-start").fill("6")
    page.locator("#editorial-end").fill("22")
    portal.click_response(page, page.locator("#editorial-apply-range"), f"/jobs/{job_id}/editor/range",
                          "POST", 200, retry_range_capacity=True)
    page.get_by_text("Recorte aplicado. Guarda el borrador para conservarlo.", exact=True).wait_for()
    before = page.locator("#editorial-cues [data-field=text]").first
    before.wait_for()
    words = before.input_value().split()
    portal.require(bool(words), "edited_cut_transcript_available")
    words[0] = "Vecinos" if words[0].casefold() == "huerto" else "Huerto"
    text = " ".join(words)
    before.fill(text)
    page.locator("#editorial-title").fill("Recorte de prueba con logo")
    crop_controls(page, 0, 0)
    preview_color(page, "#FF0000", first=True)
    frame = page.locator("#editorial-framing-composition")
    report["edited_preview"] = preview_geometry(page, frame, logo)
    frame.screenshot(path=args.report.parent / "logos-editorial-preview.png", animations="disabled")
    portal.close_preview(page.locator("#editorial-source"))
    draft = portal.click_response(page, page.locator("#editorial-save"), f"/jobs/{job_id}/drafts/", "PUT", 200,
                                  retry_draft_capacity=True).json()
    portal.require(draft["id"] == draft_id and [draft["start"], draft["end"]] == [6, 22]
                   and draft["cues"][0]["text"] == text and draft.get("logo") == logo
                   and draft["options"]["framing"] == "crop" and draft["options"]["crop_zoom"] == 2.2
                   and draft["options"]["burn_subtitles"] is True,
                   "edited_range_word_style_logo_and_crop_saved")
    export_id, _, _ = portal.start_editorial_export(page, job_id, draft)
    row = page.locator(f'#editorial-exports article[data-export-id="{export_id}"]')
    mp4 = row.get_by_role("link", name="Descargar MP4 con logo", exact=True)
    mp4.wait_for(timeout=480_000)
    root = f"/jobs/{job_id}/exports/{export_id}/files"
    expected = {ext: f"{root}/clip.{ext}" for ext in ("mp4", "srt", "vtt")}
    links = {"mp4": mp4, "srt": row.get_by_role("link", name="Descargar SRT", exact=True),
             "vtt": row.get_by_role("link", name="Descargar VTT", exact=True)}
    video = row.locator("video").get_attribute("src")
    portal.require(video == expected["mp4"] + "?inline=true", "editorial_logo_preview_variant")
    result = download_variant(page, links, expected, draft["cues"], 16, args.report.parent, "editorial")
    background = result["pixels"]["background"]
    portal.require(background[0] >= 190 and max(background[1:]) < 75, "logo_above_expected_red_crop")
    return path, draft, expected["mp4"], result


def creator_flow(browser, args, accounts, jobs, report):
    transfer = []
    with TemporaryDirectory(prefix="clipforge-logos-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        source, replacement = scratch / "logo.png", scratch / "replacement.png"
        png(source, (255, 0, 255))
        png(replacement, (0, 255, 0))
        with portal.browser_page(browser, storage=True, transfer=transfer) as page:
            portal.login(page, accounts[0], args.commit)
            portal.check_normal_permissions(page, report)
            portal.check_feedback_removed(page, report)
            report["step"] = "logo_process_synthetic_video"
            job = portal.upload_video(page, args.video, report, transfer, track_reservation=jobs.append)
            job_id = job["id"]
            portal.open_saved_job(page, job_id)
            clips = [portal.read_caption(page, job_id, item["file"]) for item in job["clips"]]
            file, initial = next((item["file"], clip) for item, clip in zip(job["clips"], clips) if clip["cues"])
            original_url = initial["output"]["mp4"]
            original_bytes = content_digest(page, original_url)
            portal.require(bool(original_bytes), "base_clip_before_branding")

            report["step"] = "logo_upload_and_library_readback"
            asset = upload_logo(page, source)
            logo = {"id": asset["id"], "revision": 1, **PLACEMENT}
            portal.check(report, "transparent_png_uploaded_and_retrieved_from_private_library")
            report["step"] = "logo_original_bytes_owner_readback"
            logo_digest = content_digest(page, asset["url"])
            portal.require(bool(logo_digest), "uploaded_png_retrievable_as_owner")
            report["step"] = "logo_saved_template_and_relogin"
            editor, panel = styles.editor_for(page, file)
            set_placement(page, asset)
            editor.locator("#clip-caption-size").fill("68")
            editor.locator("#clip-caption-color").fill(CAPTION_COLOR.lower())
            editor.locator("#clip-caption-burn").check()
            panel.get_by_role("textbox", name="Nombre del estilo", exact=True).fill(TEMPLATE)
            template = portal.click_response(page, styles.button(panel, "Guardar como estilo nuevo"),
                                             styles.STYLES, "POST", 201).json()
            portal.require(template["logo"] == logo and template["revision"] == 1
                           and template["style"]["subtitle_font_size"] == 68, "template_stores_logo_revision")
            portal.require(portal.read_caption(page, job_id, file) == initial, "upload_or_template_rendered_a_clip")
            portal.logout(page)
            portal.login(page, accounts[0], args.commit)
            portal.open_saved_job(page, job_id)
            portal.require(portal.browser_get(page, f'{styles.STYLES}/{template["id"]}')["body"] == template
                           and content_digest(page, asset["url"]) == logo_digest, "style_and_logo_lost_after_relogin")
            private_library(browser, args, accounts[1], asset, template)
            portal.check(report, "normal_creator_logo_template_relogin_and_cross_account_denial")

            report["step"] = "logo_apply_preview_and_export_automatic"
            editor, panel = styles.editor_for(page, file)
            styles.pick(panel, template["id"])
            caption_path = f"/jobs/{job_id}/clips/{file}/captions"
            applied = portal.click_response(page, styles.button(panel, "Aplicar estilo"), caption_path, "PUT", 202)
            portal.require(applied.request.post_data_json["render"] is False,
                           "logo_style_application_queued_render")
            preview = page.locator("#clip-caption-sample .caption-frame")
            report["viewports"] = []
            for label, width, height in (("desktop", 1280, 900), ("mobile", 390, 844)):
                page.set_viewport_size({"width": width, "height": height})
                sample = preview_geometry(page, preview, logo)
                portal.require(sample["screen"] <= width + 1, "logo_editor_responsive_width")
                filename = f"logos-{label}.png"
                preview.screenshot(path=args.report.parent / filename, animations="disabled")
                report["viewports"].append({"viewport": [width, height], "screenshot": filename, **sample})
            page.set_viewport_size({"width": 1280, "height": 900})
            portal.click_response(page, editor.locator("#clip-caption-save"), caption_path, "PUT", 202)
            state = portal.caption_output(page, job_id, file, initial["output"]["id"])
            report["automatic"], report["automatic_zip"] = clip_export(
                page, args, job_id, file, initial["cues"], logo, state)
            portal.check(report, "automatic_logo_preview_export_and_zip_use_the_same_variant_and_sidecars")

            report["step"] = "logo_apply_preview_and_export_edited_cut"
            draft_path, draft, edited_url, report["edited"] = editorial_export(
                page, args, job_id, template, logo, report)
            portal.check(report, "range_word_style_logo_crop_preview_and_edited_download")

            report["step"] = "logo_replacement_and_retirement_preserve_history"
            library = open_panel(page, "#creator-logo-library")
            library.locator("#creator-logo-library-select").select_option(asset["id"])
            library.locator("#creator-logo-name").fill(NAME)
            library.locator("#creator-logo-file").set_input_files(str(replacement))
            styles.expect_dialog(page, library.locator("#creator-logo-replace"),
                                 f'{LIBRARY}/{asset["id"]}', "PUT", 200)
            library.get_by_text("La nueva revisión del logo está lista para seleccionar.", exact=True).wait_for()
            latest = saved_logo(page, asset["id"])
            latest_digest = content_digest(page, latest["url"])
            portal.require(latest["revision"] == 2 and latest["id"] == asset["id"]
                           and latest_digest and latest_digest != logo_digest,
                           "replacement_advances_exact_png_revision")
            _, message = styles.expect_dialog(page, library.locator("#creator-logo-retire"),
                                              f'{LIBRARY}/{asset["id"]}', "DELETE", 200)
            portal.require(("borrador" in message.lower() or "clip" in message.lower())
                           and portal.browser_get(page, LIBRARY)["body"]["logos"] == [],
                           "retirement_explains_retained_history_and_removes_future_selection")
            template_path = f'{styles.STYLES}/{template["id"]}'
            updated = portal.browser_get(page, template_path)["body"]
            portal.require(updated["revision"] == template["revision"] + 1
                           and updated.get("logo") is None and updated["style"] == template["style"],
                           "retired_logo_removed_from_future_template_applications")
            portal.open_saved_job(page, job_id)
            _, panel = styles.editor_for(page, file)
            styles.pick(panel, template["id"])
            styles.expect_dialog(page, styles.button(panel, "Eliminar estilo"), template_path, "DELETE", 200)
            portal.logout(page)
            portal.login(page, accounts[0], args.commit)
            portal.open_saved_job(page, job_id)
            portal.require(portal.browser_get(page, draft_path)["body"] == draft
                           and portal.read_caption(page, job_id, file) == state
                           and content_digest(page, original_url) == original_bytes
                           and content_digest(page, asset["url"]) == logo_digest
                           and content_digest(page, state["output"]["mp4"]) == report["automatic"]["files"]["mp4"]
                           and content_digest(page, edited_url) == report["edited"]["files"]["mp4"],
                           "logo_or_template_retirement_changed_earlier_draft_or_files")
            portal.require(portal.browser_get(page, f"/jobs/{job_id}/selections")["body"]["analyses"] == [],
                           "logo_flow_contacted_editorial_provider")
            portal.check(report, "retired_logo_and_deleted_template_preserve_drafts_and_mp4_after_relogin")

            report["step"] = "logo_integrated_project_deletion"
            report["removal_seconds"] = deletion.confirm_deletion(page, job_id)
            deletion.check_removed(page, job_id, artifacts=(edited_url.removeprefix(f"/jobs/{job_id}"),))
            portal.check(report, "integrated_job_deleted_while_logo_history_remains_private")
            portal.logout(page)


def acceptance(browser, args, admin, report):
    accounts, jobs = [], []
    report["synthetic_owners"] = []
    report["step"] = "logo_create_synthetic_accounts"
    try:
        with portal.browser_page(browser) as page:
            portal.login(page, admin, args.commit)
            page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
            for _ in range(2):
                account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
                created = portal.create_account(page, account)
                accounts.append(account)
                portal.require(portal.ID.fullmatch(created["id"]), "logo_synthetic_owner_shape")
                report["synthetic_owners"].append(created["id"])
            portal.logout(page)
        creator_flow(browser, args, accounts, jobs, report)
        report["step"] = "logo_cleanup"
    finally:
        report["synthetic_projects"] = jobs.copy()
        styles.cleanup(browser, args, admin, accounts, jobs, report)
