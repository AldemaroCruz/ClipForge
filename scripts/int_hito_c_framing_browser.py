"""Verify C05 crop preview and immutable exports with a deterministic INT video."""
import secrets
import tempfile
from pathlib import Path

from app.check_presentation import caption_color_stats
from app.media import probe_media
from app.subtitles import to_srt, to_vtt
from scripts import int_hito_b_browser as portal
from scripts.int_hito_c_styles_browser import cleanup


CROP = {
    "upper_left": (0, 0, "#FF0000"),
    "lower_right": (1, 1, "#00FFFF"),
}
ZOOM = 2.2


def crop_controls(page, x, y):
    page.locator("#editorial-framing").select_option("crop")
    for key, value in (("x", x * 100), ("y", y * 100), ("zoom", ZOOM)):
        page.locator("#editorial-crop-" + key).fill(str(value))


def preview_color(page, expected, *, first=False):
    if first:
        page.locator("#editorial-framing-preview").click()
    canvas = page.locator("#editorial-framing-canvas")
    rgb = [int(expected[index:index + 2], 16) for index in (1, 3, 5)]
    page.wait_for_function("""rgb => {
        const c = document.querySelector('#editorial-framing-canvas');
        if (!c || !c.width || !c.height) return false;
        const px = c.getContext('2d').getImageData(c.width >> 1, c.height >> 1, 1, 1).data;
        return rgb.every((expected, i) => Math.abs(expected - px[i]) < 55);
    }""", arg=rgb, timeout=90_000)
    return canvas.evaluate("""c => ({
        dimensions: [c.width, c.height],
        rgb: [...c.getContext('2d').getImageData(c.width >> 1, c.height >> 1, 1, 1).data.slice(0,3)]
    })""")


def save_crop(page, job_id, draft, x, y):
    expected = {"framing": "crop", "crop_x": x, "crop_y": y, "crop_zoom": ZOOM}
    saved = portal.click_response(page, page.locator("#editorial-save"), f'/jobs/{job_id}/drafts/{draft["id"]}',
                                  "PUT", 200, retry_draft_capacity=True).json()
    portal.require(saved["revision"] == draft["revision"] + 1
                   and all(saved["options"][k] == v for k, v in expected.items())
                   and all(saved[k] == draft[k] for k in ("id", "start", "end", "cues"))
                   and all(saved["options"][k] == v for k, v in draft["options"].items() if k not in expected),
                   "crop_save_same_text_range_and_style")
    return saved


def export_bytes(page, export_id, scratch, draft, color):
    row = page.locator(f'#editorial-exports article[data-export-id="{export_id}"]')
    mp4 = row.get_by_role("link", name="Descargar MP4 editado", exact=True)
    mp4.wait_for(timeout=480_000)
    with tempfile.TemporaryDirectory(prefix="clipforge-c05-export-", dir=scratch) as directory:
        files = {ext: Path(directory) / f"clip.{ext}" for ext in ("mp4", "srt", "vtt")}
        for ext, link in (("mp4", mp4), ("srt", row.get_by_role("link", name="Descargar SRT", exact=True)),
                          ("vtt", row.get_by_role("link", name="Descargar VTT", exact=True))):
            portal.save_download(page, link, files[ext])
        video = probe_media(files["mp4"], pilot=True)
        pixels = caption_color_stats(files["mp4"], color)
        portal.require((video["width"], video["height"]) == (1080, 1920)
                       and video["video_codec"] == "h264" and video["audio_codec"] == "aac"
                       and abs(video["duration_seconds"] - (draft["end"] - draft["start"])) < .2,
                       "crop_export_9x16_duration_and_audio")
        portal.require(pixels["matching_pixels"] > 1080 * 480 * .9, "zoom_and_position_export_pixels")
        portal.require(files["srt"].read_text(encoding="utf-8") == to_srt(draft["cues"])
                       and files["vtt"].read_text(encoding="utf-8") == to_vtt(draft["cues"]),
                       "crop_export_same_caption_data")
        return {"pixels": pixels, "dimensions": [1080, 1920], "revision": draft["revision"],
                "files": {ext: portal.digest_of(path) for ext, path in files.items()}}


def framing_flow(browser, args, owner, jobs, report):
    transfer = []
    with portal.browser_page(browser, storage=True, transfer=transfer) as page:
        portal.login(page, owner, args.commit)
        portal.check_normal_permissions(page, report)
        job = portal.upload_video(page, args.video, report, transfer, track_reservation=jobs.append)
        job_id = job["id"]
        portal.open_saved_job(page, job_id)
        portal.open_late_draft(page, job_id, 5, 21, generated=False)
        draft_id = page.locator("#editorial-drafts").input_value()
        portal.require(portal.ID.fullmatch(draft_id), "crop_draft_identity")
        path = f"/jobs/{job_id}/drafts/{draft_id}"
        draft = portal.browser_get(page, path)["body"]
        portal.require(draft["options"]["framing"] == "contain" and draft["cues"], "crop_initial_draft")
        results = report["framing"] = {}
        for index, (case, (x, y, color)) in enumerate(CROP.items()):
            report["step"] = "manual_framing_" + case
            crop_controls(page, x, y)
            preview = preview_color(page, color, first=True)
            box = page.locator("#editorial-framing-box").evaluate(
                """box => ['x','y','width','height'].map(key => Number(box.dataset[key]))""")
            portal.require(preview["dimensions"][0] * 16 == preview["dimensions"][1] * 9
                           and box == [x * 1096, y * 394, 184, 326], "crop_preview_aspect_and_original_overlay")
            draft = save_crop(page, job_id, draft, x, y)
            portal.close_preview(page.locator("#editorial-source"))
            export, _, _ = portal.start_editorial_export(page, job_id, draft)
            encoded = export_bytes(page, export, args.state.parent, draft, color)
            results[case] = {"preview": preview, "box": box, "encoded": encoded, "crop_x": x, "crop_y": y,
                             "zoom": ZOOM, "export": export}
            if index == 0:
                first_draft = draft
        portal.open_saved_job(page, job_id)
        portal.open_editorial(page)
        page.locator("#editorial-drafts").select_option(draft_id)
        page.locator("#editorial-crop-zoom").wait_for()
        portal.require(page.locator("#editorial-framing").input_value() == "crop"
                       and all(float(page.locator("#editorial-crop-" + key).input_value()) == value
                               for key, value in (("x", 100), ("y", 100), ("zoom", ZOOM)))
                       and portal.browser_get(page, path)["body"] == draft, "crop_retained_after_reopen")
        evidence = export_bytes(page, results["upper_left"]["export"], args.state.parent, first_draft, "#FF0000")
        portal.require(evidence == results["upper_left"]["encoded"]
                       and evidence["files"]["mp4"] != results["lower_right"]["encoded"]["files"]["mp4"]
                       and evidence["files"]["srt"] == results["lower_right"]["encoded"]["files"]["srt"],
                       "crop_saved_revision_bound_to_immutable_export")
        report["viewports"] = []
        for width, height, name in ((1280, 900, "desktop"), (390, 844, "mobile")):
            page.set_viewport_size({"width": width, "height": height})
            preview_color(page, "#00FFFF", first=name == "desktop")
            panel = page.locator("#editorial-framing-result")
            portal.require(page.evaluate("() => document.documentElement.scrollWidth") <= width + 1,
                           "crop_responsive_width")
            picture = f"framing-{name}.png"
            panel.screenshot(path=args.report.parent / picture, animations="disabled")
            report["viewports"].append({"viewport": [width, height], "screenshot": picture})
        portal.close_preview(page.locator("#editorial-source"))
        selections = portal.browser_get(page, f"/jobs/{job_id}/selections")
        portal.require(selections["status"] == 200 and selections["body"]["analyses"] == [],
                       "crop_called_editorial_provider")
        portal.check(report, "normal_creator_framing_preview_and_two_approved_renders_match")
        portal.check(report, "reopen_preserves_crop_styles_text_times_and_previous_mp4")
        portal.logout(page)


def acceptance(browser, args, admin, report):
    accounts, jobs = [], []
    report["step"] = "framing_create_synthetic_account"
    try:
        owner = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
        with portal.browser_page(browser) as page:
            portal.login(page, admin, args.commit)
            page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
            created = portal.create_account(page, owner)
            accounts.append(owner)
            portal.require(portal.ID.fullmatch(created["id"]), "framing_synthetic_owner_shape")
            report["synthetic_owners"] = [created["id"]]
            portal.logout(page)
        framing_flow(browser, args, owner, jobs, report)
        report["step"] = "framing_cleanup"
    finally:
        report["synthetic_projects"] = jobs.copy()
        cleanup(browser, args, admin, accounts, jobs, report)
