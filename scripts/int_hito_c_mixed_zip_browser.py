"""Check that mixed ZIP downloads bind to the individually downloaded INT variants."""

import hashlib
import json
import re
import tempfile
from pathlib import Path
from urllib.parse import parse_qs, urlencode, urlsplit
from zipfile import ZIP_STORED, ZipFile

from app.media import probe_media
from app.subtitles import to_srt, to_vtt
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture


MANUAL_RANGE = (15, 21)
EDITORIAL_TITLE = "Variante editorial para ZIP"
EXPORT_TOKEN = re.compile(r"export:([a-f0-9]{32}):([1-9][0-9]{0,9})")
FILE_TYPES = {"mp4", "srt", "vtt"}


def zip_url(job_id, tokens, *, inspect=False):
    query = [("selection", token) for token in tokens]
    if inspect:
        query.append(("inspect", "1"))
    return f"/jobs/{job_id}/clips.zip?{urlencode(query)}"


def individual_files(page, card, target, links, duration, expected_cues=None):
    files = {}
    paths = {}
    for kind, route in links.items():
        link = card.locator(f'a[href="{route}"]')
        path = target.with_suffix("." + kind)
        if kind == "srt" and expected_cues is None:
            # A manual fragment with no cues can have an empty, valid SRT.
            with page.expect_download(timeout=120_000) as event:
                link.click()
            download = event.value
            try:
                download.save_as(path)
                portal.require(path.stat().st_size <= portal.MAX_CLIP_BYTES, "mixed_zip_manual_srt_size")
            finally:
                download.delete()
        else:
            portal.save_download(page, link, path)
        files[kind] = {"bytes": path.stat().st_size, "sha256": portal.digest_of(path)}
        paths[kind] = path
    media = probe_media(paths["mp4"], pilot=True)
    portal.require(media["video_codec"] == "h264" and media["audio_codec"] == "aac"
                   and abs(media["duration_seconds"] - duration) < .2, "mixed_zip_downloaded_correct_video")
    if expected_cues is not None:
        portal.require(paths["srt"].read_text(encoding="utf-8") == to_srt(expected_cues)
                       and paths["vtt"].read_text(encoding="utf-8") == to_vtt(expected_cues),
                       "mixed_zip_downloaded_correct_caption_sidecars")
    return files


def automatic(page, job_id, clip, scratch):
    filename = clip["file"]
    state = portal.read_caption(page, job_id, filename)
    output = state["output"]
    portal.require(state["status"] == "completed" and len(output["id"]) in {32, 64},
                   "mixed_zip_automatic_variant_ready")
    card = page.locator(f'#clip-list [data-clip-file="{filename}"]')
    links = {kind: output[kind] for kind in sorted(FILE_TYPES)}
    portal.require(all(links.values()), "mixed_zip_automatic_original_has_sidecars")
    stem = Path(filename).stem
    files = individual_files(page, card, scratch / stem, links, state["duration"], state["cues"])
    token = f'{filename}:{state["revision"]}:{output["id"]}'
    return {"kind": "automatic", "token": token, "stem": stem, "files": files,
            "revision": state["revision"], "output_id": output["id"], "clip": filename}


def manual_export(page, job_id):
    panel = page.locator("#mvp-editor-details")
    if panel.get_attribute("open") is None:
        panel.locator("summary").click()
    start, end = MANUAL_RANGE
    page.locator("#mvp-start").fill(str(start))
    page.locator("#mvp-end").fill(str(end))
    sent = portal.click_response(page, page.locator("#mvp-export"), f"/jobs/{job_id}/editor/exports", "POST", 202)
    item = sent.json()
    portal.require(portal.ID.fullmatch(item["id"]) and (item["start"], item["end"]) == MANUAL_RANGE,
                   "mixed_zip_manual_source_range")
    return item["id"]


def editorial_export(page, job_id):
    portal.open_late_draft(page, job_id, *fixture.FRAGMENT, generated=False)
    page.wait_for_function("() => /^[a-f0-9]{32}$/.test(document.querySelector('#editorial-drafts')?.value)")
    draft_id = page.locator("#editorial-drafts").input_value()
    fixture.manual_cues(page)
    page.locator("#editorial-title").fill(EDITORIAL_TITLE)
    page.locator("#editorial-color-hex").fill(fixture.BLUE.lower())
    page.locator("#editorial-burn").check()
    draft = fixture.save_draft_color(page, job_id, draft_id, fixture.BLUE)
    export_id, _, _ = portal.start_editorial_export(page, job_id, draft)
    return export_id, draft


def exported(page, job_id, identity, kind, scratch, expected_range, cues=None):
    section = "mvp-results" if kind == "manual" else "editorial-exports"
    card = page.locator(f'#{section} article[data-export-id="{identity}"]')
    checkbox = card.locator(f'input[type=checkbox][data-archive-id="{identity}"]')
    checkbox.wait_for(timeout=480_000)
    listed = portal.browser_get(page, f"/jobs/{job_id}/exports")
    portal.require(listed["status"] == 200, "mixed_zip_export_list_readback")
    owned = [item for item in listed["body"]["exports"] if item["id"] == identity]
    portal.require(len(owned) == 1, "mixed_zip_export_identity")
    item = owned[0]
    token = EXPORT_TOKEN.fullmatch(item["archive_selection"])
    kinds = item["archive_files"]
    portal.require(token is not None and token.group(1) == identity and item["status"] == "completed"
                   and (item["start"], item["end"]) == expected_range and type(kinds) is list
                   and len(set(kinds)) == len(kinds) and "mp4" in kinds and set(kinds) <= FILE_TYPES,
                   "mixed_zip_export_version_and_downloadable_files")
    if cues is not None:
        portal.require(set(kinds) == FILE_TYPES and item["cues"] == cues,
                       "mixed_zip_editorial_cues_available")
    stem = f"{kind}_{identity}"
    root = f"/jobs/{job_id}/exports/{identity}/files"
    links = {extension: f"{root}/clip.{extension}" for extension in kinds}
    files = individual_files(page, card, scratch / stem, links, expected_range[1] - expected_range[0], cues)
    return {"kind": kind, "token": token.group(), "identity": identity, "stem": stem, "files": files,
            "revision": int(token.group(2))}


def download_bundle(page, job_id, selections, destination, screenshot):
    automatic_clip, manual_clip, editorial_clip = selections
    automatic_name = "Incluir Clip " + str(int(automatic_clip["clip"][5:7])) + " en ZIP"
    page.get_by_role("checkbox", name=automatic_name, exact=True).check()
    for export in (manual_clip, editorial_clip):
        page.locator(f'input[type=checkbox][data-archive-id="{export["identity"]}"]').check()
    button = page.get_by_role("button", name="Descargar ZIP de clips seleccionados", exact=True)
    button.locator("..").screenshot(path=screenshot, animations="disabled")
    path = f"/jobs/{job_id}/clips.zip"

    def preflight(response):
        url = urlsplit(response.url)
        return url.path == path and parse_qs(url.query).get("inspect") == ["1"]

    with page.expect_response(preflight, timeout=120_000) as request:
        name = portal.save_download(page, button, destination)
    response = request.value
    submitted = parse_qs(urlsplit(response.url).query)
    portal.require(response.status == 200 and response.request.method == "GET" and name.endswith(".zip")
                   and sorted(submitted["selection"]) == sorted(item["token"] for item in selections),
                   "mixed_zip_ui_submitted_the_exact_three_variants")
    summary = response.json()
    portal.require(summary["clips"] == 3 and summary["bytes"] ==
                   sum(item["bytes"] for selection in selections for item in selection["files"].values()),
                   "mixed_zip_preflight_counts_exact_files")


def verify_bundle(path, selections):
    automatic_clip, manual_clip, editorial_clip = selections
    expected = {f'{item["stem"]}.{kind}': data for item in selections for kind, data in item["files"].items()}
    with ZipFile(path) as bundle:
        names = bundle.namelist()
        portal.require(len(names) == len(expected) + 1 and set(names) == {"manifest.json", *expected},
                       "mixed_zip_keeps_only_exact_selected_artifacts")
        with bundle.open("manifest.json") as content:
            raw = content.read(65_537)
        portal.require(len(raw) <= 65_536, "mixed_zip_manifest_size")
        manifest = json.loads(raw)
        auto = manifest["clips"]
        exports = manifest["exports"]
        portal.require(len(auto) == 1 and auto[0]["clip"] == automatic_clip["clip"]
                       and auto[0]["caption_revision"] == automatic_clip["revision"]
                       and auto[0]["output_id"] == automatic_clip["output_id"], "mixed_zip_legacy_clip_provenance")
        expected_exports = {(item["kind"], item["identity"], item["revision"])
                            for item in (manual_clip, editorial_clip)}
        portal.require(len(exports) == 2
                       and {(item["kind"], item["export_id"], item["revision"]) for item in exports} == expected_exports,
                       "mixed_zip_manual_and_editorial_version_provenance")
        rows = [record for entry in auto + exports for record in entry["files"]]
        declared = {row["file"]: {key: row[key] for key in ("bytes", "sha256")} for row in rows}
        portal.require(len(rows) == len(expected) and declared == expected,
                       "mixed_zip_manifest_matches_individual_file_bytes_and_digests")
        for name, original in expected.items():
            entry = bundle.getinfo(name)
            portal.require(entry.compress_type == ZIP_STORED and entry.file_size == original["bytes"],
                           "mixed_zip_member_matches_individual_size")
            with bundle.open(entry) as content:
                portal.require(hashlib.file_digest(content, "sha256").hexdigest() == original["sha256"],
                               "mixed_zip_member_matches_individual_sha256")
    return {"bytes": path.stat().st_size, "sha256": portal.digest_of(path), "members": len(expected),
            "clips": len(selections), "versions": [
                {"kind": item["kind"], "revision": item["revision"], "files": item["files"]}
                for item in selections
            ]}


def acceptance(browser, args, _admin, report):
    state = fixture.read_state(args.state)
    job_id = state["job_id"]
    report["synthetic_owners"] = [state["owner_id"]]
    report["synthetic_projects"] = [job_id]
    with tempfile.TemporaryDirectory(prefix="caption-mixed-zip-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        with portal.browser_page(browser) as page:
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            job = portal.open_saved_job(page, job_id)
            portal.require(len(job["clips"]) == 2 and job["clips"][0]["file"] == "clip_01.mp4",
                           "mixed_zip_two_seeded_automatic_clips")
            report["step"] = "mixed_zip_known_automatic_version"
            auto = automatic(page, job_id, job["clips"][0], scratch)
            report["step"] = "mixed_zip_render_manual_fragment"
            manual = exported(page, job_id, manual_export(page, job_id), "manual", scratch, MANUAL_RANGE)
            report["step"] = "mixed_zip_render_editorial_draft"
            identity, draft = editorial_export(page, job_id)
            edited = exported(page, job_id, identity, "editorial", scratch, fixture.FRAGMENT, draft["cues"])
            report["step"] = "mixed_zip_compare_real_downloads"
            selections = [auto, manual, edited]
            destination = scratch / "selected.zip"
            screenshot = args.report.parent / "mixed-zip-selection.png"
            download_bundle(page, job_id, selections, destination, screenshot)
            report["package"] = verify_bundle(destination, selections)
            report["package"]["screenshot"] = screenshot.name
            portal.check(report, "automatic_manual_editorial_zip_matches_individual_downloads_byte_for_byte")
            report["step"] = "mixed_zip_stale_and_duplicate_selection"
            stale = f'export:{manual["identity"]}:{manual["revision"] + 1}'
            portal.require(portal.browser_get(page, zip_url(job_id, [auto["token"], stale], inspect=True))["status"] == 409
                           and portal.browser_get(page, zip_url(job_id, [edited["token"], edited["token"]],
                                                               inspect=True))["status"] == 422,
                           "mixed_zip_stale_and_duplicate_export_rejected")
            portal.check(report, "mixed_zip_stale_and_duplicate_revisions_rejected")
            analyses = portal.browser_get(page, f"/jobs/{job_id}/selections")
            portal.require(analyses["status"] == 200 and analyses["body"]["analyses"] == [],
                           "mixed_zip_did_not_request_editorial_ai")
            portal.logout(page)
