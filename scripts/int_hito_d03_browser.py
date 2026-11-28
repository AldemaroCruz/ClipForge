"""Protected D03 acceptance with two provider calls on a controlled INT project."""

import hashlib
import json
import re
import secrets
import tempfile
from pathlib import Path
from time import monotonic
from urllib.parse import parse_qs, urlencode, urlsplit
from zipfile import ZIP_STORED, ZipFile

from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture
from scripts import int_hito_c_mixed_zip_browser as mixed
from scripts import int_hito_c_logos_browser as logos
from scripts import int_hito_c_styles_browser as styles
from scripts import int_hito_d01_browser as d01
from scripts import int_hito_d02_browser as d02


THEMES = ("agua de lluvia para el huerto", "freno de la bicicleta")
TOPIC = (
    re.compile(r"lluvia|huerto|plantas|canal[oó]n|dep[oó]sito", re.I),
    re.compile(r"freno|bicicleta|pastilla|llanta|manubrio", re.I),
)
EXPECTED_EXCERPTS = ("depósito de agua de lluvia", "cable del freno")
MANUAL = {
    "title": "Revisá el freno antes de circular",
    "description": "El clip muestra cómo ajustar el cable y revisar las pastillas.",
    "hashtags": ["#Bicicleta", "#Freno"],
}


def cleanup(browser, args, admin, report):
    if not args.state.exists():
        return
    state = fixture.read_state(args.state, prepared=False)
    actors = [state]
    if d01.outsider_path(args).exists():
        actors.append(d01.read_outsider(args))
    job = state["job_id"]
    jobs = [job] if job else []
    if job:
        with portal.browser_page(browser) as page:
            fixture.owned_session(page, state, args.commit)
            if portal.browser_get(page, f"/jobs/{job}")["status"] == 404:
                jobs = []
            portal.logout(page)
    report["synthetic_owners"] = [actor["owner_id"] for actor in actors]
    report["synthetic_projects"] = [job] if job else []
    styles.cleanup(browser, args, admin, [actor["account"] for actor in actors], jobs, report)
    report["synthetic_projects_logically_deleted"] += bool(job and not jobs)


def publication_path(job, suffix=""):
    return f"/jobs/{job}/publication" + suffix


def publication(page, job, clip):
    path = publication_path(job) + "?" + urlencode({"selection": clip["token"]})
    data = d01.get_json(page, path)
    portal.require(data["selection"] == clip["token"] and portal.SHA256.fullmatch(data["content_sha256"]),
                   "d03_publication_bound_to_current_export")
    return data


def card(page, clip):
    if clip["kind"] == "automatic":
        return page.locator(f'#clip-list [data-clip-file="{clip["clip"]}"]')
    section = "mvp-results" if clip["kind"] == "manual" else "editorial-exports"
    return page.locator(f'#{section} article[data-export-id="{clip["identity"]}"]')


def open_panel(page, clip):
    card(page, clip).get_by_role("button", name="Preparar textos para publicar", exact=True).click()
    page.locator("#publication-dialog").wait_for()
    page.locator("#publication-title").wait_for()
    return page.locator("#publication-dialog")


def close_panel(page):
    page.locator("#publication-close").click()
    page.locator("#publication-dialog").wait_for(state="hidden")


def fill_manual(page, fields):
    for key in ("title", "description"):
        page.locator("#publication-" + key).fill(fields[key])
    page.locator("#publication-hashtags").fill(" ".join(fields["hashtags"]))


def save_manual(page, job, clip, fields, previous=0, *, suggestion_id=None):
    fill_manual(page, fields)
    result = portal.click_response(page, page.locator("#publication-save"), publication_path(job), "PUT", 200)
    payload = result.request.post_data_json
    portal.require(payload["selection"] == clip["token"] and payload["revision"] == previous
                   and payload.get("suggestion_id") == suggestion_id
                   and all(payload[key] == fields[key] for key in ("title", "description", "hashtags")),
                   "d03_save_manual_posts_exact_fields_and_expected_version")
    return result


def require_saved(state, fields, revision):
    item = state["saved"]
    portal.require(item is not None and item["revision"] == revision
                   and all(item[key] == fields[key] for key in ("title", "description", "hashtags")),
                   "d03_exact_saved_publication_revision")
    return item


def start_suggestion(page, job, clip, theme):
    root = publication_path(job)
    page.locator("#publication-language").fill("es")
    page.locator("#publication-instructions").fill(
        "No incluyas cifras, nombres propios, direcciones, enlaces ni llamados a la acción."
    )
    generate = page.locator("#publication-generate")
    preview = portal.click_response(page, page.locator("#publication-preview"), root + "/preview", "POST", 200).json()
    data = preview["payload_text"]
    contents = json.dumps(data, ensure_ascii=False).casefold()
    confirmed = publication(page, job, clip)
    portal.require(preview["provider"]["provider"] == "openai"
                   and "api.openai.com" in preview["provider"]["destination"]
                   and preview["selection"] == clip["token"] and preview["content_sha256"] == confirmed["content_sha256"]
                   and confirmed["suggestion"] is None
                   and preview["language"] == "es" and preview["budget"]["provider_calls"] == 1
                   and data["prior_title"] == confirmed["target"]["title"]
                   and data["context_source"] == confirmed["target"]["context_source"]
                   and all(0 <= cue["start"] < cue["end"] <= confirmed["target"]["end"] - confirmed["target"]["start"]
                           for cue in data["clip_text"])
                   and EXPECTED_EXCERPTS[theme] in contents and not TOPIC[1 - theme].search(contents),
                   "d03_preview_contains_only_authorized_clip_content")
    consent = page.locator("#publication-consent")
    consent.wait_for()
    portal.require(generate.is_disabled() and not consent.is_checked()
                   and "api.openai.com" in page.locator("#publication-destination").inner_text()
                   and json.loads(page.locator("#publication-payload").text_content()) == data,
                   "d03_visible_selection_and_consent_before_provider_request")
    consent.check()
    begin = monotonic()
    sent = portal.click_response(page, generate, root + "/suggestions", "POST", 202)
    item = sent.json()
    body = sent.request.post_data_json
    portal.require(portal.ID.fullmatch(item["id"]) and item["status"] in {"queued", "running"}
                   and body["selection"] == clip["token"] and body["preview_token"] == preview["preview_token"]
                   and body["consent"] is True and item["provider_calls_planned"] == 1,
                   "d03_explicit_request_receipt_and_one_reservation")
    return item, body, begin


def wait_suggestion(page, job, clip, initial, begin, model, theme, report):
    while True:
        state = publication(page, job, clip)
        item = state["suggestion"]
        portal.require(item is not None and item["id"] == initial["id"], "d03_same_suggestion_remains_selected")
        status = item["status"]
        if status == "completed":
            break
        if status == "failed":
            error = item.get("error_code", "")
            raise portal.BrowserAcceptanceError(error if re.fullmatch(r"AI_[A-Z_]{1,40}", error)
                                                else "d03_provider_failed")
        portal.require(status in {"queued", "running"} and monotonic() - begin < 360, "d03_provider_timeout")
        page.wait_for_timeout(2000)
    evidence = {key: item[key] for key in ("id", "titles", "description", "hashtags", "language", "provider", "model",
                                           "provider_calls_planned", "provider_calls", "provider_responses",
                                           "provider_models_received")}
    evidence.update(theme=THEMES[theme], token=clip["token"], content_sha256=state["content_sha256"],
                    elapsed_seconds=round(monotonic() - begin, 3))
    report["suggestions"].append(evidence)
    report["usage"] = {label: sum(row[key] for row in report["suggestions"]) for label, key in (
        ("reservations", "provider_calls_planned"), ("calls", "provider_calls"), ("responses", "provider_responses"),
    )}
    text = " ".join([*item["titles"], item["description"], *item["hashtags"]])
    portal.require(1 <= len(item["titles"]) <= 3 and item["description"] and 1 <= len(item["hashtags"]) <= 8
                   and TOPIC[theme].search(text) and not TOPIC[1 - theme].search(text)
                   and not re.search(r"https?://|www\.|\d", text)
                   and item["provider"] == "openai" and item["model"] == model and item["language"] == "es"
                   and item["provider_calls_planned"] == item["provider_calls"] == item["provider_responses"] == 1
                   and item["provider_models_received"] and all(portal.MODEL.fullmatch(value)
                                                                 for value in item["provider_models_received"]),
                   "d03_real_grounded_suggestions_for_the_exact_clip")
    return state, item


def replay_suggestion(page, job, clip, body, completed):
    path = publication_path(job, "/suggestions")
    for replay in (body, {**body, "request_id": secrets.token_hex(16)}):
        result = d02.browser_post_json(page, path, replay)
        portal.require(result["status"] == 202 and result["body"]["id"] == completed["id"]
                       and result["body"]["provider_calls_planned"] == 1, "d03_replay_does_not_duplicate_reservations")
    portal.require(publication(page, job, clip)["suggestion"] == completed, "d03_replay_preserves_original_receipt")


def choose_suggestion(page, job, clip, item):
    titles = page.locator("#publication-suggestions button[data-publication-title-option]")
    titles.first.wait_for()
    portal.require(titles.count() == len(item["titles"]), "d03_ui_renders_all_provider_title_options")
    index = len(item["titles"]) - 1
    titles.nth(index).click()
    page.locator("#publication-use-description").click()
    page.locator("#publication-use-hashtags").click()
    portal.require(page.locator("#publication-title").input_value() == item["titles"][index]
                   and page.locator("#publication-description").input_value() == item["description"],
                   "d03_suggestions_apply_only_by_creator_action")
    fields = {"title": item["titles"][index][:104].rstrip() + " · Clip",
              "description": "Un depósito recoge agua de lluvia para regar el huerto.",
              "hashtags": ["#Huerto", "#AguaDeLluvia"]}
    save_manual(page, job, clip, fields, suggestion_id=item["id"])
    return require_saved(publication(page, job, clip), fields, 1)


def direct_text(page, clip, saved, scratch):
    path = scratch / f'{clip["stem"]}-publicacion.txt'
    download = page.locator("#publication-download")
    download.wait_for()
    notice = page.locator("#publication-saved")
    portal.require(str(saved["revision"]) in notice.inner_text(), "d03_ui_displays_saved_publication_revision")
    name = portal.save_download(page, download, path)
    raw = path.read_bytes()
    text = raw.decode("utf-8")
    tags = " ".join(saved["hashtags"])
    expected = f"Título\n{saved['title']}\n\nDescripción\n{saved['description']}\n\nHashtags\n{tags}\n"
    portal.require(name == "publicacion.txt" and text == expected,
                   "d03_individual_publication_file_contains_exact_utf8_saved_fields")
    return {"bytes": len(raw), "sha256": portal.digest_of(path), "raw": raw}


def verify_copy(page, saved):
    page.context.grant_permissions(["clipboard-read", "clipboard-write"], origin=portal.PUBLIC)
    for key in ("title", "description", "hashtags"):
        page.locator("#publication-copy-" + key).click()
        expected = " ".join(saved[key]) if key == "hashtags" else saved[key]
        page.wait_for_function("text => navigator.clipboard.readText().then(value => text === value)", arg=expected)


def save_before_suggestion_is_shown(page, job, clip):
    item, body, begin = start_suggestion(page, job, clip, 1)
    pending_reads = []
    path = publication_path(job)
    query = re.compile(r"^" + re.escape(portal.PUBLIC + path) + r"\?selection=.*$")

    def hold_status_read(route):
        if (route.request.method == "GET"
                and parse_qs(urlsplit(route.request.url).query).get("selection") == [clip["token"]]):
            pending_reads.append(True)
            # Keep the browser on the real, accepted queue receipt until the manual save completes.
            route.fulfill(status=200, json={"suggestion": item})
        else:
            route.fallback()

    page.route(query, hold_status_read)
    try:
        deadline = monotonic() + 6
        while not pending_reads and monotonic() < deadline:
            page.wait_for_timeout(100)
        portal.require(bool(pending_reads), "d03_in_flight_suggestion_status_observed_before_manual_save")
        save_manual(page, job, clip, MANUAL)
    finally:
        page.unroute(query, hold_status_read)
    return item, body, begin


def select_clip_in_zip(page, clip, *, texts=False):
    target = card(page, clip)
    if clip["kind"] == "automatic":
        number = int(clip["clip"][5:7])
        target.get_by_role("checkbox", name=f"Incluir Clip {number} en ZIP", exact=True).check()
    else:
        target.locator(f'input[type=checkbox][data-archive-id="{clip["identity"]}"]').check()
    if texts:
        target.locator("input[data-publication-zip]").check()


def package(page, job, clips, saved, scratch, evidence):
    path = f"/jobs/{job}/clips.zip"
    args = []
    expected = {}
    for clip in clips:
        record = saved.get(clip["token"])
        args.append(("selection", clip["token"]))
        folder = clip["stem"] + "/" if record else ""
        expected.update({f'{folder}{clip["stem"]}.{kind}': item for kind, item in clip["files"].items()})
        if record:
            args.append(("publication", f'{clip["token"]}~{record["revision"]}'))
            expected[folder + "publicacion.txt"] = record["file"]
        select_clip_in_zip(page, clip, texts=bool(record))
    button = page.get_by_role("button", name="Descargar ZIP de clips seleccionados", exact=True)
    button.locator("..").screenshot(path=evidence / "d03-mixed-zip.png", animations="disabled")
    destination = scratch / "d03-selected.zip"

    def inspecting(response):
        url = urlsplit(response.url)
        return url.path == path and parse_qs(url.query).get("inspect") == ["1"]

    with page.expect_response(inspecting, timeout=120000) as pending:
        name = portal.save_download(page, button, destination)
    response = pending.value
    requested = parse_qs(urlsplit(response.url).query)
    declared = parse_qs(urlencode(args))
    summary = response.json()
    portal.require(response.status == 200 and name.endswith(".zip")
                   and sorted(requested.get("selection", ())) == sorted(declared["selection"])
                   and sorted(requested.get("publication", ())) == sorted(declared["publication"])
                   and summary["clips"] == len(clips) and summary["bytes"] == sum(item["bytes"] for item in expected.values()),
                   "d03_mixed_zip_preflight_pins_exact_media_and_saved_texts")
    with ZipFile(destination) as zipped:
        members = zipped.namelist()
        portal.require(len(members) == len(expected) + 1 and set(members) == {"manifest.json", *expected},
                       "d03_mixed_zip_has_expected_folders_and_unchanged_media_members")
        with zipped.open("manifest.json") as stream:
            raw_manifest = stream.read(65537)
        portal.require(len(raw_manifest) <= 65536, "d03_zip_manifest_bounded")
        bundle = json.loads(raw_manifest)
        automatic = {entry["clip"]: entry for entry in bundle["clips"]}
        exported = {entry["export_id"]: entry for entry in bundle["exports"]}
        portal.require(len(automatic) + len(exported) == len(clips), "d03_zip_manifest_variant_count")
        for clip in clips:
            record = saved.get(clip["token"])
            revision = record["revision"] if record else None
            if clip["kind"] == "automatic":
                entry = automatic[clip["clip"]]
                portal.require(entry["caption_revision"] == clip["revision"] and entry["output_id"] == clip["output_id"],
                               "d03_zip_automatic_receipt_pinned")
            else:
                entry = exported[clip["identity"]]
                portal.require(entry["revision"] == clip["revision"] and entry["kind"] == clip["kind"],
                               "d03_zip_export_receipt_pinned")
            portal.require(entry.get("publication_revision") == revision, "d03_zip_manifest_pins_publication_revision")
        rows = [file for entry in list(automatic.values()) + list(exported.values()) for file in entry["files"]]
        advertised = {row["file"]: {key: row[key] for key in ("bytes", "sha256")} for row in rows}
        portal.require(len(rows) == len(expected) and advertised == {
            name: {key: data[key] for key in ("bytes", "sha256")} for name, data in expected.items()
        }, "d03_zip_manifest_agrees_with_exact_individual_downloads")
        for name, receipt in expected.items():
            member = zipped.getinfo(name)
            with zipped.open(member) as stream:
                portal.require(member.compress_type == ZIP_STORED and member.file_size == receipt["bytes"]
                               and hashlib.file_digest(stream, "sha256").hexdigest() == receipt["sha256"],
                               "d03_zip_files_match_individual_downloads_byte_for_byte")
            if "raw" in receipt:
                portal.require(zipped.read(member) == receipt["raw"], "d03_zip_publication_matches_utf8_bytes")
    return {"bytes": destination.stat().st_size, "sha256": portal.digest_of(destination), "members": len(expected),
            "media_variants": len(clips), "publication_revisions": declared["publication"]}


def new_manual_export(page, job, scratch):
    interval = (26, 34)
    panel = logos.open_panel(page, "#mvp-editor-details")
    panel.locator("#mvp-start").fill(str(interval[0]))
    panel.locator("#mvp-end").fill(str(interval[1]))
    sent = portal.click_response(page, panel.locator("#mvp-export"), f"/jobs/{job}/editor/exports", "POST", 202)
    export = sent.json()
    portal.require(portal.ID.fullmatch(export["id"]) and (export["start"], export["end"]) == interval,
                   "d03_manual_export_interval_differs_from_automatic")
    return mixed.exported(page, job, export["id"], "manual", scratch, interval)


def new_transcript_export(page, job, automatic, scratch):
    d02.open_transcript(page)
    source = d02.version(d02.list_transcript(page, job), "segments")
    d02.select_version(page, source)
    first = next(row for row in source["segments"] if row["start"] == 1142)
    last = next(row for row in source["segments"] if row["end"] == 1181)
    d02.mark(page, first, last, keyboard=True)
    draft = d02.create_draft(page, job, source, first, last)
    before = portal.read_caption(page, job, automatic["clip"])
    portal.require((draft["start"], draft["end"], draft["cues"]) == (1142, 1181, before["cues"]),
                   "d03_d02_variant_preserves_exact_source_interval_and_subtitle_text")
    page.locator("#editorial-burn").check()
    page.locator("#editorial-color-hex").fill("#FFFF00")
    saved = fixture.save_draft_color(page, job, draft["id"], "#FFFF00")
    export_id, _, _ = portal.start_editorial_export(page, job, saved)
    clip = mixed.exported(page, job, export_id, "editorial", scratch, (1142, 1181), draft["cues"])
    portal.require(clip["files"]["mp4"]["sha256"] != automatic["files"]["mp4"]["sha256"],
                   "d03_visual_change_different_mp4_same_text_and_interval")
    return clip


def new_editorial_export(page, job, scratch):
    interval = (35, 43)
    portal.open_late_draft(page, job, *interval, generated=False)
    picker = page.locator("#editorial-drafts")
    page.wait_for_function("() => /^[a-f0-9]{32}$/.test(document.querySelector('#editorial-drafts')?.value)"
                           " && document.querySelector('#editorial-export')?.disabled === false")
    draft = d01.get_json(page, f"/jobs/{job}/drafts/{picker.input_value()}")
    portal.require((draft["start"], draft["end"]) == interval and draft["cues"],
                   "d03_editorial_draft_uses_existing_transcript")
    identity, _, _ = portal.start_editorial_export(page, job, draft)
    return mixed.exported(page, job, identity, "editorial", scratch, interval, draft["cues"])


def empty_target(page, job, clip, kind):
    data = publication(page, job, clip)
    portal.require(data["target"]["kind"] == kind and data["target"]["has_content"] is True
                   and data["saved"] is None and data["suggestion"] is None,
                   "d03_new_variant_has_correct_origin_and_no_automatic_ai")
    return data


def use_visual_reuse(page, job, automatic, visual, saved):
    before = publication(page, job, automatic)
    current = empty_target(page, job, visual, "transcript")
    portal.require(before["content_sha256"] == current["content_sha256"]
                   and any(item["selection"] == automatic["token"] and item["revision"] == saved["revision"]
                           for item in current["reusable"]), "d03_visual_variant_can_reuse_exact_prior_text_revision")
    open_panel(page, visual)
    button = page.locator(f'#publication-reusable-options button[data-publication-reuse="{automatic["token"]}"]')
    result = portal.click_response(page, button, publication_path(job, "/reuse"), "POST", 200)
    request = result.request.post_data_json
    portal.require(request["selection"] == visual["token"] and request["source_selection"] == automatic["token"]
                   and request["source_revision"] == saved["revision"], "d03_reuse_ui_pins_previous_text_revision")
    after = publication(page, job, visual)
    preserved = publication(page, job, automatic)
    portal.require(after["suggestion"] is None and require_saved(after, saved, 1)["language"] == saved["language"]
                   and after["saved"]["reused_from"]["selection"] == automatic["token"]
                   and after["saved"]["reused_from"]["revision"] == saved["revision"]
                   and all(preserved[key] == before[key] for key in ("saved", "suggestion", "target", "content_sha256")),
                   "d03_visual_reuse_preserves_text_without_provider")
    close_panel(page)
    return after["saved"]


def reopen_saved(page, scratch, job, clip, saved):
    open_panel(page, clip)
    require_saved(publication(page, job, clip), saved, saved["revision"])
    portal.require(all(page.locator("#publication-" + key).input_value() == saved[key]
                       for key in ("title", "description", "language"))
                   and page.locator("#publication-hashtags").input_value().split() == saved["hashtags"],
                   "d03_reopened_saved_texts_and_language")
    verify_copy(page, saved)
    generated = direct_text(page, clip, saved, scratch)
    close_panel(page)
    return {"revision": saved["revision"], "file": generated}


def stale_zip(page, job, clip, previous_revision):
    path = f"/jobs/{job}/clips.zip?" + urlencode({"selection": clip["token"],
                                                  "publication": f'{clip["token"]}~{previous_revision}',
                                                  "inspect": "1"})
    portal.require(portal.browser_get(page, path)["status"] == 409, "d03_stale_publication_revision_rejected_before_zip")


def outsider_check(browser, args, outsider, job, clip, request, saved):
    root = publication_path(job)
    query = "?" + urlencode({"selection": clip["token"]})
    file_query = "?" + urlencode({"selection": clip["token"], "revision": saved["revision"]})
    with portal.browser_page(browser) as page:
        fixture.owned_session(page, outsider, args.commit)
        for endpoint in (root, root + query, root + "/file" + file_query):
            portal.require(portal.browser_get(page, endpoint)["status"] == 404, "d03_other_account_cannot_read_publication")
        response = d02.browser_post_json(page, root + "/suggestions", request)
        portal.require(response["status"] == 404, "d03_other_account_cannot_request_suggestions")
        update = {key: saved[key] for key in ("revision", "language", "title", "description", "hashtags")}
        status = page.evaluate("""async ([path, body]) => {
            const auth = window.ClipForgeAuth;
            const options = auth.payload(body);
            options.method = 'PUT';
            return (await auth.fetch(path, options)).status;
        }""", [root, {**update, "selection": clip["token"]}])
        portal.require(status == 404, "d03_other_account_cannot_edit_publication_texts")
        portal.logout(page)


def accept_primary(page, job, automatic, model, report):
    early, late = automatic
    report["step"] = "d03_early_clip_consent_and_suggestions"
    for clip, bounds in zip(automatic, ((26, 62), (1142, 1181)), strict=True):
        target = empty_target(page, job, clip, "automatic")["target"]
        portal.require((target["start"], target["end"]) == bounds and target["title_source"] == "automatic_title"
                       and target["context_source"] in {"subtitles", "transcript"},
                       "d03_exact_source_times_and_context_provenance")
    open_panel(page, early)
    portal.require("Título del clip automático" in page.locator("#publication-target").inner_text(),
                   "d03_initial_title_provenance_visible")
    initial, request, begin = start_suggestion(page, job, early, 0)
    _, generated = wait_suggestion(page, job, early, initial, begin, model, 0, report)
    replay_suggestion(page, job, early, request, generated)
    accepted = choose_suggestion(page, job, early, generated)
    revised = {"title": accepted["title"], "description": accepted["description"] + " El agua se aprovecha entre lluvias.",
               "hashtags": accepted["hashtags"]}
    save_manual(page, job, early, revised, accepted["revision"], suggestion_id=generated["id"])
    current = require_saved(publication(page, job, early), revised, accepted["revision"] + 1)
    close_panel(page)
    stale_zip(page, job, early, accepted["revision"])
    portal.check(report, "d03_selected_title_fields_and_revision_bound_to_early_clip")

    report["step"] = "d03_manual_save_while_late_suggestion_pending_at_browser"
    open_panel(page, late)
    initial, request, begin = save_before_suggestion_is_shown(page, job, late)
    state, generated = wait_suggestion(page, job, late, initial, begin, model, 1, report)
    replay_suggestion(page, job, late, request, generated)
    chosen = require_saved(state, MANUAL, 1)
    page.locator("#publication-suggestions").wait_for(timeout=30000)
    portal.require(chosen.get("suggestion_id") is None and
                   page.locator("#publication-title").input_value() == chosen["title"],
                   "d03_later_suggestion_never_overwrites_manual_fields")
    report["manual_before_late_result"] = {"manual_revision": chosen["revision"], "suggestion_id": generated["id"],
                                          "browser_queued_receipt_retained_until_manual_save": True,
                                          "manual_saved_at": chosen.get("saved_at"),
                                          "provider_completed_at": generated.get("completed_at"),
                                          "worker_completed_after_manual_save":
                                              generated["completed_at"] >= chosen["saved_at"]}
    close_panel(page)
    portal.check(report, "d03_distinct_grounded_results_and_manual_revision_survives_late_delivery")
    return current, chosen, request


def acceptance(browser, args, admin, report):
    state = fixture.read_state(args.state)
    outsider = d01.outsider_account(browser, args, admin)
    job = state["job_id"]
    evidence = args.report.parent
    report["synthetic_owners"] = [state["owner_id"], outsider["owner_id"]]
    report["synthetic_projects"] = [job]
    report["suggestions"] = []
    with tempfile.TemporaryDirectory(prefix="d03-browser-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        with portal.browser_page(browser) as page:
            page.set_viewport_size({"width": 1280, "height": 900})
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            project = portal.open_saved_job(page, job)
            portal.require([clip["file"] for clip in project["clips"]] == ["clip_01.mp4", "clip_02.mp4"],
                           "d03_two_same_project_synthetic_topic_clips")
            config = d01.get_json(page, "/ai/config")
            portal.require(config["provider"] == "openai" and config["configured"] and config["daily_limit"] == 100
                           and config["model"] == args.editorial_model, "d03_effective_shared_quota_and_model")
            report["daily_limit_utc"] = config["daily_limit"]
            original_cues = {clip["file"]: portal.read_caption(page, job, clip["file"]) for clip in project["clips"]}
            automatic = [mixed.automatic(page, job, clip, scratch) for clip in project["clips"]]
            early, late, request = accept_primary(page, job, automatic, args.editorial_model, report)
            portal.require(report["usage"] == {"reservations": 2, "calls": 2, "responses": 2},
                           "d03_two_exact_real_reservations_and_responses")

            report["step"] = "d03_manual_editorial_and_transcript_origins"
            manual = new_manual_export(page, job, scratch)
            different = empty_target(page, job, manual, "manual")
            original = publication(page, job, automatic[0])
            portal.require(different["content_sha256"] != original["content_sha256"]
                           and different["reusable"] == [] and original["saved"] == early,
                           "d03_changed_interval_requires_own_texts_and_preserves_previous_variant")
            open_panel(page, manual)
            page.locator("#publication-language").fill("en")
            fields = {"title": "Rainwater for the garden", "description": "A collection tank below the roof gutter.",
                      "hashtags": ["#Rainwater", "#Garden"]}
            save_manual(page, job, manual, fields)
            manual_saved = require_saved(publication(page, job, manual), fields, 1)
            portal.require(manual_saved["language"] == "en", "d03_manual_text_language_changes_independently_of_media")
            close_panel(page)
            editorial = new_editorial_export(page, job, scratch)
            empty_target(page, job, editorial, "editorial")
            open_panel(page, editorial)
            portal.require(not page.locator("#publication-download").is_visible(), "d03_export_has_no_implicit_publication")
            close_panel(page)
            transcript = new_transcript_export(page, job, automatic[1], scratch)
            transcript_saved = use_visual_reuse(page, job, automatic[1], transcript, late)
            portal.check(report, "d03_manual_editorial_transcript_and_visual_reuse_without_new_provider")

            report["step"] = "d03_relogin_copy_and_individual_publication_files"
            portal.logout(page)
            fixture.owned_session(page, state, args.commit)
            portal.open_saved_job(page, job)
            portal.open_editorial(page)
            logos.open_panel(page, "#mvp-editor-details")
            stored = {}
            for index, (clip, receipt) in enumerate(((automatic[0], early), (automatic[1], late),
                                                     (manual, manual_saved), (transcript, transcript_saved))):
                if index == 0:
                    open_panel(page, clip)
                    page.locator("#publication-dialog").screenshot(path=evidence / "d03-desktop.png", animations="disabled")
                    close_panel(page)
                if index == 1:
                    page.set_viewport_size({"width": 390, "height": 844})
                    dialog = open_panel(page, clip)
                    portal.require(dialog.evaluate("el => el.getBoundingClientRect().right <= innerWidth + 1"
                                                   " && el.scrollWidth <= el.clientWidth + 1"),
                                   "d03_publication_editor_fits_narrow_viewport")
                    dialog.screenshot(path=evidence / "d03-narrow.png", animations="disabled")
                    close_panel(page)
                stored[clip["token"]] = reopen_saved(page, scratch, job, clip, receipt)
                if index == 1:
                    page.set_viewport_size({"width": 1280, "height": 900})
            portal.check(report, "d03_saved_exact_revision_reopened_copied_and_downloaded")
            outsider_check(browser, args, outsider, job, automatic[1], request, late)

            report["step"] = "d03_mixed_zip_and_project_deletion"
            report["package"] = package(page, job, [*automatic, manual, editorial, transcript], stored, scratch, evidence)
            portal.require(all(portal.read_caption(page, job, file) == before for file, before in original_cues.items()),
                           "d03_existing_automatic_media_and_captions_intact")
            for clip, expected in zip(automatic, report["suggestions"], strict=True):
                result = publication(page, job, clip)["suggestion"]
                portal.require(result["id"] == expected["id"] and result["provider_calls"] == 1,
                               "d03_panel_save_copy_download_and_zip_create_no_editorial_calls")
            portal.require(d01.get_json(page, f"/jobs/{job}/selections")["analyses"] == [],
                           "d03_package_does_not_repeat_editorial_search_or_whisper")
            portal.check(report, "d03_mixed_zip_pins_utf8_texts_and_original_media_byte_for_byte")
            root = publication_path(job)
            query = "?" + urlencode({"selection": automatic[1]["token"]})
            portal.require(portal.browser_post(page, f"/jobs/{job}/deletion", {})["status"] == 202
                           and portal.browser_get(page, root + query)["status"] == 404
                           and d02.browser_post_json(page, root + "/suggestions", request)["status"] == 404,
                           "d03_deleted_project_cannot_get_or_request_publication_texts")
            portal.check(report, "d03_project_ownership_and_deleted_project_gates")
            portal.logout(page)
