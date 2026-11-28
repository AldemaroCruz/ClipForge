"""Focused public INT acceptance for topic search with a synthetic source."""

import hashlib
import json
import re
import secrets
import tempfile
from pathlib import Path
from time import monotonic
from urllib.parse import parse_qs, urlsplit
from zipfile import ZIP_STORED, ZipFile

from app.check_presentation import caption_color_stats
from app.media import probe_media
from app.render import run_ffmpeg
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture
from scripts import int_hito_c_logos_browser as logos
from scripts import int_hito_c_mixed_zip_browser as mixed
from scripts import int_hito_c_styles_browser as styles
from scripts.int_hito_c_framing_browser import ZOOM


EARLY = "recolección de agua de lluvia para el huerto"
LATE = "reparar el freno de una bicicleta"
ABSENT = "cómo observar ballenas jorobadas desde una embarcación"
INSTRUCTIONS = "Evitá introducciones, promociones y pasajes ajenos al tema."
WINDOWS = {
    EARLY: (24, 64, re.compile(r"agua de lluvia|huerto|depósito|recolección de lluvia", re.I)),
    LATE: (1140, 1184, re.compile(r"freno|bicicleta|pastillas", re.I)),
}
COLOR = "#FFFF00"
TITLE = "Trabajo con el freno de la bicicleta"
USAGE_KEYS = ("reservations", "calls", "responses")
REPLAY_FIELDS = {"source_commit", "run_id", "search_id", "report_sha256", "video_sha256",
                 "transcript_sha256", "model", "range_id", "evidence_segment"}


def prepare(browser, args, admin, report):
    portal.require(args.video.name == "topic.mp4", "d01_fixture_path")
    fixture.prepare(browser, args, admin, report)
    portal.require(1199.8 <= report["fixture"]["duration_seconds"] <= 1200, "d01_fixture_twenty_minutes")
    report["fixture"]["content"] = "synthetic_spoken_topics"
    portal.check(report, "d01_long_synthetic_original_uploaded_without_whisper")


def outsider_path(args):
    return args.state.with_name(args.state.name + ".outsider")


def read_outsider(args):
    state = json.loads(portal.shared_http.read_private(outsider_path(args), 4096))
    portal.require(type(state) is dict and set(state) == {"account", "owner_id"}, "d01_outsider_state")
    account = portal.shared_http.validate_admin(state["account"])
    portal.require(portal.ACCOUNT.fullmatch(account["username"]) and portal.ID.fullmatch(state["owner_id"]),
                   "d01_outsider_identity")
    return state


def outsider_account(browser, args, admin):
    if outsider_path(args).exists():
        return read_outsider(args)
    account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
    with portal.browser_page(browser) as page:
        portal.login(page, admin, args.commit)
        page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
        result = portal.create_account(page, account)
        portal.require(portal.ID.fullmatch(result["id"]), "d01_outsider_created")
        state = {"account": account, "owner_id": result["id"]}
        portal.shared_http.write_new(outsider_path(args), state)
        portal.logout(page)
    return state


def get_json(page, path):
    response = portal.browser_get(page, path)
    portal.require(response["status"] == 200 and isinstance(response["body"], dict), "d01_readback")
    return response["body"]


def history(page, path, expected_ids):
    saved = get_json(page, path)
    items = saved["analyses"]
    portal.require(saved["total"] == len(expected_ids) == len(items)
                   and {item["id"] for item in items} == set(expected_ids), "d01_distinct_persisted_searches")
    return items


def covered_catalog(preview, topic):
    provider_payload = preview["payload_text"]
    batches = provider_payload.get("chunks", [provider_payload])
    segments, catalog = {}, {}
    for batch in batches:
        portal.require(batch["topic"] == topic and batch["instructions"] == INSTRUCTIONS,
                       "d01_consent_covers_topic_and_instructions")
        segments.update((row["id"], row) for row in batch["segments"])
        catalog.update((row["range_id"], row) for row in batch["eligible_ranges"])
    first = preview["analysis_windows"][0]["start"]
    last = preview["analysis_windows"][-1]["end"]
    portal.require(1199.8 <= preview["source_duration"] <= 1200 and first <= .1
                   and last >= preview["source_duration"] - .1 and len(segments) == preview["segment_count"]
                   and preview["budget"]["provider_calls"] == len(batches)
                   and max(row["end"] for row in segments.values()) >= 1180, "d01_full_twenty_minute_coverage")
    for start, end, phrase in WINDOWS.values():
        portal.require(any(segments[row["start_segment"]]["start"] < end
                           and segments[row["end_segment"]]["end"] > start
                           and any(phrase.search(segment["text"]) for segment in segments.values()
                                   if row["start_segment"] <= segment["id"] <= row["end_segment"])
                           for row in catalog.values()), "d01_topic_windows_in_provider_catalog")
    return segments, catalog


def wait_for_analysis(page, path, began, report):
    while True:
        item = get_json(page, path)
        if item["status"] == "completed":
            record_search(report, item)
            return item
        if item["status"] == "failed" or monotonic() - began >= 540:
            record_search(report, item)
            code = item.get("error_code", "")
            raise portal.BrowserAcceptanceError(code if re.fullmatch(r"AI_[A-Z_]{1,40}", code)
                                                else "d01_real_provider_incomplete")
        portal.require(item["status"] in {"queued", "running", "processing"}, "d01_unexpected_search_state")
        page.wait_for_timeout(1500)


def verify_outcome(item, preview, model, topic, segments, catalog):
    candidates = item["candidates"]
    count = preview["budget"]["provider_calls"]
    portal.require(item["spec"]["topic"] == topic and item["spec"]["instructions"] == INSTRUCTIONS
                   and item["provider"] == "openai" and item["model"] == model
                   and item["provider_response_received"] is True
                   and item["provider_calls_planned"] == item["provider_calls"] == item["provider_responses"] == count
                   and item["provider_models_received"]
                   and all(portal.MODEL.fullmatch(name) for name in item["provider_models_received"])
                   and portal.SHA256.fullmatch(item["transcript_sha256"])
                   and item["last_transcript_end"] >= 1180
                   and item["analysis_windows"] == preview["analysis_windows"], "d01_real_provider_and_source_receipt")
    portal.provider_call_intervals(item)
    if topic == ABSENT:
        portal.require(item["outcome"] == "no_matches" and candidates == [], "d01_absent_topic_no_filler_or_retry")
        return
    portal.require(item["outcome"] == "matches" and 1 <= len(candidates) <= 2, "d01_topic_has_relevant_proposals")
    window_start, window_end, phrase = WINDOWS[topic]
    ordered = sorted(candidates, key=lambda candidate: candidate["start"])
    portal.require(len({candidate["range_id"] for candidate in candidates}) == len(candidates)
                   and all(left["end"] <= right["start"] for left, right in zip(ordered, ordered[1:])),
                   "d01_no_duplicate_or_overlapping_proposals")
    for candidate in candidates:
        interval = catalog.get(candidate["range_id"])
        portal.require(interval is not None, "d01_candidate_in_consented_catalog")
        first, last = interval["start_segment"], interval["end_segment"]
        start, end = segments[first]["start"], segments[last]["end"]
        evidence = candidate["evidence"]
        source = segments.get(evidence["segment_id"])
        portal.require(source is not None and first <= evidence["segment_id"] <= last
                       and evidence["start"] == source["start"] and evidence["end"] == source["end"],
                       "d01_evidence_segment_bound_to_range")
        if evidence["truncated"]:
            prefix = evidence["text"].removesuffix("…").rstrip()
            portal.require(bool(prefix) and source["text"].startswith(prefix), "d01_evidence_source_prefix")
        else:
            portal.require(evidence["text"] == source["text"], "d01_exact_source_excerpt")
        portal.require(candidate["start_segment"] == first and candidate["end_segment"] == last
                       and (candidate["start"], candidate["end"]) == (start, end)
                       and 20 <= round(end - start, 3) <= 60
                       and start < window_end and window_start < end and phrase.search(evidence["text"])
                       and bool(candidate["title"]) and bool(candidate["reason"]), "d01_topic_grounded_in_origin")


def search(page, path, topic, model, previous, report):
    theme = page.locator("#editorial-brief")
    theme.fill(topic)
    page.locator("#editorial-guidance").fill(INSTRUCTIONS)
    page.locator("#editorial-max-clips").select_option("2")
    generate = page.locator("#editorial-run")
    portal.require(generate.is_disabled(), "d01_consent_required")
    history(page, path, previous)
    preview = portal.click_response(page, page.locator("#editorial-preview-button"), path + "/preview",
                                    "POST", 200).json()
    portal.require(preview["spec"]["topic"] == topic and preview["spec"]["instructions"] == INSTRUCTIONS
                   and preview["spec"]["max_clips"] == 2 and preview["provider"]["model"] == model
                   and preview["provider"]["provider"] == "openai"
                   and "api.openai.com" in preview["provider"]["destination"], "d01_consent_correct_destination")
    segments, catalog = covered_catalog(preview, topic)
    consent = page.locator("#editorial-consent")
    consent.wait_for()
    portal.require(generate.is_disabled() and not consent.is_checked()
                   and preview["provider"]["destination"] in page.locator("#editorial-destination").inner_text()
                   and json.loads(page.locator("#editorial-payload").text_content()) == preview["payload_text"],
                   "d01_preview_without_authorization")
    history(page, path, previous)
    consent.check()
    began = monotonic()
    sent = portal.click_response(page, generate, path, "POST", 202)
    job_id = path.split("/")[2]
    run_id, request, _ = portal.selection_receipt(sent, job_id, preview["budget"]["provider_calls"], began)
    portal.require(run_id not in previous and request["topic"] == topic and request["instructions"] == INSTRUCTIONS
                   and request["preview_token"] == preview["preview_token"], "d01_explicit_topic_search_submission")
    replay = portal.browser_post(page, path, request)
    other_tab = portal.browser_post(page, path, {**request, "request_id": secrets.token_hex(16)})
    for receipt in (replay, other_tab):
        portal.require(receipt["status"] in {200, 202} and receipt["id"] == run_id,
                       "d01_same_authorization_recovers_same_analysis")
    item = wait_for_analysis(page, f"{path}/{run_id}", began, report)
    verify_outcome(item, preview, model, topic, segments, catalog)
    history(page, path, [*previous, run_id])
    return item, request


def record_search(report, item):
    report["searches"].append({
        "id": item["id"], "topic": item["spec"]["topic"], "instructions": item["spec"]["instructions"],
        "status": item["status"], "outcome": item.get("outcome"), "transcript_sha256": item["transcript_sha256"],
        "provider": item["provider"], "model": item["model"], "models_received": item["provider_models_received"],
        "windows": item["analysis_windows"], "last_transcript_end": item["last_transcript_end"],
        "provider_call_intervals": portal.provider_call_intervals(item),
        "reservations": item["provider_calls_planned"], "calls": item["provider_calls"],
        "responses": item["provider_responses"], "day_utc": item["day_utc"],
        "proposals": [{key: candidate[key] for key in ("range_id", "start", "end", "evidence")}
                      for candidate in item["candidates"]],
    })
    report["usage"] = {key: sum(search[key] for search in report["searches"])
                       for key in ("reservations", "calls", "responses")}


def candidate_card(page, candidate):
    return page.locator(f'#editorial-candidates article[data-range-id="{candidate["range_id"]}"]')


def show_search(page, item):
    runs = page.locator("#editorial-runs")
    option = runs.locator(f'option[value="{item["id"]}"]')
    option.wait_for(state="attached", timeout=30000)
    runs.select_option(item["id"])
    page.wait_for_function("""topic =>
        document.querySelector('#editorial-search-topic')?.textContent.includes(topic)""",
                           arg=item["spec"]["topic"])
    portal.require(INSTRUCTIONS in page.locator("#editorial-search-guidance").inner_text(),
                   "d01_ui_recovers_optional_instructions")
    if item["outcome"] == "no_matches":
        empty = page.locator("#editorial-empty")
        empty.wait_for()
        portal.require("No encontramos momentos suficientemente relacionados con este tema" in empty.inner_text()
                       and page.locator("#editorial-candidates article").count() == 0, "d01_ui_honest_empty_result")
        return
    for candidate in item["candidates"]:
        card = candidate_card(page, candidate)
        card.wait_for()
        portal.require(float(card.get_attribute("data-start")) == candidate["start"]
                       and float(card.get_attribute("data-end")) == candidate["end"]
                       and card.locator("h3").inner_text() == candidate["title"]
                       and card.locator(".editorial-reason p").inner_text() == candidate["reason"]
                       and card.locator(".editorial-evidence blockquote").inner_text() == candidate["evidence"]["text"]
                       and len(re.findall(r"\d{1,2}:\d{2}", card.locator(".editorial-interval").inner_text())) >= 2,
                       "d01_ui_shows_exact_evidence_and_readable_interval")
    portal.require(page.locator("#editorial-candidates article").count() == len(item["candidates"]),
                   "d01_ui_exact_proposals")


def verify_other_creator(browser, args, outsider, path, item, request=None):
    candidate = item["candidates"][0]
    run = f"{path}/{item['id']}"
    with portal.browser_page(browser) as page:
        fixture.owned_session(page, outsider, args.commit)
        for endpoint in (path, run):
            portal.require(portal.browser_get(page, endpoint)["status"] == 404, "d01_owner_only_search_read")
        if request is not None:
            portal.require(portal.browser_post(page, path, request)["status"] == 404,
                           "d01_owner_only_search_writes")
        portal.require(portal.browser_post(page, f"{run}/candidates/{candidate['id']}/draft", {})["status"] == 404,
                       "d01_owner_only_draft_writes")
        portal.logout(page)


def editor_flow(page, job_id, late, scratch, evidence):
    candidate = late["candidates"][0]
    card = candidate_card(page, candidate)
    card.get_by_role("button", name="Reproducir intervalo", exact=True).click()
    page.wait_for_function("""([start, end]) => {
        const video = document.querySelector('#editorial-source');
        return video.videoWidth > 0 && !video.paused && !video.seeking && !video.error
            && video.currentTime >= start - .1 && video.currentTime < end;
    }""", arg=[candidate["start"], candidate["end"]], timeout=60000)
    page.locator("#editorial-source").evaluate("video => video.pause()")
    path = f"/jobs/{job_id}/selections/{late['id']}/candidates/{candidate['id']}/draft"
    draft = portal.click_response(page, card.get_by_role("button", name="Crear / abrir borrador", exact=True),
                                  path, "POST", 201).json()
    origin = draft["selection_origin"]
    source = late["source_fingerprint"]
    portal.require(origin["analysis_id"] == late["id"] and origin["range_id"] == candidate["range_id"]
                   and origin["candidate_id"] == candidate["id"] and origin["search_topic"] == LATE
                   and origin["transcript_sha256"] == late["transcript_sha256"]
                   and origin["source_generation"] == source["source_generation"]
                   and origin["transcript_generation"] == source["transcript_generation"]
                   and origin["prompt_version"] == late["prompt_version"]
                   and (draft["start"], draft["end"]) == (candidate["start"], candidate["end"]),
                   "d01_draft_original_search_and_transcript_provenance")
    page.wait_for_function("""id => document.querySelector('#editorial-drafts')?.value === id
        && document.querySelector('#editorial-save')?.disabled === false""", arg=draft["id"])
    logo_file = scratch / "d01-logo.png"
    logos.png(logo_file, (255, 0, 255))
    logo = logos.upload_logo(page, logo_file)
    logo_panel = logos.open_panel(page, "#editorial-logos")
    logo_panel.locator("[data-logo-field=enabled]").check()
    logo_panel.locator("[data-logo-field=select]").select_option(f'{logo["id"]}:{logo["revision"]}')
    logo_panel.locator("[data-logo-field=position]").select_option(logos.PLACEMENT["position"])
    for name, value in {**logos.PLACEMENT, "opacity": 60}.items():
        if name != "position":
            logo_panel.locator(f"[data-logo-field={name}]").fill(str(value))
    page.locator("#editorial-color-hex").fill(COLOR)
    page.locator("#editorial-position").select_option("bottom")
    page.locator("#editorial-burn").check()
    template = fixture.save_new_style(page, "editorial", "Estilo de búsqueda D01", COLOR)
    portal.require(template["logo"]["id"] == logo["id"] and template["logo"]["revision"] == logo["revision"],
                   "d01_saved_style_retains_logo")
    panel = logos.open_panel(page, "#editorial-styles")
    styles.pick(panel, template["id"])
    draft_path = f"/jobs/{job_id}/drafts/{draft['id']}"
    portal.click_response(page, styles.button(panel, "Aplicar estilo"), draft_path, "PUT", 200,
                          retry_draft_capacity=True)
    page.locator("#editorial-burn").check()
    start, end = round(draft["start"] + .25, 3), round(draft["end"] - .25, 3)
    page.locator("#editorial-start").fill(str(start))
    page.locator("#editorial-end").fill(str(end))
    portal.click_response(page, page.locator("#editorial-apply-range"), f"/jobs/{job_id}/editor/range",
                          "POST", 200, retry_range_capacity=True)
    page.get_by_text("Recorte aplicado. Guarda el borrador para conservarlo.", exact=True).wait_for()
    cue = page.locator('#editorial-cues [data-field="text"]').first
    cue.wait_for()
    cue.fill("Ajustamos el freno antes de probarlo.")
    page.locator("#editorial-title").fill(TITLE)
    page.locator("#editorial-framing").select_option("crop")
    for field, value in (("x", "20"), ("y", "35"), ("zoom", str(ZOOM))):
        page.locator("#editorial-crop-" + field).fill(value)
    saved = fixture.save_draft_color(page, job_id, draft["id"], COLOR)
    portal.require((saved["start"], saved["end"]) == (start, end)
                   and saved["title"] == TITLE and saved["cues"][0]["text"] == cue.input_value()
                   and saved["selection_origin"] == origin and saved["logo"] == template["logo"]
                   and saved["style_template"] == {key: template[key] for key in ("id", "revision", "font")}
                   and saved["options"]["framing"] == "crop" and saved["options"]["crop_zoom"] == ZOOM
                   and [saved["options"]["crop_x"], saved["options"]["crop_y"]] == [.2, .35],
                   "d01_edited_range_cues_style_logo_crop_saved")
    page.locator("#editorial-framing-preview").click()
    page.locator("#editorial-framing-result").wait_for(timeout=60000)
    page.locator("#editorial-framing-composition").screenshot(path=evidence / "d01-draft.png", animations="disabled")
    portal.close_preview(page.locator("#editorial-source"))
    export_id, _, _ = portal.start_editorial_export(page, job_id, saved)
    selected = mixed.exported(page, job_id, export_id, "editorial", scratch, (start, end), saved["cues"])
    published = get_json(page, f"/jobs/{job_id}/exports")["exports"]
    exported = next((item for item in published if item["id"] == export_id), None)
    portal.require(exported is not None and exported["draft_revision"] == saved["revision"]
                   and exported["selection_origin"] == origin
                   and exported["style_template"] == saved["style_template"] and exported["logo"] == saved["logo"]
                   and exported["options"] == saved["options"], "d01_export_pins_search_draft_style_and_logo")
    mp4 = scratch / (selected["stem"] + ".mp4")
    media = probe_media(mp4, pilot=True)
    cue = saved["cues"][0]
    timestamp = (cue["start"] + cue["end"]) / 2
    pixels = caption_color_stats(mp4, COLOR, seconds=timestamp)["matching_pixels"]
    portal.require((media["width"], media["height"]) == (1080, 1920) and pixels >= 40,
                   "d01_mp4_portrait_and_burned_corrected_subtitles")
    rendered_logo = logos.frame_pixels(mp4, scratch)
    run_ffmpeg("-ss", timestamp, "-i", mp4, "-frames:v", 1, "-threads", 1, "-update", 1,
               evidence / "d01-export.png")
    return selected, {"id": export_id, "draft_id": saved["id"], "draft_revision": saved["revision"],
                      "style_template": saved["style_template"], "logo": saved["logo"],
                      "selection_origin": origin, "duration_seconds": media["duration_seconds"],
                      "burned_subtitle_pixels": pixels, "rendered_logo_pixels": rendered_logo,
                      "files": selected["files"]}


def verify_zip(page, job, automatic, editorial, scratch, evidence):
    clip_number = int(automatic["clip"][5:7])
    page.get_by_role("checkbox", name=f"Incluir Clip {clip_number} en ZIP", exact=True).check()
    page.locator(f'input[type=checkbox][data-archive-id="{editorial["identity"]}"]').check()
    button = page.get_by_role("button", name="Descargar ZIP de clips seleccionados", exact=True)
    button.locator("..").screenshot(path=evidence / "d01-mixed-zip.png", animations="disabled")
    path = f"/jobs/{job}/clips.zip"
    destination = scratch / "d01-selected.zip"

    def preflight(response):
        url = urlsplit(response.url)
        return url.path == path and parse_qs(url.query).get("inspect") == ["1"]

    with page.expect_response(preflight, timeout=120000) as pending:
        filename = portal.save_download(page, button, destination)
    response = pending.value
    selections = (automatic, editorial)
    tokens = parse_qs(urlsplit(response.url).query).get("selection", [])
    expected = {f'{item["stem"]}.{key}': data for item in selections for key, data in item["files"].items()}
    portal.require(response.status == 200 and filename.endswith(".zip")
                   and sorted(tokens) == sorted(item["token"] for item in selections)
                   and response.json()["clips"] == 2
                   and response.json()["bytes"] == sum(data["bytes"] for data in expected.values()),
                   "d01_zip_ui_pins_automatic_and_editorial_artifacts")
    with ZipFile(destination) as archive:
        entries = archive.namelist()
        portal.require(len(entries) == len(expected) + 1 and set(entries) == {"manifest.json", *expected},
                       "d01_zip_contains_only_checked_files")
        with archive.open("manifest.json") as handle:
            raw = handle.read(65537)
        portal.require(len(raw) <= 65536, "d01_zip_manifest_bound")
        manifest = json.loads(raw)
        clips, exports = manifest["clips"], manifest["exports"]
        portal.require(len(clips) == len(exports) == 1 and clips[0]["clip"] == automatic["clip"]
                       and clips[0]["output_id"] == automatic["output_id"]
                       and clips[0]["caption_revision"] == automatic["revision"]
                       and exports[0]["kind"] == "editorial" and exports[0]["export_id"] == editorial["identity"]
                       and exports[0]["revision"] == editorial["revision"], "d01_zip_manifest_exact_versions")
        rows = [row for entry in clips + exports for row in entry["files"]]
        reported = {row["file"]: {key: row[key] for key in ("bytes", "sha256")} for row in rows}
        portal.require(reported == expected and len(rows) == len(expected), "d01_zip_manifest_exact_file_receipts")
        for name, receipt in expected.items():
            member = archive.getinfo(name)
            with archive.open(member) as content:
                portal.require(member.compress_type == ZIP_STORED and member.file_size == receipt["bytes"]
                               and hashlib.file_digest(content, "sha256").hexdigest() == receipt["sha256"],
                               "d01_zip_member_matches_real_individual_download")
    return {"bytes": destination.stat().st_size, "sha256": portal.digest_of(destination),
            "members": len(expected), "tokens": tokens}


def verified_replay(page, args, job, path, report):
    verified = json.loads(portal.shared_http.read_private(args.d01_provider_evidence))
    replay = verified["replay"]
    prior = verified["evidence"]
    portal.require(verified["schema"] == "clipforge-int-d01-provider-continuation-1"
                   and verified["status"] == "passed" and verified["target_commit"] == args.commit
                   and verified["original_usage"] == dict.fromkeys(USAGE_KEYS, 3)
                   and set(replay) == REPLAY_FIELDS and replay["run_id"] == prior["run_id"]
                   and replay["model"] == args.editorial_model
                   and portal.COMMIT.fullmatch(replay["source_commit"]) and portal.ID.fullmatch(replay["search_id"])
                   and all(portal.SHA256.fullmatch(replay[key])
                           for key in ("report_sha256", "video_sha256", "transcript_sha256"))
                   and replay["report_sha256"] == prior["sha256"]["browser-d01.json"]
                   and job["fixture_sha256"] == replay["video_sha256"],
                   "d01_protected_replay_receipt")
    listing = get_json(page, path)
    items = listing["analyses"]
    portal.require(listing["total"] == len(items) == 1 and portal.ID.fullmatch(items[0]["id"]),
                   "d01_only_attested_replay_search_present")
    late = get_json(page, f"{path}/{items[0]['id']}")
    identity = late["source_fingerprint"]
    spec = late["spec"]
    usage = dict(zip(USAGE_KEYS, (late["provider_calls_planned"], late["provider_calls"],
                                 late["provider_responses"])))
    portal.require(late == items[0] and late["job_id"] == job["id"] and late["id"] != replay["search_id"]
                   and late["fixture_replay"] == replay and late["status"] == "completed" and late["outcome"] == "matches"
                   and late["provider"] == "openai" and late["model"] == args.editorial_model
                   and late["transcript_sha256"] == identity["transcript_sha256"] == replay["transcript_sha256"]
                   and 1199.8 <= identity["source_duration"] <= 1200
                   and spec["topic"] == LATE and spec["instructions"] == INSTRUCTIONS and spec["max_clips"] == 2
                   and usage == dict.fromkeys(USAGE_KEYS, 0) and late["provider_response_received"] is False
                   and late["provider_models_received"] == [] and portal.provider_call_intervals(late) == [],
                   "d01_replay_identity_and_zero_new_provider_activity")
    candidates = late["candidates"]
    portal.require(len(candidates) == 1, "d01_one_attested_replay_candidate")
    candidate = candidates[0]
    anchor = candidate["evidence"]
    start, end, phrase = WINDOWS[LATE]
    portal.require(candidate["range_id"] == replay["range_id"] and anchor["segment_id"] == replay["evidence_segment"]
                   and candidate["start"] <= anchor["start"] < anchor["end"] <= candidate["end"]
                   and candidate["start"] < end and start < candidate["end"]
                   and 20 <= round(candidate["end"] - candidate["start"], 3) <= 60
                   and phrase.search(anchor["text"]), "d01_replayed_late_range_keeps_server_evidence")
    report["provider_continuation"] = {"replay": replay, "original_usage": verified["original_usage"],
                                       "original_evidence": prior, "synthetic_search": late["id"]}
    report["usage"] = usage
    portal.check(report, "d01_protected_provider_evidence_reused_without_reservations_or_calls")
    return late


def acceptance(browser, args, admin, report):
    state = fixture.read_state(args.state)
    outsider = outsider_account(browser, args, admin)
    job_id = state["job_id"]
    path = f"/jobs/{job_id}/selections"
    report["synthetic_owners"] = [state["owner_id"], outsider["owner_id"]]
    report["synthetic_projects"] = [job_id]
    report["searches"] = []
    evidence = args.report.parent
    replay = args.d01_provider_evidence is not None
    screenshots = []
    with tempfile.TemporaryDirectory(prefix="d01-browser-", dir=args.state.parent) as current:
        scratch = Path(current)
        with portal.browser_page(browser) as page:
            page.set_viewport_size({"width": 1280, "height": 900})
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            job = portal.open_saved_job(page, job_id)
            portal.require([clip["file"] for clip in job["clips"]] == ["clip_01.mp4", "clip_02.mp4"],
                           "d01_existing_automatic_clips")
            automatic = mixed.automatic(page, job_id, job["clips"][0], scratch)
            before = {clip["file"]: portal.read_caption(page, job_id, clip["file"]) for clip in job["clips"]}
            config = get_json(page, "/ai/config")
            portal.require(config["configured"] is True and config["provider"] == "openai"
                           and config["model"] == args.editorial_model and config["daily_limit"] == 100,
                           "d01_int_real_provider_and_daily_limit")
            report["daily_limit_utc"] = config["daily_limit"]
            portal.open_editorial(page)
            portal.require("Buscar momentos por tema" in page.locator("#editorial-heading").inner_text(),
                           "d01_topic_search_entry")
            late_request = None
            if replay:
                report["step"] = "d01_verified_late_replay"
                late = verified_replay(page, args, job, path, report)
                items = [late]
            else:
                items = []
                for topic in (EARLY, LATE, ABSENT):
                    report["step"] = "d01_" + {EARLY: "early", LATE: "late", ABSENT: "absent"}[topic]
                    item, request = search(page, path, topic, args.editorial_model, [row["id"] for row in items], report)
                    if topic == LATE:
                        late_request = request
                    items.append(item)
                    show_search(page, item)
                early, late, _ = items
                portal.require(len({item["transcript_sha256"] for item in items}) == 1
                               and all(item["source_fingerprint"] == early["source_fingerprint"] for item in items),
                               "d01_same_source_and_transcript_for_all_searches")
                portal.check(report, "d01_three_explicit_searches_and_idempotent_replays")

            report["step"] = "d01_relogin_and_isolation"
            portal.logout(page)
            fixture.owned_session(page, state, args.commit)
            portal.open_saved_job(page, job_id)
            portal.open_editorial(page)
            for item in items:
                show_search(page, item)
            verify_other_creator(browser, args, outsider, path, late, late_request)
            if replay:
                desktop = "d01-late.png"
            else:
                page.locator("#editorial-empty").screenshot(path=evidence / "d01-absent.png", animations="disabled")
                screenshots.append("d01-absent.png")
                show_search(page, early)
                desktop = "d01-early.png"
            page.locator("#editorial-candidates").screenshot(path=evidence / desktop, animations="disabled")
            screenshots.append(desktop)
            page.set_viewport_size({"width": 390, "height": 844})
            show_search(page, late)
            page.wait_for_function("""() => {
                const results = document.querySelector('#editorial-candidates');
                return results.clientWidth > 0 && results.scrollWidth <= results.clientWidth + 1
                    && results.getBoundingClientRect().right <= innerWidth + 1;
            }""")
            page.locator("#editorial-candidates").screenshot(path=evidence / "d01-late-narrow.png", animations="disabled")
            page.set_viewport_size({"width": 1280, "height": 900})
            portal.check(report, "d01_relogin_restores_queries_and_private_results_desktop_and_narrow")

            report["step"] = "d01_draft_export_and_exact_zip"
            editorial, report["export"] = editor_flow(page, job_id, late, scratch, evidence)
            report["package"] = verify_zip(page, job_id, automatic, editorial, scratch, evidence)
            after = get_json(page, f"/jobs/{job_id}")
            portal.require(after["clips"] == job["clips"] and all(
                portal.read_caption(page, job_id, name) == value for name, value in before.items()
            ), "d01_automatic_clips_and_revisions_intact")
            saved_searches = history(page, path, [item["id"] for item in items])
            portal.require({item["id"]: item for item in saved_searches} == {item["id"]: item for item in items},
                           "d01_browsing_and_editing_preserve_all_searches_and_reservations")
            portal.check(report, "d01_editorial_mp4_and_mixed_zip_keep_exact_revisions_and_bytes")
            report["screenshots"] = [*screenshots, "d01-late-narrow.png", "d01-draft.png",
                                     "d01-export.png", "d01-mixed-zip.png"]
            portal.logout(page)


def cleanup(browser, args, admin, report):
    if not args.state.exists():
        return
    state = fixture.read_state(args.state, prepared=False)
    owners = [state]
    if outsider_path(args).exists():
        owners.append(read_outsider(args))
    jobs = [state["job_id"]] if state["job_id"] else []
    report["synthetic_owners"] = [owner["owner_id"] for owner in owners]
    report["synthetic_projects"] = jobs
    styles.cleanup(browser, args, admin, [owner["account"] for owner in owners], jobs, report)
