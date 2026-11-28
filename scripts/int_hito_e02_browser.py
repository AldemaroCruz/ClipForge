"""Protected bilingual translation acceptance with the real portal and provider."""

import json
import re
import secrets
import shutil
import tempfile
from pathlib import Path
from time import monotonic

from app import translation_fixture as sample
from app.media import probe_media
from app.subtitles import to_srt, to_vtt
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture
from scripts import int_hito_c_logos_browser as logos
from scripts import int_hito_c_mixed_zip_browser as mixed
from scripts import int_hito_c_styles_browser as styles
from scripts import int_hito_d01_browser as d01
from scripts import int_hito_d02_browser as d02
from scripts import int_hito_d03_browser as d03
from scripts import int_hito_e01_browser as e01


USAGE_KEYS = {"reservations": "provider_calls_planned", "calls": "provider_calls",
              "responses": "provider_responses"}
PENDING = {"queued", "running"}
MANUAL = ("Maya no vendió la cámara ORION.", "Pesaba 18 kilogramos.", "Entregó 5 cajas en Boston.")
PUBLICATION = {"title": "El equipo Atlas", "description": "Datos del equipo y su entrega en Córdoba.",
               "hashtags": ["#Atlas", "#Córdoba"]}
FIDELITY = {
    "en": (
        (r"\bluc[ií]a\b", r"\batlas\b", r"\b(?:not|never|didn['’]t|wasn['’]t)\b", r"\b(?:sell|sold)\b"),
        (r"\b(?:14|fourteen)\b", r"\b(?:kg|kilos?|kilograms?)\b"),
        (r"\b(?:3|three)\b", r"\b(?:box(?:es)?|crates?|packages?)\b", r"\bc[oó]rdoba\b",
         r"\b(?:delivered|handed|brought|took|dropped\s+off)\b"),
    ),
    "es": (
        (r"\bmaya\b", r"\borion\b", r"\bc[aá]mara\b", r"\b(?:no|nunca)\b",
         r"\bvend(?:i[oó]|er|id[oa]|iera)\b"),
        (r"\b(?:18|dieciocho)\b", r"\b(?:kg|kilos?|kilogramos?)\b"),
        (r"\b(?:5|cinco)\b", r"\b(?:cajas?|paquetes?)\b", r"\bboston\b",
         r"\b(?:entreg[oóa]|llev[oó])\b"),
    ),
}


def root(job):
    return f"/jobs/{job}/subtitle-translations"


def cue_edges(cues):
    return [(cue["start"], cue["end"]) for cue in cues]


def keyed_edges(cues):
    return [(cue["id"], cue["start"], cue["end"]) for cue in cues]


def prepare(browser, args, admin, report):
    portal.require(args.video.name == sample.FILENAME, "e02_known_bilingual_source_name")
    fixture.prepare(browser, args, admin, report)
    portal.require(report["fixture"]["duration_seconds"] == sample.DURATION, "e02_known_bilingual_source_duration")
    report["fixture"].update(languages=["es", "en"], source="authored_synthetic_espeak_ng",
                             alignment="synthetic_spoken_word_events")


def cleanup(browser, args, admin, report):
    d03.cleanup(browser, args, admin, report)


def receipt(page, job, run):
    return d01.get_json(page, f"{root(job)}/{run}")


def record_run(report, item):
    runs = report.setdefault("translations", {})
    row = {key: item[key] for key in (
        "id", "status", "source", "source_language", "target_language", "audio_language",
        "provider", "model", "provider_models_received", "source_cues", *USAGE_KEYS.values(),
    ) if key in item}
    for key in ("completed_at", "error_code", "usage", "cues", "saved_draft"):
        if key in item:
            row[key] = item[key]
    runs[item["id"]] = row
    report["usage"] = {label: sum(run.get(key, 0) for run in runs.values()) for label, key in USAGE_KEYS.items()}


def ensure_fidelity(item):
    translated = item["cues"]
    expected = FIDELITY[item["target_language"]]
    portal.require(keyed_edges(translated) == keyed_edges(item["source_cues"])
                   and len(translated) == len(expected), "e02_provider_exact_ids_order_and_server_owned_times")
    for index, (cue, fragments) in enumerate(zip(translated, expected, strict=True), 1):
        portal.require(all(re.search(pattern, cue["text"], flags=re.IGNORECASE) for pattern in fragments),
                       f"e02_{item['target_language']}_cue_{index}_meaning_name_number_unit_and_negation")
        portal.require(isinstance(cue["overflow"], bool) and 1 <= len(cue["text"]) <= 500,
                       "e02_translation_delivers_reviewable_nonempty_text")


def wait_translation(page, job, identity, since, model, report):
    while True:
        item = receipt(page, job, identity)
        record_run(report, item)
        if item["status"] == "completed":
            break
        if item["status"] == "failed":
            code = item.get("error_code", "")
            raise portal.BrowserAcceptanceError(
                code if re.fullmatch(r"[A-Z][A-Z_0-9]{1,60}", code) else "e02_provider_failed")
        portal.require(item["status"] in PENDING and monotonic() - since < 450, "e02_provider_completion_timeout")
        page.wait_for_timeout(2000)
    portal.require(item["provider"] == "openai" and item["model"] == model
                   and all(item[key] == 1 for key in USAGE_KEYS.values())
                   and item["provider_models_received"]
                   and all(portal.MODEL.fullmatch(value) for value in item["provider_models_received"]),
                   "e02_one_real_openai_reservation_call_and_response_per_direction")
    ensure_fidelity(item)
    return item


def open_dialog(page, opener):
    opener.click()
    dialog = page.locator("#translation-dialog")
    dialog.wait_for()
    page.locator("#translation-workspace").wait_for()
    page.locator("#translation-source option:checked").wait_for(state="attached")
    return dialog


def preview_request(page, job, source, language, target, model):
    page.locator("#translation-source-language").select_option(language)
    page.locator("#translation-target-language").select_option(target)
    sent = portal.click_response(page, page.locator("#translation-preview"), root(job) + "/preview", "POST", 200)
    preview = sent.json()
    cue_list = preview["cues"]
    requested = sent.request.post_data_json
    portal.require(requested == {"source": source, "source_language": language, "target_language": target}
                   and preview["source"]["id"] == source["id"] and preview["source"]["revision"] == source["revision"]
                   and preview["source_language"] == language and preview["audio_language"] == language
                   and preview["target_language"] == target and preview["provider"] == "openai"
                   and preview["model"] == model and "api.openai.com" in preview["endpoint"]
                   and cue_edges(cue_list) == cue_edges(sample.cues(language))
                   and [cue["text"] for cue in cue_list] == list(sample.TEXT[language])
                   and len({cue["id"] for cue in cue_list}) == len(cue_list),
                   "e02_consent_uses_exact_selected_revision_text_times_and_original_audio_language")
    consent = page.locator("#translation-consent")
    consent.wait_for()
    show_text = page.locator("#translation-payload").locator("..")
    if show_text.get_attribute("open") is None:
        show_text.locator("summary").click()
    displayed = page.locator("#translation-payload").text_content()
    outgoing = preview["text_to_send"]
    if isinstance(outgoing, str):
        portal.require(displayed.strip() == outgoing.strip(), "e02_exact_text_visible_in_consent")
    else:
        portal.require(json.loads(displayed) == outgoing, "e02_exact_text_visible_in_consent")
    escaped = json.dumps(outgoing, ensure_ascii=False)
    other_fixture = "Orion" if language == "es" else "Atlas"
    portal.require(other_fixture not in escaped and "E02 cambio sin guardar" not in escaped
                   and all(cue["text"] in escaped and cue["id"] in escaped for cue in cue_list)
                   and "api.openai.com" in page.locator("#translation-destination").inner_text(),
                   "e02_only_the_reviewed_source_cues_are_sent_to_approved_destination")
    portal.require(not consent.is_checked() and page.locator("#translation-run").is_disabled(),
                   "e02_explicit_consent_required_before_translation")
    return preview


def submit(page, job, preview, report):
    page.locator("#translation-consent").check()
    since = monotonic()
    result = portal.click_response(page, page.locator("#translation-run"), root(job), "POST", 202)
    item, request = result.json(), result.request.post_data_json
    record_run(report, item)
    portal.require(portal.ID.fullmatch(item["id"]) and item["status"] in PENDING
                   and request["consent"] is True and request["preview_fingerprint"] == preview["preview_fingerprint"]
                   and item["provider_calls_planned"] == 1, "e02_one_job_after_creators_explicit_consent")
    return item, request, since


def replay(page, job, request, completed):
    for body in (request, {**request, "request_id": secrets.token_hex(16)}):
        repeated = d02.browser_post_json(page, root(job), body)
        portal.require(repeated["status"] == 202 and repeated["body"]["id"] == completed["id"]
                       and all(repeated["body"][key] == 1 for key in USAGE_KEYS.values()),
                       "e02_identical_consent_replays_without_second_reservation")
    portal.require(receipt(page, job, completed["id"]) == completed, "e02_replay_leaves_exact_completed_receipt")


def variant_fields(page, cues):
    fields = page.locator("#translation-cues textarea[data-translation-cue]")
    fields.first.wait_for()
    portal.require([field.get_attribute("data-translation-cue") for field in fields.all()]
                   == [cue["id"] for cue in cues], "e02_editor_preserves_all_cue_ids_in_order")
    return fields


def save_variant(page, job, item, texts):
    fields = variant_fields(page, item["source_cues"])
    for field, text in zip(fields.all(), texts, strict=True):
        field.fill(text)
    path = f"{root(job)}/{item['id']}/draft"
    result = portal.click_response(page, page.locator("#translation-save"), path, "POST", 201)
    draft = result.json()
    submitted = result.request.post_data_json["cues"]
    origin = draft["translation_origin"]
    portal.require(submitted == [{"id": cue["id"], "text": text} for cue, text in
                                zip(item["source_cues"], texts, strict=True)]
                   and origin["run_id"] == item["id"] and origin["cue_ids"] == [cue["id"] for cue in item["source_cues"]]
                   and origin["source_language"] == item["source_language"]
                   and origin["target_language"] == item["target_language"]
                   and origin["audio_language"] == item["audio_language"]
                   and cue_edges(draft["cues"]) == cue_edges(item["source_cues"])
                   and [cue["text"] for cue in draft["cues"]] == list(texts)
                   and draft["options"][e01.HIGHLIGHT] is False and not draft.get("word_highlight"),
                   "e02_saved_variant_pins_exact_cues_audio_timeline_and_static_style")
    page.locator("#translation-open").wait_for()
    return draft


def visible_static_editor(page, draft, evidence, label):
    page.locator("#translation-open").click()
    active = page.locator("#editorial-translation-origin")
    active.wait_for()
    limitation = page.locator("#editorial-highlight-limitation")
    limitation.wait_for()
    option = page.locator("#editorial-highlight-enabled")
    portal.require(page.locator("#editorial-drafts").input_value() == draft["id"]
                   and option.is_disabled() and not option.is_checked() and "resalt" in limitation.inner_text().casefold()
                   and not page.locator("#editorial-highlight-prepare").is_visible(),
                   "e02_explains_static_translation_without_offer_to_realign_original_audio")
    portal.require("audio" in active.inner_text().casefold()
                   and "subtítulo" in active.inner_text().casefold(),
                   "e02_editor_separately_identifies_audio_and_subtitle_languages")
    if label == "narrow":
        portal.require(active.evaluate("element => element.getBoundingClientRect().right <= innerWidth + 1"),
                       "e02_translated_editor_fits_narrow_viewport")
    active.screenshot(path=evidence / f"e02-{label}-variant-languages.png", animations="disabled")
    limitation.screenshot(path=evidence / f"e02-{label}-static-notice.png", animations="disabled")


def export_item(page, job, identity):
    for _ in range(160):
        items = d01.get_json(page, f"/jobs/{job}/exports")["exports"]
        item = next((row for row in items if row["id"] == identity), None)
        if item and item["status"] == "completed":
            return item
        portal.require(not item or item["status"] in PENDING, "e02_export_worker_failed")
        page.wait_for_timeout(3000)
    raise portal.BrowserAcceptanceError("e02_export_worker_timeout")


def download_variant(page, job, identity, scratch, expected_cues, expected_span, *, target_language=None):
    item = export_item(page, job, identity)
    card = page.locator(f'#editorial-exports article[data-export-id="{identity}"]')
    checkbox = card.locator(f'input[data-archive-id="{identity}"]')
    checkbox.wait_for(timeout=30_000)
    selection = item["archive_selection"]
    token = mixed.EXPORT_TOKEN.fullmatch(selection)
    portal.require(token and token.group(1) == identity and set(item["archive_files"]) == mixed.FILE_TYPES
                   and item["cues"] == expected_cues and (item["start"], item["end"]) == expected_span,
                   "e02_completed_export_pins_exact_media_version_and_cues")
    kind = "translation" if target_language else "editorial"
    stem = f"translation_{target_language}_{identity}" if target_language else f"editorial_{identity}"
    files = {}
    for ext in ("mp4", "srt", "vtt"):
        href = f"/jobs/{job}/exports/{identity}/files/clip.{ext}"
        link = card.locator(f'a[href="{href}"]')
        path = scratch / f"{stem}.{ext}"
        suggested = portal.save_download(page, link, path)
        if target_language:
            portal.require(suggested == path.name,
                           "e02_actual_download_filename_pins_variant_language_and_identity")
        files[ext] = {"bytes": path.stat().st_size, "sha256": portal.digest_of(path)}
    media = probe_media(scratch / f"{stem}.mp4", pilot=True)
    portal.require((media["width"], media["height"], media["video_codec"], media["audio_codec"])
                   == (1080, 1920, "h264", "aac")
                   and abs(media["duration_seconds"] - (expected_span[1] - expected_span[0])) < .08
                   and (scratch / f"{stem}.srt").read_text(encoding="utf-8") == to_srt(expected_cues)
                   and (scratch / f"{stem}.vtt").read_text(encoding="utf-8") == to_vtt(expected_cues),
                   "e02_mp4_duration_and_exact_utf8_srt_and_vtt")
    return {"kind": kind, "token": selection, "identity": identity, "stem": stem,
            "files": files, "revision": int(token.group(2))}, item


def download_again(page, job, media, scratch):
    root_path = f"/jobs/{job}/exports/{media['identity']}/files"
    card = d03.card(page, media)
    for ext, receipt in media["files"].items():
        path = scratch / f"recheck-{media['identity']}.{ext}"
        portal.save_download(page, card.locator(f'a[href="{root_path}/clip.{ext}"]'), path)
        portal.require(portal.digest_of(path) == receipt["sha256"] and path.stat().st_size == receipt["bytes"],
                       "e02_original_files_preserved_byte_for_byte")


def make_original(page, job, original, scratch, evidence, report):
    e01.reopen_draft(page, job, original)
    saved, style = e01.save_active_template(page, job, original, scratch)
    plan = e01.highlight_plan(page, job, saved)
    words = e01.expect_plan(plan, saved)
    portal.require(plan["status"] == "ready" and len(words) == 14
                   and saved["audio_language"] == "es" and saved["subtitle_language"] == "es",
                   "e02_original_uses_exact_fixture_acoustic_mark_reference")
    identity, _, _ = portal.start_editorial_export(page, job, saved)
    draft, item = download_variant(page, job, identity, scratch, saved["cues"], sample.SPAN["es"])
    path = scratch / f"{draft['stem']}.mp4"
    times = e01.frame_clock(path, scratch)
    measured = e01.measure_frames(path, None, e01.reference_frames(saved, words, times), scratch, scratch, "original")
    for frame in ("first", "last"):
        (scratch / f"e01-original-{frame}.png").replace(evidence / f"e02-original-{frame}.png")
    report["original_highlight"] = {"version": plan["version"], "frames": measured, "export_id": identity}
    portal.require(item["word_highlight"] == plan and item["options"][e01.HIGHLIGHT],
                   "e02_original_export_really_burned_e01_highlight")
    for ext in draft["files"]:
        shutil.copyfile(scratch / f"{draft['stem']}.{ext}", evidence / f"e02-original-es.{ext}")
    return saved, style, draft


def save_publication(page, job, original):
    d03.open_panel(page, original)
    page.locator("#publication-language").fill("es")
    d03.save_manual(page, job, original, PUBLICATION)
    saved = d03.require_saved(d03.publication(page, job, original), PUBLICATION, 1)
    portal.require(saved["language"] == "es", "e02_known_original_publication_in_spanish")
    d03.close_panel(page)
    return saved


def no_auto_publication(page, job, translated):
    state = d03.publication(page, job, translated)
    portal.require(state["saved"] is None and state["suggestion"] is None,
                   "e02_translation_does_not_automatically_copy_or_translate_publication")
    return state


def explicit_publication_reuse(page, job, original, translated, saved):
    state = no_auto_publication(page, job, translated)
    portal.require(any(row["selection"] == original["token"] and row["revision"] == saved["revision"]
                       for row in state["reusable"]), "e02_translation_can_explicitly_reuse_pinned_original_publication")
    d03.open_panel(page, translated)
    path = d03.publication_path(job, "/reuse")
    selector = f'#publication-reusable-options button[data-publication-reuse="{original["token"]}"]'
    result = portal.click_response(page, page.locator(selector), path, "POST", 200)
    request = result.request.post_data_json
    current = d03.publication(page, job, translated)
    copied = d03.require_saved(current, PUBLICATION, 1)
    portal.require(request["selection"] == translated["token"] and request["source_selection"] == original["token"]
                   and request["source_revision"] == saved["revision"] and current["suggestion"] is None
                   and copied["language"] == saved["language"] == "es"
                   and copied["reused_from"]["selection"] == original["token"]
                   and copied["reused_from"]["revision"] == saved["revision"]
                   and copied["reused_from"]["translated_subtitles"] is True,
                   "e02_explicit_publication_reuse_preserves_original_language_and_provenance")
    d03.close_panel(page)
    return copied


def acoustic_match(source, media, span, scratch, language):
    start, end = span
    length = end - start
    reference = d02.pcm(scratch / f"{language}-source.wav", source, start, length)
    rendered = d02.pcm(scratch / f"{language}-render.wav", media, 0, length)
    shared = min(len(reference), len(rendered))
    rate = d02.SAMPLE_RATE
    portal.require(abs(shared / rate - length) < .10, "e02_translated_mp4_audio_duration_preserved")
    piece, margin = int(.30 * rate), int(.04 * rate)
    positions = []
    for cue in sample.cues(language):
        points = range(int((cue["start"] + .12) * rate), int((cue["end"] - .4) * rate), int(.12 * rate))
        positions.append(max(points, key=lambda index: sum(value * value for value in reference[index:index + piece])))
    observed = [d02.audio_score(reference, rendered, position, margin, piece) for position in positions]
    portal.require(all(score >= .88 and abs(offset) <= rate / 100 for score, offset in observed),
                   "e02_same_speech_each_cue_and_no_audio_redub_or_shift")
    return {"source_language": language, "source_interval": list(span),
            "normalised_correlation": [round(score, 4) for score, _ in observed],
            "offset_ms": [round(offset * 1000 / rate, 2) for _, offset in observed]}


def compare_static_mp4(original, translated, original_draft, variant, scratch, evidence, report):
    original_path = scratch / f"{original['stem']}.mp4"
    translated_path = scratch / f"{translated['stem']}.mp4"
    times = e01.frame_clock(translated_path, scratch)
    portal.require(times == e01.frame_clock(original_path, scratch), "e02_exact_original_frame_pts")
    samples = []
    for index, cue in enumerate(variant["cues"]):
        stamp = e01.select_frame(times, cue["start"], cue["end"])
        portal.require(stamp is not None, "e02_lexically_grounded_cue_has_measurable_frame")
        samples.append({"label": "first" if index == 0 else "last" if index == len(variant["cues"]) - 1 else "middle",
                        "cue": index, "word": None, "n": stamp[0], "seconds": stamp[1]})
    measurements = e01.measure_frames(translated_path, None, samples, scratch, scratch, "english-static")
    for frame in ("first", "last"):
        (scratch / f"e01-english-static-{frame}.png").replace(evidence / f"e02-english-static-{frame}.png")
    report["translated_static_frames"] = measurements
    # The variant keeps the logo and all geometry, but its cue text changes so
    # glyph-mask equality with the source would be the wrong assertion.
    portal.require(variant["logo"] == original_draft["logo"] and logos.frame_pixels(translated_path, scratch)
                   == logos.frame_pixels(original_path, scratch), "e02_logo_geometry_and_alpha_preserved_in_burned_mp4")


def saved_ref(kind, item):
    return {"kind": kind, "id": item["id"], "revision": item["revision"]}


def open_for_export(page, identity):
    card = page.locator(f'#editorial-exports article[data-export-id="{identity}"]')
    return open_dialog(page, card.locator("button[data-subtitle-translation]"))


def close_translation(page):
    page.keyboard.press("Escape")
    page.locator("#translation-dialog").wait_for(state="hidden")


def spanish_to_english(page, job, original, model, evidence, report):
    e01.reopen_draft(page, job, original)
    first = e01.cue_rows(page).first.locator(".caption-text")
    unsaved = first.input_value() + " E02 cambio sin guardar."
    first.fill(unsaved)
    dialog = open_dialog(page, page.locator("#editorial-translate"))
    notice = dialog.get_by_text(re.compile(r"(sin guardar|revisión guardada)", re.IGNORECASE)).first
    notice.wait_for()
    review = preview_request(page, job, saved_ref("draft", original), "es", "en", model)
    portal.require(first.input_value() == unsaved and d01.get_json(page, f"/jobs/{job}/drafts/{original['id']}") == original,
                   "e02_unsaved_text_never_changes_consent_or_source_revision")
    dialog.screenshot(path=evidence / "e02-consent-es-en.png", animations="disabled")
    initial, request, since = submit(page, job, review, report)
    complete = wait_translation(page, job, initial["id"], since, model, report)
    replay(page, job, request, complete)
    fields = variant_fields(page, complete["cues"])
    texts = [field.input_value() for field in fields.all()]
    portal.require(texts == [cue["text"] for cue in complete["cues"]], "e02_ui_shows_exact_real_model_translation")
    replacement = "Atlas" if "ATLAS" in texts[0] else "ATLAS"
    texts[0] = re.sub(r"\batlas\b", replacement, texts[0], count=1, flags=re.I)
    portal.require(texts[0] != complete["cues"][0]["text"], "e02_creator_explicitly_corrected_rendered_term")
    overflow = "A longer caption for review. " * 6
    fields.first.fill(overflow)
    page.locator("#translation-cues .translation-warning").first.wait_for()
    portal.require(fields.first.input_value() == overflow, "e02_overflow_advisory_does_not_trim_or_retime_text")
    draft = save_variant(page, job, complete, texts)
    portal.require(first.input_value() == unsaved, "e02_saving_separate_variant_preserves_unsaved_source_editor")
    # Discard only the deliberate unsaved synthetic input before switching views.
    close_translation(page)
    first.fill(original["cues"][0]["text"])
    open_dialog(page, page.locator("#editorial-translate"))
    activate_saved_run(page, complete["id"])
    visible_static_editor(page, draft, evidence, "desktop")
    page.locator("#editorial-translation-source").click()
    page.wait_for_function("id => document.querySelector('#editorial-drafts').value === id", arg=original["id"])
    portal.require(page.locator("#editorial-highlight-enabled").is_checked(),
                   "e02_back_to_original_recovers_active_e01")
    portal.check(report, "e02_real_es_en_exact_content_review_manual_term_correction_and_return_to_original")
    return draft, request


def activate_saved_run(page, identity):
    page.locator("#translation-runs").select_option(identity)
    page.locator("#translation-open").wait_for()


def english_to_spanish(page, job, source, model, evidence, report):
    page.set_viewport_size({"width": 390, "height": 844})
    dialog = open_for_export(page, source["id"])
    portal.require(dialog.evaluate("el => el.getBoundingClientRect().right <= innerWidth + 1"
                                   " && el.scrollWidth <= el.clientWidth + 1"), "e02_translation_dialog_fits_narrow")
    review = preview_request(page, job, saved_ref("export", source), "en", "es", model)
    dialog.screenshot(path=evidence / "e02-consent-en-es-narrow.png", animations="disabled")
    initial, request, since = submit(page, job, review, report)
    path = portal.PUBLIC + f"{root(job)}/{initial['id']}"
    observed, delayed = [], []

    def hold_result(route):
        response = route.fetch()
        if route.request.method == "GET" and response.status == 200:
            real = response.json()
            observed.append(real)
            if real["status"] == "completed":
                delayed.append(real)
                queued = {**real, "status": "running", "cues": []}
                route.fulfill(status=200, json=queued)
                return
        route.fulfill(response=response)

    page.route(path, hold_result)
    try:
        page.locator("#translation-manual").click()
        draft = save_variant(page, job, initial, MANUAL)
        saved = d01.get_json(page, f"/jobs/{job}/drafts/{draft['id']}")
        portal.require(saved == draft, "e02_manual_variant_persisted_before_late_result")
        while not delayed:
            if observed:
                record_run(report, observed[-1])
                portal.require(observed[-1]["status"] != "failed", "e02_late_provider_result_failed")
            portal.require(monotonic() - since < 450, "e02_protected_browser_did_not_observe_completed_result")
            page.wait_for_timeout(500)
    finally:
        page.unroute(path, hold_result)
    complete = wait_translation(page, job, initial["id"], since, model, report)
    replay(page, job, request, complete)
    page.wait_for_function("""() => document.querySelector('#translation-run-summary')
        ?.textContent.includes('Traducción disponible para revisar.')""")
    portal.require(d01.get_json(page, f"/jobs/{job}/drafts/{draft['id']}") == saved
                   and complete["saved_draft"]["id"] == draft["id"],
                   "e02_late_real_provider_result_cannot_overwrite_manual_variant")
    report["late_result"] = {"run_id": complete["id"], "manual_draft_id": draft["id"],
                             "manual_revision": draft["revision"], "manual_at": draft.get("created_at"),
                             "provider_at": complete.get("completed_at"),
                             "withheld_completed_responses": len(delayed)}
    visible_static_editor(page, draft, evidence, "narrow")
    page.set_viewport_size({"width": 1280, "height": 900})
    portal.check(report, "e02_real_en_es_translation_remains_separate_from_manual_late_race")
    return draft, request


def style_and_export(page, job, original, variant, template, scratch, evidence, report, language):
    e01.reopen_draft(page, job, variant)
    if template:
        panel = logos.open_panel(page, "#editorial-styles")
        styles.pick(panel, template["id"])
        path = f"/jobs/{job}/drafts/{variant['id']}"
        variant = portal.click_response(page, styles.button(panel, "Aplicar estilo"), path, "PUT", 200,
                                        retry_draft_capacity=True).json()
    intent = variant["translation_origin"]
    portal.require(not variant["options"][e01.HIGHLIGHT] and not variant.get("word_highlight")
                   and page.locator("#editorial-highlight-enabled").is_disabled()
                   and not page.locator("#editorial-highlight-prepare").is_visible()
                   and all(variant["options"][key] == value for key, value in original["options"].items()
                           if key not in {e01.HIGHLIGHT, e01.HIGHLIGHT_COLOR})
                   and variant.get("logo") == original.get("logo"),
                   "e02_static_translated_variant_keeps_source_style_even_after_active_template")
    identity, _, _ = portal.start_editorial_export(page, job, variant)
    media, item = download_variant(page, job, identity, scratch, variant["cues"],
                                   sample.SPAN[intent["source_language"]], target_language=language)
    portal.require(item["translation_origin"] == intent and item["audio_language"] == intent["audio_language"]
                   and item["subtitle_language"] == language and item["archive_kind"] == "translation"
                   and item["options"][e01.HIGHLIGHT] is False and not item.get("word_highlight")
                   and item.get("logo") == variant.get("logo"),
                   "e02_translated_export_and_archive_pin_full_saved_origin")
    report.setdefault("exports", {})[language] = {
        "id": identity, "archive_selection": media["token"], "archive_stem": media["stem"],
        "files": media["files"], "origin": {key: value for key, value in intent.items() if key != "source_asset"},
        "draft_revision": variant["revision"],
        "source_range": [variant["start"], variant["end"]],
    }
    if language == "en":
        report["startup_subject"] = {"job_id": job, "receipt": item["processing_receipt"]}
    for ext in media["files"]:
        shutil.copyfile(scratch / f"{media['stem']}.{ext}", evidence / f"e02-translated-{language}.{ext}")
    return variant, media


def check_boundaries(browser, args, outsider, job, source, request):
    with portal.browser_page(browser) as other:
        fixture.owned_session(other, outsider, args.commit)
        portal.require(portal.browser_get(other, root(job))["status"] == 404
                       and portal.browser_get(other, f"{root(job)}/{source['translation_origin']['run_id']}")["status"] == 404
                       and d02.browser_post_json(other, root(job), request)["status"] == 404,
                       "e02_other_account_cannot_read_or_start_translation")
        portal.logout(other)


def acceptance(browser, args, admin, report):
    state = fixture.read_state(args.state)
    outsider = d01.outsider_account(browser, args, admin)
    job = state["job_id"]
    evidence = args.report.parent
    report["synthetic_owners"] = [state["owner_id"], outsider["owner_id"]]
    report["synthetic_projects"] = [job]
    report["step"] = "e02_pin_original_draft_export_languages_and_assets"
    with tempfile.TemporaryDirectory(prefix="e02-browser-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        with portal.browser_page(browser) as page:
            page.set_viewport_size({"width": 1280, "height": 900})
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            project = portal.open_saved_job(page, job)
            config = d01.get_json(page, "/ai/config")
            portal.require(config["provider"] == "openai" and config["configured"]
                           and config["model"] == args.editorial_model and config["daily_limit"] == 100,
                           "e02_real_existing_provider_model_and_shared_daily_quota")
            report["daily_limit_utc"] = config["daily_limit"]
            portal.require(project["language"] == "mul" and project["media"]["duration_seconds"] == sample.DURATION
                           and project["fixture_sha256"] == portal.digest_of(args.video)
                           and project["fixture_alignment"] == "synthetic_spoken_word_events",
                           "e02_original_language_pair_and_synthetic_word_event_provenance")
            report["fixture"] = {"sha256": project["fixture_sha256"], "language": "mul", "spans": sample.SPAN,
                                 "alignment": project["fixture_alignment"]}
            selected = project["translation_fixture_sources"]
            base_es = d01.get_json(page, f"/jobs/{job}/drafts/{selected['es']}")
            original_es, style, media_es = make_original(page, job, base_es, scratch, evidence, report)
            media_en, original_en = download_variant(page, job, selected["en"], scratch, sample.cues("en"), sample.SPAN["en"])
            portal.require(original_en["audio_language"] == original_en["subtitle_language"] == "en"
                           and d01.get_json(page, root(job))["runs"] == [], "e02_exact_baked_english_source_and_no_initial_jobs")
            saved_publication = save_publication(page, job, media_es)

            report["step"] = "e02_es_en_review_generate_correct_and_return_to_original"
            english, request_es = spanish_to_english(page, job, original_es, args.editorial_model, evidence, report)
            report["step"] = "e02_en_es_manual_variant_before_late_real_result"
            spanish, request_en = english_to_spanish(page, job, original_en, args.editorial_model, evidence, report)
            portal.require(report["usage"] == {"reservations": 2, "calls": 2, "responses": 2},
                           "e02_two_real_provider_calls_total")
            report["step"] = "e02_relogin_static_style_audio_subtitles_and_render"
            portal.logout(page)
            fixture.owned_session(page, state, args.commit)
            english, new_en = style_and_export(page, job, original_es, english, style, scratch, evidence, report, "en")
            spanish, new_es = style_and_export(page, job, original_en, spanish, None, scratch, evidence, report, "es")
            compare_static_mp4(media_es, new_en, original_es, english, scratch, evidence, report)
            report["audio"] = {
                language: acoustic_match(args.video, scratch / f"{media['stem']}.mp4", sample.SPAN[source], scratch, source)
                for language, source, media in (("en", "es", new_en), ("es", "en", new_es))
            }
            report["audio_review"] = "decoded_pcm_comparison_no_human_listening"
            portal.check(report, "e02_saved_variants_reopen_static_and_render_exact_boundaries_and_original_audio")

            report["step"] = "e02_explicit_original_publication_reuse_and_exact_mixed_zip"
            copied = explicit_publication_reuse(page, job, media_es, new_en, saved_publication)
            no_auto_publication(page, job, new_es)
            files = {item["token"]: d03.reopen_saved(page, scratch, job, item, saved)
                     for item, saved in ((media_es, saved_publication), (new_en, copied))}
            report["package"] = d03.package(page, job, [media_es, media_en, new_en, new_es], files, scratch, scratch)
            shutil.copyfile(scratch / "d03-selected.zip", evidence / "e02-variants.zip")
            (scratch / "d03-mixed-zip.png").replace(evidence / "e02-mixed-zip.png")
            report["publication_reuse"] = copied["reused_from"]
            download_again(page, job, media_es, scratch)
            download_again(page, job, media_en, scratch)
            runs = d01.get_json(page, root(job))["runs"]
            portal.require(len(runs) == 2 and {item["id"] for item in runs} == set(report["translations"])
                           and d01.get_json(page, f"/jobs/{job}/selections")["analyses"] == []
                           and d01.get_json(page, f"/jobs/{job}/drafts/{original_es['id']}") == original_es,
                           "e02_edit_render_download_and_zip_create_no_additional_ai_or_change_source")
            portal.check(report, "e02_original_assets_and_publication_explicitly_pinned_in_mixed_zip")

            report["step"] = "e02_owner_boundary_and_tombstone"
            check_boundaries(browser, args, outsider, job, english, request_es)
            portal.require(portal.browser_post(page, f"/jobs/{job}/deletion", {})["status"] == 202
                           and portal.browser_get(page, root(job))["status"] == 404
                           and d02.browser_post_json(page, root(job), request_en)["status"] == 404,
                           "e02_deleted_project_cannot_read_or_start_translation")
            portal.check(report, "e02_other_accounts_and_deleted_projects_denied")
            portal.logout(page)
