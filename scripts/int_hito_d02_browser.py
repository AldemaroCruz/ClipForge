"""Focused INT browser acceptance for creating continuous clips from a transcript."""

import hashlib
import json
import re
import secrets
import struct
import tempfile
import wave
from pathlib import Path
from time import monotonic

from app.check_presentation import caption_color_stats
from app.media import probe_media
from app.render import run_ffmpeg
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture
from scripts import int_hito_c_logos_browser as logos
from scripts import int_hito_c_mixed_zip_browser as mixed
from scripts import int_hito_c_styles_browser as styles
from scripts import int_hito_d01_browser as d01
from scripts.int_hito_b_browser_ui import submit_quick_caption_correction


FIXTURE_NAME = "transcript.mp4"
SOURCE = "https://librivox.org/el-ingenioso-hidalgo-by-miguel-de-cervantes-saavedra/"
SOURCE_AUDIO_SHA256 = "8fa9d75f7a16b8be5f4b5c60f0b73438fd7abfe0408a12d4b3090f982eff1587"
SCRIPT_WORD_METHOD = "faster-whisper-word-timestamps"
SUBTITLE_COLOR = "#FFFF00"
SAMPLE_RATE = 8000


def state_file(args):
    state = json.loads(portal.shared_http.read_private(args.state))
    portal.require(type(state) is dict
                   and set(state) == {"account", "owner_id", "outsider", "jobs", "prior_caption", "video_sha256"}
                   and portal.SHA256.fullmatch(state["video_sha256"])
                   and set(state["jobs"]) <= {"historical", "new"}
                   and all(portal.ID.fullmatch(value) for value in state["jobs"].values()),
                   "d02_checkpoint_shape")
    actors = (state, state["outsider"]) if state["outsider"] is not None else (state,)
    for actor in actors:
        account = portal.shared_http.validate_admin(actor["account"])
        portal.require(portal.ACCOUNT.fullmatch(account["username"]) and portal.ID.fullmatch(actor["owner_id"]),
                       "d02_synthetic_checkpoint_identity")
    return state


def checkpoint(args, state, report):
    fixture.update_checkpoint(args.state, state)
    report["synthetic_projects"] = list(state["jobs"].values())
    report["synthetic_owners"] = [state["owner_id"], state["outsider"]["owner_id"]]


def add_account(page):
    account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
    result = portal.create_account(page, account)
    portal.require(portal.ID.fullmatch(result["id"]), "d02_created_synthetic_account")
    return {"account": account, "owner_id": result["id"]}


def upload(browser, args, state, version, report):
    video = args.video
    portal.require(video.name == FIXTURE_NAME, "d02_long_speech_fixture_name")
    portal.require(portal.digest_of(video) == state["video_sha256"], "d02_same_natural_video_on_both_worker_profiles")
    transfer = []
    with portal.browser_page(browser, storage=True, transfer=transfer) as page:
        fixture.owned_session(page, state, args.commit)
        previous = tuple(state["jobs"].values())

        def remember(job_id):
            state["jobs"][version] = job_id
            checkpoint(args, state, report)

        job = portal.upload_video(page, video, report, transfer, existing_projects=previous, track_reservation=remember)
        portal.logout(page)
    portal.require(job["media"]["duration_seconds"] == 1200, "d02_fixture_exact_twenty_minutes")
    report["fixture"].update(content="human_narration_librivox_spanish", source=SOURCE,
                             recording="Don Quijote, capítulo VIII, lectura de Lu",
                             audio_sha256=SOURCE_AUDIO_SHA256, sha256=state["video_sha256"])
    return job


def fingerprint(value):
    raw = json.dumps(value, sort_keys=True, ensure_ascii=False, separators=(",", ":")).encode()
    return hashlib.sha256(raw).hexdigest()


def prepare(browser, args, admin, report):
    report["step"] = "d02_prepare_synthetic_accounts"
    with portal.browser_page(browser) as page:
        portal.login(page, admin, args.commit)
        page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
        owner = add_account(page)
        state = {**owner, "outsider": None, "jobs": {}, "prior_caption": None,
                 "video_sha256": portal.digest_of(args.video)}
        portal.shared_http.write_new(args.state, state)
        state["outsider"] = add_account(page)
        checkpoint(args, state, report)
        portal.logout(page)
    old = upload(browser, args, state, "historical", report)
    report["step"] = "d02_save_caption_correction_before_promotion"
    job_id = old["id"]
    with portal.browser_page(browser) as page:
        fixture.owned_session(page, state, args.commit)
        portal.open_saved_job(page, job_id)
        clip = old["clips"][0]["file"]
        before = portal.read_caption(page, job_id, clip)
        portal.require(before["status"] == "completed" and before["cues"], "d02_historical_clip_has_subtitles")
        cues = [dict(cue) for cue in before["cues"]]
        cues[0]["text"] = "Corrección de prueba: " + cues[0]["text"][:380].strip()
        page.locator(f'#clip-list [data-clip-file="{clip}"]').get_by_role(
            "button", name="Corregir texto", exact=True).click()
        quick = page.locator('#clip-caption-editor[data-mode="quick"]')
        submit_quick_caption_correction(page, quick, 0, cues[0]["text"],
                                        f"{portal.PUBLIC}/jobs/{job_id}/clips/{clip}/captions")
        corrected = portal.caption_output(page, job_id, clip, before["output"]["id"])
        portal.require(corrected["cues"] == cues and corrected["style"] == before["style"],
                       "d02_existing_caption_corrected_before_alignment")
        state["prior_caption"] = {"file": clip, "state_sha256": fingerprint(corrected),
                                  "revision": corrected["revision"], "output_id": corrected["output"]["id"]}
        checkpoint(args, state, report)
        report["historical_caption"] = state["prior_caption"]
        portal.check(report, "d02_prior_revision_processed_natural_audio_and_saved_caption_correction")
        portal.logout(page)


def root(job):
    return f"/jobs/{job}/transcript-selection"


def list_transcript(page, job):
    data = d01.get_json(page, root(job))
    portal.require(data["job_id"] == job and data["source_duration"] == 1200 and data["min_seconds"] == 1
                   and data["max_seconds"] == 60 and data["source_url"].startswith(f"/jobs/{job}/source"),
                   "d02_transcript_source_and_export_limits")
    versions = data["versions"]
    portal.require(versions and len({value["id"] for value in versions}) == len(versions)
                   and data["default_version"] in {value["id"] for value in versions}
                   and all(portal.SHA256.fullmatch(value["id"]) for value in versions), "d02_valid_versions")
    return data


def version(data, method):
    matches = [item for item in data["versions"] if item["method"] == method]
    portal.require(len(matches) == 1, "d02_expected_version_method")
    return matches[0]


def open_transcript(page):
    heading = page.locator("#transcript-heading")
    portal.require(heading.inner_text().strip() == "Crear clip desde la transcripción", "d02_transcript_entry")
    if heading.locator("..").get_attribute("open") is None:
        heading.click()


def select_version(page, item):
    text = page.locator("#transcript-text")
    picker = page.locator("#transcript-version")
    page.wait_for_function("""version => {
        const picker = document.querySelector('#transcript-version');
        return document.querySelector('#transcript-text')?.dataset.version === version
            || (!document.querySelector('#transcript-version-choice')?.hidden
            && [...picker.options].some(option => option.value === version));
    }""", arg=item["id"])
    if text.get_attribute("data-version") != item["id"]:
        picker.select_option(item["id"])
    page.wait_for_function("version => document.querySelector('#transcript-text')?.dataset.version === version",
                           arg=item["id"])


def browser_post_json(page, path, value):
    return page.evaluate("""async ({path, value}) => {
        const auth = window.ClipForgeAuth;
        const response = await auth.fetch(path, auth.payload(value));
        return {status: response.status, body: await response.json()};
    }""", {"path": path, "value": value})


def prepare_historical(page, job, before, report):
    old_version = version(before, "segments")
    elapsed = monotonic()
    button = page.locator("#transcript-prepare")
    path = root(job) + "/prepare"
    sent = portal.click_response(page, button, path, "POST", 202).json()
    portal.require(portal.ID.fullmatch(sent["id"]) and sent["job_id"] == job
                   and sent["status"] in {"queued", "running", "completed"}, "d02_preparation_identity")
    repeated = browser_post_json(page, path, {})
    portal.require(repeated["status"] == 202 and repeated["body"]["id"] == sent["id"],
                   "d02_duplicate_alignment_recovers_same_task")
    while True:
        data = list_transcript(page, job)
        status = data["alignment_status"]
        if status == "ready":
            break
        portal.require(status in {"queued", "running"} and monotonic() - elapsed < 1200,
                       "d02_historical_alignment_incomplete")
        page.wait_for_timeout(3000)
    original = version(data, "segments")
    words = version(data, SCRIPT_WORD_METHOD)
    portal.require(original == old_version and words["id"] != original["id"],
                   "d02_historical_transcript_version_preserved")
    repeated = browser_post_json(page, path, {})
    portal.require(repeated["status"] == 202 and repeated["body"]["id"] == sent["id"]
                   and repeated["body"]["status"] == "completed", "d02_historical_alignment_reused")
    report["historical_alignment"] = {"id": sent["id"], "seconds_to_ready": round(monotonic() - elapsed, 2),
                                      "segment_version": original["id"], "word_version": words["id"],
                                      "alternate": words["alternate"]}
    portal.check(report, "d02_historical_alignment_is_idempotent_and_preserves_prior_transcript")
    return words


def transcript_units(item):
    return [unit for segment in item["segments"] for unit in segment["words"] or [segment]]


def unit(page, reference):
    return page.locator(f'#transcript-text [data-transcript-unit="{reference["id"]}"]')


def choose_late(item):
    segments = item["segments"]
    seen = {}
    for left, right in zip(segments, segments[1:]):
        for first in left["words"]:
            folded = re.sub(r"[^\w]+", "", first["text"].casefold())
            earlier = seen.setdefault(folded, first)
            if first["start"] < 1100 or len(folded) < 2 or first["id"] == earlier["id"]:
                continue
            valid = [last for last in right["words"] if 4 <= last["end"] - first["start"] <= 14]
            if valid:
                return first, valid[-1], earlier
    raise portal.BrowserAcceptanceError("d02_no_late_repeated_word_cross_segment_range")


def range_receipt(item, first, last):
    return {"version": item["id"], "first": first["id"], "last": last["id"]}


def mark(page, first, last, *, keyboard=False):
    for edge, reference in (("start", first), ("end", last)):
        unit(page, reference).click()
        action = page.locator("#transcript-mark-" + edge)
        if keyboard:
            action.press("Enter")
        else:
            action.click()


def drag(page, first, last):
    left, right = unit(page, first), unit(page, last)
    left.scroll_into_view_if_needed()
    right.scroll_into_view_if_needed()
    a, b = left.bounding_box(), right.bounding_box()
    portal.require(a is not None and b is not None, "d02_desktop_text_spans_visible")
    page.mouse.move(a["x"] + 1, a["y"] + a["height"] / 2)
    page.mouse.down()
    page.mouse.move(b["x"] + b["width"] - 1, b["y"] + b["height"] / 2, steps=12)
    page.mouse.up()


def create_draft(page, job, item, first, last, *, tolerance=.002):
    path = root(job) + "/drafts"
    response = portal.click_response(page, page.locator("#transcript-create"), path, "POST", 201)
    expected = range_receipt(item, first, last)
    portal.require(response.request.post_data_json == expected, "d02_browser_submitted_exact_references")
    saved = response.json()
    origin = saved["selection_origin"]
    portal.require(portal.ID.fullmatch(saved["id"]) and origin["mode"] == "transcript"
                   and origin["transcript_version"] == expected["version"]
                   and origin["method"] == item["method"]
                   and origin["first"] == expected["first"] and origin["last"] == expected["last"]
                   and abs(saved["start"] - first["start"]) < tolerance and abs(saved["end"] - last["end"]) < tolerance
                   and (origin["start"], origin["end"]) == (saved["start"], saved["end"])
                   and portal.SHA256.fullmatch(origin["transcript_sha256"])
                   and origin["source_generation"] and origin["transcript_generation"],
                   "d02_draft_version_source_and_absolute_range")
    if item["method"] == SCRIPT_WORD_METHOD:
        portal.require(portal.SHA256.fullmatch(origin["alignment_sha256"])
                       and origin["alignment_generation"] and origin["model_revision"],
                       "d02_draft_faster_whisper_provenance")
    page.wait_for_function("""id => document.querySelector('#editorial-drafts')?.value === id
        && document.querySelector('#editorial-save')?.disabled === false""", arg=saved["id"])
    return saved


def visible_range(page, first, last):
    for name in ("start", "end", "duration"):
        value = page.locator("#transcript-selection-" + name)
        portal.require(value.is_visible() and re.search(r"\d", value.inner_text()), "d02_visible_selection_times")
    for reference in (first, last):
        span = unit(page, reference)
        portal.require("transcript-selected" in (span.get_attribute("class") or "").split()
                       and float(span.get_attribute("data-start")) == reference["start"]
                       and float(span.get_attribute("data-end")) == reference["end"], "d02_visible_absolute_unit_times")


def play_selected(page, first, last):
    page.locator("#transcript-play-selection").click()
    page.wait_for_function("""([start, end]) => {
        const video = document.querySelector('#transcript-source');
        const word = document.querySelector('#transcript-text .transcript-playing');
        return video.videoWidth && !video.paused && !video.error && !video.seeking
            && start - .12 <= video.currentTime && video.currentTime < end && word
            && Number(word.dataset.start) <= video.currentTime + .12
            && video.currentTime <= Number(word.dataset.end) + .12;
    }""", arg=[first["start"], last["end"]], timeout=60000)
    page.locator("#transcript-source").evaluate("video => video.pause()")


def play_from_text(page, part):
    page.locator(f'#transcript-text button[data-transcript-segment="{part["id"]}"]').click()
    page.wait_for_function("""([start, end]) => {
        const video = document.querySelector('#transcript-source');
        return video.videoWidth && !video.paused && !video.error && !video.seeking
            && start - .12 <= video.currentTime && video.currentTime < end;
    }""", arg=[part["start"], part["end"]], timeout=60000)
    page.locator("#transcript-source").evaluate("video => video.pause()")


def keyboard_selection(page, item):
    units = transcript_units(item)
    first = units[0]
    final_index = next(index for index, value in enumerate(units[:30])
                       if value["end"] - first["start"] >= 1.5)
    text = page.locator("#transcript-text")
    text.press("Home")
    page.locator("#transcript-mark-start").press("Enter")
    for _ in range(final_index):
        text.press("ArrowRight")
    page.locator("#transcript-mark-end").press("Enter")
    portal.require(text.locator(".transcript-cursor").get_attribute("data-transcript-unit") == units[final_index]["id"],
                   "d02_fully_keyboard_navigation_reaches_exact_reference")
    visible_range(page, first, units[final_index])
    page.locator("#transcript-clear").press("Enter")


def pcm(path, video, start, length):
    run_ffmpeg("-ss", start, "-i", video, "-t", length, "-map", "0:a:0",
               "-ac", 1, "-ar", SAMPLE_RATE, "-c:a", "pcm_s16le", path)
    with wave.open(str(path), "rb") as source:
        portal.require(source.getparams()[:3] == (1, 2, SAMPLE_RATE), "d02_pcm_mono_format")
        count = source.getnframes()
        return struct.unpack(f"<{count}h", source.readframes(count))


def audio_score(reference, observed, position, step, length):
    target = observed[position:position + length]
    target_energy = sum(value ** 2 for value in target)
    scores = []
    for offset in range(-step, step + 1, 4):
        expected = reference[position + offset:position + offset + length]
        energy = sum(value ** 2 for value in expected)
        if len(expected) == length and energy and target_energy:
            scores.append((sum(left * right for left, right in zip(expected, target))
                           / (energy * target_energy) ** .5, offset))
    portal.require(scores, "d02_missing_audio_energy")
    return max(scores)


def acoustic_evidence(video, export, start, end, scratch, evidence):
    length = end - start
    reference = pcm(scratch / "reference.wav", video, start, length)
    observed = pcm(scratch / "clip.wav", export, 0, length)
    shared = min(len(reference), len(observed))
    margin, piece = int(.05 * SAMPLE_RATE), int(.7 * SAMPLE_RATE)
    portal.require(shared >= 3 * SAMPLE_RATE and abs(shared / SAMPLE_RATE - length) <= .15,
                   "d02_pcm_matches_export_duration")
    positions = (margin, (shared - piece) // 2, shared - piece - margin)
    samples = [audio_score(reference, observed, position, margin, piece) for position in positions]
    portal.require(all(score >= .8 for score, _ in samples), "d02_export_audio_matches_requested_original_interval")
    edge = int(1.25 * SAMPLE_RATE)
    for label, signal in (("source", reference), ("export", observed)):
        values = (*signal[:edge], *(0,) * (SAMPLE_RATE // 3), *signal[shared - edge:shared])
        path = evidence / f"d02-{label}-audio-edges.wav"
        with wave.open(str(path), "wb") as target:
            target.setparams((1, 2, SAMPLE_RATE, 0, "NONE", "not compressed"))
            target.writeframes(struct.pack(f"<{len(values)}h", *values))
    return {"method": "mono_pcm_cross_correlation_at_head_middle_tail",
            "normalised_correlation": [round(score, 4) for score, _ in samples],
            "offset_ms": [round(offset * 1000 / SAMPLE_RATE, 2) for _, offset in samples],
            "listen_source": "d02-source-audio-edges.wav", "listen_export": "d02-export-audio-edges.wav"}


def edit_export(page, args, job, draft, first, last, scratch, report):
    job_id = job["id"]
    evidence = args.report.parent
    report["step"] = "d02_apply_style_logo_and_edit_subtitles"
    origin = draft["selection_origin"]
    draft_path = f"/jobs/{job_id}/drafts/{draft['id']}"
    png = scratch / "transcript-logo.png"
    logos.png(png, (255, 0, 255))
    logo = logos.upload_logo(page, png)
    panel = logos.open_panel(page, "#editorial-logos")
    panel.locator("[data-logo-field=enabled]").check()
    panel.locator("[data-logo-field=select]").select_option(f'{logo["id"]}:{logo["revision"]}')
    panel.locator("[data-logo-field=position]").select_option(logos.PLACEMENT["position"])
    for name, value in (("size", "20"), ("opacity", "60"), ("margin", "8")):
        panel.locator(f"[data-logo-field={name}]").fill(value)
    page.locator("#editorial-color-hex").fill(SUBTITLE_COLOR)
    page.locator("#editorial-position").select_option("bottom")
    page.locator("#editorial-burn").check()
    style = fixture.save_new_style(page, "editorial", "Estilo del recorte por transcripción", SUBTITLE_COLOR)
    portal.require(style["logo"]["id"] == logo["id"], "d02_style_contains_selected_logo")
    panel = logos.open_panel(page, "#editorial-styles")
    styles.pick(panel, style["id"])
    portal.click_response(page, styles.button(panel, "Aplicar estilo"), draft_path, "PUT", 200,
                          retry_draft_capacity=True)
    page.locator("#editorial-burn").check()
    start = round(max(0, draft["start"] - .12), 3)
    end = round(min(job["media"]["duration_seconds"], draft["end"] + .12), 3)
    page.locator("#editorial-start").fill(str(start))
    page.locator("#editorial-end").fill(str(end))
    portal.click_response(page, page.locator("#editorial-apply-range"), f"/jobs/{job_id}/editor/range",
                          "POST", 200, retry_range_capacity=True)
    page.get_by_text("Recorte aplicado. Guarda el borrador para conservarlo.", exact=True).wait_for()
    cue = page.locator('#editorial-cues [data-field="text"]').first
    text = cue.input_value().split(maxsplit=1)
    changed = text[1] if len(text) == 2 else "Subtítulo corregido."
    cue.fill(changed)
    page.locator("#editorial-title").fill("Pasaje tardío elegido en la transcripción")
    page.locator("#editorial-framing").select_option("crop")
    for name, value in (("x", "20"), ("y", "35"), ("zoom", "2.2")):
        page.locator("#editorial-crop-" + name).fill(value)
    saved = fixture.save_draft_color(page, job_id, draft["id"], SUBTITLE_COLOR)
    portal.require(saved["selection_origin"] == origin and (saved["start"], saved["end"]) == (start, end)
                   and saved["cues"][0]["text"] == changed and saved["logo"] == style["logo"]
                   and saved["style_template"] == {key: style[key] for key in ("id", "revision", "font")}
                   and [saved["options"][key] for key in ("framing", "crop_x", "crop_y", "crop_zoom")]
                   == ["crop", .2, .35, 2.2],
                   "d02_saved_draft_preserves_origin_and_changes_only_editable_values")

    report["step"] = "d02_reopen_draft_and_review_borders"
    portal.open_saved_job(page, job_id)
    portal.open_editorial(page)
    page.locator("#editorial-drafts").select_option(saved["id"])
    page.wait_for_function("""([start, end]) => Number(document.querySelector('#editorial-start')?.value) === start
        && Number(document.querySelector('#editorial-end')?.value) === end
        && document.querySelector('#editorial-save')?.disabled === false""", arg=[start, end])
    portal.require(d01.get_json(page, draft_path) == saved, "d02_reopened_exact_saved_draft")
    open_transcript(page)
    aligned = version(list_transcript(page, job_id), SCRIPT_WORD_METHOD)
    select_version(page, aligned)
    visible_range(page, first, last)
    for edge in ("start", "end"):
        page.locator("#editorial-preview-" + edge).click()
        page.wait_for_function("""edge => document.querySelector('#editorial-mark-' + edge)?.disabled === false""",
                               arg=edge, timeout=60000)
    page.locator("#editorial-framing-preview").click()
    page.locator("#editorial-framing-result").wait_for(timeout=60000)
    page.locator("#editorial-framing-composition").screenshot(path=evidence / "d02-draft.png", animations="disabled")
    portal.close_preview(page.locator("#editorial-source"))

    report["step"] = "d02_render_and_download_exact_export"
    export_id, _, _ = portal.start_editorial_export(page, job_id, saved)
    selected = mixed.exported(page, job_id, export_id, "editorial", scratch, (start, end), saved["cues"])
    published = d01.get_json(page, f"/jobs/{job_id}/exports")["exports"]
    export = next((row for row in published if row["id"] == export_id), None)
    portal.require(export is not None and export["draft_revision"] == saved["revision"]
                   and all(export[key] == saved[key] for key in ("selection_origin", "style_template", "logo", "options"))
                   and all(0 <= cue["start"] < cue["end"] <= end - start + .001 for cue in export["cues"]),
                   "d02_export_retains_origin_and_relative_sidecar_timing")
    mp4 = scratch / (selected["stem"] + ".mp4")
    media = probe_media(mp4, pilot=True)
    cue = max(saved["cues"], key=lambda row: row["end"] - row["start"])
    time = (cue["start"] + cue["end"]) / 2
    pixels = caption_color_stats(mp4, SUBTITLE_COLOR, seconds=time)["matching_pixels"]
    portal.require((media["width"], media["height"]) == (1080, 1920) and pixels >= 40,
                   "d02_download_has_portrait_and_burned_subtitles")
    rendered_logo = logos.frame_pixels(mp4, scratch)
    run_ffmpeg("-ss", time, "-i", mp4, "-frames:v", 1, "-threads", 1, "-update", 1, evidence / "d02-export.png")
    sound = acoustic_evidence(args.video, mp4, start, end, scratch, evidence)
    report["export"] = {"id": export_id, "draft_id": saved["id"], "draft_revision": saved["revision"],
                        "origin": origin, "adjusted_source_range": [start, end], "files": selected["files"],
                        "duration_seconds": media["duration_seconds"], "first_word": first, "last_word": last,
                        "caption_pixels": pixels, "logo_pixels": rendered_logo, "audio": sound}
    return selected


def phrase_words(item):
    for part in item["segments"]:
        words = part["words"]
        if len(words) >= 6 and 1.5 <= words[5]["end"] - words[0]["start"] <= 12:
            return words[0], words[5]
    raise portal.BrowserAcceptanceError("d02_no_short_phrase_range")


def invalid_selection(page, job, item):
    create = page.locator("#transcript-create")
    portal.require(create.is_disabled(), "d02_empty_selection_disables_creation")
    path = root(job) + "/drafts"
    portal.require(browser_post_json(page, path, {"version": item["id"]})["status"] == 422,
                   "d02_api_rejects_empty_selection")
    words = transcript_units(item)
    first = words[0]
    overlong = next(word for word in words if word["end"] - first["start"] >= 70)
    mark(page, first, overlong, keyboard=True)
    visible_range(page, first, overlong)
    portal.require(create.is_disabled(), "d02_overlong_selection_blocks_creation")
    receipt = range_receipt(item, first, overlong)
    result = browser_post_json(page, path, receipt)
    portal.require(result["status"] in {409, 422}, "d02_api_rejects_overlong_selection")
    result = browser_post_json(page, path, {**receipt, "version": "0" * 64})
    portal.require(result["status"] == 409, "d02_api_rejects_unknown_transcript_version")


def outsider_denied(browser, args, actor, job, refs):
    path = root(job)
    with portal.browser_page(browser) as page:
        fixture.owned_session(page, actor, args.commit)
        portal.require(portal.browser_get(page, path)["status"] == 404
                       and browser_post_json(page, path + "/prepare", {})["status"] == 404
                       and browser_post_json(page, path + "/drafts", refs)["status"] == 404,
                       "d02_cross_owner_transcript_and_mutations_denied")
        portal.logout(page)


def delete_and_check(page, job, version_item):
    path = root(job)
    first = transcript_units(version_item)[0]
    refs = range_receipt(version_item, first, first)
    portal.require(portal.browser_post(page, f"/jobs/{job}/deletion", {})["status"] == 202
                   and portal.browser_get(page, path)["status"] == 404
                   and browser_post_json(page, path + "/prepare", {})["status"] == 404
                   and browser_post_json(page, path + "/drafts", refs)["status"] == 404,
                   "d02_removed_project_rejects_stale_references_and_prepare")


def acceptance(browser, args, admin, report):
    state = state_file(args)
    portal.require(state["outsider"] is not None and state["prior_caption"] is not None
                   and set(state["jobs"]) == {"historical"}, "d02_historical_checkpoint_ready")
    historical = state["jobs"]["historical"]
    new = upload(browser, args, state, "new", report)
    job_id = new["id"]
    evidence = args.report.parent
    with tempfile.TemporaryDirectory(prefix="d02-browser-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        with portal.browser_page(browser) as page:
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            for job in (historical, job_id):
                portal.require(d01.get_json(page, f"/jobs/{job}/selections")["analyses"] == [],
                               "d02_no_editorial_searches_before_acceptance")

            report["step"] = "d02_historical_segment_fallback_and_on_demand_alignment"
            portal.open_saved_job(page, historical)
            open_transcript(page)
            before = list_transcript(page, historical)
            portal.require(before["alignment_status"] == "not_prepared" and len(before["versions"]) == 1,
                           "d02_legacy_project_starts_with_segment_granularity")
            old_version = version(before, "segments")
            select_version(page, old_version)
            portal.require(unit(page, old_version["segments"][0]).get_attribute("data-granularity") == "segment",
                           "d02_legacy_fallback_is_visibly_segment_granularity")
            coarse = next(row for row in old_version["segments"] if 1 <= row["end"] - row["start"] <= 60)
            mark(page, coarse, coarse)
            original_draft = create_draft(page, historical, old_version, coarse, coarse)
            page.locator("#transcript-granularity").screenshot(path=evidence / "d02-segments.png", animations="disabled")
            historical_words = prepare_historical(page, historical, before, report)
            select_version(page, historical_words)
            prior = state["prior_caption"]
            corrected = portal.read_caption(page, historical, prior["file"])
            draft_path = f"/jobs/{historical}/drafts/{original_draft['id']}"
            portal.require(fingerprint(corrected) == prior["state_sha256"]
                           and d01.get_json(page, draft_path) == original_draft,
                           "d02_alignment_preserves_preexisting_corrected_caption_and_segment_draft")

            report["step"] = "d02_new_processing_has_word_marks_and_desktop_text_selection"
            portal.open_saved_job(page, job_id)
            open_transcript(page)
            current = list_transcript(page, job_id)
            portal.require(current["alignment_status"] == "ready", "d02_new_job_completed_native_word_alignment")
            words = version(current, SCRIPT_WORD_METHOD)
            select_version(page, words)
            invalid_selection(page, job_id, words)
            portal.open_saved_job(page, job_id)
            open_transcript(page)
            select_version(page, words)
            page.set_viewport_size({"width": 390, "height": 844})
            keyboard_selection(page, words)
            page.set_viewport_size({"width": 1280, "height": 900})
            first, last = phrase_words(words)
            drag(page, first, last)
            visible_range(page, first, last)
            page.locator("#transcript-times").screenshot(path=evidence / "d02-desktop.png", animations="disabled")
            small = create_draft(page, job_id, words, first, last)
            portal.require(small["end"] - small["start"] < 20, "d02_short_cut_allowed_below_upload_minimum")
            portal.check(report, "d02_desktop_text_selection_and_short_clip")

            report["step"] = "d02_narrow_keyboard_repeated_word_and_cross_segment"
            page.set_viewport_size({"width": 390, "height": 844})
            first, last, earlier = choose_late(words)
            mark(page, first, last, keyboard=True)
            visible_range(page, first, last)
            portal.require(earlier["id"] != first["id"] and earlier["start"] < first["start"],
                           "d02_repeated_word_resolved_by_identity")
            panel = page.locator("#transcript-heading").locator("..")
            portal.require(panel.evaluate("el => el.getBoundingClientRect().right <= innerWidth + 1"),
                           "d02_narrow_transcript_inside_viewport")
            page.locator("#transcript-times").screenshot(path=evidence / "d02-narrow.png", animations="disabled")
            part = next(segment for segment in words["segments"] if first in segment["words"])
            play_from_text(page, part)
            play_selected(page, first, last)
            late = create_draft(page, job_id, words, first, last)
            portal.require(late["id"] != small["id"], "d02_different_selection_creates_independent_draft")
            refs = range_receipt(words, first, last)
            outsider_denied(browser, args, state["outsider"], job_id, refs)
            page.set_viewport_size({"width": 1280, "height": 900})
            portal.check(report, "d02_narrow_keyboard_selects_late_cross_segment_and_right_repeated_word")
            report["repeated_word"] = {"selected": first, "earlier": earlier}
            report["word_alignment"] = {"version": words["id"], "segments": len(words["segments"]),
                                        "words": len(transcript_units(words)), "method": words["method"]}

            editorial = edit_export(page, args, new, late, first, last, scratch, report)
            report["step"] = "d02_exact_mixed_zip_and_clip_preservation"
            automatic = mixed.automatic(page, job_id, new["clips"][0], scratch)
            report["package"] = d01.verify_zip(page, job_id, automatic, editorial, scratch, scratch)
            (scratch / "d01-mixed-zip.png").replace(evidence / "d02-mixed-zip.png")
            for job in (historical, job_id):
                portal.require(d01.get_json(page, f"/jobs/{job}/selections")["analyses"] == [],
                               "d02_transcript_editing_makes_no_editorial_reservations")
            portal.check(report, "d02_rendered_clip_srt_vtt_and_mixed_zip_agree_without_ai")

            report["step"] = "d02_removed_work_stays_deleted_with_stale_selection"
            delete_and_check(page, historical, historical_words)
            portal.require(portal.browser_get(page, root(job_id))["status"] == 200,
                           "d02_deleting_fixture_leaves_other_work_operational")
            portal.check(report, "d02_stale_transcript_requests_cannot_revive_deleted_project")
            portal.logout(page)


def cleanup(browser, args, admin, report):
    if not args.state.exists():
        return
    state = state_file(args)
    actors = [state, state["outsider"]] if state["outsider"] is not None else [state]
    accounts = [actor["account"] for actor in actors]
    jobs = list(state["jobs"].values())
    report["synthetic_owners"] = [actor["owner_id"] for actor in actors]
    report["synthetic_projects"] = jobs
    # The historical project was already deleted to check stale requests.
    if jobs:
        with portal.browser_page(browser) as page:
            fixture.owned_session(page, state, args.commit)
            jobs = [job for job in jobs if portal.browser_get(page, f"/jobs/{job}")["status"] != 404]
            portal.logout(page)
    styles.cleanup(browser, args, admin, accounts, jobs, report)
    report["synthetic_projects_logically_deleted"] += len(state["jobs"]) - len(jobs)
