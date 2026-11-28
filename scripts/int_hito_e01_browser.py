"""Protected browser and encoded-frame acceptance for word highlighting in INT."""

import shutil
import tempfile
from datetime import datetime, timezone
from fractions import Fraction
from pathlib import Path
from time import monotonic

from app.render import run_ffmpeg
from scripts import int_hito_b_browser as portal
from scripts import int_hito_c_caption_color_browser as fixture
from scripts import int_hito_c_logos_browser as logos
from scripts import int_hito_c_mixed_zip_browser as mixed
from scripts import int_hito_c_styles_browser as styles
from scripts import int_hito_d01_browser as d01
from scripts import int_hito_d02_browser as d02
from scripts import int_hito_d03_browser as d03


BASE_COLOR = "#00FFFF"
ACTIVE_COLOR = "#FF2800"
BASE_RGB = (0, 255, 255)
ACTIVE_RGB = (255, 40, 0)
HIGHLIGHT = "subtitle_highlight_enabled"
HIGHLIGHT_COLOR = "subtitle_highlight_color"
ROI_WIDTH = 1080
ROI_HEIGHT = 480
ROI_TOP = 1320
MEDIA_ALIASES = {"short": "e01-short-highlight.mp4", "highlight": "e01-late-highlight.mp4",
                 "static": "e01-late-static.mp4"}


def utc():
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def start_project(browser, args, admin, report):
    with portal.browser_page(browser) as page:
        portal.login(page, admin, args.commit)
        page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
        owner = d02.add_account(page)
        state = {**owner, "outsider": None, "jobs": {}, "prior_caption": None,
                 "video_sha256": portal.digest_of(args.video)}
        portal.shared_http.write_new(args.state, state)
        state["outsider"] = d02.add_account(page)
        d02.checkpoint(args, state, report)
        portal.logout(page)
    began = utc()
    job = d02.upload(browser, args, state, "new", report)
    report["timing_subjects"] = {"process": job["id"]}
    report["phase_utc"] = {"process": {"start": began, "finish": utc()}}
    report["processing_receipts"] = {"process": job["processing_receipt"]}
    return state, job


def highlight_plan(page, job, draft):
    origin = draft["selection_origin"]
    body = {key: draft[key] for key in ("start", "end", "cues")}
    body["version"] = origin["transcript_version"]
    result = d02.browser_post_json(page, f"/jobs/{job}/caption-highlight", body)
    portal.require(result["status"] == 200, "e01_highlight_plan_public_endpoint")
    plan = result["body"]
    portal.require(plan["timing"] == "centiseconds"
                   and plan["version"] == origin["transcript_version"], "e01_plan_pins_exact_transcript_version")
    return plan


def expect_plan(plan, draft):
    rows = plan["cues"]
    origin = draft["selection_origin"]
    portal.require(plan["alignment_sha256"] == origin["alignment_sha256"]
                   and plan["alignment_generation"] == origin["alignment_generation"]
                   and plan["method"] == d02.SCRIPT_WORD_METHOD and rows, "e01_words_use_saved_faster_whisper_marks")
    ids = set()
    for row in rows:
        cue = draft["cues"][row["index"]]
        lower, upper = cue["start"], cue["end"]
        previous = lower - .011
        for word in row["words"]:
            start, end = word["start"], word["end"]
            left, right = word["offset_start"], word["offset_end"]
            portal.require(previous - .001 <= start < end <= upper + .011
                           and 0 <= left < right <= len(cue["text"])
                           and word["id"] not in ids and abs(start * 100 - round(start * 100)) < .01
                           and abs(end * 100 - round(end * 100)) < .01,
                           "e01_valid_local_word_edges_and_stable_ids")
            previous = end
            ids.add(word["id"])
    return [(row["index"], word) for row in rows for word in row["words"]]


def frame_clock(path, scratch):
    receipt = scratch / f"{path.stem}-frames.hash"
    run_ffmpeg("-copyts", "-i", path, "-map", "0:v:0", "-an", "-vf", "scale=2:2", "-c:v", "rawvideo",
               "-threads", 1, "-fps_mode", "passthrough", "-enc_time_base:v", "1/1000000", "-f", "framehash", receipt)
    lines = receipt.read_text(encoding="ascii").splitlines()
    scale = Fraction(next(line.rsplit(":", 1)[1].strip() for line in lines if line.startswith("#tb 0:")))
    ticks = [int(line.split(",")[2].strip()) for line in lines if line and not line.startswith("#")]
    portal.require(len(ticks) > 4 and all(left < right for left, right in zip(ticks, ticks[1:])),
                   "e01_encoded_video_has_monotonic_frame_timestamps")
    return [float(scale * tick) for tick in ticks]


def select_frame(times, start, end):
    center = (start + end) / 2
    eligible = [(index, stamp) for index, stamp in enumerate(times) if start + .012 <= stamp < end - .012]
    return min(eligible, key=lambda result: abs(center - result[1]), default=None)


def reference_frames(draft, words, times, *, extended=False):
    candidates = []
    for label, row in (("first", words[0]), ("last", words[-1])):
        index, word = row
        stamp = select_frame(times, word["start"], word["end"])
        portal.require(stamp is not None, "e01_first_and_last_have_measurable_video_frames")
        candidates.append({"label": label, "cue": index, "word": word, "n": stamp[0], "seconds": stamp[1]})
    if not extended:
        return candidates
    by_text = {}
    gap = repeat = transition = None
    for left, right in zip(words, words[1:]):
        first_index, first = left
        last_index, last = right
        first_frame = select_frame(times, first["start"], first["end"])
        last_frame = select_frame(times, last["start"], last["end"])
        if first_frame and last_frame and first_index != last_index and transition is None:
            transition = [(first_index, first, first_frame), (last_index, last, last_frame)]
        if first_index == last_index and gap is None:
            frame = select_frame(times, first["end"], last["start"])
            if frame is not None:
                gap = {"label": "speech-gap", "cue": first_index, "word": None, "n": frame[0], "seconds": frame[1]}
    if gap is None:
        for cue_index, cue in enumerate(draft["cues"]):
            marks = [word for index, word in words if index == cue_index]
            if not marks:
                continue
            for start, end in ((cue["start"], marks[0]["start"]), (marks[-1]["end"], cue["end"])):
                frame = select_frame(times, start, end)
                if frame is not None:
                    gap = {"label": "speech-gap", "cue": cue_index, "word": None, "n": frame[0], "seconds": frame[1]}
                    break
            if gap:
                break
    for index, word in words:
        key = word["text"].strip(" 	.,;:¿?¡!").casefold()
        stamp = select_frame(times, word["start"], word["end"])
        if key and stamp is not None:
            prior = by_text.setdefault(key, (index, word, stamp))
            if prior[1]["id"] != word["id"]:
                repeat = [prior, (index, word, stamp)]
                break
    portal.require(gap and repeat and transition, "e01_samples_include_gap_repeat_and_subtitle_transition")
    for label, pair in (("repeated", repeat), ("cue-transition", transition)):
        for number, (index, word, stamp) in enumerate(pair, 1):
            candidates.append({"label": f"{label}-{number}", "cue": index, "word": word,
                               "n": stamp[0], "seconds": stamp[1]})
    candidates.append(gap)
    for sample in candidates:
        cue = draft["cues"][sample["cue"]]
        portal.require(cue["start"] - .011 <= sample["seconds"] < cue["end"] + .011,
                       "e01_sampling_stays_inside_the_visible_subtitle")
    return candidates


def read_pixels(path, indices, scratch):
    frames = sorted(set(indices))
    expression = "+".join(f"eq(n,{index})" for index in frames)
    raw = scratch / f"{path.stem}-caption-frames.rgb"
    run_ffmpeg("-i", path, "-map", "0:v:0", "-an",
               "-vf", f"select='{expression}',crop={ROI_WIDTH}:{ROI_HEIGHT}:0:{ROI_TOP},format=rgb24",
               "-fps_mode", "passthrough", "-threads", 1, "-f", "rawvideo", raw)
    pixels = raw.read_bytes()
    step = ROI_WIDTH * ROI_HEIGHT * 3
    portal.require(len(pixels) == len(frames) * step, "e01_exact_requested_frame_extraction")
    return {number: color_mask(pixels[index * step:(index + 1) * step]) for index, number in enumerate(frames)}


def color_mask(pixels):
    base, active = set(), set()
    for offset in range(0, len(pixels), 3):
        red, green, blue = pixels[offset:offset + 3]
        if red < 58 and green > 196 and blue > 196:
            base.add(offset // 3)
        elif red > 196 and 0 <= green <= 98 and blue < 58:
            active.add(offset // 3)
    return base, active


def bounds(mask):
    rows, columns = zip(*(divmod(index, ROI_WIDTH) for index in mask), strict=True)
    return min(columns), min(rows), max(columns), max(rows)


def measure_frames(active, static, reference, scratch, evidence, label):
    active_frames = read_pixels(active, [item["n"] for item in reference], scratch)
    static_frames = read_pixels(static, [item["n"] for item in reference], scratch) if static else None
    measures = []
    for item in reference:
        base, marked = active_frames[item["n"]]
        match = item["word"] is not None
        portal.require(bool(base | marked) and (len(marked) >= 15 if match else len(marked) <= 5),
                       "e01_mp4_active_color_only_inside_the_word_interval")
        observed = base | marked
        entry = {**item, "base_pixels": len(base), "active_pixels": len(marked),
                 "active_bounds": bounds(marked) if marked else None, "caption_bounds": bounds(observed)}
        if static_frames is not None:
            fixed, unexpected = static_frames[item["n"]]
            portal.require(fixed and len(unexpected) <= 5, "e01_static_export_has_only_base_caption_color")
            similarity = len(fixed & observed) / len(fixed | observed)
            portal.require(similarity >= .88 and max(abs(a - b) for a, b in zip(bounds(fixed), bounds(observed))) <= 3,
                           "e01_word_highlight_keeps_physical_line_layout")
            entry["glyph_mask_overlap"] = round(similarity, 4)
        measures.append(entry)
    for item in reference:
        if item["label"] in {"first", "last", "speech-gap", "repeated-2"}:
            target = evidence / f"e01-{label}-{item['label']}.png"
            run_ffmpeg("-i", active, "-map", "0:v:0", "-vf", f"select='eq(n,{item['n']})'",
                       "-frames:v", 1, "-threads", 1, "-update", 1, target)
    return measures


def create_draft(page, job, item, first, last):
    d02.open_transcript(page)
    d02.select_version(page, item)
    d02.mark(page, first, last, keyboard=True)
    return d02.create_draft(page, job, item, first, last)


def set_highlight(page, enabled):
    control = page.locator("#editorial-highlight-enabled")
    control.set_checked(enabled)
    portal.require(control.is_checked() is enabled, "e01_requested_highlight_toggle")


def set_colors(page):
    page.locator("#editorial-color-hex").fill(BASE_COLOR)
    page.locator("#editorial-highlight-color-hex").fill(ACTIVE_COLOR)
    portal.require(page.locator("#editorial-color").input_value().upper() == BASE_COLOR
                   and page.locator("#editorial-highlight-color").input_value().upper() == ACTIVE_COLOR,
                   "e01_native_and_hex_active_and_base_colors_synchronized")


def apply_logo(page, scratch):
    image = scratch / "e01-logo.png"
    logos.png(image, (255, 0, 255))
    item = logos.upload_logo(page, image)
    panel = logos.open_panel(page, "#editorial-logos")
    panel.locator("[data-logo-field=enabled]").check()
    panel.locator("[data-logo-field=select]").select_option(f'{item["id"]}:{item["revision"]}')
    for key in ("size", "opacity", "margin"):
        value = 60 if key == "opacity" else logos.PLACEMENT[key]
        panel.locator(f"[data-logo-field={key}]").fill(str(value))
    panel.locator("[data-logo-field=position]").select_option(logos.PLACEMENT["position"])
    return item


def save_draft(page, job, draft, enabled):
    saved = fixture.save_draft_color(page, job, draft["id"], BASE_COLOR)
    portal.require(saved["options"][HIGHLIGHT] is enabled
                   and saved["options"][HIGHLIGHT_COLOR] == ACTIVE_COLOR, "e01_draft_persists_word_highlight_and_color")
    return saved


def save_active_template(page, job, draft, scratch):
    logo = apply_logo(page, scratch)
    page.locator("#editorial-burn").check()
    page.locator("#editorial-position").select_option("bottom")
    set_highlight(page, True)
    set_colors(page)
    template = fixture.save_new_style(page, "editorial", "Resaltado de palabra E01", BASE_COLOR)
    portal.require(template["style"][HIGHLIGHT] is True and template["style"][HIGHLIGHT_COLOR] == ACTIVE_COLOR
                   and template["logo"]["id"] == logo["id"], "e01_named_template_preserves_highlight_and_logo")
    saved = apply_template(page, job, draft, template)
    portal.require(saved["options"][HIGHLIGHT] is True and saved["options"][HIGHLIGHT_COLOR] == ACTIVE_COLOR,
                   "e01_highlight_style_applied_to_real_draft")
    return saved, template


def apply_template(page, job, draft, template):
    panel = logos.open_panel(page, "#editorial-styles")
    styles.pick(panel, template["id"])
    path = f"/jobs/{job}/drafts/{draft['id']}"
    saved = portal.click_response(page, styles.button(panel, "Aplicar estilo"), path, "PUT", 200,
                                  retry_draft_capacity=True).json()
    portal.require(saved["style_template"] == {key: template[key] for key in ("id", "revision", "font")}
                   and saved["logo"] == template["logo"] and d01.get_json(page, path) == saved,
                   "e01_style_revision_persisted_and_read_back")
    return saved


def read_export(page, job, clip):
    rows = d01.get_json(page, f"/jobs/{job}/exports")["exports"]
    found = next((item for item in rows if item["id"] == clip["identity"]), None)
    portal.require(found is not None, "e01_export_receipt_public_collection")
    return found


def render(page, job, draft, enabled, plan, scratch, evidence, label, report):
    before, start = utc(), monotonic()
    identity, _, _ = portal.start_editorial_export(page, job, draft)
    report["timing_subjects"][label + "_export"] = identity
    clip = mixed.exported(page, job, identity, "editorial", scratch, (draft["start"], draft["end"]), draft["cues"])
    report["phase_utc"][label + "_export"] = {"start": before, "finish": utc(),
                                             "browser_elapsed_seconds": round(monotonic() - start, 2)}
    item = read_export(page, job, clip)
    report["processing_receipts"][label + "_export"] = item["processing_receipt"]
    portal.require(item["draft_revision"] == draft["revision"] and item["options"] == draft["options"]
                   and item["options"][HIGHLIGHT] is enabled and item["logo"] == draft["logo"]
                   and item["selection_origin"] == draft["selection_origin"], "e01_export_pins_style_and_source")
    if enabled:
        portal.require(item["word_highlight"] == plan, "e01_mp4_render_uses_exact_measured_word_plan")
    path = scratch / (clip["stem"] + ".mp4")
    if label in MEDIA_ALIASES:
        shutil.copyfile(path, evidence / MEDIA_ALIASES[label])
    return clip, path


def seek(page, second):
    return page.locator("#editorial-source").evaluate("""async (video, second) => {
        video.pause();
        if (!video.videoWidth) {
            const event = new Promise((accept, reject) => {
                video.addEventListener('loadedmetadata', accept, {once: true});
                video.addEventListener('error', reject, {once: true});
            });
            video.load();
            await event;
        }
        if (Math.abs(video.currentTime - second) > .001) {
            const event = new Promise(accept => video.addEventListener('seeked', accept, {once: true}));
            video.currentTime = second;
            if (video.seeking) await event;
        }
        return video.currentTime;
    }""", second)


def read_preview(page, expected_word):
    text = page.locator("#editorial-sample .caption-frame > span")
    text.wait_for()
    page.wait_for_function("""expected => {
        const marked = document.querySelectorAll('#editorial-sample [data-caption-word][data-active=true]');
        return expected === null ? !marked.length
            : marked.length === 1 && marked[0].dataset.captionWord === expected;
    }""", arg=expected_word, timeout=20000)
    data = text.evaluate("""element => {
        const frame = element.parentElement.getBoundingClientRect();
        const words = [...element.querySelectorAll('[data-caption-word]')];
        const active = words.find(word => word.dataset.active === "true");
        const range = document.createRange();
        range.selectNodeContents(element);
        const lines = new Map();
        for (const box of range.getClientRects()) {
            const y = Math.round((box.top - frame.top) * 100) / 100;
            const x = [box.left - frame.left, box.right - frame.left];
            const prev = lines.get(y) || x;
            lines.set(y, [Math.min(prev[0], x[0]), Math.max(prev[1], x[1])]);
        }
        return {text: element.textContent, lines: [...lines], active: active?.dataset.captionWord ?? null,
            active_color: active ? getComputedStyle(active).color : null,
            base_color: getComputedStyle(element).color};
    }""")
    portal.require(data["base_color"] == "rgb(0, 255, 255)"
                   and (data["active_color"] == "rgb(255, 40, 0)" if expected_word else data["active_color"] is None),
                   "e01_preview_colors_match_selected_hex_values")
    return data


def preview_frames(page, draft, samples, evidence, label):
    outputs = []
    for item in sorted(samples, key=lambda row: row["seconds"]):
        effective = seek(page, draft["start"] + item["seconds"])
        expected = item["word"]["id"] if item["word"] else None
        view = read_preview(page, expected)
        portal.require(abs(effective - draft["start"] - item["seconds"]) < .015
                       and view["text"] == draft["cues"][item["cue"]]["text"], "e01_browser_and_mp4_use_same_sample_times")
        outputs.append({"label": item["label"], "effective_source_seconds": effective,
                        "clip_seconds": item["seconds"], **view})
        if item["label"] == "first":
            page.locator("#editorial-sample .caption-frame").screenshot(
                path=evidence / f"e01-{label}-preview.png", animations="disabled")
    return outputs


def exercise_player(page, draft, words):
    source = page.locator("#editorial-source")
    sample = next(word for _, word in words if word["end"] - word["start"] >= .18)
    begin = draft["start"] + max(0, sample["start"] - .055)
    seek(page, begin)
    try:
        source.evaluate("""async video => {
            video.muted = true;
            video.playbackRate = 1.5;
            await video.play();
        }""")
        paused = source.evaluate("""async (video, edge) => {
            const cap = performance.now() + 6000;
            while (video.currentTime < edge && performance.now() < cap) {
                await new Promise(requestAnimationFrame);
            }
            const running = !video.paused;
            video.pause();
            return {time: video.currentTime, running, rate: video.playbackRate};
        }""", draft["start"] + sample["start"] + .04)
        portal.require(paused["running"] and paused["rate"] == 1.5
                       and draft["start"] + sample["start"] <= paused["time"] < draft["start"] + sample["end"],
                       "e01_player_uses_actual_time_at_changed_speed")
        state = read_preview(page, sample["id"])
        page.wait_for_timeout(250)
        portal.require(source.evaluate("video => ({time: video.currentTime, paused: video.paused})")
                       == {"time": paused["time"], "paused": True} and read_preview(page, sample["id"]) == state,
                       "e01_pause_holds_word_without_independent_clock")
        source.evaluate("video => video.play()")
        page.wait_for_function("""time => {
            const video = document.querySelector('#editorial-source');
            return !video.paused && video.currentTime > time + .07;
        }""", arg=paused["time"], timeout=6000)
    finally:
        source.evaluate("video => { video.pause(); video.playbackRate = 1; }")


def reopen_draft(page, job, saved):
    portal.open_saved_job(page, job)
    portal.open_editorial(page)
    page.wait_for_function("() => document.querySelector('#editorial-save:enabled')?.getClientRects().length > 0")
    page.locator("#editorial-drafts").select_option(saved["id"])
    page.wait_for_function("""([id, start, end]) => document.querySelector('#editorial-drafts')?.value === id
        && document.querySelector('#editorial-save:enabled')
        && document.querySelector('#editorial-start')?.valueAsNumber === start
        && document.querySelector('#editorial-end')?.valueAsNumber === end""",
        arg=[saved["id"], saved["start"], saved["end"]])
    persisted = d01.get_json(page, f"/jobs/{job}/drafts/{saved['id']}")
    portal.require(persisted == saved, "e01_reopened_exact_draft_revision")


def cue_rows(page):
    return page.locator("#editorial-cues .editorial-cue")


def pause_margin(page, job, draft):
    end = round(draft["end"] + .28, 3)
    page.locator("#editorial-end").fill(str(end))
    portal.click_response(page, page.locator("#editorial-apply-range"), f"/jobs/{job}/editor/range",
                          "POST", 200, retry_range_capacity=True)
    page.get_by_text("Recorte aplicado. Guarda el borrador para conservarlo.", exact=True).wait_for()
    rows = cue_rows(page)
    expected = [dict(cue) for cue in draft["cues"]]
    expected[-1]["end"] = round(end - draft["start"] - .03, 3)
    while rows.count() > len(expected):
        rows.last.get_by_role("button", name="Quitar subtítulo", exact=True).click()
    while rows.count() < len(expected):
        page.locator("#editorial-add-cue").click()
    for number, cue in enumerate(expected):
        for field in ("start", "end", "text"):
            rows.nth(number).locator(f'[data-field="{field}"]').fill(str(cue[field]))
    saved = save_draft(page, job, draft, True)
    portal.require(saved["end"] == end and saved["start"] == draft["start"] and saved["cues"] == expected
                   and saved["selection_origin"] == draft["selection_origin"],
                   "e01_adjusted_bounds_preserve_selected_words_with_visible_tail_pause")
    return saved


def compare_pair(static, active):
    style = {**static["options"], HIGHLIGHT: True}
    portal.require(static["options"][HIGHLIGHT] is False and active["options"] == style
                   and all(static[key] == active[key] for key in ("start", "end", "logo", "cues", "selection_origin")),
                   "e01_only_effect_changes_in_same_range_logo_subtitles_and_position")


def assert_selected_edges(words, first, last):
    portal.require(words[0][1]["id"] == first["id"] and words[-1][1]["id"] == last["id"],
                   "e01_first_and_last_word_use_exact_selected_transcript_references")


def verify_preview_layout(active, static):
    observed = active["lines"]
    baseline = static["lines"]
    deviations = [abs(one - two) for (top, line), (other, reference) in zip(observed, baseline)
                  for one, two in zip([top, *line], [other, *reference], strict=True)]
    portal.require(observed and len(observed) == len(baseline) and max(deviations) <= 2,
                   "e01_preview_highlight_preserves_horizontal_wrap_and_line_position")


def short_clip(page, job, version, scratch, evidence, report):
    first, last = d02.phrase_words(version)
    draft = create_draft(page, job, version, first, last)
    portal.require(not page.locator("#editorial-highlight-enabled").is_checked()
                   and draft["options"][HIGHLIGHT] is False, "e01_existing_default_uses_static_subtitles")
    saved, template = save_active_template(page, job, draft, scratch)
    plan = highlight_plan(page, job, saved)
    words = expect_plan(plan, saved)
    assert_selected_edges(words, first, last)
    _, path = render(page, job, saved, True, plan, scratch, evidence, "short", report)
    samples = reference_frames(saved, words, frame_clock(path, scratch))
    report["short"] = {"range": [saved["start"], saved["end"]], "word_alignment_version": plan["version"],
                       "template": {key: template[key] for key in ("id", "revision", "font")},
                       "preview": preview_frames(page, saved, samples, evidence, "short"),
                       "encoded": measure_frames(path, None, samples, scratch, evidence, "short")}
    exercise_player(page, saved, words)
    portal.close_preview(page.locator("#editorial-source"))
    portal.check(report, "e01_short_clip_first_last_and_playback_rate_pause_resume")
    return saved, plan, template


def late_clips(page, job, version, template, scratch, evidence, report):
    portal.open_saved_job(page, job)
    first, last, earlier = d02.choose_late(version)
    initial = create_draft(page, job, version, first, last)
    saved = apply_template(page, job, initial, template)
    active = pause_margin(page, job, saved)
    plan = highlight_plan(page, job, active)
    words = expect_plan(plan, active)
    assert_selected_edges(words, first, last)

    set_highlight(page, False)
    static = save_draft(page, job, active, False)
    compare_pair(static, active)
    static_clip, static_path = render(page, job, static, False, None, scratch, evidence, "static", report)

    set_highlight(page, True)
    active = save_draft(page, job, static, True)
    compare_pair(static, active)
    active_clip, active_path = render(page, job, active, True, plan, scratch, evidence, "highlight", report)
    portal.require(static_clip["files"]["mp4"]["sha256"] != active_clip["files"]["mp4"]["sha256"]
                   and all(static_clip["files"][suffix] == active_clip["files"][suffix] for suffix in ("srt", "vtt")),
                   "e01_effect_changes_only_mp4_not_standard_sidecars")
    times = frame_clock(active_path, scratch)
    portal.require(times == frame_clock(static_path, scratch), "e01_exact_static_and_highlight_frame_pts")
    samples = reference_frames(active, words, times, extended=True)
    preview = preview_frames(page, active, samples, evidence, "late")
    set_highlight(page, False)
    for sample in samples:
        cue_rows(page).nth(sample["cue"]).locator('.caption-text').focus()
        static_view = read_preview(page, None)
        highlighted = next(row for row in preview if row["label"] == sample["label"])
        portal.require(static_view["text"] == highlighted["text"], "e01_static_preview_keeps_exact_cue_text")
        verify_preview_layout(highlighted, static_view)
    set_highlight(page, True)
    page.set_viewport_size({"width": 390, "height": 844})
    sample = next(row for row in samples if row["label"] == "repeated-2")
    seek(page, active["start"] + sample["seconds"])
    read_preview(page, sample["word"]["id"])
    preview_frame = page.locator("#editorial-sample .caption-frame")
    portal.require(preview_frame.evaluate("element => element.getBoundingClientRect().right <= innerWidth + 1"),
                   "e01_word_preview_fits_narrow_viewport")
    preview_frame.screenshot(path=evidence / "e01-preview-narrow.png", animations="disabled")
    page.set_viewport_size({"width": 1280, "height": 900})
    portal.close_preview(page.locator("#editorial-source"))

    measurements = measure_frames(active_path, static_path, samples, scratch, evidence, "late")
    repeated = [row for row in measurements if row["label"].startswith("repeated")]
    portal.require(repeated[0]["word"]["id"] != repeated[1]["word"]["id"],
                   "e01_two_occurrences_of_repeated_word_resolve_by_id")
    report["late"] = {"interval": [active["start"], active["end"]], "original_refs": active["selection_origin"],
                      "earlier_word_occurrence": earlier, "preview": preview, "encoded": measurements,
                      "logo": logos.frame_pixels(active_path, scratch)}
    portal.check(report, "e01_late_first_last_repeat_pause_transition_and_same_geometry")
    return active, static_clip, active_clip


def acoustic_package(args, active, active_path, scratch, report, label):
    start, end = active["start"], active["end"]
    evidence = args.report.parent
    observed = d02.acoustic_evidence(args.video, active_path, start, end, scratch, scratch)
    for key in ("listen_source", "listen_export"):
        raw_path = scratch / observed[key]
        published = evidence / observed[key].replace("d02-", f"e01-{label}-")
        shutil.copyfile(raw_path, published)
        observed[key] = published.name
    context = evidence / f"e01-{label}-original-context.wav"
    context_start, context_end = round(max(0, start - 1.25), 3), round(min(1200, end + 1.25), 3)
    d02.pcm(context, args.video, context_start, context_end - context_start)
    report.setdefault("acoustic_review", {})[label] = {
        **observed, "new_evidence": True, "selected_range": [start, end],
        "source_context_range": [context_start, context_end], "source_context": context.name,
        "export": active_path.name, "human_listening": "pending",
    }


def edit_fallback(page, job, short, initial_plan, evidence, report):
    reopen_draft(page, job, short)
    row = cue_rows(page).first.locator('[data-field="text"]')
    original = row.input_value()
    row.fill(original.upper())
    preserved = save_draft(page, job, short, True)
    plan = highlight_plan(page, job, preserved)
    original_words = [word["id"] for cue in initial_plan["cues"] if cue["index"] == 0 for word in cue["words"]]
    preserved_words = [word["id"] for cue in plan["cues"] if cue["index"] == 0 for word in cue["words"]]
    portal.require(original_words and original_words == preserved_words
                   and preserved["cues"][0]["text"] == original.upper(), "e01_case_edit_preserves_exact_mark_identity")

    row.fill("Texto agregado " + original)
    changed = save_draft(page, job, preserved, True)
    plan = highlight_plan(page, job, changed)
    portal.require(len(plan["cues"]) == len(changed["cues"]) and not plan["cues"][0]["words"]
                   and changed["cues"][0]["text"] == "Texto agregado " + original,
                   "e01_edit_inserting_words_stays_static_and_preserves_text")
    cue = changed["cues"][0]
    seek(page, changed["start"] + (cue["start"] + cue["end"]) / 2)
    portal.require(read_preview(page, None)["text"] == cue["text"], "e01_incompatible_subtitle_remains_visible")
    status = page.locator("#editorial-highlight-status")
    portal.require(status.is_visible() and status.inner_text().strip(), "e01_visible_notice_for_missing_match")
    page.locator("#editorial-sample").screenshot(path=evidence / "e01-edited-static-fallback.png", animations="disabled")
    portal.close_preview(page.locator("#editorial-source"))
    report["edited_fallback"] = {"preserved_word_ids": original_words, "inserted_text": cue["text"],
                                 "unmatched_preview_notice": status.inner_text()}
    portal.check(report, "e01_case_edit_preserves_marks_insertion_keeps_subtitle_static")


def incomplete_fallback(page, job, version, template, evidence, report):
    parts = [segment for segment in version["segments"] if not segment["words"]
             and 1.2 <= segment["end"] - segment["start"] <= 45]
    portal.require(parts, "e01_actual_natural_transcript_has_an_incomplete_segment")
    part = parts[0]
    portal.open_saved_job(page, job)
    draft = create_draft(page, job, version, part, part)
    saved = apply_template(page, job, draft, template)
    plan = highlight_plan(page, job, saved)
    portal.require(saved["cues"] and len(plan["cues"]) == len(saved["cues"])
                   and all(not cue["words"] for cue in plan["cues"]),
                   "e01_missing_marks_preserve_caption_without_artificial_times")
    first = saved["cues"][0]
    seek(page, saved["start"] + (first["start"] + first["end"]) / 2)
    portal.require(read_preview(page, None)["text"] == first["text"]
                   and page.locator("#editorial-highlight-status").inner_text().strip(),
                   "e01_incomplete_natural_marks_display_static_subtitle_and_notice")
    page.locator("#editorial-highlight-status").screenshot(path=evidence / "e01-missing-marks.png", animations="disabled")
    report["natural_fallback"] = {"segment_id": part["id"], "range": [part["start"], part["end"]],
                                  "status": plan["status"], "reason": plan["reason"]}
    portal.close_preview(page.locator("#editorial-source"))
    portal.check(report, "e01_natural_segment_without_marks_remains_static")


def acceptance_package(page, job, project, static, highlighted, scratch, evidence, report):
    portal.open_saved_job(page, job)
    portal.open_editorial(page)
    automatic = mixed.automatic(page, job, project["clips"][0], scratch)
    d03.open_panel(page, static)
    fields = {"title": "Un pasaje de Don Quijote",
              "description": "Lectura en español de un fragmento del capítulo VIII.",
              "hashtags": ["#DonQuijote", "#Lectura"]}
    d03.save_manual(page, job, static, fields)
    saved = d03.require_saved(d03.publication(page, job, static), fields, 1)
    d03.close_panel(page)
    copied = d03.use_visual_reuse(page, job, static, highlighted, saved)
    texts = {clip["token"]: d03.reopen_saved(page, scratch, job, clip, receipt)
             for clip, receipt in ((static, saved), (highlighted, copied))}
    portal.require(texts[static["token"]]["file"]["raw"] == texts[highlighted["token"]]["file"]["raw"],
                   "e01_text_reuse_produces_identical_saved_publication_bytes")
    report["package"] = d03.package(page, job, [automatic, static, highlighted], texts, scratch, scratch)
    (scratch / "d03-mixed-zip.png").replace(evidence / "e01-mixed-zip.png")
    report["publication_reuse"] = copied["reused_from"]
    portal.check(report, "e01_exact_highlight_variant_standard_sidecars_and_saved_publication_in_zip")


def outsider_check(browser, args, state, job, draft):
    with portal.browser_page(browser) as page:
        fixture.owned_session(page, state["outsider"], args.commit)
        lack_access = d02.browser_post_json(page, f"/jobs/{job}/caption-highlight", {
            "start": draft["start"], "end": draft["end"], "cues": draft["cues"],
            "version": draft["selection_origin"]["transcript_version"],
        })
        portal.require(lack_access["status"] == 404 and portal.browser_get(page, f"/jobs/{job}/exports")["status"] == 404,
                       "e01_other_account_cannot_read_word_marks_or_exports")
        portal.logout(page)


def acceptance(browser, args, admin, report):
    report["step"] = "e01_fresh_twenty_minute_natural_video"
    state, project = start_project(browser, args, admin, report)
    job = project["id"]
    evidence = args.report.parent
    requests = []

    def monitor(request):
        if request.method == "POST" and request.url.startswith(f"{portal.PUBLIC}/jobs/{job}/"):
            forbidden = ("/selections/preview", "/selections", "/publication/suggestions", "/transcript-selection/prepare")
            if request.url.endswith(forbidden):
                requests.append(True)

    with tempfile.TemporaryDirectory(prefix="e01-browser-", dir=args.state.parent) as directory:
        scratch = Path(directory)
        with portal.browser_page(browser) as page:
            page.set_viewport_size({"width": 1280, "height": 900})
            fixture.owned_session(page, state, args.commit)
            portal.check_normal_permissions(page, report)
            portal.open_saved_job(page, job)
            timeline = d02.list_transcript(page, job)
            portal.require(timeline["alignment_status"] == "ready", "e01_normal_worker_prepares_native_word_marks")
            aligned = d02.version(timeline, d02.SCRIPT_WORD_METHOD)
            page.on("request", monitor)
            report["step"] = "e01_short_highlight_template_and_preview"
            short, short_plan, template = short_clip(page, job, aligned, scratch, evidence, report)
            acoustic_package(args, short, evidence / MEDIA_ALIASES["short"], scratch, report, "short")
            portal.logout(page)
            fixture.owned_session(page, state, args.commit)
            reopen_draft(page, job, short)
            library = d01.get_json(page, styles.STYLES)
            portal.require(template in library["styles"]
                           and page.locator("#editorial-highlight-enabled").is_checked()
                           and page.locator("#editorial-highlight-color-hex").input_value().upper() == ACTIVE_COLOR
                           and page.locator("#editorial-color-hex").input_value().upper() == BASE_COLOR,
                           "e01_creator_recovers_exact_style_and_active_hex_after_relogin")
            portal.check(report, "e01_saved_highlight_template_and_colors_recover_across_sessions")

            report["step"] = "e01_late_paired_export_and_frame_comparison"
            active, static_clip, active_clip = late_clips(page, job, aligned, template, scratch, evidence, report)
            acoustic_package(args, active, evidence / MEDIA_ALIASES["highlight"], scratch, report, "new-equivalent")

            report["step"] = "e01_insertion_and_incomplete_mark_fallback"
            edit_fallback(page, job, short, short_plan, evidence, report)
            incomplete_fallback(page, job, aligned, template, evidence, report)
            outsider_check(browser, args, state, job, active)

            report["step"] = "e01_package_exact_export_and_publication_revision"
            acceptance_package(page, job, project, static_clip, active_clip, scratch, evidence, report)
            current = d01.get_json(page, f"/jobs/{job}")
            portal.require(not requests and d01.get_json(page, f"/jobs/{job}/selections")["analyses"] == []
                           and current["processing_receipt"] == project["processing_receipt"],
                           "e01_no_automatic_alignment_transcription_or_openai")
            report["editorial_usage"] = {"reservations": 0, "calls": 0, "responses": 0}
            portal.check(report, "e01_colors_and_highlight_do_not_call_openai_or_repeat_asr")

            report["step"] = "e01_deleted_project_rejects_highlight_requests"
            deletion = portal.browser_post(page, f"/jobs/{job}/deletion", {})
            result = d02.browser_post_json(page, f"/jobs/{job}/caption-highlight", {
                "start": active["start"], "end": active["end"], "cues": active["cues"],
                "version": active["selection_origin"]["transcript_version"],
            })
            portal.require(deletion["status"] == 202 and result["status"] == 404
                           and portal.browser_get(page, f"/jobs/{job}/exports")["status"] == 404,
                           "e01_deleted_project_cannot_read_or_regenerate_highlight")
            portal.check(report, "e01_owner_boundary_and_immediate_deletion_preserved")
            portal.logout(page)


def cleanup(browser, args, admin, report):
    d02.cleanup(browser, args, admin, report)
