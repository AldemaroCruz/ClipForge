"""Accept both native-timestamp cuts through the real INT browser and worker."""
from pathlib import Path
import tempfile

from scripts import int_hito_b_browser as portal
from tests.test_hito_c_cuts import CUTS, frame_times, measure_cut


def review_edge(page, edge, time, frame_times_ms):
    field = page.locator("#editorial-" + edge)
    field.fill(str(time))
    page.locator("#editorial-preview-" + edge).click()
    page.wait_for_function("""time => {
        const source = document.querySelector('#editorial-source');
        return source.videoWidth > 0 && !source.paused && !source.seeking && !source.error
            && Math.abs(source.currentTime - time) <= 1.6;
    }""", arg=time, timeout=60_000)
    page.locator("#editorial-mark-" + edge).click()
    chosen = float(field.input_value())
    portal.require(abs(chosen - time) <= 1.6 and round(chosen * 1000) in frame_times_ms,
                   "precise_cut_mark_not_from_source_frame")
    field.fill(str(time))
    return chosen


def save_marker(page, job, start, end, marker):
    cue_start = round(marker - start, 3)
    cue = {"start": cue_start, "end": round(cue_start + 0.4, 3), "text": "Marcador de audio"}
    rows = page.locator("#editorial-cues .editorial-cue")
    for index in reversed(range(rows.count())):
        rows.nth(index).get_by_role("button", name="Quitar subtítulo").click()
    page.locator("#editorial-add-cue").click()
    portal.require(rows.count() == 1, "precise_cut_marker_cue_missing")
    for key, value in cue.items():
        rows.first.locator(f'[data-field="{key}"]').fill(str(value))
    page.locator("#editorial-burn").check()
    draft = portal.click_response(page, page.locator("#editorial-save"), f"/jobs/{job}/drafts/", "PUT", 200,
                                  retry_draft_capacity=True).json()
    portal.require(draft["start"] == start and draft["end"] == end and draft["cues"] == [cue]
                   and draft["options"]["burn_subtitles"] is True, "precise_cut_draft_changed")
    return draft, cue


def acceptance(page, args, report, *, job):
    """Use the caller's freshly processed synthetic native-cadence fixture."""
    source = Path(args.precise_fixture)
    portal.require(source.is_absolute() and source.is_file() and not source.is_symlink()
                   and portal.ID.fullmatch(job), "precise_cut_fixture")
    portal.open_saved_job(page, job)
    source_times_ms = {int(time * 1000 + 0.0001) for time in frame_times(source)}
    output = report["precise_cuts"] = []
    saved = []
    for label, (start, end, marker) in zip(("late_start", "near_end"), CUTS, strict=True):
        report["step"] = "precise_cut_" + label + "_preview"
        portal.open_late_draft(page, job, round(start - 0.25, 3), round(end + 0.025, 3), generated=False)
        marked_start = review_edge(page, "start", start, source_times_ms)
        marked_end = review_edge(page, "end", end, source_times_ms)
        range_response = portal.click_response(page, page.locator("#editorial-apply-range"),
                                               f"/jobs/{job}/editor/range", "POST", 200).json()
        portal.require(range_response["start"] == start and range_response["end"] == end, "precise_cut_range_changed")
        report["step"] = "precise_cut_" + label + "_export"
        draft, cue = save_marker(page, job, start, end, marker)
        export, _, _ = portal.start_editorial_export(page, job, draft)
        row = page.locator(f'#editorial-exports article[data-export-id="{export}"]')
        row.get_by_role("link", name="Descargar MP4 editado").wait_for(timeout=480_000)
        report["step"] = "precise_cut_" + label + "_measure"
        with tempfile.TemporaryDirectory(prefix="clipforge-precise-", dir=args.report.parent) as scratch:
            local = Path(scratch)
            for extension, name in (("mp4", "MP4 editado"), ("srt", "SRT"), ("vtt", "WebVTT")):
                portal.save_download(page, row.get_by_role("link", name="Descargar " + name, exact=True),
                                     local / f"clip.{extension}")
            try:
                measurement = measure_cut(source, local / "clip.mp4", draft["start"], draft["end"], marker, cue=cue)
            except (AssertionError, StopIteration) as error:
                raise portal.BrowserAcceptanceError("precise_cut_native_timeline_mismatch") from error
            output.append({"case": label, "frame_marks_original_seconds": [marked_start, marked_end],
                           "download_sha256": portal.digest_of(local / "clip.mp4"), **measurement})
        saved.append((draft, export))

    report["step"] = "precise_cut_persistence"
    portal.open_saved_job(page, job)
    exports = portal.browser_get(page, f"/jobs/{job}/exports")["body"]["exports"]
    for draft, export in saved:
        response = portal.browser_get(page, f"/jobs/{job}/drafts/{draft['id']}")
        portal.require(response["status"] == 200 and all(response["body"][key] == draft[key]
                       for key in ("revision", "start", "end", "cues")) and any(
                       item["id"] == export and item["status"] == "completed" and item["draft_revision"] == draft["revision"]
                       for item in exports), "precise_cut_revision_lost")
    selections = portal.browser_get(page, f"/jobs/{job}/selections")
    portal.require(selections["status"] == 200 and selections["body"]["analyses"] == [],
                   "precise_cut_remote_provider_was_called")
    portal.check(report, "late_and_near_end_downloads_match_approved_native_timing")
