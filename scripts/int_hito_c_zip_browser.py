"""Check exact authenticated ZIP bytes from a normal creator on INT."""
import hashlib
import json
import secrets
import tempfile
from pathlib import Path
from urllib.parse import urlencode
from zipfile import ZIP_STORED, ZipFile

from scripts import int_hito_b_browser as portal
from scripts.int_hito_c_styles_browser import cleanup


def selection_path(job, selection, *, inspect=False):
    query = [("selection", ":".join((clip, str(revision), output_id))) for clip, revision, output_id in selection]
    if inspect:
        query.append(("inspect", "1"))
    return f"/jobs/{job}/clips.zip?" + urlencode(query)


def verify_archive(page, selection, originals, scratch):
    for name, _, _ in selection:
        label = "Incluir Clip " + str(int(name[5:7])) + " en ZIP"
        page.get_by_role("checkbox", name=label, exact=True).check()
    button = page.get_by_role("button", name="Descargar ZIP de clips seleccionados", exact=True)
    with tempfile.TemporaryDirectory(prefix="clipforge-c06-archive-", dir=scratch) as directory:
        path = Path(directory) / "clips.zip"
        portal.require(portal.save_download(page, button, path).endswith(".zip"), "archive_filename")
        with ZipFile(path) as bundle:
            expected = {}
            for name, _, _ in selection:
                clip = originals[name]
                expected[name] = clip["sha256"]
                for format, digest in clip["captions"]["sidecars"].items():
                    expected[name.removesuffix(".mp4") + "." + format] = digest
            portal.require(set(bundle.namelist()) == {"manifest.json", *expected}
                           and len(bundle.namelist()) == len(expected) + 1, "archive_exact_selected_members")
            with bundle.open("manifest.json") as payload:
                data = payload.read(65_537)
            portal.require(len(data) <= 65_536, "archive_manifest_size")
            manifest = json.loads(data)["clips"]
            portal.require([(item["clip"], item["caption_revision"], item["output_id"]) for item in manifest]
                           == list(selection), "archive_exact_revisions")
            records = {file["file"]: (file["bytes"], file["sha256"]) for item in manifest for file in item["files"]}
            for name, digest in expected.items():
                info = bundle.getinfo(name)
                portal.require(info.compress_type == ZIP_STORED and records[name] == (info.file_size, digest),
                               "archive_manifest_byte_identity")
                with bundle.open(info) as source:
                    portal.require(hashlib.file_digest(source, "sha256").hexdigest() == digest,
                                   "archive_same_bytes_as_individual_download")
        return {"bytes": path.stat().st_size, "sha256": portal.digest_of(path), "members": len(expected),
                "clips": len(selection)}


def creator_flow(browser, args, accounts, jobs, report):
    transfer = []
    with portal.browser_page(browser, storage=True, transfer=transfer) as page:
        portal.login(page, accounts[0], args.commit)
        portal.check_normal_permissions(page, report)
        job = portal.upload_video(page, args.video, report, transfer, track_reservation=jobs.append)
        job_id = job["id"]
        portal.open_saved_job(page, job_id)
        originals = portal.results(page, job, args.state.parent)
        selected = [(item["file"], item["captions"]["revision"], item["captions"]["output"]["id"])
                    for item in job["clips"]]
        portal.require(len(selected) >= 3, "archive_fixture_has_multiple_clips")
        report["step"] = "zip_subset"
        report["subset"] = verify_archive(page, selected[:1], originals, args.state.parent)
        portal.check(report, "zip_includes_only_selected_clip_and_its_sidecars")
        report["step"] = "zip_stream_size"
        report["all"] = verify_archive(page, selected, originals, args.state.parent)
        portal.require(report["all"]["bytes"] > 32 * 1024**2, "archive_over_http1_nonstreaming_limit")
        portal.check(report, "zip_stream_over_32_mib_matches_individual_files")

        name, revision, output_id = selected[0]
        stale = selection_path(job_id, [(name, revision + 1, output_id)], inspect=True)
        portal.require(portal.browser_get(page, stale)["status"] == 409, "stale_archive_revision_allowed")
        path = selection_path(job_id, selected[:1], inspect=True)
        with portal.browser_page(browser) as other:
            portal.login(other, accounts[1], args.commit)
            portal.require(portal.browser_get(other, path)["status"] == 404, "other_creator_archive_visible")
            portal.logout(other)
        portal.check(report, "stale_revision_and_other_creator_denied")
        portal.require(portal.browser_post(page, f"/jobs/{job_id}/deletion", {})["status"] == 202
                       and portal.browser_get(page, path)["status"] == 404, "deleted_archive_available")
        portal.check(report, "deleted_project_blocks_new_archive")
        portal.logout(page)


def acceptance(browser, args, admin, report):
    accounts, jobs = [], []
    report["synthetic_owners"] = []
    report["step"] = "zip_create_synthetic_accounts"
    try:
        with portal.browser_page(browser) as page:
            portal.login(page, admin, args.commit)
            page.goto(portal.PUBLIC + "/account", wait_until="domcontentloaded")
            for _ in range(2):
                account = {"username": "qa_beta_" + secrets.token_hex(10), "password": secrets.token_urlsafe(36)}
                created = portal.create_account(page, account)
                accounts.append(account)
                portal.require(portal.ID.fullmatch(created["id"]), "zip_synthetic_owner_shape")
                report["synthetic_owners"].append(created["id"])
            portal.logout(page)
        creator_flow(browser, args, accounts, jobs, report)
        report["step"] = "zip_cleanup"
    finally:
        report["synthetic_projects"] = jobs.copy()
        cleanup(browser, args, admin, accounts, jobs, report)
