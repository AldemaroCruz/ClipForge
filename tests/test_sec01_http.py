"""SEC-01 HTTP contracts for the FastAPI/Starlette/multipart security update.

The multipart parser, ASGI routes, files and JSON persistence are real.
Media bytes/transcripts are authored fixtures; processing threads are stubbed.
These checks do not claim decoding, ASR, LLM inference or browser networking.
"""
from __future__ import annotations

import hashlib
import os
from pathlib import Path
import tempfile
import threading
import unittest
from unittest.mock import patch

from auth_support import AuthenticatedTestClient as TestClient
from fastapi.testclient import TestClient as RawTestClient
from starlette.applications import Starlette
from starlette.responses import JSONResponse
from starlette.routing import Route

with tempfile.TemporaryDirectory(prefix="clipforge-sec01-import-") as bootstrap:
    with patch.dict(os.environ, {"CLIPFORGE_DATA_DIR": bootstrap, "CLIPFORGE_AI_PROVIDER": "disabled"}):
        from app import main, workspace, ai_selection
from app.state import write_json_atomic


JOB = "a" * 32
CLIP = "clip_01.mp4"
SOURCE = bytes(range(128))  # Download fixture, not a decoded MP4.


class SEC01HTTPContracts(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-sec01-http-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        root_patch = patch.object(main, "ROOT", self.root)
        root_patch.start()
        self.addCleanup(root_patch.stop)
        environment = patch.dict(os.environ, {"CLIPFORGE_AI_PROVIDER": "disabled"})
        environment.start()
        self.addCleanup(environment.stop)
        provider = patch.object(ai_selection, "request_selection", side_effect=AssertionError("No real provider in HTTP regression"))
        provider.start()
        self.addCleanup(provider.stop)
        self.folder = self.root / JOB
        self.folder.mkdir()
        (self.folder / "input.mp4").write_bytes(SOURCE)
        (self.folder / CLIP).write_bytes(SOURCE)
        write_json_atomic(self.folder / "transcript.json", [{"start": 0, "end": 4, "text": "Texto escrito para el fixture."}])
        main.persist(JOB, {
            "id": JOB, "status": "completed", "clips": [{"file": CLIP, "start": 0, "end": 4}],
            "options": {}, "processing_mode": "manual",
        })
        self.processed = threading.Event()
        process = patch.object(main, "process", side_effect=lambda job_id: self.processed.set())
        self.process = process.start()
        self.addCleanup(process.stop)
        self.client = TestClient(main.app, projects=(JOB,))
        self.addCleanup(self.client.close)
        self.addCleanup(main.JOBS.clear)

    def upload(self, *, content=b"synthetic upload\x00\r\n", filename="fixture.mp4", data=None):
        return self.client.post("/jobs", files={"file": (filename, content, "video/mp4")}, data=data or {})

    def no_upload_allocated(self):
        self.assertEqual({path.name for path in self.root.iterdir()}, {JOB})
        self.process.assert_not_called()

    def source_hashes(self):
        return {name: hashlib.sha256((self.folder / name).read_bytes()).hexdigest()
                for name in ("input.mp4", CLIP, "transcript.json", "job.json")}

    def draft_payload(self):
        return {"title": "Revisión sintética ñ", "start": 0, "end": 4,
                "options": {"subtitle_color": "#aabbcc"},
                "cues": [{"start": 0, "end": 4, "text": "Subtítulo escrito, sin ASR."}]}

    def test_multipart_upload_preserves_bytes_filename_and_typed_options(self):
        payload = b"fixture\x00\r\nbytes\xff"
        response = self.upload(content=payload, filename="../../fixture.mp4", data={
            "processing_mode": "manual", "framing": "crop", "burn_subtitles": "true",
            "crop_x": "0.25", "crop_y": "0.75", "crop_zoom": "1.5",
            "subtitle_font_size": "72", "subtitle_color": "#aabbcc",
        })
        self.assertEqual(response.status_code, 202, response.text)
        self.assertTrue(self.processed.wait(2), "The stub processing thread did not run")
        job = response.json()
        self.assertEqual(job["status"], "queued")
        self.assertEqual(job["source_filename"], "fixture.mp4")
        self.assertEqual(job["processing_mode"], "manual")
        self.assertEqual(job["options"]["subtitle_font_size"], 72)
        self.assertEqual(job["options"]["subtitle_color"], "#AABBCC")
        self.assertTrue(job["options"]["burn_subtitles"])
        self.assertEqual(job["options"]["crop_x"], 0.25)
        self.assertEqual((self.root / job["id"] / "input.mp4").read_bytes(), payload)
        self.assertEqual(self.client.get("/jobs/" + job["id"]).json()["options"], job["options"])

    def test_multipart_missing_required_file_is_structured_422(self):
        response = self.client.post("/jobs", files={"other": ("fixture.mp4", b"fixture", "video/mp4")})
        self.assertEqual(response.status_code, 422)
        self.assertTrue(any(item["loc"] == ["body", "file"] for item in response.json()["detail"]))
        self.no_upload_allocated()

    def test_multipart_missing_boundary_is_400_without_allocation(self):
        response = self.client.post("/jobs", content=b"synthetic malformed body",
                                    headers={"Content-Type": "multipart/form-data"})
        self.assertEqual(response.status_code, 400, response.text)
        self.assertIn("boundary", response.json()["detail"].lower())
        self.no_upload_allocated()

    def test_invalid_form_number_is_structured_422_before_allocation(self):
        response = self.upload(data={"crop_zoom": "not-a-number"})
        self.assertEqual(response.status_code, 422)
        self.assertTrue(any(item["loc"] == ["body", "crop_zoom"] for item in response.json()["detail"]))
        self.no_upload_allocated()

    def test_presentation_domain_violation_is_422_before_allocation(self):
        for data in ({"crop_x": "NaN"}, {"subtitle_font_size": "121"}, {"subtitle_color": "red"}):
            with self.subTest(data=data):
                response = self.upload(data=data)
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIsInstance(response.json()["detail"], str)
                self.no_upload_allocated()

    def test_wrong_extension_and_empty_upload_are_400_and_leave_no_job(self):
        for content, filename in ((b"fixture", "fixture.txt"), (b"", "fixture.mp4")):
            with self.subTest(filename=filename, empty=not content):
                response = self.upload(content=content, filename=filename)
                self.assertEqual(response.status_code, 400, response.text)
                self.no_upload_allocated()

    def test_upload_size_limit_accepts_boundary_and_rejects_extra_byte(self):
        with patch.object(main, "MAX_MB", 1):
            accepted = self.upload(content=b"x" * (1024 * 1024))
            self.assertEqual(accepted.status_code, 202, accepted.text)
            self.assertTrue(self.processed.wait(2))
            accepted_id = accepted.json()["id"]
            rejected = self.upload(content=b"x" * (1024 * 1024 + 1))
        self.assertEqual(rejected.status_code, 413, rejected.text)
        self.assertEqual({path.name for path in self.root.iterdir()}, {JOB, accepted_id})
        self.assertEqual(self.process.call_count, 1)

    def test_not_found_error_keeps_json_contract(self):
        response = self.client.get("/jobs/" + "b" * 32)
        self.assertEqual(response.status_code, 404)
        self.assertEqual(response.headers["content-type"], "application/json")
        self.assertEqual(response.json(), {"detail": "Job no encontrado"})

    def test_unreadable_job_error_preserves_bytes_and_retry_headers(self):
        path = self.folder / "job.json"
        path.write_bytes(b"{deliberately malformed fixture")
        original = path.read_bytes()
        with patch.object(main, "READ_DELAY_SECONDS", 0):
            response = self.client.get("/jobs/" + JOB)
        self.assertEqual(response.status_code, 503)
        self.assertEqual(response.headers["retry-after"], "2")
        self.assertEqual(response.headers["cache-control"], "no-store")
        self.assertIsInstance(response.json()["detail"], str)
        self.assertEqual(path.read_bytes(), original)

    def test_full_source_download_preserves_media_headers_and_bytes(self):
        response = self.client.get(f"/jobs/{JOB}/source")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, SOURCE)
        self.assertEqual(response.headers["content-type"], "video/mp4")
        self.assertEqual(response.headers["content-length"], str(len(SOURCE)))
        self.assertEqual(response.headers["accept-ranges"], "bytes")
        self.assertTrue(response.headers["content-disposition"].startswith("inline;"))

    def test_source_prefix_range_is_exact_206(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=0-15"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, SOURCE[:16])
        self.assertEqual(response.headers["content-range"], "bytes 0-15/128")
        self.assertEqual(response.headers["content-length"], "16")

    def test_source_open_ended_range_is_exact_206(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=100-"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, SOURCE[100:])
        self.assertEqual(response.headers["content-range"], "bytes 100-127/128")

    def test_source_suffix_range_is_exact_206(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=-12"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, SOURCE[-12:])
        self.assertEqual(response.headers["content-range"], "bytes 116-127/128")

    def test_source_unsatisfiable_range_is_416_with_existing_size_contract(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=128-"})
        self.assertEqual(response.status_code, 416)
        # Starlette 1.3.1 supplies the range unit required by RFC 9110 section 14.4.
        self.assertEqual(response.headers["content-range"], "bytes */128")
        self.assertEqual(response.content, b"")

    def test_source_malformed_range_is_400(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=garbage"})
        self.assertEqual(response.status_code, 400)
        self.assertNotEqual(response.headers["content-type"], "video/mp4")

    def test_overlapping_ranges_coalesce_without_amplifying_bytes(self):
        response = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=0-7,4-15"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, SOURCE[:16])
        self.assertEqual(response.headers["content-range"], "bytes 0-15/128")

    def test_if_range_matching_etag_is_partial_and_mismatch_is_full(self):
        full = self.client.get(f"/jobs/{JOB}/source")
        matched = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=0-3", "If-Range": full.headers["etag"]})
        self.assertEqual(matched.status_code, 206)
        self.assertEqual(matched.content, SOURCE[:4])
        mismatch = self.client.get(f"/jobs/{JOB}/source", headers={"Range": "bytes=0-3", "If-Range": '"fixture-not-the-etag"'})
        self.assertEqual(mismatch.status_code, 200)
        self.assertEqual(mismatch.content, SOURCE)

    def test_clip_download_range_preserves_attachment_and_exact_bytes(self):
        response = self.client.get(f"/jobs/{JOB}/clips/{CLIP}", headers={"Range": "bytes=4-11"})
        self.assertEqual(response.status_code, 206)
        self.assertEqual(response.content, SOURCE[4:12])
        self.assertEqual(response.headers["content-range"], "bytes 4-11/128")
        self.assertTrue(response.headers["content-disposition"].startswith("attachment;"))

    def test_editor_json_keeps_cached_cues_and_no_store(self):
        before = self.source_hashes()
        response = self.client.get(f"/jobs/{JOB}/clips/{CLIP}/editor")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers["cache-control"], "no-store")
        item = response.json()
        self.assertEqual(item["start"], 0)
        self.assertEqual(item["end"], 4)
        self.assertEqual(item["cues"][0]["text"], "Texto escrito para el fixture.")
        self.assertEqual(self.source_hashes(), before)

    def test_export_json_validation_rejects_fractional_font_without_creating_export(self):
        response = self.client.post(f"/jobs/{JOB}/clips/{CLIP}/exports", json={
            "options": {"subtitle_font_size": 72.5}, "cues": [],
        })
        self.assertEqual(response.status_code, 422)
        self.assertTrue(any(item["loc"] == ["body", "options", "subtitle_font_size"] for item in response.json()["detail"]))
        self.assertFalse((self.folder / "exports").exists())

    def test_burned_subtitles_require_nonempty_cues_without_creating_export(self):
        response = self.client.post(f"/jobs/{JOB}/clips/{CLIP}/exports", json={
            "options": {"burn_subtitles": True}, "cues": [],
        })
        self.assertEqual(response.status_code, 422)
        self.assertIn("subtítulos", response.json()["detail"])
        self.assertFalse((self.folder / "exports").exists())

    def test_draft_create_update_and_stale_revision_preserve_source(self):
        before = self.source_hashes()
        payload = self.draft_payload()
        # Only media metadata is stubbed: this fixture is not a playable MP4.
        with patch.object(workspace, "inspect_media", return_value={"duration_seconds": 4}):
            created = self.client.post(f"/jobs/{JOB}/drafts", json=payload)
            self.assertEqual(created.status_code, 201, created.text)
            item = created.json()
            self.assertEqual(item["revision"], 1)
            self.assertEqual(item["options"]["subtitle_color"], "#AABBCC")
            update = {**payload, "title": "Corrección humana sintética", "revision": 1}
            saved = self.client.put(f"/jobs/{JOB}/drafts/{item['id']}", json=update)
            self.assertEqual(saved.status_code, 200, saved.text)
            self.assertEqual(saved.json()["revision"], 2)
            stale = self.client.put(f"/jobs/{JOB}/drafts/{item['id']}", json=update)
            self.assertEqual(stale.status_code, 409, stale.text)
        recovered = self.client.get(f"/jobs/{JOB}/drafts/{item['id']}")
        self.assertEqual(recovered.status_code, 200)
        self.assertEqual(recovered.json()["revision"], 2)
        self.assertEqual(recovered.json()["title"], "Corrección humana sintética")
        self.assertEqual(self.source_hashes(), before)

    def test_draft_validation_rejects_boolean_revision_and_unknown_fields(self):
        for extra in ({"revision": True}, {"revision": 1, "arbitrary_filter": "fixture"}):
            with self.subTest(extra=extra):
                response = self.client.put(f"/jobs/{JOB}/drafts/" + "b" * 32,
                                           json={**self.draft_payload(), **extra})
                self.assertEqual(response.status_code, 422, response.text)
                self.assertIsInstance(response.json()["detail"], list)
                self.assertFalse((self.folder / "drafts").exists())

    def test_ai_consent_boolean_remains_strict_before_any_provider_call(self):
        response = self.client.post(f"/jobs/{JOB}/selections", json={
            "preview_token": "a" * 64, "request_id": "b" * 32, "consent": "true",
        })
        self.assertEqual(response.status_code, 422)
        self.assertTrue(any(item["loc"] == ["body", "consent"] for item in response.json()["detail"]))
        self.assertFalse((self.folder / "selections").exists())


class SEC01FormLimitContracts(unittest.TestCase):
    """Real URL-encoded parser limits in an isolated, fixture-only ASGI app."""
    def setUp(self):
        async def parse_fixture(request):
            form = await request.form(max_fields=2, max_part_size=4)
            return JSONResponse({"items": list(form.multi_items())})
        self.client = RawTestClient(Starlette(routes=[Route("/fixture-form", parse_fixture, methods=["POST"])]))
        self.addCleanup(self.client.close)

    def submit(self, body):
        return self.client.post("/fixture-form", content=body,
                                headers={"Content-Type": "application/x-www-form-urlencoded"})

    def test_urlencoded_field_limit_counts_repeated_names(self):
        for body in (b"a=1&b=2&c=3", b"a=1&a=2&a=3"):
            with self.subTest(body=body):
                response = self.submit(body)
                self.assertEqual(response.status_code, 400, response.text)
                self.assertEqual(response.headers["content-type"], "text/plain; charset=utf-8")
                self.assertEqual(response.text, "Too many fields. Maximum number of fields is 2.")

    def test_urlencoded_part_limit_counts_raw_name_plus_value(self):
        boundary = self.submit(b"a=123")
        self.assertEqual(boundary.status_code, 200, boundary.text)
        self.assertEqual(boundary.json(), {"items": [["a", "123"]]})
        rejected = self.submit(b"a=1234")
        self.assertEqual(rejected.status_code, 400, rejected.text)

    def test_urlencoded_percent_encoding_is_limited_before_unquoting(self):
        boundary = self.submit(b"%61=1")
        self.assertEqual(boundary.status_code, 200, boundary.text)
        self.assertEqual(boundary.json(), {"items": [["a", "1"]]})
        rejected = self.submit(b"%61=12")
        self.assertEqual(rejected.status_code, 400, rejected.text)


if __name__ == "__main__":
    unittest.main()
