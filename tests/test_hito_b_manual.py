"""Pilot manual clips reuse the existing Range and fenced export contracts."""

from contextlib import nullcontext
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from fastapi import HTTPException, Response

from app.cloud import router
from app.editorial import RangeChange


JOB = "b" * 32
SOURCE = {"name": "fixture-original", "generation": "7", "content_type": "video/mp4"}


def document(status="completed"):
    return {"payload": {"pilot": True, "status": status, "media": {"duration_seconds": 426.55}},
            "manifest": {"input.mp4": SOURCE}}


class ManualMvpTest(unittest.TestCase):
    def setUp(self):
        self.request = SimpleNamespace(headers={"Range": "bytes=0-"}, state=SimpleNamespace(principal=None))

    def test_large_original_range_remains_partial_and_streamed(self):
        upstream = SimpleNamespace(status_code=206, headers={
            "Content-Length": str(96 * 1024 * 1024),
            "Content-Range": "bytes 0-100663295/100663296",
        })
        with patch.object(router, "_doc", return_value=document()), \
                patch.object(router.storage, "open_object", return_value=upstream) as storage:
            response = router.source(JOB, self.request)
        storage.assert_called_once_with(SOURCE, "bytes=0-")
        self.assertEqual(206, response.status_code)
        self.assertEqual("bytes 0-100663295/100663296", response.headers["Content-Range"])
        self.assertNotIn("Content-Length", response.headers)
        self.assertEqual('inline; filename="input.mp4"', response.headers["Content-Disposition"])

    def test_editor_reuses_transcript_and_existing_export_with_fixed_format(self):
        segment = {"start": 400, "end": 410, "text": "Este texto ya estaba transcrito."}
        with patch.object(router, "_doc", return_value=document("failed")), \
                patch.object(router, "_transcript", return_value=[segment]), \
                patch.object(router, "_submit_export", side_effect=lambda job, item, _, **kw: (job, item, kw)):
            job, item, options = router.export_manual_range(
                JOB, RangeChange(start=395, end=420), self.request)
        self.assertEqual(JOB, job)
        self.assertEqual({"pilot": True}, options)
        self.assertEqual("queued", item["status"])
        self.assertEqual("contain", item["options"]["framing"])
        self.assertFalse(item["options"]["burn_subtitles"])
        self.assertEqual((395, 420), (item["start"], item["end"]))
        self.assertEqual([{"start": 5.0, "end": 15.0, "text": segment["text"]}], item["cues"])

    def test_range_outside_original_creates_no_export(self):
        with patch.object(router, "_doc", return_value=document()), \
                patch.object(router, "_submit_export") as submit, \
                self.assertRaises(HTTPException) as raised:
            router.export_manual_range(JOB, RangeChange(start=399, end=450), self.request)
        self.assertEqual(422, raised.exception.status_code)
        submit.assert_not_called()

    def test_new_manual_export_persists_worker_scope(self):
        self.request.state.principal = SimpleNamespace(id="a" * 32)
        item = {"id": "c" * 32, "status": "queued", "clip_file": "manual.mp4"}
        connection = object()
        with (
            patch.object(router.repo, "request_transaction", return_value=nullcontext((connection, None, "manual-key"))),
            patch.object(router.repo, "check_active_workspace"),
            patch.object(router.repo, "admit_beta"),
            patch.object(router.repo, "insert_document") as insert,
            patch.object(router.repo, "enqueue"),
            patch.object(router.repo, "remember_request"),
            patch.object(router, "_dispatch", side_effect=lambda result: result),
        ):
            self.assertIs(router._submit_export(JOB, item, self.request, pilot=True)["pilot"], True)
        insert.assert_called_once_with(connection, JOB, "export", item)

    def test_job_reads_wake_queued_pilot_without_touching_finished_work(self):
        with patch.object(router, "_doc", side_effect=[document("queued"), document()]), \
                patch.object(router, "reconcile", return_value={"status": "dispatched"}) as dispatch:
            self.assertEqual("dispatched", router.get_job(JOB, Response())["dispatch_status"])
            self.assertEqual("completed", router.get_job(JOB, Response())["status"])
        dispatch.assert_called_once_with()
