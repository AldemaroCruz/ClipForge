"""Pilot manual clips reuse the existing Range and fenced export contracts."""

from contextlib import nullcontext
from datetime import datetime, timezone
from types import SimpleNamespace
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException, Response

from app.cloud import router
from app.editorial import RangeChange


JOB = "b" * 32
EXPORT = "c" * 32
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
            patch.object(router.repo, "beta_document") as guard,
            patch.object(router.repo, "admit_beta"),
            patch.object(router.repo, "insert_document") as insert,
            patch.object(router.repo, "enqueue"),
            patch.object(router.repo, "remember_request"),
            patch.object(router, "_dispatch", side_effect=lambda result: result),
        ):
            self.assertIs(router._submit_export(JOB, item, self.request, pilot=True)["pilot"], True)
        guard.assert_called_once_with(connection, self.request.state.principal, JOB)
        insert.assert_called_once_with(connection, JOB, "export", item)

    def test_job_reads_wake_queued_pilot_without_touching_finished_work(self):
        with patch.object(router, "_doc", side_effect=[document("queued"), document()]), \
                patch.object(router, "reconcile", return_value={"status": "dispatched"}) as dispatch:
            self.assertEqual("dispatched", router.get_job(JOB, Response())["dispatch_status"])
            self.assertEqual("completed", router.get_job(JOB, Response())["status"])
        dispatch.assert_called_once_with()

    def test_failed_variant_retry_reuses_task_and_appends_attempt_history(self):
        task_id = "d" * 32
        connection = Mock()
        connection.execute.return_value.mappings.return_value.first.return_value = {
            "id": task_id, "status": "failed", "cleaned_at": object(),
            "fence": 7, "updated_at": datetime(2026, 11, 25, tzinfo=timezone.utc), "attempts": 2,
        }
        history = {"error_code": "SOURCE_UNAVAILABLE", "fence": 6}
        item = {"id": EXPORT, "status": "failed", "start": 395, "end": 420,
                "request_id": "manual-fixture", "error_code": "WORKER_INTERRUPTED", "attempt_history": [history]}
        variant = {"payload": item, "manifest": {}}
        with (
            patch.object(router.repo, "update_document") as update,
            patch.object(router.repo, "admit_beta") as admit,
            patch.object(router.repo, "enqueue") as enqueue,
        ):
            router.repo.retry_manual_export(connection, JOB, variant, "e" * 32)
        admit.assert_called_once_with(connection, "e" * 32)
        update.assert_called_once_with(connection, JOB, "export", item)
        enqueue.assert_not_called()
        self.assertEqual(connection.execute.call_args_list[0].args[1], {"j": JOB, "kind": "export", "item": EXPORT})
        self.assertEqual([call.args[1] for call in connection.execute.call_args_list[1:]], [{"i": task_id}] * 2)
        self.assertEqual((item["id"], item["status"], item["start"], item["end"], item["request_id"]),
                         (EXPORT, "queued", 395, 420, "manual-fixture"))
        self.assertEqual((item["retry_count"], item["retryable"], item["pilot"]), (1, False, True))
        self.assertEqual(item["attempt_history"], [history, {
            "error_code": "WORKER_INTERRUPTED", "fence": 7,
            "finished_at": "2026-11-25T00:00:00+00:00", "dispatches": 2,
        }])

    def test_failed_variant_with_output_is_never_requeued(self):
        connection = Mock()
        variant = {"payload": {"id": EXPORT, "status": "failed"}, "manifest": {"clip.mp4": SOURCE}}
        with self.assertRaises(HTTPException) as refused:
            router.repo.retry_manual_export(connection, JOB, variant, "e" * 32)
        self.assertEqual(409, refused.exception.status_code)
        connection.execute.assert_not_called()

    def test_explicit_retry_of_same_export_is_idempotent_after_queue(self):
        connection = object()
        self.request.state.principal = SimpleNamespace(id="e" * 32)
        engine = Mock()
        engine.begin.side_effect = lambda: nullcontext(connection)
        item = {"id": EXPORT, "status": "failed", "pilot": True,
                "title": "Fragmento manual", "clip_file": "manual.mp4"}
        variant = {"payload": item, "manifest": {}}

        def requeue(*_):
            item.update(status="queued", retry_count=1)

        with (
            patch.object(router, "get_engine", return_value=engine),
            patch.object(router.repo, "beta_document", return_value=document()) as owned,
            patch.object(router.repo, "document", return_value=variant) as read,
            patch.object(router.repo, "retry_manual_export", side_effect=requeue) as retry,
            patch.object(router, "_dispatch", side_effect=lambda value: dict(value)) as dispatch,
        ):
            first = router.retry_manual_export(JOB, EXPORT, self.request)
            second = router.retry_manual_export(JOB, EXPORT, self.request)
        self.assertEqual(first, second)
        self.assertEqual((first["id"], first["status"]), (EXPORT, "queued"))
        self.assertEqual(owned.call_args.args, (connection, self.request.state.principal, JOB))
        self.assertEqual(read.call_args.args, (JOB, "export", EXPORT, connection))
        retry.assert_called_once_with(connection, JOB, variant, self.request.state.principal.id)
        self.assertEqual(dispatch.call_count, 2)
