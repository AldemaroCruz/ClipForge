import unittest
from contextlib import nullcontext
import sys
from unittest.mock import Mock, patch

from fastapi import HTTPException

from app.cloud import transcript_selection as subject
from app.int_beta_proxy import allowed


IDENTITY = {"source_generation": "101", "transcript_generation": "102",
            "transcript_sha256": "a" * 64, "source_duration": 1200}
JOB = {"payload": {"id": "b" * 32}, "manifest": {}}
SIDE = {"generation": "103", "sha256": "c" * 64}
ROWS = [
    {"start": 1140, "end": 1144, "text": "Dijo fuego fuego otra vez",
     "words": [{"start": 1140, "end": 1140.4, "text": "Dijo"},
               {"start": 1140.4, "end": 1140.8, "text": "fuego"},
               {"start": 1141, "end": 1141.65, "text": "fuego"},
               {"start": 1142, "end": 1142.5, "text": "otra"},
               {"start": 1143.2, "end": 1144, "text": "vez"}]},
    {"start": 1144, "end": 1148, "text": "El viento ya volvió",
     "words": [{"start": 1144, "end": 1144.4, "text": "El"},
               {"start": 1144.5, "end": 1145.7, "text": "viento"},
               {"start": 1146, "end": 1146.4, "text": "ya"},
               {"start": 1147, "end": 1148, "text": "volvió"}]},
    {"start": 1180, "end": 1198, "text": "Este tramo sólo tiene tiempos de segmento", "words": []},
]


def snapshot(rows=ROWS, original=None):
    original = original or [{key: row[key] for key in ("start", "end", "text")} for row in ROWS]
    segments = [{**row, "id": index} for index, row in enumerate(original, 1)]
    with (patch.object(subject.editorial_selection, "source_identity", return_value=IDENTITY),
          patch.object(subject.editorial_selection, "transcript_segments", return_value=segments),
          patch.object(subject, "alignment_record", return_value=({"status": "completed"}, SIDE)),
          patch.object(subject, "_sidecar", return_value={
              "model_revision": "e" * 40, "transcriber_version": "1.1.1", "segments": rows,
          })):
        return subject.snapshot(JOB)[0]


class TranscriptSelectionTests(unittest.TestCase):
    def test_repeated_word_and_absolute_late_selection_create_relative_captions(self):
        view = snapshot()
        aligned = view["versions"][1]
        self.assertEqual(view["default_version"], aligned["id"])
        self.assertFalse(aligned["alternate"])
        self.assertTrue(view["partial"])
        request = subject.TranscriptClip(version=aligned["id"], first="w1.3", last="w2.2")
        start, end, cues, origin = subject.resolve(view, IDENTITY, request)
        self.assertEqual((start, end), (1141, 1145.7))
        self.assertEqual(cues, [{"start": 0, "end": 3, "text": "fuego otra vez"},
                                {"start": 3, "end": 4.7, "text": "El viento"}])
        self.assertEqual((origin["first"], origin["last"], origin["alignment_generation"]),
                         ("w1.3", "w2.2", "103"))
        self.assertEqual(origin["transcript_generation"], "102")

    def test_alternate_words_never_replace_historical_text_or_ids(self):
        legacy = [{"start": 1140, "end": 1148, "text": "Otra transcripción ya usada en un borrador"}]
        view = snapshot(original=legacy)
        original, aligned = view["versions"]
        self.assertEqual(view["default_version"], original["id"])
        self.assertTrue(aligned["alternate"])
        self.assertEqual(original["segments"], [{"id": "s1", "words": [], **legacy[0]}])
        self.assertNotEqual(original["id"], aligned["id"])
        self.assertEqual(subject.resolve(view, IDENTITY, subject.TranscriptClip(
            version=original["id"], first="s1", last="s1"))[:2], (1140, 1148))
        changed = {**IDENTITY, "source_generation": "104"}
        self.assertNotEqual(original["id"], subject.version_id(JOB["payload"]["id"], changed))

    def test_missing_timings_remain_segment_only(self):
        incomplete = [{**ROWS[0], "words": ROWS[0]["words"][:1]}, *ROWS[1:]]
        view = snapshot(incomplete)
        aligned = view["versions"][1]
        self.assertEqual(aligned["segments"][0]["words"], [])
        with self.assertRaises(HTTPException) as caught:
            subject.resolve(view, IDENTITY, subject.TranscriptClip(
                version=aligned["id"], first="w1.1", last="w2.2"))
        self.assertEqual(caught.exception.status_code, 422)
        self.assertEqual(subject.resolve(view, IDENTITY, subject.TranscriptClip(
            version=aligned["id"], first="s1", last="w2.2"))[:2], (1140, 1145.7))

    def test_range_limits_and_stale_version(self):
        rows = [{**ROWS[0], "start": 1100, "words": []}, *ROWS[1:]]
        view = snapshot(rows)
        aligned = view["versions"][1]
        for first, last in (("w2.2", "w2.1"), ("w2.1", "w2.1"), ("s1", "s3")):
            with self.subTest(first=first, last=last), self.assertRaises(ValueError):
                subject.resolve(view, IDENTITY, subject.TranscriptClip(version=aligned["id"], first=first, last=last))
        with self.assertRaises(HTTPException) as caught:
            subject.resolve(view, IDENTITY, subject.TranscriptClip(version="d" * 64, first="s1", last="s1"))
        self.assertEqual(caught.exception.status_code, 409)

    def test_proxy_allows_only_explicit_transcript_routes(self):
        path = f"/jobs/{JOB['payload']['id']}/transcript-selection"
        self.assertTrue(allowed("GET", path))
        self.assertTrue(allowed("POST", path + "/prepare"))
        self.assertTrue(allowed("POST", path + "/drafts"))
        self.assertFalse(allowed("GET", path + "/prepare"))
        self.assertFalse(allowed("POST", path + "/drafts/private"))

    def test_fractional_source_end_is_rounded_inward(self):
        rows = [{"start": 59, "end": 60.0006, "text": "final",
                 "words": [{"start": 59.7, "end": 60.0006, "text": "final"}]}]
        segment, = subject._aligned(rows, 60.0006)
        self.assertEqual(segment["end"], 60.0)
        self.assertEqual(segment["words"][0]["end"], 60.0)

    def test_historical_prepare_runs_without_the_worker_package(self):
        repository = subject.repo
        engine = Mock()
        engine.begin.return_value = nullcontext()
        principal = Mock(id="owner")
        with (patch.dict(sys.modules, {"app.transcribe": None}),
              patch.object(repository, "get_engine", return_value=engine),
              patch.object(repository, "beta_document", return_value=JOB),
              patch.object(subject.editorial_selection, "source_identity", return_value=IDENTITY),
              patch.object(repository, "alignment_document", return_value=None),
              patch.object(repository, "admit_beta"),
              patch.object(repository, "insert_document"),
              patch.object(repository, "enqueue") as enqueue):
            item = repository.prepare_alignment(JOB["payload"]["id"], principal)
        self.assertEqual(item["status"], "queued")
        enqueue.assert_called_once_with(None, JOB["payload"]["id"], "alignment", item["id"])
