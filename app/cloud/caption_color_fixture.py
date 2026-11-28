"""Prepare an isolated INT browser fixture without ASR or provider calls."""
import argparse
import base64
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import time
import uuid

from sqlalchemy import text

from ..auth_db import get_engine
from ..media import inspect_beta_media
from ..presentation import Presentation
from ..render import render_clip
from ..subtitles import cues_from_segments
from ..topic_fixture import transcript
from . import editorial_selection, repository as repo, storage
from .config import beta_enabled, settings


OWNER = r"^[a-f0-9]{32}$"
SYNTHETIC_OWNER = r"^qa_beta_[a-f0-9]{20}$"
SHA256 = r"^[a-f0-9]{64}$"
MAX_ORIGINAL = 64 * 1024 * 1024
FIXTURE = "caption-color-acceptance"
TOPIC_FIXTURE = "topic-acceptance"
MIME = {".mp4": "video/mp4", ".srt": "application/x-subrip", ".vtt": "text/vtt"}
D01_REPLAY = {
    "source_commit": "0e7738b9107451ee34e2783d2646aabfdce2f027",
    "run_id": "46116426162",
    "search_id": "9c604245d4bf4fb4b22a201f28beb91a",
    "report_sha256": "286890cb1761e29502e90b5efc3a6346447d1a0386e253e83e45e785e0abff13",
    "video_sha256": "86f104f332ab25223116f1803d5d6dcd9f0d5743dd21c03dd3b831940e589c62",
    "transcript_sha256": "9b660eaa0dad7515a1583dfcd01e671213170c5ba67261460469b667ccd604c5",
    "model": "gpt-6-luna",
    "range_id": "r6_9",
    "evidence_segment": 6,
}


def _locked_job(connection, owner, job):
    workspace = connection.execute(text("""
        SELECT p.workspace_id FROM auth_projects p JOIN auth_users u ON u.id=p.owner_id
        WHERE p.id=:job AND p.owner_id=:owner AND p.deletion_started_at IS NULL
          AND u.is_active AND NOT u.is_admin AND u.username ~ :synthetic_user
        FOR UPDATE OF p
        """), {"job": job, "owner": owner, "synthetic_user": SYNTHETIC_OWNER}).scalar_one_or_none()
    if workspace is None:
        raise ValueError("The exact active synthetic project was not found")
    return workspace, repo.document(job, connection=connection)


def _known_clips():
    return [
        {"file": "clip_01.mp4", "start": 1.0, "end": 7.0, "title": "Prueba de color",
         "cues": [{"start": .3, "end": 2.3, "text": "Prueba de color primera"},
                  {"start": 3.2, "end": 5.7, "text": "Prueba de color segunda"}]},
        {"file": "clip_02.mp4", "start": 8.0, "end": 14.0, "title": "Otro clip para el estilo",
         "cues": [{"start": .5, "end": 4.5, "text": "Texto y tiempos de otro clip"}]},
    ]


def _topic_clips():
    rows = transcript()
    return [
        {"file": "clip_01.mp4", "start": 26.0, "end": 62.0, "title": "Agua para el huerto",
         "cues": cues_from_segments(rows, 26.0, 62.0)},
        {"file": "clip_02.mp4", "start": 1142.0, "end": 1181.0, "title": "Freno de la bicicleta",
         "cues": cues_from_segments(rows, 1142.0, 1181.0)},
    ]


def decode_replay(value):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,2048}={0,2}", value):
        raise ValueError("Invalid topic replay encoding")
    try:
        receipt = json.loads(base64.b64decode(value, altchars=b"-_", validate=True))
    except ValueError:
        raise ValueError("Invalid topic replay encoding") from None
    if receipt != D01_REPLAY or type(receipt["evidence_segment"]) is not int:
        raise ValueError("The topic replay must match the reviewed acceptance receipt")
    return receipt


def _replay_selection(payload, manifest, receipt):
    spec = editorial_selection.EditorialSelectionSpec(
        topic="reparar el freno de una bicicleta",
        instructions="Evitá introducciones, promociones y pasajes ajenos al tema.", max_clips=2,
    )
    prepared = editorial_selection.prepare({"payload": payload, "manifest": manifest}, spec)
    identity = prepared["identity"]
    config = prepared["config"]
    if (identity["transcript_sha256"] != receipt["transcript_sha256"]
            or config.provider != "openai" or config.model != receipt["model"]):
        raise ValueError("The synthetic transcript or configured model changed since the reviewed search")
    matching = [batch for batch in prepared["batches"] if any(
        row["range_id"] == receipt["range_id"] for row in batch["content"]["eligible_ranges"]
    )]
    if len(matching) != 1:
        raise ValueError("The reviewed synthetic range is absent or ambiguous in the current catalogue")
    summary = "Búsqueda reproducida a partir de la aceptación anterior de INT."
    # The prior report preserves the selected range and evidence. These labels
    # identify the replay in the test UI without attributing new text to the model.
    answer = {"summary": summary, "candidates": [{
        "range_id": receipt["range_id"], "evidence_segment": receipt["evidence_segment"],
        "title": "Freno de la bicicleta (reproducción de prueba)",
        "reason": "Coincidencia de la aceptación anterior, abierta para comprobar el editor y la exportación.",
        "hook": 1, "clarity": 1, "completeness": 1,
    }]}
    _, candidates, warnings = editorial_selection.validate_answer(answer, {**prepared, "content": matching[0]["content"]})
    now = time.time()
    return {"id": uuid.uuid4().hex, "job_id": payload["id"], "status": "completed", "outcome": "matches",
            "mode": "llm", "pilot": True, "spec": prepared["spec"], "fixture_replay": receipt,
            "source_fingerprint": identity, "transcript_sha256": identity["transcript_sha256"],
            "provider": config.provider, "model": config.model, "prompt_version": prepared["prompt_version"],
            "created_at": now, "completed_at": now, "provider_calls_planned": 0, "provider_calls": 0,
            "provider_responses": 0, "provider_response_received": False, "provider_elapsed_seconds": 0.0,
            "provider_call_intervals": [], "provider_models_received": [], "usage": {},
            "analysis_windows": [batch["summary"] for batch in prepared["batches"]],
            "segment_count": len(prepared["segments"]), "last_transcript_end": prepared["segments"][-1]["end"],
            "candidates": candidates, "summary": summary, "warnings": warnings}


def seed(owner, job, expected_sha256, *, topic=False, replay=None):
    if not (re.fullmatch(OWNER, owner) and re.fullmatch(OWNER, job) and re.fullmatch(SHA256, expected_sha256)):
        raise ValueError("Invalid synthetic fixture identifiers")
    if replay is not None and (not topic or replay != D01_REPLAY or replay["video_sha256"] != expected_sha256):
        raise ValueError("The replay requires the exact reviewed synthetic topic video")
    cfg = settings()
    execution = os.environ.get("CLOUD_RUN_EXECUTION", "")
    if (not beta_enabled() or cfg.local_test or cfg.project != "clipforgebeta2" or cfg.region != "us-central1"
            or os.environ.get("CLOUD_RUN_JOB") != "clipforge-int-worker"
            or not re.fullmatch(r"clipforge-int-worker-[a-z0-9]+", execution)):
        raise ValueError("This fixture requires the protected INT worker execution")
    fixture = TOPIC_FIXTURE if topic else FIXTURE
    filename = "topic.mp4" if topic else "framing.mp4"
    with get_engine().begin() as connection:
        workspace, document = _locked_job(connection, owner, job)
        payload = document["payload"]
        if (payload.get("acceptance_fixture") == fixture and payload.get("fixture_sha256") == expected_sha256
                and payload.get("fixture_replay") == replay):
            return "current"
        active_task = connection.execute(text("SELECT 1 FROM cloud_tasks WHERE job_id=:job LIMIT 1"),
                                         {"job": job}).scalar()
        if (payload.get("pilot") is not True or payload["status"] != "awaiting_upload"
                or payload.get("source_filename") != filename or payload.get("upload_tracking") is not True
                or document["manifest"] or active_task):
            raise ValueError("Refusing to modify a project outside the synthetic reservation")
        original = storage.beta_original_metadata(storage.beta_original(workspace, job))
        if not original or original["bytes"] != payload["source_bytes"] or original["bytes"] > MAX_ORIGINAL:
            raise ValueError("The complete synthetic original is required")
        manifest = {"input.mp4": original}
        base = Presentation.model_validate({**payload["options"], "burn_subtitles": True})
        with TemporaryDirectory(prefix="cf-caption-color-") as directory:
            folder = Path(directory)
            source = folder / "original.mp4"
            storage.download(original, source, max_bytes=MAX_ORIGINAL)
            with source.open("rb") as raw:
                if hashlib.file_digest(raw, "sha256").hexdigest() != expected_sha256:
                    raise ValueError("The synthetic original does not match its expected SHA-256")
            media = inspect_beta_media(source)
            if topic and media["duration_seconds"] != 1200:
                raise ValueError("The topic video must use the full 20-minute limit")
            prefix = f"workspaces/{workspace}/jobs/{job}/fixtures/{execution}"
            if topic:
                raw = repo.packed(transcript()).encode()
                manifest["transcript.json"] = storage.upload(
                    f"{prefix}/transcript.json", BytesIO(raw), "application/json",
                )
            clips = _topic_clips() if topic else _known_clips()
            for clip in clips:
                output = folder / clip["file"]
                render_clip(source, output, start=clip["start"], end=clip["end"], options=base,
                            cues=clip["cues"], video_index=media["video_stream_index"], pilot=True)
                clip.update(options=base.model_dump(), caption_rendered=True, duration=clip["end"] - clip["start"])
                for suffix, content_type in MIME.items():
                    path = output.with_suffix(suffix)
                    with path.open("rb") as content:
                        manifest[path.name] = storage.upload(f"{prefix}/{path.name}", content, content_type)
        payload.update(status="completed", clips=clips, media=media, completed_at=time.time(),
                       acceptance_fixture=fixture, fixture_sha256=expected_sha256)
        if replay is not None:
            item = _replay_selection(payload, manifest, replay)
            repo.insert_document(connection, job, "selection", item)
            payload["fixture_replay"] = replay
        connection.execute(text("DELETE FROM cloud_upload_sessions WHERE job_id=:job"), {"job": job})
        repo.update_document(connection, job, "job", payload, document["revision"], manifest)
    return "prepared"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("owner")
    parser.add_argument("project")
    parser.add_argument("source_sha256")
    parser.add_argument("--topic", action="store_true")
    parser.add_argument("--replay")
    args = parser.parse_args()
    replay = decode_replay(args.replay) if args.replay is not None else None
    print(json.dumps({"status": seed(args.owner, args.project, args.source_sha256, topic=args.topic, replay=replay),
                      "fixture": TOPIC_FIXTURE if args.topic else FIXTURE}))


if __name__ == "__main__":
    main()
