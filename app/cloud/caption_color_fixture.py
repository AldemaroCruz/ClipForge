"""Prepare a synthetic INT browser project without ASR or provider calls."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from tempfile import TemporaryDirectory
import time

from sqlalchemy import text

from ..auth_db import get_engine
from ..media import inspect_beta_media
from ..presentation import Presentation
from ..render import render_clip
from . import repository as repo, storage
from .config import beta_enabled, settings


OWNER = r"^[a-f0-9]{32}$"
SYNTHETIC_OWNER = r"^qa_beta_[a-f0-9]{20}$"
SHA256 = r"^[a-f0-9]{64}$"
MAX_ORIGINAL = 64 * 1024 * 1024
FIXTURE = "caption-color-acceptance"
MIME = {".mp4": "video/mp4", ".srt": "application/x-subrip", ".vtt": "text/vtt"}


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


def seed(owner, job, expected_sha256):
    if not (re.fullmatch(OWNER, owner) and re.fullmatch(OWNER, job) and re.fullmatch(SHA256, expected_sha256)):
        raise ValueError("Invalid synthetic fixture identifiers")
    cfg = settings()
    execution = os.environ.get("CLOUD_RUN_EXECUTION", "")
    if (not beta_enabled() or cfg.local_test or cfg.project != "clipforgebeta2" or cfg.region != "us-central1"
            or os.environ.get("CLOUD_RUN_JOB") != "clipforge-int-worker"
            or not re.fullmatch(r"clipforge-int-worker-[a-z0-9]+", execution)):
        raise ValueError("This fixture requires the protected INT worker execution")
    with get_engine().begin() as connection:
        workspace, document = _locked_job(connection, owner, job)
        payload = document["payload"]
        if payload.get("acceptance_fixture") == FIXTURE and payload.get("fixture_sha256") == expected_sha256:
            return "current"
        active_task = connection.execute(text("SELECT 1 FROM cloud_tasks WHERE job_id=:job LIMIT 1"),
                                         {"job": job}).scalar()
        if (payload.get("pilot") is not True or payload["status"] != "awaiting_upload"
                or payload.get("source_filename") != "framing.mp4" or payload.get("upload_tracking") is not True
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
            clips = _known_clips()
            for clip in clips:
                output = folder / clip["file"]
                render_clip(source, output, start=clip["start"], end=clip["end"], options=base,
                            cues=clip["cues"], video_index=media["video_stream_index"], pilot=True)
                clip.update(options=base.model_dump(), caption_rendered=True, duration=clip["end"] - clip["start"])
                for suffix, content_type in MIME.items():
                    path = output.with_suffix(suffix)
                    name = f"workspaces/{workspace}/jobs/{job}/fixtures/{execution}/{path.name}"
                    with path.open("rb") as content:
                        manifest[path.name] = storage.upload(name, content, content_type)
        payload.update(status="completed", clips=clips, media=media, completed_at=time.time(),
                       acceptance_fixture=FIXTURE, fixture_sha256=expected_sha256)
        connection.execute(text("DELETE FROM cloud_upload_sessions WHERE job_id=:job"), {"job": job})
        repo.update_document(connection, job, "job", payload, document["revision"], manifest)
    return "prepared"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("owner")
    parser.add_argument("project")
    parser.add_argument("source_sha256")
    args = parser.parse_args()
    print(json.dumps({"status": seed(args.owner, args.project, args.source_sha256), "fixture": FIXTURE}))


if __name__ == "__main__":
    main()
