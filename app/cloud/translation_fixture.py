"""Seed only a verified synthetic INT upload for the bilingual rehearsal."""

import argparse
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

from .. import translation_fixture as sample
from ..auth_db import get_engine
from ..media import inspect_beta_media
from ..presentation import Presentation
from ..render import render_clip
from . import editorial_selection, repository as repo, storage, transcript_selection
from .caption_color_fixture import MAX_ORIGINAL, MIME, OWNER, SHA256, _locked_job
from .config import beta_enabled, settings
from .router import VERSION


FIXTURE = "subtitle-translation-acceptance"


def json_artifact(prefix, name, value):
    return storage.upload(f"{prefix}/{name}", BytesIO(repo.packed(value).encode()), "application/json")


def seed_clips(source, directory, prefix, media, options):
    clips, manifest = [], {}
    for index, (language, (start, end)) in enumerate(sample.SPAN.items(), 1):
        name = f"clip_{index:02}.mp4"
        cues = sample.cues(language)
        output = directory / name
        render_clip(source, output, start=start, end=end, options=options, cues=cues,
                    video_index=media["video_stream_index"], pilot=True)
        clips.append({"file": name, "start": start, "end": end, "title": sample.TITLES[language],
                      "cues": cues, "options": options.model_dump(), "caption_rendered": True,
                      "duration": end - start, "audio_language": language, "subtitle_language": language})
        for suffix, content_type in MIME.items():
            path = output.with_suffix(suffix)
            with path.open("rb") as content:
                manifest[path.name] = storage.upload(f"{prefix}/{path.name}", content, content_type)
    return clips, manifest


def seed_drafts(connection, payload, manifest, options, fixture_revision):
    job = payload["id"]
    identity = editorial_selection.source_identity({"payload": payload, "manifest": manifest})
    sidecar = manifest[transcript_selection.SIDECAR]
    transcript = transcript_selection.version_id(job, identity, sidecar)
    payload["transcript_alignment"] = {"status": "completed", "source_fingerprint": identity}
    now = time.time()
    common = {"job_id": job, "revision": 1, "created_at": now, "updated_at": now,
              "version": VERSION, "options": options.model_dump()}
    drafts = {}
    for language, (start, end) in sample.SPAN.items():
        item = {**common, "id": uuid.uuid4().hex, "title": sample.TITLES[language],
                "clip_file": None, "start": start, "end": end, "cues": sample.cues(language),
                "audio_language": language, "subtitle_language": language}
        if language == "es":
            item["selection_origin"] = {
                **identity, "mode": "transcript", "transcript_version": transcript,
                "method": transcript_selection.METHOD, "first": "s1", "last": "s3",
                "start": start, "end": end, "alignment_sha256": sidecar["sha256"],
                "alignment_generation": sidecar["generation"], "model_revision": fixture_revision,
                "transcriber_version": FIXTURE,
            }
        repo.insert_document(connection, job, "draft", item)
        drafts[language] = item
    english = drafts["en"]
    exported = {**english, "id": uuid.uuid4().hex, "status": "completed", "completed_at": now,
                "pilot": True, "draft_id": english["id"], "draft_revision": english["revision"],
                "clip_file": f"manual_{english['id'][:8]}.mp4", "source_clip_file": None}
    files = {f"clip{suffix}": manifest[f"clip_02{suffix}"] for suffix in MIME}
    repo.insert_document(connection, job, "export", exported, files)
    payload["translation_fixture_sources"] = {"es": drafts["es"]["id"], "en": exported["id"]}


def seed(owner, job, expected_sha256):
    if not (re.fullmatch(OWNER, owner) and re.fullmatch(OWNER, job) and re.fullmatch(SHA256, expected_sha256)):
        raise ValueError("Invalid synthetic translation fixture identifiers")
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
        task = connection.execute(text("SELECT 1 FROM cloud_tasks WHERE job_id=:job LIMIT 1"),
                                  {"job": job}).scalar()
        if (payload.get("pilot") is not True or payload["status"] != "awaiting_upload"
                or payload.get("source_filename") != sample.FILENAME or payload.get("upload_tracking") is not True
                or document["manifest"] or task):
            raise ValueError("Refusing to change a project outside the synthetic translation reservation")
        original = storage.beta_original_metadata(storage.beta_original(workspace, job))
        if not original or original["bytes"] != payload["source_bytes"] or original["bytes"] > MAX_ORIGINAL:
            raise ValueError("The complete synthetic original is required")
        prefix = f"workspaces/{workspace}/jobs/{job}/fixtures/{execution}"
        options = Presentation.model_validate({**payload["options"], "burn_subtitles": True})
        with TemporaryDirectory(prefix="cf-translation-fixture-") as temporary:
            directory = Path(temporary)
            source = directory / "original.mp4"
            storage.download(original, source, max_bytes=MAX_ORIGINAL)
            with source.open("rb") as raw:
                if hashlib.file_digest(raw, "sha256").hexdigest() != expected_sha256:
                    raise ValueError("The synthetic video does not match its expected SHA-256")
            media = inspect_beta_media(source)
            if media["duration_seconds"] != sample.DURATION:
                raise ValueError("The synthetic bilingual video duration changed")
            clips, manifest = seed_clips(source, directory, prefix, media, options)
        manifest["input.mp4"] = original
        rows = sample.timeline()
        fixture_revision = hashlib.sha256(repo.packed(sample.recipe()).encode()).hexdigest()[:40]
        raw_rows = [{key: row[key] for key in ("start", "end", "text")} for row in rows]
        manifest["transcript.json"] = json_artifact(prefix, "transcript.json", raw_rows)
        manifest[transcript_selection.SIDECAR] = json_artifact(prefix, transcript_selection.SIDECAR, {
            "schema": 1, "method": transcript_selection.METHOD, "model_revision": fixture_revision,
            "transcriber_version": FIXTURE,
            "segments": [{**row, "words": marked["words"]} for row, marked in zip(raw_rows, rows, strict=True)],
        })
        payload.update(status="completed", clips=clips, media=media, completed_at=time.time(), language="mul",
                       acceptance_fixture=FIXTURE, fixture_sha256=expected_sha256,
                       fixture_alignment="synthetic_spoken_word_events")
        seed_drafts(connection, payload, manifest, options, fixture_revision)
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
