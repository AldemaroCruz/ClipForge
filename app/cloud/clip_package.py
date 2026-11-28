"""Authenticated, bounded ZIP streams from completed, generation-pinned clips."""
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
import hashlib
import json
import re
from time import monotonic
from zipfile import ZIP_STORED, ZipFile, ZipInfo

from fastapi import HTTPException
from requests import RequestException

from ..auth_db import get_engine
from . import clip_captions, repository as repo, storage

MAX_CLIPS = 30
MAX_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
STREAM_SECONDS = 150
OBJECT_TIMEOUT = (5, 15)
SELECTION = re.compile(r"(clip_[0-9]{2}\.mp4):([1-9][0-9]{0,9}):([a-f0-9]{32}(?:[a-f0-9]{32})?)")
CONTENT_TYPES = {"mp4": "video/mp4", "srt": "application/x-subrip", "vtt": "text/vtt"}


@dataclass(frozen=True)
class Selection:
    filename: str
    revision: int
    output_id: str


@dataclass(frozen=True)
class Member:
    filename: str
    object: dict


@dataclass(frozen=True)
class Package:
    clips: int
    bytes: int
    members: tuple[Member, ...]
    provenance: tuple[dict, ...]

    def summary(self):
        return {"clips": self.clips, "bytes": self.bytes, "max_clips": MAX_CLIPS, "max_bytes": MAX_BYTES}


def _parse(tokens: list[str]) -> list[Selection]:
    selections = []
    for token in tokens:
        match = SELECTION.fullmatch(token)
        if match is None:
            raise HTTPException(422, "La selección de clips no es válida.")
        filename, revision, output_id = match.groups()
        selections.append(Selection(filename, int(revision), output_id))
    if not 1 <= len(selections) <= MAX_CLIPS or len({item.filename for item in selections}) != len(selections):
        raise HTTPException(422, "Seleccioná entre 1 y 30 clips distintos.")
    return selections


def _validate_object(item, kind, project_prefix):
    if (not isinstance(item, dict) or item.get("content_type") != CONTENT_TYPES[kind]
            or not isinstance(item.get("name"), str) or not item["name"].startswith(project_prefix)
            or not re.fullmatch(r"[a-z0-9/._-]+", item["name"]) or ".." in item["name"]
            or type(item.get("bytes")) is not int or item["bytes"] < (1 if kind == "mp4" else 0)
            or not isinstance(item.get("sha256"), str) or not re.fullmatch(r"[a-f0-9]{64}", item["sha256"])
            or not isinstance(item.get("generation"), str) or not re.fullmatch(r"[1-9][0-9]{0,30}", item["generation"])):
        raise HTTPException(409, "No se puede verificar uno de los archivos del clip. Volvé a generar el clip.")


def prepare(job_id, tokens: list[str], principal) -> Package:
    selections = _parse(tokens)
    members: list[Member] = []
    provenance = []
    total = 0
    # The project row serializes the snapshot with caption edits and deletion.
    # Release it before starting the stream. No request marks an active task.
    with get_engine().begin() as connection:
        doc = repo.beta_document(connection, principal, job_id)
        project_prefix = f"workspaces/{principal.workspace_id}/jobs/{job_id}/"
        for item in selections:
            objects = clip_captions.selected_output(doc, item.filename, item.revision, item.output_id, connection)
            files = []
            for kind, original in objects.items():
                _validate_object(original, kind, project_prefix)
                total += original["bytes"]
                if total > MAX_BYTES:
                    raise HTTPException(413, "Los archivos seleccionados superan 128 MiB. Seleccioná menos clips.")
                filename = f"{item.filename.removesuffix('.mp4')}.{kind}"
                members.append(Member(filename, original))
                files.append({"file": filename, "bytes": original["bytes"], "sha256": original["sha256"]})
            provenance.append({
                "clip": item.filename, "caption_revision": item.revision, "output_id": item.output_id, "files": files,
            })
    return Package(len(selections), total, tuple(members), tuple(provenance))


class _ChunkSink:
    """Unseekable ZIP sink that retains only the output of one write step."""
    def __init__(self):
        self.chunks: list[bytes] = []

    def write(self, data: bytes) -> int:
        if data:
            self.chunks.append(data)
        return len(data)

    def flush(self):
        pass

    def drain(self) -> Iterable[bytes]:
        chunks, self.chunks = self.chunks, []
        return chunks


def _check_deadline(deadline):
    if monotonic() > deadline:
        raise storage.StorageError("Se agotó el tiempo de transferencia del ZIP.")


def _write_member(archive, sink, member, deadline) -> Iterator[bytes]:
    _check_deadline(deadline)
    item = member.object
    source = storage.open_object(item, retry=False, timeout=OBJECT_TIMEOUT)
    digest = hashlib.sha256()
    size = 0
    try:
        entry = ZipInfo(member.filename)
        entry.file_size = item["bytes"]
        with archive.open(entry, "w", force_zip64=True) as target:
            for chunk in source.iter_content(CHUNK_BYTES):
                _check_deadline(deadline)
                size += len(chunk)
                if size > item["bytes"]:
                    raise storage.StorageError("Cambió el tamaño de un archivo del ZIP.")
                digest.update(chunk)
                target.write(chunk)
                yield from sink.drain()
            if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
                raise storage.StorageError("Un archivo del ZIP no pasó la verificación.")
    except RequestException:
        raise storage.TransportError("Se interrumpió la transferencia de un archivo del ZIP.") from None
    finally:
        storage.close(source)
    yield from sink.drain()


def chunks(package: Package) -> Iterator[bytes]:
    deadline = monotonic() + STREAM_SECONDS
    sink = _ChunkSink()
    with ZipFile(sink, "w", compression=ZIP_STORED, allowZip64=True) as archive:
        for member in package.members:
            yield from _write_member(archive, sink, member, deadline)
        info = ZipInfo("manifest.json")
        data = json.dumps({"clips": package.provenance}, ensure_ascii=False, separators=(",", ":"))
        archive.writestr(info, data)
    # An interrupted or corrupt member never emits the archive footer.
    yield from sink.drain()
