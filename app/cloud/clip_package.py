"""Authenticated, bounded ZIP streams from generation-pinned clip versions."""
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
from . import clip_captions, publication, repository as repo, storage

MAX_CLIPS = 30
MAX_BYTES = 128 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024
STREAM_SECONDS = 150
OBJECT_TIMEOUT = (5, 15)
SELECTION = re.compile(r"(clip_[0-9]{2}\.mp4):([1-9][0-9]{0,9}):([a-f0-9]{32}(?:[a-f0-9]{32})?)")
EXPORT_SELECTION = re.compile(r"export:([a-f0-9]{32}):([1-9][0-9]{0,18})")
DOCUMENT_ID = re.compile(r"[a-f0-9]{32}")
CONTENT_TYPES = {"mp4": "video/mp4", "srt": "application/x-subrip", "vtt": "text/vtt"}


@dataclass(frozen=True)
class Selection:
    filename: str | None
    revision: int
    output_id: str


@dataclass(frozen=True)
class Member:
    filename: str
    object: dict | None = None
    content: bytes | None = None


@dataclass(frozen=True)
class Package:
    clips: int
    bytes: int
    members: tuple[Member, ...]
    provenance: tuple[dict, ...]
    export_provenance: tuple[dict, ...] = ()

    def summary(self):
        return {"clips": self.clips, "bytes": self.bytes, "max_clips": MAX_CLIPS, "max_bytes": MAX_BYTES}


def _parse(tokens: list[str]) -> list[Selection]:
    selections = []
    for token in tokens:
        match = SELECTION.fullmatch(token)
        if match is not None:
            filename, revision, output_id = match.groups()
            selections.append(Selection(filename, int(revision), output_id))
            continue
        match = EXPORT_SELECTION.fullmatch(token)
        if match is None:
            raise HTTPException(422, "La selección de clips no es válida.")
        output_id, revision = match.groups()
        selections.append(Selection(None, int(revision), output_id))
    if not 1 <= len(selections) <= MAX_CLIPS or len({item.filename or item.output_id for item in selections}) != len(selections):
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


def is_pilot_manual_export(item):
    return (item.get("clip_file") == "manual.mp4" and item.get("title") == "Fragmento manual"
            and (item.get("pilot") is True or item.get("pilot") is None))


def _completed_export(document):
    item = document["payload"]
    if item.get("status") != "completed" or item.get("clip_captions") is True:
        return None, {}
    draft_id = item.get("draft_id")
    if item.get("pilot") is True and isinstance(draft_id, str) and DOCUMENT_ID.fullmatch(draft_id):
        kind = "editorial"
    elif is_pilot_manual_export(item):
        kind = "manual"
    else:
        return None, {}
    manifest = document["manifest"]
    if "clip.mp4" not in manifest:
        return None, {}
    return kind, {part: manifest[f"clip.{part}"] for part in CONTENT_TYPES if f"clip.{part}" in manifest}


def export_selection(document, job_id, workspace_id):
    """Advertise only completed exports with verifiable files from this project."""
    _, objects = _completed_export(document)
    export_id = document["payload"].get("id")
    if not objects or not isinstance(export_id, str) or not DOCUMENT_ID.fullmatch(export_id):
        return {}
    try:
        for kind, original in objects.items():
            _validate_object(original, kind, f"workspaces/{workspace_id}/jobs/{job_id}/")
    except HTTPException:
        return {}
    return {"archive_selection": f"export:{export_id}:{document['revision']}",
            "archive_files": list(objects)}


def _publication_revisions(tokens, publications):
    revisions = {}
    for token in publications:
        selection, _, revision = token.rpartition("~")
        if (selection not in tokens or selection in revisions
                or not re.fullmatch(r"[1-9][0-9]{0,18}", revision)):
            raise HTTPException(422, "La selección de textos para el ZIP no es válida.")
        revisions[selection] = int(revision)
    return revisions


def prepare(job_id, tokens: list[str], principal, publications=()) -> Package:
    selections = _parse(tokens)
    text_revisions = _publication_revisions(set(tokens), publications)
    members: list[Member] = []
    provenance = []
    export_provenance = []
    total = 0
    # The project row serializes the snapshot with caption edits and deletion.
    # Release it before starting the stream. No request marks an active task.
    with get_engine().begin() as connection:
        doc = repo.beta_document(connection, principal, job_id)
        project_prefix = f"workspaces/{principal.workspace_id}/jobs/{job_id}/"
        for token, item in zip(tokens, selections, strict=True):
            files = []
            if item.filename is not None:
                objects = clip_captions.selected_output(doc, item.filename, item.revision, item.output_id, connection)
                stem = item.filename.removesuffix(".mp4")
                entry = {
                    "clip": item.filename, "caption_revision": item.revision, "output_id": item.output_id, "files": files,
                }
                provenance.append(entry)
            else:
                export = repo.document(job_id, "export", item.output_id, connection)
                export_kind, objects = _completed_export(export)
                if export["revision"] != item.revision or export["payload"].get("id") != item.output_id or not objects:
                    raise HTTPException(409, "Cambió una exportación seleccionada. Actualizá la lista y volvé a seleccionarla.")
                stem = f"{export_kind}_{item.output_id}"
                entry = {
                    "kind": export_kind, "export_id": item.output_id, "revision": item.revision, "files": files,
                }
                export_provenance.append(entry)
            folder = ""
            text_content = None
            if token in text_revisions:
                revision = text_revisions[token]
                saved = publication.saved_for_selection(connection, job_id, token)
                if not saved or saved["revision"] != revision:
                    raise HTTPException(409, "Cambió una revisión de textos. Volvé a seleccionarla para el ZIP.")
                text_content = publication.text_bytes(saved)
                folder = f"{stem}/"
                entry["publication_revision"] = revision
            for kind, original in objects.items():
                _validate_object(original, kind, project_prefix)
                total += original["bytes"]
                if total > MAX_BYTES:
                    raise HTTPException(413, "Los archivos seleccionados superan 128 MiB. Seleccioná menos clips.")
                filename = f"{folder}{stem}.{kind}"
                members.append(Member(filename, original))
                files.append({"file": filename, "bytes": original["bytes"], "sha256": original["sha256"]})
            if text_content is not None:
                total += len(text_content)
                if total > MAX_BYTES:
                    raise HTTPException(413, "Los archivos seleccionados superan 128 MiB. Seleccioná menos clips.")
                filename = f"{folder}publicacion.txt"
                members.append(Member(filename, content=text_content))
                files.append({"file": filename, "bytes": len(text_content),
                              "sha256": hashlib.sha256(text_content).hexdigest()})
    return Package(len(selections), total, tuple(members), tuple(provenance), tuple(export_provenance))


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
    if member.content is not None:
        archive.writestr(ZipInfo(member.filename), member.content)
        yield from sink.drain()
        return
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
        manifest = {"clips": package.provenance}
        if package.export_provenance:
            manifest["exports"] = package.export_provenance
        data = json.dumps(manifest, ensure_ascii=False, separators=(",", ":"))
        archive.writestr(info, data)
    # An interrupted or corrupt member never emits the archive footer.
    yield from sink.drain()
