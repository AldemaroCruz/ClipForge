"""Store private static PNGs in immutable generations scoped to a creator."""
from contextlib import contextmanager
from hashlib import sha256
from io import BytesIO
from struct import unpack
import uuid

from fastapi import APIRouter, HTTPException, Query, Request, Response
from sqlalchemy import text
from starlette.concurrency import run_in_threadpool

from ..auth_db import get_engine
from ..logo_placement import LogoPlacement
from ..subtitles import plain_text
from . import repository as repo, storage

MAX_BYTES = 5 * 1024 * 1024
MAX_DIMENSION = 2048
MAX_STORED_BYTES = 17 * 1024 * 1024  # Canonical RGBA can be larger than the upload.
MAX_REVISION = 2_147_483_647
OWNER_LOCK = 1837086435
ID_PATTERN = r"^[a-f0-9]{32}$"
PNG_HEADER = b"\x89PNG\r\n\x1a\n\0\0\0\rIHDR"
PNG_ERROR = "Elegí un PNG estático válido de hasta 5 MiB y 2048 píxeles por lado."
router = APIRouter(prefix="/creator-logos")


def canonical_png(data):
    from PIL import Image

    if not data.startswith(PNG_HEADER) or len(data) < 33:
        raise HTTPException(422, PNG_ERROR)
    width, height = unpack(">II", data[16:24])
    if not 1 <= width <= MAX_DIMENSION or not 1 <= height <= MAX_DIMENSION:
        raise HTTPException(422, PNG_ERROR)
    try:
        with Image.open(BytesIO(data), formats=["PNG"]) as original:
            if original.get_format_mimetype() == "image/apng":
                raise ValueError("Animated PNG")
            original.verify()
        with Image.open(BytesIO(data), formats=["PNG"]) as original:
            original.load()
            with original.convert("RGBA") as image:
                image.info.clear()
                output = BytesIO()
                image.save(output, format="PNG")
    except (OSError, SyntaxError, ValueError, Image.DecompressionBombError):
        raise HTTPException(422, PNG_ERROR) from None
    if output.tell() > MAX_STORED_BYTES:
        raise HTTPException(422, PNG_ERROR)
    return output, width, height


async def uploaded_png(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "image/png":
        raise HTTPException(415, PNG_ERROR)
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_BYTES:
            raise HTTPException(413, PNG_ERROR)
        data.extend(chunk)
    return await run_in_threadpool(canonical_png, data)


@contextmanager
def _library(principal, *, mutate=False):
    with get_engine().begin() as connection:
        repo.check_active_workspace(connection, principal)
        if mutate:
            connection.execute(text("SELECT pg_advisory_xact_lock(:ns,hashtext(:owner))"),
                               {"ns": OWNER_LOCK, "owner": principal.id})
        yield connection


def _read_revision(connection, owner_id, workspace_id, logo_id, revision):
    item = connection.execute(text("""
        SELECT l.id,l.name,l.retired_at,l.latest_revision,r.revision,r.width,r.height,r.object
        FROM cloud_creator_logos l JOIN cloud_creator_logo_revisions r ON r.logo_id=l.id
        WHERE l.id=:i AND l.owner_id=:o AND l.workspace_id=:w AND r.revision=:r
        """), {"i": logo_id, "o": owner_id, "w": workspace_id, "r": revision}).mappings().first()
    if item is None:
        raise HTTPException(404, "Logo no encontrado.")
    return item


def storage_item_for_job(job_id, logo):
    placement = LogoPlacement.model_validate(logo)
    with get_engine().connect() as connection:
        owner = connection.execute(text("""
            SELECT owner_id,workspace_id FROM auth_projects
            WHERE id=:i AND deletion_started_at IS NULL
            """), {"i": job_id}).mappings().first()
        if owner is None:
            raise HTTPException(404, "Trabajo no encontrado.")
        return _read_revision(connection, owner["owner_id"], owner["workspace_id"],
                              placement.id, placement.revision)["object"]


def resolve(connection, principal, payload, previous=None):
    """A retained snapshot can be edited after its library item was retired."""
    if "logo" not in payload.model_fields_set:
        return previous
    logo = payload.logo
    if logo is None:
        return None
    old = previous or {}
    if logo.id != old.get("id") or logo.revision != old.get("revision"):
        row = _read_revision(connection, principal.id, principal.workspace_id, logo.id, logo.revision)
        if row["retired_at"] is not None or row["latest_revision"] != logo.revision:
            raise HTTPException(409, "El logo cambió o se retiró. Volvé a abrir la biblioteca.")
    return logo.model_dump()


def template_logo(connection, principal, logo, previous=None):
    if logo is None or logo == previous:
        return logo
    row = _read_revision(connection, principal.id, principal.workspace_id, logo["id"], logo["revision"])
    return logo if row["retired_at"] is None else None


def _public(row):
    data = {key: row[key] for key in ("id", "name", "revision", "width", "height")}
    return {**data, "url": f"/creator-logos/{data['id']}/{data['revision']}"}


@router.get("")
def list_logos(request: Request):
    principal = request.state.principal
    with _library(principal) as connection:
        rows = connection.execute(text("""
            SELECT l.id,l.name,r.revision,r.width,r.height
            FROM cloud_creator_logos l JOIN cloud_creator_logo_revisions r ON r.logo_id=l.id
            WHERE l.owner_id=:o AND l.workspace_id=:w AND l.retired_at IS NULL
              AND l.latest_revision=r.revision ORDER BY lower(l.name),l.id
            """), {"o": principal.id, "w": principal.workspace_id}).mappings().all()
    return {"logos": [_public(row) for row in rows]}


def _store(principal, name, data, logo_id=None, revision=None):
    name = plain_text(name)
    if not name:
        raise HTTPException(422, "Escribí un nombre para el logo.")
    source, width, height = data
    with _library(principal, mutate=True) as connection:
        if logo_id is not None:
            old = _read_revision(connection, principal.id, principal.workspace_id, logo_id, revision)
            if old["retired_at"] is not None or old["latest_revision"] != revision:
                raise HTTPException(409, "El logo cambió o se retiró. Volvé a abrir la biblioteca.")
        target = logo_id or uuid.uuid4().hex
        next_revision = (revision or 0) + 1
        digest = sha256(source.getbuffer()).hexdigest()
        # An interrupted database write can adopt the same verified GCS
        # generation on retry without replacing any installed reference.
        object_name = f"workspaces/{principal.workspace_id}/creator-logos/{digest}.png"
        try:
            manifest = storage.upload(object_name, source, "image/png", reuse_identical=True)
        except storage.StorageError:
            raise HTTPException(502, "No se pudo guardar el logo. Volvé a intentarlo.") from None
        values = {"i": target, "o": principal.id, "w": principal.workspace_id, "n": name, "r": next_revision,
                  "x": width, "y": height, "object": repo.packed(manifest)}
        if logo_id is None:
            connection.execute(text("""
                INSERT INTO cloud_creator_logos(id,owner_id,workspace_id,name,latest_revision)
                VALUES (:i,:o,:w,:n,:r)
                """), values)
        else:
            connection.execute(text("""
                UPDATE cloud_creator_logos SET name=:n,latest_revision=:r WHERE id=:i
                """), values)
        connection.execute(text("""
            INSERT INTO cloud_creator_logo_revisions(logo_id,revision,width,height,object)
            VALUES (:i,:r,:x,:y,CAST(:object AS jsonb))
            """), values)
    return _public({"id": target, "name": name, "revision": next_revision, "width": width, "height": height})


@router.post("", status_code=201)
async def create_logo(request: Request, name: str = Query(min_length=1, max_length=80)):
    data = await uploaded_png(request)
    return await run_in_threadpool(_store, request.state.principal, name, data)


@router.put("/{logo_id}")
async def replace_logo(logo_id: str, request: Request, name: str = Query(min_length=1, max_length=80),
                       revision: int = Query(ge=1, lt=MAX_REVISION)):
    data = await uploaded_png(request)
    return await run_in_threadpool(_store, request.state.principal, name, data, logo_id, revision)


@router.delete("/{logo_id}")
def retire_logo(logo_id: str, request: Request, revision: int = Query(ge=1, le=MAX_REVISION)):
    principal = request.state.principal
    with _library(principal, mutate=True) as connection:
        item = _read_revision(connection, principal.id, principal.workspace_id, logo_id, revision)
        if item["latest_revision"] != revision:
            raise HTTPException(409, "El logo cambió. Volvé a abrir la biblioteca.")
        connection.execute(text("""
            UPDATE cloud_creator_logos SET retired_at=clock_timestamp()
            WHERE id=:i AND retired_at IS NULL
            """), {"i": logo_id})
        connection.execute(text("""
            UPDATE cloud_caption_styles SET logo=NULL,revision=revision+1
            WHERE owner_id=:o AND logo->>'id'=:i
            """), {"o": principal.id, "i": logo_id})
    return {"retired": True}


@router.get("/{logo_id}/{revision}")
def logo_image(logo_id: str, revision: int, request: Request):
    principal = request.state.principal
    with _library(principal) as connection:
        item = _read_revision(connection, principal.id, principal.workspace_id, logo_id, revision)["object"]
    try:
        upstream = storage.open_object(item)
        try:
            data = bytearray()
            for chunk in upstream.iter_content(128 * 1024):
                if len(data) + len(chunk) > min(MAX_STORED_BYTES, item["bytes"]):
                    raise storage.StorageError("Logo generation size mismatch")
                data.extend(chunk)
            if len(data) != item["bytes"] or sha256(data).hexdigest() != item["sha256"]:
                raise storage.StorageError("Logo generation digest mismatch")
        finally:
            storage.close(upstream)
    except storage.StorageError:
        raise HTTPException(502, "El logo guardado todavía no está disponible.") from None
    return Response(bytes(data), media_type="image/png", headers={"Cache-Control": "private, no-store"})
