"""Creator beta feedback stored in PostgreSQL without exposing project content."""
from contextlib import contextmanager
import json
from typing import Literal
import unicodedata
import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, StrictBool, ValidationError, field_validator, model_validator
from sqlalchemy import column, select, table, text
from sqlalchemy.exc import SQLAlchemyError
from starlette.concurrency import run_in_threadpool

from ..auth import require_access
from ..auth_db import AuthConfigurationError, get_engine
from ..environment import identity
from . import repository

Category = Literal["error", "suggestion", "quality"]
MAX_BODY = 32768
MAX_COMMENT = 2000
REPORT_FIELDS = ("id", "category", "comment", "job_id", "clip_file", "useful",
                 "publishable", "error_code", "application_revision", "created_at")
REPORTS = table("cloud_feedback", column("user_id"), *(column(name) for name in REPORT_FIELDS))
USERS = table("auth_users", column("id"), column("username"))

router = APIRouter(prefix="/beta", tags=["feedback"], dependencies=[Depends(require_access)])


class ReportBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    category: Category
    comment: str = Field(strict=True, min_length=1, max_length=MAX_COMMENT)
    job_id: str | None = Field(default=None, strict=True, pattern=r"^[0-9a-f]{32}$")
    clip_file: str | None = Field(default=None, strict=True, pattern=r"^clip_[0-9]{2}[.]mp4$")
    useful: StrictBool | None = None
    publishable: StrictBool | None = None

    @field_validator("comment")
    @classmethod
    def clean_comment(cls, value):
        value = value.strip()
        if not value or any(unicodedata.category(char) in {"Cc", "Cs"} and char not in "\n\r\t"
                            for char in value):
            raise ValueError("Invalid comment")
        return value

    @model_validator(mode="after")
    def check_association(self):
        if (self.clip_file is not None and self.job_id is None
                or self.clip_file is None and (self.useful is not None or self.publishable is not None)):
            raise ValueError("Invalid clip association")
        return self


async def _body(request):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Envía un objeto JSON.")
    data = bytearray()
    async for chunk in request.stream():
        if len(data) + len(chunk) > MAX_BODY:
            raise HTTPException(413, "El comentario es demasiado grande.")
        data.extend(chunk)
    try:
        return ReportBody.model_validate(json.loads(data))
    except (ValueError, TypeError, ValidationError):
        raise HTTPException(422, "Comentario o contexto de feedback inválido.") from None


@contextmanager
def _storage():
    try:
        with get_engine().begin() as connection:
            yield connection
    except (AuthConfigurationError, SQLAlchemyError):
        raise HTTPException(503, "El almacenamiento de feedback no está disponible.") from None


def _context(connection, principal, body):
    if body.job_id is None:
        return None
    owned = connection.execute(text("""SELECT id FROM auth_projects
        WHERE id=:job AND owner_id=:owner AND workspace_id=:workspace FOR SHARE"""),
        {"job": body.job_id, "owner": principal.id, "workspace": principal.workspace_id}).scalar_one_or_none()
    if owned is None:
        raise HTTPException(404, "Proyecto no encontrado.")
    document = repository.document(body.job_id, connection=connection)
    payload = document["payload"]
    clips = payload.get("clips", [])
    manifest = document["manifest"]
    if body.clip_file is not None and (
        not isinstance(manifest, dict) or body.clip_file not in manifest
        or not isinstance(clips, list)
        or not any(isinstance(clip, dict) and clip.get("file") == body.clip_file for clip in clips)
    ):
        raise HTTPException(404, "Clip no encontrado.")
    if payload.get("status") != "failed":
        return None
    return repository.public_beta_error_code(payload.get("error_code"))


def _submit(principal, body):
    revision = identity()["revision"]
    if not revision:
        raise HTTPException(503, "La versión de la aplicación no está disponible.")
    with _storage() as connection:
        active = connection.execute(text("SELECT id FROM auth_users WHERE id=:user AND is_active FOR SHARE"),
                                    {"user": principal.id}).scalar_one_or_none()
        if active is None:
            raise HTTPException(401, "Inicia sesión para continuar.")
        row = {"id": uuid.uuid4().hex, "user_id": principal.id, **body.model_dump(),
               "error_code": _context(connection, principal, body), "application_revision": revision}
        row["created_at"] = connection.execute(REPORTS.insert().values(**row).returning(
            REPORTS.c.created_at)).scalar_one()
        del row["user_id"]
    return {"item": row}


def _list(principal, limit, offset, *, admin=False):
    if admin and not principal.is_admin:
        raise HTTPException(403, "Se requiere el permiso users:manage.")
    statement = select(*(REPORTS.c[name] for name in REPORT_FIELDS))
    if admin:
        statement = statement.select_from(REPORTS.join(USERS, REPORTS.c.user_id == USERS.c.id))
        statement = statement.add_columns(REPORTS.c.user_id, USERS.c.username)
    else:
        statement = statement.where(REPORTS.c.user_id == principal.id)
    statement = statement.order_by(REPORTS.c.created_at.desc(), REPORTS.c.id.desc()).offset(offset).limit(limit + 1)
    with _storage() as connection:
        rows = connection.execute(statement).mappings().all()
    return {"items": [dict(row) for row in rows[:limit]], "has_more": len(rows) > limit}


@router.post("/feedback", status_code=201)
async def submit_feedback(request: Request):
    body = await _body(request)
    return await run_in_threadpool(_submit, request.state.principal, body)


@router.get("/feedback")
def own_feedback(request: Request, limit: int = Query(20, ge=1, le=50),
                 offset: int = Query(0, ge=0, le=10000)):
    return _list(request.state.principal, limit, offset)


@router.get("/admin/feedback")
def admin_feedback(request: Request, limit: int = Query(20, ge=1, le=50),
                   offset: int = Query(0, ge=0, le=10000)):
    return _list(request.state.principal, limit, offset, admin=True)
