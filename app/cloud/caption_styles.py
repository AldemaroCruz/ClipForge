"""Private, revisioned subtitle styles for the INT creator portal."""
from contextlib import contextmanager
from typing import Literal
import uuid

from fastapi import APIRouter, HTTPException, Query, Request
from pydantic import BaseModel, ConfigDict, Field, RootModel, field_validator, model_validator
from sqlalchemy import text

from ..auth_db import get_engine
from ..logo_placement import LogoPlacement
from ..presentation import Presentation, separate_highlight
from ..subtitles import plain_text
from . import creator_logos
from . import repository as repo

FONT = "DejaVu Sans Bold"
STYLE_LIMIT = 200
STYLE_ID = r"^[0-9a-f]{32}$"
STYLE_FIELDS = {key for key in Presentation.model_fields if key.startswith("subtitle_")}
router = APIRouter(prefix="/caption-styles")


def style_values(options):
    return Presentation.model_validate(options).model_dump(include=STYLE_FIELDS)


def _style_row(row):
    item = dict(row)
    extension = item.pop("style_highlight") or {}
    item["style"] = style_values({**item["style"], **extension})
    return item


class SavedStyle(RootModel[dict]):
    @model_validator(mode="before")
    @classmethod
    def normalize(cls, value):
        if not isinstance(value, dict) or not value.keys() <= STYLE_FIELDS:
            raise ValueError("El estilo admite únicamente los parámetros de presentación de los subtítulos.")
        return style_values(value)


class StyleInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    name: str = Field(min_length=1, max_length=80)
    font: Literal["DejaVu Sans Bold"]
    style: SavedStyle
    logo: LogoPlacement | None = None

    @field_validator("name")
    @classmethod
    def normalize_name(cls, value):
        name = plain_text(value)
        if not name:
            raise ValueError("Escribe un nombre para el estilo.")
        return name


class StyleUpdate(StyleInput):
    revision: int = Field(ge=1, strict=True)


class StyleRevision(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str = Field(pattern=STYLE_ID)
    revision: int = Field(ge=1, strict=True)


class DefaultStyle(BaseModel):
    model_config = ConfigDict(extra="forbid")
    id: str | None = Field(pattern=STYLE_ID)
    revision: int | None = Field(default=None, ge=1, strict=True)

    @model_validator(mode="after")
    def validate_pair(self):
        if (self.id is None) != (self.revision is None):
            raise ValueError("Indica el estilo predeterminado y su versión.")
        return self


@contextmanager
def owner_transaction(principal, *, mutate=False):
    with get_engine().begin() as connection:
        repo.check_active_workspace(connection, principal)
        if mutate:
            connection.execute(text("SELECT pg_advisory_xact_lock(:namespace,hashtext(:owner))"),
                               {"namespace": creator_logos.OWNER_LOCK, "owner": principal.id})
        yield connection


def owned_style(connection, owner, style_id, revision=None):
    item = connection.execute(text("""
        SELECT id,name,font,style,style_highlight,logo,revision,is_default
        FROM cloud_caption_styles WHERE owner_id=:o AND id=:i
        """), {"o": owner, "i": style_id}).mappings().first()
    if item is None:
        raise HTTPException(404, "Estilo no encontrado.")
    if revision is not None and item["revision"] != revision:
        raise HTTPException(409, "El estilo cambió. Volvé a abrir la lista de estilos.")
    return _style_row(item)


def snapshot(item):
    return {key: item[key] for key in ("id", "revision", "font")}


def resolve(connection, principal, payload, options, previous_options, previous_snapshot, previous_logo=None):
    """Apply exact values from a current preset or keep an unchanged stored copy."""
    if payload.style_template is not None:
        reference = payload.style_template
        item = owned_style(connection, principal.id, reference.id, reference.revision)
        logo = creator_logos.template_logo(connection, principal, item["logo"], previous_logo)
        return {**options, **item["style"]}, snapshot(item), logo
    logo = creator_logos.resolve(connection, principal, payload, previous_logo)
    if previous_snapshot and style_values(options) == style_values(previous_options) and logo == previous_logo:
        return options, previous_snapshot, logo
    return options, None, logo


def default_for(connection, owner):
    row = connection.execute(text("""
        SELECT id,font,style,style_highlight,logo,revision FROM cloud_caption_styles WHERE owner_id=:o AND is_default
        """), {"o": owner}).mappings().first()
    return _style_row(row) if row else None


def _check_name(connection, owner, name, style_id=""):
    duplicate = connection.execute(text("""
        SELECT 1 FROM cloud_caption_styles WHERE owner_id=:o AND name_key=:n AND id<>:i
        """), {"o": owner, "n": name.casefold(), "i": style_id}).scalar()
    if duplicate:
        raise HTTPException(409, "Ya tenés un estilo con ese nombre.")


@router.get("")
def list_styles(request: Request):
    principal = request.state.principal
    with owner_transaction(principal) as connection:
        rows = connection.execute(text("""
            SELECT id,name,font,style,style_highlight,logo,revision,is_default
            FROM cloud_caption_styles WHERE owner_id=:o ORDER BY name_key,id
            """), {"o": principal.id}).mappings().all()
    return {"styles": [_style_row(row) for row in rows],
            "fonts": [{"id": FONT, "label": FONT}]}


@router.post("", status_code=201)
def create_style(payload: StyleInput, request: Request):
    principal = request.state.principal
    style, highlight = separate_highlight(payload.style.root)
    with owner_transaction(principal, mutate=True) as connection:
        _check_name(connection, principal.id, payload.name)
        count = connection.execute(text("SELECT count(*) FROM cloud_caption_styles WHERE owner_id=:o"),
                                   {"o": principal.id}).scalar_one()
        if count >= STYLE_LIMIT:
            raise HTTPException(409, "Alcanzaste el máximo de estilos guardados.")
        logo = creator_logos.resolve(connection, principal, payload)
        return _style_row(connection.execute(text("""
            INSERT INTO cloud_caption_styles(id,owner_id,name,name_key,font,style,style_highlight,logo)
            VALUES (:i,:o,:n,:k,:f,CAST(:s AS jsonb),CAST(:h AS jsonb),CAST(:l AS jsonb))
            RETURNING id,name,font,style,style_highlight,logo,revision,is_default
            """), {"i": uuid.uuid4().hex, "o": principal.id, "n": payload.name, "k": payload.name.casefold(),
                   "f": payload.font, "s": repo.packed(style), "h": repo.packed(highlight) if highlight else None,
                   "l": repo.packed(logo) if logo is not None else None}).mappings().one())


@router.put("/default")
def choose_default(payload: DefaultStyle, request: Request):
    principal = request.state.principal
    with owner_transaction(principal, mutate=True) as connection:
        if payload.id is not None:
            owned_style(connection, principal.id, payload.id, payload.revision)
        connection.execute(text("UPDATE cloud_caption_styles SET is_default=false WHERE owner_id=:o AND is_default"),
                           {"o": principal.id})
        if payload.id is not None:
            connection.execute(text("UPDATE cloud_caption_styles SET is_default=true WHERE owner_id=:o AND id=:i"),
                               {"o": principal.id, "i": payload.id})
    return {"default_id": payload.id}


@router.get("/{style_id}")
def get_style(style_id: str, request: Request):
    principal = request.state.principal
    with owner_transaction(principal) as connection:
        return owned_style(connection, principal.id, style_id)


@router.put("/{style_id}")
def update_style(style_id: str, payload: StyleUpdate, request: Request):
    principal = request.state.principal
    style, highlight = separate_highlight(payload.style.root)
    with owner_transaction(principal, mutate=True) as connection:
        previous = owned_style(connection, principal.id, style_id, payload.revision)
        logo = creator_logos.resolve(connection, principal, payload, previous["logo"])
        if (previous["logo"] == logo
                and all(previous[key] == value for key, value in payload.model_dump(exclude={"revision", "logo"}).items())):
            return previous
        _check_name(connection, principal.id, payload.name, style_id)
        return _style_row(connection.execute(text("""
            UPDATE cloud_caption_styles SET name=:n,name_key=:k,font=:f,style=CAST(:s AS jsonb),style_highlight=CAST(:h AS jsonb),
                logo=CAST(:l AS jsonb),revision=revision+1
            WHERE owner_id=:o AND id=:i RETURNING id,name,font,style,style_highlight,logo,revision,is_default
            """), {"i": style_id, "o": principal.id, "n": payload.name, "k": payload.name.casefold(),
                   "f": payload.font, "s": repo.packed(style), "h": repo.packed(highlight) if highlight else None,
                   "l": repo.packed(logo) if logo is not None else None}).mappings().one())


@router.delete("/{style_id}")
def delete_style(style_id: str, request: Request, revision: int = Query(ge=1)):
    principal = request.state.principal
    with owner_transaction(principal, mutate=True) as connection:
        owned_style(connection, principal.id, style_id, revision)
        connection.execute(text("DELETE FROM cloud_caption_styles WHERE owner_id=:o AND id=:i"),
                           {"o": principal.id, "i": style_id})
    return {"deleted": True}
