"""Validated public presentation schema. No arbitrary filter expressions accepted."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, field_validator


class Presentation(BaseModel):
    model_config = ConfigDict(extra="forbid")
    framing: Literal["contain", "blur", "crop"] = "contain"
    burn_subtitles: bool = False
    # Script-space font size on the 1080 x 1920 export, not browser CSS pixels.
    # Flat fields keep multipart uploads and existing JSON requests compatible.
    subtitle_font_size: int = Field(default=52, ge=24, le=120, strict=True)
    subtitle_color: str = Field(default="#FFFFFF", min_length=7, max_length=7,
                                pattern=r"^#[0-9a-fA-F]{6}$")

    subtitle_position: Literal["bottom", "center", "top"] = "bottom"
    subtitle_margin_v: int = Field(default=230, ge=0, le=650, strict=True)
    subtitle_outline: int = Field(default=3, ge=0, le=12, strict=True)
    subtitle_outline_color: str = Field(default="#201510", min_length=7, max_length=7,
                                        pattern=r"^#[0-9a-fA-F]{6}$")
    subtitle_shadow: int = Field(default=1, ge=0, le=8, strict=True)

    crop_x: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)
    crop_y: float = Field(default=0.5, ge=0, le=1, allow_inf_nan=False)
    crop_zoom: float = Field(default=1, ge=1, le=3, allow_inf_nan=False)

    @field_validator("subtitle_color", "subtitle_outline_color")
    @classmethod
    def normalize_subtitle_color(cls, value: str) -> str:
        return value.upper()


class Cue(BaseModel):
    model_config = ConfigDict(extra="forbid")
    start: float = Field(ge=0, le=60, allow_inf_nan=False)
    end: float = Field(gt=0, le=60, allow_inf_nan=False)
    text: str = Field(min_length=1, max_length=500)


class ExportRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")
    options: Presentation = Field(default_factory=Presentation)
    cues: list[Cue] = Field(max_length=400)
