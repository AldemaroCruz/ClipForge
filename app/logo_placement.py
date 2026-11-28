"""Private creator logo identity and its placement on the final frame."""
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field


class LogoPlacement(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[a-f0-9]{32}$")
    revision: int = Field(ge=1, le=2_147_483_647, strict=True)
    position: Literal["top-left", "top-right", "bottom-left", "bottom-right"] = "top-right"
    # Size is the longest side, and both margins are measured against frame width.
    size: int = Field(default=18, ge=5, le=40, strict=True)
    opacity: int = Field(default=80, ge=0, le=100, strict=True)
    margin: int = Field(default=4, ge=0, le=20, strict=True)
