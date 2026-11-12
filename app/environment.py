"""Public, non-secret local environment identification; no runtime inspection."""
import os
import re

from fastapi import HTTPException


def identity():
    label = os.getenv("CLIPFORGE_ENVIRONMENT", "")
    revision = os.getenv("CLIPFORGE_REVISION", "")
    if not label and not revision:
        return {"environment": "", "revision": ""}
    if label not in {"DEV", "INT", "RESTORE"} or not re.fullmatch(r"[0-9a-f]{40}", revision):
        raise HTTPException(503, "La identificación del ambiente no está disponible.")
    return {"environment": label, "revision": revision}
