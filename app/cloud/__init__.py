"""Explicit cloud backend. Importing this package never contacts cloud services."""

import os


def enabled() -> bool:
    value = os.getenv("CLIPFORGE_STORAGE_BACKEND", "local")
    if value not in {"local", "gcs"}:
        raise ValueError("Unsupported storage backend")
    return value == "gcs"
