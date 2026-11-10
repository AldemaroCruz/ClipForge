"""Safe JSON persistence for the single-process local MVP."""

import json
import os
import tempfile
from pathlib import Path
from typing import Any


def write_json_atomic(path: Path, data: Any) -> None:
    """Publish a complete JSON document without truncating its previous version.

    The temporary file lives beside the destination, on the same filesystem.
    This prevents partially written JSON from being visible to readers. It is
    not a database transaction or a lock for multiple independent writers.
    """
    path = Path(path)
    # Serialize first: invalid data must not touch the existing destination.
    payload = json.dumps(data, ensure_ascii=False, indent=2, allow_nan=False)
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            temporary = Path(handle.name)
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
        # Close the temporary file before replacing it (also important on Windows).
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            temporary.unlink(missing_ok=True)
