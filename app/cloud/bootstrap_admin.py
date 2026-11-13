"""One-shot first administrator bootstrap from an explicitly mounted secret."""
import json
import os
from pathlib import Path
from ..auth import bootstrap_admin


def main():
    try:
        path = Path(os.environ["CLIPFORGE_BOOTSTRAP_ADMIN_FILE"])
        if path.stat().st_size > 8192:
            raise ValueError("Invalid bootstrap input")
        value = json.loads(path.read_text(encoding="utf-8"))
        if set(value) != {"username", "password"} or not all(isinstance(v, str) for v in value.values()):
            raise ValueError("Invalid bootstrap input")
        bootstrap_admin(value["username"], value["password"])
        print(json.dumps({"status": "created", "credentials_printed": False}))
        return 0
    except Exception:
        print(json.dumps({"status": "failed", "message": "First administrator not created; check protected input and existing administrators."}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
