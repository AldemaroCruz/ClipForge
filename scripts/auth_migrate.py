"""Apply AUTH-01 migrations only to the explicitly configured PostgreSQL database."""
import json
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from app.auth_migrations import MigrationError, upgrade


def main():
    try:
        result = upgrade()
    except MigrationError as error:
        print(str(error), file=sys.stderr)
        return 1
    print(json.dumps(result))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
