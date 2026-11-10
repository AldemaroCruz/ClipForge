"""Read-only pre-upgrade check for the mounted project and persisted job states.

The helper container supplies PYTHONPATH=/tools and mounts app/ and scripts/ there.
This command uses only the standard library and never starts the application.
"""
from __future__ import annotations

import argparse
from pathlib import Path

from app import backup, lease


def verify_mounted_imports() -> None:
    """Reject accidental imports from the old image or an unrelated app package."""
    expected_app = Path(__file__).resolve().parents[1] / "app"
    for module, filename in ((backup, "backup.py"), (lease, "lease.py")):
        origin = getattr(module, "__file__", None)
        if origin is None or Path(origin).resolve() != (expected_app / filename).resolve():
            raise RuntimeError(
                "Upgrade helper imported the wrong app package. "
                "Check the /tools mounts and PYTHONPATH=/tools; do not stop the service."
            )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, default=Path("/data"))
    args = parser.parse_args(argv)
    verify_mounted_imports()
    print("Upgrade imports OK: app.backup + app.lease from mounted project.", flush=True)
    files, _ = backup.inventory(args.data)
    backup.assert_quiescent(files)
    print("No active persisted job/export/AI state. Do not start new work during maintenance.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
