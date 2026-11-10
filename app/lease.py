"""Cross-process exclusion for one API or one offline maintenance command.

This is not a distributed lock. Use only a local filesystem and a single host.
The lock file is intentionally retained: unlinking a held inode breaks exclusion.
"""
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator
import os


class LeaseBusy(RuntimeError):
    pass


@contextmanager
def data_lease(root: Path) -> Iterator[None]:
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    path = root / '.clipforge-runtime.lock'
    if path.is_symlink():
        raise ValueError('El archivo de bloqueo no puede ser un enlace.')
    handle = path.open('a+b')
    try:
        if os.name == 'nt':
            import msvcrt
            if path.stat().st_size == 0:
                handle.write(b'\0'); handle.flush()
            handle.seek(0)
            try:
                msvcrt.locking(handle.fileno(), msvcrt.LK_NBLCK, 1)
            except OSError as exc:
                raise LeaseBusy('data/ está en uso; detén la aplicación antes de mantenerla.') from exc
        else:
            import fcntl
            try:
                fcntl.flock(handle.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise LeaseBusy('data/ está en uso; detén la aplicación antes de mantenerla.') from exc
        yield
    finally:
        handle.close()  # Releases the OS lock, including on process termination.
