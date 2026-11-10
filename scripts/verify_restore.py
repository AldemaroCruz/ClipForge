"""Read-only verification of a restored tree against the trusted archive.

Invoked in the INSTALLED image, with PYTHONPATH=/app and read-only mounts.
No app server, inference, ffmpeg, network, timestamp mutation or JSON rewriting.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import zipfile

from app.backup import archive_manifest, digest_file, inventory, verify_backup


def verify_restored(archive: Path, root: Path, expected_sha256: str) -> dict[str, object]:
    """Re-read bytes and integer mtimes after restoration, fail closed on any mismatch."""
    if root.is_symlink() or not root.is_dir():
        raise ValueError('La raiz restaurada debe ser un directorio real existente.')
    summary = verify_backup(archive, expected_sha256)
    with zipfile.ZipFile(archive) as zipped:
        manifest = archive_manifest(zipped)
    expected = {item['path']: item for item in manifest['files']}
    actual, excluded = inventory(root)
    if excluded or {name for name, _ in actual} != set(expected):
        raise ValueError('El inventario restaurado difiere del manifiesto.')
    # inventory ignores the runtime lease. A fresh recovery must not contain one.
    if (root / '.clipforge-runtime.lock').exists() or (root / '.clipforge-runtime.lock').is_symlink():
        raise ValueError('El destino de prueba tiene un lock de aplicacion; no es una copia recien restaurada.')
    for name, path in actual:
        entry = expected[name]
        before = path.stat()
        if before.st_size != entry['bytes'] or digest_file(path) != entry['sha256']:
            raise ValueError('El contenido restaurado no coincide con el SHA-256 del manifiesto.')
        after = path.stat()
        if after.st_size != before.st_size or after.st_mtime_ns != before.st_mtime_ns:
            raise ValueError('Un archivo restaurado cambio durante la verificacion.')
        if after.st_mtime_ns != entry['mtime_ns']:
            # Expose only integer diagnostic values, never transcription or key material.
            raise ValueError(
                'Fecha restaurada distinta: esperado_ns={0}, observado_ns={1}, delta_ns={2}. '
                'No se declara compatible con las propuestas IA.'.format(
                    entry['mtime_ns'], after.st_mtime_ns,
                    after.st_mtime_ns - entry['mtime_ns']))
    return {
        'status': 'ok', 'scope': 'restored_bytes_and_exact_mtimes',
        'files': summary['files'], 'bytes': summary['bytes'],
        'hashes_match': True, 'timestamps_match': True,
        'content_reviewed': False, 'ai_inference_tested': False,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--archive', type=Path, required=True)
    parser.add_argument('--root', type=Path, required=True)
    parser.add_argument('--sha256', required=True)
    args = parser.parse_args(argv)
    try:
        result = verify_restored(args.archive, args.root, args.sha256)
    except Exception as exc:
        message = str(exc) if isinstance(exc, ValueError) else 'Verificacion fallida: revisa lectura, formato y permisos.'
        print(json.dumps({'status': 'failed', 'error_type': type(exc).__name__, 'message': message}, ensure_ascii=False), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
