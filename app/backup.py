"""Offline, streaming backup/verify/restore. No overwrite and no ZIP extractall.

Works with the standard library only. No model import, network or credentials.
A backup is PRIVATE CONTENT, not encrypted; hashes detect corruption, not forgery.
"""
from __future__ import annotations
import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import sys
import tempfile
import time
import zipfile
from .lease import data_lease

FORMAT = 'clipforge-backup-1'
MAX_FILES = 100_000
MAX_BYTES = 500 * 1024**3
MAX_MANIFEST = 40 * 1024**2
CHUNK = 1024**2
ID = r'[0-9a-f]{32}'
# Explicit data schema: unknown files fail rather than vanish in a partial backup.
PATTERNS = [
    rf'{ID}/(?:input\.mp4|job\.json|transcript\.json|project\.json|clip_\d{{2}}\.(?:mp4|srt|vtt|ass))',
    rf'{ID}/previews/source\.jpg', rf'{ID}/drafts/{ID}\.json',
    rf'{ID}/exports/{ID}/(?:export\.json|review\.json|clip\.(?:mp4|srt|vtt|ass))',
    rf'{ID}/selections/{ID}/selection\.json',
    rf'{ID}/deliveries/{ID}/(?:delivery\.json|delivery\.zip)',
    rf'{ID}/metrics/(?:process|export)-{ID}\.json',
    rf'{ID}/review-time/{ID}\.json', rf'templates/{ID}\.json',
]
ALLOWED = re.compile('(?:' + '|'.join(PATTERNS) + ')')


def digest_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open('rb') as f:
        for chunk in iter(lambda: f.read(CHUNK), b''):
            h.update(chunk)
    return h.hexdigest()


def safe_name(name: str) -> str:
    p = PurePosixPath(name)
    if (not name or '\\' in name or ':' in name or p.is_absolute()
            or any(x in {'.', '..', ''} for x in name.split('/'))
            or any(ord(c) < 32 for c in name) or not ALLOWED.fullmatch(name)):
        raise ValueError('Ruta desconocida o insegura en los datos; no se incluyó silenciosamente.')
    return name


def secret_file(path: Path) -> bool:
    return any(x.lower() in {'.env', '.env.ai', 'token', 'stored_tokens', 'credentials.json', 'secrets.json'}
               or x.lower().startswith('.env.') or x.lower().endswith(('.pem', '.key', '.p12'))
               for x in path.parts)


def inventory(root: Path) -> tuple[list[tuple[str, Path]], int]:
    if root.is_symlink() or not root.is_dir():
        raise ValueError('data/ debe ser un directorio real existente.')
    files: list[tuple[str, Path]] = []
    excluded = 0
    for parent, dirs, names in os.walk(root, followlinks=False):
        for d in dirs:
            if (Path(parent) / d).is_symlink():
                raise ValueError('No se permiten enlaces en data/.')
        for name in names:
            p = Path(parent) / name
            relative = p.relative_to(root)
            if p.is_symlink() or not stat.S_ISREG(p.lstat().st_mode):
                raise ValueError('No se permiten enlaces ni archivos especiales.')
            if relative.as_posix() == '.clipforge-runtime.lock':
                continue
            if secret_file(relative):
                excluded += 1
                continue
            n = safe_name(relative.as_posix())
            files.append((n, p))
            if len(files) > MAX_FILES:
                raise ValueError('Demasiados archivos para este backup.')
    return sorted(files), excluded


def assert_quiescent(files: list[tuple[str, Path]]) -> None:
    for name, path in files:
        if path.name not in {'job.json', 'export.json', 'selection.json'}:
            continue
        try:
            obj = json.loads(path.read_text(encoding='utf-8'))
        except (ValueError, OSError):
            # Preserve corrupt bytes as well; restore does NOT promise to repair them.
            continue
        if isinstance(obj, dict) and obj.get('status') in {'queued','validating','transcribing','rendering','running'}:
            raise ValueError('Hay estados activos. Termina los trabajos antes del respaldo; no se reanudarán desde un ZIP.')


def create_backup(root: Path, output: Path) -> dict:
    root, output = Path(root).absolute(), Path(output).absolute()
    if not root.is_dir() or root.is_symlink():
        raise ValueError('La carpeta data/ debe existir; no se respalda una ruta inventada.')
    if output.exists() or output.is_symlink() or output.with_suffix(output.suffix + '.sha256').exists():
        raise FileExistsError('El backup destino ya existe.')
    if output.is_relative_to(root.resolve()) or output.parent.resolve().is_relative_to(root.resolve()):
        raise ValueError('Guarda los backups fuera de data/.')
    output.parent.mkdir(parents=True, exist_ok=True)
    with data_lease(root):
        files, excluded = inventory(root)
        assert_quiescent(files)
        total = sum(p.stat().st_size for _, p in files)
        if total > MAX_BYTES or shutil.disk_usage(output.parent).free < total + 32 * CHUNK:
            raise ValueError('Sin espacio suficiente o backup demasiado grande.')
        manifest = {'format': FORMAT, 'created_at': time.time(), 'app_version': '0.4.2',
                    'files': [], 'excluded_secret_files': excluded,
                    'cache_included': False, 'encrypted': False}
        snapshots = {n: (p.stat().st_size, p.stat().st_mtime_ns) for n, p in files}
        fd, tempname = tempfile.mkstemp(prefix='.backup-', suffix='.tmp', dir=output.parent)
        os.close(fd)
        temp = Path(tempname)
        try:
            with zipfile.ZipFile(temp, 'w', compression=zipfile.ZIP_STORED, allowZip64=True) as z:
                for name, path in files:
                    h = hashlib.sha256(); size = 0
                    with path.open('rb') as src, z.open('data/' + name, 'w', force_zip64=True) as dst:
                        while chunk := src.read(CHUNK):
                            size += len(chunk)
                            if size > snapshots[name][0]:
                                raise ValueError('Los datos cambiaron durante el respaldo.')
                            dst.write(chunk); h.update(chunk)
                    if (size, path.stat().st_mtime_ns) != snapshots[name]:
                        raise ValueError('Los datos cambiaron durante el respaldo.')
                    manifest['files'].append({'path': name, 'bytes': size, 'sha256': h.hexdigest(), 'mtime_ns': snapshots[name][1]})
                again, _ = inventory(root)
                if [n for n, _ in again] != [n for n, _ in files] or any(
                    (p.stat().st_size, p.stat().st_mtime_ns) != snapshots[n] for n,p in again):
                    raise ValueError('Los datos cambiaron durante el respaldo.')
                z.writestr('manifest.json', json.dumps(manifest, ensure_ascii=False, indent=2))
            verify_backup(temp)
            # Reserve the final name with exclusive create; never replace someone else's backup.
            with output.open('xb'):
                pass
            try:
                os.replace(temp, output)
            except Exception:
                output.unlink(missing_ok=True)
                raise
            sha = digest_file(output)
            with output.with_suffix(output.suffix + '.sha256').open('x', encoding='utf-8') as sidecar:
                sidecar.write(f'{sha}  {output.name}\n')
            return {'status':'ok', 'files':len(files), 'data_bytes':total,
                    'sha256':sha, 'excluded_secret_files':excluded, 'encrypted':False}
        finally:
            temp.unlink(missing_ok=True)


def archive_manifest(z: zipfile.ZipFile) -> dict:
    infos = z.infolist()
    names = [i.filename for i in infos]
    if len(infos) > MAX_FILES + 1 or len(set(names)) != len(names) or 'manifest.json' not in names:
        raise ValueError('ZIP duplicado, excesivo o sin manifiesto.')
    if z.getinfo('manifest.json').file_size > MAX_MANIFEST:
        raise ValueError('Manifiesto demasiado grande.')
    m = json.loads(z.read('manifest.json'))
    if not isinstance(m,dict) or m.get('format') != FORMAT or not isinstance(m.get('files'),list):
        raise ValueError('Formato de backup no reconocido.')
    listed: set[str] = set()
    total = 0
    for f in m['files']:
        if not isinstance(f,dict): raise ValueError('Entrada de manifiesto inválida.')
        name = safe_name(f.get('path',''))
        size = f.get('bytes'); sha = f.get('sha256'); mtime = f.get('mtime_ns')
        if (type(size) is not int or size < 0 or type(mtime) is not int or mtime < 0 or not isinstance(sha,str)
                or not re.fullmatch('[a-f0-9]{64}',sha) or name in listed):
            raise ValueError('Tamaño, hash o ruta inválidos.')
        listed.add(name); total += size
        info = z.getinfo('data/' + name)
        mode = info.external_attr >> 16
        if info.is_dir() or stat.S_ISLNK(mode) or (stat.S_IFMT(mode) not in (0, stat.S_IFREG)):
            raise ValueError('Entrada ZIP no regular.')
        if info.file_size != size or info.flag_bits & 1:
            raise ValueError('Tamaño incorrecto o ZIP cifrado no soportado.')
    if total > MAX_BYTES or set(names) != {'manifest.json'} | {'data/' + n for n in listed}:
        raise ValueError('Archivo extra o tamaño fuera del límite.')
    return m


def verify_backup(path: Path, expected_sha256: str | None = None) -> dict:
    if expected_sha256 and (not re.fullmatch('[a-fA-F0-9]{64}',expected_sha256)
                            or digest_file(path) != expected_sha256.lower()):
        raise ValueError('El SHA-256 externo del backup no coincide.')
    with zipfile.ZipFile(path) as z:
        m = archive_manifest(z)
        for f in m['files']:
            h = hashlib.sha256(); count = 0
            with z.open('data/' + f['path']) as src:
                while chunk := src.read(CHUNK):
                    count += len(chunk)
                    if count > f['bytes']: raise ValueError('El tamaño excede el manifiesto.')
                    h.update(chunk)
            if count != f['bytes'] or h.hexdigest() != f['sha256']:
                raise ValueError('CRC o SHA-256 no coincide; backup corrupto.')
    return {'status':'ok', 'files':len(m['files']), 'bytes':sum(f['bytes'] for f in m['files'])}


def restore_backup(path: Path, destination: Path, expected_sha256: str | None = None) -> dict:
    destination = destination.absolute()
    if destination.exists() or destination.is_symlink():
        raise FileExistsError('Restaura en una carpeta NUEVA: nunca se sobrescribe ni mezcla data/.')
    verify_backup(path, expected_sha256)
    destination.parent.mkdir(parents=True, exist_ok=True)
    if destination.parent.is_symlink():
        raise ValueError('El padre del destino no puede ser un enlace.')
    with zipfile.ZipFile(path) as z:
        m = archive_manifest(z)
        if shutil.disk_usage(destination.parent).free < sum(f['bytes'] for f in m['files']) + 32 * CHUNK:
            raise ValueError('Espacio insuficiente para restaurar.')
        stage = Path(tempfile.mkdtemp(prefix='.restore-', dir=destination.parent))
        try:
            for f in m['files']:
                target = stage / f['path']
                target.parent.mkdir(parents=True, exist_ok=True)
                h = hashlib.sha256(); count = 0
                with z.open('data/' + f['path']) as src, target.open('xb') as dst:
                    while chunk := src.read(CHUNK):
                        count += len(chunk)
                        if count > f['bytes']: raise ValueError('Tamaño inesperado.')
                        dst.write(chunk); h.update(chunk)
                    dst.flush(); os.fsync(dst.fileno())
                if count != f['bytes'] or h.hexdigest() != f['sha256']:
                    raise ValueError('Los bytes restaurados no coinciden.')
                os.utime(target, ns=(f['mtime_ns'], f['mtime_ns']))
                if target.stat().st_mtime_ns != f['mtime_ns']:
                    raise ValueError('El destino no conserva la precisión temporal; no se publica una restauración incompatible con las propuestas IA.')
            # Reserve destination exclusively. It did not exist when invoked.
            destination.mkdir()
            try:
                # Move only after all hashes passed. Rename a reserved empty directory on POSIX;
                # on Windows remove our own empty reservation immediately before rename.
                if os.name == 'nt': destination.rmdir()
                os.replace(stage, destination)
            except Exception:
                if destination.is_dir() and not any(destination.iterdir()): destination.rmdir()
                raise
            return {'status':'ok', 'files':len(m['files']), 'restored_to':str(destination),
                    'originals_overwritten':False, 'content_reviewed':False}
        finally:
            if stage.exists(): shutil.rmtree(stage)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    subs = parser.add_subparsers(dest='command',required=True)
    p = subs.add_parser('create'); p.add_argument('--data',type=Path,required=True); p.add_argument('--output',type=Path,required=True)
    p = subs.add_parser('verify'); p.add_argument('archive',type=Path); p.add_argument('--sha256')
    p = subs.add_parser('restore'); p.add_argument('archive',type=Path); p.add_argument('--destination',type=Path,required=True); p.add_argument('--sha256')
    args = parser.parse_args(argv)
    try:
        if args.command == 'create': result = create_backup(args.data,args.output)
        elif args.command == 'verify': result = verify_backup(args.archive,args.sha256)
        else: result = restore_backup(args.archive,args.destination,args.sha256)
        print(json.dumps(result,ensure_ascii=False,indent=2)); return 0
    except Exception as exc:
        # No absolute paths or archive contents in diagnostics.
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,
                          'message':str(exc) if isinstance(exc,(ValueError,FileExistsError,RuntimeError)) else 'Operación fallida: revisa permisos, espacio y formato.'},ensure_ascii=False),file=sys.stderr)
        return 1

if __name__ == '__main__':
    raise SystemExit(main())
