"""Resolve an optional, pre-captured local Whisper snapshot without network."""
from __future__ import annotations
import hashlib
import json
import os
from pathlib import Path
import re
import threading

_LOCK = threading.Lock()
_VERIFIED: dict[tuple, str] = {}


def resolve_model() -> str:
    lock_path = os.getenv('CLIPFORGE_MODEL_LOCK')
    name = os.getenv('WHISPER_MODEL','tiny')
    if not lock_path:
        return name  # Legacy development behavior, clearly labeled unpinned.
    lock = json.loads(Path(lock_path).read_text(encoding='utf-8'))
    repo, revision = lock.get('repo_id',''), lock.get('revision','')
    if (lock.get('schema') != 1 or lock.get('model') != name
            or not re.fullmatch(r'Systran/faster-whisper-[A-Za-z0-9._-]+',repo)
            or not re.fullmatch('[a-f0-9]{40}',revision)):
        raise ValueError('El lock del modelo no corresponde a WHISPER_MODEL.')
    home = Path(os.getenv('HF_HOME','/models/huggingface'))
    snapshot = home / 'hub' / ('models--' + repo.replace('/','--')) / 'snapshots' / revision
    files = lock.get('files')
    if not isinstance(files,list) or not files or not {'model.bin','config.json','tokenizer.json'} <= {f.get('name') for f in files}:
        raise ValueError('Lock de modelo incompleto.')
    key_parts = [str(snapshot)]
    for f in files:
        if (not isinstance(f,dict) or not re.fullmatch(r'[A-Za-z0-9_.-]+',f.get('name',''))
                or not re.fullmatch('[0-9a-f]{64}', f.get('sha256','')) or type(f.get('bytes')) is not int):
            raise ValueError('Lock de modelo inválido.')
        path = snapshot / f['name']
        # HuggingFace snapshots legitimately link to blob files inside this cache.
        if not path.resolve().is_relative_to(home.resolve()) or not path.is_file():
            raise ValueError('Falta el modelo fijado en caché. No se descargó ni cambió de revisión automáticamente.')
        s = path.stat()
        key_parts.append((f['name'],s.st_size,s.st_mtime_ns,f['sha256']))
    key = tuple(key_parts)
    with _LOCK:
        if key not in _VERIFIED:
            for f in files:
                path = snapshot / f['name']; h = hashlib.sha256()
                with path.open('rb') as source:
                    for chunk in iter(lambda: source.read(1024**2), b''): h.update(chunk)
                if path.stat().st_size != f['bytes'] or h.hexdigest() != f['sha256']:
                    raise ValueError('Hash del modelo incorrecto; no se carga un peso distinto al fijado.')
            _VERIFIED.clear(); _VERIFIED[key] = str(snapshot)
    return _VERIFIED[key]


def main(argv=None) -> int:
    import argparse
    import sys
    p=argparse.ArgumentParser(description='Verify or explicitly fetch the pinned model; never sends user data.')
    p.add_argument('action',choices=['verify','fetch']);p.add_argument('--allow-network',action='store_true')
    args=p.parse_args(argv)
    try:
        if not os.getenv('CLIPFORGE_MODEL_LOCK'):
            raise ValueError('No model lock is configured.')
        if args.action=='fetch':
            if not args.allow_network:raise ValueError('Fetching requires explicit --allow-network.')
            m=json.loads(Path(os.environ['CLIPFORGE_MODEL_LOCK']).read_text(encoding='utf-8'))
            if (not re.fullmatch(r'Systran/faster-whisper-[A-Za-z0-9._-]+',m.get('repo_id',''))
                    or not re.fullmatch('[a-f0-9]{40}',m.get('revision',''))
                    or m.get('model')!=os.getenv('WHISPER_MODEL','tiny')
                    or not isinstance(m.get('files'),list)
                    or any(not isinstance(f,dict) or not re.fullmatch('[A-Za-z0-9_.-]+',f.get('name','')) for f in m['files'])):
                raise ValueError('Invalid lock.')
            from huggingface_hub import snapshot_download
            snapshot_download(m['repo_id'],revision=m['revision'],
                              cache_dir=str(Path(os.getenv('HF_HOME','/models/huggingface'))/'hub'),
                              allow_patterns=[f['name'] for f in m['files']],token=False)
        resolve_model()
        print(json.dumps({'status':'ok','model_hashes_verified':True,'inference_tested':False,
                          'download_requested':args.action=='fetch'}));return 0
    except Exception as exc:
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,
                          'message':'Pinned model verification/fetch failed. No user media or credentials were sent.'}),file=sys.stderr)
        return 1

if __name__=='__main__':raise SystemExit(main())
