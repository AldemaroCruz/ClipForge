"""Run inside the EXISTING trusted image. Stdlib only, no network/importing ASR.
Only allowlisted runtime metadata is emitted, never environment dumps or tokens.
"""
import argparse
import hashlib
import importlib.metadata as md
import json
import os
from pathlib import Path
import platform
import re
import subprocess
import sys
import time



def sha(path):
    h=hashlib.sha256()
    with path.open('rb') as f:
        for c in iter(lambda:f.read(1024**2),b''):h.update(c)
    return h.hexdigest()


def packages():
    found={}
    for d in md.distributions():
        name=re.sub('[-_.]+','-',d.metadata['Name']).lower();version=d.version
        if not re.fullmatch('[a-z0-9][a-z0-9-]*',name) or not re.fullmatch('[A-Za-z0-9.!+_-]+',version):
            raise ValueError('Invalid package metadata; not exporting unsafe requirement')
        if d.read_text('direct_url.json'):
            raise ValueError('Direct URL installation found. Review it manually; no credentials are written.')
        if name in found and found[name]!=version:raise ValueError('Duplicate package versions')
        found[name]=version
    return dict(sorted(found.items()))


def model_snapshot(home,model):
    if not re.fullmatch('[A-Za-z0-9._-]+',model):raise ValueError('Only standard cached Whisper names are supported')
    repo='Systran/faster-whisper-'+model
    path=home/'hub'/('models--'+repo.replace('/','--'))
    revision=(path/'refs'/'main').read_text().strip()
    if not re.fullmatch('[a-f0-9]{40}',revision):raise ValueError('No exact cached revision')
    snapshot=path/'snapshots'/revision
    required=['config.json','model.bin','tokenizer.json','vocabulary.txt','vocabulary.json','preprocessor_config.json']
    files=[]
    for name in required:
        p=snapshot/name
        if not p.exists():continue
        if not p.resolve().is_relative_to(home.resolve()):raise ValueError('Cache points outside HF_HOME')
        files.append({'name':name,'bytes':p.stat().st_size,'sha256':sha(p)})
    if not {'config.json','model.bin','tokenizer.json'} <= {f['name'] for f in files}:
        raise ValueError('Snapshot incomplete: use one real transcription before capturing release')
    return {'schema':1,'model':model,'repo_id':repo,'revision':revision,'files':files,'network_used':False}


def ffmpeg_version():
    # Metadata-only consumers import packages() without an app import root.
    # Media capture uses the existing scoped PYTHONPATH of Prepare-Upgrade.
    from app.media_binaries import resolve_media_binary
    lines=subprocess.check_output([resolve_media_binary('ffmpeg'),'-version'],text=True,timeout=10).splitlines()
    if not lines or not lines[0].strip():
        raise ValueError('FFmpeg version output is empty; capture stopped')
    return lines[0]


def capture(output,home,model):
    pkgs=packages()
    for name in ['fastapi','uvicorn','python-multipart','faster-whisper','requests','av']:
        if name not in pkgs:raise ValueError('Production dependency missing: '+name)
    check=subprocess.run([sys.executable,'-m','pip','check'],capture_output=True,text=True,timeout=60)
    if check.returncode: raise ValueError('pip check failed in existing runtime; capture stopped')
    pinned_model=model_snapshot(home,model)
    report={'schema':1,'captured_at':time.time(),'python':platform.python_version(),'machine':platform.machine(),
            'system':platform.system(),'packages':pkgs,'network_used':False,'inference_tested':False,
            'ffmpeg':ffmpeg_version()}
    output.mkdir(parents=True,exist_ok=True)
    for name in ['runtime-lock.json','runtime-requirements.txt','model-lock.json']:
        if (output/name).exists():raise FileExistsError('Capture already exists')
    (output/'runtime-lock.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    (output/'runtime-requirements.txt').write_text('# Captured from existing image; exact installed versions, NOT distribution hashes.\n'+''.join(f'{k}=={v}\n' for k,v in pkgs.items()),encoding='utf-8')
    (output/'model-lock.json').write_text(json.dumps(pinned_model,indent=2)+'\n',encoding='utf-8')
    print(json.dumps({'status':'ok','packages':len(pkgs),'python':report['python'],
                      'model_revision':pinned_model['revision'],'network_used':False},indent=2))

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True)
    p.add_argument('--cache',type=Path,default=Path('/models/huggingface'));p.add_argument('--model',default='tiny')
    a=p.parse_args()
    try: capture(a.output,a.cache,a.model)
    except Exception as e:
        print(json.dumps({'status':'failed','error_type':type(e).__name__,
                          'message':str(e) if isinstance(e,ValueError) else 'Cannot capture runtime/model; original data unchanged.'}),file=sys.stderr)
        raise SystemExit(1)
