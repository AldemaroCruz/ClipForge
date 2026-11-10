"""Read-only acceptance evidence from existing jobs; never calls ASR or a provider.

This verifies saved artifacts and full MP4 decoding. It cannot certify the truth
of titles, audio quality, speech recognition accuracy or that a model was real.
Editorial review and authorization remain explicit operator attestations.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import time
import zipfile
from .backup import digest_file
from .state import write_json_atomic
from .media_binaries import resolve_media_binary


def read_json(path: Path) -> dict:
    if path.is_symlink(): raise ValueError('Symlink not accepted')
    value=json.loads(path.read_text(encoding='utf-8'))
    if not isinstance(value,dict): raise ValueError('Expected object')
    return value


def inspect_project(root: Path, job_id: str, *, decode: bool = False, require_ai: bool = True,
                    reviewed_content: bool = False) -> dict:
    if not re.fullmatch('[0-9a-f]{32}',job_id): raise ValueError('ID de proyecto inválido.')
    folder=root/job_id
    if folder.is_symlink(): raise ValueError('No se admiten enlaces.')
    job=read_json(folder/'job.json')
    source=folder/'input.mp4'
    checks={'source_present':source.is_file() and not source.is_symlink(),
            'job_completed':job.get('status') == 'completed',
            'transcript_present':False,'ai_proposal_to_approved_export':False,
            'delivery_hashes_verified':False,'delivered_video_decoded':False}
    transcript=folder/'transcript.json'
    if transcript.is_file() and not transcript.is_symlink():
        t=json.loads(transcript.read_text(encoding='utf-8'))
        checks['transcript_present']=isinstance(t,list) and bool(t) and all(isinstance(s,dict) for s in t)
    qualifying: set[str] = set()
    for p in sorted((folder/'exports').glob('*/export.json')):
        if not re.fullmatch('[0-9a-f]{32}',p.parent.name): continue
        e=read_json(p); review_path=p.parent/'review.json'
        if e.get('status') != 'completed' or not review_path.is_file(): continue
        r=read_json(review_path)
        if r.get('status') != 'approved': continue
        if not require_ai:
            qualifying.add(p.parent.name); continue
        origin=e.get('selection_origin',{})
        analysis_id=origin.get('analysis_id','')
        draft_id=e.get('draft_id','')
        if not all(re.fullmatch('[0-9a-f]{32}',v) for v in (analysis_id,draft_id)): continue
        a=read_json(folder/'selections'/analysis_id/'selection.json')
        d=read_json(folder/'drafts'/f'{draft_id}.json')
        candidate=next((x for x in a.get('candidates',[]) if x.get('id') == origin.get('candidate_id')),None)
        if (a.get('status')=='completed' and a.get('mode')=='llm' and candidate
                and d.get('selection_origin')==origin
                and e.get('draft_revision',0)>0 and e.get('draft_revision',0)<=d.get('revision',0)):
            qualifying.add(p.parent.name)
    checks['ai_proposal_to_approved_export']=bool(qualifying) if require_ai else None
    checked_deliveries=0; checked_videos=0; warnings=[]
    for p in sorted((folder/'deliveries').glob('*/delivery.zip')):
        with zipfile.ZipFile(p) as z:
            if z.getinfo('manifest.json').file_size > 4*1024**2: raise ValueError('Manifiesto excesivo.')
            m=json.loads(z.read('manifest.json')); matching=[]
            for entry in m.get('clips',[]):
                eid=entry.get('export_id')
                if eid not in qualifying: continue
                has_video=False; has_srt=False
                for f in entry.get('files',[]):
                    name=f.get('path',''); q=PurePosixPath(name)
                    if q.is_absolute() or '..' in q.parts or '\\' in name:
                        raise ValueError('Ruta de entrega insegura.')
                    basename=q.name
                    if basename not in {'clip.mp4','clip.srt','clip.vtt'}: raise ValueError('Archivo de entrega desconocido.')
                    disk=folder/'exports'/eid/basename
                    if not disk.is_file() or disk.is_symlink(): raise ValueError('Falta un archivo de variante.')
                    if z.getinfo(name).file_size != f.get('bytes') or disk.stat().st_size != f.get('bytes'):
                        raise ValueError('Los tamaños de entrega no coinciden.')
                    h=hashlib.sha256()
                    with z.open(name) as member:
                        for chunk in iter(lambda:member.read(1024**2),b''): h.update(chunk)
                    if h.hexdigest()!=f.get('sha256') or digest_file(disk)!=f.get('sha256'):
                        raise ValueError('La entrega no coincide con su manifiesto y variante.')
                    if basename=='clip.srt': has_srt=True
                    if basename=='clip.mp4':
                        has_video=True
                        if decode:
                            result=subprocess.run([resolve_media_binary('ffmpeg'),'-nostdin','-v','error','-protocol_whitelist','file,pipe',
                                '-i',str(disk),'-map','0:v:0','-map','0:a:0','-f','null','-'],capture_output=True,timeout=1800)
                            if result.returncode: raise ValueError('El MP4 no se decodifica completo con audio y video.')
                            checked_videos+=1
                if has_video and has_srt: matching.append(eid)
            if matching: checked_deliveries+=1
    checks['delivery_hashes_verified']=checked_deliveries>0
    checks['delivered_video_decoded']=checked_videos>0 if decode else None
    required=['source_present','job_completed','delivery_hashes_verified']
    if require_ai: required+=['transcript_present','ai_proposal_to_approved_export']
    if decode: required+=['delivered_video_decoded']
    structural=all(checks[k] for k in required)
    return {'schema':1,'version':'0.4.2','generated_at':time.time(),'job_id':job_id,
            'scope':'saved_artifact_integrity_not_model_inference',
            'status':'passed' if structural else 'incomplete', 'checks':checks,
            'qualifying_exports':len(qualifying),'deliveries_verified':checked_deliveries,
            'videos_decoded':checked_videos,'source_sha256':digest_file(source) if checks['source_present'] else None,
            'transcript_sha256':digest_file(transcript) if checks['transcript_present'] else None,
            'operator_attests_content_reviewed':reviewed_content,
            'acceptance_ready':structural and decode and reviewed_content,
            'provider_contacted':False,'whisper_executed':False,
            'note':'Una marca del operador no es una evaluación automática. Tres videos reales siguen siendo requisito del hito.'}


def main(argv=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--data',type=Path,default=Path('/data'));p.add_argument('--project',required=True)
    p.add_argument('--output',type=Path,required=True);p.add_argument('--decode',action='store_true')
    p.add_argument('--manual',action='store_true',help='Validate a manual delivery, not full AI acceptance')
    p.add_argument('--reviewed-content',action='store_true',help='Operator personally listened and checked titles/subtitles')
    args=p.parse_args(argv)
    try:
        if args.output.absolute().is_relative_to(args.data.resolve()): raise ValueError('La evidencia se escribe fuera de data/.')
        if args.output.exists(): raise FileExistsError('Usa un nombre nuevo para la evidencia.')
        result=inspect_project(args.data,args.project,decode=args.decode,require_ai=not args.manual,reviewed_content=args.reviewed_content)
        write_json_atomic(args.output,result)
        print(json.dumps(result,ensure_ascii=False,indent=2));return 0 if result['acceptance_ready'] else 2
    except Exception as exc:
        print(json.dumps({'status':'failed','error_type':type(exc).__name__,
                          'message':'Verificación incompleta: revisa proyecto, entrega, permisos y evidencia local. No se llamó a IA.'}),file=sys.stderr)
        return 1

if __name__=='__main__': raise SystemExit(main())
