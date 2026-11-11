"""Local operational dashboard. Read-only inventory, explicit review-time entries.

No provider calls. Missing historical metrics are null, not invented zero timings.
All errors are counted without exposing transcription, filenames or secrets.
"""
from __future__ import annotations
import json
import math
import os
from pathlib import Path
import re
import shutil
import time
from fastapi import APIRouter, HTTPException, Request, Response
from pydantic import BaseModel, ConfigDict, Field
from .state import write_json_atomic
from .auth import visible_project_ids

router = APIRouter()
ID = re.compile('[0-9a-f]{32}')
MAX_FILES = 100_000


def backend():
    from . import main
    return main


def read_object(path: Path, warnings: list[str]) -> dict | None:
    try:
        if path.is_symlink() or path.stat().st_size > 8*1024**2: raise ValueError()
        obj = json.loads(path.read_text(encoding='utf-8'))
        if not isinstance(obj,dict): raise ValueError()
        return obj
    except (OSError, ValueError, TypeError):
        warnings.append('Registro ilegible o no compatible; totales parciales.')
        return None


def number(value) -> float | None:
    return float(value) if type(value) in (int,float) and math.isfinite(value) and value >= 0 else None


def project_stats(root: Path, job_id: str) -> dict:
    if not ID.fullmatch(job_id): raise ValueError('Invalid project')
    folder = root / job_id; warnings: list[str] = []
    job = read_object(folder/'job.json',warnings) or {}
    stages: dict[str,float] = {}; measured = 0; interrupted = 0
    for p in sorted((folder/'metrics').glob('*.json')):
        m = read_object(p,warnings)
        if not m: continue
        if m.get('status') not in {'completed','failed'}:
            interrupted += 1; continue
        measured += 1
        values=m.get('stage_seconds',{})
        if not isinstance(values,dict): warnings.append('Métricas no compatibles.'); continue
        for key in ('validation','model_load','transcription','selection','render','queue'):
            n=number(values.get(key))
            if n is not None: stages[key] = round(stages.get(key,0)+n,6)
    tokens={'input_tokens':0,'output_tokens':0}; reported=0; missing=0; calls=0; ai_elapsed=0.0; active_ai=0
    for p in sorted((folder/'selections').glob('*/selection.json')):
        m=read_object(p,warnings)
        if not m: continue
        if m.get('status') == 'running': active_ai += 1
        if m.get('mode') != 'llm': continue
        if m.get('request_started_at'): calls += 1
        usage=m.get('usage')
        if isinstance(usage,dict) and any(type(usage.get(k)) is int for k in tokens):
            reported += 1
            for k in tokens:
                v=usage.get(k)
                if type(v) is int and v >= 0: tokens[k] += v
        elif m.get('request_started_at'): missing += 1
        n=number(m.get('elapsed_seconds'))
        if n is not None: ai_elapsed += n
    approved=0; exports=0; failed=0; active=0
    for p in sorted((folder/'exports').glob('*/export.json')):
        e=read_object(p,warnings)
        if not e: continue
        if e.get('status') == 'completed':
            exports += 1
            review=p.parent/'review.json'
            if review.is_file():
                r=read_object(review,warnings)
                if r and r.get('status') == 'approved': approved += 1
        elif e.get('status') == 'failed': failed += 1
        else: active += 1
    minutes=0.0; sessions=0
    for p in sorted((folder/'review-time').glob('*.json')):
        r=read_object(p,warnings)
        if r and number(r.get('minutes')) is not None:
            minutes += r['minutes']; sessions += 1
    total=0; count=0; truncated=False
    for parent,dirs,files in os.walk(folder, followlinks=False):
        dirs[:] = [d for d in dirs if not (Path(parent)/d).is_symlink()]
        for name in files:
            p=Path(parent)/name; count += 1
            if count > MAX_FILES: truncated=True; break
            if p.is_symlink(): warnings.append('Enlace omitido en uso de disco.'); continue
            try: total += p.stat().st_size
            except OSError: warnings.append('Archivo no accesible al medir espacio.')
        if truncated: break
    if truncated: warnings.append('Inventario de espacio limitado; resultado parcial.')
    active_job = job.get('status') in {'queued','validating','transcribing','rendering'}
    media=job.get('media') if isinstance(job.get('media'),dict) else {}
    return {'job_id':job_id,'status':job.get('status','unreadable'),
            'source_seconds':number(media.get('duration_seconds')),
            'initial_clips':len(job.get('clips',[])) if isinstance(job.get('clips'),list) else 0,
            'completed_exports':exports,'approved_exports':approved,'failed_exports':failed,
            'active_work':active + int(active_job) + active_ai, 'data_bytes':total,
            'timed_runs':measured,'unfinished_metric_records':interrupted,
            'stage_seconds':stages if measured else None,
            'ai_requests_attempted':calls, 'ai_usage_records':reported,'ai_usage_missing':missing,
            'tokens_reported':tokens if reported else None,'ai_elapsed_seconds':round(ai_elapsed,3),
            'review_minutes':round(minutes,3),'review_sessions':sessions,
            'review_minutes_per_approved':round(minutes/approved,3) if approved and sessions else None,
            'cost_usd':None,'warnings_count':len(warnings),'warnings':sorted(set(warnings)),
            'scope':'current saved artifacts; elapsed times available only from v0.4.2'}


@router.get('/ops/summary')
def summary(request: Request, response: Response):
    service=backend(); response.headers['Cache-Control']='no-store'
    folders=sorted(service.ROOT / job_id for job_id in visible_project_ids(request.state.principal)
                   if (service.ROOT / job_id).is_dir() and not (service.ROOT / job_id).is_symlink())
    rows=[project_stats(service.ROOT,p.name) for p in folders[:500]]
    disk=shutil.disk_usage(service.ROOT)
    rss=None
    try:
        for line in Path('/proc/self/status').read_text().splitlines():
            if line.startswith('VmRSS:'): rss=int(line.split()[1])*1024
    except (OSError,ValueError): pass
    return {'version':service.VERSION, 'generated_at':time.time(), 'projects':rows,
            'partial':len(folders)>500,'disk_free_bytes':disk.free,'disk_total_bytes':disk.total,
            'api_rss_bytes':rss,'memory_scope':'API process only, not children/whole container',
            'model_pinned':bool(os.getenv('CLIPFORGE_MODEL_LOCK')),
            'credentials_included':False,'cost_usd':None}


@router.get('/jobs/{job_id}/operations')
def operations(job_id: str, response: Response):
    service=backend(); service.load_job(job_id); response.headers['Cache-Control']='no-store'
    return project_stats(service.ROOT,job_id)


class ReviewTime(BaseModel):
    model_config=ConfigDict(extra='forbid')
    id: str=Field(pattern='^[0-9a-f]{32}$',min_length=32,max_length=32)
    minutes: float=Field(gt=0,le=1440,allow_inf_nan=False,strict=True)


@router.post('/jobs/{job_id}/review-time',status_code=201)
def review_time(job_id: str, request: ReviewTime):
    service=backend(); service.load_job(job_id)
    path=service.ROOT/job_id/'review-time'/f'{request.id}.json'
    with service.LOCK:
        if path.exists():
            warnings=[]; item=read_object(path,warnings)
            if not item: raise HTTPException(503,'Registro de tiempo ilegible; se conserva.')
            if item.get('minutes') != request.minutes: raise HTTPException(409,'Ese registro ya tiene otra duración; no se sobrescribe.')
            return item
        if len(list(path.parent.glob('*.json'))) >= 1000: raise HTTPException(409,'Límite de registros de revisión alcanzado.')
        item={'id':request.id,'job_id':job_id,'minutes':request.minutes,'created_at':time.time(),
              'source':'operator_entered','version':service.VERSION}
        try: write_json_atomic(path,item)
        except OSError as exc: raise HTTPException(503,'No se pudo guardar el tiempo.') from exc
    return item
