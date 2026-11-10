"""Best-effort operational timings; never store transcript, prompt, error body or keys."""
from __future__ import annotations
import logging
import re
import time
from pathlib import Path
from .state import write_json_atomic


class Recorder:
    def __init__(self, root: Path, job_id: str, kind: str, run_id: str):
        if kind not in {'process','export'} or any(not re.fullmatch('[a-f0-9]{32}', x) for x in (job_id,run_id)):
            raise ValueError('Invalid metric identity')
        self.path = root / job_id / 'metrics' / f'{kind}-{run_id}.json'
        self.started = self.last = time.monotonic()
        self.current: str | None = None
        self.record = {'schema':1,'version':'0.4.2','job_id':job_id,'kind':kind,'id':run_id,
                       'started_at':time.time(),'status':'running','stage_seconds':{}}

    def _flush(self) -> None:
        try:
            write_json_atomic(self.path, self.record)
        except OSError:
            # Telemetry must never turn a successful render into a failed job.
            logging.getLogger('uvicorn.error').warning('No se pudieron persistir métricas; contenido omitido.')

    def phase(self, name: str) -> None:
        if name not in {'validation','model_load','transcription','selection','render','queue'}:
            raise ValueError('Invalid metric phase')
        now = time.monotonic()
        if self.current:
            self.record['stage_seconds'][self.current] = round(
                self.record['stage_seconds'].get(self.current,0) + now-self.last,6)
        self.last = now; self.current = name
        self.record['active_stage'] = name
        self._flush()

    def finish(self, status: str, error_code: str | None = None) -> None:
        now = time.monotonic()
        if self.current:
            self.record['stage_seconds'][self.current] = round(
                self.record['stage_seconds'].get(self.current,0) + now-self.last,6)
        self.current = None
        self.record.update(status=status if status in {'completed','failed'} else 'failed',
                           elapsed_seconds=round(now-self.started,6),completed_at=time.time(),active_stage=None)
        if error_code:
            self.record['error_code'] = error_code if re.fullmatch('[A-Z][A-Z0-9_]{0,79}', error_code) else 'PROCESSING_FAILED'
        self._flush()
