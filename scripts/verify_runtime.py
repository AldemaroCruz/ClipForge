"""Exact package/Python check for the inherited image; no install, no network."""
import argparse
import json
import platform
from pathlib import Path
from capture_runtime import packages

p=argparse.ArgumentParser();p.add_argument('lock',type=Path);args=p.parse_args()
expected=json.loads(args.lock.read_text(encoding='utf-8'))
actual=packages()
if (actual!=expected['packages'] or platform.python_version()!=expected['python']
        or platform.machine()!=expected['machine']):
    raise SystemExit('Runtime mismatch. No dependencies were installed or silently changed.')
print('Runtime matches captured package versions, Python and architecture.')
