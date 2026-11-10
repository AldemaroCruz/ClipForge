"""Regression suite over unchanged production packages; test-only imports appended."""
import json
from pathlib import Path
import platform
import sys
import unittest
from capture_runtime import packages

expected=json.loads(Path('/app/release-tools/runtime-lock.json').read_text())
if packages()!=expected['packages'] or platform.python_version()!=expected['python']:
    raise SystemExit('Production runtime differs from captured lock before test imports.')
sys.path.insert(0,'/app')
# End, not front: an installed production package always takes precedence.
sys.path.append('/opt/test-deps')
suite=unittest.defaultTestLoader.discover('/app/tests')
result=unittest.TextTestRunner(verbosity=2).run(suite)
raise SystemExit(0 if result.wasSuccessful() else 1)
