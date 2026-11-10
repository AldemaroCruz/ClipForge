"""Allowlisted configuration only. Safe to run in the existing container."""
import json
import os
print(json.dumps({k:os.getenv(k) for k in ('WHISPER_MODEL','HF_HOME','CLIPFORGE_DATA_DIR')}))
