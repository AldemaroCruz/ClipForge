
# Rendered by Terraform and appended to the Noble startup.
if [[ "$${NOBLE_FIRST_INSTALL:-0}" == 1 ]]; then
  /usr/bin/timeout 70 /usr/bin/python3 -I -B - '${nonce}' '${legacy}' '${publisher}' <<'CLIPFORGE_NOBLE_PUBLISHER'
import base64
import hashlib
import sys

try:
    nonce, encoded_legacy, encoded_publisher = sys.argv[1:]
    original = base64.b64decode(encoded_legacy, validate=True)
    source = base64.b64decode(encoded_publisher, validate=True)
    if hashlib.sha256(original).hexdigest() != 'a8211bbfbe29f0694f633b403fbe41e08ef6dfbc8abb9705f56e1f8e13ea10ad' or not 0 < len(source) <= 65536:
        raise ValueError('publisher bytes')
    legacy = {'__name__': 'noble_hostkey_dependency'}
    publisher = {'__name__': 'noble_hostkey_publisher'}
    exec(compile(original, '<hostkey-dependency>', 'exec'), legacy)
    exec(compile(source, '<noble-hostkey-publisher>', 'exec'), publisher)
    publisher['publish'](nonce, source, legacy)
except Exception:
    print('CLIPFORGE_NOBLE_HOSTKEY_BLOCKED', file=sys.stderr)
    raise SystemExit(1)
CLIPFORGE_NOBLE_PUBLISHER
fi
