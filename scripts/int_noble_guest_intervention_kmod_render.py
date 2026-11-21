"""Render the exact review payload. This command never opens a transport."""

import argparse
import base64
import bz2
from hashlib import sha256
from pathlib import Path


DEPENDENCIES = (
    ("int_noble_kernel_guest.py", "_clipforge_noble_kernel_reads",
     "8563467b6bd43dcf74820b98a937e936892bcd61e64a53018fa06eedce3e33d6", ""),
    ("int_noble_demo_preflight_guest.py", "checks",
     "75524167066245c1957d85dce98390a149de3c1c2add98b52209e148402ef618", "_noble_kernel_reads = _clipforge_noble_kernel_reads"),
    ("int_noble_guest_apt.py", "guest",
     "0e9de319484b8f5cbde311d1500bd9c4f23d676ac06ac7507b50c3e9c8328c13", "apt_checks = checks"),
    ("int_noble_kernel_consumers_guest.py", "probe",
     "ee677d92cfa91013645be9cf41aca7bd201042006cf1fd3e16b04b35c2125f19", ""),
)


def compressed(raw):
    return repr(base64.b64encode(bz2.compress(raw, compresslevel=9)))


def payload_bytes(scripts):
    rows = ["import base64, bz2, sys, types", ""]
    for name, alias, expected, init in DEPENDENCIES:
        raw = (scripts / name).read_bytes()
        if sha256(raw).hexdigest() != expected:
            raise ValueError("Changed payload dependency " + name)
        rows += [f"{alias} = types.ModuleType({alias!r})", f"sys.modules[{alias!r}] = {alias}"]
        if init:
            rows.append(f"{alias}.{init}")
        rows.append(f"exec(compile(bz2.decompress(base64.b64decode({compressed(raw)})), {name!r}, 'exec'), {alias}.__dict__)")
    source = Path(__file__).with_name("int_noble_guest_intervention_kmod.py").read_bytes()
    rows.append(f"exec(compile(bz2.decompress(base64.b64decode({compressed(source)})), '<kmod-only>', 'exec'), globals())")
    payload = ("\n".join(rows) + "\n").encode("ascii")
    if not 0 < len(payload) <= 65536:
        raise ValueError("Reviewed payload exceeds existing transport argument bound")
    return payload


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scripts", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    payload = payload_bytes(args.scripts)
    with args.output.open("xb") as output:
        output.write(payload)
    print(sha256(payload).hexdigest())
