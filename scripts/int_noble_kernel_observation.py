"""Read only kernel exposure metadata of the already observed Noble boot."""
import argparse
import base64
import json
import os
from pathlib import Path
import re

from scripts import int_guest_inventory as transport
from scripts import int_noble_first_observation as first
from scripts import int_noble_hostkey as host
from scripts import int_noble_demo_preflight_guest as demo
from scripts import int_noble_kernel_consumers_guest as consumers
from scripts import int_noble_kernel_guest as probe
from scripts import int_noble_postverify as postverify


WORKFLOW = ".github/workflows/int-db01-noble-kernel-observe.yml"
CONTROLS = "d6915938ea056d6df6e15d29457c0f0c1f46a69e"
ORIGINAL_APPLY = "44761685941"
POSTVERIFY_RUN = "44772432816"
INITIAL_RUN = "44772950030"
SUMMARY_SHA = "6a719afddfbc6fddab75d503bf5b0ff43519d23dbfe7bc8bd0fdcb37b412d0b8"
PIN_SHA = "eace51fdd5447ed1d10b02d498c4d48caf9ac33e42bd58596e10282028ebb414"
SUMMARY_SCHEMA = "clipforge-int-noble-kernel-observation-summary-1"
RECEIPT_SCHEMA = "clipforge-int-noble-kernel-observation-receipt-1"
INVENTORY_NAME = "inventory.json"
DEMO_SCOPE = "demo-readiness"
CONSUMERS_SCOPE = "demo-kernel-consumers"
SCOPES = {"kernel": probe, DEMO_SCOPE: demo, CONSUMERS_SCOPE: consumers}
KERNEL_RUN = "44789936845"
KERNEL_CONTROLS = "e825a049eee977468bf029cfc71395fa86ffe6bf"
PINNED_IDS = {"instance_id": "7365414160255801909", "data_disk_id": "7382984635240536620"}
require = first.require


def check_hosted(env):
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_REPOSITORY") == "AldemaroCruz/ClipForge"
            and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_WORKFLOW_REF") == f"AldemaroCruz/ClipForge/{WORKFLOW}@refs/heads/ci/bootstrap-sec03"
            and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))
            and env["GITHUB_SHA"] == env.get("GUEST_APPROVED_COMMIT"), "NOBLE_KERNEL_HOSTED_BOUNDARY")


def verify_handoff(github_token, scope="kernel"):
    first.checked_creation_runs(ORIGINAL_APPLY, CONTROLS, github_token, POSTVERIFY_RUN)
    postverify.verify_github_run(INITIAL_RUN, CONTROLS, github_token, first.OBSERVE_PATH, "success")
    if scope in {DEMO_SCOPE, CONSUMERS_SCOPE}:
        postverify.verify_github_run(KERNEL_RUN, KERNEL_CONTROLS, github_token, WORKFLOW, "success")


def checked_inputs(raw, pin_raw):
    _, summary = first.creation_handoff(raw, SUMMARY_SHA, CONTROLS, ORIGINAL_APPLY, POSTVERIFY_RUN)
    require(all(summary["candidate"][key] == value for key, value in PINNED_IDS.items()), "NOBLE_KERNEL_SCOPE")
    return summary, first.check_pin(pin_raw, PIN_SHA, summary, SUMMARY_SHA)


def payload_bytes(scope="kernel"):
    require(scope in SCOPES, "NOBLE_READ_SCOPE")
    raw = Path(probe.__file__).read_bytes()
    if scope != "kernel":
        extension = Path(SCOPES[scope].__file__).read_bytes()
        raw = ("import base64, sys, types\n"
               "_noble_kernel_reads = types.ModuleType('_clipforge_noble_kernel_reads')\n"
               "sys.modules[_noble_kernel_reads.__name__] = _noble_kernel_reads\n"
               f"exec(compile(base64.b64decode({base64.b64encode(raw)!r}), '<reviewed-kernel>', 'exec'), _noble_kernel_reads.__dict__)\n"
               f"exec(compile(base64.b64decode({base64.b64encode(extension)!r}), '<reviewed-demo>', 'exec'), globals())\n").encode("ascii")
    require(0 < len(raw) <= 65536, "NOBLE_KERNEL_PAYLOAD_SIZE")
    return raw


def check_guest(raw, code, expected_boot_id, scope="kernel"):
    tool = SCOPES[scope]
    if code != 0:
        diagnostic = host.closed_json(raw)
        require(set(diagnostic) == {"schema", "error"} and diagnostic["schema"] == tool.SCHEMA
                and re.fullmatch(r"[A-Z_]{3,100}", diagnostic["error"]), "NOBLE_KERNEL_GUEST_RESULT")
        raise transport.Blocked(diagnostic["error"])
    return tool.validate(raw, expected_boot_id)


def link(guest, before, after, payload, controls):
    require(before == after and all(after[key] == value for key, value in PINNED_IDS.items()), "NOBLE_KERNEL_CONTROL_PLANE_CHANGED")
    return {"schema": RECEIPT_SCHEMA, "initial_observation_run_id": INITIAL_RUN, "controls_commit": controls,
            "payload_sha256": host.sha(payload), "control_plane": after, "guest": guest,
            "risk_accepted": False, "runtime_authorized": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify-handoff", "check", "run", "cleanup"))
    operation = parser.parse_args(argv).operation
    env = os.environ
    try:
        check_hosted(env)
        scope = env.get("NOBLE_READ_SCOPE", "kernel")
        require(scope in SCOPES, "NOBLE_READ_SCOPE")
        if operation == "verify-handoff":
            verify_handoff(env["GH_TOKEN"], scope)
            return 0
        work, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
        if operation == "cleanup":
            result = transport.cleanup(environ=env, workdir=work, reports=reports)
            return int(result["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"})
        raw = transport._local_bytes(Path(env["NOBLE_HANDOFF"]) / "summary.json", 262144)
        summary, pin = checked_inputs(raw, env["NOBLE_HOST_PIN_JSON"].encode("ascii"))
        if operation == "check":
            return 0
        transport.validate_deploy_credentials(env, transport._credential_document(env))
        token = env["GCP_ACCESS_TOKEN"]
        result = first.collect(env, work, reports, summary, pin, reader=lambda route: first.read_compute(route, token),
                               client=transport.Client(lambda: token), kernel=True, kernel_scope=scope)
        return int(result["status"] != "observation_complete")
    except (OSError, KeyError, ValueError, transport.Failure) as error:
        code = str(error)
        diagnostic = {"status": "blocked", "operation": operation,
                      "error_code": code if re.fullmatch(r"[A-Z_]{3,100}", code) else type(error).__name__}
        if isinstance(error, transport.Failure):
            diagnostic["failure"] = error.receipt
        print(json.dumps(diagnostic))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
