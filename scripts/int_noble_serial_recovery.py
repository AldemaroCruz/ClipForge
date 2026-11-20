"""Temporarily enable the exact Noble serial port and use its pinned regional gateway."""

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import time
import uuid

from scripts import int_noble_human_access as human


GATEWAY = "us-central1-ssh-serialport.googleapis.com"
PUBLIC_GATEWAY_SHA = "ef4bd67300567c65749fa2535d34dba854ace8e4cb3fa5862d90b01e5cf16b0b"
SERIAL_KEY = "serial-port-enable"
CONSTRAINT = "constraints/compute.disableSerialPortAccess"
SERIAL_INTENT = "clipforge-noble-serial-recovery-intent-1"
SHIELDED = {"enableSecureBoot": True, "enableVtpm": True, "enableIntegrityMonitoring": True}
PERMISSIONS = {"compute.instances.get", "compute.instances.setMetadata", "compute.instances.getSerialPortOutput",
               "compute.instances.reset"}


def approval(raw, digest, human_authority):
    human.require(human.HEX.fullmatch(digest) and human.sha(raw) == digest, "serial_review_decision_digest")
    result = json.loads(raw)
    exact = {"schema": "clipforge-noble-serial-recovery-authority-1", "temporary_serial_approved": True,
             "human_access_decision_sha256": human_authority, "actor": human.ACCOUNT, "project": human.PROJECT,
             "zone": human.ZONE, "instance_id": human.INSTANCE_ID, "boot_disk_id": human.BOOT_DISK,
             "data_disk_id": human.DATA_DISK, "gateway_key_sha256": PUBLIC_GATEWAY_SHA,
             "serial_port": 1, "original_serial_setting": "FALSE", "approved_serial_setting": "TRUE"}
    human.require(set(result) == set(exact) | {"authorization_reference", "approved_commit"}
                  and all(result[key] == value for key, value in exact.items())
                  and re.fullmatch(r"[A-Za-z0-9. /_-]{8,160}", result["authorization_reference"])
                  and re.fullmatch(r"[a-f0-9]{40}", result["approved_commit"]), "serial_review_decision_scope")
    return result


def metadata(vm):
    fingerprint = vm["metadata"]["fingerprint"]
    items = vm["metadata"]["items"]
    human.require(isinstance(items, list) and len(items) <= 64
                  and all(set(item) == {"key", "value"} for item in items)
                  and len({item["key"] for item in items}) == len(items)
                  and re.fullmatch(r"[A-Za-z0-9_+/=-]{8,256}", fingerprint), "serial_metadata_shape")
    current = [item["value"] for item in items if item["key"] == SERIAL_KEY]
    human.require(current in [["TRUE"], ["FALSE"]], "serial_current_setting_unknown")
    rest = sorted((item for item in items if item["key"] != SERIAL_KEY), key=lambda item: item["key"])
    return fingerprint, current[0], rest


def guard(client, *, need_policy=True):
    vm = human.checked_target(client)
    human.require(vm["shieldedInstanceConfig"] == SHIELDED, "serial_shielded_configuration_changed")
    permissions = client.request("POST", human.VM_ROUTE + "/testIamPermissions", {"permissions": sorted(PERMISSIONS)})
    human.require(set(permissions.get("permissions", [])) == PERMISSIONS, "serial_required_instance_permissions")
    sa = client.request("POST", human.SA_IAM, {"permissions": ["iam.serviceAccounts.actAs"]})
    human.require(sa.get("permissions") == ["iam.serviceAccounts.actAs"], "serial_required_sa_permission")
    if need_policy:
        policy = client.request("POST", human.POLICY_ROUTE, {"constraint": CONSTRAINT})
        boolean = policy.get("booleanPolicy")
        human.require(policy.get("constraint") == CONSTRAINT and isinstance(boolean, dict)
                      and boolean.get("enforced", False) is False, "serial_effective_org_policy_unconfirmed_or_denied")
    return vm


def wait_operation(client, initial):
    name = initial["name"]
    human.require(re.fullmatch(r"operation-[0-9A-Za-z-]{3,200}", name)
                  and str(initial.get("targetId")) == human.INSTANCE_ID and initial["operationType"] == "setMetadata",
                  "serial_metadata_operation_identity")
    expected = f"{human.COMPUTE}/zones/{human.ZONE}/operations/{name}"
    bound = time.monotonic() + 24
    operation = initial
    while time.monotonic() < bound:
        if operation["status"] == "DONE":
            human.require(not operation.get("error"), "serial_metadata_operation_failed")
            return name
        time.sleep(1)
        operation = client.request("GET", expected)
        human.require(operation["name"] == name and str(operation.get("targetId")) == human.INSTANCE_ID,
                      "serial_metadata_operation_changed")
    raise human.Blocked("serial_metadata_wait_timeout_reconcile")


def update(client, fingerprint, rest, next_value, request_id):
    body = {"fingerprint": fingerprint, "items": [*rest, {"key": SERIAL_KEY, "value": next_value}]}
    operation = client.request("POST", f"{human.VM_ROUTE}/setMetadata?requestId={request_id}", body)
    operation_id = wait_operation(client, operation)
    _, after, other = metadata(human.checked_target(client))
    human.require((after, other) == (next_value, rest), "serial_metadata_postcheck_mismatch")
    return operation_id


def enable(client, path, authorization, gateway):
    gateway_key(gateway)
    before = guard(client)
    fp, state, rest = metadata(before)
    human.require(state == "FALSE", "serial_not_at_reviewed_disabled_baseline")
    row = {"schema": SERIAL_INTENT, "authorization_sha256": authorization, "original_value": "FALSE",
           "enabled_value": "TRUE", "other_metadata_sha256": human.sha(human.canonical(rest)),
           "original_boot_timestamp": before["lastStartTimestamp"], "instance_id": human.INSTANCE_ID}
    request_id = uuid.uuid5(uuid.NAMESPACE_URL, human.VM_ROUTE + authorization + "enable")
    human.write_once(path, row)
    return {"status": "serial_temporarily_enabled", "cloud_operation": update(client, fp, rest, "TRUE", request_id)}


def owned_state(client, path, authorization, *, need_policy=False):
    record = json.loads(human.scoped_json(path, 8192))
    human.require(record.get("schema") == SERIAL_INTENT and record.get("authorization_sha256") == authorization
                  and record.get("instance_id") == human.INSTANCE_ID and record.get("original_value") == "FALSE"
                  and record.get("enabled_value") == "TRUE", "serial_intent_scope")
    vm = guard(client, need_policy=need_policy)
    fingerprint, state, rest = metadata(vm)
    human.require(human.sha(human.canonical(rest)) == record.get("other_metadata_sha256"), "serial_foreign_metadata_drift")
    return fingerprint, state, rest


def restore(client, path, authorization):
    fingerprint, state, rest = owned_state(client, path, authorization)
    if state == "FALSE":
        return {"status": "serial_disabled_verified"}
    request_id = uuid.uuid5(uuid.NAMESPACE_URL, human.VM_ROUTE + authorization + "restore")
    # No automatic repeat after an unknown DELETE-equivalent or a conflicting write.
    human.write_once(path.with_suffix(path.suffix + ".restore"), {"request_id": str(request_id), "original_value": "FALSE"})
    return {"status": "serial_disabled_verified", "cloud_operation": update(client, fingerprint, rest, "FALSE", request_id)}


def gateway_key(path):
    raw = human.scoped_json(path, 8192)
    human.require(human.sha(raw) == PUBLIC_GATEWAY_SHA, "serial_gateway_pubkey_digest")
    rows = raw.decode("ascii").splitlines()
    human.require(0 < len(rows) <= 32 and len(set(rows)) == len(rows)
                  and all(re.fullmatch(r"ecdsa-sha2-nistp256 [A-Za-z0-9+/=]{32,1200}", line) for line in rows),
                  "serial_gateway_key_format")
    return "".join(f"[{GATEWAY}]:9600 {line}\n" for line in rows)


def serial_argv(ssh, known, private):
    username = f"{human.PROJECT}.{human.ZONE}.{human.INSTANCE}.{human.POSIX}.port=1.replay-lines=40"
    return [ssh, "-F", "NUL", "-tt", "-p", "9600", "-i", str(private), "-l", username,
            "-o", f'UserKnownHostsFile="{known}"', "-o", "GlobalKnownHostsFile=NUL", "-o", "StrictHostKeyChecking=yes",
            "-o", "HostKeyAlgorithms=ecdsa-sha2-nistp256", "-o", "UpdateHostKeys=no", "-o", "IdentitiesOnly=yes",
            "-o", "IdentityAgent=none", "-o", "CertificateFile=none", "-o", "PreferredAuthentications=publickey",
            "-o", "BatchMode=yes", "-o", "ForwardAgent=no", "-o", "ClearAllForwardings=yes", "-o", "ConnectionAttempts=1",
            "-o", "ConnectTimeout=15", "-o", "ServerAliveInterval=15", "-o", "ServerAliveCountMax=2", GATEWAY]


def attach(client, path, authorization, gateway, human_intent, human_authority, digest, private):
    _, state, _ = owned_state(client, path, authorization, need_policy=True)
    human.require(state == "TRUE", "serial_enable_required")
    human.owned_key(client, human_intent, digest, human_authority, active=True)
    ssh = shutil.which("ssh.exe")
    human.require(ssh and private.is_file() and not private.is_symlink(), "serial_client_or_private_key")
    with tempfile.TemporaryDirectory(prefix="clipforge-noble-serial-") as folder:
        known = Path(folder) / "known_hosts"
        known.write_text(gateway_key(gateway), encoding="ascii")
        completed = subprocess.run(serial_argv(ssh, known, private), timeout=900)
    return {"status": "serial_interactive_session_closed", "ssh_exit": completed.returncode,
            "grub_interactive_proven": False, "recovery_proven": False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("enable", "attach", "restore"))
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--human-approval", type=Path, required=True)
    parser.add_argument("--human-approval-sha256", required=True)
    parser.add_argument("--key-intent", type=Path, required=True)
    parser.add_argument("--serial-intent", type=Path, required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--gateway-key", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    args = parser.parse_args()
    try:
        _, digest, _ = human.key_line(human.scoped_json(args.public_key, 2048))
        human_decision = human.decision(human.scoped_json(args.human_approval, 8192), args.human_approval_sha256, digest)
        authority = args.approval_sha256
        serial_decision = approval(human.scoped_json(args.approval, 8192), authority, args.human_approval_sha256)
        human.require(serial_decision["approved_commit"] == human_decision["approved_commit"], "serial_human_control_commit")
        gcloud = shutil.which("gcloud.cmd")
        human.require(gcloud is not None, "serial_windows_gcloud")
        client = human.Client(human.human_token(gcloud))
        if args.operation == "restore":
            result = restore(client, args.serial_intent, authority)
        elif args.operation == "enable":
            human.owned_key(client, args.key_intent, digest, args.human_approval_sha256, active=True)
            result = enable(client, args.serial_intent, authority, args.gateway_key)
        else:
            human.require(args.private_key and args.public_key.resolve() == Path(str(args.private_key.resolve()) + ".pub"),
                          "serial_private_key_pair")
            result = attach(client, args.serial_intent, authority, args.gateway_key, args.key_intent,
                            args.human_approval_sha256, digest, args.private_key.resolve())
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        result = {"status": "serial_blocked_or_reconcile",
                  "error": str(error) if isinstance(error, human.Blocked) else type(error).__name__}
    print(human.canonical(result).decode("ascii"))
    return int(result["status"] == "serial_blocked_or_reconcile" or result.get("ssh_exit", 0) != 0)


if __name__ == "__main__":
    raise SystemExit(main())
