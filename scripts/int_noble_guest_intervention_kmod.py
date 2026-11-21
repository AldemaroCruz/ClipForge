"""One-shot application or withdrawal of the reviewed Noble kmod-only rule."""

from datetime import datetime, timezone
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import re
import stat
import sys
import tempfile

if "probe" not in globals():
    from scripts import int_noble_demo_preflight_guest as checks
    from scripts import int_noble_guest_apt as guest
    from scripts import int_noble_kernel_consumers_guest as probe


RULE = (b"# Proposed for Noble only, subject to reviewed guest evidence and approval.\n"
        b"blacklist xen_netback\ninstall xen_netback /bin/false\n"
        b"blacklist ceph\ninstall ceph /bin/false\n"
        b"blacklist nfsd\ninstall nfsd /bin/false\n")
RULE_PATH = probe.KMOD_RULE
RULE_BYTES = 207
RULE_SHA256 = probe.KMOD_SHA256
JOURNAL = guest.ROOT / "clipforge-noble-kmod-only"
PIN_SHA256 = "eace51fdd5447ed1d10b02d498c4d48caf9ac33e42bd58596e10282028ebb414"
OBSERVATION_SHA256 = "f9e067a9bf95fda7b11e0d904597e14a41224ba19cdcc378a74f08431cad5b65"
INPUT = "clipforge-int-noble-kmod-input-1"
AUTHORIZATION = "clipforge-int-noble-kmod-authority-1"
RECEIPT = "clipforge-int-noble-kmod-receipt-1"
INTENT = "clipforge-int-noble-kmod-intent-1"
OBSERVATION = "clipforge-int-noble-kernel-observation-receipt-1"
MAX_INPUT = 65536
HEX = re.compile(r"[a-f0-9]{64}")
COMMIT = re.compile(r"[a-f0-9]{40}")
OP_ID = re.compile(r"[a-z][a-z0-9-]{15,63}")
IDENTITY = {"instance_id": guest.INSTANCE, "boot_disk_id": guest.BOOT_DISK, "data_disk_id": guest.DATA_DISK,
            "boot_id": guest.GUEST_BOOT, "release": guest.RELEASE}
require, canonical = guest.require, guest.canonical


def digest(raw):
    return sha256(raw).hexdigest()


def object_sha(value):
    return digest(canonical(value))


def decode(raw):
    value = json.loads(raw.decode("ascii"), object_pairs_hook=probe.unique_pairs)
    require(isinstance(value, dict) and canonical(value) in {raw, raw.removesuffix(b"\n")}, "kmod_noncanonical_input")
    return value


def current(authority, *, now=None):
    expiry = datetime.fromisoformat(authority["expires_utc"])
    require(expiry.utcoffset() == timezone.utc.utcoffset(expiry)
            and (now or datetime.now(timezone.utc)) < expiry, "kmod_authority_expired_or_not_utc")


def request(raw, executable_sha256, *, now=None):
    require(0 < len(raw) <= MAX_INPUT and HEX.fullmatch(executable_sha256), "kmod_input_size_or_executable")
    value = decode(raw)
    require(set(value) == {"schema", "authority", "authority_sha256", "evidence"}
            and value["schema"] == INPUT, "kmod_input_schema")
    authority, evidence = value["authority"], value["evidence"]
    expected = {"schema": AUTHORIZATION, **IDENTITY, "pin_sha256": PIN_SHA256,
                "rule_sha256": RULE_SHA256, "payload_sha256": executable_sha256,
                "evidence_sha256": object_sha(evidence)}
    require(isinstance(authority, dict) and set(authority) == set(expected) | {
            "operation", "operation_id", "approved_commit", "snapshot_sha256", "expires_utc"}
            and all(authority[key] == item for key, item in expected.items())
            and authority["operation"] in {"apply", "withdraw"}
            and OP_ID.fullmatch(authority["operation_id"]) and COMMIT.fullmatch(authority["approved_commit"])
            and HEX.fullmatch(authority["snapshot_sha256"])
            and object_sha(authority) == value["authority_sha256"], "kmod_authority_scope")
    current(authority, now=now)
    require(len(RULE) == RULE_BYTES and digest(RULE) == RULE_SHA256, "kmod_reviewed_rule_bytes")
    return authority, value["authority_sha256"], evidence


def checked_baseline(evidence, snapshot_sha256):
    require(set(evidence) == {"schema", "initial_observation_run_id", "controls_commit", "payload_sha256", "control_plane",
                              "guest", "risk_accepted", "runtime_authorized"}
            and evidence["schema"] == OBSERVATION and evidence["initial_observation_run_id"] == "44772950030"
            and COMMIT.fullmatch(evidence["controls_commit"]) and evidence["payload_sha256"] == OBSERVATION_SHA256
            and evidence["risk_accepted"] is False and evidence["runtime_authorized"] is False
            and object_sha(evidence["control_plane"]) == snapshot_sha256
            and all(evidence["control_plane"][key] == IDENTITY[key] for key in ("instance_id", "boot_disk_id", "data_disk_id")),
            "kmod_reviewed_observation_scope")
    return probe.validate(canonical(evidence["guest"]), IDENTITY["boot_id"])


def checked_consumers(report):
    raw = canonical(report)
    probe.validate(raw, IDENTITY["boot_id"])
    kernel, xen, ceph, kmod = (report[name] for name in ("kernel", "xen", "ceph", "kmod"))
    require(kernel["release"] == IDENTITY["release"] and kernel["virtualization"] == "google"
            and xen["private_nic_driver"] in {"gve", "virtio_net"} and xen["backend_vifs"] == 0,
            "kmod_xen_consumer_or_driver_indeterminate")
    require(all(ceph[field] == 0 for field in ("pid1_mounts", "fstab_mounts", "named_processes", "pid1_canonical_remote_sockets"))
            and ceph["packages"] is not None and ceph["data_disk_relation"] == "expected_device_unmounted", "kmod_ceph_or_disk_state")
    require(all(row == {"disk": "module_file", "loaded": False, "sysfs": False} for row in kernel["modules"].values())
            and kernel["autoload"]["modules_load"] == dict.fromkeys(probe.kernel.MODULES, 0)
            and kernel["autoload"]["modprobe"] is not None and kmod["helper"] == "standard"
            and kmod["modules_disabled"] is False
            and kmod["boot_blacklist"] == dict.fromkeys(probe.kernel.MODULES, False), "kmod_current_kernel_or_loader_state")
    require(all(row is not None and row["active"] == "inactive" for row in kernel["units"].values())
            and kernel["mounts"] is not None and not any(kernel["mounts"].values())
            and kernel["exports"]["configured"] == 0 and kernel["exports"]["active"] in {None, 0}
            and all(ports is not None and not any(ports.values()) for ports in kernel["listeners"].values()),
            "kmod_other_consumer_or_indeterminate")
    return digest(raw)


def live_report():
    guest.guest_identity(expected_boot=IDENTITY["boot_id"])
    nfs = checks.nfs_exports()
    require(nfs["host_mount_namespace"] is True and nfs["registered_filesystem"] is False and nfs["module_loaded"] is False
            and nfs["nfsd_mounts"] == nfs["active_count"] == nfs["configured_count"] == 0, "kmod_live_nfs_consumer_or_indeterminate")
    live = probe.collect()
    checked_consumers(live)
    return live


def verify_unmitigated(before):
    checked_consumers(before)
    require(before["kmod"]["scope_rule"] == "absent", "kmod_rule_already_exists")
    for module in probe.kernel.MODULES:
        declaration = before["kernel"]["autoload"]["modprobe"][module]
        require(declaration["blacklist"] == 0 and declaration["install"] == "default" and declaration["dependencies"] == 0,
                "kmod_preexisting_module_rule")
        old = before["kmod"]["dry_run"][module]
        require(old["direct"] == "would_insert" and isinstance(old["aliases"], list) and old["aliases"]
                and all(item == "would_insert" for item in old["aliases"]), "kmod_unproven_baseline_resolution")


def expected_transition(before, after):
    """Only the reviewed rule and its kmod effects may change in this boot."""
    verify_unmitigated(before)
    checked_consumers(after)
    expected = json.loads(canonical(before))
    expected["kmod"]["scope_rule"] = "reviewed"
    for module in probe.kernel.MODULES:
        old = before["kmod"]["dry_run"][module]
        new = after["kmod"]["dry_run"][module]
        require(new["direct"] == "deny_install" and isinstance(new["aliases"], list)
                and len(new["aliases"]) == len(old["aliases"])
                and all(item in {"deny_install", "no_action_reported"} for item in new["aliases"]), "kmod_unproven_postcheck")
        expected["kernel"]["autoload"]["modprobe"][module].update(blacklist=1, install="deny")
        expected["kmod"]["dry_run"][module] = new
    require(after == expected, "kmod_consumer_or_configuration_drift")


def safe_directory(path, mode):
    state = path.lstat()
    require(stat.S_ISDIR(state.st_mode) and state.st_uid == state.st_gid == 0 and stat.S_IMODE(state.st_mode) == mode,
            "kmod_untrusted_directory")


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_exclusive(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    sync_directory(path.parent)


def read_closed_file(path, mode, limit):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1 and before.st_uid == before.st_gid == 0
                and stat.S_IMODE(before.st_mode) == mode and 0 < before.st_size <= limit, "kmod_untrusted_file")
        raw = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
    identity = ("st_dev", "st_ino", "st_mode", "st_size", "st_uid", "st_gid", "st_mtime_ns", "st_ctime_ns", "st_nlink")
    present = path.lstat()
    require(len(raw) == before.st_size and all(getattr(before, key) == getattr(after, key) == getattr(present, key)
                                            for key in identity), "kmod_file_changed_during_read")
    return raw, {key.removeprefix("st_"): getattr(present, key) for key in identity}


def rule_record():
    raw, fields = read_closed_file(RULE_PATH, 0o644, RULE_BYTES)
    require(raw == RULE and digest(raw) == RULE_SHA256, "kmod_rule_content_changed")
    return {**fields, "sha256": RULE_SHA256}


def install_rule():
    fd, temporary = tempfile.mkstemp(prefix=".clipforge-kmod-", dir=RULE_PATH.parent)
    try:
        with os.fdopen(fd, "wb") as stream:
            os.fchmod(stream.fileno(), 0o644)
            stream.write(RULE)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, RULE_PATH, follow_symlinks=False)
    finally:
        Path(temporary).unlink()
        sync_directory(RULE_PATH.parent)


def result(authority, authority_sha256):
    return {"schema": RECEIPT, **IDENTITY, "status": "blocked_before_intent", "operation": authority["operation"],
            "operation_id": authority["operation_id"], "approved_commit": authority["approved_commit"],
            "authority_sha256": authority_sha256, "snapshot_sha256": authority["snapshot_sha256"],
            "payload_sha256": authority["payload_sha256"], "rule_sha256": RULE_SHA256, "bootstrap_authorized": False,
            "runtime_authorized": False, "risk_accepted": False, "reboot_attempted": False}


def apply(authority, evidence, receipt):
    if os.path.lexists(JOURNAL):
        receipt["status"] = "prior_intent_requires_reconciliation"
        raise guest.Blocked("kmod_apply_must_reconcile")
    before = checked_baseline(evidence, authority["snapshot_sha256"])
    verify_unmitigated(before)
    require(live_report() == before, "kmod_live_observation_drift")
    require(before["kmod"]["scope_rule"] == "absent" and not os.path.lexists(RULE_PATH), "kmod_rule_already_exists")
    current(authority)
    JOURNAL.mkdir(mode=0o700)
    receipt["status"] = "apply_outcome_unknown_reconcile"
    sync_directory(JOURNAL.parent)
    intent = {"schema": INTENT, "operation": "apply", "authority_sha256": receipt["authority_sha256"],
              "operation_id": authority["operation_id"], "before_sha256": object_sha(before), "snapshot_sha256": authority["snapshot_sha256"]}
    write_exclusive(JOURNAL / "apply.intent.json", canonical(intent))
    require(live_report() == before and not os.path.lexists(RULE_PATH), "kmod_state_changed_after_intent")
    current(authority)
    install_rule()
    after = live_report()
    expected_transition(before, after)
    owned = rule_record()
    guest.guest_identity(expected_boot=IDENTITY["boot_id"])
    final = {**receipt, "status": "applied_verified", "before": before, "after": after,
             "intent_sha256": object_sha(intent), "file": owned}
    write_exclusive(JOURNAL / "apply.receipt.json", canonical(final))
    return final


def withdraw(authority, evidence, receipt):
    safe_directory(JOURNAL, 0o700)
    marker = JOURNAL / "withdraw.intent.json"
    if os.path.lexists(marker):
        receipt["status"] = "prior_intent_requires_reconciliation"
        raise guest.Blocked("kmod_withdraw_must_reconcile")
    raw, _ = read_closed_file(JOURNAL / "apply.receipt.json", 0o600, MAX_INPUT)
    applied = decode(raw)
    require(applied == evidence and applied["schema"] == RECEIPT and applied["operation"] == "apply"
            and applied["status"] == "applied_verified" and applied["snapshot_sha256"] == authority["snapshot_sha256"]
            and applied["rule_sha256"] == RULE_SHA256 and applied["payload_sha256"] == authority["payload_sha256"]
            and all(applied[key] == item for key, item in IDENTITY.items()), "kmod_apply_receipt_scope")
    intent_raw, _ = read_closed_file(JOURNAL / "apply.intent.json", 0o600, 4096)
    require(digest(intent_raw) == applied["intent_sha256"], "kmod_apply_intent_changed")
    expected_transition(applied["before"], applied["after"])
    require(rule_record() == applied["file"] and live_report() == applied["after"], "kmod_withdraw_state_drift")
    current(authority)
    intent = {"schema": INTENT, "operation": "withdraw", "authority_sha256": receipt["authority_sha256"],
              "operation_id": authority["operation_id"], "applied_receipt_sha256": digest(raw),
              "snapshot_sha256": authority["snapshot_sha256"]}
    receipt["status"] = "withdraw_outcome_unknown_reconcile"
    write_exclusive(marker, canonical(intent))
    require(live_report() == applied["after"] and rule_record() == applied["file"], "kmod_withdraw_state_changed_after_intent")
    current(authority)
    RULE_PATH.unlink()
    sync_directory(RULE_PATH.parent)
    require(not os.path.lexists(RULE_PATH) and live_report() == applied["before"], "kmod_withdraw_postcheck_drift")
    guest.guest_identity(expected_boot=IDENTITY["boot_id"])
    final = {**receipt, "status": "withdrawn_verified", "intent_sha256": object_sha(intent),
             "applied_receipt_sha256": digest(raw), "restored_observation_sha256": object_sha(applied["before"])}
    write_exclusive(JOURNAL / "withdraw.receipt.json", canonical(final))
    return final


def execute(raw, executable_sha256):
    receipt = {"schema": RECEIPT, "status": "blocked_before_intent", "bootstrap_authorized": False,
               "runtime_authorized": False, "risk_accepted": False, "reboot_attempted": False}
    try:
        authority, authority_sha256, evidence = request(raw, executable_sha256)
        receipt = result(authority, authority_sha256)
        guest.guest_identity(expected_boot=IDENTITY["boot_id"])
        safe_directory(RULE_PATH.parent, 0o755)
        if authority["operation"] == "apply":
            return apply(authority, evidence, receipt)
        return withdraw(authority, evidence, receipt)
    except (OSError, UnicodeError, http.client.HTTPException, ValueError, KeyError, TypeError, RecursionError) as error:
        receipt["error"] = str(error) if isinstance(error, guest.Blocked) else type(error).__name__
        return receipt


if __name__ == "__main__":
    if "DB01_OPERATOR_SHA256" not in globals():
        raise SystemExit("Use the reviewed protected INT bridge to invoke this payload.")
    receipt = execute(sys.stdin.buffer.read(MAX_INPUT + 1), DB01_OPERATOR_SHA256)
    print(canonical(receipt).decode("ascii"), flush=True)
    raise SystemExit(0 if receipt["status"] in {"applied_verified", "withdrawn_verified"} else 1)
