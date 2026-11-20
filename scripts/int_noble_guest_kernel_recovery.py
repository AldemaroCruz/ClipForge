"""Capture the reviewed boot files and restore only the exact owned mitigation delta."""

import argparse
import json
import os
from pathlib import Path
import re
import stat
import tempfile

from scripts import int_noble_guest_apt as guest


BOOT_CFG = Path("/boot/grub/grub.cfg")
BOOT_ENV = BOOT_CFG.with_name("grubenv")
BASELINE_CFG = "0c8ac3e6c7dcb616eddcae12723da2b69f0e4fb471d2457bd41f3ed4797fab97"
RECOVERY = guest.ROOT / "clipforge-noble-kernel-recovery"
EXACT_DROP_INS = {
    Path("/etc/modprobe.d/98-clipforge-int-noble-kernel.conf"): "4bf91a0780473f141bef96afec377c7f7d627fc4b207137544b7dd4bee034784",
    Path("/etc/default/grub.d/98-clipforge-int-noble-kernel.cfg"): "00ad808796f99113e7c7755d508ef703d7252eb57eee09a7eb374edd7ffc17b6",
}
SCHEMA = "clipforge-noble-kernel-recovery-authority-1"


def file_bytes(path, maximum=1048576):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as stream:
        meta = os.fstat(stream.fileno())
        guest.require(stat.S_ISREG(meta.st_mode) and meta.st_uid == 0 and meta.st_gid == 0
                      and 0 < meta.st_size <= maximum, "kernel_recovery_file_attributes")
        raw = stream.read(maximum + 1)
        guest.require(len(raw) == meta.st_size, "kernel_recovery_file_changed")
    return raw, stat.S_IMODE(meta.st_mode)


def digest(raw):
    return guest.sha256(raw).hexdigest()


def write_exclusive(path, raw):
    fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_WRONLY, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def decision(raw, expected):
    guest.require(len(raw) <= 8192 and digest(raw) == expected, "kernel_recovery_authority_digest")
    result = json.loads(raw)
    tied = {"schema": SCHEMA, "instance_id": guest.INSTANCE, "boot_disk_id": guest.BOOT_DISK,
            "data_disk_id": guest.DATA_DISK, "original_grub_sha256": BASELINE_CFG,
            "original_boot_id": guest.GUEST_BOOT, "runtime_authorized": False,
            "conditional_restore_approved": True}
    guest.require(set(result) == set(tied) | {"operation_id", "approved_commit"}
                  and all(result[key] == value for key, value in tied.items())
                  and re.fullmatch(r"[a-z][a-z0-9-]{15,63}", result["operation_id"])
                  and re.fullmatch(r"[a-f0-9]{40}", result["approved_commit"]), "kernel_recovery_authority_scope")
    return result


def capture(authority, decision_sha):
    guest.guest_identity()
    guest.require(not any(os.path.lexists(path) for path in EXACT_DROP_INS), "kernel_owned_paths_not_absent")
    grub, mode = file_bytes(BOOT_CFG)
    grubenv, _ = file_bytes(BOOT_ENV, 1024)
    guest.require(digest(grub) == BASELINE_CFG and len(grubenv) == 1024, "kernel_original_boot_files_changed")
    RECOVERY.mkdir(mode=0o700)
    write_exclusive(RECOVERY / "grub.cfg.original", grub)
    write_exclusive(RECOVERY / "grubenv.original", grubenv)
    record = {"operation_id": authority["operation_id"], "owner_decision_sha256": decision_sha,
              "original_cfg_sha256": digest(grub), "original_cfg_mode": mode, "original_env_sha256": digest(grubenv),
              "original_boot_id": guest.GUEST_BOOT, "drop_ins_originally_absent": True}
    write_exclusive(RECOVERY / "snapshot.json", guest.canonical(record) + b"\n")
    sync_directory(RECOVERY)
    sync_directory(RECOVERY.parent)
    return {"status": "original_boot_files_preserved", **record, "bootstrap_authorized": False}


def atomic_replace(path, raw, mode):
    with tempfile.NamedTemporaryFile(prefix=".clipforge-noble-restore-", dir=path.parent, delete=False) as stream:
        own = Path(stream.name)
        try:
            os.fchmod(stream.fileno(), mode)
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
            os.replace(own, path)
            sync_directory(path.parent)
        finally:
            own.unlink(missing_ok=True)


def restore(authority, decision_sha, reviewed_after, reason="failed_post_restart"):
    boot = guest.guest_identity(expected_boot=None)
    reviewed_boot = (reason == "failed_post_restart" and boot != guest.GUEST_BOOT
                     or reason == "aborted_pre_restart" and boot == guest.GUEST_BOOT)
    guest.require(reviewed_boot and re.fullmatch(r"[a-f0-9]{64}", reviewed_after)
                  and (reason == "aborted_pre_restart" or reviewed_after != BASELINE_CFG),
                  "kernel_restore_requires_reviewed_boot_and_reason")
    directory = RECOVERY.lstat()
    guest.require(stat.S_ISDIR(directory.st_mode) and directory.st_uid == 0
                  and stat.S_IMODE(directory.st_mode) == 0o700, "kernel_recovery_snapshot_directory")
    record = json.loads(file_bytes(RECOVERY / "snapshot.json", 8192)[0])
    guest.require(record["operation_id"] == authority["operation_id"] and record["owner_decision_sha256"] == decision_sha
                  and record["original_boot_id"] == guest.GUEST_BOOT and record["drop_ins_originally_absent"] is True,
                  "kernel_recovery_snapshot_scope")
    base, _ = file_bytes(RECOVERY / "grub.cfg.original")
    current, mode = file_bytes(BOOT_CFG)
    guest.require(digest(base) == record["original_cfg_sha256"] == BASELINE_CFG
                  and digest(current) == reviewed_after and mode == record["original_cfg_mode"], "kernel_recovery_grub_drift")
    owned = {path: expected for path, expected in EXACT_DROP_INS.items() if os.path.lexists(path)}
    guest.require((reason == "aborted_pre_restart" and (owned or reviewed_after != BASELINE_CFG) or owned == EXACT_DROP_INS)
                  and all(digest(file_bytes(path, 8192)[0]) == expected for path, expected in owned.items()),
                  "kernel_recovery_drop_in_drift")
    write_exclusive(RECOVERY / "restore.intent.json", guest.canonical({"boot_id": boot, "grub_before": reviewed_after, "reason": reason}) + b"\n")
    sync_directory(RECOVERY)
    # Preserve grubenv runtime fields. This operator never changes or rewinds them.
    if reviewed_after != BASELINE_CFG:
        atomic_replace(BOOT_CFG, base, mode)
    for path, expected in owned.items():
        guest.require(digest(file_bytes(path, 8192)[0]) == expected, "kernel_recovery_restore_interrupted_by_drift")
        path.unlink()
        sync_directory(path.parent)
    guest.require(digest(file_bytes(BOOT_CFG)[0]) == BASELINE_CFG
                  and not any(os.path.lexists(path) for path in EXACT_DROP_INS), "kernel_recovery_postcheck_failed")
    receipt = {"status": "owned_kernel_configuration_restored_bootstrap_blocked", "boot_id": boot,
               "restored_grub_sha256": BASELINE_CFG, "bootstrap_authorized": False,
               "grubenv_retained": True, "reboot_attempted": False, "reason": reason}
    write_exclusive(RECOVERY / "restore.receipt.json", guest.canonical(receipt) + b"\n")
    sync_directory(RECOVERY)
    return receipt


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("capture", "restore"))
    parser.add_argument("--decision", type=Path, required=True)
    parser.add_argument("--decision-sha256", required=True)
    parser.add_argument("--approved-installed-grub-sha256")
    parser.add_argument("--restore-reason", choices=("aborted_pre_restart", "failed_post_restart"))
    args = parser.parse_args()
    try:
        authority = decision(args.decision.read_bytes(), args.decision_sha256)
        result = (capture(authority, args.decision_sha256) if args.operation == "capture" else
                  restore(authority, args.decision_sha256, args.approved_installed_grub_sha256, args.restore_reason))
    except (OSError, ValueError, TypeError, KeyError) as error:
        result = {"status": "kernel_recovery_blocked_or_reconcile", "bootstrap_authorized": False,
                  "error": str(error) if isinstance(error, guest.Blocked) else type(error).__name__}
    print(guest.canonical(result).decode("ascii"))
    return int(result["status"] == "kernel_recovery_blocked_or_reconcile")


if __name__ == "__main__":
    raise SystemExit(main())
