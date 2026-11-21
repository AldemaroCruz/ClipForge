"""Check the protected transport boundary without authenticating or starting it."""

from scripts import int_bootstrap_db as transport
from scripts import int_noble_kernel_observation as observer

from scripts import int_noble_guest_intervention_kmod as payload


def admit(raw, executable, *, protected_authority_sha256, protected_payload_sha256,
          controls_commit, handoff, pin_bytes, snapshot):
    """Bind already authenticated approvals and a fresh Compute snapshot."""
    payload.require(payload.digest(executable) == protected_payload_sha256, "kmod_protected_payload_mismatch")
    authority, authority_sha256, _ = payload.request(raw, protected_payload_sha256)
    payload.require(authority_sha256 == protected_authority_sha256 and controls_commit == authority["approved_commit"],
                    "kmod_protected_authority_or_commit_mismatch")
    _, pin = observer.checked_inputs(handoff, pin_bytes)
    payload.require(payload.digest(pin_bytes) == authority["pin_sha256"] and snapshot == pin["control_plane"]
                    and payload.object_sha(snapshot) == authority["snapshot_sha256"], "kmod_protected_snapshot_drift")
    return authority


def command(executable, protected_payload_sha256):
    """Render the existing digest-checked SSH command for the approved transport."""
    return transport.remote_loader(executable, protected_payload_sha256)


def accept_success(raw, native_exit, before, after, authority, protected_authority_sha256):
    """Verify a successful guest receipt after an independent fresh Compute read."""
    payload.require(native_exit == 0, "kmod_primary_failure_requires_reconciliation")
    payload.require(0 < len(raw) <= payload.MAX_INPUT and after == before
                    and payload.object_sha(before) == authority["snapshot_sha256"], "kmod_post_snapshot_drift")
    actual = payload.decode(raw)
    expected = payload.result(authority, protected_authority_sha256)
    status = "applied_verified" if authority["operation"] == "apply" else "withdrawn_verified"
    expected["status"] = status
    details = {"before", "after", "file"} if status == "applied_verified" else {"applied_receipt_sha256", "restored_observation_sha256"}
    payload.require(set(actual) == set(expected) | details | {"intent_sha256"}
                    and all(actual[key] == value for key, value in expected.items())
                    and payload.HEX.fullmatch(actual["intent_sha256"]), "kmod_post_receipt_mismatch")
    if status == "applied_verified":
        payload.expected_transition(actual["before"], actual["after"])
        file = actual["file"]
        payload.require(set(file) == {"dev", "ino", "mode", "size", "uid", "gid", "mtime_ns", "ctime_ns", "nlink", "sha256"}
                        and all(type(file[key]) is int and file[key] >= 0 for key in set(file) - {"sha256"})
                        and file["mode"] == 0o100644 and file["size"] == payload.RULE_BYTES
                        and file["uid"] == file["gid"] == 0 and file["nlink"] == 1 and file["sha256"] == payload.RULE_SHA256,
                        "kmod_post_file_mismatch")
    else:
        payload.require(all(payload.HEX.fullmatch(actual[key]) for key in details)
                        and actual["applied_receipt_sha256"] == authority["evidence_sha256"], "kmod_withdraw_receipt_mismatch")
    return actual
