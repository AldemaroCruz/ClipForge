"""Materialize and verify only the proposed, temporary Noble apply permissions."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from scripts import int_db01_noble_read_iam as iam


PROFILE_PATH = Path("config/int-db01-noble-write-iam.json")
PROFILE_SCHEMA = "clipforge-db01-noble-write-iam-1"
APPROVAL_SCHEMA = "clipforge-db01-noble-write-authorization-1"
APPROVAL_DECISION = "authorize_exact_write_delta_for_noble_create_observe"
RECEIPT_SCHEMA = "clipforge-db01-noble-write-iam-receipt-1"
PRODUCER = "c302dcc366ed450f91c1693072eb9008e7975e4c"
RUN = "44650537240"
PLAN_MANIFEST_SHA = "6ca0f88d6345b2f77e3a28ace8c0cc8051544a23b259054f49ec24bdf2a9d4ff"
PROJECT = iam.PROJECT
ZONE = "projects/816643438938/iap_tunnel/zones/us-central1-a"
POLICY_ENDPOINTS = {
    PROJECT: "https://cloudresourcemanager.googleapis.com/v1/" + PROJECT,
    ZONE: "https://iap.googleapis.com/v1/" + ZONE,
}
ROLE_PERMISSIONS = {
    "clipforgeIntNobleSaCreateAttach": (
        PROJECT, "create", {"iam.serviceAccounts.actAs", "iam.serviceAccounts.create",
                            "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy"},
    ),
    "clipforgeIntNobleSaBindDeploy": (PROJECT, "create", {"iam.serviceAccounts.setIamPolicy"}),
    "clipforgeIntNobleIapZoneRead": (ZONE, "create", {"iap.tunnelZones.getIamPolicy"}),
    "clipforgeIntRecoveryIapPolicy_20261118T044838Z": (
        ZONE, "reuse", {"iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.setIamPolicy"},
    ),
}
IAM_SET_CONDITION = ' && api.getAttribute("iam.googleapis.com/modifiedGrantsByRole", []).hasOnly(["roles/iam.serviceAccountUser"])'
WINDOW_START = "2026-11-20T22:00:00Z"
WINDOW_END = "2026-11-21T00:00:00Z"
REQUIRE = iam.contract.require


def load_profile(root=iam.ROOT):
    profile = iam.foundation.decode((root / PROFILE_PATH).read_bytes())
    iam.check_fields(profile, {"schema", "principal", "not_before_utc", "expires_utc", "roles", "policies"})
    REQUIRE(profile["schema"] == PROFILE_SCHEMA and profile["principal"] == iam.MEMBER
            and (profile["not_before_utc"], profile["expires_utc"]) == (WINDOW_START, WINDOW_END), "Unreviewed WRITE profile")
    iam.check_fields(profile["roles"], {iam.ROLE_PREFIX + role for role in ROLE_PERMISSIONS})
    iam.check_fields(profile["policies"], POLICY_ENDPOINTS)
    time = f'request.time >= timestamp("{WINDOW_START}") && request.time < timestamp("{WINDOW_END}")'
    bindings = {}
    for role, (target, mode, required) in ROLE_PERMISSIONS.items():
        resource = iam.ROLE_PREFIX + role
        spec = profile["roles"][resource]
        iam.check_fields(spec, {"mode", "definition"})
        definition = spec["definition"]
        iam.check_fields(definition, {"title", "description", "stage", "includedPermissions"})
        REQUIRE(spec["mode"] == mode and definition["stage"] == "GA"
                and definition["includedPermissions"] == sorted(required), "Unreviewed WRITE permissions")
        bindings[resource] = (target, time + (IAM_SET_CONDITION if role == "clipforgeIntNobleSaBindDeploy" else ""))
    for target, policy in profile["policies"].items():
        iam.check_fields(policy, {"baseline_policy_sha256", "add_bindings"})
        REQUIRE(iam.valid_digest(policy["baseline_policy_sha256"]) and isinstance(policy["add_bindings"], list),
                "Missing WRITE baseline")
        for binding in policy["add_bindings"]:
            iam.check_fields(binding, {"role", "members", "condition"})
            expected_scope, expression = bindings.pop(binding["role"])
            iam.check_fields(binding["condition"], {"title", "description", "expression"})
            REQUIRE(target == expected_scope and binding["members"] == [iam.MEMBER]
                    and binding["condition"]["expression"] == expression, "Unreviewed WRITE binding")
    REQUIRE(not bindings, "Missing WRITE binding")
    return profile, iam.digest(profile)


def canonical_policy(target, policy):
    REQUIRE(target in POLICY_ENDPOINTS, "Unknown WRITE target")
    if (target == ZONE and isinstance(policy, dict) and policy.keys() <= {"etag", "version", "bindings"}
            and policy.get("version") in (None, 0, 1, 3) and policy.get("bindings", []) == []):
        policy = {**policy, "version": 3, "bindings": []}
    return iam.canonical_policy(policy)


def semantics(target, policy):
    value = canonical_policy(target, policy)
    del value["etag"]
    return value


def requested_policy(target, before, additions):
    requested = canonical_policy(target, before)
    requested["bindings"] += additions
    return canonical_policy(target, requested)


def verify_delta(target, before, after, additions):
    REQUIRE(before["etag"] != after["etag"] and after.get("version") == 3
            and semantics(target, after) == semantics(target, requested_policy(target, before, additions)),
            "WRITE policy changed beyond the exact additions")


def get_policy(target, token):
    raw = iam.request_json(POLICY_ENDPOINTS[target] + ":getIamPolicy", token, "POST",
                           {"options": {"requestedPolicyVersion": 3}})
    canonical_policy(target, raw)
    return raw


def set_policy(target, policy, token):
    canonical_policy(target, policy)
    payload = {"policy": policy}
    if target == PROJECT:
        payload["updateMask"] = "bindings,etag"
    return iam.request_json(POLICY_ENDPOINTS[target] + ":setIamPolicy", token, "POST", payload)


def proof_name(controls):
    REQUIRE(re.fullmatch(r"[a-f0-9]{40}", controls) is not None and controls != PRODUCER, "Exact distinct controls commit required")
    return f"{iam.custody.PREFIX}{controls}/{RUN}-1/foundation-state.json"


def verify_approval(approval, controls, profile_sha):
    iam.check_fields(approval, {"schema", "decision", "owner_approval_ref", "producer_commit", "producer_run",
                               "controls_commit", "profile_sha256", "plan_manifest_sha256"})
    REQUIRE(approval == {
        "schema": APPROVAL_SCHEMA, "decision": APPROVAL_DECISION, "owner_approval_ref": approval["owner_approval_ref"],
        "producer_commit": PRODUCER, "producer_run": RUN, "controls_commit": controls,
        "profile_sha256": profile_sha, "plan_manifest_sha256": PLAN_MANIFEST_SHA,
    } and isinstance(approval["owner_approval_ref"], str) and 0 < len(approval["owner_approval_ref"].strip()) <= 500,
            "The owner decision does not identify the exact Noble WRITE delta and saved plan")


def preflight(profile, token):
    from scripts import db01_noble_plan
    REQUIRE(db01_noble_plan.state_identity()["current_lock_absent"] is True, "Pinned state and lock precheck failed")
    before = {}
    for target, spec in profile["policies"].items():
        policy = get_policy(target, token)
        REQUIRE(iam.digest(policy) == spec["baseline_policy_sha256"], "WRITE policy baseline changed")
        requested_policy(target, policy, spec["add_bindings"])
        before[target] = policy
    for role, spec in profile["roles"].items():
        try:
            current = iam.request_json("https://iam.googleapis.com/v1/" + role, token)
        except iam.CloudError as error:
            if spec["mode"] == "create" and error.status == 404:
                continue
            raise
        REQUIRE(spec["mode"] == "reuse", "Proposed role identifier already exists")
        iam.check_role_definition(role, current, spec)
    return before


def check_grant_window():
    now = datetime.now(timezone.utc)
    REQUIRE(datetime.fromisoformat(WINDOW_START) <= now < datetime.fromisoformat(WINDOW_END), "Outside approved WRITE window")
    return now.isoformat()


def grant(profile, token, journal, controls, profile_sha):
    issued = check_grant_window()
    before = preflight(profile, token)
    iam.write_new(journal / "before.json", before)
    for role, spec in profile["roles"].items():
        if spec["mode"] != "create":
            continue
        check_grant_window()
        name = role.rsplit("/", 1)[1]
        iam.write_new(journal / f"{name}-intent.json", spec["definition"])
        iam.request_json("https://iam.googleapis.com/v1/" + PROJECT + "/roles", token, "POST",
                         {"roleId": name, "role": spec["definition"]})
        role_value = iam.request_json("https://iam.googleapis.com/v1/" + role, token)
        iam.check_role_definition(role, role_value, spec)
        iam.write_new(journal / f"{name}-readback.json", role_value)
    transitions = {}
    for index, (target, spec) in enumerate(profile["policies"].items()):
        check_grant_window()
        REQUIRE(get_policy(target, token) == before[target], "WRITE policy changed after preflight")
        payload = requested_policy(target, before[target], spec["add_bindings"])
        iam.write_new(journal / f"{index}-intent.json", {"target": target, "policy": payload})
        response = set_policy(target, payload, token)
        after = get_policy(target, token)
        verify_delta(target, before[target], after, spec["add_bindings"])
        REQUIRE(canonical_policy(target, response) == canonical_policy(target, after), "WRITE response and readback differ")
        transitions[target] = {"before": before[target], "after": after}
        iam.write_new(journal / f"{index}-readback.json", transitions[target])
    for target, delta in transitions.items():
        REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, delta["after"]),
                "WRITE policy differs before receipt publication")
    receipt = {"schema": RECEIPT_SCHEMA, "producer_commit": PRODUCER, "controls_commit": controls,
               "profile_sha256": profile_sha, "issued_utc": issued, "policies": transitions}
    iam.write_new(journal / "write-receipt.json", receipt)
    raw = iam.custody.canonical(receipt)
    ref = iam.custody.upload(proof_name(controls), raw)
    iam.write_new(journal / "write-receipt-reference.json", ref)
    REQUIRE(iam.custody.fetch_verified(ref) == raw, "WRITE receipt readback differs")
    return ref


def withdraw(profile, token, source, journal):
    baseline = iam.foundation.decode((source / "before.json").read_bytes())
    iam.check_fields(baseline, POLICY_ENDPOINTS)
    changes = []
    for index, (target, spec) in enumerate(profile["policies"].items()):
        before = baseline[target]
        REQUIRE(iam.digest(before) == spec["baseline_policy_sha256"], "Unexpected pre-grant policy")
        intent = source / f"{index}-intent.json"
        if not intent.is_file():
            continue
        REQUIRE(not intent.is_symlink() and iam.foundation.decode(intent.read_bytes()) ==
                {"target": target, "policy": requested_policy(target, before, spec["add_bindings"])}, "Unknown grant intent")
        current = get_policy(target, token)
        if semantics(target, current) != semantics(target, before):
            verify_delta(target, before, current, spec["add_bindings"])
            changes.append((index, target, current, {**canonical_policy(target, before), "etag": current["etag"]}))
    for index, target, current, requested in reversed(changes):
        REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, current),
                "WRITE policy changed before retirement")
        iam.write_new(journal / f"{index}-intent.json", {"target": target, "policy": requested})
        response = set_policy(target, requested, token)
        after = get_policy(target, token)
        REQUIRE(semantics(target, after) == semantics(target, requested)
                and canonical_policy(target, response) == canonical_policy(target, after), "WRITE retirement differs")
        iam.write_new(journal / f"{index}-readback.json", {"target": target, "policy": after})
    return len(changes)


def publish_decision(profile, controls, approval, decision, journal):
    from scripts import int_noble_apply
    reference = iam.foundation.decode((journal / "write-receipt-reference.json").read_bytes())
    REQUIRE(decision["owner_approval_ref"] == approval["owner_approval_ref"] and decision["write_receipt"] == reference,
            "Apply decision differs from the authorized WRITE transaction")
    manifest = iam.foundation.decode(iam.custody.fetch_verified(int_noble_apply.PLAN["manifest"]))
    int_noble_apply.verify_manifest(manifest)
    int_noble_apply.verify_decision(decision, manifest, profile, {"GITHUB_SHA": controls}, datetime.now(timezone.utc))
    applied = iam.foundation.decode((journal / "write-receipt.json").read_bytes())
    REQUIRE(iam.custody.fetch_verified(reference) == iam.custody.canonical(applied), "WRITE receipt differs from the local journal")
    encoded = iam.custody.canonical(decision)
    iam.write_new(journal / "decision-upload-intent.json", {"sha256": iam.custody.sha256(encoded)})
    name = f"{iam.custody.PREFIX}{controls}/{RUN}-1/manifest.json"
    ref = iam.custody.upload(name, encoded)
    iam.write_new(journal / "owner-decision-reference.json", ref)
    REQUIRE(iam.custody.fetch_verified(ref) == encoded, "Private decision readback differs")
    return ref


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("describe", "preflight", "grant", "publish-decision", "withdraw"))
    parser.add_argument("--controls-commit")
    parser.add_argument("--profile-sha256")
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--decision", type=Path)
    args = parser.parse_args(argv)
    token = None
    try:
        profile, digest = load_profile()
        if args.operation == "describe":
            print(json.dumps({"profile_sha256": digest, "window": [WINDOW_START, WINDOW_END], "grants_authorized": False}))
            return 0
        REQUIRE(digest == args.profile_sha256 and args.controls_commit and args.receipt_dir, "Exact WRITE context required")
        proof_name(args.controls_commit)
        iam.verify_checkout(args.controls_commit)
        iam.verify_receipt_location(args.receipt_dir)
        if args.operation != "preflight":
            REQUIRE(args.approval is not None and args.approval.is_file(), "Private owner approval is required")
            iam.verify_receipt_location(args.approval)
            approval = iam.foundation.decode(args.approval.read_bytes())
            verify_approval(approval, args.controls_commit, digest)
        if args.operation == "publish-decision":
            REQUIRE(args.decision is not None and args.decision.is_file(), "Private apply decision is required")
            iam.verify_receipt_location(args.decision)
            decision = iam.foundation.decode(args.decision.read_bytes())
        token = iam.admin_token()
        os.environ["GCP_ACCESS_TOKEN"] = token
        if args.operation in ("withdraw", "publish-decision"):
            REQUIRE(iam.foundation.decode((args.receipt_dir / "approval.json").read_bytes()) == approval,
                    "The operation must use the original grant approval")
        if args.operation == "publish-decision":
            result = {"status": "decision_verified", "reference": publish_decision(
                profile, args.controls_commit, approval, decision, args.receipt_dir)}
        elif args.operation == "withdraw":
            journal = args.receipt_dir / datetime.now(timezone.utc).strftime("withdraw-%Y%m%dT%H%M%S.%fZ")
            journal.mkdir(mode=0o700)
            result = {"status": "withdrawn", "policy_count": withdraw(profile, token, args.receipt_dir, journal)}
        elif args.operation == "grant":
            args.receipt_dir.mkdir(mode=0o700)
            iam.write_new(args.receipt_dir / "approval.json", approval)
            result = {"status": "granted_verified", "reference": grant(profile, token, args.receipt_dir, args.controls_commit, digest)}
        else:
            args.receipt_dir.mkdir(mode=0o700)
            before = preflight(profile, token)
            iam.write_new(args.receipt_dir / "before.json", before)
            result = {"status": "preflight_verified", "policies": len(before)}
        print(json.dumps(result))
        return 0
    except Exception as error:
        result = {"status": "blocked", "operation": args.operation, "error_type": type(error).__name__}
        if isinstance(error, iam.CloudError):
            result["http_status"] = error.status
        print(json.dumps(result))
        return 1
    finally:
        if token is not None:
            os.environ.pop("GCP_ACCESS_TOKEN", None)


if __name__ == "__main__":
    raise SystemExit(main())
