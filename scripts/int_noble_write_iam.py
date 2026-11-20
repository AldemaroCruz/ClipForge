"""Migrate and verify the four reviewed Noble WRITE bindings."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re

from scripts import int_db01_noble_read_iam as iam


PROFILE_PATH = Path("config/int-db01-noble-write-iam.json")
PROFILE_SCHEMA = "clipforge-db01-noble-write-iam-2"
APPROVAL_SCHEMA = "clipforge-db01-noble-stable-write-authorization-1"
APPROVAL_DECISION = "replace_exact_temporal_noble_write_with_stable"
REVOCATION_DECISION = "revoke_exact_stable_noble_write"
PARTIAL_REVOCATION_DECISION = "revoke_exact_partial_noble_write"
RECEIPT_SCHEMA = "clipforge-db01-noble-stable-write-receipt-1"
TEMPORAL_SCHEMA = "clipforge-db01-noble-write-iam-receipt-1"
TEMPORAL_CONTROL = "e5f4943ca6a67a257f8d09666abaad54822f1ee1"
TEMPORAL_PROFILE_SHA = "61f1abf24d45b5f1d0dcf432100c5b32a7ef3d188df034a22dd55a361488fe08"
READ_PRODUCER = "c302dcc366ed450f91c1693072eb9008e7975e4c"
TEMPORAL_RECEIPT = {
    "name": f"{iam.custody.PREFIX}{TEMPORAL_CONTROL}/44650537240-1/foundation-state.json",
    "generation": "1795141428931762",
    "sha256": "ff0110f556739be46e27369ac621be14597afae589ed3af21f0eed007225b0b7",
    "size": 25027,
}
READ_RECEIPT = {
    "name": iam.proof_name(READ_PRODUCER),
    "generation": "1795136476328109",
    "sha256": "e495bd6cca23fa19ecbd2c0ead3876273f4d9f797793d41afbea44475833af48",
    "size": 43427,
}
PROJECT = iam.PROJECT
ZONE = "projects/816643438938/iap_tunnel/zones/us-central1-a"
POLICY_ENDPOINTS = {
    PROJECT: "https://cloudresourcemanager.googleapis.com/v1/" + PROJECT,
    ZONE: "https://iap.googleapis.com/v1/" + ZONE,
}
SA_POLICY_SETTER = "clipforgeIntNobleSaBindDeploy"
ROLE_PERMISSIONS = {
    "clipforgeIntNobleSaCreateAttach": (
        PROJECT, {"iam.serviceAccounts.actAs", "iam.serviceAccounts.create",
                  "iam.serviceAccounts.get", "iam.serviceAccounts.getIamPolicy"},
    ),
    SA_POLICY_SETTER: (PROJECT, {"iam.serviceAccounts.setIamPolicy"}),
    "clipforgeIntNobleIapZoneRead": (ZONE, {"iap.tunnelZones.getIamPolicy"}),
    "clipforgeIntRecoveryIapPolicy_20261118T044838Z": (
        ZONE, {"iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.setIamPolicy"},
    ),
}
SA_POLICY_CONDITION = {
    "title": "clipforge_int_noble_sa_member_stable",
    "description": "Noble service-account policy edits limited to serviceAccountUser",
    "expression": 'api.getAttribute("iam.googleapis.com/modifiedGrantsByRole", []).hasOnly(["roles/iam.serviceAccountUser"])',
}
REQUIRE = iam.contract.require


def load_profile(root=iam.ROOT):
    profile = iam.foundation.decode((root / PROFILE_PATH).read_bytes())
    iam.check_fields(profile, {"schema", "principal", "roles", "policies"})
    REQUIRE(profile["schema"] == PROFILE_SCHEMA and profile["principal"] == iam.MEMBER, "Unreviewed WRITE profile")
    iam.check_fields(profile["roles"], {iam.ROLE_PREFIX + role for role in ROLE_PERMISSIONS})
    iam.check_fields(profile["policies"], POLICY_ENDPOINTS)
    expected = {target: [] for target in POLICY_ENDPOINTS}
    for role, (target, permissions) in ROLE_PERMISSIONS.items():
        resource = iam.ROLE_PREFIX + role
        spec = profile["roles"][resource]
        iam.check_fields(spec, {"mode", "definition"})
        definition = spec["definition"]
        iam.check_fields(definition, {"title", "description", "stage", "includedPermissions"})
        REQUIRE(spec["mode"] == "reuse" and definition["stage"] == "GA"
                and definition["includedPermissions"] == sorted(permissions)
                and all(isinstance(definition[key], str) and definition[key] for key in ("title", "description")),
                "Unreviewed WRITE role")
        binding = {"role": resource, "members": [iam.MEMBER]}
        if role == SA_POLICY_SETTER:
            binding["condition"] = SA_POLICY_CONDITION
        expected[target].append(binding)
    for target, policy in profile["policies"].items():
        iam.check_fields(policy, {"baseline_policy_sha256", "add_bindings"})
        REQUIRE(iam.valid_digest(policy["baseline_policy_sha256"]) and isinstance(policy["add_bindings"], list)
                and sorted(map(iam.custody.canonical, policy["add_bindings"]))
                == sorted(map(iam.custody.canonical, expected[target])), "Unreviewed WRITE binding")
    return profile, iam.digest(profile)


def canonical_policy(target, policy):
    REQUIRE(target in POLICY_ENDPOINTS, "Unknown WRITE target")
    # IAP can omit version or bindings when only unconditional bindings remain.
    if target == ZONE and isinstance(policy, dict):
        version = policy.get("version", 0)
        bindings = policy.get("bindings", [])
        if (type(version) is int and version in (0, 1, 3) and isinstance(bindings, list)
                and all(isinstance(binding, dict) and "condition" not in binding for binding in bindings)):
            policy = {**policy, "version": 3, "bindings": bindings}
    return iam.canonical_policy(policy)


def semantics(target, policy):
    value = canonical_policy(target, policy)
    del value["etag"]
    return value


def requested_policy(target, before, additions):
    requested = canonical_policy(target, before)
    requested["bindings"] += additions
    return canonical_policy(target, requested)


def verify_transition(target, before, after, requested):
    REQUIRE(before["etag"] != after["etag"] and semantics(target, after) == semantics(target, requested),
            "WRITE policy changed beyond the approved transition")


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


def stable_proof_name(controls):
    REQUIRE(isinstance(controls, str) and re.fullmatch(r"[a-f0-9]{40}", controls)
            and controls not in {TEMPORAL_CONTROL, READ_PRODUCER}, "Exact stable migration commit required")
    return f"{iam.custody.PREFIX}{controls}/1-1/foundation-state.json"


def verify_stable_reference(reference, receipt=None):
    iam.check_fields(reference, {"name", "generation", "sha256", "size"})
    match = re.fullmatch(re.escape(iam.custody.PREFIX) + r"([a-f0-9]{40})/1-1/foundation-state\.json",
                         reference["name"]) if isinstance(reference["name"], str) else None
    REQUIRE(match and reference["name"] == stable_proof_name(match.group(1))
            and (receipt is None or receipt["controls_commit"] == match.group(1))
            and isinstance(reference["generation"], str) and re.fullmatch(r"[1-9][0-9]*", reference["generation"])
            and iam.valid_digest(reference["sha256"]) and type(reference["size"]) is int
            and 0 < reference["size"] <= 2 * 1024 * 1024, "Invalid stable WRITE receipt reference")


def timestamp(value):
    result = datetime.fromisoformat(value)
    REQUIRE(result.utcoffset() == timedelta(0), "UTC receipt timestamp required")
    return result


def verify_temporal_receipt(profile, temporal, read_proof):
    iam.check_fields(temporal, {"schema", "producer_commit", "controls_commit", "profile_sha256", "issued_utc", "policies"})
    REQUIRE(temporal["schema"] == TEMPORAL_SCHEMA and temporal["producer_commit"] == READ_PRODUCER
            and temporal["controls_commit"] == TEMPORAL_CONTROL and temporal["profile_sha256"] == TEMPORAL_PROFILE_SHA
            and iam.digest(temporal) == TEMPORAL_RECEIPT["sha256"], "Archived temporal WRITE receipt differs")
    timestamp(temporal["issued_utc"])
    iam.check_fields(temporal["policies"], POLICY_ENDPOINTS)
    for target, spec in profile["policies"].items():
        delta = temporal["policies"][target]
        iam.check_fields(delta, {"before", "after"})
        before, after = delta["before"], delta["after"]
        REQUIRE(iam.digest(before) == spec["baseline_policy_sha256"], "Archived WRITE baseline differs")
        if target in read_proof["policies"]:
            REQUIRE(canonical_policy(target, before) == canonical_policy(target, read_proof["policies"][target]["after"]),
                    "Archived WRITE baseline differs from the retained READ policy")
        prior_bindings = canonical_policy(target, before)["bindings"]
        added = [row for row in canonical_policy(target, after)["bindings"] if row not in prior_bindings]
        REQUIRE(all("condition" in row for row in added)
                and sorted((row["role"], row["members"]) for row in added)
                == sorted((row["role"], row["members"]) for row in spec["add_bindings"]),
                "Archived WRITE bindings differ from the approved scopes or principal")
        verify_transition(target, before, after, requested_policy(target, before, added))


def verify_stable_receipt(profile, stable, temporal, read_proof):
    verify_temporal_receipt(profile, temporal, read_proof)
    iam.check_fields(stable, {"schema", "controls_commit", "profile_sha256", "issued_utc",
                             "temporary_receipt", "read_receipt", "policies"})
    stable_proof_name(stable["controls_commit"])
    REQUIRE(stable["schema"] == RECEIPT_SCHEMA and stable["profile_sha256"] == iam.digest(profile)
            and stable["temporary_receipt"] == TEMPORAL_RECEIPT and stable["read_receipt"] == READ_RECEIPT
            and timestamp(stable["issued_utc"]) >= timestamp(temporal["issued_utc"]),
            "Stable WRITE receipt ancestry differs")
    iam.check_fields(stable["policies"], POLICY_ENDPOINTS)
    for target, delta in stable["policies"].items():
        iam.check_fields(delta, {"before", "after"})
        archived = temporal["policies"][target]
        REQUIRE(canonical_policy(target, delta["before"]) == canonical_policy(target, archived["after"]),
                "Stable WRITE before policy differs from archived temporal WRITE")
        expected = requested_policy(target, archived["before"], profile["policies"][target]["add_bindings"])
        verify_transition(target, delta["before"], delta["after"], expected)


def load_read_chain():
    from scripts import db01_noble_plan
    return db01_noble_plan.load_iam_evidence({
        "GITHUB_SHA": READ_PRODUCER, "DB01_NOBLE_IAM_RECEIPT": iam.custody.canonical(READ_RECEIPT).decode("ascii"),
    })


def load_stable_evidence(reference):
    verify_stable_reference(reference)
    profile, _ = load_profile()
    read_profile, read_proof, etags, record = load_read_chain()
    temporal = iam.foundation.decode(iam.custody.fetch_verified(TEMPORAL_RECEIPT))
    stable = iam.foundation.decode(iam.custody.fetch_verified(reference))
    verify_stable_reference(reference, stable)
    verify_stable_receipt(profile, stable, temporal, read_proof)
    return profile, stable, read_profile, read_proof, etags, record


def verify_roles(roles, token):
    for role, spec in roles.items():
        value = iam.request_json("https://iam.googleapis.com/v1/" + role, token)
        iam.check_role_definition(role, value, spec)


def verify_live_policies(profile, receipt, token):
    verify_roles(profile["roles"], token)
    for target, delta in receipt["policies"].items():
        REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, delta["after"]),
                "Live policy differs from stable WRITE receipt")


def verify_unaffected_read(read_profile, read_proof, token):
    verify_roles(read_profile["roles"], token)
    for target in set(read_profile["policies"]) - set(POLICY_ENDPOINTS):
        observed = iam.get_policy(target, read_profile["policies"][target], token)
        expected = read_proof["policies"][target]["after"]
        REQUIRE(iam.canonical_policy(observed) == iam.canonical_policy(expected),
                "An unaffected stable READ policy changed")


def verify_approval(approval, controls, profile_sha, operation="migrate"):
    expected = {
        "migrate": (APPROVAL_DECISION, {"temporary_receipt"}),
        "revoke": (REVOCATION_DECISION, {"stable_receipt"}),
        "revoke-partial": (PARTIAL_REVOCATION_DECISION, {"temporary_receipt", "migration_controls_commit"}),
    }
    decision, fields = expected[operation]
    iam.check_fields(approval, {"schema", "decision", "owner_approval_ref", "controls_commit", "profile_sha256"} | fields)
    REQUIRE(approval["schema"] == APPROVAL_SCHEMA
            and approval["decision"] == decision
            and approval["controls_commit"] == controls and approval["profile_sha256"] == profile_sha
            and ("temporary_receipt" not in fields or approval["temporary_receipt"] == TEMPORAL_RECEIPT)
            and isinstance(approval["owner_approval_ref"], str) and 0 < len(approval["owner_approval_ref"].strip()) <= 500,
            "The owner decision does not identify the exact WRITE action")
    if operation == "revoke":
        verify_stable_reference(approval["stable_receipt"])
    if operation == "revoke-partial":
        stable_proof_name(approval["migration_controls_commit"])


def load_journal(path):
    if not path.exists():
        return None
    REQUIRE(path.is_file() and not path.is_symlink() and not getattr(path, "is_junction", lambda: False)(),
            "Unreviewed WRITE journal file")
    return iam.foundation.decode(path.read_bytes())


def keep_record(path, value):
    existing = load_journal(path)
    if existing is None:
        iam.write_new(path, value)
    else:
        REQUIRE(existing == value, "WRITE journal differs from the recorded operation")


def reconcile_policies(changes, token, journal):
    """Classify every scope before requesting any policy write."""
    observed = {}
    for index, (target, (before, desired)) in enumerate(changes.items()):
        intent = load_journal(journal / f"{index}-intent.json")
        readback = load_journal(journal / f"{index}-readback.json")
        live = get_policy(target, token)
        expected = {"target": target, "before": before, "requested": desired}
        REQUIRE(intent is None or intent == expected, "Unknown WRITE transition intent")
        if readback is not None:
            iam.check_fields(readback, {"before", "after"})
            REQUIRE(intent and canonical_policy(target, readback["before"]) == canonical_policy(target, before)
                    and canonical_policy(target, readback["after"]) == canonical_policy(target, live),
                    "Current policy differs from the journal readback")
            verify_transition(target, before, live, desired)
            observed[target] = (readback["after"], True)
        elif canonical_policy(target, live) == canonical_policy(target, before):
            observed[target] = (live, False)
        else:
            REQUIRE(intent is not None, "Live policy differs without a matching transition intent")
            verify_transition(target, before, live, desired)
            observed[target] = (live, True)
    return observed


def transition_policies(changes, token, journal):
    observed = reconcile_policies(changes, token, journal)
    results = {}
    for index, (target, (before, desired)) in enumerate(changes.items()):
        live, completed = observed[target]
        if not completed:
            REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, live),
                    "WRITE policy changed after preflight")
            keep_record(journal / f"{index}-intent.json", {"target": target, "before": before, "requested": desired})
            response = set_policy(target, desired, token)
            live = get_policy(target, token)
            verify_transition(target, before, live, desired)
            REQUIRE(canonical_policy(target, response) == canonical_policy(target, live),
                    "WRITE response differs from policy readback")
        results[target] = {"before": before, "after": live}
        keep_record(journal / f"{index}-readback.json", results[target])
    for target, delta in results.items():
        REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, delta["after"]),
                "WRITE policy changed before saving the receipt")
    return results


def planned_migration(profile, temporal):
    changes = {}
    for target in POLICY_ENDPOINTS:
        spec = profile["policies"][target]
        archived = temporal["policies"][target]
        before = archived["after"]
        desired = requested_policy(target, archived["before"], spec["add_bindings"])
        changes[target] = before, {**desired, "etag": before["etag"]}
    return changes


def verify_backend_idle(*, migration):
    from scripts import db01_noble_plan, int_release_state
    driver = iam.driver
    bucket_path = "/b/" + iam.contract.BUCKET
    if migration:
        db01_noble_plan.current_origin(allow_successor=True)
        prefix = f"{iam.custody.PREFIX}{READ_PRODUCER}/44650537240-1/foundation-state.json"
        result = driver.metadata(bucket_path + "/o", {"prefix": prefix, "fields": "items(name),nextPageToken"})
        REQUIRE(not result.get("items") and not result.get("nextPageToken"), "An original Noble execution intent exists")
    else:
        bucket = driver.metadata(bucket_path, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
        int_release_state.private_current_state(bucket)


def store_receipt(receipt, journal):
    raw = iam.custody.canonical(receipt)
    name = stable_proof_name(receipt["controls_commit"])
    sha256 = iam.custody.sha256(raw)
    keep_record(journal / "stable-receipt.json", receipt)
    reference_path = journal / "stable-receipt-reference.json"
    reference = load_journal(reference_path)
    if reference is None:
        intent_path = journal / "upload-intent.json"
        prior_intent = load_journal(intent_path)
        keep_record(intent_path, {"name": name, "sha256": sha256})
        existing = []
        if prior_intent is not None:
            page = iam.driver.metadata("/b/" + iam.contract.BUCKET + "/o", {
                "prefix": name, "fields": "items(name,generation,size),nextPageToken",
            })
            existing = page.get("items", [])
            REQUIRE(not page.get("nextPageToken") and len(existing) <= 1, "Ambiguous stable WRITE receipt custody")
        if existing:
            obj = existing[0]
            reference = {"name": obj["name"], "generation": obj["generation"], "size": int(obj["size"]), "sha256": sha256}
        else:
            reference = iam.custody.upload(name, raw)
    verify_stable_reference(reference, receipt)
    REQUIRE(iam.custody.fetch_verified(reference) == raw, "Stable WRITE receipt readback differs")
    keep_record(reference_path, reference)
    return reference


def migrate(profile, temporal, read_proof, token, journal, controls):
    verify_temporal_receipt(profile, temporal, read_proof)
    changes = planned_migration(profile, temporal)
    policies = transition_policies(changes, token, journal)
    prior = load_journal(journal / "stable-receipt.json")
    receipt = {
        "schema": RECEIPT_SCHEMA, "controls_commit": controls, "profile_sha256": iam.digest(profile),
        "issued_utc": prior["issued_utc"] if prior else datetime.now(timezone.utc).isoformat(),
        "temporary_receipt": TEMPORAL_RECEIPT, "read_receipt": READ_RECEIPT, "policies": policies,
    }
    verify_stable_receipt(profile, receipt, temporal, read_proof)
    return store_receipt(receipt, journal)


def revoke(stable, temporal, token, journal):
    changes = {}
    for target in POLICY_ENDPOINTS:
        if target not in stable["policies"]:
            continue
        delta = stable["policies"][target]
        before = delta["after"]
        baseline = canonical_policy(target, temporal["policies"][target]["before"])
        changes[target] = before, {**baseline, "etag": before["etag"]}
    policies = transition_policies(changes, token, journal)
    keep_record(journal / "revocation-receipt.json", {"stable_issued_utc": stable["issued_utc"], "policies": policies})
    return policies


def revoke_partial(profile, temporal, approval, token, source, journal):
    """Revoke only a transition supported by the original journal and current etags."""
    source_approval = load_journal(source / "approval.json")
    verify_approval(source_approval, approval["migration_controls_commit"], iam.digest(profile))
    changes = planned_migration(profile, temporal)
    recorded = journal / "partial-source.json"
    partial = load_journal(recorded)
    if partial is None:
        observed = reconcile_policies(changes, token, source)
        partial = {"issued_utc": datetime.now(timezone.utc).isoformat(), "policies": {
            target: {"before": changes[target][0], "after": live}
            for target, (live, completed) in observed.items() if completed
        }}
        iam.write_new(recorded, partial)
    iam.check_fields(partial, {"issued_utc", "policies"})
    timestamp(partial["issued_utc"])
    REQUIRE(set(partial["policies"]) <= set(changes), "Unknown partial WRITE policy")
    for index, (target, (before, desired)) in enumerate(changes.items()):
        if target not in partial["policies"]:
            REQUIRE(canonical_policy(target, get_policy(target, token)) == canonical_policy(target, before),
                    "An untouched policy changed before partial revocation")
            continue
        policy = partial["policies"][target]
        iam.check_fields(policy, {"before", "after"})
        REQUIRE(load_journal(source / f"{index}-intent.json") == {"target": target, "before": before, "requested": desired}
                and policy["before"] == before, "Unknown partial WRITE intent")
        verify_transition(target, before, policy["after"], desired)
    return revoke(partial, temporal, token, journal)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("describe", "preflight", "migrate", "revoke", "revoke-partial"))
    parser.add_argument("--controls-commit")
    parser.add_argument("--profile-sha256")
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--source-journal", type=Path)
    args = parser.parse_args(argv)
    token = None
    phase = "verify_profile_and_approval"
    try:
        profile, digest = load_profile()
        if args.operation == "describe":
            print(json.dumps({"profile_sha256": digest, "mode": "stable", "bindings": 4}))
            return 0
        controls, journal = args.controls_commit, args.receipt_dir
        REQUIRE(digest == args.profile_sha256 and controls and journal, "Exact WRITE context required")
        stable_proof_name(controls)
        iam.verify_checkout(controls)
        iam.verify_receipt_location(journal)
        approval = None
        if args.operation == "revoke-partial":
            REQUIRE(args.source_journal is not None and args.source_journal.is_dir(), "Original private migration journal required")
            iam.verify_receipt_location(args.source_journal)
            REQUIRE(args.source_journal.resolve() != journal.resolve(), "Partial revocation requires a separate journal")
        else:
            REQUIRE(args.source_journal is None, "The source journal is only used for partial revocation")
        if args.operation != "preflight":
            REQUIRE(args.approval is not None and args.approval.is_file(), "Private owner approval is required")
            iam.verify_receipt_location(args.approval)
            approval = iam.foundation.decode(args.approval.read_bytes())
            verify_approval(approval, controls, digest, args.operation)
        phase = "authenticate_administrator"
        token = iam.admin_token()
        os.environ["GCP_ACCESS_TOKEN"] = token
        phase = "verify_read_and_temporal_receipts"
        read_profile, read_proof, _, _ = load_read_chain()
        temporal = iam.foundation.decode(iam.custody.fetch_verified(TEMPORAL_RECEIPT))
        verify_temporal_receipt(profile, temporal, read_proof)
        phase = "verify_roles_and_live_policies"
        verify_roles(profile["roles"], token)
        verify_unaffected_read(read_profile, read_proof, token)
        migration = args.operation in {"preflight", "migrate"}
        observed = reconcile_policies(planned_migration(profile, temporal), token, journal) if migration else {}
        pending = any(not completed for _, completed in observed.values())
        phase = "verify_idle_backend"
        if not migration or pending or load_journal(journal / "stable-receipt-reference.json") is None:
            verify_backend_idle(migration=pending)
        if args.operation == "preflight":
            result = {"status": "preflight_verified", "policies": len(observed),
                      "already_migrated": sum(completed for _, completed in observed.values())}
        else:
            journal.mkdir(mode=0o700, exist_ok=True)
            keep_record(journal / "approval.json", approval)
            if args.operation == "migrate":
                phase = "migrate_policies_and_verify_receipt"
                reference = migrate(profile, temporal, read_proof, token, journal, controls)
                result = {"status": "stable_write_verified", "reference": reference}
            elif args.operation == "revoke":
                phase = "verify_stable_receipt_and_revoke"
                reference = approval["stable_receipt"]
                stable = iam.foundation.decode(iam.custody.fetch_verified(reference))
                verify_stable_reference(reference, stable)
                verify_stable_receipt(profile, stable, temporal, read_proof)
                policies = revoke(stable, temporal, token, journal)
                result = {"status": "stable_write_revoked", "policies": len(policies)}
            else:
                phase = "verify_partial_journal_and_revoke"
                policies = revoke_partial(profile, temporal, approval, token, args.source_journal, journal)
                result = {"status": "partial_write_revoked", "policies": len(policies)}
        print(json.dumps(result))
        return 0
    except Exception as error:
        result = {"status": "blocked", "operation": args.operation, "phase": phase, "error_type": type(error).__name__}
        if isinstance(error, iam.CloudError):
            result["http_status"] = error.status
        print(json.dumps(result))
        return 1
    finally:
        if token is not None:
            os.environ.pop("GCP_ACCESS_TOKEN", None)


if __name__ == "__main__":
    raise SystemExit(main())
