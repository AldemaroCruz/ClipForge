"""Continue only the verified partial INT Demo A before_bootstrap IAM delta."""

import argparse
import json
from pathlib import Path
import re

from scripts import int_demo_a_iam as delta


iam = delta.iam
require = delta.require
PHASE = "before_bootstrap"
ACCOUNT, INSTANCE = (delta.NOBLE[name] for name in ("account", "instance"))
FULL_INSTANCE = "//compute.googleapis.com/" + INSTANCE.rsplit("/", 1)[0] + "/7365414160255801909"
ORIGINAL_COMMIT = "92d0320332b17756da5dca17a21b93a31b405951"
ORIGINAL_ID = "c2624656789148d39466c2d6e3e41755"
ORIGINAL_RESULT = "d4a26e3d549abb2c3c749df1cff8d23d0c314cb2ec0ff9f68054e12afd26b40e"
SCHEMA = "clipforge-int-demo-a-iam-resume-owner-decision-1"
ORIGIN_FILES = {"initial.json", "result.json", "policy-0.intent.json", "policy-0.response.json", "policy-1.intent.json",
                *(f"role-{index}.intent.json" for index in range(3))}


def request_with_diagnostic(url, token, method="GET", body=None):
    return iam.request_json(url, token, method, body, retain_error=True)


def read_document(path):
    raw = delta.private_document(path)
    value = delta.host.closed_json(raw)
    require(isinstance(value, dict), "resume_private_object_required")
    return raw, value


def validate_authority(value, commit, controller_sha):
    iam.check_fields(value, {"schema", "operation", "phase", "operation_id", "controls_commit", "controller_sha256", "profile_sha256",
                             "owner", "approval_ref", "valid_from", "expires_at", "original_commit", "original_operation_id",
                             "original_result_sha256", "reconciliation_sha256"})
    require(value["schema"] == SCHEMA and value["operation"] == "continue" and value["phase"] == PHASE
            and value["controls_commit"] == commit and iam.valid_digest(controller_sha) and value["controller_sha256"] == controller_sha
            and value["profile_sha256"] == delta.PROFILE_SHA and value["owner"] == iam.ADMIN
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and value["operation_id"] != ORIGINAL_ID
            and isinstance(value["approval_ref"], str) and 1 <= len(value["approval_ref"].strip()) <= 500
            and value["original_commit"] == ORIGINAL_COMMIT and value["original_operation_id"] == ORIGINAL_ID
            and value["original_result_sha256"] == ORIGINAL_RESULT and iam.valid_digest(value["reconciliation_sha256"]),
            "resume_exact_authority_required")
    delta.valid_now(value)
    return value


def requested_state(item, observed):
    return observed["etag"] != item["before"]["etag"] and iam.semantic(observed) == iam.semantic(item["requested"])


def verify_original_summary(changes, original, reconciliation, authority):
    roles = delta.roles_for(changes)
    created = {name for name, spec in roles.items() if spec["mode"] == "create"}
    pending = {"operation": "setIamPolicy", "resource": INSTANCE}
    require(original["schema"] == delta.RESULT_SCHEMA and original["status"] == "indeterminate_reconciliation_required"
            and original["phase"] == PHASE and original["operation"] == "apply" and original["controls_commit"] == ORIGINAL_COMMIT
            and original["primary_error"] == "http_400" and original["pending"] == pending
            and len(original["roles_created"]) == 3 and set(original["roles_created"]) == created
            and set(original["policies"]) == {ACCOUNT}, "resume_original_result_scope")
    account = original["policies"][ACCOUNT]
    require(account["before"] == changes[ACCOUNT]["before"] and requested_state(changes[ACCOUNT], account["after"]),
            "resume_original_account_effect")
    require(reconciliation["operation_id"] == authority["original_operation_id"] == ORIGINAL_ID
            and reconciliation["commit"] == ORIGINAL_COMMIT and reconciliation["status"] == original["status"]
            and reconciliation["pending"] == pending and reconciliation["primary_error"] == original["primary_error"]
            and reconciliation["approval_sha256_canonical"] == original["approval_sha256"]
            and reconciliation["files"]["result.json"]["sha256"] == authority["original_result_sha256"] == ORIGINAL_RESULT,
            "resume_original_reconciliation_binding")
    observed_roles = {row["name"]: row for row in reconciliation["reconciled_roles"]}
    require(len(reconciliation["reconciled_roles"]) == len(roles) and set(observed_roles) == set(roles)
            and all(row == {"name": name, "expected_mode": roles[name]["mode"],
                            "journal_verified": name in created, "observed": "exact_present"}
                    for name, row in observed_roles.items()), "resume_original_role_readbacks")
    policies = {row["resource"]: row for row in reconciliation["reconciled_policies"]}
    require(len(reconciliation["reconciled_policies"]) == len(changes) and set(policies) == set(changes),
            "resume_original_policy_readback_set")
    for name, item in changes.items():
        observed = account["after"] if name == ACCOUNT else item["before"]
        status = "exact_requested_delta_with_verified_journal" if name == ACCOUNT else "exact_baseline"
        row = {"resource": name, "role": item["binding"]["role"], "principal": item["binding"]["members"][0],
               "condition": item["binding"].get("condition"), "baseline_etag": item["before"]["etag"],
               "observed": status, "live_etag": observed["etag"], "live_policy_sha256": iam.digest(observed)}
        require(policies[name] == row, "resume_original_policy_readback_changed")


def history(profile, directory, authority):
    original_journal = directory / ORIGINAL_ID
    require(original_journal.is_dir() and not original_journal.is_symlink()
            and {path.name for path in original_journal.iterdir()} == ORIGIN_FILES, "resume_original_journal_scope")
    reconciliation_raw, reconciliation = read_document(directory / "reconciliation.json")
    require(delta.sha(reconciliation_raw) == authority["reconciliation_sha256"]
            and reconciliation["custody"] == str(original_journal) and set(reconciliation["files"]) == ORIGIN_FILES,
            "resume_original_custody_changed")
    documents = {}
    for name, reference in reconciliation["files"].items():
        raw, documents[name] = read_document(original_journal / name)
        require(reference == {"bytes": len(raw), "sha256": delta.sha(raw)}, "resume_original_journal_bytes_changed")
    _, approver = read_document(directory / "owner-decision.json")
    original = documents["result.json"]
    changes = delta.targets(profile, PHASE)
    require(delta.load_profile(delta.private_document(directory / "profile.json")) == profile
            and approver["operation_id"] == ORIGINAL_ID and approver["controls_commit"] == ORIGINAL_COMMIT
            and original["approval_sha256"] == iam.digest(approver)
            and documents["initial.json"] == {"authority": approver, "policies": changes}, "resume_original_decision_changed")
    for index, name in enumerate(original["roles_created"]):
        require(documents[f"role-{index}.intent.json"] == {"operation": "createRole", "resource": name},
                "resume_original_role_intent_changed")
    for index, resource in enumerate((ACCOUNT, INSTANCE)):
        require(documents[f"policy-{index}.intent.json"] == {"operation": "setIamPolicy", "resource": resource, **changes[resource]},
                "resume_original_policy_intent_changed")
    require(delta.canonical_policy(ACCOUNT, documents["policy-0.response.json"]) == original["policies"][ACCOUNT]["after"],
            "resume_original_account_response_changed")
    verify_original_summary(changes, original, reconciliation, authority)
    source = {"operation_id": ORIGINAL_ID, "controls_commit": ORIGINAL_COMMIT, "custody": str(original_journal),
              "result_sha256": ORIGINAL_RESULT, "reconciliation_sha256": delta.sha(reconciliation_raw),
              "receipts": reconciliation["files"]}
    return original, reconciliation, source


def prepare_live(changes, original, token, request):
    live = {}
    checks = []
    for name, item in changes.items():
        try:
            current = delta.read_policy(name, token, request)
            acceptable = (current == original["policies"][ACCOUNT]["after"] if name == ACCOUNT
                          else current == item["before"] or requested_state(item, current))
            require(acceptable, "resume_unattributed_full_policy_or_etag_drift")
            live[name] = current
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            checks.append({"operation": "getIamPolicy", "resource": name, "reason": delta.safe_error(error)})
    # Retain the existing identity, bucket, role-definition and policy readbacks.
    # A second policy read must match this capture exactly, including the etag.
    stable = {name: {**item, "before": live.get(name, item["before"])} for name, item in changes.items()}
    checks.extend(delta.preflight(stable, token, request, withdrawing=True))
    return live, checks


def grantable_compute(role, token, request):
    query = {"fullResourceName": FULL_INSTANCE, "view": "BASIC", "pageSize": 300}
    pages, cursors, matches = [], set(), []
    for _ in range(12):
        response = request("https://iam.googleapis.com/v1/roles:queryGrantableRoles", token, "POST", dict(query))
        rows = response.get("roles", [])
        require(isinstance(rows, list) and len(rows) <= 300, "resume_grantability_page_shape")
        pages.append({"roles": len(rows), "response_sha256": iam.digest(response)})
        matches.extend(row for row in rows if row["name"] == role)
        cursor = response.get("nextPageToken", "")
        if not cursor:
            require(len(matches) <= 1, "resume_grantability_duplicate_role")
            return {"resource": FULL_INSTANCE, "role": role, "pages": pages,
                    "matching_role": matches[0] if matches else None}
        require(isinstance(cursor, str) and cursor not in cursors, "resume_grantability_pagination")
        cursors.add(cursor)
        query["pageToken"] = cursor
    raise ValueError("resume_grantability_page_bound")


def read_after_interruption(changes, live, report, token, request):
    readbacks = {}
    for name, item in changes.items():
        try:
            observed = delta.read_policy(name, token, request)
            if observed == report["policies"].get(name, {}).get("after"):
                state = "verified_effect_exact"
            elif observed == live[name]:
                state = "preflight_policy_exact"
            elif name != ACCOUNT and requested_state(item, observed):
                state = "requested_effect_observed_unattributed"
            else:
                state = "unattributed_policy_or_etag"
            readbacks[name] = {"status": state, "policy": observed}
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            readbacks[name] = {"status": "read_failed", "reason": delta.safe_error(error)}
    return readbacks


def continue_changes(profile, original, reconciliation, authority, token, journal, *,
                     request=request_with_diagnostic, enforce_time=delta.valid_now):
    changes = delta.targets(profile, PHASE)
    report = {"schema": delta.RESULT_SCHEMA, "status": "blocked", "controls_commit": authority["controls_commit"],
              "approval_sha256": iam.digest(authority), "phase": PHASE, "operation": "continue",
              "operation_id": authority["operation_id"], "original_operation_id": authority["original_operation_id"],
              "roles_created": [], "policies": {}, "policy_actions": {}, "pending": None}
    live = {}
    stage = {"operation": "preflight"}
    try:
        verify_original_summary(changes, original, reconciliation, authority)
        enforce_time(authority)
        live, checks = prepare_live(changes, original, token, request)
        iam.write_new(journal / "preflight.json", {"live": live, "checks": checks})
        if checks:
            report["checks"] = checks
        require(not checks, "resume_preflight_blocked")
        stage = {"operation": "queryGrantableRoles", "resource": INSTANCE}
        grantability = grantable_compute(changes[INSTANCE]["binding"]["role"], token, request)
        iam.write_new(journal / "compute-grantable.json", grantability)
        require(grantability["matching_role"] is not None, "resume_compute_role_not_grantable")
        for index, (name, item) in enumerate(changes.items()):
            enforce_time(authority)
            stage = {"operation": "getIamPolicy", "resource": name}
            require(delta.read_policy(name, token, request) == live[name], "resume_policy_changed_after_preflight")
            if name == ACCOUNT or requested_state(item, live[name]):
                report["policies"][name] = {"before": item["before"], "after": live[name]}
                report["policy_actions"][name] = "preserved_original" if name == ACCOUNT else "already_exact"
                continue
            stage = {"operation": "getRole", "resource": item["binding"]["role"]}
            delta.role_definition(item["binding"]["role"], item["roles"], token, request, absent=False)
            stage = {"operation": "setIamPolicy", "resource": name}
            desired = {**item["requested"], "etag": live[name]["etag"]}
            iam.write_new(journal / f"policy-{index}.intent.json", {**stage, "before": live[name], "requested": desired})
            enforce_time(authority)
            report["pending"] = dict(stage)
            reply = delta.write_policy(name, desired, token, request)
            iam.write_new(journal / f"policy-{index}.response.json", reply)
            stage = {"operation": "getIamPolicy", "resource": name}
            after = delta.read_policy(name, token, request)
            require(isinstance(reply, dict) and reply.get("etag") == after["etag"] and requested_state(item, after),
                    "resume_unreconciled_write_response")
            report["policies"][name] = {"before": item["before"], "after": after}
            report["policy_actions"][name] = "written_and_verified"
            report["pending"] = None
        for name, pair in report["policies"].items():
            stage = {"operation": "getIamPolicy", "resource": name}
            require(delta.read_policy(name, token, request) == pair["after"], "resume_final_policy_drift")
        report["status"] = "applied_and_verified"
    except (OSError, ValueError, KeyError, TypeError, AttributeError, KeyboardInterrupt) as error:
        report["primary_error"] = delta.safe_error(error)
        report["failed_operation"] = stage
        reject = isinstance(error, iam.CloudError) and stage["operation"] == "setIamPolicy"
        if reject:
            report["rejection"] = {**stage, "http_status": error.status, "body": error.diagnostic}
            try:
                iam.write_new(journal / "write-rejection.json", report["rejection"])
            except OSError as record_error:
                report["secondary_error"] = delta.safe_error(record_error)
        if report["pending"] or "written_and_verified" in report["policy_actions"].values():
            report["reconciled_policies"] = read_after_interruption(changes, live, report, token, request)
            report["status"] = "indeterminate_reconciliation_required"
            explicit_rejection = reject and 400 <= error.status < 500 and error.status not in {408, 429}
            if explicit_rejection and all(row["status"] in {"verified_effect_exact", "preflight_policy_exact"}
                                          for row in report["reconciled_policies"].values()):
                report["status"] = "rejected_reconciled"
    return report


def keep_final_receipts(journal, result, changes, authority, source):
    require(result["status"] == "applied_and_verified" and result["pending"] is None and set(result["policies"]) == set(changes),
            "resume_full_final_readbacks_required")
    deploy = delta.noble_receipt(result, changes)
    native = delta.native_receipt(result, changes, authority["controls_commit"])
    references = {}
    for name, document in (("deploy-policy-receipt.json", deploy), ("native-iam-receipt.json", native)):
        path = journal / name
        delta.keep_receipt(path, document)
        raw, checked = read_document(path)
        require(checked == document, "resume_private_receipt_readback_drift")
        references[name] = {"bytes": len(raw), "sha256": delta.sha(raw)}
    raw, checked = read_document(journal / "result.json")
    require(checked == result, "resume_private_result_readback_drift")
    references["result.json"] = {"bytes": len(raw), "sha256": delta.sha(raw)}
    record = {"schema": "clipforge-int-demo-a-iam-continuation-receipt-1", "status": result["status"], "original": source,
              "operation_id": authority["operation_id"], "controls_commit": authority["controls_commit"],
              "controller_sha256": authority["controller_sha256"], "profile_sha256": delta.PROFILE_SHA,
              "approval_sha256": result["approval_sha256"], "receipts": references, "policy_actions": result["policy_actions"],
              "final_etags": {name: pair["after"]["etag"] for name, pair in result["policies"].items()}}
    path = journal / "continuation-receipt.json"
    delta.keep_receipt(path, record)
    raw, checked = read_document(path)
    require(checked == record, "resume_private_continuation_readback_drift")
    return {**references, path.name: {"bytes": len(raw), "sha256": delta.sha(raw)}}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("review", "continue"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--commit", required=True)
    parser.add_argument("--approval", required=True, type=Path)
    parser.add_argument("--original", required=True, type=Path)
    parser.add_argument("--journal", type=Path)
    args = parser.parse_args(argv)
    result = None
    try:
        iam.verify_checkout(args.commit)
        profile = delta.load_profile(delta.private_document(args.profile))
        _, approval = read_document(args.approval)
        authority = validate_authority(approval, args.commit, delta.sha(Path(__file__).read_bytes()))
        original, reconciliation, source = history(profile, args.original, authority)
        if args.command == "review":
            print(json.dumps({"status": "original_custody_verified", "original": source, "phase": PHASE}))
            return 0
        journal = args.journal
        require(journal is not None and journal.name == authority["operation_id"], "resume_new_operation_journal_required")
        iam.verify_receipt_location(journal)
        require(not journal.is_relative_to(args.original), "resume_journal_must_be_separate")
        journal.mkdir(mode=0o700)
        iam.write_new(journal / "continuation-source.json", {"original": source, "approval": authority})
        token = iam.admin_token()
        result = continue_changes(profile, original, reconciliation, authority, token, journal)
        delta.keep_receipt(journal / "result.json", result)
        public = {key: result.get(key) for key in ("status", "primary_error", "failed_operation", "operation_id", "policy_actions")}
        if result["status"] == "applied_and_verified":
            public["receipts"] = keep_final_receipts(journal, result, delta.targets(profile, PHASE), authority, source)
        print(json.dumps(public))
        return int(result["status"] != "applied_and_verified")
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        public = {"status": "blocked", "error": delta.safe_error(error)}
        if result is not None:
            public.update(operation_status=result["status"], primary_error=result.get("primary_error"))
        print(json.dumps(public))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
