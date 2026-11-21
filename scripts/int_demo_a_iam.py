"""Review and execute only the administrator-owned IAM delta of INT Demo A."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re

from scripts import int_db01_noble_read_iam as iam
from scripts import int_demo_a_native as native
from scripts import int_demo_a_noble_policy as noble
from scripts import int_demo_a_plan_scope as scope
from scripts import int_demo_a_receipts as receipts
from scripts import int_noble_hostkey as host
from scripts import int_noble_write_iam as writer


PROJECT = "clipforgebeta2"
IAP = native.IAP_PATH
SECRETS = tuple(sorted(native.SECRET_POLICY_NAMES))
BUCKET = f"projects/_/buckets/{receipts.BUCKET}"
STORAGE = f"https://storage.googleapis.com/storage/v1/b/{receipts.BUCKET}"
NOBLE = {"account": noble.ACCOUNT,
         "instance": f"projects/{PROJECT}/zones/us-central1-a/instances/clipforge-int-db01-noble",
         "tunnel": "projects/816643438938/iap_tunnel/zones/us-central1-a/instances/7365414160255801909"}
BEFORE = tuple(NOBLE.values()) + (BUCKET, *SECRETS)
PHASES = {"before_bootstrap": BEFORE, "after_protected_service": (IAP,)}
PROFILE_SHA = "e132c0099538142124efd799e74b34ef392b310b9c29dd34d40f0f865f241102"
APPROVAL_SCHEMA = "clipforge-int-demo-a-iam-owner-decision-1"
RESULT_SCHEMA = "clipforge-int-demo-a-iam-admin-result-1"
require = noble.require
policy = noble.canonical
sha = iam.custody.sha256


def load_profile(raw):
    value = host.closed_json(raw)
    require(iam.digest(value) == PROFILE_SHA, "exact_reviewed_demo_a_iam_profile_required")
    return value


def canonical_policy(resource, raw):
    require(isinstance(raw, dict), "unexpected_iam_policy_response")
    if resource == BUCKET:
        require(raw.get("kind") == "storage#policy" and raw.get("resourceId") == BUCKET, "bucket_policy_resource_changed")
        raw = {key: item for key, item in raw.items() if key not in ("kind", "resourceId")}
    return policy(raw)


def targets(profile, phase, iap_before=None):
    require(phase in PHASES, "invalid_iam_phase")
    rows = profile["before_bootstrap"]
    if phase == "after_protected_service":
        before = policy(iap_before)
        require(before["bindings"] == [], "iap_service_policy_is_not_empty")
        rows = [{"resource": IAP, "before": before, "add_binding": profile[phase]["binding"]}]
    result = {}
    for row in rows:
        resource, binding = row["resource"], row["add_binding"]
        before = canonical_policy(resource, row["before"])
        after = policy({**before, "bindings": [*before["bindings"], binding]})
        if "after_semantic" in row:
            require(iam.semantic(after) == iam.semantic(policy({**row["after_semantic"], "etag": before["etag"]})),
                    "reviewed_iam_after_differs")
        result[resource] = {"before": before, "requested": after, "roles": profile["roles"][binding["role"]], "binding": binding}
    require(set(result) == set(PHASES[phase]), "iam_scope_targets_changed")
    return result


def read_policy(resource, token, request):
    if resource in NOBLE.values():
        method, url, body = noble.ROUTES[next(key for key, route in NOBLE.items() if route == resource)]
    elif resource == BUCKET:
        method, url, body = "GET", STORAGE + "/iam?optionsRequestedPolicyVersion=3", None
    elif resource in SECRETS:
        method, url, body = "GET", f"https://secretmanager.googleapis.com/v1/{resource}:getIamPolicy?options.requestedPolicyVersion=3", None
    else:
        require(resource == IAP, "iam_scope_target")
        method, url, body = "POST", native.IAP_API + ":getIamPolicy", {"options": {"requestedPolicyVersion": 3}}
    return canonical_policy(resource, request(url, token, method, body))


def write_policy(resource, value, token, request):
    body = {"policy": value}
    if resource == BUCKET:
        return request(STORAGE + "/iam", token, "PUT", value)
    if resource == NOBLE["instance"]:
        url = noble.ROUTES["instance"][1].split("/getIamPolicy", 1)[0] + "/setIamPolicy"
    elif resource == NOBLE["account"]:
        url = f"https://iam.googleapis.com/v1/{resource}:setIamPolicy"
        body["updateMask"] = "bindings,etag"
    elif resource in SECRETS:
        url = f"https://secretmanager.googleapis.com/v1/{resource}:setIamPolicy"
        body["updateMask"] = "bindings,etag"
    else:
        require(resource in (NOBLE["tunnel"], IAP), "iam_scope_target")
        url = f"https://iap.googleapis.com/v1/{resource}:setIamPolicy"
    return request(url, token, "POST", body)


def role_definition(role, spec, token, request, *, absent):
    try:
        current = request("https://iam.googleapis.com/v1/" + role, token)
    except iam.CloudError as error:
        if absent and error.status == 404:
            return
        raise
    require(not absent, "iam_new_role_already_exists")
    iam.check_role_definition(role, current, spec)


def roles_for(changes):
    return {item["binding"]["role"]: item["roles"] for item in changes.values()}


def preflight(changes, token, request, *, withdrawing=False):
    checks = []
    for member in sorted({item["binding"]["members"][0] for item in changes.values()}):
        email = member.removeprefix("serviceAccount:")
        try:
            account = request(f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/{email}", token)
            require(account.get("email") == email and account.get("projectId") == PROJECT
                    and account.get("disabled", False) is False, "iam_recipient_not_active")
        except (iam.CloudError, ValueError) as error:
            checks.append({"operation": "getServiceAccount", "resource": email, "reason": safe_error(error)})
    if BUCKET in changes:
        try:
            bucket = request(STORAGE + "?fields=name%2CprojectNumber%2CiamConfiguration%28uniformBucketLevelAccess%29", token)
            require(bucket.get("name") == receipts.BUCKET and str(bucket.get("projectNumber")) == "816643438938"
                    and bucket.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled") is True,
                    "demo_a_bucket_uniform_access_required")
        except (iam.CloudError, ValueError) as error:
            checks.append({"operation": "getBucket", "resource": BUCKET, "reason": safe_error(error)})
    for role, spec in roles_for(changes).items():
        try:
            role_definition(role, spec, token, request, absent=not withdrawing and spec["mode"] != "reuse")
        except (iam.CloudError, ValueError) as error:
            checks.append({"operation": "getRole", "resource": role, "reason": safe_error(error)})
    for resource, pair in changes.items():
        try:
            require(read_policy(resource, token, request) == pair["before"], "full_policy_or_etag_drift")
        except (iam.CloudError, ValueError) as error:
            checks.append({"operation": "getIamPolicy", "resource": resource, "reason": safe_error(error)})
    return checks


def valid_now(approval, now=None):
    now = now or datetime.now(timezone.utc)
    start, until = (datetime.fromisoformat(approval[key]) for key in ("valid_from", "expires_at"))
    require(start.utcoffset() == until.utcoffset() == timezone.utc.utcoffset(now) and start <= now < until,
            "iam_decision_not_current")


def authority(value, commit, command):
    iam.check_fields(value, {"schema", "operation", "phase", "operation_id", "controls_commit", "profile_sha256",
                             "owner", "approval_ref", "valid_from", "expires_at", "protected_apply", "iap_before",
                             "prerequisites_sha256", "withdraw_from"})
    phase = value["phase"]
    require(value["schema"] == APPROVAL_SCHEMA and value["controls_commit"] == commit and value["profile_sha256"] == PROFILE_SHA
            and value["owner"] == iam.ADMIN and phase in PHASES and value["operation"] in {"apply", "withdraw"}
            and (command == "preflight" or command == value["operation"])
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and isinstance(value["approval_ref"], str)
            and 1 <= len(value["approval_ref"].strip()) <= 500 and re.fullmatch(r"[a-f0-9]{40}", commit), "exact_iam_authority_required")
    require((phase == "after_protected_service") == (value["protected_apply"] is not None and value["iap_before"] is not None)
            and (phase == "after_protected_service" or value["protected_apply"] is value["iap_before"] is None)
            and ((phase == "after_protected_service" and value["operation"] == "apply") == iam.valid_digest(value["prerequisites_sha256"]))
            and ((value["operation"] == "withdraw") == iam.valid_digest(value["withdraw_from"])), "iam_authority_phase_binding")
    valid_now(value)
    return value


def verify_protected_service(commit, reference, raw, token, read_run, read_service):
    """Bind the IAP writer to a completed protected apply and the same private runtime."""
    ref = native.reference(reference, suffix="manifest.json")
    prior = host.closed_json(raw)
    scope.phase_state(scope.HUMAN_ACCESS, prior)
    run = str(prior.get("run", ""))
    require(re.fullmatch(receipts.RUN, run) and prior.get("schema") == "clipforge-int-demo-a-result-2"
            and prior.get("phase") == "apply" and prior.get("controls_commit") == commit
            and ref["name"] == f"{iam.custody.PREFIX}{commit}/{run}-1/manifest.json"
            and len(raw) == ref["size"] and sha(raw) == ref["sha256"] == scope.phase_receipt_sha(prior),
            "iam_protected_apply_receipt_changed")
    expected = {"id": int(run), "run_attempt": 1, "status": "completed", "conclusion": "success", "head_sha": commit,
                "head_branch": native.BRANCH, "event": "workflow_dispatch", "path": native.WORKFLOWS["apply"]}
    current = read_run(run)
    require(all(current.get(key) == item for key, item in expected.items()), "iam_protected_apply_run_changed")
    require(read_service(scope.PROTECTED_RUNTIME, None, token) == prior["run_service"], "iam_protected_service_identity_changed")
    return prior


def safe_error(error):
    if isinstance(error, iam.CloudError):
        return f"http_{error.status}"
    value = str(error)
    return value if re.fullmatch(r"[a-z_]{1,96}", value) else type(error).__name__


def run_changes(changes, approval, token, directory, *, request=iam.request_json, enforce_time=valid_now, service_check=None):
    """Keep intent before each mutation, require immediate CAS/readback and never retry writes."""
    withdrawing = approval["operation"] == "withdraw"
    report = {"schema": RESULT_SCHEMA, "status": "blocked", "controls_commit": approval["controls_commit"],
              "approval_sha256": iam.digest(approval), "phase": approval["phase"], "operation": approval["operation"],
              "roles_created": [], "policies": {}, "pending": None}
    try:
        checks = preflight(changes, token, request, withdrawing=withdrawing)
        if checks:
            report["checks"] = checks
        require(not checks, "demo_a_iam_preflight_blocked")
        iam.write_new(directory / "initial.json", {"authority": approval, "policies": changes})
        if not withdrawing:
            for role, spec in roles_for(changes).items():
                if spec["mode"] == "reuse":
                    continue
                enforce_time(approval)
                role_definition(role, spec, token, request, absent=True)
                report["pending"] = {"operation": "createRole", "resource": role}
                iam.write_new(directory / f"role-{len(report['roles_created'])}.intent.json", report["pending"])
                enforce_time(approval)
                current = request(f"https://iam.googleapis.com/v1/projects/{PROJECT}/roles", token, "POST",
                                  {"roleId": role.rsplit("/", 1)[1], "role": spec["definition"]})
                iam.check_role_definition(role, current, spec)
                role_definition(role, spec, token, request, absent=False)
                report["roles_created"].append(role)
                report["pending"] = None
        for index, (resource, pair) in enumerate(changes.items()):
            enforce_time(approval)
            if service_check:
                service_check()
            role_definition(pair["binding"]["role"], pair["roles"], token, request, absent=False)
            require(read_policy(resource, token, request) == pair["before"], "full_policy_or_etag_drift")
            report["pending"] = {"operation": "setIamPolicy", "resource": resource}
            iam.write_new(directory / f"policy-{index}.intent.json", {**report["pending"], **pair})
            enforce_time(approval)
            reply = write_policy(resource, pair["requested"], token, request)
            iam.write_new(directory / f"policy-{index}.response.json", reply)
            require(isinstance(reply, dict), "unexpected_iam_write_response")
            live = read_policy(resource, token, request)
            require(live["etag"] != pair["before"]["etag"] and reply.get("etag") == live["etag"]
                    and iam.semantic(live) == iam.semantic(pair["requested"]), "unreconciled_iam_postcheck")
            report["policies"][resource] = {"before": pair["before"], "after": live}
            report["pending"] = None
        for resource, pair in report["policies"].items():
            require(read_policy(resource, token, request) == pair["after"], "iam_final_policy_drift")
        if service_check:
            service_check()
        report["status"] = "withdrawn_and_verified" if withdrawing else "applied_and_verified"
    except (OSError, KeyError, TypeError, AttributeError, ValueError, KeyboardInterrupt) as error:
        report["primary_error"] = safe_error(error)
        if report["pending"]:
            report["status"] = "indeterminate_reconciliation_required"
    return report


def withdraw_changes(changes, approval, source):
    require(isinstance(source, dict) and iam.digest(source) == approval["withdraw_from"] and source.get("schema") == RESULT_SCHEMA
            and source.get("operation") == "apply" and source.get("phase") == approval["phase"]
            and source.get("controls_commit") == approval["controls_commit"] and source.get("pending") is None
            and source.get("status") in {"applied_and_verified", "blocked"}, "iam_withdraw_source_unreconciled")
    require(bool(source["policies"]) and set(source["policies"]) <= set(changes), "no_verified_own_iam_writes")
    result = {}
    for resource, pair in source["policies"].items():
        item = changes[resource]
        require(policy(pair["before"]) == item["before"], "iam_withdraw_baseline_changed")
        live = policy(pair["after"])
        iam.check_policy_delta(item["before"], live, [item["binding"]])
        result[resource] = {**item, "before": live, "requested": {**item["before"], "etag": live["etag"]}}
    return result


def noble_receipt(result, changes):
    require(result["status"] == "applied_and_verified" and result["phase"] == "before_bootstrap", "iam_noble_receipt_unverified")
    return {"schema": "clipforge-int-demo-a-noble-policy-receipt-2", "status": result["status"],
            "approval_sha256": result["approval_sha256"], "policies": {key: {
                **result["policies"][resource], "role": changes[resource]["binding"]["role"],
                "role_definition": changes[resource]["roles"]["definition"],
            } for key, resource in NOBLE.items()}}


def native_receipt(prerequisites, changes, commit, protected_ref=None, protected=None, iap_result=None):
    require(prerequisites["controls_commit"] == commit, "iam_prerequisite_commit_changed")
    initial = protected_ref is protected is iap_result is None
    iap = None
    if not initial:
        require(protected_ref is not None and isinstance(protected, dict) and isinstance(iap_result, dict)
                and iap_result["status"] == "applied_and_verified" and iap_result["phase"] == "after_protected_service"
                and iap_result["controls_commit"] == commit and protected["controls_commit"] == commit,
                "iap_policy_receipt_unverified")
        iap = iap_result["policies"][IAP]
    deployment = scope.PROTECTED_RUNTIME if initial else scope.HUMAN_ACCESS
    return {"schema": "clipforge-int-demo-a-native-iam-receipt-1", "controls_commit": commit, "deployment_phase": deployment,
            "backend_generation": scope.phase_state(deployment, protected)["generation"], "read_receipt": writer.READ_RECEIPT,
            "protected_runtime_apply": protected_ref, "noble_policies": noble_receipt(prerequisites, changes),
            "secret_policies": {resource: prerequisites["policies"][resource] for resource in SECRETS}, "iap_policy": iap}


def private_document(path):
    require(isinstance(path, Path), "private_iam_document_required")
    iam.verify_receipt_location(path)
    require(path.is_file() and 0 < path.stat().st_size < receipts.LIMIT, "private_iam_document_unavailable")
    return path.read_bytes()


def github_run(run):
    return host.closed_json(iam.run_local(["gh", "api", f"repos/{native.REPOSITORY}/actions/runs/{run}"]).encode("utf-8"))


def keep_receipt(path, receipt):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(iam.custody.canonical(receipt))
        stream.flush()
        os.fsync(stream.fileno())


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("review", "preflight", "apply", "withdraw"))
    parser.add_argument("--profile", required=True, type=Path)
    parser.add_argument("--commit")
    parser.add_argument("--approval", type=Path)
    parser.add_argument("--journal", type=Path)
    parser.add_argument("--prior-result", type=Path)
    args = parser.parse_args(argv)
    try:
        profile = load_profile(args.profile.read_bytes())
        original_changes = targets(profile, "before_bootstrap")
        if args.command == "review":
            print(json.dumps({"status": "review_only", "profile_sha256": PROFILE_SHA, "targets": {k: list(v) for k, v in PHASES.items()}}))
            return 0
        iam.verify_checkout(args.commit)
        decision = authority(host.closed_json(private_document(args.approval)), args.commit, args.command)
        phase = decision["phase"]
        token = iam.admin_token()
        protected = gate = None
        if phase == "after_protected_service":
            ref = decision["protected_apply"]
            native.reference(ref, suffix="manifest.json")
            raw = iam.custody.fetch_verified(ref, token=token)
            protected = verify_protected_service(args.commit, ref, raw, token, github_run, native.verify_live_iap)
            def gate():
                require(native.verify_live_iap(scope.PROTECTED_RUNTIME, None, token) == protected["run_service"],
                        "iam_protected_service_identity_changed")
        changes = targets(profile, phase, decision["iap_before"])
        withdrawing = decision["operation"] == "withdraw"
        prior = host.closed_json(private_document(args.prior_result)) if args.prior_result else None
        if withdrawing:
            changes = withdraw_changes(changes, decision, prior)
        elif phase == "after_protected_service":
            require(prior and iam.digest(prior) == decision["prerequisites_sha256"], "previous_iam_receipt_required")
            native_receipt(prior, original_changes, args.commit)
        if args.command == "preflight":
            checks = preflight(changes, token, iam.request_json, withdrawing=withdrawing)
            print(json.dumps({"status": "blocked" if checks else "preflight_readbacks_verified", "checks": checks}))
            return int(bool(checks))
        journal = args.journal
        require(isinstance(journal, Path), "private_iam_journal_required")
        iam.verify_receipt_location(journal)
        require(journal.name == decision["operation_id"], "exact_iam_operation_journal_required")
        journal.mkdir(mode=0o700)
        result = run_changes(changes, decision, token, journal, service_check=gate)
        try:
            keep_receipt(journal / "result.json", result)
        except OSError as error:
            print(json.dumps({"status": "blocked", "primary_error": result.get("primary_error"), "custody_error": safe_error(error)}))
            return 1
        if result["status"] == "applied_and_verified":
            if phase == "before_bootstrap":
                keep_receipt(journal / "deploy-policy-receipt.json", noble_receipt(result, changes))
                native_inputs = native_receipt(result, changes, args.commit)
            else:
                native_inputs = native_receipt(prior, original_changes, args.commit, decision["protected_apply"], protected, result)
            keep_receipt(journal / "native-iam-receipt.json", native_inputs)
        print(json.dumps({"status": result["status"], "primary_error": result.get("primary_error"), "written": len(result["policies"])}))
        return int(result["status"] not in {"applied_and_verified", "withdrawn_and_verified"})
    except (OSError, KeyError, TypeError, ValueError) as error:
        print(json.dumps({"status": "blocked", "error": safe_error(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
