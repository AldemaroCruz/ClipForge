"""Prepare or execute only the reviewed stable DB-01 Terraform READ delta."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts import check_tf_int as contract
from scripts import int_foundation_close as historical
from scripts import int_foundation_verify as foundation
from scripts import int_release as custody
from scripts import tf_int_plan as driver


ROOT = driver.ROOT
PROFILE = Path("config/int-db01-noble-read-iam.json")
SCHEMA = "clipforge-db01-noble-stable-read-iam-1"
RECEIPT_SCHEMA = "clipforge-db01-noble-stable-read-receipt-1"
APPROVAL_SCHEMA = "clipforge-db01-noble-stable-read-approval-1"
APPROVAL_DECISION = "apply_exact_stable_read_and_plan_once_with_scoped_rollback"
ADMIN = "admin@ixbalam.studio"
MEMBER = historical.TF_MEMBER
PROJECT = "projects/clipforgebeta2"
ROLE_PREFIX = PROJECT + "/roles/"
NEW_ROLE = ROLE_PREFIX + "clipforgeIntNobleIapPolicyRead"
LOG_BUCKET = PROJECT + "/locations/us-central1/buckets/clipforge-int-access"
LOG_VIEW = LOG_BUCKET + "/views/pilot-access"
SECRETS = [PROJECT + "/secrets/clipforge-int-" + name for name in ("bootstrap-admin", "postgres-ca")]
SA = PROJECT + "/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
IAP = historical.IAP_RESOURCE
SOURCE = {
    "run_id": 44608046539, "attempt": 1, "commit": "5c7bba01c77fd6b1ddbe1660cb84a9a7f72bce9d",
    "artifact_sha256": "6c13aac23fa06096bfa10e1579d3e9048ff8ba3fdfc116f26a0634cd6df41800",
}
REQUIRED_ROLES = {
    ROLE_PREFIX + "clipforgeIntRead" + label + "_20261118T180000Z": permission
    for label, permission in {
        "LogBucket": "logging.buckets.get",
        "LogSink": "logging.sinks.get",
        "LogView": "logging.views.get",
        "LogViewPolicy": "logging.views.getIamPolicy",
        "PostgresPolicy": "iam.serviceAccounts.getIamPolicy",
        "RoleMetadata": "iam.roles.get",
        "SecretMetadata": "secretmanager.secrets.get",
        "SecretPolicy": "secretmanager.secrets.getIamPolicy",
    }.items()
} | {NEW_ROLE: "iap.tunnelInstances.getIamPolicy"}
REQUIRED_POLICIES = {
    PROJECT: ("project", {"logging.buckets.get", "logging.sinks.get", "logging.views.get", "iam.roles.get"}),
    LOG_VIEW: ("logging_view", {"logging.views.getIamPolicy"}),
    **{target: ("secret", {"secretmanager.secrets.get", "secretmanager.secrets.getIamPolicy"}) for target in SECRETS},
    SA: ("service_account", {"iam.serviceAccounts.getIamPolicy"}),
    IAP: ("iap", {"iap.tunnelInstances.getIamPolicy"}),
}
SCOPED_ROLES = {
    "logging.buckets.get": ("LogBucket", LOG_BUCKET, "log_bucket"),
    "logging.views.get": ("LogView", LOG_VIEW, "log_view"),
}
MAX_RESPONSE = 2 * 1024 * 1024


class CloudError(ValueError):
    def __init__(self, status, *, diagnostic=None):
        self.status = status
        self.diagnostic = diagnostic
        super().__init__(f"Cloud read or write returned HTTP {status}")


def digest(value):
    return custody.sha256(custody.canonical(value))


def check_fields(value, keys):
    contract.require(isinstance(value, dict) and value.keys() == set(keys), "Unexpected READ object keys")


def valid_digest(value):
    return isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) is not None


def allowed_condition(permission):
    if permission not in SCOPED_ROLES:
        return {}
    resource_type, resource, label = SCOPED_ROLES[permission]
    return {"condition": {
        "title": "clipforge_int_terraform_operational_" + label,
        "description": "Stable operational Terraform refresh of the exact INT Logging resource",
        "expression": f'resource.type == "logging.googleapis.com/{resource_type}" && resource.name == "{resource}"',
    }}


def load_profile(root=ROOT):
    profile = foundation.decode((root / PROFILE).read_bytes())
    check_fields(profile, {"schema", "lifetime", "administrator", "principal", "source_observation", "roles", "policies"})
    contract.require(profile["schema"] == SCHEMA and profile["lifetime"] == "stable_operational"
            and profile["administrator"] == ADMIN and profile["principal"] == MEMBER
            and profile["source_observation"] == SOURCE, "Unreviewed stable READ identity, lifetime or evidence")
    check_fields(profile["roles"], REQUIRED_ROLES)
    check_fields(profile["policies"], REQUIRED_POLICIES)
    for role, spec in profile["roles"].items():
        check_fields(spec, {"mode", "definition"})
        definition = spec["definition"]
        check_fields(definition, {"title", "description", "stage", "includedPermissions"})
        contract.require(spec["mode"] == ("create" if role == NEW_ROLE else "reuse")
                and definition["stage"] == "GA" and definition["includedPermissions"] == [REQUIRED_ROLES[role]]
                and all(isinstance(definition[key], str) and definition[key] for key in ("title", "description")),
                "Unreviewed role mode or definition")
    addresses = []
    for resource, spec in profile["policies"].items():
        api, permissions = REQUIRED_POLICIES[resource]
        check_fields(spec, {"api", "baseline_policy_sha256", "baseline_etag_sha256", "state_etags", "add_bindings"})
        contract.require(spec["api"] == api and valid_digest(spec["baseline_policy_sha256"])
                and valid_digest(spec["baseline_etag_sha256"]) and isinstance(spec["state_etags"], list) and spec["state_etags"],
                "Unreviewed policy scope or baseline")
        for entry in spec["state_etags"]:
            check_fields(entry, {"address", "sha256"})
            contract.require(isinstance(entry["address"], str) and valid_digest(entry["sha256"]), "Invalid state etag record")
            addresses.append(entry["address"])
        expected = [{"role": role, "members": [MEMBER], **allowed_condition(permission)}
                    for role, permission in REQUIRED_ROLES.items() if permission in permissions]
        contract.require(isinstance(spec["add_bindings"], list)
                and sorted(map(custody.canonical, spec["add_bindings"])) == sorted(map(custody.canonical, expected)),
                "Unreviewed READ binding member, role, scope or condition")
    contract.require(len(set(addresses)) == len(addresses) == 11 and set(addresses) <= contract.FOUNDATION_ADDRESSES,
                     "Unreviewed managed policy references")
    return profile, digest(profile)


def canonical_policy(policy):
    contract.require(isinstance(policy, dict) and policy.keys() <= {"version", "etag", "bindings", "auditConfigs"}
            and type(policy.get("version")) is int and policy["version"] == 3
            and isinstance(policy.get("etag"), str) and policy["etag"]
            and isinstance(policy.get("bindings"), list), "Private IAM version 3 policy with etag required")
    bindings = []
    for binding in policy["bindings"]:
        contract.require(isinstance(binding, dict) and set(binding) in ({"role", "members"}, {"role", "members", "condition"})
                and isinstance(binding["role"], str) and isinstance(binding["members"], list) and binding["members"]
                and all(isinstance(member, str) and member for member in binding["members"])
                and len(binding["members"]) == len(set(binding["members"])), "Unrecognized role binding")
        if "condition" in binding:
            condition = binding["condition"]
            contract.require(isinstance(condition, dict) and condition.keys() <= {"title", "description", "expression", "location"}
                    and isinstance(condition.get("expression"), str) and all(isinstance(v, str) for v in condition.values()),
                    "Unrecognized IAM condition")
        bindings.append({**binding, "members": sorted(binding["members"])})
    keys = [custody.canonical({key: value for key, value in row.items() if key != "members"}) for row in bindings]
    contract.require(len(keys) == len(set(keys)), "Ambiguous duplicate IAM binding")
    result = {**policy, "bindings": sorted(bindings, key=custody.canonical)}
    if "auditConfigs" in policy:
        audits = []
        for config in policy["auditConfigs"]:
            check_fields(config, {"service", "auditLogConfigs"})
            entries = []
            for log in config["auditLogConfigs"]:
                contract.require(log.keys() <= {"logType", "exemptedMembers"} and isinstance(log.get("logType"), str),
                                 "Unreviewed audit log setting")
                entries.append({**log, "exemptedMembers": sorted(log["exemptedMembers"])} if "exemptedMembers" in log else log)
            audits.append({**config, "auditLogConfigs": sorted(entries, key=custody.canonical)})
        result["auditConfigs"] = sorted(audits, key=custody.canonical)
    return result


def semantic(policy):
    value = canonical_policy(policy)
    del value["etag"]
    return value


def check_policy_delta(before, after, bindings):
    expected = {**before, "bindings": [*before["bindings"], *bindings]}
    contract.require(before["etag"] != after["etag"] and semantic(after) == semantic(expected),
                     "Policy delta differs from the exact stable READ bindings")


def proof_name(commit):
    contract.require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None, "Exact reviewed SHA required")
    return custody.PREFIX + commit + f"/{SOURCE['run_id']}-{SOURCE['attempt']}/manifest.json"


def rejection_diagnostic(stream, token):
    """Retain only a bounded, sanitized projection of a Google API rejection."""
    try:
        raw = stream.read(4097)
        if len(raw) > 4096:
            return {"body_status": "oversized"}
        error = json.loads(raw).get("error", {})
        if not isinstance(error, dict):
            return {"body_status": "not_google_error"}
        message = error.get("message", "")
        if not isinstance(message, str):
            return {"body_status": "not_google_error"}
        if token:
            message = message.replace(token, "[redacted]")
        message = re.sub(r"(?i)\b(?:bearer\s+|ya29\.|eyJ[A-Za-z0-9_-]*\.)[A-Za-z0-9._~+/=-]+", "[redacted]", message)
        message = re.sub(r"[\x00-\x1f\x7f-\x9f]", " ", message).strip()[:700]
        status = error.get("status")
        return {"body_status": "sanitized", "status": status if isinstance(status, str) and re.fullmatch(r"[A-Z_]{1,48}", status) else None,
                "message": message}
    except (OSError, ValueError, AttributeError):
        return {"body_status": "unavailable"}


def request_json(url, token, method="GET", body=None, *, retain_error=False):
    request = Request(url, method=method, data=custody.canonical(body) if body is not None else None,
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                               "X-Goog-Request-Reason": "ClipForge DB01 Noble stable operational READ"})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=30) as stream:
            raw = stream.read(MAX_RESPONSE + 1)
    except HTTPError as error:
        try:
            diagnostic = rejection_diagnostic(error, token) if retain_error else None
        finally:
            error.close()
        raise CloudError(error.code, diagnostic=diagnostic) from None
    contract.require(len(raw) <= MAX_RESPONSE, "Private IAM response exceeded its bound")
    return foundation.decode(raw)


def get_policy(target, spec, token):
    contract.require(target in REQUIRED_POLICIES and REQUIRED_POLICIES[target][0] == spec["api"], "Unreviewed policy read")
    method, url, body = historical.policy_endpoint(target)
    result = request_json(url, token, method, body)
    canonical_policy(result)
    return result


def set_policy(target, original, token):
    canonical_policy(original)
    contract.require(target in REQUIRED_POLICIES, "Unreviewed policy write")
    _, url, _ = historical.policy_endpoint(target)
    endpoint = url.split(":getIamPolicy")[0] + ":setIamPolicy"
    # The update mask preserves server audit configuration. IAP uses its reviewed full-policy API.
    body = {"policy": original} | ({"updateMask": "bindings,etag"} if target != IAP else {})
    return request_json(endpoint, token, "POST", body)


def get_role(role, token):
    contract.require(role in REQUIRED_ROLES, "Unreviewed role read")
    return request_json("https://iam.googleapis.com/v1/" + role, token)


def check_role_definition(role, observed, spec):
    contract.require(isinstance(observed, dict) and observed.get("name") == role and observed.get("deleted") in (None, False)
            and {key: observed.get(key) for key in spec["definition"]} == spec["definition"],
            "Current custom role differs from the approved definition")


def require_new_role_absent(token):
    try:
        get_role(NEW_ROLE, token)
    except CloudError as error:
        if error.status == 404:
            return
        raise
    raise ValueError("The proposed IAP role identifier already exists")


def verify_recipients(policies, token):
    query = {"query": " OR ".join("roles=" + role for role in sorted(REQUIRED_ROLES)), "pageSize": 100}
    # A new member or condition may not be inferred from an Asset Index result;
    # compare all indexed bindings with the same bindings in authoritative policies.
    allowed = set()
    for target, policy in policies.items():
        canonical_target = target.replace("projects/clipforgebeta2/", "projects/816643438938/", 1) if target.startswith(
            (LOG_VIEW, *SECRETS)
        ) else target
        for row in policy["bindings"]:
            if row["role"] in REQUIRED_ROLES:
                contract.require(row["members"] == [MEMBER] and "condition" in row,
                                 "Existing custom role has another member or unreviewed unconditional binding")
                allowed.add((canonical_target, custody.canonical(row)))
    found = set()
    pages = set()
    for _ in range(4):
        result = request_json("https://cloudasset.googleapis.com/v1/projects/816643438938:searchAllIamPolicies?" +
                              urlencode(query), token)
        for entry in result.get("results", []):
            resource = entry["resource"].split("/", 3)[3]
            for row in entry["policy"].get("bindings", []):
                if row["role"] in REQUIRED_ROLES:
                    found.add((resource, custody.canonical(row)))
        page = result.get("nextPageToken", "")
        if not page:
            contract.require(found == allowed, "Indexed role recipients differ from the direct policy inventory")
            return
        contract.require(isinstance(page, str) and page not in pages, "Role recipient search pagination did not advance")
        pages.add(page)
        query["pageToken"] = page
    raise ValueError("Role recipient verification exceeded its pagination bound")


def preflight(profile, token):
    project = request_json("https://cloudresourcemanager.googleapis.com/v1/" + PROJECT, token)
    contract.require(project.get("projectId") == "clipforgebeta2" and str(project.get("projectNumber")) == "816643438938",
                     "INT project identity differs")
    before = {}
    for target, spec in profile["policies"].items():
        policy = get_policy(target, spec, token)
        contract.require(digest(policy) == spec["baseline_policy_sha256"] and digest(policy["etag"]) == spec["baseline_etag_sha256"],
                         "An authoritative policy changed since its reviewed baseline")
        canonical_policy({**policy, "bindings": [*policy["bindings"], *spec["add_bindings"]]})
        before[target] = policy
    for role, spec in profile["roles"].items():
        if spec["mode"] == "reuse":
            check_role_definition(role, get_role(role, token), spec)
    require_new_role_absent(token)
    verify_recipients(before, token)
    from scripts import db01_noble_plan as noble
    contract.require(noble.state_identity()["current_lock_absent"] is True, "Original pinned backend and no live lock required")
    return before


def run_local(command):
    result = subprocess.run(command, capture_output=True, text=True, timeout=30)
    contract.require(result.returncode == 0, "Local tool failed; private native output withheld")
    return result.stdout.strip()


def verify_checkout(commit):
    proof_name(commit)
    contract.require(run_local(["git", "-C", str(ROOT), "rev-parse", "HEAD"]) == commit
            and not run_local(["git", "-C", str(ROOT), "status", "--porcelain", "--untracked-files=no"]),
            "Run from the clean reviewed checkout")


def admin_token():
    cli = shutil.which("gcloud") or shutil.which("gcloud.cmd")
    forbidden = ("CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_AUTH_ACCESS_TOKEN",
                 "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE",
                 "GOOGLE_APPLICATION_CREDENTIALS", "GCP_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN")
    contract.require(cli and not any(os.environ.get(key) for key in forbidden), "Existing unimpersonated admin CLI required")
    active = run_local([cli, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)"])
    contract.require(active == ADMIN, "The active gcloud account must be the reviewed administrator")
    for key in ("auth/impersonate_service_account", "auth/access_token_file", "auth/credential_file_override"):
        contract.require(run_local([cli, "config", "get-value", key, "--quiet"]) in ("", "(unset)"),
                         "Administrator CLI credential override refused")
    token = run_local([cli, "auth", "print-access-token", "--account=" + ADMIN, "--quiet"])
    contract.require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,8192}", token) is not None, "Current administrator token required")
    return token


def verify_receipt_location(path):
    contract.require(path.is_absolute() and path.parent.exists(), "Use an absolute private directory with an existing parent")
    for ancestor in (path, *path.parents):
        contract.require(not ancestor.is_symlink() and not getattr(ancestor, "is_junction", lambda: False)()
                         and not (ancestor / ".git").exists(),
                         "Private receipt directory must be outside Git and free of reparse ancestors")


def approval_digest(path, commit, profile_sha):
    contract.require(path is not None and path.is_file(), "Private owner decision file required")
    verify_receipt_location(path)
    value = foundation.decode(path.read_bytes())
    check_fields(value, {"schema", "decision", "reviewed_commit", "package_sha256", "source_observation", "approval_ref"})
    reference = value["approval_ref"]
    contract.require(value["schema"] == APPROVAL_SCHEMA and value["decision"] == APPROVAL_DECISION
            and value["reviewed_commit"] == commit and value["package_sha256"] == profile_sha
            and value["source_observation"] == SOURCE and isinstance(reference, str)
            and 1 <= len(reference.strip()) <= 500, "Owner decision does not authorize this exact IAM delta and one plan")
    return digest(value)


def write_new(path, value):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as stream:
        stream.write(custody.canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def apply_delta(profile, before, token, directory, commit, profile_sha, approval_sha):
    receipt = {"schema": RECEIPT_SCHEMA, "commit": commit, "profile_sha256": profile_sha,
               "owner_approval_sha256": approval_sha, "issued_utc": datetime.now(timezone.utc).isoformat(),
               "policies": {}}
    spec = profile["roles"][NEW_ROLE]
    write_new(directory / "role-create-intent.json", spec["definition"])
    role = request_json("https://iam.googleapis.com/v1/" + PROJECT + "/roles", token, "POST",
                        {"roleId": NEW_ROLE.rsplit("/", 1)[1], "role": spec["definition"]})
    check_role_definition(NEW_ROLE, role, spec)
    check_role_definition(NEW_ROLE, get_role(NEW_ROLE, token), spec)
    write_new(directory / "role-created.json", role)
    for index, (target, binding_spec) in enumerate(profile["policies"].items()):
        # Recheck the baseline just before changing it. The service also checks etag.
        live = get_policy(target, binding_spec, token)
        original = before[target]
        contract.require(digest(live) == digest(original), "Policy changed since the preflight; no retry")
        additions = binding_spec["add_bindings"]
        requested = {**original, "bindings": [*original["bindings"], *additions]}
        write_new(directory / f"{index:02d}-grant-intent.json", {"target": target, "policy": requested})
        response = set_policy(target, requested, token)
        actual = get_policy(target, binding_spec, token)
        check_policy_delta(original, actual, additions)
        contract.require(canonical_policy(response) == canonical_policy(actual), "Grant response and policy readback differ")
        receipt["policies"][target] = {"before": original, "after": actual}
        write_new(directory / f"{index:02d}-grant-readback.json", receipt["policies"][target])
    for target, spec in profile["policies"].items():
        contract.require(canonical_policy(get_policy(target, spec, token)) == canonical_policy(receipt["policies"][target]["after"]),
                         "Policy changed before publishing the private IAM receipt")
    write_new(directory / "iam-receipt.json", receipt)
    raw = custody.canonical(receipt)
    reference = custody.upload(proof_name(commit), raw)
    write_new(directory / "iam-receipt-reference.json", reference)
    contract.require(custody.fetch_verified(reference) == raw, "Private immutable IAM receipt readback differs")
    return reference


def rollback_delta(profile, before, token, directory, journal):
    candidates = {}
    for index, (target, spec) in enumerate(profile["policies"].items()):
        original = before[target]
        contract.require(digest(original) == spec["baseline_policy_sha256"]
                         and digest(original["etag"]) == spec["baseline_etag_sha256"], "Invalid rollback baseline")
        attempted = directory / f"{index:02d}-grant-intent.json"
        if not attempted.is_file():
            continue
        contract.require(not attempted.is_symlink() and foundation.decode(attempted.read_bytes()) ==
                         {"target": target, "policy": {**original, "bindings": [*original["bindings"], *spec["add_bindings"]]}},
                         "Rollback grant intent differs")
        live = get_policy(target, spec, token)
        # Separate observed non-commit from a successful or ambiguous write.
        if semantic(live) == semantic(original):
            continue
        check_policy_delta(original, live, spec["add_bindings"])
        candidates[index] = (target, original, live)
    for index, (target, original, live) in reversed(list(candidates.items())):
        requested = {**original, "etag": live["etag"]}
        write_new(journal / f"{index:02d}-rollback-intent.json", {"target": target, "policy": requested})
        response = set_policy(target, requested, token)
        actual = get_policy(target, profile["policies"][target], token)
        contract.require(semantic(actual) == semantic(original)
                         and canonical_policy(response) == canonical_policy(actual),
                         "Rollback readback differs from the preserved policy")
        write_new(journal / f"{index:02d}-rollback-readback.json", {"target": target, "policy": actual})
    return len(candidates)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("describe", "preflight", "apply", "rollback"))
    parser.add_argument("--reviewed-commit")
    parser.add_argument("--package-sha256")
    parser.add_argument("--receipt-dir", type=Path)
    parser.add_argument("--approval", type=Path)
    args = parser.parse_args(argv)
    token = None
    try:
        profile, sha = load_profile()
        if args.operation == "describe":
            print(json.dumps({"package_sha256": sha, "profile": profile}))
            return 0
        contract.require(sha == args.package_sha256 and args.reviewed_commit and args.receipt_dir,
                         "Reviewed commit, package SHA and private receipt directory required")
        verify_checkout(args.reviewed_commit)
        directory = args.receipt_dir
        verify_receipt_location(directory)
        mutating = args.operation in ("apply", "rollback")
        approval_sha = approval_digest(args.approval, args.reviewed_commit, sha) if mutating else None
        token = admin_token()
        os.environ["GCP_ACCESS_TOKEN"] = token
        context = {"commit": args.reviewed_commit, "package_sha256": sha, "administrator": ADMIN}
        if args.operation == "rollback":
            preflight_path = directory / "preflight.json"
            contract.require(preflight_path.is_file() and not preflight_path.is_symlink(), "Original preflight receipt required")
            previous = foundation.decode(preflight_path.read_bytes())
            contract.require(previous["context"] == context and previous["owner_approval_sha256"] == approval_sha
                             and set(previous["before"]) == set(profile["policies"]),
                             "Rollback receipt identity differs")
            journal = directory / datetime.now(timezone.utc).strftime("rollback-%Y%m%dT%H%M%S.%fZ")
            journal.mkdir(mode=0o700)
            print(json.dumps({"status": "rollback_verified", "policies_restored": rollback_delta(
                profile, previous["before"], token, directory, journal), "role_definition_retained": NEW_ROLE}))
            return 0
        directory.mkdir(mode=0o700)
        before = preflight(profile, token)
        write_new(directory / "preflight.json", {"context": context, "before": before, "owner_approval_sha256": approval_sha})
        if args.operation == "apply":
            reference = apply_delta(profile, before, token, directory, args.reviewed_commit, sha,
                                    approval_sha)
            print(json.dumps({"status": "stable_read_delta_verified", "reference": reference}))
        else:
            print(json.dumps({"status": "preflight_verified", "policies": len(before), **context}))
        return 0
    except (OSError, ValueError, TypeError, AttributeError, KeyError, subprocess.TimeoutExpired) as error:
        # The executor may fail after a write. Inspect intent/readback evidence before any next action.
        print(json.dumps({"status": "blocked", "operation": args.operation, "error_type": type(error).__name__,
                          **({"http_status": error.status} if isinstance(error, CloudError) else {})}))
        return 1
    finally:
        if token is not None:
            os.environ.pop("GCP_ACCESS_TOKEN", None)


if __name__ == "__main__":
    raise SystemExit(main())
