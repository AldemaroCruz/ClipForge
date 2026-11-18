"""Close the serial-6 foundation with one explicitly approved saved binary.

Configuration producer P and current execution controls D are separate source
identities. This entry point never grants or withdraws administrative IAM, runs
a replacement plan, imports state or promotes runtime/guest/application phases.
"""
from datetime import datetime, timedelta, timezone
import base64
import gzip
import io
import json
import os
from pathlib import Path
import re
import shutil
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, tf_int_plan as driver, int_release as custody
from scripts import check_int_foundation as foundation, int_foundation_recovery as recovery
from scripts import int_release_state as state_reader, review_int_foundation_plan as image_review
from scripts import int_iap_diagnostic as diagnostic

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "config/int-foundation-close.json"
WORKFLOW = ".github/workflows/int-foundation-close.yml"
SCHEMA = "clipforge-int-foundation-close-proposal-1"
DECISION_SCHEMA = "clipforge-int-foundation-close-decision-1"
ACTIVE_CONFIGURATION_SHA256 = "bf2a20357afc9ccd86edf34efd4a069ba7f43eb14b2853022ec031a9850fe0e1"
EXPECTED_BINDINGS_SHA256 = "5ffd5ef36b6a4e6b2c49917828b3289c2ec4731772dda1805f9bf9da9a996ffa"
EXPECTED_IAM_SOURCE_SHA256 = "13aa4f5ae778237b890dd02ae8f5c3f5364bfa13f857a5f0386d22d3744e67a1"
EXPECTED_IAM_MANIFEST_SHA256 = "2b26ef420a8534211f5760f45a20eeaad23b2ec79e44b25a2176bd3a1520589d"
STARTUP_SHA256 = "a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255"
RISK_LIMIT = "2026-11-28T05:59:59Z"
IAP_RESOURCE = "projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131"
TF_MEMBER = "serviceAccount:clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com"
DEPLOY_MEMBER = "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
FUNCTIONAL_ROLE = "roles/iap.tunnelResourceAccessor"
MANAGEMENT_ROLE = "projects/clipforgebeta2/roles/clipforgeIntRecoveryIapPolicy_20261118T044838Z"
WINDOW = {"not_before_utc": "2026-11-18T18:15:00Z", "expires_utc": "2026-11-18T20:15:00Z"}
MAX_RECEIPTS = 1024 * 1024
RETIRED_RUNS = {"44194990499", "44219757502", "44354702837"}
PLAN_FIELDS = ("configuration_commit", "controls_commit", "baseline_configuration_commit", "run_id", "run_attempt",
               "created_utc", "expires_utc", "configuration_sha256", "provider_lock_sha256", "terraform_version", "provider_version",
               "backend", "inputs", "image", "risk_acceptance", "binary", "json", "recovery_phase", "completed_imports",
               "recovery_contract_sha256", "control_sources_sha256")
CLOSURE_SOURCES = ("scripts/int_foundation_close.py", "tests/test_int_foundation_close.py",
                   ".github/workflows/int-foundation-close.yml", "config/int-foundation-close.json")


def instant(value):
    return foundation.instant(value)


def canonical(value):
    return custody.canonical(value)


def load_proposal(root=ROOT):
    return image_review.decode((root / CONFIG).read_bytes())


def plan_selection(manifest, reference):
    """Only versionable references/provenance, never the complete private manifest."""
    return {key: manifest[key] for key in PLAN_FIELDS} | {"manifest": reference}


def backend_fields(contract):
    return {key: contract["backend"][key] for key in
            ("bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version")}


def verify_proposal(proposal, contract, now=None):
    c.require(proposal.get("schema") == SCHEMA and proposal.get("status") == "proposed_not_authorized"
              and proposal.get("apply_authorized") is False and proposal.get("runtime_authorized") is False
              and proposal.get("administrative_iam_performed_by_workflow") is False,
              "A pending or unmaterialized closure proposal cannot authorize execution")
    c.require((proposal.get("repository"), proposal.get("branch"), proposal.get("environment")) ==
              ("AldemaroCruz/ClipForge", "ci/bootstrap-sec03", "int"), "Closure execution boundary differs")
    c.require(recovery.serial6_mode(contract) and len(contract["backend"]["managed_addresses"]) == 41
              and contract["imports"] == [] and contract["completed_imports"] == recovery.expected_imports(),
              "Closure requires the recognized serial-6 state and five completed imports")
    plan = proposal["plan"]
    c.require(isinstance(plan, dict) and set(plan) == set(PLAN_FIELDS) | {"manifest"}, "The exact new plan selection has not been materialized")
    c.require(plan["run_id"] not in RETIRED_RUNS
              and bool(re.fullmatch(r"[1-9][0-9]*", plan["run_id"])) and bool(re.fullmatch(r"[1-9][0-9]*", plan["run_attempt"]))
              and bool(re.fullmatch(r"[a-f0-9]{40}", plan["configuration_commit"])) and plan["controls_commit"] == plan["configuration_commit"]
              and plan["configuration_sha256"] == proposal["configuration_sha256"] == ACTIVE_CONFIGURATION_SHA256
              and plan["backend"] == proposal["backend"] == backend_fields(contract),
              "Only the newly reviewed convergent serial-6 plan is eligible")
    c.require(plan["inputs"] == contract["inputs"] and plan["terraform_version"] == "1.15.8" and plan["provider_version"] == "8.11.0"
              and plan["provider_lock_sha256"] == contract["source_bindings"]["provider_lock_sha256"]
              and plan["recovery_phase"] == recovery.SERIAL6_PHASE and plan["completed_imports"] == contract["completed_imports"]
              and plan["risk_acceptance"] == contract["risk_acceptance"]
              and all(bool(re.fullmatch(r"[a-f0-9]{64}", plan[key])) for key in ("recovery_contract_sha256", "control_sources_sha256")),
              "Plan inputs, source versions, completed imports or risk limits differ")
    created, expires = instant(plan["created_utc"]), instant(plan["expires_utc"])
    c.require(created <= (now or datetime.now(timezone.utc)) < expires and expires-created == timedelta(hours=24), "Plan TTL cannot be renewed or extended")
    prefix = custody.PREFIX + plan["configuration_commit"] + "/" + plan["run_id"] + "-" + plan["run_attempt"] + "/"
    for key, name in (("manifest", "manifest.json"), ("binary", "int.tfplan"), ("json", "int.json")):
        reference = plan[key]
        custody.object_name(reference["name"])
        c.require(set(reference) == {"name", "generation", "sha256", "size"} and reference["name"] == prefix + name
                  and bool(re.fullmatch(r"[1-9][0-9]*", reference.get("generation", "")))
                  and bool(re.fullmatch(r"[a-f0-9]{64}", reference.get("sha256", "")))
                  and type(reference.get("size")) is int and 0 < reference["size"] <= custody.LIMIT,
                  "Incomplete or changed exact closure private reference")
        recovery.reject_original_plan(reference, contract)
    review = proposal["expected_review"]
    c.require(review.get("counts") == {"no-op": 41, "create": 1} and review.get("imports") == []
              and review.get("addresses") == sorted(c.FOUNDATION_ADDRESSES)
              and review.get("existing_state_addresses") == contract["backend"]["managed_addresses"]
              and review.get("apply_authorized") is False, "Closure must preserve the 41 resources and create only IAP")
    verify_iam_package(proposal["iam_package"])
    c.require(instant(plan["risk_acceptance"]["maximum_expiry_utc"]) <= instant(RISK_LIMIT), "Risk acceptance was extended")
    return proposal


def verify_iam_package(package):
    c.require(isinstance(package, dict) and package.get("window") == WINDOW
              and all(bool(re.fullmatch(r"[a-f0-9]{64}", package.get(key, ""))) for key in ("manifest_sha256", "source_proposal_sha256")),
              "Exact materialized administrative package and fixed successor window required")
    rows = package.get("bindings", [])
    c.require(isinstance(rows, list) and len(rows) == 11 and len({row.get("binding_id") for row in rows}) == 11,
              "Eleven distinct administrative bindings must remain a list")
    # This exact canonical descriptor set binds all nine reused role IDs,
    # permissions, eleven resources and all three complete CEL conditions.
    # A date in a role name is not an expiry; the complete condition is hashed.
    c.require(package["source_proposal_sha256"] == EXPECTED_IAM_SOURCE_SHA256 and package["manifest_sha256"] == EXPECTED_IAM_MANIFEST_SHA256
              and custody.sha256(canonical(rows)) == EXPECTED_BINDINGS_SHA256,
              "Administrative descriptors differ from the exact proposed eleven-binding schema")
    roles = {}
    for row in rows:
        c.require(row.get("member") == TF_MEMBER and isinstance(row.get("key"), str)
                  and bool(re.fullmatch(r"[A-Za-z0-9_-]{1,100}", row.get("binding_id", "")))
                  and bool(re.fullmatch(r"projects/clipforgebeta2/roles/clipforgeInt[A-Za-z0-9_]+", row.get("role", "")))
                  and row.get("resource", "").startswith("projects/") and isinstance(row.get("condition"), dict)
                  and row.get("condition_sha256") == custody.sha256(canonical(row["condition"]))
                  and isinstance(row.get("permissions"), list) and row["permissions"] == sorted(set(row["permissions"])),
                  "Administrative binding identity, conditions or role definition differ")
        expression = row["condition"].get("expression", "")
        c.require(WINDOW["not_before_utc"] in expression and WINDOW["expires_utc"] in expression,
                  "Both fixed administrative time bounds must remain in every binding")
        c.require(row["role"] not in roles or roles[row["role"]] == row["permissions"], "Role permissions disagree across bindings")
        roles[row["role"]] = row["permissions"]
    c.require(len(roles) == 9, "Only the nine existing role definitions may be reused")
    management = [row for row in rows if row["key"] == "iap_management"]
    c.require(len(management) == 1 and management[0]["resource"] == IAP_RESOURCE and management[0]["role"] == MANAGEMENT_ROLE
              and management[0]["permissions"] == ["iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.setIamPolicy"],
              "Only the exact instance policy-management role is writable")
    for row in rows:
        if row["key"] != "iap_management":
            c.require(all(permission.endswith((".get", ".getIamPolicy")) for permission in row["permissions"]),
                      "Other temporary roles must remain metadata/policy reads only")
        policy_endpoint(row["resource"])
    return rows


def decision_template(report, proposal):
    expiry = min(instant(proposal["plan"]["expires_utc"]), instant(WINDOW["expires_utc"]),
                 instant(proposal["plan"]["risk_acceptance"]["maximum_expiry_utc"]), instant(RISK_LIMIT))
    return {"schema": DECISION_SCHEMA, "owner": "AldemaroCruz", "apply_decision": "pending",
            "plan": proposal["plan"], "expected_review": proposal["expected_review"],
            "apply_controls_commit": report["control_commit"], "control_sources_sha256": report["control_sources_sha256"],
            "evidence_sha256": custody.sha256(canonical(report)), "expires_utc": expiry.isoformat(),
            "iam_package": {"manifest_sha256": proposal["iam_package"]["manifest_sha256"],
                            "source_proposal_sha256": proposal["iam_package"]["source_proposal_sha256"],
                            "administrator_receipt_index_sha256": None, "window": WINDOW},
            "residual_decisions": [
                {"id": "F-SAST-EXEC", "decision": "pending", "execution_route": WORKFLOW,
                 "native_review": report["sast"], "control_sources_sha256": report["control_sources_sha256"]},
                {"id": "F-VM-XML", "decision": "pending", "image": proposal["plan"]["image"],
                 "conditions": foundation.INACTIVE_DATABASE_CONDITIONS},
                {"id": "F-AUDIT-0077", "decision": "pending", "operational": False, "retention_days": 30}],
            "risk_expiry_utc": proposal["plan"]["risk_acceptance"]["maximum_expiry_utc"], "runtime_authorized": False,
            "administrative_retirement": "separate_administrator_exact_iap_management_binding_after_success_receipt"}


def verify_owner_decision(decision, expected_sha, report, proposal, environ, now=None):
    current = now or datetime.now(timezone.utc)
    c.require(isinstance(decision, dict) and bool(re.fullmatch(r"[a-f0-9]{64}", expected_sha))
              and custody.sha256(canonical(decision)) == expected_sha, "Missing or altered exact closure decision")
    expected = decision_template(report, proposal)
    expected["apply_decision"] = "approve_exact_serial6_closure_binary_once"
    for row in expected["residual_decisions"]:
        row["decision"] = {"F-SAST-EXEC": "approve_exact_new_closure_execution_route_for_this_binary_only",
                           "F-VM-XML": "preserve_exact_image_inactive_database_conditions",
                           "F-AUDIT-0077": "preserve_alternative_pending_operational_validation"}[row["id"]]
    package = decision.get("iam_package", {})
    c.require(bool(re.fullmatch(r"[a-f0-9]{64}", package.get("administrator_receipt_index_sha256", "") or "")),
              "Actual administrative grant receipt bytes are required")
    expected["iam_package"]["administrator_receipt_index_sha256"] = package["administrator_receipt_index_sha256"]
    c.require(decision == expected, "This binary, execution source closure or residual decision has not been approved")
    commit = environ.get("GITHUB_SHA", "")
    c.require(bool(re.fullmatch(r"[a-f0-9]{40}", commit)) and commit == environ.get("INT_APPROVED_COMMIT")
              == report.get("control_commit") == decision["apply_controls_commit"], "Current controls/evidence/dispatch differ")
    c.require(report.get("integrity_status") == "passed" and set(report.get("integrity", {})) == foundation.REQUIRED_CHECKS
              and all(row.get("status") == "passed" for row in report["integrity"].values())
              and report.get("source_files", {}).get("scripts/tf_int_plan.py") == foundation.EXECUTION_SOURCE_SHA256
              and all(name in report["source_files"] for name in CLOSURE_SOURCES)
              and custody.sha256(canonical(report["source_files"])) == report["control_sources_sha256"],
              "Fresh complete foundation integrity and the frozen native execution source are required")
    pending = [row for row in report.get("sast", {}).get("findings", []) if row.get("disposition") == "risk_pending"]
    c.require(len(report.get("sast", {}).get("findings", [])) == len(pending) == 3 and {(row.get("rule"), row.get("line")) for row in pending} ==
              {("B404", 16), ("B603", 169), ("B603", 180)}
              and all(row.get("resource") == "scripts/tf_int_plan.py" and row.get("severity") == "LOW"
                      and row.get("source_sha256") == foundation.EXECUTION_SOURCE_SHA256 for row in pending),
              "Unknown or higher SAST findings cannot inherit a historical acceptance")
    c.require(instant(proposal["plan"]["created_utc"]) <= current < instant(decision["expires_utc"])
              and instant(WINDOW["not_before_utc"]) <= current < instant(WINDOW["expires_utc"])
              and current < instant(decision["risk_expiry_utc"]) <= instant(RISK_LIMIT), "Plan, execution window or risk decision expired")
    return {"decision_sha256": expected_sha, "evidence_sha256": decision["evidence_sha256"],
            "apply_controls_commit": commit, "configuration_commit": proposal["plan"]["configuration_commit"]}


def decode_receipts(encoded):
    c.require(isinstance(encoded, str) and 0 < len(encoded) <= 60000, "Compressed receipt input is missing or too large")
    try:
        compressed = base64.b64decode(encoded, validate=True)
        with gzip.GzipFile(fileobj=io.BytesIO(compressed)) as stream:
            raw = stream.read(MAX_RECEIPTS + 1)
        c.require(len(raw) <= MAX_RECEIPTS, "Administrative receipt bundle exceeds its private bound")
        return raw.decode("utf-8")
    except (ValueError, OSError, EOFError, UnicodeError):
        raise ValueError("Invalid bounded gzip/base64 administrative receipt bundle") from None


def verify_iam_receipts(serialized, decision, proposal):
    c.require(isinstance(serialized, str) and len(serialized.encode()) <= MAX_RECEIPTS, "Administrative receipt bundle missing or oversized")
    bundle = image_review.decode(serialized)
    c.require(set(bundle) == {"index", "files"} and isinstance(bundle["index"], str) and isinstance(bundle["files"], dict),
              "Closed raw receipt index/files bundle required")
    c.require(custody.sha256(bundle["index"].encode()) == decision["iam_package"]["administrator_receipt_index_sha256"],
              "Administrative index bytes differ from the owner decision")
    index = image_review.decode(bundle["index"])
    c.require(set(index) == {"schema", "manifest_sha256", "source_proposal_sha256", "files"}
              and index["schema"] == "clipforge-int-read-admin-receipt-index-1"
              and index["manifest_sha256"] == proposal["iam_package"]["manifest_sha256"]
              and index["source_proposal_sha256"] == proposal["iam_package"]["source_proposal_sha256"]
              and isinstance(index["files"], list) and len(index["files"]) == 97, "Complete administrative grant log required")
    descriptors = {row["binding_id"]: row for row in verify_iam_package(proposal["iam_package"])}
    grants, verified, names, all_exact = set(), set(), set(), 0
    attempted, completed = set(), set()
    completed_resources = {"role_preflight": set(), "policy_preflight": set(), "before_binding": set()}
    allowed = {"role_preflight", "policy_preflight", "before_binding", "grant_binding", "verify_binding", "all_exact_grants"}
    fields = {"schema", "sequence", "utc", "manifest_sha256", "operation", "status", "key", "resource", "http_status", "mutation_attempted", "details"}
    for sequence, item in enumerate(index["files"], 1):
        c.require(set(item) == {"name", "sha256"} and item["name"] == f"{sequence:04d}.json" and item["name"] not in names
                  and isinstance(bundle["files"].get(item["name"]), str), "Administrative receipt sequence differs")
        names.add(item["name"]); raw = bundle["files"][item["name"]].encode()
        c.require(custody.sha256(raw) == item["sha256"], "Administrative phase receipt bytes differ")
        row = image_review.decode(raw)
        c.require(set(row) == fields and row["schema"] == "clipforge-int-read-admin-receipt-1"
                  and row["sequence"] == sequence and row["manifest_sha256"] == index["manifest_sha256"]
                  and row["operation"] in allowed and row["status"] in {"attempted", "completed"}
                  and row["http_status"] in {None, 200} and isinstance(row["details"], dict)
                  and instant(WINDOW["not_before_utc"]) <= instant(row["utc"]) < instant(WINDOW["expires_utc"]),
                  "Failed, foreign, expired or unreviewed administrative phase")
        if sequence <= 18:
            phase, status = "role_preflight", "attempted" if sequence % 2 else "completed"
        elif sequence <= 30:
            phase, status = "policy_preflight", "attempted" if sequence % 2 else "completed"
        elif sequence <= 96:
            offset = sequence-31
            binding = proposal["iam_package"]["bindings"][offset//6]
            phase, status = ("before_binding", "grant_binding", "verify_binding")[(offset%6)//2], "attempted" if offset%2 == 0 else "completed"
            c.require(row["key"] == binding["key"] and row["resource"] == binding["resource"], "Administrative binding order/resource differs")
        else:
            phase, status = "all_exact_grants", "completed"
        c.require(row["operation"] == phase and row["status"] == status, "Administrative phase order differs from the complete 97-phase procedure")
        no_http = row["status"] == "attempted" or row["operation"] == "all_exact_grants"
        c.require(row["http_status"] is None if no_http else type(row["http_status"]) is int and row["http_status"] == 200,
                  "Administrative completed HTTP operation lacks an exact successful response")
        expected_mutation = row["operation"] == "grant_binding" and row["status"] == "completed"
        c.require(row["mutation_attempted"] is expected_mutation, "Unreviewed administrative mutation phase")
        pair = (row["operation"], row["key"], row["resource"])
        if row["operation"] != "all_exact_grants":
            if row["status"] == "attempted":
                c.require(pair not in attempted, "Duplicate attempted administrative phase")
                attempted.add(pair)
            else:
                c.require(pair in attempted and pair not in completed, "Administrative completion lacks its unique attempted phase")
                completed.add(pair)
                if row["operation"] in completed_resources:
                    identity = (row["key"], row["resource"]) if row["operation"] == "before_binding" else row["resource"]
                    c.require(identity not in completed_resources[row["operation"]], "Duplicate administrative preflight completion")
                    completed_resources[row["operation"]].add(identity)
        if row["operation"] in {"grant_binding", "verify_binding"} and row["status"] == "completed":
            details = row["details"]
            c.require(set(details) == {"binding_id", "role", "member", "condition_sha256"} and details.get("binding_id") in descriptors,
                      "Administrative binding receipt descriptor differs")
            expected = descriptors[details["binding_id"]]
            c.require(row["key"] == expected["key"] and row["resource"] == expected["resource"]
                      and all(details[key] == expected[key] for key in ("role", "member", "condition_sha256")),
                      "Administrative role/member/resource/condition differs")
            seen = grants if row["operation"] == "grant_binding" else verified
            c.require(details["binding_id"] not in seen and (row["operation"] == "grant_binding" or details["binding_id"] in grants),
                      "Administrative completion duplicate or verification precedes grant")
            seen.add(details["binding_id"])
        if row["operation"] == "all_exact_grants":
            c.require(sequence == 97 and row["status"] == "completed" and grants == verified == set(descriptors)
                      and row["details"] == {"roles": 9, "bindings": 11, "role_definitions_created": 0, **WINDOW},
                      "Administrative grant set is not exact and complete")
            all_exact += 1
    c.require(names == set(bundle["files"]) and grants == verified == set(descriptors) and all_exact == 1,
              "Incomplete or extra administrative receipt files")
    c.require(attempted == completed and completed_resources["role_preflight"] == {row["role"] for row in descriptors.values()}
              and completed_resources["policy_preflight"] == {row["resource"] for row in descriptors.values()}
              and completed_resources["before_binding"] == {(row["key"],row["resource"]) for row in descriptors.values()},
              "The nine role, six policy and eleven binding preflights must all be preserved")
    return {"bindings_granted_and_verified": 11, "existing_roles_verified": 9, "receipt_files": 97,
            "administrator_receipt_index_sha256": decision["iam_package"]["administrator_receipt_index_sha256"]}


def policy_endpoint(resource):
    fixed = {
        "projects/clipforgebeta2": ("POST", "https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy", {"options": {"requestedPolicyVersion": 3}}),
        IAP_RESOURCE: ("POST", "https://iap.googleapis.com/v1/" + IAP_RESOURCE + ":getIamPolicy", {"options": {"requestedPolicyVersion": 3}}),
        "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com":
            ("POST", "https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3", None),
    }
    if resource in fixed:
        return fixed[resource]
    if resource in {"projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin", "projects/clipforgebeta2/secrets/clipforge-int-postgres-ca"}:
        return "GET", "https://secretmanager.googleapis.com/v1/" + resource + ":getIamPolicy?options.requestedPolicyVersion=3", None
    view = "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access"
    if resource == view:
        return "POST", "https://logging.googleapis.com/v2/" + view + ":getIamPolicy", {"options": {"requestedPolicyVersion": 3}}
    raise ValueError("Unreviewed administrative policy resource")


def read_json(url, operation, resource, *, method="GET", payload=None):
    # Callers construct endpoints from reviewed fixed resources, never accept a
    # URL from a workflow input or credential document.
    fixed_resources = ("projects/clipforgebeta2", IAP_RESOURCE,
        "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com",
        "projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin", "projects/clipforgebeta2/secrets/clipforge-int-postgres-ca",
        "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access/views/pilot-access")
    allowed = {(endpoint, verb, canonical(body)) for verb, endpoint, body in map(policy_endpoint, fixed_resources)}
    base = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
    fixed_gets = {base + "instances/clipforge-int-base-postgres", base + "disks/clipforge-int-base-postgres",
                  base + "disks/clipforge-int-base-postgres-data", "https://logging.googleapis.com/v2/projects/clipforgebeta2/sinks/clipforge-int-access"}
    role = bool(re.fullmatch(r"https://iam\.googleapis\.com/v1/projects/clipforgebeta2/roles/clipforgeInt[A-Za-z0-9_]+", url))
    c.require((url, method, canonical(payload)) in allowed or (method == "GET" and payload is None and (url in fixed_gets or role)),
              "Unreviewed closure read endpoint or method; no credential forwarded")
    request = Request(url, data=canonical(payload) if payload is not None else None, method=method,
                      headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"], "Content-Type": "application/json"})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(MAX_RECEIPTS + 1)
    except HTTPError as error:
        failure = driver.FailedOperation(operation, "HTTP " + str(error.code) + ": required closure read failed", error.code)
        failure.receipt.update(resource=resource, resources=[resource], http_status=error.code, method=method)
        raise failure from None
    c.require(len(raw) <= MAX_RECEIPTS, "Private closure metadata exceeds bound")
    result = image_review.decode(raw)
    c.require(isinstance(result, dict), "Private closure metadata must be an object")
    return result


def read_policy(resource):
    method, url, payload = policy_endpoint(resource)
    return read_json(url, "read_closure_IAM_policy", resource, method=method, payload=payload)


def verify_live_iam(proposal):
    bindings = verify_iam_package(proposal["iam_package"])
    policies = {resource: read_policy(resource) for resource in {row["resource"] for row in bindings}}
    c.require(all(policy.get("version") == 3 for policy in policies.values()), "Conditional administrative policies require version 3")
    roles = {}
    for row in bindings:
        if row["role"] not in roles:
            roles[row["role"]] = read_json("https://iam.googleapis.com/v1/" + row["role"], "read_existing_closure_role", row["role"])
        role = roles[row["role"]]
        c.require(role.get("name") == row["role"] and role.get("stage") == "GA" and role.get("deleted", False) is False
                  and sorted(role.get("includedPermissions", [])) == row["permissions"], "Existing temporary role definition changed")
        matches = [binding for binding in policies[row["resource"]].get("bindings", []) if binding.get("role") == row["role"]
                   and row["member"] in binding.get("members", []) and binding.get("condition") == row["condition"]]
        c.require(len(matches) == 1, "Administrative grant missing, changed, duplicated or withdrawn")
    return {"exact_bindings": 11, "exact_existing_roles": 9, "effective_permission_not_inferred_from_policy_presence": True}


def verify_plan_bridge(manifest, proposal, module, producer_root, environ):
    contract = recovery.load_contract(producer_root)
    recovery.static_contract(producer_root, contract)
    verify_proposal(proposal, contract)
    recovery.verify_new_manifest(manifest, contract)
    c.require(manifest.get("plan_review_status") == "recovery_plan_requires_new_review", "A blocked or incomplete plan cannot be applied")
    c.require(plan_selection(manifest, proposal["plan"]["manifest"]) == proposal["plan"], "Producer manifest differs from the reviewed public selection")
    c.require(custody.sha256((producer_root / recovery.CONTRACT).read_bytes()) == manifest["recovery_contract_sha256"], "Producer recovery contract bytes changed")
    fingerprint, _ = foundation.fingerprint(producer_root, foundation.load_contract(producer_root))
    c.require(fingerprint == manifest["control_sources_sha256"], "Producer control-source fingerprint changed")
    files = {name: custody.sha256((module / name).read_bytes()) for name in c.FILES}
    c.require(files == manifest["configuration_files"] and custody.sha256(canonical(files)) == ACTIVE_CONFIGURATION_SHA256
              and {str(path.relative_to(module)).replace(os.sep, "/") for path in module.rglob("*") if path.is_file()} == set(c.FILES),
              "The exact ten producer sources must contain no imports or added configuration")
    c.require(environ.get("INT_STAGE") == "foundation" and environ.get("TF_WORKSPACE", "default") == "default"
              and custody.inputs(environ) == manifest["inputs"], "Foundation backend/workspace or reviewed inputs changed")
    return contract


def verify_wif(environ):
    adc = Path(environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    c.require(adc.is_file() and not adc.is_symlink() and adc.name.startswith("gha-creds-") and adc.suffix == ".json",
              "Fresh Actions WIF credential file required")
    with adc.open("rb") as stream:
        raw = stream.read(65537)
    c.require(len(raw) <= 65536, "ADC metadata exceeds its private bound")
    document = image_review.decode(raw)
    c.require(isinstance(document, dict) and isinstance(document.get("credential_source"), dict)
              and isinstance(document.get("service_account_impersonation_url", ""), str), "ADC metadata shape differs")
    metadata = diagnostic.credential_metadata(environ, document)
    c.require(document.get("type") == "external_account" and metadata["ADC"]["configured_target_matches"]
              and not metadata["unexpected_overrides"]
              and document.get("audience") == "//iam.googleapis.com/" + environ.get("GCP_WIF_PROVIDER", "")
              and document.get("token_url") == "https://sts.googleapis.com/v1/token"
              and not any(key in document for key in ("private_key", "private_key_id"))
              and isinstance(document.get("credential_source"), dict) and "executable" not in document["credential_source"],
              "ADC is not the exact reviewed WIF provider/target without personal or permanent-key overrides")
    for name in ("GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"):
        c.require(not environ.get(name) or Path(environ[name]).resolve() == adc.resolve(), "Credential-file selection alias differs")
    return {**metadata, "WIF_audience_matches_provider": True, "STS_endpoint_verified": True}


def vm_proof(planned=None, planned_disk=None):
    base = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
    vm = read_json(base + "instances/clipforge-int-base-postgres", "read_unchanged_foundation_VM", "1670495097211408131")
    metadata = {row["key"]: row.get("value", "") for row in vm.get("metadata", {}).get("items", [])}
    interfaces, disks = vm.get("networkInterfaces", []), vm.get("disks", [])
    c.require(str(vm.get("id")) == "1670495097211408131" and vm.get("name") == "clipforge-int-base-postgres"
              and vm.get("status") == "RUNNING" and vm.get("canIpForward") is False
              and vm.get("deletionProtection") is True and vm.get("machineType", "").endswith("/e2-micro")
              and len(interfaces) == 1 and interfaces[0].get("networkIP") == "10.80.1.2"
              and not interfaces[0].get("accessConfigs") and not interfaces[0].get("ipv6AccessConfigs")
              and metadata.get("enable-oslogin") == "TRUE" and metadata.get("block-project-ssh-keys") == "TRUE"
              and custody.sha256(metadata.get("startup-script", "").encode()) == STARTUP_SHA256
              and all(vm.get("shieldedInstanceConfig", {}).get(key) is True for key in ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring"))
              and len(disks) == 2 and all(row.get("autoDelete") is False for row in disks) and sum(row.get("boot") is True for row in disks) == 1,
              "Existing VM identity, startup, network or disk protection changed")
    if planned is not None:
        c.require(planned.get("machine_type") == vm["machineType"].rsplit("/",1)[-1]
                  and planned.get("deletion_protection") == vm["deletionProtection"] and planned.get("can_ip_forward") is False
                  and planned.get("network_interface", [{}])[0].get("network_ip") == interfaces[0]["networkIP"]
                  and planned.get("metadata") == {key:value for key,value in metadata.items() if key != "startup-script"}
                  and custody.sha256(str(planned.get("metadata_startup_script", "")).encode()) == custody.sha256(metadata["startup-script"].encode()),
                  "Live VM differs from the exact reviewed private plan")
        attachments = planned.get("attached_disk", [])
        c.require(len(attachments) == 1 and any(not row.get("boot") and row.get("source") == attachments[0].get("source")
                  and row.get("deviceName") == attachments[0].get("device_name") for row in disks), "Data disk differs from the reviewed attachment")
    private = {key: vm.get(key) for key in ("id", "name", "zone", "machineType", "deletionProtection", "canIpForward", "serviceAccounts", "shieldedInstanceConfig", "status", "creationTimestamp", "lastStartTimestamp", "lastStopTimestamp")}
    private.update(metadata_items=sorted(vm.get("metadata", {}).get("items", []), key=canonical), disks=disks,
                   networkInterfaces=interfaces, tags=vm.get("tags", {}).get("items", []))
    disk_proofs = []
    for attachment in disks:
        name = attachment.get("source", "").rsplit("/", 1)[-1]
        c.require(name in {"clipforge-int-base-postgres", "clipforge-int-base-postgres-data"}, "Unreviewed VM disk attachment")
        disk = read_json(base + "disks/" + name, "read_unchanged_foundation_disk", name)
        if attachment.get("boot"):
            c.require(str(disk.get("id")) == "2158164599035219715" and str(disk.get("sourceImageId")) == "5913446147369107523",
                      "Boot disk or pinned image identity changed")
        else:
            c.require(str(disk.get("id")) == "6427691858848206684" and str(disk.get("sizeGb")) == "20" and disk.get("type", "").endswith("/pd-standard")
                      and (planned_disk is None or (str(planned_disk.get("size")) == str(disk["sizeGb"])
                      and planned_disk.get("type") == disk["type"].rsplit("/",1)[-1] and planned_disk.get("name") == disk.get("name"))),
                      "Reviewed data disk size/type/name changed")
        disk_proofs.append({key: disk.get(key) for key in ("id", "name", "sizeGb", "type", "zone", "sourceImage", "sourceImageId", "diskEncryptionKey", "labels", "lastAttachTimestamp", "lastDetachTimestamp")})
    private["disk_metadata"] = disk_proofs
    return {"instance_id": "1670495097211408131", "configuration_sha256": custody.sha256(canonical(private)), "startup_unchanged": True,
            "two_retained_disks": True, "guest_access_performed": False}


def sink_proof(planned):
    resource = "projects/clipforgebeta2/sinks/clipforge-int-access"
    value = read_json("https://logging.googleapis.com/v2/" + resource, "read_convergent_foundation_sink", resource)
    destination = "logging.googleapis.com/projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access"
    c.require(planned.get("unique_writer_identity") is True and planned.get("writer_identity") in {None, ""}
              and value.get("name") == "clipforge-int-access" and value.get("writerIdentity") in {None, ""}
              and value.get("destination") == planned.get("destination") == destination
              and value.get("filter") == planned.get("filter")
              and bool(value.get("disabled", False)) == bool(planned.get("disabled", False)) is False
              and bool(value.get("includeChildren", False)) == bool(planned.get("include_children", False))
              and bool(value.get("interceptChildren", False)) == bool(planned.get("intercept_children", False))
              and (value.get("description") or "") == (planned.get("description") or "")
              and (value.get("exclusions") or []) == (planned.get("exclusions") or [])
              and (value.get("bigqueryOptions") or {}) == (planned.get("bigquery_options") or {}),
              "Sink API fields or provider-8.11 empty-writer representation differ from the reviewed NOOP")
    stable = {key:item for key,item in value.items() if key not in {"createTime", "updateTime"}}
    return {"name": "clipforge-int-access", "destination_sha256": custody.sha256(destination.encode()),
            "filter_sha256": custody.sha256(str(value.get("filter")).encode()), "enabled": True,
            "stable_API_configuration_sha256": custody.sha256(canonical(stable)),
            "API_writer_identity_absent_or_empty": True, "provider_8_11_read_unique_writer_identity": True,
            "representation_converged_without_second_plan": True, "exclusive_writer_identity_not_inferred": True,
            "operational_audit_coverage_not_inferred": True}


def without_functional_member(policy):
    rows, matches = [], 0
    for binding in policy.get("bindings", []):
        cleaned = dict(binding); members = list(binding.get("members", []))
        if binding.get("role") == FUNCTIONAL_ROLE and binding.get("condition") is None and DEPLOY_MEMBER in members:
            matches += 1; members.remove(DEPLOY_MEMBER)
        if members:
            cleaned["members"] = sorted(members); rows.append(cleaned)
    return {key: value for key, value in policy.items() if key not in {"etag", "bindings"}} | {"bindings": sorted(rows, key=canonical)}, matches


def functional_iap_proof(before, after):
    old, old_count = without_functional_member(before)
    new, new_count = without_functional_member(after)
    c.require(old_count == 0 and new_count == 1 and old == new, "Functional IAP member preexists/missing/conditional/duplicated or another policy binding changed")
    return {"resource": IAP_RESOURCE, "role": FUNCTIONAL_ROLE, "member": DEPLOY_MEMBER, "condition": None,
            "present_exactly_once": True, "all_other_policy_bindings_preserved": True}


def state_after_apply(bucket, plan):
    raw, obj, _ = state_reader.private_current_state(bucket)
    state = image_review.decode(raw)
    proof = state_reader.state_contract(raw, lineage=plan["backend"]["lineage"])
    c.require(proof["serial"] > 6 and obj["generation"] != plan["backend"]["generation"]
              and all(not instance.get("deposed") and instance.get("status") in {None, "ready"}
                      for resource in state.get("resources", []) for instance in resource.get("instances", [])),
              "A new untainted complete foundation descendant is required")
    iap = [resource for resource in state["resources"] if resource.get("type") == "google_iap_tunnel_instance_iam_member" and resource.get("name") == "protected_bootstrap"]
    c.require(len(iap) == 1 and len(iap[0].get("instances", [])) == 1, "Exactly one functional IAP state instance required")
    attributes = iap[0]["instances"][0]["attributes"]
    c.require(attributes.get("project") == "816643438938" and attributes.get("instance") == "1670495097211408131"
              and attributes.get("zone") == "us-central1-a" and attributes.get("role") == FUNCTIONAL_ROLE
              and attributes.get("member") == DEPLOY_MEMBER and not attributes.get("condition"), "Final IAP state identity/role/member/condition differs")
    live = [row for row in driver.backend_inventory(bucket)["live"] if row["name"].startswith(c.PREFIX + "/")]
    c.require(len(live) == 1 and live[0]["name"] == driver.STATE_NAME and live[0]["generation"] == obj["generation"],
              "Current state generation or active lock changed after apply")
    return {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw), "sha256": custody.sha256(raw), **proof}


def apply_reviewed(work, reports, environ, root=ROOT):
    custody.hosted_context(environ); c.validate_variables(environ)
    proposal = load_proposal(root); producer = root / "plan-source"
    contract = recovery.load_contract(producer)
    verify_proposal(proposal, contract)
    wif_metadata = verify_wif(environ)
    report = foundation.fetch_evidence(environ, root)
    decision = image_review.decode(environ.get("CLOSE_DECISION_JSON", "null"))
    approval = verify_owner_decision(decision, environ.get("CLOSE_DECISION_SHA256", ""), report, proposal, environ)
    receipts = verify_iam_receipts(decode_receipts(environ.get("CLOSE_IAM_RECEIPTS_GZIP_B64")), decision, proposal)
    module = work / "module"; module.mkdir()
    for name in c.FILES:
        target = module / name; target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(producer / "infra/gcp/int-base" / name, target)
    (work / "terraform.rc").write_text("provider_installation {\n  direct {}\n}\n", encoding="utf-8")
    plan = proposal["plan"]
    manifest = image_review.decode(custody.fetch_verified(plan["manifest"]))
    verify_plan_bridge(manifest, proposal, module, producer, environ)
    native_json = image_review.decode(custody.fetch_verified(plan["json"]))
    review = recovery.verify_recovery_plan(native_json, contract)
    c.require(review == proposal["expected_review"], "Exact native plan actions or full metadata classification changed")
    changes = {row["address"]: row for row in native_json["resource_changes"] if row.get("mode") == "managed"}
    iap = changes[recovery.PENDING_IAP]["change"]["after"]
    c.require(iap.get("project") == "816643438938" and iap.get("instance") == "1670495097211408131" and iap.get("zone") == "us-central1-a",
              "The sole creation must use the numeric IAP identity")
    planned_sink = changes["google_logging_project_sink.access"]["change"]["after"]
    target = work / "int.tfplan"; target.write_bytes(custody.fetch_verified(plan["binary"]))
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    before = recovery.inspect_partial(bucket, contract)
    c.require(image_review.image_metadata() == plan["image"], "Pinned image metadata changed")
    planned_vm = changes["google_compute_instance.postgres"]["change"]["after"]
    planned_disk = changes["google_compute_disk.postgres"]["change"]["after"]
    iam = verify_live_iam(proposal); vm = vm_proof(planned_vm,planned_disk); sink = sink_proof(planned_sink); policy = read_policy(IAP_RESOURCE)
    c.require(without_functional_member(policy)[1] == 0, "Unexpected functional IAP binding outside the recognized 41-address state")
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "foundation_close_init", work)
    c.require(recovery.inspect_partial(bucket, contract) == before and verify_live_iam(proposal) == iam and vm_proof(planned_vm,planned_disk) == vm
              and sink_proof(planned_sink) == sink and read_policy(IAP_RESOURCE) == policy, "State, IAM, VM or sink changed during initialization")
    verify_owner_decision(decision, environ["CLOSE_DECISION_SHA256"], report, proposal, environ)
    c.require(custody.sha256(target.read_bytes()) == plan["binary"]["sha256"]
              and {name: custody.sha256((module / name).read_bytes()) for name in c.FILES} == manifest["configuration_files"],
              "Saved binary or exact producer sources changed before execution")
    (work / "apply-attempted.json").write_bytes(canonical({"binary_sha256": plan["binary"]["sha256"], "controls_commit": environ["GITHUB_SHA"]}))
    driver.run([binary, "apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(target)], "foundation_close_apply_saved", work)
    (work / "apply-completed.json").write_bytes(b"{}")
    state = state_after_apply(bucket, plan)
    c.require(vm_proof(planned_vm,planned_disk) == vm and sink_proof(planned_sink) == sink, "Post-apply VM or sink differs; preserve resulting state without retry")
    functional = functional_iap_proof(policy, read_policy(IAP_RESOURCE))
    verify_live_iam(proposal)
    receipt = {"schema": "clipforge-int-foundation-close-receipt-1", "plan_manifest": plan["manifest"], "plan_binary": plan["binary"],
        "parent_serial6_state": plan["backend"], "producer_commit": plan["configuration_commit"], "producer_controls_commit": plan["controls_commit"],
        "configuration_sha256": plan["configuration_sha256"], "approval": approval, "administrative_receipts": receipts,
        "credential_selection": wif_metadata,
        "issuer": {"workflow": WORKFLOW, "repository": "AldemaroCruz/ClipForge", "commit": environ["GITHUB_SHA"],
                   "run_id": environ["GITHUB_RUN_ID"], "run_attempt": environ["GITHUB_RUN_ATTEMPT"]},
        "state": state, "functional_IAP": functional, "unchanged_VM": vm, "sink_convergence": sink,
        "administrative_IAP_management_retirement": "pending_separate_administrator_exact_binding_withdrawal",
        "runtime_authorized": False, "guest_authorized": False}
    name = custody.PREFIX + environ["GITHUB_SHA"] + "/" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"] + "/foundation-state.json"
    reference = custody.upload(name, canonical(receipt))
    summary = {"status": "foundation_closed_administrative_IAP_retirement_pending", "receipt": reference, "state": state,
               "functional_IAP": functional, "unchanged_VM": vm, "sink_convergence": sink, "runtime_authorized": False, "guest_authorized": False}
    save_summary(reports, summary)
    return summary


def save_summary(reports, summary):
    encoded = json.dumps(summary, indent=2) + "\n"
    (reports / "close-summary.json").write_text(encoded, encoding="utf-8")
    (reports / "close-summary.md").write_text("# INT foundation closure\n\nStatus: " + summary["status"]
        + "\n\nAdministrative IAP management withdrawal is a separate exact-binding action. No guest, database or runtime promotion.\n\n```json\n"
        + encoded + "```\n", encoding="utf-8")


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["check", "producer", "apply"])
    args = parser.parse_args(); os.umask(0o077)
    if args.operation in {"check", "producer"}:
        proposal = verify_proposal(load_proposal(), recovery.load_contract())
        if args.operation == "producer":
            c.require(bool(os.environ.get("GITHUB_OUTPUT")), "GitHub step output required")
            with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
                stream.write("producer_commit=" + proposal["plan"]["configuration_commit"] + "\n")
        print("Exact closure proposal verified; no execution authorization.")
        return 0
    work, reports = driver.private_paths()
    try:
        apply_reviewed(work, reports, os.environ)
        return 0
    except Exception as error:
        summary = {"status": "blocked_or_partial_foundation_close_preserve_state_no_retry", "runtime_authorized": False,
                   "error": getattr(error, "receipt", {"operation": "foundation_close_preflight", "error_type": type(error).__name__})}
        if (work / "apply-completed.json").exists():
            summary["status"] = "native_close_apply_completed_postverification_failed_no_retry"
        if (work / "foundation_close_apply_saved.log").is_file():
            summary["error"] = recovery.sanitized_native_errors((work / "foundation_close_apply_saved.log").read_bytes())
        if (work / "apply-attempted.json").exists():
            try:
                bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
                raw, obj, _ = state_reader.private_current_state(bucket); value = image_review.decode(raw)
                pin = load_proposal()["backend"]
                c.require(value.get("version") == 4 and value.get("terraform_version") == "1.15.8" and value.get("lineage") == pin["lineage"]
                          and type(value.get("serial")) is int and value["serial"] >= 6, "Unexpected partial state header")
                summary["partial_state"] = {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw),
                    "sha256": custody.sha256(raw), "lineage": value["lineage"], "serial": value["serial"]}
            except Exception as inspect_error:
                summary["partial_state_inspection"] = {"error_type": type(inspect_error).__name__}
        save_summary(reports, summary)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
