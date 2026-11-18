"""Bounded IAP credential/route reads and optional serial-6 recovery plan.

No grant/apply entry point exists. Native IAM reads use the pinned provider,
while the explicit-token comparison uses Python HTTPS and states that limit.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, tf_int_plan as driver, int_release as custody
from scripts import int_release_state as states, int_iap_provider_probe as native

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "config/int-iap-diagnostic.json"
TF_SA = "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com"
ROUTES = {
    "numeric": "projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131",
    "named": "projects/clipforgebeta2/iap_tunnel/zones/us-central1-a/instances/clipforge-int-base-postgres"}
SELECTION_VARS = ("GOOGLE_CREDENTIALS", "GOOGLE_CLOUD_KEYFILE_JSON", "GCLOUD_KEYFILE_JSON",
                  "GOOGLE_OAUTH_ACCESS_TOKEN", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT",
                  "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT_DELEGATES", "GOOGLE_APPLICATION_CREDENTIALS",
                  "GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "GCP_ACCESS_TOKEN")
OVERRIDES = SELECTION_VARS[:6]
LOG_BUCKET = "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access"
LOG_VIEW = LOG_BUCKET + "/views/pilot-access"
POSTGRES_SA = "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"
READ_TARGETS = (
    ("grant_logging_bucket", "GET", "https://logging.googleapis.com/v2/" + LOG_BUCKET, None, "logging.buckets.get", LOG_BUCKET),
    *(("grant_secret_" + key, "GET", "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/" + name,
       None, "secretmanager.secrets.get", "projects/clipforgebeta2/secrets/" + name)
      for key, name in (("bootstrap", "clipforge-int-bootstrap-admin"), ("ca", "clipforge-int-postgres-ca"))),
    ("grant_postgres_policy", "POST", "https://iam.googleapis.com/v1/" + POSTGRES_SA + ":getIamPolicy?options.requestedPolicyVersion=3",
     None, "iam.serviceAccounts.getIamPolicy", POSTGRES_SA),
    ("grant_custom_role", "GET", "https://iam.googleapis.com/v1/projects/clipforgebeta2/roles/clipforgeIntBootstrapReader",
     None, "iam.roles.get", "projects/clipforgebeta2/roles/clipforgeIntBootstrapReader"),
    *(("secret_" + key + "_policy", "GET", "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/" + name
       + ":getIamPolicy?options.requestedPolicyVersion=3", None, "secretmanager.secrets.getIamPolicy",
       "projects/clipforgebeta2/secrets/" + name)
      for key, name in (("bootstrap", "clipforge-int-bootstrap-admin"), ("ca", "clipforge-int-postgres-ca"))),
    ("logging_sink", "GET", "https://logging.googleapis.com/v2/projects/clipforgebeta2/sinks/clipforge-int-access", None,
     "logging.sinks.get", "projects/clipforgebeta2/sinks/clipforge-int-access"),
    ("logging_view", "GET", "https://logging.googleapis.com/v2/" + LOG_VIEW, None, "logging.views.get", LOG_VIEW),
    ("logging_view_policy", "POST", "https://logging.googleapis.com/v2/" + LOG_VIEW + ":getIamPolicy",
     {"options": {"requestedPolicyVersion": 3}}, "logging.views.getIamPolicy", LOG_VIEW),
)


class ReferenceDifference(ValueError):
    def __init__(self, expected, observed):
        self.receipt = {"operation": "state_reference", "status": "current_reference_differs_no_guard_adoption",
                        "expected": expected, "observed": observed}
        super().__init__("Current state reference differs; only sanitized metadata is retained")


def instant(value):
    parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    c.require(parsed.tzinfo is not None, "Timezone required")
    return parsed


def load_contract(root=ROOT):
    contract = json.loads((root / CONFIG).read_bytes())
    c.require(contract.get("schema") == "clipforge-int-iap-read-diagnostic-1" and contract.get("grants_authorized") is False
              and contract.get("apply_authorized") is False, "Diagnostic cannot authorize mutations")
    c.require(contract["routes"] == ROUTES and contract["terraform_service_account"] == TF_SA,
              "Diagnostic principal or resources differ")
    c.require(contract.get("foundation_configuration_sha256") == "1cf09b8ebd357761a217b7cae3d46e37397eadff39deeaa79500aac5276a7a7c"
              and contract["provider_configuration_evidence"]["provider_config_key"] == "google"
              and contract["provider_configuration_evidence"]["provider_alias"] is None
              and not contract["provider_configuration_evidence"]["credential_expression_keys_present"],
              "The pending resource provider configuration no longer matches the reviewed default provider")
    return contract


def verify_provider_reference(root, contract):
    files = {name: custody.sha256((root / "infra/gcp/int-base" / name).read_bytes()) for name in c.FILES}
    c.require(custody.sha256(custody.canonical(files)) == contract["foundation_configuration_sha256"],
              "Foundation HCL/provider/alias configuration changed; do not substitute the diagnostic module")
    return {"configuration_sha256": custody.sha256(custody.canonical(files)), "source_files": files,
            "provider_config_key": "google", "alias": None, "credentials_expressions": []}


def credential_metadata(environ, document):
    """Return a closed metadata projection; never return credential-source data."""
    present = {name: bool(environ.get(name)) for name in SELECTION_VARS}
    target_url = document.get("service_account_impersonation_url", "")
    match = re.fullmatch(r"https://iamcredentials\.googleapis\.com/v1/projects/-/serviceAccounts/([^/:]+):generateAccessToken", target_url)
    target = match.group(1) if match else None
    valid = document.get("type") == "external_account" and target == TF_SA
    overrides = [name for name in OVERRIDES if present[name]]
    return {"configured_identity": TF_SA, "effective_identity": None,
            "effective_identity_proof": "requires_correlated_server_audit_event",
            "provider_config_key": "google", "provider_alias": None,
            "provider_expected_selection": "ADC" if not overrides else "override_present_not_reproduced",
            "explicit_preflight_selection": "GCP_ACCESS_TOKEN_not_a_provider_auth_variable",
            "environment_presence": present, "unexpected_overrides": overrides,
            "ADC": {"type": document.get("type") if document.get("type") in {"external_account", "service_account", "authorized_user"} else "unknown",
                    "configured_impersonation_target": target if target == TF_SA else "unexpected_or_missing",
                    "configured_target_matches": valid,
                    "credential_source_field_names": sorted(set(document.get("credential_source", {})) & {"url", "headers", "format", "file", "executable"}),
                    "unknown_source_field_count": len(set(document.get("credential_source", {})) - {"url", "headers", "format", "file", "executable"})}}


def policy_metadata(policy, expected, now=None):
    c.require(isinstance(policy, dict) and isinstance(policy.get("bindings", []), list), "Invalid IAM policy response")
    normalized = {key: value for key, value in policy.items() if key != "etag"}
    bindings = []
    direct = []
    for row in policy.get("bindings", []):
        c.require(isinstance(row, dict) and isinstance(row.get("members", []), list), "Invalid IAM binding response")
        cleaned = dict(row)
        cleaned["members"] = sorted(row.get("members", []))
        bindings.append(cleaned)
        if expected["member"] in row.get("members", []):
            condition = row.get("condition")
            direct.append({"role": row.get("role"), "condition_sha256": custody.sha256(custody.canonical(condition)),
                           "is_exact_reviewed_role": row.get("role") == expected["role"],
                           "condition_matches_reviewed": condition == expected["condition"]})
    normalized["bindings"] = sorted(bindings, key=custody.canonical)
    return {"policy_semantic_sha256": custody.sha256(custody.canonical(normalized)),
            "etag_sha256": custody.sha256(str(policy.get("etag", "")).encode()),
            "binding_count": len(bindings), "version": policy.get("version"),
            "Terraform_direct_bindings": sorted(direct, key=custody.canonical),
            "reviewed_binding_present_exactly": sum(row["is_exact_reviewed_role"] and row["condition_matches_reviewed"] for row in direct) == 1,
            "reviewed_binding_expiry_utc": expected["expires_utc"],
            "reviewed_binding_expired_now": (now or datetime.now(timezone.utc)) >= instant(expected["expires_utc"])}


def compare_matrix(rows):
    comparisons = []
    for dimension, pairs in (("authentication", [("numeric", "explicit_http", "numeric", "provider_ADC"),
                                                ("named", "explicit_http", "named", "provider_ADC")]),
                              ("route", [("numeric", "explicit_http", "named", "explicit_http"),
                                         ("numeric", "provider_ADC", "named", "provider_ADC")])):
        for left_route, left_mode, right_route, right_mode in pairs:
            left = next(row for row in rows if row["route"] == left_route and row["mode"] == left_mode)
            right = next(row for row in rows if row["route"] == right_route and row["mode"] == right_mode)
            readable = left.get("http_status") == right.get("http_status") == 200
            comparisons.append({"dimension": dimension, "left": [left_mode, left_route], "right": [right_mode, right_route],
                                "statuses": [left.get("http_status"), right.get("http_status")],
                                "policies_comparable": readable,
                                "policy_contents_equal": left["policy"]["policy_semantic_sha256"] == right["policy"]["policy_semantic_sha256"] if readable else None,
                                "Terraform_bindings_equal": left["policy"]["Terraform_direct_bindings"] == right["policy"]["Terraform_direct_bindings"] if readable else None,
                                "etag_equal": left["policy"]["etag_sha256"] == right["policy"]["etag_sha256"] if readable else None})
    return comparisons


def state_reference(raw, obj, inventory, contract):
    pin = contract["state_reference"]
    observed = {"name": obj["name"], "generation": str(obj["generation"]), "size": len(raw), "sha256": custody.sha256(raw)}
    expected_pin = {"name": driver.STATE_NAME, **{key: pin[key] for key in ("generation", "size", "sha256")}}
    if observed != expected_pin:
        raise ReferenceDifference(expected_pin, observed)
    live = [row for row in inventory["live"] if row["name"].startswith(c.PREFIX + "/")]
    c.require(len(live) == 1 and live[0]["name"] == driver.STATE_NAME and live[0]["generation"] == obj["generation"],
              "A current lock or another state object prevents diagnosis")
    state = json.loads(raw)
    c.require(state.get("lineage") == pin["lineage"] and type(state.get("serial")) is int and state.get("serial") == 6
              and state.get("terraform_version") == "1.15.8" and type(state.get("version")) is int
              and state.get("version") == 4, "State header differs from serial6 reference")
    addresses = []
    for resource in state.get("resources", []):
        c.require(not resource.get("module"), "Unreviewed module in current state")
        if resource.get("mode") == "data":
            c.require(resource["type"] in c.DATA_TYPES, "Unreviewed state data source")
            continue
        c.require(resource.get("mode") == "managed", "Unreviewed resource mode")
        for instance in resource.get("instances", []):
            c.require(not instance.get("deposed") and instance.get("status") in {None, "ready"}, "Tainted/deposed state requires review")
            name = resource["type"] + "." + resource["name"]
            if "index_key" in instance:
                name += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            addresses.append(name)
    expected = c.FOUNDATION_ADDRESSES - {"google_iap_tunnel_instance_iam_member.protected_bootstrap"}
    c.require(len(addresses) == 41 and set(addresses) == expected and set(state.get("outputs", {})) <= {"reviewed_boundary"},
              "The 41 registered addresses differ; no automatic state adoption")
    return {"generation": obj["generation"], "sha256": custody.sha256(raw), "serial": 6, "lineage": state["lineage"],
            "managed_addresses": sorted(addresses), "current_lock": False}


def direct_probe(route, token, reason):
    c.require(route in ROUTES and re.fullmatch(r"[A-Za-z0-9 ]{1,180}", reason), "Unreviewed IAP read")
    request = Request("https://iap.googleapis.com/v1/" + ROUTES[route] + ":getIamPolicy?alt=json",
                      data=b'{"options":{"requestedPolicyVersion":3}}', method="POST",
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json", "X-Goog-Request-Reason": reason})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(1024 * 1024 + 1)
        c.require(len(raw) <= 1024 * 1024, "Private IAM policy exceeds bound")
        return {"http_status": 200, "private_policy": json.loads(raw)}
    except HTTPError as error:
        raw = error.read(16384)
        try:
            body = json.loads(raw).get("error", {})
            status = body.get("status") if body.get("status") in {"PERMISSION_DENIED", "NOT_FOUND", "UNAUTHENTICATED"} else "other"
        except (ValueError, AttributeError):
            status = "unstructured_error_withheld"
        return {"http_status": error.code, "operation": "getIamPolicy", "error_status": status,
                "required_permission_for_operation": "iap.tunnelInstances.getIamPolicy",
                "resource": ROUTES[route], "raw_error_withheld": True}


def direct_identity_anchor(token, reason):
    """Auditable bucket metadata GET using exactly the preflight bearer token."""
    c.require(bool(re.fullmatch(r"[A-Za-z0-9 ]{1,180}", reason)), "Invalid diagnostic correlation reason")
    request = Request("https://storage.googleapis.com/storage/v1/b/clipforgebeta2-int-media?fields=name",
                      headers={"Authorization": "Bearer " + token, "X-Goog-Request-Reason": reason})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(65537)
        c.require(len(raw) <= 65536 and json.loads(raw).get("name") == "clipforgebeta2-int-media", "Unexpected identity anchor metadata")
        status = 200
    except HTTPError as error:
        status = error.code
    return {"bucket": "clipforgebeta2-int-media", "operation": "storage.buckets.get", "http_status": status,
            "reason": reason, "effective_identity": None, "proof": "requires_authenticated_server_audit_event"}


def required_reads(token, reason):
    """Read only ten fixed metadata/policy endpoints; publish no response values."""
    c.require(bool(re.fullmatch(r"[A-Za-z0-9 ]{1,150}", reason)), "Invalid read correlation reason")
    rows = []
    for key, method, url, body, permission, resource in READ_TARGETS:
        started = datetime.now(timezone.utc).isoformat()
        request = Request(url, method=method, data=custody.canonical(body) if body is not None else None,
                          headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                                   "X-Goog-Request-Reason": reason})
        row = {"key": key, "category": "grant_verification" if key.startswith("grant_") else "dependent_read",
               "method": method, "resource": resource, "required_permission_for_operation": permission,
               "started_utc": started, "authentication": "same_explicit_WIF_token_as_IAP_matrix"}
        try:
            with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=45) as response:
                raw = response.read(1024 * 1024 + 1)
            c.require(len(raw) <= 1024 * 1024 and isinstance(json.loads(raw), dict), "Bounded metadata JSON required")
            row.update(http_status=200, private_response_sha256=custody.sha256(raw), private_response_bytes=len(raw))
        except HTTPError as error:
            row.update(http_status=error.code, response_payload_withheld=True)
        except (OSError, ValueError):
            row.update(http_status=None, error="transport_or_invalid_private_response", response_payload_withheld=True)
        row["completed_utc"] = datetime.now(timezone.utc).isoformat()
        rows.append(row)
    return rows


def reads_allow_plan(result):
    rows = result.get("required_reads", [])
    return (len(rows) == len(READ_TARGETS) and {row.get("key") for row in rows} == {row[0] for row in READ_TARGETS}
            and all(row.get("http_status") == 200 for row in rows)
            and len(result.get("probes", [])) == 4
            and {(row.get("route"), row.get("mode")) for row in result["probes"]}
            == {(route, mode) for route in ROUTES for mode in ("explicit_http", "provider_ADC")}
            and all(row.get("http_status") == 200 for row in result["probes"]))


def run_diagnostic(work, reports, environ, root=ROOT):
    custody.hosted_context(environ)
    c.validate_variables(environ)
    c.require(environ.get("INT_REVIEWED_CONTROLS_COMMIT") == environ.get("GITHUB_SHA"), "Exact diagnostic control commit required")
    contract = load_contract(root)
    source_proof = verify_provider_reference(root, contract)
    adc = Path(environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    c.require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json", "Fresh Actions ADC file required")
    metadata = credential_metadata(environ, json.loads(adc.read_bytes()))
    c.require(metadata["ADC"]["configured_target_matches"] and not metadata["unexpected_overrides"], "Unexpected credential selection; metadata only, no native probe")
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    raw, obj, inventory = states.private_current_state(bucket)
    proof = state_reference(raw, obj, inventory, contract)
    after = driver.backend_inventory(bucket)
    state_reference(raw, obj, after, contract)
    run_id = environ["GITHUB_RUN_ID"]
    c.require(bool(re.fullmatch(r"[1-9][0-9]*", run_id)), "Run identity required")
    rows = []
    for route in ROUTES:
        reason = "ClipForge IAP diagnostic run " + run_id + " explicit " + route
        anchor = direct_identity_anchor(environ["GCP_ACCESS_TOKEN"], reason)
        result = direct_probe(route, environ["GCP_ACCESS_TOKEN"], reason)
        policy = result.pop("private_policy", None)
        row = {"route": route, "mode": "explicit_http", "resource": ROUTES[route], "library": "Python urllib HTTPS; not provider transport",
               "reason": reason, "identity_anchor": anchor, **result}
        if policy is not None:
            row["policy"] = policy_metadata(policy, contract["expired_binding"])
        rows.append(row)
        native_reason = "ClipForge IAP diagnostic run " + run_id + " provider ADC " + route
        result = native.run_native(work / ("native-" + route), route, native_reason, source_root=root)
        policy = result.pop("policy", None)
        c.require(set(result) <= {"native_exit", "phase", "errors", "library", "reason", "route", "identity_anchor_bucket",
                                "configured_identity_is_observed_identity", "backend"}, "Unreviewed native diagnostic result field")
        status = 200 if policy is not None else next((error["status"] for error in result.get("errors", [])
                       if "iap.tunnelInstances.getIamPolicy" in error.get("permissions", [])), None)
        row = {"route": route, "mode": "provider_ADC", "resource": ROUTES[route], "http_status": status, **result}
        if policy is not None:
            row["policy"] = policy_metadata(policy, contract["expired_binding"])
        rows.append(row)
    dependencies = required_reads(environ["GCP_ACCESS_TOKEN"], "ClipForge IAP diagnostic required reads run " + run_id)
    state_reference(raw, obj, driver.backend_inventory(bucket), contract)
    return {"schema": "clipforge-int-iap-diagnostic-result-1", "status": "read_comparison_completed_no_grants_no_apply",
            "controls_commit": environ["GITHUB_SHA"], "credentials": metadata, "provider_source": source_proof,
            "state_reference": proof, "comparisons": compare_matrix(rows), "probes": rows, "required_reads": dependencies,
            "historical_403_before_original_expiry": instant(contract["historical_failure_utc"]) < instant(contract["expired_binding"]["expires_utc"]),
            "original_binding_expired_now": datetime.now(timezone.utc) >= instant(contract["expired_binding"]["expires_utc"]),
            "historical_cause": "not_inferred_from_current_expired_grant_or_administrator_reads",
            "identity_effective_audit_validation": "pending_correlated_server_events_no_assumption_from_configured_target",
            "new_apply_authorized": False, "new_grants_authorized": False}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["check", "diagnose"])
    args = parser.parse_args()
    if args.operation == "check":
        verify_provider_reference(ROOT, load_contract())
        print("Bounded IAP diagnostic source verified; no cloud operation.")
        return 0
    os.umask(0o077)
    work, reports = driver.private_paths()
    try:
        result = run_diagnostic(work, reports, os.environ)
        code = 0
    except Exception as error:
        result = {"schema": "clipforge-int-iap-diagnostic-result-1", "status": "blocked_no_grants_no_apply", "error":
                  getattr(error, "receipt", {"operation": "diagnostic_preflight", "error_type": type(error).__name__}),
                  "new_grants_authorized": False, "new_apply_authorized": False}
        code = 1
    (reports / "iap-diagnostic.json").write_text(json.dumps(result, indent=2) + "\n")
    (reports / "iap-diagnostic.md").write_text("# IAP read diagnostic\n\nStatus: " + result["status"] + "\n\nNo grants or apply. Native policies/plans/credentials are private scratch only.\n")
    if code == 0 and os.environ.get("IAP_ATTEMPT_RECOVERY_PLAN") == "true":
        from scripts import int_foundation_recovery as recovery
        contract = recovery.load_contract()
        if contract.get("recovery_phase") != "serial6_no_imports":
            plan_result = {"status": "plan_not_run_serial6_guard_not_activated", "apply_authorized": False,
                           "reason": "Current reference must be verified before the active guard is changed"}
            recovery.save_summary(reports, plan_result)
        elif not reads_allow_plan(result):
            recovery.save_summary(reports, {"status": "blocked_required_reads_no_plan_no_apply", "apply_authorized": False,
                                  "required_reads": result["required_reads"], "IAP_comparisons": result["comparisons"]})
            code = 1
        else:
            # All original HCL is pinned. No import file is copied: the five
            # completed imports are already registered in the serial6 state.
            module = work / "module"
            module.mkdir()
            for name in c.FILES:
                path = module / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes((ROOT / "infra/gcp/int-base" / name).read_bytes())
            (work / "terraform.rc").write_text("provider_installation {\n  direct {}\n}\n")
            try:
                plan_result = recovery.plan_recovery(work, reports, os.environ)
                code = int(plan_result["status"] != "recovery_plan_requires_new_review")
            except Exception as error:
                diagnostic = getattr(error, "receipt", {"operation": "serial6_plan_preflight", "error_type": type(error).__name__})
                if (work / "recovery_plan.log").is_file():
                    diagnostic = recovery.sanitized_native_errors((work / "recovery_plan.log").read_bytes())
                recovery.save_summary(reports, {"status": "blocked_serial6_refresh_no_apply_no_retry", "apply_authorized": False, "error": diagnostic})
                code = 1
    print("IAP diagnostic: " + result["status"] + "; only sanitized evidence retained.")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
