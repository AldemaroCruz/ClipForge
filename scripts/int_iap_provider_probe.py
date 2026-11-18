"""Private, data-source-only reproduction of the Google 8.11 IAP read path.

The returned ``policy`` is PRIVATE input for the caller's allowlisted summary.
It must never be logged or uploaded. This module does not select credentials:
the frozen Terraform driver inherits the caller's ADC environment unchanged.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re

from scripts import check_tf_int as contract
from scripts import tf_int_plan as driver


ROOT = Path(__file__).resolve().parents[1]
PROJECT = "clipforgebeta2"
NUMBER = "816643438938"
ZONE = "us-central1-a"
MEDIA_BUCKET = "clipforgebeta2-int-media"
PROVIDER_VERSION = "8.11.0"
PROVIDER_SOURCE_COMMIT = "67f96115b523ba050b11dad30237f14023667de8"
PROVIDER_LOCK_SHA256 = "89e2189a1b882ac5ad3ce74ad17a304e95cf7fa072b9ced86fce09e78b88b5fa"
ROUTES = {
    "numeric": {"project": NUMBER, "instance": "1670495097211408131"},
    "named": {"project": PROJECT, "instance": "clipforge-int-base-postgres"},
}
DATA = {
    "data.google_iap_tunnel_instance_iam_policy.probe":
        ("google_iap_tunnel_instance_iam_policy", "probe"),
    "data.google_storage_bucket.identity": ("google_storage_bucket", "identity"),
}
MAX_PLAN_BYTES = 8 * 1024 * 1024
MAX_POLICY_BYTES = 1024 * 1024


def _parameters(route, reason):
    contract.require(isinstance(route, str) and route in ROUTES, "Unreviewed IAP route")
    # Punctuation makes Google encode a reason in Audit Logs. A simple unique
    # ASCII label can be matched literally without exposing a token or URL.
    contract.require(isinstance(reason, str)
                     and re.fullmatch(r"[A-Za-z0-9]+(?: [A-Za-z0-9]+)*", reason)
                     and len(reason) <= 160, "Invalid public diagnostic request reason")


def native_module(route, reason):
    """Return the complete isolated .tf.json module, with no backend or writes."""
    _parameters(route, reason)
    return {
        "terraform": {
            "required_version": "= 1.15.8",
            "required_providers": {
                "google": {"source": "hashicorp/google", "version": "= 8.11.0"},
            },
        },
        "provider": {"google": {
            "project": PROJECT, "region": "us-central1", "zone": ZONE,
            "request_reason": reason,
        }},
        "data": {
            "google_storage_bucket": {"identity": {
                "project": PROJECT, "name": MEDIA_BUCKET,
            }},
            "google_iap_tunnel_instance_iam_policy": {"probe": {
                **ROUTES[route], "zone": ZONE,
                # The audit anchor must finish even when the following IAP
                # policy read fails. All inputs are known during planning.
                "depends_on": ["data.google_storage_bucket.identity"],
            }},
        },
    }


def validate_native_module(value, route, reason):
    """Reject any additional provider option, source, output or operation."""
    contract.require(value == native_module(route, reason),
                     "Native diagnostic module differs from its exact read-only contract")


def _data_rows(module, *, complete):
    contract.require(isinstance(module, dict) and not module.get("child_modules"),
                     "Diagnostic plans cannot contain child modules")
    rows = module.get("resources", [])
    contract.require(isinstance(rows, list), "Invalid diagnostic data resources")
    addresses = []
    for row in rows:
        contract.require(isinstance(row, dict) and row.get("mode") == "data"
                         and row.get("address") in DATA,
                         "Diagnostic plan contains a managed or unreviewed resource")
        expected_type, expected_name = DATA[row["address"]]
        contract.require(row.get("type") == expected_type and row.get("name") == expected_name
                         and row.get("provider_name") == "registry.terraform.io/hashicorp/google",
                         "Diagnostic data source identity differs")
        addresses.append(row["address"])
    contract.require(len(addresses) == len(set(addresses))
                     and (set(addresses) == set(DATA) if complete else set(addresses) <= set(DATA)),
                     "Diagnostic data source coverage differs")
    return rows


def extract_policy(plan_json):
    """Validate a successful data-only plan and return its private IAP policy."""
    contract.require(isinstance(plan_json, dict), "Invalid private diagnostic plan")
    contract.require(plan_json.get("terraform_version") == "1.15.8",
                     "Diagnostic Terraform version differs")
    planned = plan_json.get("planned_values", {})
    contract.require(isinstance(planned, dict) and planned.get("outputs", {}) == {}
                     and plan_json.get("output_changes", {}) == {}, "Diagnostic outputs are forbidden")
    rows = _data_rows(planned.get("root_module", {}), complete=True)
    prior = plan_json.get("prior_state")
    if prior is not None:
        contract.require(isinstance(prior, dict), "Invalid diagnostic prior values")
        prior_values = prior.get("values", {})
        contract.require(isinstance(prior_values, dict) and prior_values.get("outputs", {}) == {},
                         "Diagnostic prior outputs are forbidden")
        _data_rows(prior_values.get("root_module", {}), complete=False)
    for field in ("resource_changes", "resource_drift"):
        changes = plan_json.get(field, [])
        contract.require(isinstance(changes, list), "Invalid diagnostic change list")
        _data_rows({"resources": changes}, complete=False)
        for row in changes:
            change = row.get("change", {})
            contract.require(isinstance(change, dict)
                             and change.get("actions") in (["read"], ["no-op"]),
                             "Diagnostic plan contains a mutation action")
    source = next(row for row in rows if row["address"] == "data.google_iap_tunnel_instance_iam_policy.probe")
    values = source.get("values")
    contract.require(isinstance(values, dict), "Diagnostic IAP data values are missing")
    raw = values.get("policy_data")
    contract.require(isinstance(raw, str) and len(raw.encode("utf-8")) <= MAX_POLICY_BYTES,
                     "Diagnostic IAP policy is missing or exceeds its private bound")
    try:
        policy = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("Invalid private diagnostic IAP policy JSON") from None
    contract.require(isinstance(policy, dict) and isinstance(policy.get("bindings", []), list),
                     "Invalid private diagnostic IAP policy shape")
    return policy


def _diagnostic(operation, text, native_exit):
    """Keep the existing sanitizer, then reduce publication to known fields."""
    match = re.search(r"(?:googleapi: Error |HTTP(?: Error)?[ :]+)([1-5][0-9]{2})\b", text)
    status = int(match.group(1)) if match else None
    sanitized = contract.diagnostic(operation, text, status)
    # The existing sanitizer predates IAP. Add only these two fixed identifiers;
    # never copy an arbitrary API response or Terraform diagnostic into a report.
    iap_permissions = [permission for permission in (
        "iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.setIamPolicy",
    ) if permission in text]
    permission_allowlist = {
        "storage.buckets.get", "serviceusage.services.use",
        "iam.serviceAccounts.getAccessToken", "iam.serviceAccounts.implicitDelegation",
        "iap.tunnelInstances.getIamPolicy", "iap.tunnelInstances.setIamPolicy",
    }
    permissions = sorted((set(sanitized["permissions"]) | set(iap_permissions)) & permission_allowlist)
    allowed_resources = {
        "projects/" + values["project"] + "/iap_tunnel/zones/" + ZONE + "/instances/" + values["instance"]
        for values in ROUTES.values()
    }
    resources = [resource for resource in sanitized["resources"] if resource in allowed_resources]
    if status == 403 and "iap.tunnelInstances.getIamPolicy" in iap_permissions:
        message = "IAP getIamPolicy returned HTTP 403; full diagnostic remains private."
    elif status is not None:
        message = "Native provider returned HTTP " + str(status) + "; full diagnostic remains private."
    else:
        message = "Native diagnostic did not complete; full diagnostic remains private."
    return {"operation": operation, "status": status, "native_exit": native_exit,
            "permissions": permissions[:20], "resources": resources[:2], "messages": [message]}


def _library_metadata():
    return {
        "terraform_version": "1.15.8", "google_provider_version": PROVIDER_VERSION,
        "provider_source_commit": PROVIDER_SOURCE_COMMIT,
        "provider_lock_sha256": PROVIDER_LOCK_SHA256,
        "iap_updater": "IapTunnelInstanceIamUpdater.GetResourceIamPolicy",
        "read_wrapper": "DatasourceIamPolicyRead/iamPolicyReadWithRetry",
        "managed_read_uses_same_updater": True,
        "wrapper_is_managed_resource_read": False,
        "native_read_retry_timeout_seconds": 600,
        "credentials_selected_here": False,
        "identity_requires_correlated_audit_event": True,
    }


def _no_state_files(work):
    # This is a fresh local module, with no backend block or previous state.
    # Terraform's transient native lock is allowed during plan, never bypassed.
    contract.require(not any(path.is_file() and (
        path.name.endswith((".tfstate", ".tfstate.backup"))
        or path.name == ".terraform.tfstate.lock.info") for path in work.rglob("*")),
        "Data-only diagnostic unexpectedly retained a state or lock file")


def run_native(work, route, reason, *, source_root=ROOT):
    """Run init/plan/show in an empty private child; return no public payloads.

    ``policy`` in the successful return is private. The caller must remove it
    after deriving an explicit summary. All native output stays under ``work``;
    workflow cleanup must remove that dedicated scratch, including on failure.
    A 403 is a diagnostic outcome, not proof about a historical authorization.
    """
    module = native_module(route, reason)
    validate_native_module(module, route, reason)
    work, source_root = Path(work), Path(source_root).resolve()
    contract.require(not work.is_symlink(), "Private diagnostic scratch cannot be a symlink")
    work = work.resolve()
    contract.require(not work.is_relative_to(source_root) and not source_root.is_relative_to(work),
                     "Private diagnostic scratch must not overlap the checkout")
    contract.require(not work.exists() or (work.is_dir() and not any(work.iterdir())),
                     "Native diagnostic requires a new empty private directory")
    contract.require(not any(key.startswith(("TF_VAR_", "TF_CLI_ARGS", "TF_LOG")) for key in os.environ),
                     "Ambient Terraform options or debug logging are forbidden")
    lock = (source_root / "infra/gcp/int-base/.terraform.lock.hcl").read_bytes()
    contract.require(hashlib.sha256(lock).hexdigest() == PROVIDER_LOCK_SHA256,
                     "The pinned Google provider lock differs")
    work.mkdir(mode=0o700, parents=True, exist_ok=True)
    (work / "module").mkdir(mode=0o700)
    (work / "module/main.tf.json").write_text(json.dumps(module, indent=2) + "\n", encoding="utf-8", newline="\n")
    (work / "module/.terraform.lock.hcl").write_bytes(lock)
    (work / "terraform.rc").write_text("provider_installation {\n  direct {}\n}\n", encoding="utf-8", newline="\n")
    result = {"native_exit": None, "phase": "initialization", "errors": [],
              "library": _library_metadata(), "reason": reason, "route": route,
              "identity_anchor_bucket": MEDIA_BUCKET,
              "configured_identity_is_observed_identity": False,
              "backend": "isolated_local_module_without_backend_configuration"}
    binary = driver.terraform_binary()
    init_exit, _ = driver.run([binary, "init", "-backend=false", "-lockfile=readonly", "-input=false", "-no-color"],
                              "iap_diag_init", work, accepted=(0, 1))
    if init_exit != 0:
        text = (work / "iap_diag_init.log").read_text(encoding="utf-8", errors="replace")
        result["errors"] = [_diagnostic("iap_diag_init", text, init_exit)]
        return result
    plan_path = work / "diagnostic.tfplan"
    result["phase"] = "plan"
    plan_exit, _ = driver.run([binary, "plan", "-input=false", "-lock=true", "-lock-timeout=60s",
                               "-detailed-exitcode", "-no-color", "-out=" + str(plan_path)],
                              "iap_diag_plan", work, accepted=(0, 1, 2))
    result["native_exit"] = plan_exit
    _no_state_files(work)
    if plan_exit == 1:
        text = (work / "iap_diag_plan.log").read_text(encoding="utf-8", errors="replace")
        result["errors"] = [_diagnostic("iap_diag_plan", text, plan_exit)]
        return result
    result["phase"] = "show"
    _, raw = driver.run([binary, "show", "-json", str(plan_path)], "iap_diag_show", work)
    contract.require(len(raw) <= MAX_PLAN_BYTES, "Private diagnostic plan exceeds its size bound")
    try:
        plan_json = json.loads(raw)
    except (ValueError, TypeError):
        raise ValueError("Invalid private diagnostic Terraform JSON") from None
    result["policy"] = extract_policy(plan_json)
    _no_state_files(work)
    result["phase"] = "complete"
    return result
