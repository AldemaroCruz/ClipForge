"""Compare explicit foundation plans without executing tools or revealing private values.

The callable accepts parsed JSON; the CLI additionally verifies the raw JSON
bytes against each private manifest. Neither interface authorizes an apply.
"""
from __future__ import annotations

import argparse
from datetime import datetime
import hashlib
import json
from pathlib import Path
import re


ROOT = Path(__file__).resolve().parents[1]
MAX_BYTES = 64 * 1024 * 1024
SCHEMA = "clipforge-int-foundation-comparison-1"
_MISSING = object()
# Only root-level custody fields may change during renewal. There is deliberately
# no configurable path-ignore mechanism and no recursive removal of timestamps.
PLAN_VOLATILE = frozenset({"timestamp"})
MANIFEST_CUSTODY = frozenset({"commit", "run_id", "run_attempt", "created_utc", "binary", "json"})
FOUNDATION_ADDRESSES = frozenset({
    "google_compute_address.postgres", "google_compute_disk.postgres",
    "google_compute_firewall.deny_egress", "google_compute_firewall.https",
    "google_compute_firewall.iap", "google_compute_firewall.postgres",
    "google_compute_instance.postgres", "google_compute_instance_iam_member.protected_bootstrap",
    "google_compute_network.int", "google_compute_route.egress", "google_compute_router.egress",
    "google_compute_router_nat.maintenance", 'google_compute_subnetwork.private["postgres"]',
    'google_compute_subnetwork.private["run"]', "google_iap_tunnel_instance_iam_member.protected_bootstrap",
    "google_logging_log_view.access", "google_logging_log_view_iam_member.audit_reader",
    "google_logging_project_bucket_config.access", "google_logging_project_sink.access",
    "google_project_iam_audit_config.storage_access", "google_project_iam_custom_role.bootstrap_reader",
    "google_project_iam_member.bootstrap_reader", 'google_secret_manager_secret.runtime["bootstrap-admin"]',
    'google_secret_manager_secret.runtime["postgres-ca"]',
    *{'google_secret_manager_secret_iam_member.runtime["' + key + '"]' for key in
      ("api_ca", "api_password", "bootstrap_admin", "migrate_ca", "migrate_password", "worker_ca", "worker_password")},
    *{'google_secret_manager_secret_iam_member.version_publisher["' + key + '"]' for key in
      ("app_password", "bootstrap_admin", "migrator_password", "postgres_ca")},
    "google_service_account_iam_member.protected_bootstrap", 'google_storage_bucket.private["backups"]',
    'google_storage_bucket.private["media"]', "google_storage_bucket_iam_member.backup_writer",
    'google_storage_bucket_iam_member.media["api"]', 'google_storage_bucket_iam_member.media["worker"]',
    "terraform_data.boundary",
})
VARIABLES = frozenset({"project_id", "machine_type", "run_subnet_cidr", "postgres_subnet_cidr",
                       "data_disk_gb", "runtime_image", "secret_versions", "stage"})
_PUBLIC_FIELDS = frozenset((
    "plan manifest resource_changes planned_values prior_state configuration variables root_module resources "
    "outputs output_changes checks relevant_attributes format_version terraform_version provider_config "
    "address mode type name provider_name change actions before after after_unknown before_sensitive "
    "after_sensitive after_identity value values sensitive expressions constant_value references "
    "provider_config_key count_expression for_each_expression depends_on schema_version index "
    "metadata metadata_startup_script machine_type boot_disk initialize_params image attached_disk "
    "disk_size_gb size disk_type auto_delete deletion_protection source device_name "
    "network_interface access_config network_ip nat_ip network subnetwork ip_cidr_range "
    "source_ranges destination_ranges allow deny ports protocol direction priority disabled "
    "target_service_accounts source_service_accounts role member members permissions service_account "
    "email scopes service audit_log_config log_type exempted_members filter destination exclusions "
    "retention_days retention_policy retention_period is_locked logging log_bucket log_object_prefix "
    "versioning enabled uniform_bucket_level_access public_access_prevention force_destroy "
    "replication auto location labels effective_labels terraform_labels id project region zone "
    "secret_id secret_data password private_key private_key_pem client_secret access_token refresh_token "
    "disk_encryption_key_raw disk_encryption_key_rsa api app_password migrator_password postgres_ca "
    "bootstrap_admin project_id data_disk_gb run_subnet_cidr postgres_subnet_cidr runtime_image "
    "secret_versions stage complete applyable errored backend bucket prefix workspace lineage serial "
    "state_generation state_sha256 configuration_sha256 provider_lock_sha256 inputs repository branch "
    "schema approval runtime_published commit run_id run_attempt created_utc binary json generation sha256 "
    "timestamp tls certificate settings parent lock_time_timeout prevent_destroy secure_boot "
    "enable_secure_boot enable_vtpm enable_integrity_monitoring shielded_instance_config "
    "private_ip_google_access stack_type enable_flow_logs log_config flow_sampling aggregation_interval "
    "enable_oslogin block_project_ssh_keys lifecycle_rule condition action age days_since_noncurrent_time "
    "num_newer_versions soft_delete_policy retention_duration_seconds"
).split())
_SECRET_FIELDS = frozenset({"secret_data", "password", "private_key", "private_key_pem", "client_secret",
                            "access_token", "refresh_token", "disk_encryption_key_raw", "disk_encryption_key_rsa"})


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def _sha(value):
    if value is _MISSING:
        raw = b"clipforge-comparison-absent"
    else:
        raw = value.encode("utf-8") if isinstance(value, str) else _canonical(value)
    return hashlib.sha256(raw).hexdigest()


def _segment(value):
    if isinstance(value, int):
        return str(value)
    if value in _PUBLIC_FIELDS or value in FOUNDATION_ADDRESSES:
        return value.replace("~", "~0").replace("/", "~1")
    return "field@" + _sha(value)[:20]


def _path(parts):
    return "/" + "/".join(_segment(part) for part in parts)


def _category(parts):
    text = "/".join(map(str, parts)).lower()
    for word, category in (("metadata_startup_script", "vm_startup"), ("secret", "secrets"),
                           ("iam", "iam"), ("audit", "audit"), ("logging", "audit"),
                           ("firewall", "network"), ("network", "network"), ("subnet", "network"),
                           ("disk", "disks"), ("google_compute_instance", "vm")):
        if word in text:
            return category
    return "manifest_binding" if parts[0] == "manifest" else "plan_configuration"


def _public(value, parts, hidden):
    if hidden or value is _MISSING:
        return False
    field = parts[-1]
    address = next((part for part in parts if part in FOUNDATION_ADDRESSES), "")
    if not address or "metadata" in parts or not ("after" in parts or "values" in parts):
        return False
    if field == "image" and address == "google_compute_instance.postgres" and "boot_disk" in parts and "initialize_params" in parts:
        return isinstance(value, str) and bool(re.fullmatch(
            r"(?:https://www\.googleapis\.com/compute/v1/projects/)?debian-cloud/(?:global/)?images/debian-[a-z0-9-]+", value))
    if field == "role" and "_iam_" in address:
        return isinstance(value, str) and bool(re.fullmatch(r"(?:roles/[A-Za-z0-9.]+|projects/clipforgebeta2/roles/[A-Za-z0-9_]+)", value))
    if field == "member" and "_iam_" in address:
        return isinstance(value, str) and bool(re.fullmatch(
            r"(?:serviceAccount:[A-Za-z0-9._-]+@(?:clipforgebeta2|gcp-sa-iap)\.iam\.gserviceaccount\.com|user:admin@ixbalam\.studio|allUsers|allAuthenticatedUsers)", value))
    if field in {"size", "disk_size_gb"} and (address == "google_compute_disk.postgres" or "boot_disk" in parts):
        return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65536
    if address.startswith("google_compute_firewall.") and (field == "ports" or (isinstance(field, int) and "ports" in parts)):
        candidates = value if isinstance(value, list) else [value]
        return bool(candidates) and all(isinstance(v, str) and re.fullmatch(r"[0-9]{1,5}(?:-[0-9]{1,5})?", v) for v in candidates)
    return False


def _sensitive_paths(value, mask, parts, result):
    if mask is True:
        result.add(parts)
    elif isinstance(mask, dict):
        for key, child in mask.items():
            _sensitive_paths(value.get(key) if isinstance(value, dict) else None, child, parts + (key,), result)
    elif isinstance(mask, list):
        for index, child in enumerate(mask):
            _sensitive_paths(value[index] if isinstance(value, list) and index < len(value) else None,
                             child, parts + (index,), result)


def _collect_sensitive(value, parts, result):
    if isinstance(value, dict):
        if "values" in value and "sensitive_values" in value:
            _sensitive_paths(value["values"], value["sensitive_values"], parts + ("values",), result)
        if isinstance(value.get("change"), dict):
            for field in ("before", "after"):
                _sensitive_paths(value["change"].get(field), value["change"].get(field + "_sensitive"),
                                 parts + ("change", field), result)
        for key, child in value.items():
            _collect_sensitive(child, parts + (key,), result)
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _collect_sensitive(child, parts + (index,), result)


def _normal(value, parts=()):
    if isinstance(value, dict):
        return {key: _normal(child, parts + (key,)) for key, child in value.items()}
    if isinstance(value, list):
        # Terraform's resource collection order is not an input. Attribute lists
        # such as interfaces, IAM conditions and disks retain their exact order.
        if parts and parts[-1] in {"resources", "resource_changes"} and all(
                isinstance(child, dict) and isinstance(child.get("address"), str) for child in value):
            addresses = [child["address"] for child in value]
            if len(addresses) == len(set(addresses)):
                return {child["address"]: _normal(child, parts + (child["address"],)) for child in value}
        return [_normal(child, parts + (index,)) for index, child in enumerate(value)]
    return value


def _diff(old, new, parts, output, sensitive):
    if type(old) is type(new) and old == new:
        return
    if isinstance(old, dict) and isinstance(new, dict):
        for key in sorted(set(old) | set(new)):
            _diff(old.get(key, _MISSING), new.get(key, _MISSING), parts + (key,), output, sensitive)
        return
    if isinstance(old, list) and isinstance(new, list) and len(old) == len(new):
        for index, (left, right) in enumerate(zip(old, new)):
            _diff(left, right, parts + (index,), output, sensitive)
        return
    hidden = any(parts[:len(prefix)] == prefix for prefix in sensitive)
    row = {"path": _path(parts), "category": _category(parts), "old_sha256": _sha(old), "new_sha256": _sha(new),
           "old_present": old is not _MISSING, "new_present": new is not _MISSING}
    if _public(old, parts, hidden):
        row["old_public_value"] = old
    if _public(new, parts, hidden):
        row["new_public_value"] = new
    output.append(row)


def _module_resources(module):
    if not isinstance(module, dict):
        return []
    result = list(module.get("resources", []))
    for child in module.get("child_modules", []):
        result.extend(_module_resources(child))
    return result


def _secret_values(value):
    if isinstance(value, dict):
        return any((key in _SECRET_FIELDS and child is not None and child is not False)
                   or _secret_values(child) for key, child in value.items()
                   if key not in {"after_sensitive", "before_sensitive", "sensitive_values"})
    return isinstance(value, list) and any(_secret_values(child) for child in value)


def _sensitive_payload(value, mask):
    if mask is True:
        return value is not None
    if isinstance(mask, dict):
        return any(_sensitive_payload(value.get(key) if isinstance(value, dict) else None, child)
                   for key, child in mask.items())
    if isinstance(mask, list):
        return any(_sensitive_payload(value[index] if isinstance(value, list) and index < len(value) else None, child)
                   for index, child in enumerate(mask))
    return False


def _has_sensitive_payload(value):
    if isinstance(value, dict):
        if any(_sensitive_payload(value.get(field), value.get(field + "_sensitive")) for field in ("before", "after")):
            return True
        if _sensitive_payload(value.get("values"), value.get("sensitive_values")):
            return True
        return any(_has_sensitive_payload(child) for child in value.values())
    return isinstance(value, list) and any(_has_sensitive_payload(child) for child in value)


def _timestamp(value):
    try:
        return isinstance(value, str) and datetime.fromisoformat(value.replace("Z", "+00:00")).tzinfo is not None
    except ValueError:
        return False


def _guard(plan, manifest, side, faults):
    def require(condition, category):
        if not condition:
            faults.append({"side": side, "category": category})
    require(isinstance(plan, dict) and isinstance(manifest, dict), "document_shape")
    if not isinstance(plan, dict) or not isinstance(manifest, dict):
        return
    changes = plan.get("resource_changes")
    require(isinstance(changes, list) and all(isinstance(row, dict) for row in changes), "resource_shape")
    changes = changes if isinstance(changes, list) and all(isinstance(row, dict) for row in changes) else []
    addresses = [row.get("address") for row in changes]
    require(len(addresses) == 42 and all(isinstance(v, str) for v in addresses)
            and set(addresses) == FOUNDATION_ADDRESSES, "exact_foundation_scope")
    require(all(row.get("mode") == "managed" and isinstance(row.get("change"), dict)
                and row["change"].get("actions") == ["create"] and row["change"].get("before") is None
                and isinstance(row["change"].get("after"), dict) for row in changes), "create_only_initial_state")
    require(not any(row.get("mode") == "managed" for row in _module_resources(
        plan.get("prior_state", {}).get("values", {}).get("root_module", {}))), "prior_managed_resources")
    planned = _module_resources(plan.get("planned_values", {}).get("root_module", {}))
    require(len(planned) == 42 and all(isinstance(row, dict) and row.get("mode") == "managed" for row in planned)
            and {row.get("address") for row in planned} == FOUNDATION_ADDRESSES, "planned_value_scope")
    variables = plan.get("variables", {})
    require(isinstance(variables, dict) and set(variables) == VARIABLES, "effective_variable_scope")
    require(isinstance(variables, dict) and variables.get("secret_versions") == {"value": None}, "secret_versions_forbidden")
    require(isinstance(variables, dict) and variables.get("stage") == {"value": "foundation"}
            and variables.get("project_id") == {"value": "clipforgebeta2"}, "foundation_project_inputs")
    require(not _secret_values(plan) and not _has_sensitive_payload(plan), "secret_payload_or_unknown_secret")
    require(plan.get("terraform_version") == manifest.get("terraform_version") == "1.15.8"
            and plan.get("format_version") == "1.2", "terraform_version")
    require(plan.get("errored") is False and plan.get("complete") is True and plan.get("applyable") is True,
            "incomplete_or_errored_plan")
    require(_timestamp(plan.get("timestamp")), "plan_timestamp_shape")
    backend = manifest.get("backend", {})
    require(isinstance(backend, dict) and all(backend.get(k) == v for k, v in
        {"bucket": "clipforgebeta2-tfstate-int", "prefix": "terraform/int/tf-int-01", "workspace": "default"}.items()),
        "backend_scope")
    require(manifest.get("schema") == "clipforge-int-e2e-private-plan-1"
            and manifest.get("repository") == "AldemaroCruz/ClipForge" and manifest.get("branch") == "ci/bootstrap-sec03",
            "manifest_scope")
    require(isinstance(manifest.get("commit"), str) and bool(re.fullmatch(r"[a-f0-9]{40}", manifest["commit"]))
            and all(isinstance(manifest.get(key), str) and bool(re.fullmatch(r"[1-9][0-9]*", manifest[key]))
                    for key in ("run_id", "run_attempt")) and _timestamp(manifest.get("created_utc")), "custody_identity_shape")
    inputs = manifest.get("inputs", {})
    require(isinstance(inputs, dict) and set(inputs) == {"stage", "machine_type", "runtime_image", "secret_versions"}
            and all(variables.get(k) == {"value": v} for k, v in inputs.items()), "manifest_input_binding")
    for key in ("configuration_sha256", "provider_lock_sha256"):
        require(isinstance(manifest.get(key), str) and re.fullmatch(r"[a-f0-9]{64}", manifest[key]) is not None,
                "manifest_hash_binding")
    for key in ("binary", "json"):
        reference = manifest.get(key)
        require(isinstance(reference, dict) and set(reference) == {"name", "generation", "sha256", "size"}
                and isinstance(reference.get("name"), str) and reference["name"].startswith("private-plans/int/")
                and isinstance(reference.get("generation"), str) and bool(re.fullmatch(r"[1-9][0-9]*", reference["generation"]))
                and isinstance(reference.get("sha256"), str) and bool(re.fullmatch(r"[a-f0-9]{64}", reference["sha256"]))
                and type(reference.get("size")) is int and 0 < reference["size"] <= MAX_BYTES, "manifest_reference")
        if isinstance(reference, dict):
            expected = "private-plans/int/" + str(manifest.get("commit")) + "/" + str(manifest.get("run_id")) + "-" + str(manifest.get("run_attempt"))
            require(reference.get("name") == expected + ("/int.tfplan" if key == "binary" else "/int.json"), "custody_object_binding")


def compare(old_plan, new_plan, old_manifest, new_manifest):
    """Return only safe differences; equality grants no deployment authorization."""
    report = {"schema": SCHEMA, "status": "blocked_input_change", "guards": [], "differences": [],
              "custody_changes": [], "managed_count": {}, "document_sha256": {},
              "hash_encoding": "Strings: UTF-8; other JSON values: canonical JSON; presence recorded separately.",
              "raw_json_binding": "Not verified by parsed-object API; CLI verifies supplied raw bytes.",
              "apply_authorized": False}
    try:
        for side, plan, manifest in (("old", old_plan, old_manifest), ("new", new_plan, new_manifest)):
            _canonical(plan)
            _canonical(manifest)
            _guard(plan, manifest, side, report["guards"])
            report["managed_count"][side] = sum(row.get("mode") == "managed" for row in plan.get("resource_changes", []) if isinstance(row, dict))
            report["document_sha256"][side] = {"plan": _sha(plan), "manifest": _sha(manifest),
                "effective_variables": _sha(plan.get("variables")), "configuration": _sha(plan.get("configuration")),
                "inputs": _sha(manifest.get("inputs")), "backend": _sha(manifest.get("backend"))}
        left, right = _normal(old_plan), _normal(new_plan)
        sensitive = set()
        for normalized in (left, right):
            _collect_sensitive(normalized, ("plan",), sensitive)
        _diff({k: v for k, v in left.items() if k not in PLAN_VOLATILE},
              {k: v for k, v in right.items() if k not in PLAN_VOLATILE}, ("plan",), report["differences"], sensitive)
        _diff({k: v for k, v in old_manifest.items() if k not in MANIFEST_CUSTODY},
              {k: v for k, v in new_manifest.items() if k not in MANIFEST_CUSTODY},
              ("manifest",), report["differences"], sensitive)
        for root_name, before, after, ignored in (("plan", old_plan, new_plan, PLAN_VOLATILE),
                                                ("manifest", old_manifest, new_manifest, MANIFEST_CUSTODY)):
            _diff({k: v for k, v in before.items() if k in ignored}, {k: v for k, v in after.items() if k in ignored},
                  (root_name,), report["custody_changes"], set())
        if not report["guards"] and not report["differences"]:
            report["status"] = "equivalent_operational_plan"
    except (ValueError, TypeError, KeyError, AttributeError, RecursionError):
        report["guards"].append({"category": "invalid_or_excessively_nested_json"})
    return report


def _read_private(path):
    candidate = Path(path)
    resolved = candidate.resolve(strict=True)
    if candidate.is_symlink() or resolved.is_relative_to(ROOT) or not resolved.is_file() or resolved.stat().st_size > MAX_BYTES:
        raise ValueError("Private explicit inputs outside the checkout required")
    with resolved.open("rb") as stream:
        raw = stream.read(MAX_BYTES + 1)
    if len(raw) > MAX_BYTES:
        raise ValueError("Input too large")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate JSON key")
            result[key] = value
        return result
    def finite(_value):
        raise ValueError("Non-finite JSON value")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite), raw


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("old-plan", "new-plan", "old-manifest", "new-manifest"):
        parser.add_argument("--" + name, required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        old, old_raw = _read_private(args.old_plan)
        new, new_raw = _read_private(args.new_plan)
        old_manifest, _ = _read_private(args.old_manifest)
        new_manifest, _ = _read_private(args.new_manifest)
        report = compare(old, new, old_manifest, new_manifest)
        bound = all(isinstance(manifest.get("json"), dict) and manifest["json"].get("size") == len(raw)
                    and manifest["json"].get("sha256") == hashlib.sha256(raw).hexdigest()
                    for manifest, raw in ((old_manifest, old_raw), (new_manifest, new_raw)))
        report["raw_json_binding"] = "verified" if bound else "failed"
        if not bound:
            report["status"] = "blocked_input_change"
            report["guards"].append({"category": "raw_json_manifest_binding"})
    except (OSError, ValueError, TypeError, AttributeError, RecursionError):
        report = {"schema": SCHEMA, "status": "blocked_input_change", "guards": [{"category": "private_input_invalid"}],
                  "differences": [], "apply_authorized": False}
    print(json.dumps(report, sort_keys=True, indent=2))
    return 0 if report["status"] == "equivalent_operational_plan" else 2


if __name__ == "__main__":
    raise SystemExit(main())
