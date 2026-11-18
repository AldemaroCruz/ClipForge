"""One private foundation recovery plan from an exact inspected partial state.

No apply, import CLI, IAM grant, state write or backend migration entry point.
Import blocks preview five owner-confirmed manual bootstrap bindings only.
New callers/argv are reviewed planning controls, not inherited F-SAST acceptance.
"""
from __future__ import annotations

from collections import Counter
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote, urlencode, urlsplit
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, int_release as custody, tf_int_plan as driver

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "config/int-foundation-recovery.json"
SCHEMA = "clipforge-int-foundation-recovery-1"
MANIFEST_SCHEMA = "clipforge-int-foundation-recovery-private-plan-1"
LIMIT = 8 * 1024 * 1024
IMPORT_ROWS = (
    ('runtime["api_password"]', "pg-app-password", "secretAccessor", "api"),
    ('runtime["worker_password"]', "pg-app-password", "secretAccessor", "worker"),
    ('runtime["migrate_password"]', "pg-migrator-password", "secretAccessor", "migrate"),
    ('version_publisher["app_password"]', "pg-app-password", "secretVersionAdder", "deploy"),
    ('version_publisher["migrator_password"]', "pg-migrator-password", "secretVersionAdder", "deploy"))


def expected_imports():
    rows = []
    for address, secret, role, account in IMPORT_ROWS:
        sid = "clipforge-int-" + secret
        role = "roles/secretmanager." + role
        member = "serviceAccount:clipforge-" + account + "-int@clipforgebeta2.iam.gserviceaccount.com"
        rows.append({"address": "google_secret_manager_secret_iam_member." + address,
                     "id": "projects/clipforgebeta2/secrets/" + sid + " " + role + " " + member,
                     "secret_id": sid, "role": role, "member": member, "condition": None})
    return rows


def load_contract(root=ROOT):
    value = json.loads((root / CONTRACT).read_bytes())
    c.require(value.get("schema") == SCHEMA and value.get("mode") == "plan_only_no_apply"
              and value.get("apply_authorized") is False, "Unknown or apply-enabled recovery contract")
    return value


def import_source(contract):
    c.require(contract["imports"] == expected_imports(), "Only the five reviewed member imports are permitted")
    result = "# Reviewed recovery import proposals only. Planning previews imports; only a separately authorized apply could persist them.\n\n"
    for row in contract["imports"]:
        result += "import {\n  to = " + row["address"] + "\n  id = " + json.dumps(row["id"]) + "\n}\n\n"
    return (result.rstrip() + "\n").encode()


def static_contract(root, contract=None):
    contract = contract or load_contract(root)
    c.require(contract["target_addresses"] == sorted(c.FOUNDATION_ADDRESSES)
              and contract["plan_ttl_seconds"] == 86400 and contract["apply_authorized"] is False,
              "Recovery cannot expand targets, plan lifetime or apply authority")
    source = root / "infra/gcp/int-base"
    c.source_contract(source)
    binding = custody.source_binding(source, {"GITHUB_SHA": contract["baseline"]["configuration_commit"],
                                             "RUNTIME_IMAGE": contract["inputs"]["runtime_image"]})
    c.require(binding["configuration_sha256"] == contract["source_bindings"]["base_configuration_sha256"]
              and binding["provider_lock_sha256"] == contract["source_bindings"]["provider_lock_sha256"]
              and binding["inputs"] == contract["inputs"], "Original HCL, inputs, provider or startup changed")
    c.require(custody.sha256((root / "scripts/tf_int_plan.py").read_bytes()) == contract["source_bindings"]["execution_driver_sha256"],
              "Original execution driver changed; prior source evidence cannot transfer")
    c.require(contract["source_bindings"]["imports_source"] == "config/int-foundation-recovery-imports.tf",
              "Unreviewed import source")
    raw = (root / contract["source_bindings"]["imports_source"]).read_bytes()
    c.require(raw == import_source(contract) and custody.sha256(raw) == contract["source_bindings"]["imports_sha256"],
              "Recovery import source changed or contains other HCL")
    return binding


def managed_addresses(state):
    addresses = []
    for resource in state.get("resources", []):
        c.require(not resource.get("module"), "Unreviewed state module")
        if resource.get("mode") == "data":
            c.require(resource.get("type") in c.DATA_TYPES, "Unknown state data source")
            continue
        c.require(resource.get("mode") == "managed", "Unknown state mode")
        for instance in resource.get("instances", []):
            c.require(not instance.get("deposed") and instance.get("status") in {None, "ready"},
                      "Deposed or tainted state requires separate review")
            address = resource["type"] + "." + resource["name"]
            if "index_key" in instance:
                c.require(type(instance["index_key"]) in {int, str}, "Invalid state index")
                address += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            addresses.append(address)
    c.require(len(addresses) == len(set(addresses)), "Duplicate state instance")
    return sorted(addresses)


def verify_partial_bytes(raw, inventory, contract):
    pin = contract["backend"]
    c.require({k: pin[k] for k in ("bucket", "prefix", "workspace", "name")} ==
              {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "name": driver.STATE_NAME},
              "Recovery backend identity differs")
    scoped = lambda rows: [row for row in rows if row.get("name", "").startswith(c.PREFIX + "/")]
    current = scoped(inventory["live"])
    c.require(not any(row["name"].endswith(".tflock") for row in current), "Current backend lock blocks recovery")
    c.require(len(current) == 1 and current[0]["name"] == pin["name"]
              and current[0]["generation"] == pin["generation"] and int(current[0]["size"]) == pin["size"],
              "Current state generation, workspace or size changed")
    versions = scoped(inventory["versions"]) + scoped(inventory["soft_deleted"])
    c.require(all(row["name"] in {driver.STATE_NAME, driver.LOCK_NAME} for row in versions)
              and any(row["name"] == pin["name"] and row["generation"] == pin["generation"] for row in inventory["versions"]),
              "Incomplete or unknown backend history")
    c.require(len(raw) == pin["size"] and custody.sha256(raw) == pin["sha256"], "Partial state bytes/hash changed")
    state = json.loads(raw)
    c.require(all(state.get(key) == pin[key] for key in ("version", "terraform_version", "lineage", "serial"))
              and type(state.get("serial")) is int and type(state.get("version")) is int,
              "Partial state lineage, serial or Terraform version changed")
    addresses = managed_addresses(state)
    c.require(addresses == pin["managed_addresses"] and len(addresses) == 20
              and set(addresses) <= c.FOUNDATION_ADDRESSES and set(state.get("outputs", {})) <= {"reviewed_boundary"},
              "Partial resource provenance or outputs changed")
    return {"classification": "recognized_partial_foundation_state", "state":
            {key: pin[key] for key in ("bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version")},
            "managed_addresses": addresses, "historical_locks_are_not_active": True, "apply_authorized": False}


def verify_import_observations(observations, contract):
    c.require(contract.get("management_owner_confirmed") is True, "Management owner must confirm the five bootstrap bindings")
    c.require(contract["imports"] == expected_imports(), "Unreviewed or extra import identity")
    for row in contract["imports"]:
        observed = observations.get(row["secret_id"], {})
        c.require(observed.get("http") == 200 and isinstance(observed.get("policy"), dict), "Cannot read an import's exact IAM policy")
        matches = [binding for binding in observed["policy"].get("bindings", [])
                   if binding.get("role") == row["role"] and row["member"] in binding.get("members", [])]
        c.require(len(matches) == 1 and not matches[0].get("condition"), "Absent, conditional or ambiguous bootstrap member")
    return contract["imports"]


def reject_original_plan(reference, contract):
    forbidden = contract["original_plan_forbidden"]
    c.require(isinstance(reference, dict) and not any(reference.get("sha256") == forbidden[key]["sha256"]
              or reference.get("name") == forbidden[key]["name"]
              or reference.get("generation") == forbidden[key]["generation"] for key in ("binary", "manifest"))
              and ("/" + forbidden["run_id"] + "-") not in reference.get("name", ""),
              "Original 42-create plan is retired after partial apply and cannot be reused")


def verify_recovery_plan(plan, contract):
    c.require(plan.get("terraform_version") == "1.15.8" and plan.get("errored") is not True,
              "Wrong or failed native Terraform recovery plan")
    c.require(set(plan.get("variables", {})) == c.VARIABLES, "Unreviewed recovery variables or secret input")
    for key, value in {"project_id": c.PROJECT, "run_subnet_cidr": "10.80.0.0/26",
                       "postgres_subnet_cidr": "10.80.1.0/28", "data_disk_gb": 20}.items():
        c.require(plan["variables"][key].get("value") == value, "Recovery environment/network/disk defaults changed")
    for key, value in contract["inputs"].items():
        c.require(plan.get("variables", {}).get(key, {}).get("value") == value, "Recovery inputs changed")
    planned = plan.get("planned_values", {}).get("root_module", {})
    c.require(not planned.get("child_modules"), "Recovery cannot introduce modules")
    resources = planned.get("resources", [])
    c.require(all((row.get("mode") == "data" and row.get("type") in c.DATA_TYPES)
                  or (row.get("mode") == "managed" and row.get("type") == row.get("address", "").split(".")[0])
                  for row in resources), "Unreviewed planned resource or secret payload source")
    targets = {r["address"] for r in resources if r.get("mode") == "managed"}
    c.require(len(targets) == sum(row.get("mode") == "managed" for row in resources), "Duplicate planned address")
    c.require(targets == set(contract["target_addresses"]) == c.FOUNDATION_ADDRESSES,
              "Recovery must preserve exactly the foundation target addresses")
    prior = set(contract["backend"]["managed_addresses"])
    imports = {row["address"]: row["id"] for row in contract["imports"]}
    counts, imported, seen, computed_roles = Counter(), [], set(), []
    for row in plan.get("resource_changes", []):
        if row.get("mode") == "data":
            c.require(row.get("type") in c.DATA_TYPES, "Unreviewed plan data source")
            continue
        address = row.get("address")
        c.require(address in targets and address not in seen and row.get("mode") == "managed"
                  and row.get("type") == address.split(".")[0], "Unreviewed or duplicate resource change")
        seen.add(address)
        change = row["change"]
        actions = change["actions"]
        c.require(actions in (["create"], ["no-op"]), "Updates, deletion, replacement or unknown actions require review")
        c.require(address not in prior or actions == ["no-op"], "Existing foundation resources cannot be changed")
        c.require(address in prior or address in imports or actions == ["create"],
                  "A pending resource cannot become a no-op without explicit state/import provenance")
        importing = change.get("importing")
        if address in imports:
            c.require(isinstance(importing, dict) and importing.get("id") == imports[address]
                      and actions == ["no-op"], "The five existing bindings need explicit reviewed no-change imports")
            imported.append(address)
        else:
            c.require(not importing, "Unreviewed import")
        if "_iam_member" in row["type"]:
            after = change.get("after") or {}
            expected_role = c.expected_iam_role(address)
            role_matches = after.get("role") == expected_role
            if address == "google_project_iam_member.bootstrap_reader" and after.get("role") is None:
                configured = [r for r in plan.get("configuration", {}).get("root_module", {}).get("resources", [])
                              if r.get("address") == address]
                roles = [r.get("change", {}).get("after", {}) for r in plan["resource_changes"]
                         if r.get("address") == "google_project_iam_custom_role.bootstrap_reader"]
                role_matches = (actions == ["create"] and change.get("after_unknown", {}).get("role") is True
                                and len(configured) == len(roles) == 1
                                and configured[0].get("expressions", {}).get("role") == {"references": [
                                    "google_project_iam_custom_role.bootstrap_reader.name", "google_project_iam_custom_role.bootstrap_reader"]}
                                and roles[0].get("project") == c.PROJECT and roles[0].get("role_id") == "clipforgeIntBootstrapReader"
                                and roles[0].get("permissions") == ["compute.disks.get", "compute.instances.get", "compute.projects.get", "run.operations.get"])
                if role_matches:
                    computed_roles.append({"address": address, "native_value": "unknown_until_create",
                                           "expected_role_from_exact_configuration": expected_role})
            c.require(role_matches
                      and after.get("member") == c.expected_iam_member(address) and not after.get("condition"),
                      "Planned IAM principal, role or condition changed")
        counts[actions[0]] += 1
    c.require(seen == targets and set(imported) == set(imports)
              and set(plan.get("output_changes", {})) <= {"reviewed_boundary"}, "Recovery plan or outputs are incomplete")
    return {"counts": dict(counts), "imports": sorted(imported), "addresses": sorted(targets), "computed_iam_roles": computed_roles,
            "existing_state_addresses": sorted(prior), "apply_authorized": False,
            "risk_acceptance": "Existing risk conditions/expiry preserved; this new plan is not approved"}


def verify_new_manifest(manifest, contract, now=None):
    c.require(manifest.get("schema") == MANIFEST_SCHEMA and manifest.get("apply_authorized") is False
              and manifest.get("risk_acceptance") == contract["risk_acceptance"], "Recovery manifest grants new authority or changes risk limits")
    commit = manifest.get("configuration_commit", "")
    c.require(bool(re.fullmatch(r"[a-f0-9]{40}", commit)) and manifest.get("controls_commit") == commit
              and manifest.get("baseline_configuration_commit") == contract["baseline"]["configuration_commit"],
              "Recovery configuration/control source identities differ")
    c.require(manifest.get("backend") == {key: contract["backend"][key] for key in
              ("bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version")}
              and manifest.get("inputs") == contract["inputs"] and manifest.get("imports") == contract["imports"]
              and manifest.get("terraform_version") == "1.15.8" and manifest.get("provider_version") == "8.11.0",
              "Recovery backend, imports, versions or inputs differ")
    files = manifest.get("configuration_files", {})
    c.require(set(files) == set(c.FILES) | {"recovery-imports.tf"}
              and all(isinstance(v, str) and re.fullmatch(r"[a-f0-9]{64}", v) for v in files.values())
              and custody.sha256(custody.canonical({name: files[name] for name in c.FILES})) == contract["source_bindings"]["base_configuration_sha256"]
              and files["recovery-imports.tf"] == contract["source_bindings"]["imports_sha256"]
              and files[".terraform.lock.hcl"] == manifest.get("provider_lock_sha256") == contract["source_bindings"]["provider_lock_sha256"]
              and custody.sha256(custody.canonical(files)) == manifest.get("configuration_sha256"),
              "Recovery source hashes or provider lock differ")
    c.require(manifest.get("base_configuration_sha256") == contract["source_bindings"]["base_configuration_sha256"]
              and bool(re.fullmatch(r"[a-f0-9]{64}", manifest.get("control_sources_sha256", ""))), "Missing control/configuration integrity")
    c.require(bool(re.fullmatch(r"[1-9][0-9]*", manifest.get("run_id", "")))
              and manifest["run_id"] != contract["original_plan_forbidden"]["run_id"]
              and bool(re.fullmatch(r"[1-9][0-9]*", manifest.get("run_attempt", ""))), "Unreviewed or original run identity")
    prefix = custody.PREFIX + commit + "/" + manifest["run_id"] + "-" + manifest["run_attempt"] + "/"
    for key, name in (("binary", "int.tfplan"), ("json", "int.json")):
        ref = manifest[key]
        c.require(set(ref) == {"name", "generation", "sha256", "size"} and ref["name"] == prefix + name
                  and bool(re.fullmatch(r"[1-9][0-9]*", ref["generation"]))
                  and bool(re.fullmatch(r"[a-f0-9]{64}", ref["sha256"])) and type(ref["size"]) is int and 0 < ref["size"] <= custody.LIMIT,
                  "Private recovery reference is incompatible")
        reject_original_plan(ref, contract)
    created = datetime.fromisoformat(manifest["created_utc"].replace("Z", "+00:00"))
    expires = datetime.fromisoformat(manifest["expires_utc"].replace("Z", "+00:00"))
    c.require(created.tzinfo is not None and expires.tzinfo is not None
              and created <= (now or datetime.now(timezone.utc)) < expires and expires - created == timedelta(seconds=86400),
              "Recovery plan expired, dated in the future or extends the 24-hour lifetime")


def read_private(url, operation, resource):
    target = urlsplit(url)
    state_path = "/storage/v1/b/" + c.BUCKET + "/o/" + quote(driver.STATE_NAME, safe="")
    secret_paths = {"/v1/projects/clipforgebeta2/secrets/" + row["secret_id"] + ":getIamPolicy" for row in expected_imports()}
    c.require(target.scheme == "https" and not target.username and not target.password and not target.fragment
              and target.port in {None, 443} and ((target.hostname == "storage.googleapis.com" and target.path == state_path)
              or (target.hostname == "secretmanager.googleapis.com" and target.path in secret_paths and not target.query)),
              "Unreviewed private recovery endpoint; no credential is forwarded")
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(Request(url, headers={
                "Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]}), timeout=90) as response:
            raw = response.read(LIMIT + 1)
        c.require(len(raw) <= LIMIT, "Private recovery read exceeds bound")
        return raw
    except HTTPError as error:
        raise driver.FailedOperation(operation + " " + resource, error.read(16384).decode(errors="replace"), error.code) from None


def inspect_partial(bucket, contract):
    inventory = driver.backend_inventory(bucket)
    pin = contract["backend"]
    # Check current metadata before requesting the immutable generation.
    current = [row for row in inventory["live"] if row["name"].startswith(c.PREFIX + "/")]
    c.require(len(current) == 1 and current[0]["name"] == pin["name"] and current[0]["generation"] == pin["generation"],
              "A current lock or changed state prevents private recovery inspection")
    url = "https://storage.googleapis.com/storage/v1/b/" + c.BUCKET + "/o/" + quote(pin["name"], safe="") + "?" + urlencode(
        {"alt": "media", "generation": pin["generation"], "ifGenerationMatch": pin["generation"]})
    raw = read_private(url, "read current partial state", pin["name"])
    proof = verify_partial_bytes(raw, inventory, contract)
    verify_partial_bytes(raw, driver.backend_inventory(bucket), contract)
    return proof


def inspect_imports(contract):
    observations = {}
    for sid in sorted({row["secret_id"] for row in contract["imports"]}):
        url = "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/" + sid + ":getIamPolicy"
        observations[sid] = {"http": 200, "policy": json.loads(read_private(url, "read bootstrap IAM member", sid))}
    verify_import_observations(observations, contract)
    return custody.sha256(custody.canonical(observations))


def plan_recovery(work, reports, environ):
    custody.hosted_context(environ)
    c.validate_variables(environ)
    c.require(environ.get("INT_REVIEWED_CONTROLS_COMMIT") == environ.get("GITHUB_SHA"),
              "Recovery dispatch must name the exact reviewed controls commit")
    c.require(environ.get("INT_STAGE") == "foundation" and environ.get("TF_WORKSPACE", "default") == "default",
              "Recovery is only the existing foundation workspace")
    adc = Path(environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    c.require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json", "Only fresh Actions WIF credentials may plan")
    contract = load_contract()
    static_contract(ROOT, contract)
    c.require(custody.inputs(environ) == contract["inputs"], "Recovery dispatch inputs differ")
    module = work / "module"
    # The unchanged driver checks prepare the base module. Verify every byte
    # before adding the one explicit import file, without changing the checkout.
    binding = custody.source_binding(module, environ)
    c.require(binding["configuration_sha256"] == contract["source_bindings"]["base_configuration_sha256"], "Prepared module drift")
    c.require({p.name for p in module.glob("*.tf")} == {name for name in c.FILES if name.endswith(".tf")}
              and not list(module.glob("*.tf.json")) and not list(module.glob("*.tfvars*")), "Unexpected Terraform module input")
    with (module / "recovery-imports.tf").open("xb") as stream:
        stream.write(import_source(contract))
    files = {name: custody.sha256((module / name).read_bytes()) for name in (*c.FILES, "recovery-imports.tf")}
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    proof = inspect_partial(bucket, contract)
    observations_sha = inspect_imports(contract)
    from scripts import review_int_foundation_plan as image_review
    image = image_review.image_metadata()
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "recovery_init", work)
    driver.run([binary, "validate", "-no-color"], "recovery_validate", work)
    c.require(inspect_partial(bucket, contract) == proof, "Backend changed during init")
    target = work / "int.tfplan"
    inputs = contract["inputs"]
    code, _ = driver.run([binary, "plan", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", "-detailed-exitcode",
                           "-var=machine_type=" + inputs["machine_type"], "-var=runtime_image=" + inputs["runtime_image"],
                           "-var=stage=foundation", "-var=secret_versions=null", "-out=" + str(target)], "recovery_plan", work, accepted=(0, 1, 2))
    c.require(inspect_partial(bucket, contract) == proof and inspect_imports(contract) == observations_sha,
              "Backend or exact import policies changed while planning")
    c.require({name: custody.sha256((module / name).read_bytes()) for name in files} == files,
              "Terraform/import/provider sources changed during planning")
    c.require(code in {0, 2}, "Native recovery plan failed; preserve diagnostics, no retry")
    _, raw = driver.run([binary, "show", "-json", str(target)], "recovery_private_plan_json", work)
    source_plan = json.loads(raw)
    try:
        review = verify_recovery_plan(source_plan, contract)
        review_status = "recovery_plan_requires_new_review"
    except ValueError:
        # Preserve an unexpected *real* plan for private review rather than
        # discarding it or manufacturing desired counts. This remains a failure.
        review = {"status": "blocked_material_plan_difference", "apply_authorized": False,
                  "changes": [{"address": row.get("address"), "type": row.get("type"),
                               "actions": row.get("change", {}).get("actions"),
                               "importing": bool(row.get("change", {}).get("importing"))}
                              for row in source_plan.get("resource_changes", []) if row.get("mode") == "managed"]}
        review_status = "blocked_recovery_plan_material_difference"
    (work / "private-plan.json").write_bytes(raw)
    from scripts import check_int_foundation as foundation
    prefix = custody.PREFIX + environ["GITHUB_SHA"] + "/" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"] + "/"
    created = datetime.now(timezone.utc)
    manifest = {"schema": MANIFEST_SCHEMA, "configuration_commit": environ["GITHUB_SHA"], "controls_commit": environ["GITHUB_SHA"],
                "baseline_configuration_commit": contract["baseline"]["configuration_commit"],
                "configuration_sha256": custody.sha256(custody.canonical(files)), "configuration_files": files,
                "base_configuration_sha256": binding["configuration_sha256"], "provider_lock_sha256": binding["provider_lock_sha256"],
                "terraform_version": binding["terraform_version"], "provider_version": "8.11.0", "inputs": inputs,
                "control_sources_sha256": foundation.fingerprint(ROOT, foundation.load_contract())[0],
                "recovery_contract_sha256": custody.sha256((ROOT / CONTRACT).read_bytes()), "backend": proof["state"],
                "imports": contract["imports"], "import_policies_sha256": observations_sha, "image": image,
                "created_utc": created.isoformat(), "expires_utc": (created + timedelta(seconds=86400)).isoformat(),
                "run_id": environ["GITHUB_RUN_ID"], "run_attempt": environ["GITHUB_RUN_ATTEMPT"], "apply_authorized": False,
                "risk_acceptance": contract["risk_acceptance"], "original_plan_rejected": contract["original_plan_forbidden"],
                "plan_review_status": review_status}
    manifest["binary"] = custody.upload(prefix + "int.tfplan", target.read_bytes())
    manifest["json"] = custody.upload(prefix + "int.json", raw)
    verify_new_manifest(manifest, contract)
    reference = custody.upload(prefix + "manifest.json", custody.canonical(manifest))
    reject_original_plan(reference, contract)
    summary = {"schema": SCHEMA, "status": review_status, "apply_authorized": False,
               "backend": proof, "review": review, "manifest": reference, "binary": manifest["binary"],
               "configuration_commit": environ["GITHUB_SHA"], "controls_commit": environ["GITHUB_SHA"],
               "created_utc": manifest["created_utc"], "expires_utc": manifest["expires_utc"], "image": image}
    save_summary(reports, summary)
    return summary


def save_summary(reports, summary):
    (reports / "recovery-summary.json").write_text(json.dumps(summary, indent=2) + "\n")
    markdown = "# INT recovery preparation\n\nStatus: " + summary["status"] + "\n\nNo apply, effective import or IAM grant is authorized.\n\n```json\n" + json.dumps(summary, indent=2) + "\n```\n"
    (reports / "recovery-summary.md").write_text(markdown)
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write(markdown)


def sanitized_native_errors(raw):
    text = raw.decode(errors="replace")
    messages, permissions, resources = [], set(), set()
    candidates = [line for line in text.splitlines() if re.search(r"(?:^Error:|Permission|permission|PERMISSION_DENIED|googleapi: Error)", line)]
    for line in candidates:
        row = c.diagnostic("recovery_plan", line, 1)
        messages.extend(row["messages"])
        resources.update(row["resources"])
        permissions.update(re.findall(r"[Pp]ermission\s+['\"]?((?:iam|logging|iap|secretmanager|resourcemanager|compute|storage|serviceusage)\.[A-Za-z0-9_.]+)", line))
    unique = list(dict.fromkeys(messages))
    return {"operation": "recovery_plan", "native_exit": 1, "messages": unique[:100],
            "permissions": sorted(permissions), "resources": sorted(resources), "message_limit_reached": len(unique) > 100,
            "original_private_log_sha256": custody.sha256(raw), "original_private_log_bytes": len(raw),
            "raw_log_published": False}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["check", "plan"])
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "check":
        static_contract(ROOT)
        print("Recovery source contract verified; no cloud call or plan executed.")
        return 0
    work, reports = driver.private_paths()
    try:
        summary = plan_recovery(work, reports, os.environ)
        return 0 if summary["status"] == "recovery_plan_requires_new_review" else 1
    except Exception as error:
        diagnostic = getattr(error, "receipt", {"operation": "recovery_plan_preflight", "error_type": type(error).__name__})
        # A failed native plan uses its full private log for sanitization; raw
        # content, state attributes, outputs and credentials are never artifacts.
        if (work / "recovery_plan.log").exists():
            diagnostic = sanitized_native_errors((work / "recovery_plan.log").read_bytes())
        save_summary(reports, {"schema": SCHEMA, "status": "blocked_no_apply_no_retry", "apply_authorized": False,
                               "error": diagnostic, "controls_commit": os.environ.get("GITHUB_SHA")})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
