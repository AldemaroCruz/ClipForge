"""Review-gated recovery of one immutable private plan; never grants IAM.

The producer checkout remains separate from the dispatch control checkout.
Proposal data and pending decision templates cannot authorize execution.
"""
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, int_release as custody, tf_int_plan as driver
from scripts import check_int_foundation as foundation, int_foundation_recovery as recovery
from scripts import int_release_state as state_reader
from scripts import review_int_foundation_plan as image_review

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "config/int-foundation-recovery-apply.json"
SCHEMA = "clipforge-int-foundation-recovery-apply-proposal-1"
DECISION_SCHEMA = "clipforge-int-foundation-recovery-single-plan-decision-1"
WORKFLOW = ".github/workflows/int-foundation-recovery-apply.yml"
IAM_KEYS = {"project_policy", "logging_config", "secret_create", "secret_policies", "iap_policy", "postgres_sa_policy"}


def load_proposal(root=ROOT):
    return image_review.decode((root / CONFIG).read_bytes())


def instant(value):
    return foundation.instant(value)


def verify_proposal(proposal, recovery_contract, now=None):
    c.require(proposal.get("schema") == SCHEMA and proposal.get("status") == "proposed_not_authorized"
              and proposal.get("apply_authorized") is False and proposal.get("runtime_authorized") is False
              and proposal.get("iam_grants_performed_by_apply_helper") is False,
              "A proposal cannot itself authorize apply, runtime or IAM grants")
    c.require((proposal.get("repository"), proposal.get("branch"), proposal.get("environment")) ==
              ("AldemaroCruz/ClipForge", "ci/bootstrap-sec03", "int"), "Recovery execution boundary changed")
    plan = proposal["plan"]
    # This uses the original producer contract, including the serial-5 pin.
    recovery.verify_new_manifest({**plan, "schema": recovery.MANIFEST_SCHEMA, "apply_authorized": False,
                                 "base_configuration_sha256": recovery_contract["source_bindings"]["base_configuration_sha256"]},
                                recovery_contract, now=now)
    c.require(plan["run_id"] == "44219757502" and plan["run_attempt"] == "1"
              and plan["configuration_commit"] == "264d1cfad6500e1abd60d3e7f966a3614a3a5831"
              and plan["controls_commit"] == plan["configuration_commit"], "Only the reviewed recovery producer is eligible")
    prefix = custody.PREFIX + plan["configuration_commit"] + "/44219757502-1/"
    expected = {"manifest": ("manifest.json", "1794967145187552", "a6cd844f31900ab7d1c6012fa3a7b936a86698218551b2582a63266d88f4189e", 6593),
                "binary": ("int.tfplan", "1794967144807369", "c75860660cee6f3ac1c929963bac70f660e08d40767610e1895cd115f2462469", 44420),
                "json": ("int.json", "1794967145021694", "1ffeed1cfcd2b90e1df94dcdd23a77f78b3c5ba611255bc2eae11c2ff81ef194", 293465)}
    for key, (name, generation, sha, size) in expected.items():
        c.require(plan[key] == {"name": prefix + name, "generation": generation, "sha256": sha, "size": size},
                  "Unreviewed recovery reference, generation, digest or size")
        recovery.reject_original_plan(plan[key], recovery_contract)
    review = proposal["expected_review"]
    c.require(review.get("counts") == {"no-op": 25, "create": 17}
              and review.get("addresses") == sorted(c.FOUNDATION_ADDRESSES)
              and review.get("imports") == sorted(row["address"] for row in recovery_contract["imports"])
              and review.get("existing_state_addresses") == recovery_contract["backend"]["managed_addresses"],
              "Recovery actions, import preview or partial-state addresses changed")
    return proposal


def decision_template(report, proposal):
    return {"schema": DECISION_SCHEMA, "owner": "AldemaroCruz", "apply_decision": "pending",
            "plan": proposal["plan"], "expected_review": proposal["expected_review"],
            "apply_controls_commit": report["control_commit"],
            "control_sources_sha256": report["control_sources_sha256"],
            "evidence_sha256": custody.sha256(custody.canonical(report)),
            "expires_utc": proposal["plan"]["expires_utc"],
            "iam_package": {"manifest_sha256": proposal["iam_package"]["manifest_sha256"],
                            "expires_utc": proposal["iam_package"]["expires_utc"], "administrator_receipt_sha256": None},
            "residual_decisions": [
                {"id": "F-SAST-EXEC", "decision": "pending", "execution_route": WORKFLOW,
                 "control_sources_sha256": report["control_sources_sha256"], "native_review": report["sast"]},
                {"id": "F-VM-XML", "decision": "pending", "image": proposal["plan"]["image"],
                 "conditions": foundation.INACTIVE_DATABASE_CONDITIONS},
                {"id": "F-AUDIT-0077", "decision": "pending", "operational": False, "retention_days": 30}],
            "risk_expiry_utc": proposal["plan"]["risk_acceptance"]["maximum_expiry_utc"],
            "runtime_authorized": False}


def verify_owner_decision(decision, expected_sha, report, proposal, environ, now=None):
    current = now or datetime.now(timezone.utc)
    c.require(isinstance(decision, dict) and bool(re.fullmatch(r"[a-f0-9]{64}", expected_sha))
              and custody.sha256(custody.canonical(decision)) == expected_sha, "Missing or changed exact recovery owner decision")
    expected = decision_template(report, proposal)
    expected["apply_decision"] = "approve_exact_recovery_binary_once"
    for row in expected["residual_decisions"]:
        row["decision"] = {"F-SAST-EXEC": "approve_new_exact_recovery_execution_route_for_this_binary_only",
                           "F-VM-XML": "preserve_exact_image_inactive_database_conditions",
                           "F-AUDIT-0077": "preserve_alternative_pending_operational_validation"}[row["id"]]
    package = decision.get("iam_package", {})
    c.require(set(package) == {"manifest_sha256", "expires_utc", "administrator_receipt_sha256"}
              and all(bool(re.fullmatch(r"[a-f0-9]{64}", package.get(k) or ""))
                      for k in ("manifest_sha256", "administrator_receipt_sha256"))
              and current < instant(package["expires_utc"])
              and package.get("manifest_sha256") == proposal["iam_package"]["manifest_sha256"]
              and package.get("expires_utc") == proposal["iam_package"]["expires_utc"],
              "Reviewed IAM package and administrator receipt are required")
    expected["iam_package"] = package
    c.require(decision == expected, "New plan, caller or residual risk has no exact owner approval")
    commit = environ.get("GITHUB_SHA", "")
    c.require(bool(re.fullmatch(r"[a-f0-9]{40}", commit)) and commit == environ.get("INT_APPROVED_COMMIT")
              == decision["apply_controls_commit"] == report["control_commit"], "Dispatch/control/evidence commit mismatch")
    c.require(report.get("integrity_status") == "passed" and set(report.get("integrity", {})) == foundation.REQUIRED_CHECKS
              and all(row.get("status") == "passed" for row in report["integrity"].values()), "Incomplete foundation integrity cannot be accepted")
    # Only the same three frozen native warnings may be considered, now with
    # an explicit review of the new caller and its entire source closure.
    pending = [row for row in report["sast"].get("findings", []) if row.get("disposition") == "risk_pending"]
    c.require(len(pending) == 3 and {(row.get("rule"), row.get("line")) for row in pending} ==
              {("B404", 16), ("B603", 169), ("B603", 180)}
              and all(row.get("resource") == "scripts/tf_int_plan.py" and row.get("severity") == "LOW"
                      and row.get("source_sha256") == foundation.EXECUTION_SOURCE_SHA256 for row in pending),
              "Unknown or higher-risk SAST finding blocks recovery")
    c.require(instant(proposal["plan"]["created_utc"]) <= current < instant(decision["expires_utc"])
              and current < instant(decision["risk_expiry_utc"])
              <= instant("2026-11-28T05:59:59+00:00"), "Plan or individual acceptance expired")
    return {"decision_sha256": expected_sha, "evidence_sha256": decision["evidence_sha256"],
            "apply_controls_commit": commit, "configuration_commit": proposal["plan"]["configuration_commit"]}


def verify_iam_receipts(serialized, decision, proposal):
    """Validate exact sanitized receipt bytes, not an unbacked digest assertion."""
    c.require(set(proposal["iam_package"]["bindings"]) == IAM_KEYS, "IAM package must name exactly the six reviewed bindings")
    c.require(isinstance(serialized, str) and len(serialized.encode()) <= 1024 * 1024, "IAM receipt input is absent or oversized")
    bundle = image_review.decode(serialized)
    c.require(isinstance(bundle, dict) and set(bundle) == {"index", "files"} and isinstance(bundle["index"], str)
              and isinstance(bundle["files"], dict), "IAM receipt input is not a closed bundle")
    c.require(custody.sha256(bundle["index"].encode()) == decision["iam_package"]["administrator_receipt_sha256"], "IAM receipt index digest differs")
    index = image_review.decode(bundle["index"])
    c.require(set(index) == {"schema", "bundle_manifest_sha256", "authorization_reference_sha256", "mode", "files"}
              and index["schema"] == "clipforge-int-foundation-iam-receipt-index-1" and index["mode"] == "Grant"
              and index["bundle_manifest_sha256"] == proposal["iam_package"]["manifest_sha256"]
              and bool(re.fullmatch(r"[a-f0-9]{64}", index["authorization_reference_sha256"]))
              and isinstance(index["files"], list) and 0 < len(index["files"]) <= 128, "IAM receipt index scope differs")
    names, completed, attempted = set(), set(), set()
    fields = {"schema", "bundle_manifest_sha256", "authorization_reference_sha256", "sequence", "utc", "mode", "operation", "status",
              "key", "mutation_attempted", "resource", "role", "member", "condition_sha256", "http_status", "native_exit_code", "error_category"}
    for sequence, item in enumerate(index["files"], 1):
        c.require(set(item) == {"name", "sha256"} and item["name"] == f"{sequence:04d}.json"
                  and item["name"] not in names and isinstance(bundle["files"].get(item["name"]), str), "IAM receipt sequence/name differs")
        names.add(item["name"])
        raw = bundle["files"][item["name"]].encode()
        c.require(custody.sha256(raw) == item["sha256"], "IAM phase receipt bytes changed")
        row = image_review.decode(raw)
        c.require(set(row) == fields and row["schema"] == "clipforge-int-foundation-iam-receipt-1"
                  and row["sequence"] == sequence and row["mode"] == "Grant" and row["bundle_manifest_sha256"] == index["bundle_manifest_sha256"]
                  and row["authorization_reference_sha256"] == index["authorization_reference_sha256"]
                  and row["status"] in {"started", "attempted", "completed"}, "Failed, rollback or unrecognized IAM phase blocks apply")
        c.require(instant(row["utc"]) < instant(proposal["iam_package"]["expires_utc"]), "Grant receipt postdates package expiry")
        if row["operation"] == "grant_binding":
            key = row["key"]
            c.require(key in proposal["iam_package"]["bindings"] and row["mutation_attempted"] is True,
                      "IAM binding receipt key differs")
            expected = proposal["iam_package"]["bindings"][key]
            c.require(all(row.get(k) == expected[k] for k in ("resource", "role", "member", "condition_sha256")), "IAM binding receipt target/condition differs")
            if row["status"] == "attempted":
                c.require(key not in attempted, "Duplicate IAM binding attempt requires review")
                attempted.add(key)
            elif row["status"] == "completed":
                c.require(key in attempted and key not in completed and row["http_status"] in {None, 200}
                          and row["native_exit_code"] in {None, 0}, "IAM binding completion is not successful")
                completed.add(key)
    c.require(names == set(bundle["files"]) and completed == attempted == set(proposal["iam_package"]["bindings"]),
              "All six exact temporary IAM binding completions are required")
    return index


def iam_metadata(url):
    """Only fixed getIamPolicy and role-definition reads; never setIamPolicy."""
    options = b'{"options":{"requestedPolicyVersion":3}}'
    policies = {
        "https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy":
            ("POST", options, "read_project_iam_policy", "projects/clipforgebeta2"),
        "https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:getIamPolicy":
            ("POST", options, "read_iap_instance_iam_policy",
             "projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131"),
        "https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3":
            ("POST", None, "read_postgres_service_account_iam_policy",
             "projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com")}
    role = re.fullmatch(r"https://iam\.googleapis\.com/v1/projects/clipforgebeta2/roles/clipforgeIntRecovery[A-Za-z0-9_]+", url)
    c.require(url in policies or role is not None, "Unreviewed IAM read endpoint")
    method, payload, operation, resource = policies[url] if url in policies else (
        "GET", None, "read_recovery_role_definition", url.removeprefix("https://iam.googleapis.com/v1/"))
    request = Request(url, data=payload, method=method,
                      headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"], "Content-Type": "application/json"})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(1024 * 1024 + 1)
    except HTTPError as error:
        failure = driver.FailedOperation(operation, "HTTP " + str(error.code) + ": IAM metadata read failed", error.code)
        failure.receipt.update(resource=resource, resources=[resource], http_status=error.code, method=method)
        raise failure from None
    c.require(len(raw) <= 1024 * 1024, "IAM read exceeds private bound")
    return image_review.decode(raw)


def verify_live_iam(proposal):
    """Receipts do not prove a binding survived; check current policy presence.

    This is not a claim that Deny/PAB/org policies or all future creates permit
    the operation. Native authorization failures remain failures, without retry.
    """
    bindings = proposal["iam_package"]["bindings"]
    c.require(set(bindings) == IAM_KEYS, "Exactly six temporary bindings are required")
    project = iam_metadata("https://cloudresourcemanager.googleapis.com/v1/projects/clipforgebeta2:getIamPolicy")
    iap = iam_metadata("https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131:getIamPolicy")
    sa = iam_metadata("https://iam.googleapis.com/v1/projects/clipforgebeta2/serviceAccounts/clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com:getIamPolicy?options.requestedPolicyVersion=3")
    for key, expected in bindings.items():
        policy = iap if key == "iap_policy" else sa if key == "postgres_sa_policy" else project
        found = [row for row in policy.get("bindings", []) if row.get("role") == expected["role"]
                 and expected["member"] in row.get("members", []) and row.get("condition") == expected["condition"]]
        c.require(len(found) == 1, "Temporary binding absent, changed or withdrawn; no recovery apply")
        role = iam_metadata("https://iam.googleapis.com/v1/" + expected["role"])
        c.require(role.get("name") == expected["role"] and role.get("deleted", False) is False and role.get("stage") == "GA"
                  and sorted(role.get("includedPermissions", [])) == sorted(expected["permissions"]), "Temporary custom role differs from review")
    return {"bindings_present": 6, "role_definitions_match": 6, "effective_authorization_not_inferred": True}


def verify_plan_bridge(manifest, proposal, module, original_root, environ):
    original_contract = recovery.load_contract(original_root)
    recovery.static_contract(original_root, original_contract)
    verify_proposal(proposal, original_contract)
    recovery.verify_new_manifest(manifest, original_contract)
    plan = proposal["plan"]
    c.require(all(manifest.get(key) == value for key, value in plan.items() if key != "manifest"),
              "Private manifest differs from reviewed plan proposal")
    c.require(custody.sha256((original_root / recovery.CONTRACT).read_bytes()) == manifest["recovery_contract_sha256"],
              "Original recovery contract changed")
    producer_fingerprint, _ = foundation.fingerprint(original_root, foundation.load_contract(original_root))
    c.require(producer_fingerprint == manifest["control_sources_sha256"], "Original producer controls changed")
    files = {name: custody.sha256((module / name).read_bytes()) for name in (*c.FILES, "recovery-imports.tf")}
    c.require(files == manifest["configuration_files"] and custody.sha256(custody.canonical(files)) == manifest["configuration_sha256"],
              "Original configuration, startup, inputs or provider lock changed")
    c.require({str(p.relative_to(module)).replace(os.sep, "/") for p in module.rglob("*") if p.is_file()} == set(files),
              "Unexpected file in isolated recovery module")
    c.require(environ.get("INT_STAGE") == "foundation" and custody.inputs(environ) == manifest["inputs"]
              and environ.get("TF_WORKSPACE", "default") == "default", "Recovery cannot activate runtime or another workspace")
    return original_contract


def live_preflight(bucket, contract, plan):
    proof = recovery.inspect_partial(bucket, contract)
    c.require(recovery.inspect_imports(contract) == plan["import_policies_sha256"], "Bootstrap import policies changed")
    c.require(image_review.image_metadata() == plan["image"], "Reviewed image metadata or identity changed")
    base = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
    vm = image_review.decode(image_review.read_private(base + "instances/clipforge-int-base-postgres",
                                                      256 * 1024, "read existing foundation VM", "1670495097211408131"))
    metadata = {row["key"]: row.get("value", "") for row in vm.get("metadata", {}).get("items", [])}
    c.require(str(vm.get("id")) == "1670495097211408131" and vm.get("deletionProtection") is True
              and vm.get("machineType", "").endswith("/e2-micro") and len(vm.get("networkInterfaces", [])) == 1
              and vm["networkInterfaces"][0].get("networkIP") == "10.80.1.2"
              and not vm["networkInterfaces"][0].get("accessConfigs")
              and metadata.get("enable-oslogin") == "TRUE" and metadata.get("block-project-ssh-keys") == "TRUE"
              and custody.sha256(metadata.get("startup-script", "").encode()) ==
              "a93bd662abce93b12c6389a37fccca49612ef3d1ee83eb882051cd5489daf255"
              and all(vm.get("shieldedInstanceConfig", {}).get(k) is True for k in
                      ("enableSecureBoot", "enableVtpm", "enableIntegrityMonitoring")), "Existing VM identity or reviewed protections/startup changed")
    disks = vm.get("disks", [])
    c.require(len(disks) == 2 and all(row.get("autoDelete") is False for row in disks)
              and sum(row.get("boot") is True for row in disks) == 1, "Reviewed VM disk attachment/protection changed")
    boot = next(row for row in disks if row.get("boot"))
    boot_name = boot.get("source", "").rsplit("/", 1)[-1]
    c.require(boot_name == "clipforge-int-base-postgres", "Unexpected boot disk resource")
    disk = image_review.decode(image_review.read_private(base + "disks/" + boot_name, 65536,
                                                       "read existing VM boot image", boot_name))
    c.require(str(disk.get("id")) == "2158164599035219715"
              and str(disk.get("sourceImageId")) == "5913446147369107523", "Existing VM boot image identity changed")
    return proof


def emit_receipt(work, plan, approval, environ, *, bucket):
    raw, obj, _ = state_reader.private_current_state(bucket)
    result = state_reader.state_contract(raw, lineage=plan["backend"]["lineage"])
    c.require(all(instance.get("status") in {None, "ready"} for resource in image_review.decode(raw).get("resources", [])
                  for instance in resource.get("instances", [])), "Tainted state requires private review, not a success receipt")
    c.require(result["serial"] > plan["backend"]["serial"] and obj["generation"] != plan["backend"]["generation"],
              "Recovery success requires a new state descendant")
    current = [row for row in driver.backend_inventory(bucket)["live"] if row["name"].startswith(c.PREFIX + "/")]
    c.require(len(current) == 1 and current[0]["name"] == driver.STATE_NAME and current[0]["generation"] == obj["generation"],
              "State or active lock changed during post-apply verification")
    receipt = {"schema": "clipforge-int-foundation-recovery-apply-receipt-1", "parent_partial_state": plan["backend"],
               "plan_manifest": plan["manifest"], "plan_binary": plan["binary"], "configuration_commit": plan["configuration_commit"],
               "producer_controls_commit": plan["controls_commit"], "approval": approval,
               "issuer": {"workflow": WORKFLOW, "repository": "AldemaroCruz/ClipForge", "run_id": environ["GITHUB_RUN_ID"],
                          "run_attempt": environ["GITHUB_RUN_ATTEMPT"], "commit": environ["GITHUB_SHA"]},
               "state": {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw), "sha256": custody.sha256(raw), **result},
               "runtime_authorized": False, "legacy_runtime_provenance_requires_separate_review": True}
    name = custody.PREFIX + environ["GITHUB_SHA"] + "/" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"] + "/foundation-state.json"
    return custody.upload(name, custody.canonical(receipt)), receipt


def apply_reviewed(work, reports, environ, root=ROOT):
    custody.hosted_context(environ)
    c.validate_variables(environ)
    proposal = load_proposal(root)
    original = root / "plan-source"
    # Workflow checks git HEAD separately, and this byte bridge independently
    # verifies every consumed configuration and producer-control source.
    contract = recovery.load_contract(original)
    verify_proposal(proposal, contract)
    report = foundation.fetch_evidence(environ, root)
    decision = image_review.decode(environ.get("RECOVERY_DECISION_JSON", "null"))
    approval = verify_owner_decision(decision, environ.get("RECOVERY_DECISION_SHA256", ""), report, proposal, environ)
    verify_iam_receipts(environ.get("RECOVERY_IAM_RECEIPTS_JSON"), decision, proposal)
    adc = Path(environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    c.require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json", "Fresh Actions WIF credentials required")
    module = work / "module"
    module.mkdir()
    (work / "terraform.rc").write_text("provider_installation {\n  direct {}\n}\n", encoding="utf-8")
    for name in c.FILES:
        target = module / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(original / "infra/gcp/int-base" / name, target)
    (module / "recovery-imports.tf").write_bytes((original / "config/int-foundation-recovery-imports.tf").read_bytes())
    plan = proposal["plan"]
    manifest = image_review.decode(custody.fetch_verified(plan["manifest"]))
    verify_plan_bridge(manifest, proposal, module, original, environ)
    raw_json = custody.fetch_verified(plan["json"])
    c.require(recovery.verify_recovery_plan(image_review.decode(raw_json), contract) == proposal["expected_review"], "Native actions differ from review")
    target = work / "int.tfplan"
    target.write_bytes(custody.fetch_verified(plan["binary"]))
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    before = live_preflight(bucket, contract, plan)
    iam_proof = verify_live_iam(proposal)
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "recovery_apply_init", work)
    c.require(live_preflight(bucket, contract, plan) == before, "Backend changed during init")
    c.require(verify_live_iam(proposal) == iam_proof, "Temporary IAM changed during init")
    # No replan, implicit vars, import command, force-unlock or retry.
    verify_owner_decision(decision, environ["RECOVERY_DECISION_SHA256"], report, proposal, environ)
    c.require(custody.sha256(target.read_bytes()) == plan["binary"]["sha256"], "Saved binary changed before apply")
    c.require({name: custody.sha256((module / name).read_bytes()) for name in manifest["configuration_files"]} == manifest["configuration_files"],
              "Configuration changed during init")
    (work / "apply-attempted.json").write_bytes(custody.canonical({"binary_sha256": plan["binary"]["sha256"], "controls_commit": environ["GITHUB_SHA"]}))
    driver.run([binary, "apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(target)], "recovery_apply_saved", work)
    (work / "apply-completed.json").write_bytes(b"{}")
    reference, receipt = emit_receipt(work, plan, approval, environ, bucket=bucket)
    summary = {"status": "recovery_apply_completed_guest_and_audit_checks_pending", "plan_run": plan["run_id"], "approval": approval,
               "receipt": reference, "state": receipt["state"], "runtime_authorized": False}
    foundation.save_apply_summary(reports, summary, environ)
    return summary


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["check", "apply"])
    args = parser.parse_args()
    os.umask(0o077)
    if args.operation == "check":
        verify_proposal(load_proposal(), recovery.load_contract())
        print("Recovery proposal verified offline; no apply authorization or cloud mutation.")
        return 0
    work, reports = driver.private_paths()
    try:
        apply_reviewed(work, reports, os.environ)
        return 0
    except Exception as error:
        # The only failure output is an allowlisted diagnostic. Native raw
        # output and state attributes remain private; never auto retry.
        summary = {"status": "blocked_or_partial_recovery_preserve_state_no_retry", "runtime_authorized": False,
                   "error": getattr(error, "receipt", {"operation": "recovery_apply_preflight", "error_type": type(error).__name__})}
        if (work / "apply-completed.json").exists():
            summary["status"] = "native_apply_completed_post_apply_verification_failed_no_retry"
        if (work / "recovery_apply_saved.log").exists():
            summary["error"] = recovery.sanitized_native_errors((work / "recovery_apply_saved.log").read_bytes())
            summary["error"]["operation"] = "recovery_apply_saved"
        if (work / "apply-attempted.json").exists() or (work / "recovery_apply_saved.log").exists():
            try:
                bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
                raw, obj, _ = state_reader.private_current_state(bucket)
                header = image_review.decode(raw)
                pin = recovery.load_contract()["backend"]
                c.require(header.get("version") == 4 and header.get("terraform_version") == "1.15.8"
                          and header.get("lineage") == pin["lineage"] and type(header.get("serial")) is int
                          and header["serial"] >= pin["serial"], "Unexpected partial state header requires private review")
                summary["partial_state"] = {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw),
                                            "sha256": custody.sha256(raw), "lineage": header.get("lineage"), "serial": header.get("serial")}
            except Exception as inspect_error:
                summary["partial_state_inspection"] = {"error_type": type(inspect_error).__name__}
        foundation.save_apply_summary(reports, summary, os.environ)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
