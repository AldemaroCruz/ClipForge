"""TF-INT-01: curated validation and one real plan; no mutation command exists.

Native backend locking remains enabled. Plans/JSON are retained only in immutable
private GCS objects; local diagnostics/backend files are removed by cleanup.
Only an explicit summary schema is permitted in logs and GitHub artifacts.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

# Actions invokes this file directly. Its import path otherwise contains only
# scripts/, while private custody and phase-two provenance use package imports.
ROOT = Path(__file__).resolve().parents[1]
if __package__ in (None, ""):
    sys.path.insert(0, str(ROOT))

try:
    from scripts import check_tf_int as contract
except ModuleNotFoundError:
    import check_tf_int as contract


MODULE = ROOT / "infra/gcp/int-base"
TRIVY = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6"
TERRAFORM_IMAGE = "hashicorp/terraform:1.15.8@sha256:7ae513256f7ce67879e218ae8593d6fbe216ec9e123abe6c94e4e10704857963"
PYTHON_IMAGE = "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
BASE_PREFIX = "terraform/int/"
STATE_NAME = contract.PREFIX + "/default.tfstate"
LOCK_NAME = contract.PREFIX + "/default.tflock"
# Read-only inspected empty initial snapshot in this exact backend/workspace.
# This is an identity pin, never a copy of state or permission to adopt resources.
INITIAL_STATE = {
    "name": STATE_NAME, "generation": "1794599421671184", "size": "181",
    "lineage": "813c84a2-2ef1-ceb3-177e-3a2c3b815066",
    "sha256": "648a329bdee385b59be64b598a2cbce07653e42edfcf5deb12f0d14133c4c223",
}


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Cloud metadata API redirects are forbidden")


class FailedOperation(ValueError):
    def __init__(self, operation, text, status=None):
        self.receipt = contract.diagnostic(operation, text, status)
        super().__init__(operation + " failed; only sanitized diagnostics may be published")


def private_paths():
    temporary = Path(os.environ["RUNNER_TEMP"]).resolve()
    work = Path(os.environ["TF_INT_WORK_DIR"]).resolve()
    reports = Path(os.environ["TF_INT_REPORT_DIR"]).resolve()
    contract.require(work.parent == temporary and work.name.startswith("clipforge-tf-int01."), "Work directory must be a dedicated runner temporary child")
    contract.require(reports.parent == temporary and reports.name.startswith("clipforge-tf-report.")
                     and reports != work, "Reports require a separate dedicated runner temporary child")
    contract.require(not ROOT.is_relative_to(work) and not work.is_relative_to(ROOT), "Private scratch must not overlap the checkout")
    return work, reports


def save_summary(reports, value):
    # All callers construct this allowlisted schema; no plan values or API bodies.
    (reports / "summary.json").write_text(json.dumps(value, indent=2) + "\n", encoding="utf-8")
    lines = ["# TF-INT-01", "", "Status: " + value["status"], "",
             "Project: clipforgebeta2 (816643438938); region: us-central1.",
             "", "Plan-only. No application image or deployment permission is approved.",
             "Full plan/JSON stay private in generation-pinned GCS objects. Credentials are never uploaded.", ""]
    if "checks" in value:
        lines.extend(["Checks: " + ", ".join(k + "=" + str(v) for k, v in value["checks"].items()), ""])
    if "backend" in value:
        backend = value["backend"]
        lines.extend(["Backend/workspace: " + backend["bucket"] + "/" + backend["prefix"] + "/default",
                      "Classification: " + backend["classification"], "",
                      "| Object | Generation | Category | Created UTC | Deleted UTC | Bytes |",
                      "| --- | --- | --- | --- | --- | --- |"])
        for category in ("live", "historical", "soft_deleted"):
            for obj in backend[category]:
                lines.append("| " + " | ".join(str(v) for v in [obj["name"], obj["generation"], category,
                             obj.get("timeCreated", ""), obj.get("timeDeleted", obj.get("softDeleteTime", "")), obj["size"]]) + " |")
        lines.append("")
    if "plan" in value:
        lines.extend(["Detailed exit code: " + str(value["plan_exit_code"]),
                      "Actions: " + json.dumps(value["plan"]["counts"], sort_keys=True),
                      "Destructive actions: none.", "", "| Resource | Action |", "| --- | --- |"])
        lines.extend("| " + row["address"] + " | " + ", ".join(row["actions"]) + " |" for row in value["plan"]["resources"])
        lines.extend(["", "PostgreSQL has no public IP. Ingress: private Run subnet TCP/5432; IAP TCP/22.",
                      "Egress: PostgreSQL subnet only, NAT, HTTPS/443; other VM egress denied.",
                      "Separate retained 20 GiB data disk and retained 10 GiB boot disk; VM deletion protection.",
                      "Private media/backups buckets: UBLA, public access prevention, versioning, 7-day soft delete.",
                      "Media retention 7 days; backups retention 30 days, live backups expire after 90 days.",
                      "Cloud Run API: built-in IAP for admin@ixbalam.studio, zero to one instance; three single-task Jobs.",
                      "DATA_READ/WRITE: project-wide GCS audit enablement; pilot-bucket sink/view, 30-day retention.",
                      "Google-managed encryption proposed; key findings remain unaccepted. No IAM/service changes executed.", ""])
    if "private_plan" in value:
        lines.extend(["Private immutable plan custody (no payloads in this report):", "```json",
                      json.dumps(value["private_plan"], indent=2), "```", ""])
    if "foundation_receipt" in value:
        lines.extend(["Private post-foundation provenance for an explicitly reviewed phase-two dispatch:", "```json",
                      json.dumps(value["foundation_receipt"], indent=2), "```", ""])
    if "cost" in value:
        cost = value["cost"]
        lines.extend(["Full runtime target estimated monthly USD before exclusions: " + str(cost["monthly_usd"]),
                      "Foundation estimate with the same example GCS/log volumes USD: " + str(cost["foundation_monthly_usd"]),
                      "e2-small comparison USD: " + str(cost["e2_small_monthly_usd"]), ""])
        lines.extend("- " + text for text in cost["assumptions"])
        lines.extend(["", "Pricing sources:", *["- " + url for url in cost["sources"]], ""])
    if "iac_findings" in value:
        lines.extend(["IaC findings are recorded, not accepted. Apply and deployment remain unauthorized.",
                      "", "| Finding | Severity | Resource |", "| --- | --- | --- |"])
        lines.extend("| " + row["id"] + " | " + row["severity"] + " | " + row["resource"] + " |"
                     for row in value["iac_findings"])
    if "error" in value:
        lines.extend(["Sanitized failure receipt:", "```json", json.dumps(value["error"], indent=2), "```"])
    markdown = "\n".join(lines) + "\n"
    (reports / "summary.md").write_text(markdown, encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write(markdown)


def cost_estimate(machine):
    value = json.loads((ROOT / "config/tf-int01-costs.json").read_text())
    rates, usage, hours = value["rates"], value["example_usage"], value["hours_per_month"]
    base = ((usage["boot_disk_gib"] + usage["data_disk_gib"]) * rates["pd_standard_gib_month"]
            + hours * (rates["nat_vm_hour"] + rates["nat_external_ip_hour"])
            + usage["nat_processed_gib"] * rates["nat_processed_gib"]
            + (usage["media_gib_including_versions"] + usage["backup_gib_including_versions"]) * rates["gcs_standard_gib_month"])
    extra = (usage["api_active_seconds"] * (rates["run_api_vcpu_second"] + rates["run_api_gib_second"])
             + usage["api_requests_million"] * rates["run_requests_million"]
             + usage["worker_seconds"] * (2 * rates["run_job_vcpu_second"] + 4 * rates["run_job_gib_second"])
             + usage["administration_job_seconds"] * (rates["run_job_vcpu_second"] + rates["run_job_gib_second"])
             + usage["artifact_gib_including_model_and_old_revisions"] * rates["artifact_gib_month"]
             + usage["audit_logging_gib_including_duplicate_default"] * rates["logging_gib"]
             + usage["network_logging_gib"] * rates["network_logging_gib"]
             + usage["secret_active_versions"] * rates["secret_version_month"]
             + usage["secret_access_operations"] / 10000 * rates["secret_access_10000"]
             + usage["gcs_class_a_operations"] / 1000 * rates["gcs_class_a_1000"]
             + usage["gcs_class_b_operations"] / 1000 * rates["gcs_class_b_1000"]
             + usage["internet_egress_gib"] * rates["internet_egress_gib"]
             + usage["private_plan_storage_gib"] * rates["gcs_standard_gib_month"])
    return {"monthly_usd": round(base + extra + hours * rates[machine + "_hour"], 2),
            "foundation_monthly_usd": round(base + hours * rates[machine + "_hour"]
                + usage["audit_logging_gib_including_duplicate_default"] * rates["logging_gib"]
                + usage["network_logging_gib"] * rates["network_logging_gib"]
                + usage["private_plan_storage_gib"] * rates["gcs_standard_gib_month"], 2),
            "base_infrastructure_monthly_usd": round(base + hours * rates[machine + "_hour"], 2),
            "pilot_additional_monthly_usd": round(extra, 2),
            "e2_small_monthly_usd": round(base + extra + hours * rates["e2-small_hour"], 2),
            "profile": machine, "usage": usage, "assumptions": value["assumptions"], "sources": value["sources"]}


def run(command, operation, work, *, accepted=(0,)):
    environment = dict(os.environ)
    contract.require(not any(key.startswith(("TF_VAR_", "TF_CLI_ARGS", "TF_LOG")) for key in environment),
                     "Ambient Terraform options or secrets are forbidden")
    environment.update(TF_INPUT="false", TF_IN_AUTOMATION="true", TF_DATA_DIR=str(work / "terraform-data"), CHECKPOINT_DISABLE="1")
    environment["TF_CLI_CONFIG_FILE"] = str(work / "terraform.rc")
    result = subprocess.run(command, cwd=work / "module", capture_output=True, timeout=1200, env=environment, check=False)
    raw = result.stdout + b"\n" + result.stderr
    (work / (operation + ".log")).write_bytes(raw)
    if result.returncode not in accepted:
        raise FailedOperation(operation, raw.decode("utf-8", errors="replace"), result.returncode)
    return result.returncode, result.stdout


def terraform_binary():
    binary = shutil.which("terraform")
    contract.require(binary is not None, "Pinned Terraform executable is required")
    result = subprocess.run([binary, "version", "-json"], capture_output=True, timeout=30, check=True,
                            env={**os.environ, "TF_CLI_CONFIG_FILE": os.devnull})
    contract.require(json.loads(result.stdout)["terraform_version"] == "1.15.8", "Wrong Terraform version")
    return binary


def metadata(path, params=None):
    # This helper can only read Storage metadata, not object payloads or secrets.
    contract.require(path == "/b/" + contract.BUCKET or path == "/b/" + contract.BUCKET + "/o", "Unreviewed Storage request")
    url = "https://storage.googleapis.com/storage/v1" + path
    if params:
        url += "?" + urlencode(params)
    request = Request(url, headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]})
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(1024 * 1024 + 1)
        contract.require(len(raw) <= 1024 * 1024, "Storage metadata response exceeded bound")
        return json.loads(raw)
    except HTTPError as error:
        text = error.read(16384).decode("utf-8", errors="replace")
        raise FailedOperation("backend metadata " + path, text, error.code) from None


def backend_inventory(bucket):
    """List the authorized base completely, keeping live and historical separate."""
    contract.backend_contract(bucket)
    inventory = {}
    fields = "nextPageToken,items(name,generation,size,timeCreated,updated,timeDeleted,softDeleteTime,hardDeleteTime)"
    for category, options in (("live", {}), ("versions", {"versions": "true"}),
                              ("soft_deleted", {"softDeleted": "true"})):
        if category == "soft_deleted" and int(bucket.get("softDeletePolicy", {}).get("retentionDurationSeconds", 0)) == 0:
            inventory[category] = []
            continue
        items, seen_pages, page = [], set(), None
        for _ in range(20):
            params = {"prefix": BASE_PREFIX, "maxResults": "1000", "fields": fields, **options}
            if page:
                params["pageToken"] = page
            result = metadata("/b/" + contract.BUCKET + "/o", params)
            items.extend(result.get("items", []))
            page = result.get("nextPageToken")
            if not page:
                break
            contract.require(page not in seen_pages, "Repeated backend inventory page; incomplete diagnosis")
            seen_pages.add(page)
        else:
            raise ValueError("Backend inventory exceeds its bound; no truncated result is accepted")
        contract.require(all(o.get("name", "").startswith(BASE_PREFIX)
                             and re.fullmatch(r"[1-9][0-9]*", str(o.get("generation", "")))
                             and re.fullmatch(r"[0-9]+", str(o.get("size", ""))) for o in items),
                         "Invalid or out-of-scope backend inventory")
        contract.require(len({(o["name"], o["generation"]) for o in items}) == len(items), "Duplicate backend object generation")
        inventory[category] = items
    return inventory


def classify_backend(inventory):
    """Only metadata classification; a recognized candidate still needs byte checks."""
    live_ids = {(o["name"], o["generation"]) for o in inventory["live"]}
    historical = [o for o in inventory["versions"] if (o["name"], o["generation"]) not in live_ids]
    result = {"bucket": contract.BUCKET, "prefix": contract.PREFIX, "workspace": "default",
              "live": inventory["live"], "historical": historical, "soft_deleted": inventory["soft_deleted"]}
    scoped = lambda rows: [o for o in rows if o["name"].startswith(contract.PREFIX + "/")]
    current = scoped(inventory["live"])
    all_versions = scoped(inventory["versions"]) + scoped(inventory["soft_deleted"])
    if any(o["name"].endswith(".tflock") for o in current):
        result["classification"] = "blocked_current_lock"
    elif any(o["name"] not in {STATE_NAME, LOCK_NAME} for o in current + all_versions):
        result["classification"] = "blocked_unknown_object_or_workspace"
    else:
        states = [o for o in all_versions if o["name"] == STATE_NAME]
        current_states = [o for o in current if o["name"] == STATE_NAME]
        if not states and not current_states:
            result["classification"] = "uninitialized"
        elif (len(current_states) == 1 and len(states) == 1
              and all(current_states[0].get(k) == INITIAL_STATE[k] for k in ("name", "generation", "size"))
              and (STATE_NAME, INITIAL_STATE["generation"]) in {(o["name"], o["generation"]) for o in inventory["versions"]}):
            result["classification"] = "initial_state_pending_private_verification"
        else:
            result["classification"] = "blocked_state_provenance_unconfirmed"
    return result


def verify_initial_state(raw):
    """An exact inspected empty snapshot; no resource, output or new lineage adoption."""
    contract.require(len(raw) == int(INITIAL_STATE["size"])
                     and hashlib.sha256(raw).hexdigest() == INITIAL_STATE["sha256"],
                     "Existing state bytes differ from the inspected initial snapshot")
    state = json.loads(raw)
    contract.require(set(state) == {"version", "terraform_version", "serial", "lineage", "outputs", "resources", "check_results"}
                     and state["version"] == 4 and type(state["version"]) is int
                     and state["terraform_version"] == "1.15.8" and type(state["serial"]) is int and state["serial"] == 1
                     and state["lineage"] == INITIAL_STATE["lineage"]
                     and state["outputs"] == {} and state["resources"] == [] and state["check_results"] is None,
                     "State is not the recognized empty initial state; resources or uncertain provenance block planning")


def read_initial_state(work):
    """Generation-pinned read of this one state, never a generic object downloader."""
    params = {"alt": "media", "generation": INITIAL_STATE["generation"], "ifGenerationMatch": INITIAL_STATE["generation"]}
    url = ("https://storage.googleapis.com/storage/v1/b/" + contract.BUCKET + "/o/"
           + quote(STATE_NAME, safe="") + "?" + urlencode(params))
    request = Request(url, headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]})
    target = work / "initial-state-private.json"
    created = False
    try:
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
                raw = response.read(65537)
        except HTTPError as error:
            raise FailedOperation("read pinned initial state " + STATE_NAME,
                                  error.read(16384).decode("utf-8", errors="replace"), error.code) from None
        contract.require(len(raw) <= 65536, "Initial state exceeds the private inspection bound")
        with target.open("xb") as stream:
            created = True
            stream.write(raw)
        target.chmod(0o600)
        verify_initial_state(raw)
    finally:
        if created and target.exists():
            target.unlink()


def inspect_backend(bucket, work, reports, receipt):
    result = classify_backend(backend_inventory(bucket))
    receipt["backend"] = result
    # Metadata survives failures, but state contents never enter the summary.
    save_summary(reports, receipt)
    contract.require(result["classification"] in {"uninitialized", "initial_state_pending_private_verification"},
                     "Backend stopped: " + result["classification"] + "; no adoption, deletion or force-unlock is allowed")
    if result["classification"] == "initial_state_pending_private_verification":
        read_initial_state(work)
        # Detect a new live lock or changed generation before invoking Terraform.
        confirmed = classify_backend(backend_inventory(bucket))
        contract.require(confirmed["classification"] == result["classification"],
                         "Backend changed during private state verification; stop before Terraform")
        result = confirmed
        result["classification"] = "recognized_initial_state"
        result["initial_lineage"] = INITIAL_STATE["lineage"]
        result["initial_state_sha256"] = INITIAL_STATE["sha256"]
        receipt["backend"] = result
    save_summary(reports, receipt)
    return result


def checks(work, reports, receipt):
    sources = contract.source_contract(MODULE)
    module = work / "module"
    module.mkdir()
    (work / "terraform.rc").write_text('disable_checkpoint = true\n', encoding="utf-8")
    for name in contract.FILES:
        target = module / name
        target.parent.mkdir(exist_ok=True, parents=True)
        target.write_text(sources[name], encoding="utf-8", newline="\n")
    binary = terraform_binary()
    for label, arguments in [
        ("fmt", ["fmt", "-check", "-recursive"]),
        ("init_backend_false", ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"]),
        ("validate", ["validate", "-no-color"]),
    ]:
        run([binary, *arguments], label, work)
        receipt["checks"][label] = "passed"
    uid = str(os.getuid()) if hasattr(os, "getuid") else "10001"
    gid = str(os.getgid()) if hasattr(os, "getgid") else "10001"
    authored_tests = work / "contract-tests"
    for name in ("scripts/check_tf_int.py", "scripts/tf_int_plan.py", "scripts/int_release.py", "scripts/int_release_state.py",
                 "scripts/int_secrets.py", "scripts/int_bootstrap_vm.py", "scripts/int_bootstrap_db.py", "scripts/int_release_image.py",
                 "tests/test_tf_int.py", "tests/test_int_infra_release.py", "scripts/check_int_foundation.py",
                 "scripts/classify_int_foundation_sast.py", "scripts/prepare_ci_scan.py", "scripts/prepare_ci_context.py",
                 "tests/test_int_foundation.py", "tests/test_int_foundation_sast.py", "config/int-foundation-contract.json"):
        target = authored_tests / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--user", uid + ":" + gid,
         "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m", "--mount", "type=bind,source=" + str(authored_tests) + ",target=/source,readonly",
         "--workdir", "/source", PYTHON_IMAGE, "python", "-B", "-m", "unittest", "discover", "-s", "tests", "-v"],
        "python_negative_contracts", work)
    receipt["checks"]["python_negative_contracts"] = "passed_without_network"
    isolated = ["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--user", uid + ":" + gid,
         "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m", "--mount", "type=bind,source=" + str(module) + ",target=/source,readonly"]
    run([*isolated, "--mount", "type=bind,source=" + str(work / "terraform-data") + ",target=/tfdata,readonly",
         "--workdir", "/source", "--env", "TF_DATA_DIR=/tfdata", "--env", "TF_CLI_CONFIG_FILE=/dev/null",
         TERRAFORM_IMAGE, "test", "-no-color"], "native_mock_contracts", work)
    receipt["checks"]["native_mock_contracts"] = "passed_without_network"
    code, raw = run([*isolated,
         TRIVY, "config", "--skip-check-update", "--disable-telemetry", "--misconfig-scanners", "terraform",
         "--exit-code", "1", "--format", "json", "/source"], "iac_security", work, accepted=(0, 1))
    scan = json.loads(raw)
    results = scan.get("Results", [])
    contract.require(sum(t.get("MisconfSummary", {}).get("Successes", 0) for t in results) > 0, "IaC scan did not execute real checks")
    findings = [m for t in results for m in t.get("Misconfigurations", [])]
    contract.require(code == int(bool(findings)), "IaC scanner exit and report disagree")
    receipt["iac_findings"] = [{"id": m["ID"], "severity": m["Severity"], "title": m.get("Title", ""),
                                 "resource": m.get("CauseMetadata", {}).get("Resource", "unknown"),
                                 "start_line": m.get("CauseMetadata", {}).get("StartLine"),
                                 "end_line": m.get("CauseMetadata", {}).get("EndLine"),
                                 "decision": "pending_owner_decision_not_accepted",
                                 "control_proposed": "Cloud Audit Logs access records; bucket access-logging rule still reports"
                                      if m["ID"] == "GCP-0077" else "Google-managed default encryption; no customer key proposed"}
                                for m in findings]
    # Same HIGH/CRITICAL blocking level as the application scanners; lower
    # findings stay visible and unaccepted. This workflow cannot apply anything.
    contract.require(not any(m["Severity"] in {"HIGH", "CRITICAL"} for m in findings), "IaC HIGH/CRITICAL findings block planning")
    receipt["checks"]["iac_security"] = "reviewed_findings_not_accepted" if findings else "passed"
    receipt["status"] = "checks_passed"
    save_summary(reports, receipt)


def real_plan(work, reports, receipt):
    from scripts import int_release
    contract.validate_variables(os.environ)
    reviewed_inputs = int_release.inputs(os.environ)
    expected = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted"}
    contract.require(all(os.environ.get(k) == v for k, v in expected.items()), "Real plans are restricted to the approved hosted Actions context")
    adc = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
    contract.require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json",
                     "Only the current Actions federated credential file may be used")
    contract.require(os.environ.get("TF_WORKSPACE", "default") == "default", "Only the existing default workspace is authorized")
    backend = (work / "module/backend-int.hcl").read_text(encoding="utf-8")
    contract.require(dict(re.findall(r'^\s*(bucket|prefix)\s*=\s*"([^"]+)"\s*$', backend, re.M))
                     == {"bucket": contract.BUCKET, "prefix": contract.PREFIX}, "Backend configuration differs from the authorized existing backend")
    bucket = metadata("/b/" + contract.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    def inspect():
        if reviewed_inputs["stage"] == "runtime":
            from scripts.int_release_state import inspect_approved_foundation
            inspected = inspect_approved_foundation(bucket, work / "module", os.environ)
            receipt["backend"] = inspected
            save_summary(reports, receipt)
            return inspected
        return inspect_backend(bucket, work, reports, receipt)
    inspected = inspect()
    receipt["checks"]["backend_private_versioned_state_recognized"] = inspected["classification"]
    binary = terraform_binary()
    run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "init", work)
    receipt["checks"]["init"] = "passed"
    run([binary, "validate", "-no-color"], "validate_backend", work)
    receipt["checks"]["validate_backend"] = "passed"
    # Re-check after native init. A recognized snapshot must remain identical;
    # an existing state with resources is never adopted by this first-plan path.
    inspect()
    plan = work / "int.tfplan"
    code, _ = run([binary, "plan", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", "-detailed-exitcode",
                   "-var=machine_type=" + reviewed_inputs["machine_type"], "-var=runtime_image=" + reviewed_inputs["runtime_image"],
                   "-var=stage=" + reviewed_inputs["stage"],
                   "-var=secret_versions=" + json.dumps(reviewed_inputs["secret_versions"]), "-out=" + str(plan)],
                  "plan", work, accepted=(0, 1, 2))
    inspect()
    contract.require(contract.detailed_exit(code) != "error", "Plan returned exit code 1")
    _, raw = run([binary, "show", "-json", str(plan)], "private_plan_json", work)
    receipt.update(status="planned", plan_exit_code=code, plan=contract.plan_contract(json.loads(raw), (work / "module/postgres-install.sh").read_text()))
    (work / "private-plan.json").write_bytes(raw)
    receipt["private_plan"] = int_release.retain_plan(work, receipt["backend"], os.environ)
    receipt["full_plan_retained"] = True
    save_summary(reports, receipt)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["checks", "plan", "cleanup"])
    args = parser.parse_args(argv)
    os.umask(0o077)
    work, reports = private_paths()
    if args.operation == "cleanup":
        if work.exists():
            shutil.rmtree(work)
        print("Removed only this run's local private scratch; retained GCS plan objects remain private and immutable.")
        return 0
    receipt = {"schema": "clipforge-tf-int01-summary-1", "status": "started", "checks": {},
               "cost": cost_estimate(os.environ.get("MACHINE_TYPE", "e2-micro")),
               "full_plan_retained": False, "deployment_approved": False}
    if (reports / "summary.json").exists():
        receipt = json.loads((reports / "summary.json").read_text())
    try:
        if args.operation == "checks":
            checks(work, reports, receipt)
        else:
            real_plan(work, reports, receipt)
        print(json.dumps({"operation": args.operation, "status": receipt["status"]}))
        return 0
    except Exception as error:
        receipt.update(status="blocked", error=error.receipt if isinstance(error, FailedOperation)
                       else {"operation": args.operation, "error_type": type(error).__name__, "message": str(error)[:300]})
        if args.operation == "plan" and (work / "plan.log").exists() and not isinstance(error, FailedOperation):
            receipt["error"] = contract.diagnostic("plan", (work / "plan.log").read_text(errors="replace"), 1)
        save_summary(reports, receipt)
        print(json.dumps({"operation": args.operation, "status": "blocked", "error": receipt["error"]}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
