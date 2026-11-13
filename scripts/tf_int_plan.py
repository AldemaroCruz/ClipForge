"""TF-INT-01: curated validation and one real plan; no mutation command exists.

Only backend locking can write remotely. Complete plans, diagnostics and backend
files stay in a private runner scratch directory that final cleanup removes.
Only an explicit summary schema is permitted in logs and artifacts.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

try:
    from scripts import check_tf_int as contract
except ModuleNotFoundError:
    import check_tf_int as contract


ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "infra/gcp/int-base"
TRIVY = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6"
TERRAFORM_IMAGE = "hashicorp/terraform:1.15.8@sha256:7ae513256f7ce67879e218ae8593d6fbe216ec9e123abe6c94e4e10704857963"
PYTHON_IMAGE = "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"


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
             "Full plan/JSON/credentials are temporary, never uploaded, and removed by final cleanup.", ""]
    if "checks" in value:
        lines.extend(["Checks: " + ", ".join(k + "=" + str(v) for k, v in value["checks"].items()), ""])
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
                      "Services required (bootstrap-owned, no activation): Compute, Storage, IAM, IAP, OS Login, Artifact Registry, Secret Manager, STS.", ""])
    if "cost" in value:
        cost = value["cost"]
        lines.extend(["Estimated monthly USD before exclusions: " + str(cost["monthly_usd"]),
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
    return {"monthly_usd": round(base + hours * rates[machine + "_hour"], 2),
            "e2_small_monthly_usd": round(base + hours * rates["e2-small_hour"], 2),
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
    for name in ("scripts/check_tf_int.py", "scripts/tf_int_plan.py", "tests/test_tf_int.py"):
        target = authored_tests / name
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / name, target)
    run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only", "--cap-drop", "ALL",
         "--security-opt", "no-new-privileges", "--user", uid + ":" + gid,
         "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m", "--mount", "type=bind,source=" + str(authored_tests) + ",target=/source,readonly",
         "--workdir", "/source", PYTHON_IMAGE, "python", "-B", "-m", "unittest", "discover", "-s", "tests", "-p", "test_tf_int.py", "-v"],
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
    receipt["iac_findings"] = [{"id": m["ID"], "severity": m["Severity"],
                                 "resource": m.get("CauseMetadata", {}).get("Resource", "unknown")}
                                for m in findings]
    # Same HIGH/CRITICAL blocking level as the application scanners; lower
    # findings stay visible and unaccepted. This workflow cannot apply anything.
    contract.require(not any(m["Severity"] in {"HIGH", "CRITICAL"} for m in findings), "IaC HIGH/CRITICAL findings block planning")
    receipt["checks"]["iac_security"] = "reviewed_findings_not_accepted" if findings else "passed"
    receipt["status"] = "checks_passed"
    save_summary(reports, receipt)


def real_plan(work, reports, receipt):
    contract.validate_variables(os.environ)
    expected = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted"}
    contract.require(all(os.environ.get(k) == v for k, v in expected.items()), "Real plans are restricted to the approved hosted Actions context")
    adc = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
    contract.require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json",
                     "Only the current Actions federated credential file may be used")
    bucket = metadata("/b/" + contract.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    listing = metadata("/b/" + contract.BUCKET + "/o", {"prefix": contract.PREFIX + "/", "versions": "true", "maxResults": "1", "fields": "items(name,generation),nextPageToken"})
    contract.backend_contract(bucket, listing)
    if int(bucket.get("softDeletePolicy", {}).get("retentionDurationSeconds", 0)) > 0:
        soft_deleted = metadata("/b/" + contract.BUCKET + "/o", {"prefix": contract.PREFIX + "/", "softDeleted": "true", "maxResults": "1", "fields": "items(name,generation),nextPageToken"})
        contract.backend_contract(bucket, soft_deleted)
    receipt["checks"]["backend_private_versioned_prefix_unused"] = "passed"
    binary = terraform_binary()
    run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "init", work)
    receipt["checks"]["init"] = "passed"
    run([binary, "validate", "-no-color"], "validate_backend", work)
    receipt["checks"]["validate_backend"] = "passed"
    plan = work / "int.tfplan"
    code, _ = run([binary, "plan", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", "-detailed-exitcode",
                   "-var=machine_type=" + os.environ.get("MACHINE_TYPE", "e2-micro"), "-out=" + str(plan)],
                  "plan", work, accepted=(0, 1, 2))
    contract.require(contract.detailed_exit(code) != "error", "Plan returned exit code 1")
    _, raw = run([binary, "show", "-json", str(plan)], "private_plan_json", work)
    receipt.update(status="planned", plan_exit_code=code, plan=contract.plan_contract(json.loads(raw), (work / "module/postgres-install.sh").read_text()))
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
        print("Removed only this run's private Terraform scratch; no full plan remains available.")
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
