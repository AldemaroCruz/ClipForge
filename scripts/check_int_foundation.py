"""Foundation evidence and one-plan approval contract, independent of app CI.

Integrity checks never manufacture security acceptance. Pending native findings
remain visible and block apply unless an owner supplies the exact, hashed
single-plan decision described in the evidence. Runtime keeps its existing gate.
"""
from __future__ import annotations
from collections import Counter
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import os
from pathlib import Path
import shutil
from urllib.error import HTTPError
from urllib.parse import urlencode, urlsplit
from urllib.request import Request, ProxyHandler, build_opener, HTTPRedirectHandler
import zipfile

from scripts import check_tf_int as c, int_release as release, tf_int_plan as driver
from scripts import classify_int_foundation_sast as sast
from scripts import prepare_ci_scan

ROOT = Path(__file__).resolve().parents[1]
CONTRACT = "config/int-foundation-contract.json"
REPORT_SCHEMA = "clipforge-int-foundation-evidence-1"
DECISION_SCHEMA = "clipforge-int-foundation-single-plan-decision-1"
WORKFLOW = ".github/workflows/int-foundation-check.yml"
BUNDLE = ("foundation-report.json", "bandit-native.json", "iac-native.json", "gitleaks-native.json")
REQUIRED_CHECKS = {"static_scope_bindings_cost_iam", "fmt", "init_backend_false", "validate", "bandit_install_offline",
                   "gitleaks", "actionlint", "vm_startup_shellcheck", "python_contracts", "native_mock_contracts", "iac_native", "bandit_native"}


def load_contract(root=ROOT):
    value = json.loads((root / CONTRACT).read_text(encoding="utf-8"))
    c.require(value.get("schema") == "clipforge-int-foundation-contract-1", "Unknown foundation contract")
    return value


def scope_files(contract):
    scope = contract["scope"]
    return sorted(set(scope["executed_python"] + scope["test_support_python"] + scope["tests"]
                      + scope["workflows"] + scope["config"]
                      + ["infra/gcp/int-base/" + name for name in scope["module_files"]]))


def fingerprint(root, contract):
    names = scope_files(contract)
    prepare_ci_scan.validate_paths(names)
    values = {}
    for name in names:
        target = root / name
        prepare_ci_scan.context._check_components(target)
        c.require(not target.is_symlink() and target.is_file(), "Incomplete foundation source scope")
        values[name] = release.sha256(target.read_bytes())
    return release.sha256(release.canonical(values)), values


def check_static(root, module, contract):
    c.require(tuple(contract["scope"]["module_files"]) == c.FILES, "Foundation Terraform inventory changed")
    c.source_contract(module)
    binding = release.source_binding(module, {"GITHUB_SHA": contract["plan"]["commit"],
                                            "RUNTIME_IMAGE": contract["plan"]["inputs"]["runtime_image"]})
    for key in ("configuration_sha256", "provider_lock_sha256", "terraform_version", "inputs"):
        c.require(binding[key] == contract["plan"][key], "Original foundation plan binding changed: " + key)
    c.require(sorted(c.FOUNDATION_ADDRESSES) == contract["plan"]["managed_addresses"], "Foundation resource scope changed")
    c.require(release.sha256((root / ".gitleaks.toml").read_bytes()) == contract["unchanged_gitleaks_policy_sha256"],
              "Secret policy changed; fresh precision evidence and review are required")
    cost = json.loads((root / "config/tf-int01-costs.json").read_text())
    c.require(cost["region"] == c.REGION and cost["hours_per_month"] == 730, "Cost scope changed")
    return binding


def prepare(work, paths):
    contract = load_contract()
    prepare_ci_scan.prepare_scan(ROOT, paths, work / "source")
    source = work / "source"
    fingerprint(source, contract)
    module = work / "module"
    module.mkdir()
    for name in c.FILES:
        target = module / name
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text((source / "infra/gcp/int-base" / name).read_text(), newline="\n")
    (work / "terraform.rc").write_text("disable_checkpoint = true\n")
    check_static(source, module, contract)
    lock = (source / "requirements-ci-tools.lock").read_text().splitlines()
    packages = contract["tools"]["bandit_wheels"]
    selected = [line for line in lock if any(line.startswith(name + "==") for name in packages)]
    c.require(len(selected) == len(packages) and all(" --hash=sha256:" in line for line in selected), "Missing pinned Bandit dependency")
    (work / "bandit.lock").write_text("\n".join(selected) + "\n")
    return contract


def bandit_contract(raw, contract):
    expected = {"/source/" + name for name in contract["scope"]["executed_python"]}
    c.require(raw.get("errors") == [] and set(raw.get("metrics", {})) == expected | {"_totals"},
              "Bandit must analyze the complete foundation execution closure without errors")
    c.require(raw["metrics"]["_totals"].get("loc", 0) > 0, "Bandit executed no source checks")
    fields = {"loc", "nosec", "skipped_tests"} | {kind + "." + level for kind in ("CONFIDENCE", "SEVERITY")
               for level in ("HIGH", "MEDIUM", "LOW", "UNDEFINED")}
    for metrics in raw["metrics"].values():
        c.require(set(metrics) == fields and all(type(v) is int and v >= 0 for v in metrics.values()), "Missing native Bandit metrics")
        c.require(metrics["nosec"] == 0 and metrics["skipped_tests"] == 0, "Bandit suppression is forbidden")
    totals = raw["metrics"]["_totals"]
    c.require(all(totals[field] == sum(raw["metrics"][name][field] for name in expected) for field in fields), "Native Bandit metric totals differ")
    c.require(all(issue.get("filename") in expected for issue in raw.get("results", [])), "Unexpected Bandit source")
    for kind, field in (("SEVERITY", "issue_severity"), ("CONFIDENCE", "issue_confidence")):
        counts = Counter(issue.get(field) for issue in raw.get("results", []))
        c.require(set(counts) <= {"HIGH", "MEDIUM", "LOW", "UNDEFINED"}
                  and all(totals[kind + "." + level] == counts[level] for level in ("HIGH", "MEDIUM", "LOW", "UNDEFINED")),
                  "Native Bandit findings contradict metrics")


def iac_contract(raw, contract):
    results = raw.get("Results", [])
    c.require(sum(row.get("MisconfSummary", {}).get("Successes", 0) for row in results) > 0, "IaC scanner did not execute")
    rows = [{"id": finding["ID"], "severity": finding["Severity"], "resource": finding.get("CauseMetadata", {}).get("Resource")}
            for result in results for finding in result.get("Misconfigurations", [])]
    canonical = lambda items: Counter(release.canonical(row) for row in items)
    c.require(canonical(rows) == canonical(contract["iac_findings_preserved"]), "New or changed IaC finding requires review")
    c.require(not any(row["severity"] in {"HIGH", "CRITICAL"} for row in rows), "Foundation IaC HIGH/CRITICAL blocks apply")
    return rows


def checks(work, reports):
    contract = load_contract(work / "source")
    source = work / "source"
    source_hash, source_files = fingerprint(source, contract)
    report = {"schema": REPORT_SCHEMA, "phase": "foundation", "control_commit": os.environ.get("GITHUB_SHA", "local_uncommitted_snapshot"),
              "contract_sha256": release.sha256((source / CONTRACT).read_bytes()), "control_sources_sha256": source_hash,
              "source_files": source_files, "plan": contract["plan"], "integrity": {}, "readiness": "blocked",
              "application_ci": "separate_contract_not_reclassified", "vm_inventory_sca_tls_restore": "not_proven_before_creation"}
    uid = str(os.getuid()) if hasattr(os, "getuid") else "10001"
    gid = str(os.getgid()) if hasattr(os, "getgid") else "10001"
    base = ["docker", "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=" + uid + ":" + gid, "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m"]
    source_mount = ["--mount", "type=bind,source=" + str(source) + ",target=/source,readonly"]
    report_mount = ["--mount", "type=bind,source=" + str(reports) + ",target=/reports"]
    def check(name, command, accepted=(0,)):
        try:
            code, raw = driver.run(command, "foundation_" + name, work, accepted=accepted)
            report["integrity"][name] = {"status": "passed", "native_exit": code}
            return code, raw
        except Exception:
            report["integrity"][name] = {"status": "failed", "message": "Private check failed; no raw command log is published"}
            return None, b""
    check_static(source, work / "module", contract)
    report["integrity"]["static_scope_bindings_cost_iam"] = {"status": "passed"}
    binary = driver.terraform_binary()
    for name, args in (("fmt", ["fmt", "-check", "-recursive"]),
                       ("init_backend_false", ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"]),
                       ("validate", ["validate", "-no-color"])):
        check(name, [binary, *args])
    # Dependencies were downloaded in a separate networked preparation step.
    check("bandit_install_offline", [*base, "--mount", "type=bind,source=" + str(work) + ",target=/private", contract["tools"]["python"],
          "python", "-m", "pip", "install", "--disable-pip-version-check", "--no-cache-dir", "--no-index", "--no-deps", "--require-hashes",
          "--find-links=/private/wheels", "--target=/private/bandit-tools", "-r", "/private/bandit.lock"])
    code, raw = check("gitleaks", [*base, *source_mount, *report_mount, contract["tools"]["gitleaks"], "dir", "/source", "--config", "/source/.gitleaks.toml",
              "--no-banner", "--redact=100", "--ignore-gitleaks-allow", "--exit-code=1", "--report-format=json", "--report-path=/reports/gitleaks-native.json"], (0, 1))
    leaks = json.loads((reports / "gitleaks-native.json").read_text()) if (reports / "gitleaks-native.json").exists() else None
    if code != 0 or leaks != []:
        report["integrity"]["gitleaks"]["status"] = "failed"
    check("actionlint", [*base, *source_mount, "--workdir=/source", contract["tools"]["actionlint"], "-color", *contract["scope"]["workflows"]])
    # ShellCheck's scratch image has no /etc/os-release. This explicit schema
    # fixture supplies only the two referenced names; it is not VM evidence.
    schema = work / "os-release-lint-schema"
    schema.write_text("# Static lint schema only; not VM inventory or package proof.\nID=debian\nVERSION_CODENAME=trixie\n")
    check("vm_startup_shellcheck", [*base, *source_mount, "--mount", "type=bind,source=" + str(schema) + ",target=/etc/os-release,readonly",
          contract["tools"]["shellcheck"], "--external-sources", "--severity=style", "/source/infra/gcp/int-base/postgres-install.sh"])
    report["integrity"]["vm_startup_shellcheck"]["scope"] = "Static script plus explicit ID/VERSION_CODENAME schema fixture; not a VM or package scan"
    check("python_contracts", [*base, *source_mount, "--workdir=/source", contract["tools"]["python"], "python", "-B", "-m", "unittest",
          "tests.test_tf_int", "tests.test_int_infra_release", "tests.test_int_foundation", "tests.test_int_foundation_sast", "-v"])
    check("native_mock_contracts", [*base, "--mount", "type=bind,source=" + str(work / "module") + ",target=/source,readonly",
          "--mount", "type=bind,source=" + str(work / "terraform-data") + ",target=/tfdata,readonly", "--workdir=/source",
          "--env=TF_DATA_DIR=/tfdata", "--env=TF_CLI_CONFIG_FILE=/dev/null", contract["tools"]["terraform"], "test", "-no-color"])
    code, raw = check("iac_native", [*base, "--mount", "type=bind,source=" + str(work / "module") + ",target=/source,readonly", contract["tools"]["trivy"],
          "config", "--skip-check-update", "--disable-telemetry", "--misconfig-scanners", "terraform", "--exit-code=1", "--format=json", "/source"], (0, 1))
    if raw:
        (reports / "iac-native.json").write_bytes(raw)
        try:
            report["iac_findings"] = iac_contract(json.loads(raw), contract)
        except ValueError:
            report["integrity"]["iac_native"]["status"] = "failed"
    if report["integrity"]["gitleaks"]["status"] == "passed":
        code, _ = check("bandit_native", [*base, *source_mount, *report_mount,
              "--mount", "type=bind,source=" + str(work / "bandit-tools") + ",target=/tools,readonly", "--env=PYTHONPATH=/tools", "--workdir=/source",
              contract["tools"]["python"], "python", "-B", "-m", "bandit", "--severity-level=all", "--confidence-level=all", "--ignore-nosec",
              "--format=json", "--output=/reports/bandit-native.json", *["/source/" + name for name in contract["scope"]["executed_python"]]], (0, 1))
        if (reports / "bandit-native.json").exists():
            native = json.loads((reports / "bandit-native.json").read_text())
            try:
                bandit_contract(native, contract)
                c.require(code == int(bool(native["results"])), "Bandit native exit disagrees with report")
                report["sast"] = sast.evaluate(source, native)
            except ValueError:
                report["integrity"]["bandit_native"]["status"] = "failed"
    report["integrity_status"] = "passed" if set(report["integrity"]) == REQUIRED_CHECKS and all(row["status"] == "passed" for row in report["integrity"].values()) else "failed"
    report["residual_controls"] = contract["residual_controls"]
    report["readiness"] = "blocked"  # F-AUDIT-0077/F-VM-XML remain individual decisions even if SAST has no findings.
    report["native_report_sha256"] = {name: release.sha256((reports / name).read_bytes()) for name in BUNDLE[1:] if (reports / name).exists()}
    report["pending_owner_decision"] = decision_template(report, contract)
    (reports / "foundation-report.json").write_text(json.dumps(report, indent=2) + "\n")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a") as stream:
            stream.write("Foundation integrity: **" + report["integrity_status"] + "**; security readiness: **" + report["readiness"] + "**.\n\nApplication CI retains its separate result. No apply or risk acceptance was performed.\n\n```json\n" + json.dumps(report["pending_owner_decision"], indent=2) + "\n```\n")
            stream.write("Evidence canonical SHA256: `" + release.sha256(release.canonical(report)) + "`. The displayed decision remains pending.\n")
    return report


def decision_template(report, contract):
    residual = [row for row in report.get("sast", {}).get("findings", []) if row.get("disposition") == "risk_pending"]
    return {"schema": DECISION_SCHEMA, "plan_commit": contract["plan"]["commit"], "control_commit": report["control_commit"],
            "manifest": contract["plan"]["manifest"], "binary": contract["plan"]["binary"],
            "configuration_sha256": contract["plan"]["configuration_sha256"], "provider_lock_sha256": contract["plan"]["provider_lock_sha256"],
            "inputs": contract["plan"]["inputs"], "backend": contract["plan"]["backend"],
            "control_sources_sha256": report["control_sources_sha256"], "evidence_sha256": None,
            "expires_utc": (datetime.fromisoformat(contract["plan"]["created_utc"]) + timedelta(seconds=86400)).isoformat(),
            "apply_decision": "pending_not_authorized", "residual_decisions": [
                {"id": "F-SAST-EXEC", "decision": "pending_not_accepted", "findings": residual},
                *[{**row, "decision": "pending_not_accepted"} for row in contract["residual_controls"]]]}


def verify_plan_bridge(manifest, module, environ, reference, contract=None):
    contract = contract or load_contract()
    plan = contract["plan"]
    c.require(environ.get("INT_STAGE") == "foundation" and isinstance(manifest.get("inputs"), dict)
              and manifest["inputs"].get("stage") == "foundation", "The control bridge is foundation-only")
    c.require(environ.get("INT_APPROVED_PLAN_COMMIT") == plan["commit"] == manifest.get("commit")
              and environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"), "Both exact plan and control commits need explicit approval")
    c.require(reference == plan["manifest"] and all(manifest.get(key) == plan[key] for key in
              ("binary", "json", "configuration_sha256", "provider_lock_sha256", "terraform_version", "inputs", "backend", "created_utc")),
              "The bridge cannot change or reseal the approved saved plan")
    binding = release.source_binding(module, environ)
    c.require(all(binding[key] == manifest[key] for key in ("inputs", "configuration_sha256", "provider_lock_sha256", "terraform_version", "repository", "branch")),
              "Plan and control checkout differ in Terraform/startup/provider/inputs")


def verify_owner_decision(decision, expected_sha, report, contract):
    c.require(release.sha256(release.canonical(decision)) == expected_sha, "Owner decision hash differs from the reviewed canonical JSON")
    expected = decision_template(report, contract)
    c.require(set(decision) == set(expected) and all(decision[key] == expected[key] for key in expected
              if key not in {"apply_decision", "residual_decisions", "evidence_sha256", "expires_utc"}), "Owner decision does not bind this exact plan, control and evidence scope")
    c.require(decision["evidence_sha256"] == release.sha256(release.canonical(report)), "Owner decision names different foundation evidence")
    expires = datetime.fromisoformat(decision["expires_utc"])
    c.require(datetime.now(timezone.utc) < expires <= datetime.fromisoformat(expected["expires_utc"]), "Decision cannot extend the original plan lifetime")
    c.require(decision["apply_decision"] == "approve_exact_foundation_binary_once", "No specific saved-plan apply authorization")
    residual = expected["residual_decisions"][0]["findings"]
    # This is one named residual, not a general exception mechanism. Every other
    # native finding/error/high severity remains inadmissible.
    allowed = {("B404", 16), ("B603", 169), ("B603", 180)}
    c.require(all(row.get("resource") == "scripts/tf_int_plan.py" and row.get("severity") == "LOW"
                  and (row.get("rule"), row.get("line")) in allowed for row in residual)
              and len({(row["rule"], row["line"]) for row in residual}) == len(residual), "Unknown or higher-risk finding cannot be accepted through F-SAST-EXEC")
    required = [] if not residual else [{"id": "F-SAST-EXEC", "decision": "approve_exact_execution_sites_for_this_binary_only", "findings": residual}]
    decisions = {"F-AUDIT-0077": "approve_this_alternative_with_mandatory_operational_validation",
                 "F-VM-XML": "approve_expected_dependency_install_inactive_only_with_mandatory_vm_inventory_review"}
    required.extend({**row, "decision": decisions[row["id"]]} for row in contract["residual_controls"])
    c.require(decision["residual_decisions"] == required, "Unresolved execution warnings still block foundation apply")
    c.require(report["integrity_status"] == "passed", "Failed integrity checks cannot be overridden by a risk decision")
    c.require(set(report.get("integrity", {})) == REQUIRED_CHECKS
              and all(row.get("status") == "passed" for row in report["integrity"].values()), "Incomplete foundation checks cannot authorize apply")


class StopRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def github_json(path, environ):
    opener = build_opener(ProxyHandler({}), StopRedirect())
    request = Request("https://api.github.com/repos/AldemaroCruz/ClipForge" + path, headers={
        "Authorization": "Bearer " + environ["GH_TOKEN"], "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with opener.open(request, timeout=60) as response:
        raw = response.read(1024 * 1024 + 1)
    c.require(len(raw) <= 1024 * 1024, "Foundation GitHub evidence exceeds bound")
    return json.loads(raw)


def fetch_evidence(environ, root=ROOT):
    contract = load_contract(root)
    commit = environ["GITHUB_SHA"]
    runs = github_json("/actions/workflows/int-foundation-check.yml/runs?" + urlencode({"head_sha": commit, "branch": contract["branch"], "per_page": 100}), environ)["workflow_runs"]
    runs = [row for row in runs if row.get("head_sha") == commit and row.get("head_branch") == contract["branch"] and row.get("path") == WORKFLOW]
    c.require(bool(runs), "No exact-control-commit foundation evidence exists")
    run = max(runs, key=lambda row: (row["run_number"], row["run_attempt"]))
    c.require(run.get("status") == "completed" and run.get("conclusion") in {"success", "failure"}
              and run.get("event") in {"push", "workflow_dispatch"}, "Foundation evidence run is incomplete, cancelled or from another event")
    name = "int-foundation-evidence-" + commit + "-" + str(run["id"]) + "-" + str(run["run_attempt"])
    artifacts = github_json("/actions/runs/" + str(run["id"]) + "/artifacts?per_page=100", environ)["artifacts"]
    matches = [row for row in artifacts if row.get("name") == name and row.get("expired") is False]
    c.require(len(matches) == 1, "Missing or ambiguous exact foundation evidence artifact")
    request = Request("https://api.github.com/repos/AldemaroCruz/ClipForge/actions/artifacts/" + str(matches[0]["id"]) + "/zip",
                      headers={"Authorization": "Bearer " + environ["GH_TOKEN"]})
    opener = build_opener(ProxyHandler({}), StopRedirect())
    try:
        response = opener.open(request, timeout=60)
    except HTTPError as error:
        c.require(error.code == 302, "Cannot download private foundation evidence")
        location = error.headers.get("Location", "")
        target = urlsplit(location)
        c.require(target.scheme == "https" and not target.username and not target.password and not target.fragment
                  and target.hostname and target.hostname.endswith((".blob.core.windows.net", ".actions.githubusercontent.com")),
                  "Unexpected artifact storage redirect")
        # Never forward the GitHub token to the signed storage URL or log it.
        response = opener.open(Request(location), timeout=60)
    with response:
        raw = response.read(16 * 1024 * 1024 + 1)
    c.require(len(raw) <= 16 * 1024 * 1024, "Foundation evidence archive exceeds bound")
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        c.require(len(archive.namelist()) == len(BUNDLE) and set(archive.namelist()) == set(BUNDLE), "Unexpected foundation evidence archive contents")
        data = {}
        for name in BUNDLE:
            item = archive.getinfo(name)
            c.require(item.file_size <= 8 * 1024 * 1024, "Foundation evidence member exceeds bound")
            data[name] = archive.read(name)
    report = json.loads(data["foundation-report.json"])
    source_hash, files = fingerprint(root, contract)
    c.require(report.get("schema") == REPORT_SCHEMA and report.get("control_commit") == commit
              and report.get("contract_sha256") == release.sha256((root / CONTRACT).read_bytes())
              and report.get("control_sources_sha256") == source_hash and report.get("source_files") == files
              and report.get("plan") == contract["plan"], "Foundation evidence source/contract/plan bindings differ")
    c.require(all(release.sha256(data[name]) == report["native_report_sha256"][name] for name in BUNDLE[1:]), "Native evidence bytes changed")
    native = json.loads(data["bandit-native.json"])
    bandit_contract(native, contract)
    c.require(report["sast"] == sast.evaluate(root, native), "SAST classifications do not reproduce from exact native findings/source")
    iac_contract(json.loads(data["iac-native.json"]), contract)
    c.require(json.loads(data["gitleaks-native.json"]) == [], "Secret findings block foundation")
    return report


def require_foundation_ci(environ, root=ROOT):
    report = fetch_evidence(environ, root)
    decision = json.loads(environ.get("FOUNDATION_DECISION_JSON", "null"))
    c.require(isinstance(decision, dict), "A reviewed plan-specific owner decision is required; int approval alone is insufficient")
    verify_owner_decision(decision, environ.get("FOUNDATION_DECISION_SHA256", ""), report, load_contract(root))
    return {"plan_commit": decision["plan_commit"], "control_commit": decision["control_commit"],
            "decision_sha256": environ["FOUNDATION_DECISION_SHA256"], "evidence_sha256": decision["evidence_sha256"]}


def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["prepare", "checks"])
    parser.add_argument("--paths", type=Path)
    args = parser.parse_args()
    os.umask(0o077)
    work, reports = driver.private_paths()
    if args.operation == "prepare":
        c.require(args.paths is not None, "Complete tracked-path input required")
        prepare(work, args.paths)
        return 0
    report = checks(work, reports)
    print(json.dumps({"integrity": report["integrity_status"], "security_readiness": report["readiness"], "apply_executed": False}))
    return 0 if report["readiness"] == "ready_for_specific_approval" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception:
        print("Foundation validation blocked; private diagnostics retained locally, no acceptance or apply performed.")
        raise SystemExit(1)
