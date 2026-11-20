"""Preview the isolated Noble candidate using the existing private INT backend."""

import argparse
from collections import Counter
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from ipaddress import ip_address, ip_network
import json
import os
from pathlib import Path
import re
import shutil
import sys
from urllib.error import HTTPError
from urllib.parse import urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts import check_tf_int as contract
from scripts import db01_noble_diagnostic as native_diagnostic
from scripts import int_foundation_verify as foundation
from scripts import int_db01_noble_read_iam as stable_iam
from scripts import int_release as custody
from scripts import int_release_state as state_reader
from scripts import tf_int_plan as driver


ROOT = driver.ROOT
MODULE = Path("infra/gcp/int-base")
FAMILY = "ubuntu-2404-lts-amd64"
IMAGE_PROJECT = "ubuntu-os-cloud"
IMAGE_ROOT = f"projects/{IMAGE_PROJECT}/global"
API = "https://www.googleapis.com/compute/v1/"
PROJECT_ROOT = "projects/clipforgebeta2/"
SUBNET = "regions/us-central1/subnetworks/clipforge-int-base-postgres"
NETWORK = "global/networks/clipforge-int-base"
ROUTER = "regions/us-central1/routers/clipforge-int-base-egress"
ADDRESS = "10.80.1.3"
EXISTING = contract.FOUNDATION_ADDRESSES
CREATES = {
    "google_service_account.noble[0]",
    "google_compute_address.noble[0]",
    "google_compute_disk.noble_boot[0]",
    "google_compute_disk.noble_data[0]",
    "google_compute_instance.noble[0]",
    "google_compute_firewall.noble_iap[0]",
    "google_compute_firewall.noble_https[0]",
    "google_compute_firewall.noble_deny_egress[0]",
    "google_compute_instance_iam_member.noble_deploy[0]",
    "google_iap_tunnel_instance_iam_member.noble_deploy[0]",
    "google_service_account_iam_member.noble_deploy[0]",
}
RUNTIME_PLACEHOLDER = (
    "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@"
    "sha256:d4b65631b30c26785ae18898cd826990fa20b4dce45015fb241ba108ddba7d49"
)
IMAGE_FIELDS = "name,id,status,architecture,family,selfLink,creationTimestamp,deprecated,licenses,diskSizeGb"
IMAGE_QUERY = {"fields": IMAGE_FIELDS, "$apiVersion": "2026-09-01"}
NOBLE_FILES = (
    "noble-candidate.tf",
    "db01-noble-startup.sh",
    "db01-noble-hostkey-template.sh",
    "tests/noble-candidate.tftest.hcl",
)
HELPERS = ("scripts/int_vm_hostkey_guest.py", "scripts/int_noble_hostkey.py")
SCHEMA = "clipforge-db01-noble-private-plan-1"
SUMMARY_SCHEMA = "clipforge-db01-noble-plan-summary-1"
BACKEND_FIELDS = {*foundation.STATE_PIN, "managed_addresses", "current_lock_absent"}
IAM_PROOF_LIMIT = 256 * 1024
PRIVATE_FILES = {"binary": "int.tfplan", "json": "int.json", "manifest": "manifest.json"}
SUMMARY_SECTIONS = {
    "checks": "Checks",
    "iac_findings": "IaC findings pending review",
    "image": "Verified Noble image",
    "backend": "Observed backend evidence",
    "network": "Observed candidate network",
    "iam_refresh": "Verified stable IAM policy delta and native refresh",
    "plan_exit_code": "Native detailed exit code",
    "actions": "Observed managed actions",
    "private_plan": "Private object receipts",
    "diagnostic": "Sanitized operation failure",
    "summary_error": "Summary failure",
}
REQUIRE = contract.require


class Blocked(ValueError):
    def __init__(self, operation, status=None, error_type=None):
        self.operation = operation
        self.status = status
        self.error_type = error_type
        super().__init__(operation)


def compute_get(path, operation, **params):
    request = Request(API + path + "?" + urlencode(params), method="GET",
                      headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=45) as response:
            raw = response.read(2 * 1024 * 1024 + 1)
    except HTTPError as error:
        raise Blocked(operation, error.code) from None
    REQUIRE(len(raw) <= 2 * 1024 * 1024, "Compute read exceeded its bound")
    return json.loads(raw)


def image_identity(image):
    name, numeric = image["name"], str(image["id"])
    REQUIRE(re.fullmatch(r"ubuntu-2404-noble-amd64-v[0-9]{8}[a-z]?", name)
            and re.fullmatch(r"[1-9][0-9]*", numeric) and image["family"] == FAMILY
            and image["status"] == "READY" and image["architecture"] == "X86_64"
            and image["selfLink"] == API + IMAGE_ROOT + "/images/" + name
            and image.get("deprecated", {}).get("state") in {None, "ACTIVE"}
            and 0 < int(image["diskSizeGb"]) <= 10, "Unexpected standard Noble image identity")
    licenses = image.get("licenses", [])
    REQUIRE(licenses == [API + IMAGE_ROOT + "/licenses/ubuntu-2404-lts"], "Unexpected Noble license")
    return {key: image[key] for key in ("name", "id", "status", "architecture", "family", "selfLink",
                                         "creationTimestamp", "diskSizeGb", "licenses")}


def resolve_image():
    discovered = image_identity(compute_get(IMAGE_ROOT + "/images/family/" + FAMILY,
                                            "public_noble_family", **IMAGE_QUERY))
    exact = image_identity(compute_get(IMAGE_ROOT + "/images/" + discovered["name"],
                                       "exact_public_noble_image", **IMAGE_QUERY))
    REQUIRE(exact == discovered, "Family discovery and exact image identity disagree")
    return exact


def check_instance_addresses():
    # Compare NIC addresses locally. The equality filter cannot traverse repeated NICs.
    params = {"maxResults": 100, "returnPartialSuccess": "true",
              "fields": "nextPageToken,unreachables,warning/code,"
                        "items/*/warning/code,items/*/instances/networkInterfaces(networkIP,ipv6Address,aliasIpRanges/ipCidrRange)"}
    seen = set()
    address = ip_address(ADDRESS)
    for _ in range(10):
        page = compute_get(PROJECT_ROOT + "aggregated/instances", "check_candidate_ip_in_use", **params)
        REQUIRE(isinstance(page, dict) and page.get("unreachables", []) == [], "Incomplete instance page")
        zones = page.get("items", {})
        warning = page.get("warning", {}).get("code")
        REQUIRE(warning in (None, "NO_RESULTS_ON_PAGE")
                and isinstance(zones, dict) and (zones or warning == "NO_RESULTS_ON_PAGE"),
                "Candidate IP observation has incomplete instance coverage")
        for zone in zones.values():
            instances = zone.get("instances", [])
            warning = zone.get("warning", {}).get("code")
            REQUIRE(isinstance(instances, list) and warning in (None, "NO_RESULTS_ON_PAGE")
                    and (instances or warning == "NO_RESULTS_ON_PAGE"), "Incomplete zonal instance list")
            for instance in instances:
                interfaces = instance.get("networkInterfaces")
                REQUIRE(isinstance(interfaces, list) and interfaces, "Instance NIC evidence is missing")
                for nic in interfaces:
                    primary = nic.get("networkIP")
                    aliases = nic.get("aliasIpRanges", [])
                    REQUIRE(isinstance(aliases, list) and (primary or nic.get("ipv6Address")),
                            "Instance NIC has incomplete address evidence")
                    REQUIRE((not primary or address != ip_address(primary))
                            and all(address not in ip_network(alias["ipCidrRange"], strict=False) for alias in aliases),
                            "Candidate private IP is in use")
        token = page.get("nextPageToken", "")
        REQUIRE(isinstance(token, str) and token not in seen, "Instance pagination did not advance")
        if not token:
            return
        seen.add(token)
        params["pageToken"] = token
    raise Blocked("candidate_ip_pagination_bound")


def preflight_network():
    subnet = compute_get(PROJECT_ROOT + SUBNET, "read_noble_subnet",
                         fields="name,ipCidrRange,network,privateIpGoogleAccess,stackType")
    REQUIRE(subnet == {"name": "clipforge-int-base-postgres", "ipCidrRange": "10.80.1.0/28",
                       "network": API + PROJECT_ROOT + NETWORK, "privateIpGoogleAccess": True,
                       "stackType": "IPV4_ONLY"}, "PostgreSQL subnet differs from reviewed network")
    router = compute_get(PROJECT_ROOT + ROUTER, "read_existing_nat",
                         fields="network,nats(name,natIpAllocateOption,sourceSubnetworkIpRangesToNat,subnetworks(name,sourceIpRangesToNat))")
    matches = [nat for nat in router.get("nats", []) if nat["name"] == "clipforge-int-base-maintenance"]
    REQUIRE(router["network"] == subnet["network"] and len(matches) == 1
            and matches[0]["natIpAllocateOption"] == "AUTO_ONLY"
            and matches[0]["sourceSubnetworkIpRangesToNat"] == "LIST_OF_SUBNETWORKS"
            and any(s["name"].endswith("/" + SUBNET) and s["sourceIpRangesToNat"] == ["PRIMARY_IP_RANGE"]
                    for s in matches[0]["subnetworks"]), "Existing NAT does not cover the candidate subnet")
    reserved = compute_get(PROJECT_ROOT + "regions/us-central1/addresses", "check_reserved_candidate_ip",
                           filter=f'address = "{ADDRESS}"', fields="nextPageToken,items(address,subnetwork)")
    REQUIRE(not reserved.get("nextPageToken") and not reserved.get("items"),
            "Candidate private IP is reserved or availability is incomplete")
    check_instance_addresses()
    return {"subnet": SUBNET, "nat": matches[0]["name"], "private_ip": ADDRESS, "observed_available": True}


def state_identity():
    bucket = driver.metadata("/b/" + contract.BUCKET,
                             {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    raw, obj, summary = state_reader.private_current_state(bucket)
    scoped = [item for item in summary["live"] if item["name"].startswith(contract.PREFIX + "/")]
    return foundation.validate_current_state(raw, obj, {"items": scoped}, {"state": foundation.STATE_PIN})


def snapshot(work):
    source = work / "source"
    paths = (*[MODULE / name for name in (*contract.FILES, *NOBLE_FILES)], *map(Path, HELPERS))
    binding = {}
    for path in paths:
        original = ROOT / path
        REQUIRE(original.is_file() and not original.is_symlink(), "Exact source missing")
        raw = original.read_bytes()
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
        binding[path.as_posix()] = custody.sha256(raw)
    (work / "module").symlink_to(source / MODULE, target_is_directory=True)
    (work / "terraform.rc").write_text("disable_checkpoint = true\n", encoding="utf-8")
    return binding


def digest(value):
    return custody.sha256(custody.canonical(value))


def verify_iam_reference(reference, commit):
    REQUIRE(isinstance(reference, dict) and reference.keys() == {"name", "generation", "sha256", "size"}
            and all(isinstance(reference[key], str) for key in ("name", "generation", "sha256"))
            and reference["name"] == stable_iam.proof_name(commit)
            and re.fullmatch(r"[1-9][0-9]*", reference["generation"])
            and re.fullmatch(r"[a-f0-9]{64}", reference["sha256"])
            and type(reference["size"]) is int and 0 < reference["size"] <= IAM_PROOF_LIMIT,
            "Invalid stable READ proof reference")


@contextmanager
def guarded_phase(operation):
    try:
        yield
    except Exception as error:
        if isinstance(error, HTTPError):
            status = error.code
        elif isinstance(error, stable_iam.CloudError):
            status = error.status
        else:
            status = None
        raise Blocked(operation, status, type(error).__name__) from None


def load_iam_evidence(environ):
    profile, profile_sha256 = stable_iam.load_profile()
    commit = environ["GITHUB_SHA"]
    reference = foundation.decode(environ["DB01_NOBLE_IAM_RECEIPT"])
    verify_iam_reference(reference, commit)
    proof = foundation.decode(custody.fetch_verified(reference))
    REQUIRE(proof.keys() == {"schema", "commit", "profile_sha256", "owner_approval_sha256", "issued_utc", "policies"}
            and proof["schema"] == "clipforge-db01-noble-stable-read-receipt-1"
            and proof["commit"] == commit and proof["profile_sha256"] == profile_sha256
            and re.fullmatch(r"[a-f0-9]{64}", proof["owner_approval_sha256"])
            and datetime.fromisoformat(proof["issued_utc"]).utcoffset() == timedelta(0)
            and proof["policies"].keys() == profile["policies"].keys(), "Unrecognized stable READ policy proof")
    etags = {}
    for resource, spec in profile["policies"].items():
        policy = proof["policies"][resource]
        REQUIRE(policy.keys() == {"before", "after"} and digest(policy["before"]) == spec["baseline_policy_sha256"]
                and digest(policy["before"]["etag"]) == spec["baseline_etag_sha256"],
                "Stable READ proof baseline differs from reviewed policy")
        stable_iam.check_policy_delta(policy["before"], policy["after"], spec["add_bindings"])
        for entry in spec["state_etags"]:
            address, saved_etag_sha256 = entry["address"], entry["sha256"]
            REQUIRE(address in EXISTING and address not in etags, "Unrecognized managed IAM etag address")
            etags[address] = saved_etag_sha256, digest(policy["after"]["etag"])
    receipt = {"receipt": reference, "profile_sha256": profile_sha256,
               "owner_approval_sha256": proof["owner_approval_sha256"], "policies_checked": len(profile["policies"])}
    return profile, proof, etags, receipt


def verify_live_iam(profile, proof, token):
    for role, spec in profile["roles"].items():
        stable_iam.check_role_definition(role, stable_iam.get_role(role, token), spec)
    for resource, spec in profile["policies"].items():
        live = stable_iam.get_policy(resource, spec, token)
        REQUIRE(digest(stable_iam.canonical_policy(live))
                == digest(stable_iam.canonical_policy(proof["policies"][resource]["after"])),
                "Live IAM policy differs from the verified stable READ result")


def has_unknown(value):
    if isinstance(value, dict):
        return any(has_unknown(item) for item in value.values())
    if isinstance(value, list):
        return any(has_unknown(item) for item in value)
    return value is not False and value is not None


def verify_iam_refresh(rows, managed, etags):
    REQUIRE(isinstance(rows, list), "Malformed native refresh evidence")
    expected_drift = {address for address, (saved, live) in etags.items() if saved != live}
    observed = set()
    for address, (_, live) in etags.items():
        row = managed[address]
        change = row["change"]
        before, after = change.get("before"), change.get("after")
        REQUIRE(row.get("type") == address.split(".")[0] and change.get("actions") == ["no-op"]
                and isinstance(before, dict) and isinstance(after, dict)
                and isinstance(after.get("etag"), str) and digest(after["etag"]) == live
                and digest(before) == digest(after) and not has_unknown(change.get("after_unknown"))
                and not change.get("replace_paths"),
                "Native plan does not preserve the verified live IAM resource as a complete no-op")
    for row in rows:
        address, change = row["address"], row["change"]
        REQUIRE(address in expected_drift and address not in observed and row["mode"] == "managed"
                and row.get("type") == managed[address]["type"] and not row.get("deposed")
                and not row.get("previous_address") and "importing" not in row and "importing" not in change
                and change.get("actions") == ["update"] and not change.get("replace_paths")
                and not has_unknown(change.get("after_unknown")), "Unrecognized native resource drift")
        before, after = change.get("before"), change.get("after")
        REQUIRE(isinstance(before, dict) and isinstance(after, dict)
                and isinstance(before.get("etag"), str) and digest(before["etag"]) == etags[address][0]
                and digest({**before, "etag": after.get("etag")}) == digest(after)
                and digest(after) == digest(managed[address]["change"]["after"]),
                "Native refresh differs from the reviewed IAM etag transition")
        observed.add(address)
    REQUIRE(observed == expected_drift, "Native plan omitted a reviewed IAM etag transition")


def action_summary(plan, iam_etags=None):
    REQUIRE(plan.get("complete") is True and plan.get("applyable") is True
            and plan.get("errored") is False and not plan.get("deferred_changes")
            and not plan.get("action_invocations"), "Native plan is incomplete, errored or deferred")
    actions, managed = {}, {}
    for row in plan.get("resource_changes", []):
        if row["mode"] == "data":
            continue
        REQUIRE(row["mode"] == "managed", "Unexpected resource mode")
        address = row["address"]
        change = row["change"]
        REQUIRE(address not in actions and not row.get("previous_address") and not row.get("deposed")
                and "importing" not in change and "importing" not in row, "Move, import, deposed or duplicate resource")
        actions[address] = change["actions"]
        managed[address] = row
    refresh = plan.get("resource_drift", [])
    if iam_etags is not None:
        verify_iam_refresh(refresh, managed, iam_etags)
    drift = {row["address"]: row["change"]["actions"] for row in refresh}
    deviations = {path: actions.get(path, ["missing"]) for path in sorted(EXISTING | CREATES | actions.keys())
                  if actions.get(path) != (["no-op"] if path in EXISTING else ["create"] if path in CREATES else None)}
    counts = dict(Counter("/".join(value) for value in actions.values()))
    return {"counts": counts, "preserved_addresses": sorted(path for path in EXISTING if actions.get(path) == ["no-op"]),
            "candidate_addresses": sorted(path for path in CREATES if actions.get(path) == ["create"]),
            "deviations": deviations, "refresh_drift": drift}


def validate_action_scope(actions, exit_code, verified_iam_addresses=()):
    REQUIRE(exit_code == 2 and actions == {
        "counts": {"no-op": len(EXISTING), "create": len(CREATES)},
        "preserved_addresses": sorted(EXISTING),
        "candidate_addresses": sorted(CREATES),
        "deviations": {},
        "refresh_drift": {address: ["update"] for address in verified_iam_addresses},
    }, "Native plan differs from the reviewed additive scope")


def retain(work, report, sources):
    commit = os.environ["GITHUB_SHA"]
    run, attempt = os.environ["GITHUB_RUN_ID"], os.environ["GITHUB_RUN_ATTEMPT"]
    REQUIRE(all(re.fullmatch(r"[1-9][0-9]*", value) for value in (run, attempt)), "Invalid hosted run identity")
    prefix = f"{custody.PREFIX}{commit}/{run}-{attempt}/"
    now = datetime.now(timezone.utc)
    manifest = {"schema": SCHEMA, "commit": commit, "run_id": run, "run_attempt": attempt,
                "created_utc": now.isoformat(), "expires_utc": (now + timedelta(hours=24)).isoformat(),
                "terraform_version": "1.15.8", "provider_version": "8.11.0",
                "inputs": {"machine_type": "e2-micro", "stage": "foundation", "db01_noble_candidate": report["image"]},
                "source_sha256": sources, "backend": report["backend"], "actions": report["actions"],
                "iam_refresh": report["iam_refresh"],
                "apply_authorized": False}
    report["private_plan"] = {"bucket": contract.BUCKET}
    for kind, path in (("binary", "int.tfplan"), ("json", "private-plan.json")):
        reference = custody.upload(prefix + PRIVATE_FILES[kind], (work / path).read_bytes())
        manifest[kind] = reference
        report["private_plan"][kind] = reference
    report["private_plan"]["manifest"] = custody.upload(prefix + PRIVATE_FILES["manifest"], custody.canonical(manifest))
    report["private_plan"]["expires_utc"] = manifest["expires_utc"]


def check(work, report):
    sources = snapshot(work)
    (work / "source-sha256.json").write_bytes(custody.canonical(sources))
    binary = driver.terraform_binary()
    for phase, command in (
        ("fmt", ["fmt", "-check", "-recursive"]),
        ("validate_init", ["init", "-backend=false", "-input=false", "-lockfile=readonly", "-no-color"]),
        ("validate", ["validate", "-no-color"]),
    ):
        driver.run([binary, *command], phase, work)
        report["checks"][phase] = "passed"
    _, raw = driver.run([binary, "test", "-filter=tests/noble-candidate.tftest.hcl", "-json", "-no-color"],
                        "noble_native_mock", work)
    rows = [json.loads(line) for line in raw.splitlines()]
    summaries = [row["test_summary"] for row in rows if row.get("type") == "test_summary"]
    REQUIRE(len(summaries) == 1 and summaries[0].get("passed") == 5
            and summaries[0].get("failed") == summaries[0].get("errored") == summaries[0].get("skipped") == 0,
            "All five native Noble mock plans must execute")
    report["checks"]["noble_native_mock"] = "passed"
    module = work / "source" / MODULE
    scan_inputs = {"runtime_image": RUNTIME_PLACEHOLDER, "db01_noble_candidate": {
        "image_name": "ubuntu-2404-noble-amd64-v20261114", "image_id": "1"}}
    scan_inputs_path = module / "noble-scan.tfvars.json"
    scan_inputs_path.write_bytes(custody.canonical(scan_inputs))
    uid = f"{os.getuid()}:{os.getgid()}"
    code, raw = driver.run(["docker", "run", "--rm", "--pull", "never", "--network", "none", "--read-only",
                            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--user", uid,
                            "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=128m",
                            "--mount", f"type=bind,source={module},target=/source,readonly", driver.TRIVY,
                            "config", "--skip-check-update", "--disable-telemetry", "--misconfig-scanners", "terraform",
                            "--tf-vars", "/source/noble-scan.tfvars.json", "--include-non-failures",
                            "--exit-code", "1", "--format", "json", "/source"],
                           "noble_iac_security", work, accepted=(0, 1))
    scan_inputs_path.unlink()
    results = json.loads(raw)["Results"]
    REQUIRE(sum(item.get("MisconfSummary", {}).get("Successes", 0) for item in results) > 0,
            "Native IaC checks did not execute")
    checks = [row for item in results for row in item.get("Misconfigurations", [])]
    REQUIRE(all(row.get("Status") in {"PASS", "FAIL"} for row in checks)
            and any("google_compute_instance.noble" in row.get("CauseMetadata", {}).get("Resource", "")
                    for row in checks), "IaC scan did not cover the enabled Noble VM")
    findings = [row for row in checks if row["Status"] == "FAIL"]
    REQUIRE(code == int(bool(findings)), "IaC scanner exit disagrees with findings")
    report["iac_findings"] = [{"id": row["ID"], "severity": row["Severity"],
                               "resource": row.get("CauseMetadata", {}).get("Resource", "unknown")} for row in findings]
    REQUIRE(not any(row["Severity"] in {"HIGH", "CRITICAL"} for row in findings), "IaC HIGH/CRITICAL findings block planning")
    report["checks"]["noble_iac_security"] = "passed_with_native_findings_pending_review" if findings else "passed"


def real_plan(work, report):
    custody.hosted_context(os.environ)
    adc = Path(os.environ["GOOGLE_APPLICATION_CREDENTIALS"])
    REQUIRE(os.environ.get("GITHUB_RUN_ATTEMPT") == "1"
            and adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json"
            and os.environ.get("TF_WORKSPACE", "default") == "default", "Protected WIF ADC and default workspace required")
    REQUIRE(set(report["checks"]) == {"fmt", "validate_init", "validate", "noble_native_mock", "noble_iac_security"},
            "Missing checks from this attempt")
    report["image"] = resolve_image()
    report["backend"] = state_identity()
    report["network"] = preflight_network()
    with guarded_phase("noble_iam_receipt"):
        profile, proof, etags, iam_receipt = load_iam_evidence(os.environ)
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color",
                "-backend-config=backend-int.hcl"], "noble_backend_init", work)
    REQUIRE(state_identity() == report["backend"], "State changed before native plan")
    with guarded_phase("noble_iam_precheck"):
        verify_live_iam(profile, proof, os.environ["GCP_ACCESS_TOKEN"])
    image = report["image"]
    var = json.dumps({"image_name": image["name"], "image_id": str(image["id"])}, separators=(",", ":"))
    path = work / "int.tfplan"
    code, _ = driver.run([binary, "plan", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s",
                          "-detailed-exitcode", "-refresh=true", "-var=stage=foundation", "-var=machine_type=e2-micro",
                          "-var=runtime_image=" + RUNTIME_PLACEHOLDER, "-var=secret_versions=null",
                          "-var=db01_noble_candidate=" + var, "-out=" + str(path)], "noble_native_plan", work, accepted=(0, 2))
    REQUIRE(state_identity() == report["backend"], "State changed across native plan")
    _, raw = driver.run([binary, "show", "-json", str(path)], "noble_private_show", work)
    report["plan_exit_code"] = code
    verified_iam_addresses = sorted(address for address, (saved, live) in etags.items() if saved != live)
    with guarded_phase("noble_native_scope"):
        report["actions"] = action_summary(json.loads(raw), etags)
        validate_action_scope(report["actions"], code, verified_iam_addresses)
    with guarded_phase("noble_iam_postcheck"):
        verify_live_iam(profile, proof, os.environ["GCP_ACCESS_TOKEN"])
    report["iam_refresh"] = {**iam_receipt, "etag_only_addresses": verified_iam_addresses}
    (work / "private-plan.json").write_bytes(raw)
    sources = json.loads((work / "source-sha256.json").read_text(encoding="utf-8"))
    REQUIRE(all(custody.sha256((work / "source" / name).read_bytes()) == sha for name, sha in sources.items()),
            "Private configuration bytes changed after checks")
    retain(work, report, sources)


def validate_summary(report):
    REQUIRE(isinstance(report, dict) and report.get("schema") == SUMMARY_SCHEMA
            and report.get("apply_authorized") is False
            and report.get("status") in ("checks_passed", "blocked", "planned")
            and isinstance(report.get("checks"), dict)
            and report.keys() <= {"schema", "status", "apply_authorized", *SUMMARY_SECTIONS},
            "Expected a Noble summary")
    backend = report.get("backend", {})
    REQUIRE(isinstance(backend, dict) and backend.keys() <= BACKEND_FIELDS, "Incompatible Noble backend evidence")
    if report["status"] != "planned":
        return
    REQUIRE(BACKEND_FIELDS == backend.keys() and isinstance(report.get("image"), dict)
            and isinstance(report.get("network"), dict) and report["network"].get("observed_available") is True
            and "diagnostic" not in report and "summary_error" not in report, "Missing Noble planning evidence")
    iam_refresh = report.get("iam_refresh")
    REQUIRE(isinstance(iam_refresh, dict) and iam_refresh.keys() ==
            {"receipt", "profile_sha256", "owner_approval_sha256", "policies_checked", "etag_only_addresses"}
            and iam_refresh["policies_checked"] == 6
            and isinstance(iam_refresh["etag_only_addresses"], list)
            and iam_refresh["etag_only_addresses"] == sorted(set(iam_refresh["etag_only_addresses"]))
            and set(iam_refresh["etag_only_addresses"]) <= EXISTING
            and all(re.fullmatch(r"[a-f0-9]{64}", iam_refresh[field]) for field in ("profile_sha256", "owner_approval_sha256")),
            "Missing verified IAM refresh evidence")
    validate_action_scope(report.get("actions"), report.get("plan_exit_code"), iam_refresh["etag_only_addresses"])
    references = report.get("private_plan")
    REQUIRE(isinstance(references, dict) and references.keys() == {"bucket", "expires_utc", *PRIVATE_FILES}
            and references["bucket"] == contract.BUCKET
            and datetime.fromisoformat(references["expires_utc"]).utcoffset() == timedelta(0),
            "Missing private plan custody")
    prefix = None
    for kind, filename in PRIVATE_FILES.items():
        ref = references[kind]
        REQUIRE(isinstance(ref, dict) and ref.keys() == {"name", "generation", "sha256", "size"}
                and re.fullmatch(r"[1-9][0-9]*", ref["generation"])
                and re.fullmatch(r"[a-f0-9]{64}", ref["sha256"])
                and type(ref["size"]) is int and ref["size"] > 0, "Invalid private plan object receipt")
        name = re.fullmatch("(" + re.escape(custody.PREFIX) + r"[a-f0-9]{40}/[1-9][0-9]*-[1-9][0-9]*/)"
                            + re.escape(filename), ref["name"])
        REQUIRE(name and (prefix is None or prefix == name[1]), "Private receipts do not bind the same attempt")
        prefix = name[1]
    commit = prefix[len(custody.PREFIX):].split("/", 1)[0]
    verify_iam_reference(iam_refresh["receipt"], commit)


def summary_markdown(report, sections):
    lines = ["# DB-01-NOBLE-PLAN", "", "Status: " + report["status"], "", "Apply authorized: false.", ""]
    if report["status"] != "planned":
        lines.extend(["A completed plan with private custody was not confirmed.", ""])
    for key in sections:
        if key in report:
            # These are the permitted JSON receipts, including the native sanitized diagnostic.
            value = json.dumps(report[key], indent=2, ensure_ascii=True).replace("`", r"\u0060")
            lines.extend(["## " + SUMMARY_SECTIONS[key], "", "```json", value, "```", ""])
    return "\n".join(lines) + "\n"


def render_summary(report):
    validate_summary(report)
    return summary_markdown(report, SUMMARY_SECTIONS)


def save_summary(reports, report):
    json_path = reports / "summary.json"
    markdown_path = reports / "summary.md"
    step_summary = os.environ.get("GITHUB_STEP_SUMMARY")
    stage = "render_summary"
    try:
        markdown = render_summary(report)
        stage = "write_summary_json"
        json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        stage = "write_summary_markdown"
        markdown_path.write_text(markdown, encoding="utf-8")
        if step_summary:
            stage = "write_step_summary"
            with Path(step_summary).open("a", encoding="utf-8") as stream:
                stream.write(markdown)
    except Exception as error:
        report.update(status="blocked", summary_error={"operation": stage, "error_type": type(error).__name__})
        print(json.dumps({key: report[key] for key in ("diagnostic", "summary_error") if key in report}), file=sys.stderr)
        try:
            json_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
            markdown_path.write_text(summary_markdown(report, ("diagnostic", "summary_error")), encoding="utf-8")
        except (OSError, TypeError, ValueError) as fallback:
            print(json.dumps({"operation": "write_summary_fallback", "error_type": type(fallback).__name__}), file=sys.stderr)
        return 1
    return int(report["status"] == "blocked")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("checks", "plan"))
    command = parser.parse_args(argv).operation
    os.umask(0o077)
    work, reports = driver.private_paths()
    path = reports / "summary.json"
    report = {"schema": SUMMARY_SCHEMA, "checks": {}, "apply_authorized": False}
    try:
        if command == "plan":
            prior = json.loads(path.read_text(encoding="utf-8"))
            REQUIRE(isinstance(prior, dict) and prior.get("status") == "checks_passed"
                    and prior.keys() <= {"schema", "status", "apply_authorized", "checks", "iac_findings"},
                    "Expected the checks-only summary from this attempt")
            validate_summary(prior)
            report = prior
        contract.validate_variables(os.environ)
        commit = os.environ["GITHUB_SHA"]
        REQUIRE(re.fullmatch(r"[a-f0-9]{40}", commit) and commit == os.environ["DB01_NOBLE_APPROVED_COMMIT"],
                "Exact Noble plan controls SHA required")
        if command == "checks":
            check(work, report)
            report["status"] = "checks_passed"
        else:
            real_plan(work, report)
            report["status"] = "planned"
    except driver.FailedOperation as error:
        report.update(status="blocked", diagnostic=native_diagnostic.operation_receipt(work, error.receipt))
    except Blocked as error:
        report.update(status="blocked", diagnostic={"operation": error.operation, "http_status": error.status})
        if error.error_type:
            report["diagnostic"]["error_type"] = error.error_type
    except Exception as error:
        report.update(status="blocked", diagnostic={"operation": command, "error_type": type(error).__name__})
    return save_summary(reports, report)


if __name__ == "__main__":
    raise SystemExit(main())
