"""Prepare or execute only the exact saved DB-01 Noble creation plan."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import io
import json
import os
from pathlib import Path
import re
import shutil
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener
from zipfile import ZipFile

from scripts import check_tf_int as c
from scripts import db01_noble_diagnostic as diagnostic
from scripts import db01_noble_plan as noble
from scripts import int_db01_noble_read_iam as iam
from scripts import int_foundation_close as historical
from scripts import int_foundation_verify as foundation
from scripts import int_noble_guest_observation as guest
from scripts import int_noble_write_iam as writer
from scripts import int_release as custody
from scripts import int_release_state as states
from scripts import tf_int_plan as driver


ROOT = driver.ROOT
PRODUCER = "c302dcc366ed450f91c1693072eb9008e7975e4c"
PLAN_RUN = "44650537240"
PLAN_ARTIFACT = "14590397506"
PLAN_ARTIFACT_SHA = "36471b4b181f0ec07da1c9366a568359e2258b9aa66b4cfad92be48566dd7435"
PRODUCER_WORKFLOW = ".github/workflows/int-db01-noble-plan.yml"
WORKFLOW = ".github/workflows/int-db01-noble-apply.yml"
REPOSITORY = "AldemaroCruz/ClipForge"
PLAN_PREFIX = f"{custody.PREFIX}{PRODUCER}/{PLAN_RUN}-1/"
PLAN = {
    "binary": {"name": PLAN_PREFIX + "int.tfplan", "generation": "1795136719332961", "size": 64698,
               "sha256": "ce93b8dc52fc9ffddc91c30720f667d66752412aa6faf0ab2a347e8ddc49f8d6"},
    "json": {"name": PLAN_PREFIX + "int.json", "generation": "1795136719496104", "size": 403117,
             "sha256": "ecd4973495e0a179b845787872038ef92e228425ec8421bf8f742674fb9741bd"},
    "manifest": {"name": PLAN_PREFIX + "manifest.json", "generation": "1795136719671258", "size": 10100,
                 "sha256": "6ca0f88d6345b2f77e3a28ace8c0cc8051544a23b259054f49ec24bdf2a9d4ff"},
}
READ_RECEIPT = {"name": iam.proof_name(PRODUCER), "generation": "1795136476328109", "size": 43427,
                "sha256": "e495bd6cca23fa19ecbd2c0ead3876273f4d9f797793d41afbea44475833af48"}
PLAN_EXPIRY = "2026-11-21T01:05:19.179283+00:00"
IMAGE_NAME = "ubuntu-2404-noble-amd64-v20261105"
IMAGE_ID = "1892012953239034119"
PLAN_STATE = {**foundation.STATE_PIN, "managed_addresses": sorted(noble.EXISTING), "current_lock_absent": True}
SOURCE_PATHS = (*[noble.MODULE / name for name in (*c.FILES, *noble.NOBLE_FILES)], *map(Path, noble.HELPERS))
DECISION_SCHEMA = "clipforge-db01-noble-create-observe-decision-2"
CREATION_SCHEMA = "clipforge-db01-noble-creation-receipt-1"
DECISION = "exact_noble_creation_and_first_observation_authorized"
OUTPUT_HASH_KEYS = ("hostkey_nonce", "startup_sha256")
PROJECT_POLICY = writer.PROJECT
IAP_ZONE = writer.ZONE
IAC_FINDINGS_SHA = "537659806270b78d3693b16944255111621c8b163937da9b0a32ae065ee70f54"
PRESERVED_FINDINGS_SHA = "8f24781c182729038933b5b26b67256dd0b86e0cc995afd227cc9badb5e1ad49"
POLICY_READ = {"options": {"requestedPolicyVersion": 3}}
NATIVE_OPERATION = "noble_apply_saved"
ARTIFACT_FILES = {"summary.json", "summary.md", "iam-read-preflight.json"}
ARTIFACT_LIMIT = 1024 * 1024
WORKFLOW_BRANCH = "ci/bootstrap-sec03"


def utc(value):
    match = datetime.fromisoformat(value.replace("Z", "+00:00"))
    c.require(match.utcoffset() == timedelta(0), "UTC timestamp required")
    return match


def verify_plan_ttl(manifest, now):
    created, expires = utc(manifest["created_utc"]), utc(manifest["expires_utc"])
    c.require(expires - created == timedelta(hours=24), "Plan lifetime was changed")
    if now >= expires:
        raise noble.Blocked("noble_apply_plan_expired")
    if now < created:
        raise noble.Blocked("noble_apply_plan_not_yet_created")


def verify_reference(value, *, fixed=None, suffix=None, commit=None):
    iam.check_fields(value, {"name", "generation", "sha256", "size"})
    name = custody.object_name(value["name"])
    c.require(isinstance(value["generation"], str) and re.fullmatch(r"[1-9][0-9]*", value["generation"])
              and iam.valid_digest(value["sha256"]) and type(value["size"]) is int and 0 < value["size"] <= 2 * 1024 * 1024
              and (fixed is None or value == fixed) and (suffix is None or name.endswith("/" + suffix))
              and (commit is None or name.startswith(custody.PREFIX + commit + "/")),
              "Private immutable object reference differs")
    return value


def producer_prefix(commit, run):
    c.require(isinstance(commit, str) and re.fullmatch(r"[a-f0-9]{40}", commit)
              and isinstance(run, str) and re.fullmatch(r"[1-9][0-9]{0,19}", run), "Exact producer commit and run required")
    return f"{custody.PREFIX}{commit}/{run}-1/"


def plan_selection(commit, run, manifest, artifact):
    prefix = producer_prefix(commit, run)
    verify_reference(manifest)
    c.require(manifest["name"] == prefix + "manifest.json", "Manifest reference differs from the producer attempt")
    iam.check_fields(artifact, {"id", "sha256"})
    c.require(isinstance(artifact["id"], str) and re.fullmatch(r"[1-9][0-9]{0,19}", artifact["id"])
              and iam.valid_digest(artifact["sha256"]), "Exact producer artifact ID and SHA-256 required")
    if run == PLAN_RUN:
        c.require(commit == PRODUCER and manifest == PLAN["manifest"]
                  and artifact == {"id": PLAN_ARTIFACT, "sha256": PLAN_ARTIFACT_SHA},
                  "Historical plan and artifact references are immutable")
    return {"producer_commit": commit, "producer_run": run, "manifest": manifest, "artifact": artifact}


def selection_from_environment(environ):
    return plan_selection(environ["DB01_NOBLE_PRODUCER_COMMIT"], environ["DB01_NOBLE_PRODUCER_RUN"],
                          foundation.decode(environ["DB01_NOBLE_PLAN_MANIFEST"]),
                          {"id": environ["DB01_NOBLE_PLAN_ARTIFACT_ID"], "sha256": environ["DB01_NOBLE_PLAN_ARTIFACT_SHA256"]})


def verify_manifest(value, selection):
    commit, run = selection["producer_commit"], selection["producer_run"]
    prefix = producer_prefix(commit, run)
    fields = {"schema", "commit", "run_id", "run_attempt", "created_utc", "expires_utc",
              "terraform_version", "provider_version", "inputs", "source_sha256", "backend",
              "actions", "iam_refresh", "apply_authorized", "binary", "json"}
    iam.check_fields(value, fields if run == PLAN_RUN else fields | {"stable_write_receipt"})
    c.require(value["schema"] == noble.SCHEMA and value["commit"] == commit and value["run_id"] == run
              and value["run_attempt"] == "1" and value["terraform_version"] == "1.15.8" and value["provider_version"] == "8.11.0"
              and value["apply_authorized"] is False
              and value["iam_refresh"]["receipt"] == READ_RECEIPT,
              "Manifest provenance, plan or pinned backend differs")
    for kind in ("binary", "json"):
        verify_reference(value[kind])
        c.require(value[kind]["name"] == prefix + noble.PRIVATE_FILES[kind], "Plan object is outside the exact producer attempt")
    if run == PLAN_RUN:
        c.require(value["binary"] == PLAN["binary"] and value["json"] == PLAN["json"] and value["expires_utc"] == PLAN_EXPIRY
                  and value["backend"] == PLAN_STATE, "Historical binary, JSON, backend or lifetime differs")
    else:
        noble.verify_backend_reference(value["backend"])
        verify_reference(value["stable_write_receipt"])
    iam.check_fields(value["inputs"], {"stage", "machine_type", "db01_noble_candidate"})
    image = value["inputs"]["db01_noble_candidate"]
    c.require(value["inputs"]["stage"] == "foundation" and value["inputs"]["machine_type"] == "e2-micro"
              and noble.image_identity(image) == image, "Plan inputs or exact public image differ")
    if run == PLAN_RUN:
        c.require(image["name"] == IMAGE_NAME and image["id"] == IMAGE_ID, "Historical public image differs")
    c.require(set(value["source_sha256"]) == {path.as_posix() for path in SOURCE_PATHS}
              and all(map(iam.valid_digest, value["source_sha256"].values())), "Plan source closure differs")
    return {"manifest": selection["manifest"], "binary": value["binary"], "json": value["json"]}


def decision_name(controls, producer_run):
    producer_prefix(controls, producer_run)
    # Attempt 1 is the only valid producer. The separate decision never replaces its manifest.
    return f"{custody.PREFIX}{controls}/{producer_run}-2/manifest.json"


def verify_decision(decision, manifest, plan, artifact, profile, findings, controls, now):
    iam.check_fields(decision, {"schema", "decision", "owner_approval_ref", "issued_utc", "producer_commit", "producer_run",
                               "controls_commit", "project", "plan", "expires_utc", "write_profile_sha256", "write_receipt",
                               "plan_artifact", "iac_findings_sha256", "iac_decisions"})
    c.require(decision["schema"] == DECISION_SCHEMA and decision["decision"] == DECISION
              and isinstance(decision["owner_approval_ref"], str) and 0 < len(decision["owner_approval_ref"].strip()) <= 500
              and decision["producer_commit"] == manifest["commit"] and decision["producer_run"] == manifest["run_id"]
              and decision["controls_commit"] == controls
              and decision["project"] == c.PROJECT and decision["plan"] == plan and decision["plan_artifact"] == artifact
              and decision["expires_utc"] == manifest["expires_utc"]
              and utc(manifest["created_utc"]) <= utc(decision["issued_utc"]) <= now
              and decision["write_profile_sha256"] == noble.digest(profile)
              and decision["iac_findings_sha256"] == noble.digest(findings), "Separate exact owner approval is required")
    candidate = reviewed_findings(findings, historical_plan=manifest["run_id"] == PLAN_RUN)
    rows = decision["iac_decisions"]
    c.require(isinstance(rows, list) and len(rows) == len(candidate), "Individual Noble IaC decisions are required")
    for number, row in zip(candidate, rows, strict=True):
        iam.check_fields(row, {"finding_index", "decision", "rationale"})
        c.require(type(row["finding_index"]) is int and row["finding_index"] == number
                  and row["decision"] == "reviewed_for_this_noble_creation"
                  and isinstance(row["rationale"], str) and 0 < len(row["rationale"].strip()) <= 500,
                  "Each finding needs an explicit review for this exact operation")
    verify_reference(decision["write_receipt"])
    if "stable_write_receipt" in manifest:
        c.require(decision["write_receipt"] == manifest["stable_write_receipt"],
                  "Stable WRITE receipt differs from the approved plan")
    verify_plan_ttl(manifest, now)


def reviewed_findings(findings, *, historical_plan):
    c.require(isinstance(findings, list), "Producer IaC evidence is missing")
    preserved, candidate = [], []
    for index, row in enumerate(findings, 1):
        iam.check_fields(row, {"id", "severity", "resource"})
        c.require(isinstance(row["id"], str) and bool(row["id"])
                  and row["severity"] in {"LOW", "MEDIUM", "INFORMATIONAL"}
                  and row["resource"] in noble.EXISTING | noble.CREATES, "Unreviewed IaC finding blocks creation")
        if row["resource"] in noble.EXISTING:
            preserved.append(row)
        else:
            candidate.append(index)
    c.require(noble.digest(preserved) == PRESERVED_FINDINGS_SHA,
              "IaC findings on the preserved resources differ from the reviewed scope")
    if historical_plan:
        c.require(noble.digest(findings) == IAC_FINDINGS_SHA, "Historical IaC findings differ from the archived report")
    return candidate


def canonical_direct_policy(policy):
    version = policy.get("version", 0)
    c.require(type(version) is int and version in {0, 1, 3} and
              (version == 3 or not any("condition" in binding for binding in policy.get("bindings", []))),
              "Conditional IAM policy must have version three")
    # GCP returns version zero/one for policies with no conditions, including an empty zone.
    return iam.canonical_policy({**policy, "version": 3, "bindings": policy.get("bindings", [])})


def copy_sources(work, producer, manifest):
    source = work / "source"
    for relative in SOURCE_PATHS:
        file = producer / relative
        c.require(file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(producer.resolve()),
                  "Producer source is not a checked-out file")
        raw = file.read_bytes()
        reviewed = ROOT / relative
        c.require(custody.sha256(raw) == manifest["source_sha256"][relative.as_posix()]
                  and reviewed.is_file() and not reviewed.is_symlink() and reviewed.resolve().is_relative_to(ROOT.resolve())
                  and reviewed.read_bytes() == raw, "Producer source differs from the reviewed controls")
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    (work / "module").symlink_to(source / noble.MODULE, target_is_directory=True)
    (work / "terraform.rc").write_text("disable_checkpoint = true\nprovider_installation {\n  direct {}\n}\n", encoding="utf-8")


class ArtifactRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        # Surface a standard HTTPError 302 so the signed destination is checked before any request.
        return None


def verify_producer_run(environ, selection):
    tokens = {"Authorization": "Bearer " + environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28"}
    api = f"https://api.github.com/repos/{REPOSITORY}/actions/"
    opener = build_opener(ProxyHandler({}), driver.NoRedirect())
    commit, run, artifact_ref = selection["producer_commit"], selection["producer_run"], selection["artifact"]
    endpoints = (f"runs/{run}/attempts/1", f"artifacts/{artifact_ref['id']}")
    records = []
    for endpoint in endpoints:
        with opener.open(Request(api + endpoint, headers=tokens), timeout=30) as response:
            body = response.read(1024 * 1024 + 1)
        c.require(len(body) <= 1024 * 1024, "Producer metadata exceeds its bound")
        records.append(foundation.decode(body))
    value, artifact = records
    expected = {"id": int(run), "run_attempt": 1, "head_sha": commit, "head_branch": WORKFLOW_BRANCH,
                "event": "workflow_dispatch", "path": PRODUCER_WORKFLOW, "status": "completed", "conclusion": "success"}
    c.require(all(value.get(key) == item for key, item in expected.items())
              and value.get("repository", {}).get("full_name") == REPOSITORY, "Saved plan producer is not the exact successful attempt")
    c.require(artifact["id"] == int(artifact_ref["id"]) and artifact["expired"] is False
              and artifact["name"] == f"db01-noble-plan-summary-{commit}-{run}-1"
              and artifact["digest"] == "sha256:" + artifact_ref["sha256"]
              and artifact["workflow_run"]["head_sha"] == commit and artifact["workflow_run"]["id"] == int(run),
              "Exact producer artifact evidence is no longer retained")
    request = Request(api + endpoints[1] + "/zip", headers=tokens)
    artifact_opener = build_opener(ProxyHandler({}), ArtifactRedirect())
    try:
        response = artifact_opener.open(request, timeout=30)
    except HTTPError as error:
        location = error.headers.get("Location", "")
        target = urlsplit(location)
        error.close()
        c.require(error.code == 302 and target.scheme == "https" and not target.username and not target.password
                  and not target.fragment and target.port in (None, 443)
                  and target.hostname and target.hostname.endswith((".blob.core.windows.net", ".actions.githubusercontent.com")),
                  "Unexpected producer artifact storage redirect")
        response = opener.open(Request(location), timeout=30)
    with response:
        raw = response.read(ARTIFACT_LIMIT + 1)
    c.require(len(raw) <= ARTIFACT_LIMIT and custody.sha256(raw) == artifact_ref["sha256"],
              "Producer artifact bytes differ from the approved SHA-256")
    with ZipFile(io.BytesIO(raw)) as archive:
        c.require(len(archive.namelist()) == len(ARTIFACT_FILES) and set(archive.namelist()) == ARTIFACT_FILES
                  and all(item.file_size <= ARTIFACT_LIMIT for item in archive.infolist()), "Unexpected producer artifact contents")
        return foundation.decode(archive.read("summary.json"))


def verify_artifact_summary(summary, manifest, plan):
    noble.validate_summary(summary)
    c.require(summary["status"] == "planned" and summary["backend"] == manifest["backend"]
              and summary["image"] == manifest["inputs"]["db01_noble_candidate"]
              and summary["actions"] == manifest["actions"] and summary["iam_refresh"] == manifest["iam_refresh"]
              and summary.get("stable_write_receipt") == manifest.get("stable_write_receipt")
              and summary["private_plan"] == {"bucket": c.BUCKET, "expires_utc": manifest["expires_utc"], **plan},
              "Producer summary does not describe the exact private plan")
    checks = summary["checks"]
    c.require(all(checks.get(name) == "passed" for name in ("fmt", "validate_init", "validate", "noble_native_mock"))
              and checks.get("noble_iac_security") in {"passed", "passed_with_native_findings_pending_review"},
              "Incomplete producer configuration evidence")
    findings = summary["iac_findings"]
    reviewed_findings(findings, historical_plan=manifest["run_id"] == PLAN_RUN)
    return findings


def current_state():
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    foundation.validate_bucket(bucket, {"backend": {"bucket": c.BUCKET}, "project_number": "816643438938"})
    return states.private_current_state(bucket)


def origin_state(expected=PLAN_STATE):
    pin, raw = noble.current_origin(allow_successor=(expected != PLAN_STATE))
    c.require(pin == expected, "Saved plan state no longer current")
    return foundation.decode(raw)


def state_postcheck(raw, obj, parent, read_profile, read_proof, write_proof, image, *, origin=PLAN_STATE):
    state = foundation.decode(raw)
    c.require(state["version"] == 4 and state["terraform_version"] == "1.15.8"
              and state["lineage"] == origin["lineage"] and type(state["serial"]) is int and state["serial"] > origin["serial"]
              and obj["name"] == origin["name"] and obj["generation"] != origin["generation"],
              "Apply did not record a new state generation in the exact lineage")
    for row in state["resources"]:
        c.require(row.get("mode") in {"data", "managed"} and not row.get("module")
                  and (row.get("mode") == "managed" or row["type"] in c.DATA_TYPES)
                  and all(not item.get("deposed") and item.get("status") in {None, "ready"} for item in row["instances"]),
                  "Unrecognized or tainted state resource")
    old, after = foundation._attributes(parent), foundation._attributes(state)
    c.require(set(old) == noble.EXISTING and set(after) == noble.EXISTING | noble.CREATES, "Expected exactly 53 managed addresses")
    values = {}
    for policy, spec in read_profile["policies"].items():
        read_etag = read_proof["policies"][policy]["after"]["etag"]
        write_etag = write_proof["policies"].get(policy, {}).get("after", {}).get("etag", read_etag)
        for row in spec["state_etags"]:
            address = row["address"]
            c.require(noble.digest(old[address]["etag"]) == row["sha256"], "Prior IAM state etag changed")
            # A state-only read of a resource covered by the exact bounded IAM delta
            # may record the latest observed etag or retain the approved planned value.
            values[address] = {old[address]["etag"], read_etag, write_etag}
    for address in noble.EXISTING:
        if address in values:
            etag = after[address].get("etag")
            c.require(etag in values[address] and {**old[address], "etag": etag} == after[address],
                      "Post-apply state has an unapproved IAM attribute difference")
        else:
            c.require(old[address] == after[address], "Post-apply state changed an existing resource")
    c.require(set(state["outputs"]) == set(parent["outputs"]) | {"db01_noble_candidate"}
              and all(state["outputs"][key] == item for key, item in parent["outputs"].items()),
              "Existing state outputs changed")
    output = state["outputs"]["db01_noble_candidate"]
    c.require(output["sensitive"] is False, "Candidate output is not publishable")
    candidate = output["value"]
    verify_candidate(candidate, after, image)
    proof = {"name": obj["name"], "generation": obj["generation"], "size": len(raw), "sha256": custody.sha256(raw),
             "lineage": state["lineage"], "serial": state["serial"], "managed_address_count": len(after),
             "preserved_address_count": len(old), "current_lock_absent": True}
    return proof, candidate


def verify_candidate(candidate, attrs, image):
    expected = {"instance_name": guest.host.INSTANCE, "boot_disk": guest.BOOT_DISK, "data_disk": guest.DATA_DISK,
                "data_device": guest.DEVICE_NAME, "private_ip": guest.PRIVATE_IP, "service_email": guest.GUEST_EMAIL,
                "image_name": image["name"], "image_id": image["id"]}
    numeric = ("instance_id", "boot_disk_id", "data_disk_id")
    hashes = OUTPUT_HASH_KEYS
    iam.check_fields(candidate, {*expected, *numeric, *hashes})
    c.require(all(candidate[key] == value for key, value in expected.items())
              and all(isinstance(candidate[key], str) and re.fullmatch(r"[1-9][0-9]*", candidate[key]) for key in numeric)
              and all(iam.valid_digest(candidate[key]) for key in hashes)
              and len({candidate[key] for key in (*numeric, "image_id")}) == 4
              and not guest.LEGACY_IDS.intersection(candidate.values()), "Unexpected Noble state output")
    vm, boot, data = (attrs["google_compute_" + name + ".noble" + suffix + "[0]"]
                      for name, suffix in (("instance", ""), ("disk", "_boot"), ("disk", "_data")))
    c.require(str(vm["instance_id"]) == candidate["instance_id"] and str(boot["disk_id"]) == candidate["boot_disk_id"]
              and str(data["disk_id"]) == candidate["data_disk_id"], "Candidate output is not bound to its managed instances")


def compute(path, operation, **params):
    return noble.compute_get(path, operation, **params)


def observed_resources(candidate, token):
    vm = compute(guest.INSTANCE_PATH, "read_noble_instance")
    boot = compute(f"{guest.ZONE_PATH}/disks/{guest.BOOT_DISK}", "read_noble_boot")
    data = compute(f"{guest.ZONE_PATH}/disks/{guest.DATA_DISK}", "read_noble_data")
    project = compute(PROJECT_POLICY, "read_noble_project")
    c.require(not vm.get("lastStopTimestamp"), "Noble shows a stop before first observation")
    candidate = {**candidate, "creation_timestamp": vm["creationTimestamp"], "first_boot_timestamp": vm["lastStartTimestamp"]}
    projected = {key: candidate[key] for key in ("instance_id", "boot_disk_id", "data_disk_id", "image_name", "image_id",
                                                  "startup_sha256", "creation_timestamp", "first_boot_timestamp")}
    snapshot = guest.control_snapshot(vm, boot, data, project, projected)
    root = PROJECT_POLICY + "/regions/us-central1/addresses/"
    address = compute(root + guest.host.INSTANCE, "read_noble_reserved_address")
    c.require(address["name"] == guest.host.INSTANCE and address["address"] == guest.PRIVATE_IP
              and address["addressType"] == "INTERNAL" and address.get("status") == "IN_USE"
              and guest.link_is(address["subnetwork"], guest.SUBNET_PATH)
              and len(address["users"]) == 1 and guest.link_is(address["users"][0], guest.INSTANCE_PATH),
              "Private reserved address does not belong to the exact new VM")
    sa = f"{PROJECT_POLICY}/serviceAccounts/{guest.GUEST_EMAIL}"
    account = iam.request_json(f"https://iam.googleapis.com/v1/{sa}", token)
    c.require(account["email"] == guest.GUEST_EMAIL and account["projectId"] == c.PROJECT
              and not account.get("disabled"), "Unexpected Noble service account")
    verify_firewalls()
    verify_new_bindings(sa, candidate["instance_id"], token)
    return candidate, snapshot


def verify_firewalls():
    for suffix, direction, priority, range_key, ranges, rule, opposite in (
        ("iap-ssh", "INGRESS", 1000, "sourceRanges", ["35.235.240.0/20"], ("allowed", [{"IPProtocol": "tcp", "ports": ["22"]}]), "denied"),
        ("https", "EGRESS", 1000, "destinationRanges", ["0.0.0.0/0"], ("allowed", [{"IPProtocol": "tcp", "ports": ["443"]}]), "denied"),
        ("deny-egress", "EGRESS", 65534, "destinationRanges", ["0.0.0.0/0"], ("denied", [{"IPProtocol": "all"}]), "allowed"),
    ):
        name = f"{guest.host.INSTANCE}-{suffix}"
        value = compute(f"{PROJECT_POLICY}/global/firewalls/{name}", "read_noble_firewall")
        c.require(value["name"] == name and guest.link_is(value["network"], guest.NETWORK_PATH)
                  and value["direction"] == direction and value["priority"] == priority and not value.get("disabled")
                  and value[range_key] == ranges and value["targetServiceAccounts"] == [guest.GUEST_EMAIL]
                  and value[rule[0]] == rule[1] and not value.get(opposite)
                  and not any(value.get(key) for key in ("sourceTags", "targetTags", "sourceServiceAccounts"))
                  and value["logConfig"] == {"enable": True, "metadata": "EXCLUDE_ALL_METADATA"},
                  "Unexpected Noble firewall")


def verify_new_bindings(sa, instance_id, token):
    c.require(re.fullmatch(r"[1-9][0-9]*", instance_id), "Numeric IAP target required")
    policies = (
        (f"{noble.API}{guest.INSTANCE_PATH}/getIamPolicy?optionsRequestedPolicyVersion=3", "GET", None,
         {"role": "roles/compute.osAdminLogin"}),
        (f"https://iam.googleapis.com/v1/{sa}:getIamPolicy?options.requestedPolicyVersion=3", "POST", None,
         {"role": "roles/iam.serviceAccountUser"}),
        (f"https://iap.googleapis.com/v1/{IAP_ZONE}/instances/{instance_id}:getIamPolicy", "POST", POLICY_READ,
         {"role": "roles/iap.tunnelResourceAccessor", "condition": {"title": "db01_noble_ssh_only", "expression": "destination.port == 22"}}),
    )
    for url, method, body, binding in policies:
        policy = canonical_direct_policy(iam.request_json(url, token, method, body))
        c.require(policy["bindings"] == [{**binding, "members": [historical.DEPLOY_MEMBER]}]
                  and not policy.get("auditConfigs"), "Unexpected direct Noble resource IAM policy")


def verify_context(environ, producer_run):
    custody.hosted_context(environ)
    c.validate_variables(environ)
    sha = environ["GITHUB_SHA"]
    c.require(re.fullmatch(r"[a-f0-9]{40}", sha)
              and environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/{WORKFLOW_BRANCH}"
              and environ.get("DB01_NOBLE_APPROVED_CONTROL_COMMIT") == sha
              and re.fullmatch(r"[1-9][0-9]*", environ["GITHUB_RUN_ID"])
              and environ["GITHUB_RUN_ID"] != producer_run and environ.get("GITHUB_RUN_ATTEMPT") == "1"
              and environ.get("TF_WORKSPACE", "default") == "default" and not environ.get("TF_REATTACH_PROVIDERS"),
              "Exact new protected apply-run context required")
    historical.verify_wif(environ)


def prefix(environ):
    return f"{custody.PREFIX}{environ['GITHUB_SHA']}/{environ['GITHUB_RUN_ID']}-1/"


def persist_native_log(work, environ, error=None):
    log = work / (NATIVE_OPERATION + ".log")
    # The legacy runner persists stdout/stderr on all normal exits. A timeout
    # can still carry captured output even when that file was never written.
    if not log.is_file() and error is not None:
        buffers = (getattr(error, "stdout", b""), getattr(error, "stderr", b""))
        if not any(isinstance(item, bytes) and item for item in buffers):
            return None
        raw = b"\n".join(item for item in buffers if isinstance(item, bytes))
    else:
        with log.open("rb") as stream:
            raw = stream.read(diagnostic.MAX_NATIVE_BYTES + 1)
    bound = diagnostic.MAX_NATIVE_BYTES
    c.require(len(raw) <= bound, "Native private log exceeded bound; no complete capture claimed")
    payload = {"schema": "clipforge-db01-noble-apply-native-log-1", "encoding": "base64", "size": len(raw),
               "sha256": custody.sha256(raw), "output": base64.b64encode(raw).decode("ascii")}
    encoded = custody.canonical(payload)
    reference = custody.upload(prefix(environ) + "int.json", encoded)
    c.require(custody.fetch_verified(reference) == encoded, "Private native log read-back differs")
    return reference


def error_receipt(error, phase, work):
    if isinstance(error, noble.Blocked):
        return {"operation": error.operation, "http_status": error.status, "error_type": error.error_type or type(error).__name__}
    if isinstance(error, driver.FailedOperation):
        native = {"operation": error.receipt["operation"], "status": error.receipt["status"]}
        if phase == NATIVE_OPERATION:
            log = work / (NATIVE_OPERATION + ".log")
            if log.is_file() and log.stat().st_size <= diagnostic.MAX_NATIVE_BYTES:
                native.update(diagnostic.classify_native_errors(log.read_text(encoding="utf-8", errors="replace")))
        return native
    status = error.code if isinstance(error, HTTPError) else error.status if isinstance(error, iam.CloudError) else None
    if isinstance(error, ValueError):
        storage = re.fullmatch(r"Private plan storage (?:GET|POST) failed with HTTP ([1-5][0-9]{2})", str(error))
        if storage:
            status = int(storage[1])
    return {"operation": phase, "error_type": type(error).__name__, "http_status": status}


def partial_observation(token):
    report = {}
    try:
        raw, obj, _ = current_state()
        state = foundation.decode(raw)
        present = set(foundation._attributes(state))
        report["state"] = {"generation": obj["generation"], "sha256": custody.sha256(raw), "lineage": state["lineage"],
                           "serial": state["serial"], "managed_address_count": len(present), "current_lock_absent": True,
                           "observed_candidate_addresses": sorted(present & noble.CREATES)}
    except Exception as error:
        report["state"] = {"status": "unconfirmed", "error_type": type(error).__name__}
    targets = {
        "vm": guest.INSTANCE_PATH,
        "boot_disk": guest.ZONE_PATH + "/disks/" + guest.BOOT_DISK,
        "data_disk": guest.ZONE_PATH + "/disks/" + guest.DATA_DISK,
        "address": PROJECT_POLICY + "/regions/us-central1/addresses/" + guest.host.INSTANCE,
        **{suffix: PROJECT_POLICY + "/global/firewalls/" + guest.host.INSTANCE + "-" + suffix
           for suffix in ("iap-ssh", "https", "deny-egress")},
    }
    observed = {}
    for key, target in targets.items():
        try:
            value = compute(target, "reconcile_" + key, fields="name,id")
            c.require(value["name"] == target.rsplit("/", 1)[-1] and re.fullmatch(r"[1-9][0-9]*", str(value["id"])),
                      "Reconciled resource does not match its lookup")
            observed[key] = {"status": "observed", "id": str(value["id"])}
        except Exception as error:
            observed[key] = error_receipt(error, "reconcile_" + key, Path("."))
    try:
        url = f"https://iam.googleapis.com/v1/{PROJECT_POLICY}/serviceAccounts/{guest.GUEST_EMAIL}"
        account = iam.request_json(url, token)
        c.require(account["email"] == guest.GUEST_EMAIL and account["projectId"] == c.PROJECT
                  and re.fullmatch(r"[1-9][0-9]*", account["uniqueId"]), "Reconciled service account differs")
        observed["service_account"] = {"status": "observed", "id": account["uniqueId"]}
    except Exception as error:
        observed["service_account"] = error_receipt(error, "reconcile_service_account", Path("."))
    # The state above can expose exact binding addresses if Terraform recorded
    # them. No automatic edits, unlock, import, or second apply on uncertain state.
    return {**report, "resources": observed}


def save_summary(reports, report):
    target = reports / "summary.json"
    temporary = reports / "summary.pending.json"
    temporary.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    temporary.replace(target)


def execute_native(work, reports, environ, report, binary, saved):
    save_summary(reports, {**report, "operation": NATIVE_OPERATION, "status": "native_apply_intent_confirmed",
                           "native_apply_attempted": None})
    report.update(operation=NATIVE_OPERATION, status="native_apply_attempted", native_apply_attempted=True)
    try:
        driver.run([binary, "apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(saved)], NATIVE_OPERATION, work)
    except Exception as error:
        report["diagnostic"] = error_receipt(error, NATIVE_OPERATION, work)
        try:
            report["native_log"] = persist_native_log(work, environ, error)
        except Exception as custody_error:
            report["native_log_error"] = error_receipt(custody_error, "retain_private_native_log", work)
        raise
    report["native_apply_completed"] = True
    report["operation"] = "retain_private_native_log"
    report["native_log"] = persist_native_log(work, environ)


def claim_once(environ, manifest, plan, decision_reference, report, attempted):
    # All plans for this pinned additive scope share the original create-only marker.
    # Regeneration cannot bypass an uncertain attempt against the same parent state.
    intent = {"schema": "clipforge-db01-noble-apply-intent-2", "producer_commit": manifest["commit"],
              "producer_run": manifest["run_id"], "controls_commit": environ["GITHUB_SHA"],
              "apply_run_id": environ["GITHUB_RUN_ID"], "decision": decision_reference,
              "manifest": plan["manifest"], "binary": plan["binary"], "intent_utc": attempted.isoformat()}
    encoded = custody.canonical(intent)
    report["operation"] = "claim_exact_saved_plan"
    report["intent"] = custody.upload(PLAN_PREFIX + "foundation-state.json", encoded)
    c.require(custody.fetch_verified(report["intent"]) == encoded, "Private one-shot intent read-back differs")


def load_plan(environ, selection, report):
    report["operation"] = "verify_noble_plan_manifest"
    manifest = foundation.decode(custody.fetch_verified(selection["manifest"]))
    plan = verify_manifest(manifest, selection)
    report["plan_expires_utc"] = manifest["expires_utc"]
    verify_plan_ttl(manifest, datetime.now(timezone.utc))
    report["operation"] = "verify_noble_producer_artifact"
    summary = verify_producer_run(environ, selection)
    return manifest, plan, verify_artifact_summary(summary, manifest, plan)


def exact_plan_actions(native, manifest, etags):
    verified_iam_addresses = sorted(address for address, (saved, live) in etags.items() if saved != live)
    actions = noble.action_summary(native, etags)
    noble.validate_action_scope(actions, 2, verified_iam_addresses)
    c.require(actions == manifest["actions"], "Custodied native actions differ from the manifest")


def apply_saved(work, reports, environ, report):
    report["operation"] = "validate_noble_dispatch_selection"
    selection = selection_from_environment(environ)
    report.update(producer_commit=selection["producer_commit"], producer_run=selection["producer_run"])
    verify_context(environ, selection["producer_run"])
    token = environ["GCP_ACCESS_TOKEN"]
    producer = ROOT / "plan-source"
    manifest, plan, findings = load_plan(environ, selection, report)
    report["operation"] = "verify_noble_owner_decision"
    reference = foundation.decode(environ["DB01_NOBLE_OWNER_DECISION"])
    controls = environ["GITHUB_SHA"]
    verify_reference(reference, suffix="manifest.json", commit=controls)
    c.require(reference["name"] == decision_name(controls, selection["producer_run"]),
              "Separate private decision must use the exact reviewed namespace")
    decision = foundation.decode(custody.fetch_verified(reference))
    profile, _ = writer.load_profile(ROOT)
    verify_decision(decision, manifest, plan, selection["artifact"], profile, findings, controls, datetime.now(timezone.utc))
    report["operation"] = "verify_noble_read_temporal_stable_receipts"
    write_profile, write_proof, read_profile, read_proof, historical_etags, iam_receipt = writer.load_stable_evidence(
        decision["write_receipt"])
    c.require(profile == write_profile, "Stable WRITE profile changed")
    etags = (noble.stable_iam_etags(read_profile, historical_etags, write_proof)
             if "stable_write_receipt" in manifest else historical_etags)
    refreshed = sorted(address for address, (saved, live) in etags.items() if saved != live)
    c.require({**iam_receipt, "etag_only_addresses": refreshed} == manifest["iam_refresh"], "IAM proof differs from plan review")
    report["approval"] = {"decision": reference, "write_receipt": decision["write_receipt"],
                          "write_profile_sha256": decision["write_profile_sha256"], "plan_manifest": plan["manifest"],
                          "iac_findings_sha256": decision["iac_findings_sha256"], "observation": True}
    report["operation"] = "verify_noble_producer_sources"
    copy_sources(work, producer, manifest)
    report["operation"] = "verify_noble_native_plan"
    native_plan = foundation.decode(custody.fetch_verified(plan["json"]))
    exact_plan_actions(native_plan, manifest, etags)
    resources = {row["address"]: row["change"]["after"] for row in native_plan["resource_changes"] if row["mode"] == "managed"}
    debian_vm = resources["google_compute_instance.postgres"]
    debian_disk = resources["google_compute_disk.postgres"]
    planned_values = native_plan["output_changes"]["db01_noble_candidate"]["after"]
    planned_hashes = {key: planned_values[key] for key in OUTPUT_HASH_KEYS}
    planned_startup = resources["google_compute_instance.noble[0]"]["metadata_startup_script"]
    bound_image = manifest["inputs"]["db01_noble_candidate"]
    c.require(all(map(iam.valid_digest, planned_hashes.values()))
              and planned_values["image_name"] == bound_image["name"] and planned_values["image_id"] == bound_image["id"]
              and custody.sha256(planned_startup.encode("utf-8")) == planned_hashes["startup_sha256"],
              "Reviewed producer image, startup or host-key binding differs")
    saved = work / "saved-noble.tfplan"
    saved.write_bytes(custody.fetch_verified(plan["binary"]))
    with noble.guarded_phase("noble_apply_preflight"):
        origin_state(manifest["backend"])
        stable_debian = historical.vm_proof(debian_vm, debian_disk)
        noble.verify_live_stable_iam(write_profile, write_proof, read_profile, read_proof, token)
        image = noble.image_identity(compute(noble.IMAGE_ROOT + "/images/" + bound_image["name"], "check_exact_plan_image",
                                             **noble.IMAGE_QUERY))
        c.require(image == bound_image, "Exact public plan image changed")
        noble.preflight_network()
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color",
                "-backend-config=backend-int.hcl"], "noble_apply_init", work)
    _, shown = driver.run([binary, "show", "-json", str(saved)], "noble_apply_show_saved", work)
    c.require(foundation.decode(shown) == native_plan, "Exact saved binary no longer renders the reviewed native JSON")
    with noble.guarded_phase("noble_apply_final_preflight"):
        c.require(custody.sha256(saved.read_bytes()) == plan["binary"]["sha256"]
                  and all(custody.sha256((work / "source" / path).read_bytes()) == checksum
                          for path, checksum in manifest["source_sha256"].items()), "Saved plan or producer source bytes changed")
        noble.verify_live_stable_iam(write_profile, write_proof, read_profile, read_proof, token)
        c.require(historical.vm_proof(debian_vm, debian_disk) == stable_debian, "Existing Debian VM differs before apply")
        noble.preflight_network()
        parent = origin_state(manifest["backend"])
    attempted = datetime.now(timezone.utc)
    verify_plan_ttl(manifest, attempted)
    claim_once(environ, manifest, plan, reference, report, attempted)
    verify_plan_ttl(manifest, datetime.now(timezone.utc))
    execute_native(work, reports, environ, report, binary, saved)
    report["operation"] = "verify_noble_post_apply"
    raw, obj, _ = current_state()
    state, candidate = state_postcheck(raw, obj, parent, read_profile, read_proof, write_proof, bound_image,
                                      origin=manifest["backend"])
    c.require({key: candidate[key] for key in OUTPUT_HASH_KEYS} == planned_hashes,
              "Recorded startup or host-key nonce differs from the saved plan")
    report["state"] = state
    noble.verify_live_stable_iam(write_profile, write_proof, read_profile, read_proof, token)
    c.require(historical.vm_proof(debian_vm, debian_disk) == stable_debian, "Existing Debian VM or attached disks differ after apply")
    candidate, snapshot = observed_resources(candidate, token)
    c.require(guest.timestamp(candidate["creation_timestamp"]) >= attempted,
              "Noble instance preexisted the one-shot creation intent")
    _, stable, _ = current_state()
    c.require(stable["generation"] == state["generation"], "State changed during the apply postchecks")
    report.update(status="created_verified", candidate=candidate, control_plane=snapshot, debian_preserved=True)
    encoded = custody.canonical(report)
    try:
        report["receipt"] = custody.upload(prefix(environ) + "foundation-state.json", encoded)
        c.require(custody.fetch_verified(report["receipt"]) == encoded, "Private creation receipt read-back differs")
    except Exception:
        report["status"] = "created_receipt_unconfirmed"
        raise


def publish_decision(controls, decision_path, output):
    iam.verify_checkout(controls)
    for path in (decision_path, output):
        iam.verify_receipt_location(path)
    c.require(decision_path.is_file() and decision_path.stat().st_size <= ARTIFACT_LIMIT and not output.exists(),
              "Bounded approval file and a new private reference path required")
    decision = foundation.decode(decision_path.read_bytes())
    selection = plan_selection(decision["producer_commit"], decision["producer_run"],
                               decision["plan"]["manifest"], decision["plan_artifact"])
    cli = shutil.which("gh") or shutil.which("gh.exe")
    c.require(cli is not None, "Existing GitHub CLI session required for producer evidence")
    github_token = iam.run_local([cli, "auth", "token", "--hostname", "github.com"])
    c.require(bool(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,8192}", github_token)), "Read-only producer evidence token required")
    token = iam.admin_token()
    os.environ["GCP_ACCESS_TOKEN"] = token
    try:
        manifest, plan, findings = load_plan({"GH_TOKEN": github_token}, selection, {})
        profile, _ = writer.load_profile(ROOT)
        verify_decision(decision, manifest, plan, selection["artifact"], profile, findings, controls, datetime.now(timezone.utc))
        write_profile, write_proof, read_profile, read_proof, _, _ = writer.load_stable_evidence(decision["write_receipt"])
        c.require(profile == write_profile, "Stable WRITE profile changed")
        noble.verify_live_stable_iam(write_profile, write_proof, read_profile, read_proof, token)
        origin_state(manifest["backend"])
        verify_plan_ttl(manifest, datetime.now(timezone.utc))
        name = decision_name(controls, selection["producer_run"])
        raw = custody.canonical(decision)
        iam.write_new(output.with_name(output.name + ".intent"), {"name": name, "sha256": custody.sha256(raw)})
        reference = custody.upload(name, raw)
        c.require(custody.fetch_verified(reference) == raw, "Private decision read-back differs")
        iam.write_new(output, reference)
    finally:
        os.environ.pop("GCP_ACCESS_TOKEN", None)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    commands.add_parser("check")
    commands.add_parser("apply")
    publication = commands.add_parser("publish-decision")
    publication.add_argument("--controls", required=True)
    publication.add_argument("--decision", required=True, type=Path)
    publication.add_argument("--output", required=True, type=Path)
    args = parser.parse_args(argv)
    if args.operation == "check":
        writer.load_profile(ROOT)
        for reference in (*PLAN.values(), READ_RECEIPT):
            verify_reference(reference)
        if "DB01_NOBLE_PLAN_MANIFEST" in os.environ:
            selection_from_environment(os.environ)
        return 0
    if args.operation == "publish-decision":
        try:
            publish_decision(args.controls, args.decision, args.output)
        except Exception as error:
            print(json.dumps({"status": "blocked", "diagnostic": error_receipt(error, "publish_noble_owner_decision", ROOT)}),
                  file=sys.stderr)
            return 1
        print(json.dumps({"status": "decision_verified", "controls_commit": args.controls}))
        return 0
    os.umask(0o077)
    work, reports = driver.private_paths()
    report = {"schema": CREATION_SCHEMA, "status": "blocked_preflight", "operation": "verify_noble_saved_plan",
              "controls_commit": os.environ.get("GITHUB_SHA"),
              "apply_run_id": os.environ.get("GITHUB_RUN_ID"), "native_apply_attempted": False, "native_apply_completed": False,
              "bootstrap_authorized": False, "application_authorized": False}
    try:
        save_summary(reports, report)
        apply_saved(work, reports, os.environ, report)
        save_summary(reports, report)
    except Exception as error:
        if report["status"] != "created_receipt_unconfirmed":
            report["status"] = ("postcheck_unconfirmed" if report["native_apply_completed"] else
                                "apply_outcome_unconfirmed" if report["native_apply_attempted"] else "blocked_preflight")
        if "diagnostic" not in report:
            report["diagnostic"] = error_receipt(error, report["operation"], work)
        print(json.dumps({"status": report["status"], "native_apply_attempted": report["native_apply_attempted"],
                          "diagnostic": report["diagnostic"]}), file=sys.stderr)
        if report["native_apply_attempted"]:
            report["reconciliation"] = partial_observation(os.environ["GCP_ACCESS_TOKEN"])
        try:
            save_summary(reports, report)
        except Exception as summary_error:
            print(json.dumps({"status": "blocked", "diagnostic": error_receipt(summary_error, "write_noble_apply_summary", work)}),
                  file=sys.stderr)
        return 1
    print(json.dumps({"status": report["status"], "operation": report["operation"],
                      "native_apply_completed": report["native_apply_completed"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
