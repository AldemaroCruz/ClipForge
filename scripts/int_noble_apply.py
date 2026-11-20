"""Prepare or execute only the exact saved DB-01 Noble creation plan."""

import argparse
import base64
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

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
DECISION_SCHEMA = "clipforge-db01-noble-create-observe-decision-1"
CREATION_SCHEMA = "clipforge-db01-noble-creation-receipt-1"
DECISION = "exact_noble_creation_and_first_observation_authorized"
OUTPUT_HASH_KEYS = ("hostkey_nonce", "startup_sha256")
PROJECT_POLICY = writer.PROJECT
IAP_ZONE = writer.ZONE
IAC_FINDINGS_SHA = "537659806270b78d3693b16944255111621c8b163937da9b0a32ae065ee70f54"
NOBLE_IAC_INDICES = (8, 9, 10, 11)
POLICY_READ = {"options": {"requestedPolicyVersion": 3}}
NATIVE_OPERATION = "noble_apply_saved"
NATIVE_TIMEOUT = timedelta(seconds=1200)


def utc(value):
    match = datetime.fromisoformat(value.replace("Z", "+00:00"))
    c.require(match.utcoffset() == timedelta(0), "UTC timestamp required")
    return match


def verify_window(manifest, profile, now, *, must_fit_apply=False):
    created, expires = utc(manifest["created_utc"]), utc(manifest["expires_utc"])
    start, end = utc(profile["not_before_utc"]), utc(profile["expires_utc"])
    deadline = min(end, expires)
    c.require(manifest["expires_utc"] == PLAN_EXPIRY and expires - created == timedelta(hours=24)
              and created <= start < end <= expires, "Original plan or WRITE window timing was changed")
    if now >= expires:
        raise noble.Blocked("noble_apply_original_plan_expired")
    if not start <= now < deadline or (must_fit_apply and now + NATIVE_TIMEOUT >= deadline):
        raise noble.Blocked("noble_apply_write_window_unavailable")


def verify_reference(value, *, fixed=None, suffix=None, commit=None):
    iam.check_fields(value, {"name", "generation", "sha256", "size"})
    name = custody.object_name(value["name"])
    c.require(isinstance(value["generation"], str) and re.fullmatch(r"[1-9][0-9]*", value["generation"])
              and iam.valid_digest(value["sha256"]) and type(value["size"]) is int and 0 < value["size"] <= 2 * 1024 * 1024
              and (fixed is None or value == fixed) and (suffix is None or name.endswith("/" + suffix))
              and (commit is None or name.startswith(custody.PREFIX + commit + "/")),
              "Private immutable object reference differs")
    return value


def verify_manifest(value):
    iam.check_fields(value, {"schema", "commit", "run_id", "run_attempt", "created_utc", "expires_utc",
                             "terraform_version", "provider_version", "inputs", "source_sha256", "backend",
                             "actions", "iam_refresh", "apply_authorized", "binary", "json"})
    c.require(value["schema"] == noble.SCHEMA and value["commit"] == PRODUCER and value["run_id"] == PLAN_RUN
              and value["run_attempt"] == "1" and value["terraform_version"] == "1.15.8" and value["provider_version"] == "8.11.0"
              and value["backend"] == PLAN_STATE and value["apply_authorized"] is False
              and value["binary"] == PLAN["binary"] and value["json"] == PLAN["json"]
              and value["iam_refresh"]["receipt"] == READ_RECEIPT and value["expires_utc"] == PLAN_EXPIRY,
              "Original manifest provenance, plan, state or TTL differs")
    iam.check_fields(value["inputs"], {"stage", "machine_type", "db01_noble_candidate"})
    image = value["inputs"]["db01_noble_candidate"]
    c.require(value["inputs"]["stage"] == "foundation" and value["inputs"]["machine_type"] == "e2-micro"
              and image["name"] == IMAGE_NAME and image["id"] == IMAGE_ID and noble.image_identity(image) == image,
              "Original plan inputs or exact public image differ")
    c.require(set(value["source_sha256"]) == {path.as_posix() for path in SOURCE_PATHS}
              and all(map(iam.valid_digest, value["source_sha256"].values())), "Plan source closure differs")


def verify_decision(decision, manifest, profile, environ, now):
    iam.check_fields(decision, {"schema", "decision", "owner_approval_ref", "issued_utc", "producer_commit", "producer_run",
                               "controls_commit", "project", "plan", "expires_utc", "write_profile_sha256", "write_receipt",
                               "iac_findings_sha256", "iac_decisions"})
    c.require(decision["schema"] == DECISION_SCHEMA and decision["decision"] == DECISION
              and isinstance(decision["owner_approval_ref"], str) and 0 < len(decision["owner_approval_ref"].strip()) <= 500
              and decision["producer_commit"] == PRODUCER and decision["producer_run"] == PLAN_RUN
              and decision["controls_commit"] == environ["GITHUB_SHA"] and decision["controls_commit"] != PRODUCER
              and decision["project"] == c.PROJECT and decision["plan"] == PLAN and decision["expires_utc"] == PLAN_EXPIRY
              and utc(manifest["created_utc"]) <= utc(decision["issued_utc"]) <= now
              and decision["write_profile_sha256"] == noble.digest(profile)
              and decision["iac_findings_sha256"] == IAC_FINDINGS_SHA, "Separate exact owner approval is required")
    rows = decision["iac_decisions"]
    c.require(isinstance(rows, list) and len(rows) == len(NOBLE_IAC_INDICES), "Individual Noble IaC decisions are required")
    for number, row in zip(NOBLE_IAC_INDICES, rows):
        iam.check_fields(row, {"finding_index", "decision", "rationale"})
        c.require(type(row["finding_index"]) is int and row["finding_index"] == number
                  and row["decision"] == "reviewed_for_this_noble_creation"
                  and isinstance(row["rationale"], str) and 0 < len(row["rationale"].strip()) <= 500,
                  "Each finding needs an explicit review for this exact operation")
    verify_reference(decision["write_receipt"])
    c.require(decision["write_receipt"]["name"] == writer.proof_name(environ["GITHUB_SHA"]),
              "WRITE receipt must use the exact decision namespace")
    verify_window(manifest, profile, now)


def canonical_direct_policy(policy):
    version = policy.get("version", 0)
    c.require(type(version) is int and version in {0, 1, 3} and
              (version == 3 or not any("condition" in binding for binding in policy.get("bindings", []))),
              "Conditional IAM policy must have version three")
    # GCP returns version zero/one for policies with no conditions, including an empty zone.
    return iam.canonical_policy({**policy, "version": 3, "bindings": policy.get("bindings", [])})


def verify_write_receipt(receipt, profile, read_proof, environ, now):
    iam.check_fields(receipt, {"schema", "producer_commit", "controls_commit", "profile_sha256", "issued_utc", "policies"})
    c.require(receipt["schema"] == writer.RECEIPT_SCHEMA and receipt["producer_commit"] == PRODUCER
              and receipt["controls_commit"] == environ["GITHUB_SHA"]
              and receipt["profile_sha256"] == noble.digest(profile) and set(receipt["policies"]) == set(profile["policies"])
              and utc(profile["not_before_utc"]) <= utc(receipt["issued_utc"]) <= now < utc(profile["expires_utc"]),
              "WRITE receipt provenance or active window differs")
    for target, row in receipt["policies"].items():
        iam.check_fields(row, {"before", "after"})
        spec = profile["policies"][target]
        c.require(noble.digest(row["before"]) == spec["baseline_policy_sha256"], "WRITE baseline differs from the reviewed policy")
        if target in read_proof["policies"]:
            c.require(writer.canonical_policy(target, row["before"]) == iam.canonical_policy(read_proof["policies"][target]["after"]),
                      "WRITE baseline does not preserve the exact retained READ result")
        writer.verify_delta(target, row["before"], row["after"], spec["add_bindings"])


def verify_live_iam(read_profile, read_proof, write_profile, write_proof, token):
    roles = {**read_profile["roles"], **write_profile["roles"]}
    for role, spec in roles.items():
        result = iam.request_json("https://iam.googleapis.com/v1/" + role, token)
        iam.check_role_definition(role, result, spec)
    for target, record in read_proof["policies"].items():
        if target not in write_proof["policies"]:
            live = iam.get_policy(target, read_profile["policies"][target], token)
            c.require(iam.canonical_policy(live) == iam.canonical_policy(record["after"]), "Stable READ policy changed")
    for target, record in write_proof["policies"].items():
        live = writer.get_policy(target, token)
        c.require(writer.canonical_policy(target, live) == writer.canonical_policy(target, record["after"]),
                  "A live policy differs from the authorized WRITE result")


def copy_sources(work, producer, manifest):
    source = work / "source"
    for relative in SOURCE_PATHS:
        file = producer / relative
        c.require(file.is_file() and not file.is_symlink() and file.resolve().is_relative_to(producer.resolve()),
                  "Producer source is not a checked-out file")
        raw = file.read_bytes()
        c.require(custody.sha256(raw) == manifest["source_sha256"][relative.as_posix()], "Producer source bytes differ")
        target = source / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(raw)
    (work / "module").symlink_to(source / noble.MODULE, target_is_directory=True)
    (work / "terraform.rc").write_text("disable_checkpoint = true\nprovider_installation {\n  direct {}\n}\n", encoding="utf-8")


def verify_producer_run(environ):
    tokens = {"Authorization": "Bearer " + environ["GH_TOKEN"], "Accept": "application/vnd.github+json",
              "X-GitHub-Api-Version": "2022-11-28"}
    api = f"https://api.github.com/repos/{REPOSITORY}/actions/"
    opener = build_opener(ProxyHandler({}), driver.NoRedirect())
    endpoints = (f"runs/{PLAN_RUN}/attempts/1", f"artifacts/{PLAN_ARTIFACT}")
    records = []
    for endpoint in endpoints:
        with opener.open(Request(api + endpoint, headers=tokens), timeout=30) as response:
            body = response.read(1024 * 1024 + 1)
        c.require(len(body) <= 1024 * 1024, "Producer metadata exceeds its bound")
        records.append(foundation.decode(body))
    value, artifact = records
    expected = {"id": int(PLAN_RUN), "run_attempt": 1, "head_sha": PRODUCER, "head_branch": "ci/bootstrap-sec03",
                "event": "workflow_dispatch", "path": PRODUCER_WORKFLOW, "status": "completed", "conclusion": "success"}
    c.require(all(value.get(key) == item for key, item in expected.items()), "Saved plan producer run is not the exact successful attempt")
    c.require(artifact["id"] == int(PLAN_ARTIFACT) and artifact["expired"] is False
              and artifact["name"] == f"db01-noble-plan-summary-{PRODUCER}-{PLAN_RUN}-1"
              and artifact["digest"] == "sha256:" + PLAN_ARTIFACT_SHA
              and artifact["workflow_run"]["head_sha"] == PRODUCER and artifact["workflow_run"]["id"] == int(PLAN_RUN),
              "Exact producer artifact evidence is no longer retained")


def current_state():
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    foundation.validate_bucket(bucket, {"backend": {"bucket": c.BUCKET}, "project_number": "816643438938"})
    return states.private_current_state(bucket)


def origin_state():
    raw, obj, inventory = current_state()
    live = [item for item in inventory["live"] if item["name"].startswith(c.PREFIX + "/")]
    pin = foundation.validate_current_state(raw, obj, {"items": live}, {"state": foundation.STATE_PIN})
    c.require(pin == PLAN_STATE, "Saved plan state no longer current")
    return foundation.decode(raw)


def state_postcheck(raw, obj, parent, read_profile, read_proof, write_proof):
    state = foundation.decode(raw)
    c.require(state["version"] == 4 and state["terraform_version"] == "1.15.8"
              and state["lineage"] == PLAN_STATE["lineage"] and type(state["serial"]) is int and state["serial"] > 7
              and obj["name"] == PLAN_STATE["name"] and obj["generation"] != PLAN_STATE["generation"],
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
    verify_candidate(candidate, after)
    proof = {"name": obj["name"], "generation": obj["generation"], "size": len(raw), "sha256": custody.sha256(raw),
             "lineage": state["lineage"], "serial": state["serial"], "managed_address_count": len(after),
             "preserved_address_count": len(old), "current_lock_absent": True}
    return proof, candidate


def verify_candidate(candidate, attrs):
    expected = {"instance_name": guest.host.INSTANCE, "boot_disk": guest.BOOT_DISK, "data_disk": guest.DATA_DISK,
                "data_device": guest.DEVICE_NAME, "private_ip": guest.PRIVATE_IP, "service_email": guest.GUEST_EMAIL,
                "image_name": IMAGE_NAME, "image_id": IMAGE_ID}
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
        (f"https://iam.googleapis.com/v1/{sa}:getIamPolicy", "POST", POLICY_READ, {"role": "roles/iam.serviceAccountUser"}),
        (f"https://iap.googleapis.com/v1/{IAP_ZONE}/instances/{instance_id}:getIamPolicy", "POST", POLICY_READ,
         {"role": "roles/iap.tunnelResourceAccessor", "condition": {"title": "db01_noble_ssh_only", "expression": "destination.port == 22"}}),
    )
    for url, method, body, binding in policies:
        policy = canonical_direct_policy(iam.request_json(url, token, method, body))
        c.require(policy["bindings"] == [{**binding, "members": [historical.DEPLOY_MEMBER]}]
                  and not policy.get("auditConfigs"), "Unexpected direct Noble resource IAM policy")


def verify_context(environ):
    custody.hosted_context(environ)
    c.validate_variables(environ)
    sha = environ["GITHUB_SHA"]
    c.require(re.fullmatch(r"[a-f0-9]{40}", sha) and sha != PRODUCER
              and environ.get("GITHUB_WORKFLOW_REF") == f"{REPOSITORY}/{WORKFLOW}@refs/heads/ci/bootstrap-sec03"
              and environ.get("DB01_NOBLE_APPROVED_CONTROL_COMMIT") == sha
              and re.fullmatch(r"[1-9][0-9]*", environ["GITHUB_RUN_ID"])
              and environ["GITHUB_RUN_ID"] != PLAN_RUN and environ.get("GITHUB_RUN_ATTEMPT") == "1"
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


def claim_once(environ, decision_reference, report, attempted):
    # This create-only marker outlives the runner and binds the saved plan even
    # when a later execution control commit tries to reference the same binary.
    intent = {"schema": "clipforge-db01-noble-apply-intent-1", "producer_commit": PRODUCER,
              "controls_commit": environ["GITHUB_SHA"], "apply_run_id": environ["GITHUB_RUN_ID"],
              "decision": decision_reference, "binary": PLAN["binary"], "intent_utc": attempted.isoformat()}
    encoded = custody.canonical(intent)
    report["operation"] = "claim_exact_saved_plan"
    report["intent"] = custody.upload(PLAN_PREFIX + "foundation-state.json", encoded)
    c.require(custody.fetch_verified(report["intent"]) == encoded, "Private one-shot intent read-back differs")


def apply_saved(work, reports, environ, report):
    verify_context(environ)
    verify_producer_run(environ)
    token = environ["GCP_ACCESS_TOKEN"]
    profile, _ = writer.load_profile(ROOT)
    producer = ROOT / "plan-source"
    manifest = foundation.decode(custody.fetch_verified(PLAN["manifest"]))
    verify_manifest(manifest)
    reference = foundation.decode(environ["DB01_NOBLE_OWNER_DECISION"])
    controls = environ["GITHUB_SHA"]
    verify_reference(reference, suffix="manifest.json", commit=controls)
    c.require(reference["name"] == f"{custody.PREFIX}{controls}/{PLAN_RUN}-1/manifest.json",
              "Separate private decision must use the exact reviewed namespace")
    decision = foundation.decode(custody.fetch_verified(reference))
    verify_decision(decision, manifest, profile, environ, datetime.now(timezone.utc))
    write_proof = foundation.decode(custody.fetch_verified(decision["write_receipt"]))
    read_profile, read_proof, etags, iam_receipt = noble.load_iam_evidence({
        "GITHUB_SHA": PRODUCER, "DB01_NOBLE_IAM_RECEIPT": custody.canonical(READ_RECEIPT).decode("ascii"),
    })
    c.require({**iam_receipt, "etag_only_addresses": sorted(etags)} == manifest["iam_refresh"], "READ proof differs from plan review")
    verify_write_receipt(write_proof, profile, read_proof, environ, datetime.now(timezone.utc))
    report["approval"] = {"decision": reference, "write_receipt": decision["write_receipt"],
                          "write_profile_sha256": decision["write_profile_sha256"], "plan_manifest": PLAN["manifest"],
                          "iac_findings_sha256": IAC_FINDINGS_SHA, "observation": True}
    copy_sources(work, producer, manifest)
    native_plan = foundation.decode(custody.fetch_verified(PLAN["json"]))
    actions = noble.action_summary(native_plan, etags)
    noble.validate_action_scope(actions, 2, sorted(etags))
    c.require(actions == manifest["actions"], "Custodied native actions differ from the manifest")
    resources = {row["address"]: row["change"]["after"] for row in native_plan["resource_changes"] if row["mode"] == "managed"}
    debian_vm = resources["google_compute_instance.postgres"]
    debian_disk = resources["google_compute_disk.postgres"]
    planned_values = native_plan["output_changes"]["db01_noble_candidate"]["after"]
    planned_hashes = {key: planned_values[key] for key in OUTPUT_HASH_KEYS}
    planned_startup = resources["google_compute_instance.noble[0]"]["metadata_startup_script"]
    c.require(all(map(iam.valid_digest, planned_hashes.values()))
              and custody.sha256(planned_startup.encode("utf-8")) == planned_hashes["startup_sha256"],
              "Reviewed producer startup and host-key binding differ")
    saved = work / "saved-noble.tfplan"
    saved.write_bytes(custody.fetch_verified(PLAN["binary"]))
    with noble.guarded_phase("noble_apply_preflight"):
        origin_state()
        stable_debian = historical.vm_proof(debian_vm, debian_disk)
        verify_live_iam(read_profile, read_proof, profile, write_proof, token)
        image = noble.image_identity(compute(noble.IMAGE_ROOT + "/images/" + IMAGE_NAME, "check_exact_plan_image", **noble.IMAGE_QUERY))
        c.require(image == manifest["inputs"]["db01_noble_candidate"], "Exact public plan image changed")
        noble.preflight_network()
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color",
                "-backend-config=backend-int.hcl"], "noble_apply_init", work)
    _, shown = driver.run([binary, "show", "-json", str(saved)], "noble_apply_show_saved", work)
    c.require(foundation.decode(shown) == native_plan, "Exact saved binary no longer renders the reviewed native JSON")
    with noble.guarded_phase("noble_apply_final_preflight"):
        c.require(custody.sha256(saved.read_bytes()) == PLAN["binary"]["sha256"]
                  and all(custody.sha256((work / "source" / path).read_bytes()) == checksum
                          for path, checksum in manifest["source_sha256"].items()), "Saved plan or producer source bytes changed")
        verify_live_iam(read_profile, read_proof, profile, write_proof, token)
        c.require(historical.vm_proof(debian_vm, debian_disk) == stable_debian, "Existing Debian VM differs before apply")
        noble.preflight_network()
        parent = origin_state()
    verify_window(manifest, profile, datetime.now(timezone.utc), must_fit_apply=True)
    attempted = datetime.now(timezone.utc)
    claim_once(environ, reference, report, attempted)
    verify_window(manifest, profile, datetime.now(timezone.utc), must_fit_apply=True)
    execute_native(work, reports, environ, report, binary, saved)
    report["operation"] = "verify_noble_post_apply"
    raw, obj, _ = current_state()
    state, candidate = state_postcheck(raw, obj, parent, read_profile, read_proof, write_proof)
    c.require({key: candidate[key] for key in OUTPUT_HASH_KEYS} == planned_hashes,
              "Recorded startup or host-key nonce differs from the saved plan")
    report["state"] = state
    verify_live_iam(read_profile, read_proof, profile, write_proof, token)
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "apply"))
    operation = parser.parse_args(argv).operation
    if operation == "check":
        writer.load_profile(ROOT)
        for reference in (*PLAN.values(), READ_RECEIPT):
            verify_reference(reference)
        return 0
    os.umask(0o077)
    work, reports = driver.private_paths()
    report = {"schema": CREATION_SCHEMA, "status": "blocked_preflight", "operation": "verify_noble_saved_plan",
              "producer_commit": PRODUCER, "controls_commit": os.environ.get("GITHUB_SHA"),
              "apply_run_id": os.environ.get("GITHUB_RUN_ID"), "native_apply_attempted": False, "native_apply_completed": False,
              "plan_expires_utc": PLAN_EXPIRY, "bootstrap_authorized": False, "application_authorized": False}
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
        if report["native_apply_attempted"]:
            report["reconciliation"] = partial_observation(os.environ["GCP_ACCESS_TOKEN"])
        save_summary(reports, report)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
