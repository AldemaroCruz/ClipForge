"""Independent read-only serial-7 postverification; no Terraform execution path.

The only optional cloud mutation creates one new private receipt object with
ifGenerationMatch=0. Authentication is supplied by the caller's existing usual
ADMIN guard; this module never invokes gcloud, ADC, a shell or another process.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

from scripts import check_tf_int as c
from scripts import int_foundation_close as close
from scripts import int_release_state as state_reader

ROOT = Path(__file__).resolve().parents[1]
CONFIG = "config/int-foundation-verification.json"
SCHEMA = "clipforge-int-foundation-postverification-config-1"
RECEIPT_SCHEMA = "clipforge-int-foundation-postverification-receipt-1"
LIMIT = 8 * 1024 * 1024
STATE_PIN = {"name": "terraform/int/tf-int-01/default.tfstate", "generation": "1795030868572779", "size": 110325,
             "sha256": "aa2d7bf8d15d0fe3fb8461483483be2aa49ccede18c94d67a1f5a5a723ef13ce",
             "lineage": "813c84a2-2ef1-ceb3-177e-3a2c3b815066", "serial": 7, "terraform_version": "1.15.8"}
DECISION_SHA = "82da9870c3a8a79d2502ec1f7febc14f6daa05f82fad415aea1cf3db26588777"
GRANT_SHA = "815a33c8f0af1acb0b202958e021973b27b628f4766d5ee75bd6589dde8ad19d"
WITHDRAW_SHA = "162509372f5975a470129de5e5bafcf25a2d0bfa8e9fbd4e9af2dde9d1a07fdd"
SUMMARY_SHA = "14e2b4cfde9c03921163995644b7677859a281195b1b7f1818e9eaf4fbea0d99"
PRODUCER = "24c753bd04cd3e530f08acee3768cb10545d1977"
RUN = "44382086626"
IAP = close.IAP_RESOURCE
COMPUTE_BASE = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
VM_URL = COMPUTE_BASE + "instances/clipforge-int-base-postgres"
DISK_URLS = tuple(COMPUTE_BASE + "disks/" + name for name in ("clipforge-int-base-postgres", "clipforge-int-base-postgres-data"))
SINK_URL = "https://logging.googleapis.com/v2/projects/clipforgebeta2/sinks/clipforge-int-access"
IAP_URL = "https://iap.googleapis.com/v1/" + IAP + ":getIamPolicy"
IAP_BODY = {"options": {"requestedPolicyVersion": 3}}
BASELINE_SHA = "e4c72e49ba1772f9d063903ab526a30e55a61d2634af03fe9de4d2d5449b4838"
ADMIN_ACTOR = {"account": "admin@ixbalam.studio", "source": "usual_admin_guard_external",
               "guard_source_sha256": "46e619f6a72fc1e20dce21f890749971328ba37c5cd206b17a8e031bfd753704"}
BASELINE_SIZE = 1622


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def decode(raw):
    def pairs(items):
        value = {}
        for key, item in items:
            c.require(key not in value, "Duplicate postverification JSON key")
            value[key] = item
        return value
    c.require(isinstance(raw, (bytes, str)) and 0 < len(raw) <= LIMIT, "Bounded private JSON required")
    try:
        return json.loads(raw, object_pairs_hook=pairs)
    except (ValueError, UnicodeError):
        raise ValueError("Invalid private postverification JSON") from None


def instant(value):
    return close.instant(value)


def load_config(root=ROOT):
    return validate_contract(decode((root / CONFIG).read_bytes()))


def validate_contract(cfg):
    fields = {"schema", "operation", "project_id", "project_number", "backend", "state", "parent_state", "plan",
              "original_execution", "iam_package", "historical_observations", "local_evidence", "managed_addresses",
              "critical_unchanged_addresses", "receipt", "runtime_authorized", "guest_authorized", "application_authorized"}
    c.require(isinstance(cfg, dict) and set(cfg) == fields and cfg["schema"] == SCHEMA
              and cfg["operation"] == "read_only_postverification_with_optional_single_immutable_receipt"
              and (cfg["project_id"], cfg["project_number"]) == ("clipforgebeta2", "816643438938")
              and cfg["backend"] == {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default"}
              and cfg["state"] == STATE_PIN and cfg["managed_addresses"] == sorted(c.FOUNDATION_ADDRESSES)
              and cfg["critical_unchanged_addresses"] == ["google_compute_instance.postgres", "google_compute_disk.postgres", "google_logging_project_sink.access"]
              and all(cfg[key] is False for key in ("runtime_authorized", "guest_authorized", "application_authorized")),
              "Postverification boundary or exact serial-7 pin differs")
    parent = cfg["parent_state"]
    c.require(set(parent) == {"bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version"}
              and parent["bucket"] == c.BUCKET and parent["prefix"] == c.PREFIX and parent["workspace"] == "default"
              and parent["terraform_version"] == "1.15.8" and parent["name"] == STATE_PIN["name"] and parent["generation"] == "1794975925421249"
              and parent["serial"] == 6 and parent["lineage"] == STATE_PIN["lineage"]
              and parent["sha256"] == "360a728e0e3dcb37050389b5bf936a4359107eeeb579794b96d35743a59a1f43" and parent["size"] == 109542,
              "Historical serial-6 provenance differs")
    plan = cfg["plan"]
    c.require(set(plan) == {"configuration_commit", "controls_commit", "run_id", "run_attempt", "created_utc", "expires_utc", "configuration_sha256", "provider_lock_sha256", "terraform_version", "provider_version", "manifest", "binary", "json"}
              and plan["configuration_commit"] == plan["controls_commit"] == PRODUCER
              and (plan["run_id"], plan["run_attempt"], plan["terraform_version"], plan["provider_version"]) == ("44360231461", "1", "1.15.8", "8.11.0")
              and instant(plan["expires_utc"]) > instant(plan["created_utc"]), "Historical approved producer differs")
    for key, name in (("manifest", "manifest.json"), ("binary", "int.tfplan"), ("json", "int.json")):
        reference = plan[key]
        c.require(set(reference) == {"name", "generation", "size", "sha256"}
                  and reference["name"] == "private-plans/int/" + PRODUCER + "/44360231461-1/" + name
                  and re.fullmatch(r"[1-9][0-9]*", reference["generation"])
                  and re.fullmatch(r"[a-f0-9]{64}", reference["sha256"])
                  and type(reference["size"]) is int and 0 < reference["size"] <= LIMIT, "Unreviewed private historical reference")
    original = cfg["original_execution"]
    c.require(set(original) == {"run_id", "run_attempt", "workflow", "control_commit", "workflow_conclusion", "native_completion_status", "native_completion_observed_utc"}
              and original["run_id"] == RUN and original["run_attempt"] == "1"
              and original["control_commit"] == "65057bbc51c6a3907d5529a3aae543f82583814e"
              and original["workflow"] == ".github/workflows/int-foundation-close.yml"
              and original["workflow_conclusion"] == "failure"
              and original["native_completion_status"] == "native_close_apply_completed_postverification_failed_no_retry",
              "Original failed workflow provenance must remain unchanged")
    close.verify_iam_package(cfg["iam_package"])
    evidence = cfg["local_evidence"]
    c.require(set(evidence) == {"owner_decision", "administrative_authorization", "close_summary", "grant_index", "withdrawal_index", "baseline_iap_policy"}
              and evidence["owner_decision"]["sha256"] == DECISION_SHA and evidence["grant_index"]["sha256"] == GRANT_SHA
              and evidence["withdrawal_index"]["sha256"] == WITHDRAW_SHA and evidence["close_summary"]["sha256"] == SUMMARY_SHA,
              "Historical decision or administrative receipt reference differs")
    names = {"owner_decision": "close-owner-decision.authorized.json", "administrative_authorization": "owner-administrative-authorization.json",
             "close_summary": "run-44382086626/close-summary.json", "grant_index": "receipts/receipt-index.json",
             "withdrawal_index": "withdrawal-receipts/receipt-index.json", "baseline_iap_policy": "iap-iam.json"}
    c.require(all(set(evidence[key]) == {"name", "sha256", "size"} and evidence[key]["name"] == name
              and re.fullmatch(r"[a-f0-9]{64}", evidence[key]["sha256"]) and type(evidence[key]["size"]) is int
              and 0 < evidence[key]["size"] <= LIMIT for key, name in names.items())
              and evidence["baseline_iap_policy"]["sha256"] == BASELINE_SHA and evidence["baseline_iap_policy"]["size"] == BASELINE_SIZE,
              "Historical local evidence name, bound or baseline pin differs")
    observations = cfg["historical_observations"]
    c.require(set(observations) == {"grants_first_utc", "grants_completed_utc", "owner_decision_checked_utc", "withdrawal_first_utc", "withdrawal_completed_utc"}, "Unknown historical observation field")
    ordered = [observations[key] for key in ("grants_first_utc", "grants_completed_utc", "owner_decision_checked_utc")]
    ordered += [original["native_completion_observed_utc"], observations["withdrawal_first_utc"], observations["withdrawal_completed_utc"]]
    times = [instant(value) for value in ordered]
    c.require(times == sorted(times) and instant(close.WINDOW["not_before_utc"]) <= times[0]
              and times[-1] < instant(close.WINDOW["expires_utc"]), "Historical execution observations are unordered or outside their fixed window")
    c.require(cfg["receipt"] == {"schema": RECEIPT_SCHEMA, "prefix": "private-plans/int/", "original_run_component": RUN + "-1",
              "filename": "foundation-state.json", "if_generation_match": "0", "maximum_bytes": 65536}, "Immutable receipt destination contract differs")
    return cfg


def verified(raw, reference):
    c.require(isinstance(raw, bytes) and len(raw) == int(reference["size"]) and sha(raw) == reference["sha256"],
              "Pinned private evidence bytes differ")
    return decode(raw)


def validate_current_state(raw, metadata, inventory, cfg):
    pin = cfg["state"]
    c.require(metadata.get("name") == pin["name"] and str(metadata.get("generation")) == pin["generation"]
              and str(metadata.get("size")) == str(pin["size"]), "Current state metadata differs from the serial-7 pin")
    c.require(isinstance(inventory, dict) and not inventory.get("nextPageToken") and isinstance(inventory.get("items"), list),
              "Complete current backend inventory required")
    current = inventory["items"]
    c.require(len(current) == 1 and current[0].get("name") == pin["name"]
              and str(current[0].get("generation")) == pin["generation"]
              and str(current[0].get("size")) == str(pin["size"]), "Current lock, other object, workspace or generation blocks verification")
    value = verified(raw, pin)
    proof = state_reader.state_contract(raw, lineage=pin["lineage"])
    c.require(proof["serial"] == 7 and all(not row.get("deposed") and row.get("status") in {None, "ready"}
              for resource in value["resources"] for row in resource.get("instances", [])), "Exact ready serial-7 state required")
    return {**pin, "managed_addresses": proof["managed_addresses"], "current_lock_absent": True}


def validate_iap_policy(policy, cfg, *, baseline=None):
    rows = policy.get("bindings", [])
    functional = [row for row in rows if row.get("role") == close.FUNCTIONAL_ROLE and row.get("condition") is None
                  and close.DEPLOY_MEMBER in row.get("members", [])]
    management = next(row for row in cfg["iam_package"]["bindings"] if row["binding_id"] == "iap_management")
    c.require(len(functional) == 1, "Functional Deploy IAP member must be present exactly once without a condition")
    c.require(not any(row.get("role") == management["role"] and close.TF_MEMBER in row.get("members", [])
              and row.get("condition") == management["condition"] for row in rows), "Reviewed new temporary IAP management binding is still present")
    if baseline is not None:
        close.functional_iap_proof(baseline, policy)
    return {"resource": IAP, "functional_role": close.FUNCTIONAL_ROLE, "functional_member": close.DEPLOY_MEMBER,
            "functional_condition": None, "functional_present_exactly_once": True,
            "retired_management_condition_sha256": management["condition_sha256"], "exact_management_binding_absent": True,
            "only_reviewed_management_binding_checked": True, "effective_permissions_not_inferred": True,
            "all_other_policy_bindings_preserved": baseline is not None, "baseline_policy_sha256": BASELINE_SHA if baseline is not None else None}


def validate_vm(vm, disks, planned_vm, planned_disk):
    mapping = {VM_URL: vm}
    c.require(isinstance(disks, list) and len(disks) == 2, "Both exact retained disk responses required")
    for disk in disks:
        url = COMPUTE_BASE + "disks/" + str(disk.get("name", ""))
        c.require(url in DISK_URLS and url not in mapping, "Unreviewed or duplicated disk response")
        mapping[url] = disk
    def reader(url, operation, resource):
        c.require(url in mapping, "Unexpected pure VM validation read")
        return mapping[url]
    return close.vm_proof(planned_vm, planned_disk, reader=reader)


def validate_sink(value, planned):
    def reader(url, operation, resource):
        c.require(url == SINK_URL, "Unexpected pure sink validation read")
        return value
    return close.sink_proof(planned, reader=reader)


def validate_history(decision_raw, grant_bundle, withdrawal_bundle, close_proposal, close_summary_raw, cfg):
    decision = verified(decision_raw, cfg["local_evidence"]["owner_decision"])
    summary = verified(close_summary_raw, cfg["local_evidence"]["close_summary"])
    observed = cfg["historical_observations"]
    c.require(decision["schema"] == close.DECISION_SCHEMA and decision["owner"] == "AldemaroCruz"
              and decision["apply_decision"] == "approve_exact_serial6_closure_binary_once"
              and decision["apply_controls_commit"] == cfg["original_execution"]["control_commit"]
              and decision["plan"] == close_proposal["plan"] and decision["expected_review"] == close_proposal["expected_review"]
              and decision["runtime_authorized"] is False
              and decision["iam_package"]["manifest_sha256"] == cfg["iam_package"]["manifest_sha256"]
              and decision["iam_package"]["administrator_receipt_index_sha256"] == GRANT_SHA,
              "Historical exact owner decision differs")
    c.require(all(cfg["plan"][key] == decision["plan"][key] for key in cfg["plan"]), "Historical private plan selection differs from the approved decision")
    check_time = instant(observed["owner_decision_checked_utc"])
    c.require(instant(decision["plan"]["created_utc"]) <= check_time < instant(decision["expires_utc"])
              and check_time < instant(decision["plan"]["expires_utc"])
              and instant(close.WINDOW["not_before_utc"]) <= check_time < instant(close.WINDOW["expires_utc"]),
              "Decision was not valid at its historical observation")
    native_observed = instant(cfg["original_execution"]["native_completion_observed_utc"])
    c.require(check_time <= native_observed < instant(decision["expires_utc"])
              and native_observed < instant(decision["plan"]["expires_utc"])
              and native_observed < instant(decision["risk_expiry_utc"]), "Historical native completion was observed outside the approved execution bounds")
    c.require(summary.get("status") == cfg["original_execution"]["native_completion_status"] and summary.get("runtime_authorized") is False,
              "Original workflow failure/native completion evidence differs")
    c.require(sha(grant_bundle["index"].encode()) == GRANT_SHA, "Real historical grant index required")
    grants = close.verify_iam_receipts(json.dumps(grant_bundle), decision, close_proposal)
    grant_index = decode(grant_bundle["index"])
    grant_times = [instant(decode(grant_bundle["files"][row["name"]])["utc"]) for row in grant_index["files"]]
    c.require(instant(decode(grant_bundle["files"][grant_index["files"][0]["name"]])["utc"]) == instant(observed["grants_first_utc"])
              and instant(decode(grant_bundle["files"][grant_index["files"][-1]["name"]])["utc"]) == instant(observed["grants_completed_utc"]),
              "Historical grant observation dates differ")
    c.require(grant_times == sorted(grant_times), "Historical grant timestamps are not ordered")
    c.require(set(withdrawal_bundle) == {"index", "files"} and sha(withdrawal_bundle["index"].encode()) == WITHDRAW_SHA,
              "Real historical withdrawal index required")
    index = decode(withdrawal_bundle["index"])
    c.require(set(index) == {"schema", "manifest_sha256", "source_proposal_sha256", "files"}
              and index["schema"] == "clipforge-int-read-admin-receipt-index-1"
              and index["manifest_sha256"] == cfg["iam_package"]["manifest_sha256"]
              and index["source_proposal_sha256"] == cfg["iam_package"]["source_proposal_sha256"] and len(index["files"]) == 9,
              "Complete nine-phase withdrawal log required")
    management = next(row for row in cfg["iam_package"]["bindings"] if row["binding_id"] == "iap_management")
    expected_details = {key: management[key] for key in ("binding_id", "role", "member", "condition_sha256")}
    times, names = [], set()
    for number, item in enumerate(index["files"], 1):
        name = f"{number:04d}.json"
        c.require(set(item) == {"name", "sha256"} and item["name"] == name and name not in names, "Withdrawal sequence differs")
        names.add(name); raw = withdrawal_bundle["files"][name].encode()
        c.require(sha(raw) == item["sha256"], "Withdrawal phase bytes differ")
        row = decode(raw)
        phase = ("withdraw_preflight", "withdraw_before", "withdraw_management", "verify_management_withdrawal")[(number-1)//2] if number < 9 else "management_withdrawn"
        status = "attempted" if number < 9 and number % 2 else "completed"
        c.require(row["schema"] == "clipforge-int-read-admin-receipt-1" and row["sequence"] == number
                  and row["manifest_sha256"] == index["manifest_sha256"] and row["operation"] == phase and row["status"] == status
                  and row["mutation_attempted"] is (number == 6) and row["http_status"] == (200 if number < 9 and number % 2 == 0 else None)
                  and (row["key"], row["resource"]) == (("iap_management", IAP) if number < 9 else ("", "")),
                  "Failed or foreign withdrawal phase")
        at = instant(row["utc"]); times.append(at)
        c.require(instant(close.WINDOW["not_before_utc"]) <= at < instant(close.WINDOW["expires_utc"]), "Withdrawal outside its historical authorization")
        if number in {6, 8}:
            c.require(row["details"] == expected_details, "Withdrawal binding descriptor differs")
        if number == 9:
            c.require(row["details"] == {"binding_id": "iap_management", "functional_deploy_binding_preserved": True, "unrelated_bindings_preserved": True},
                      "Withdrawal final preservation proof differs")
    c.require(names == set(withdrawal_bundle["files"]) and times == sorted(times)
              and times[0] == instant(observed["withdrawal_first_utc"]) and times[-1] == instant(observed["withdrawal_completed_utc"]),
              "Incomplete or shifted historical withdrawal observations")
    return {"owner_decision_sha256": DECISION_SHA, "grants": grants, "grant_receipt_index_sha256": GRANT_SHA,
            "withdrawal_receipt_index_sha256": WITHDRAW_SHA, "withdrawal_receipt_files": 9,
            "observed_utc": observed, "historical_window_only": close.WINDOW,
            "current_temporary_read_grants_required": False, "current_window_validity_not_required": True,
            "original_close_summary_sha256": SUMMARY_SHA}


def expected_history(cfg):
    return {"owner_decision_sha256": DECISION_SHA,
            "grants": {"bindings_granted_and_verified": 11, "existing_roles_verified": 9, "receipt_files": 97, "administrator_receipt_index_sha256": GRANT_SHA},
            "grant_receipt_index_sha256": GRANT_SHA, "withdrawal_receipt_index_sha256": WITHDRAW_SHA, "withdrawal_receipt_files": 9,
            "observed_utc": cfg["historical_observations"], "historical_window_only": close.WINDOW,
            "current_temporary_read_grants_required": False, "current_window_validity_not_required": True,
            "original_close_summary_sha256": SUMMARY_SHA}


def _attributes(state):
    result = {}
    for resource in state.get("resources", []):
        if resource.get("mode") == "data":
            continue
        c.require(resource.get("mode") == "managed" and not resource.get("module"), "Unreviewed state resource")
        for instance in resource.get("instances", []):
            address = resource["type"] + "." + resource["name"]
            if "index_key" in instance:
                address += "[" + json.dumps(instance["index_key"], separators=(",", ":")) + "]"
            c.require(address not in result and isinstance(instance.get("attributes"), dict), "Duplicate or malformed state instance")
            result[address] = instance["attributes"]
    return result


def verify_evidence(cfg, *, new_commit, observed_utc, history, manifest_raw, plan_raw, state6_raw, state7_raw,
                    state_metadata, inventory, vm, disks, sink, iap_policy, baseline_iap_policy_raw, read_actor=None):
    validate_contract(cfg)
    c.require(bool(re.fullmatch(r"[a-f0-9]{40}", new_commit)) and new_commit not in {cfg["original_execution"]["control_commit"], PRODUCER}, "New verification control commit required")
    c.require(instant(observed_utc) >= instant(cfg["historical_observations"]["withdrawal_completed_utc"]), "New postverification cannot precede the historical retirement")
    c.require(read_actor == ADMIN_ACTOR, "External usual ADMIN guard metadata required")
    baseline = verified(baseline_iap_policy_raw, cfg["local_evidence"]["baseline_iap_policy"])
    manifest = verified(manifest_raw, cfg["plan"]["manifest"])
    plan = verified(plan_raw, cfg["plan"]["json"])
    c.require(manifest["binary"] == cfg["plan"]["binary"] and manifest["json"] == cfg["plan"]["json"]
              and manifest["configuration_commit"] == PRODUCER and manifest["run_id"] == "44360231461", "Historical exact saved plan provenance differs")
    changes = {row["address"]: row for row in plan.get("resource_changes", []) if row.get("mode") == "managed"}
    c.require(set(changes) == c.FOUNDATION_ADDRESSES and not plan.get("deferred_changes")
              and all(row["change"]["actions"] == (["create"] if address == "google_iap_tunnel_instance_iam_member.protected_bootstrap" else ["no-op"])
                      and not row["change"].get("importing") for address, row in changes.items()), "Historical plan must remain one IAP creation plus 41 NOOPs")
    state_proof = validate_current_state(state7_raw, state_metadata, inventory, cfg)
    parent = verified(state6_raw, cfg["parent_state"]); current = decode(state7_raw)
    c.require(parent.get("version") == 4 and parent.get("serial") == 6 and parent.get("lineage") == STATE_PIN["lineage"], "Historical serial-6 header differs")
    old, new = _attributes(parent), _attributes(current)
    pending = "google_iap_tunnel_instance_iam_member.protected_bootstrap"
    c.require(set(old) == c.FOUNDATION_ADDRESSES - {pending} and set(new) == c.FOUNDATION_ADDRESSES, "Parent or final managed addresses differ")
    iap = new[pending]
    c.require(iap.get("project") == "816643438938" and iap.get("zone") == "us-central1-a"
              and iap.get("instance") in {"1670495097211408131", IAP} and iap.get("role") == close.FUNCTIONAL_ROLE
              and iap.get("member") == close.DEPLOY_MEMBER and iap.get("condition") in (None, []), "State IAP canonical numeric identity differs")
    critical = []
    for address in cfg["critical_unchanged_addresses"]:
        c.require(old[address] == new[address], "Critical full state attributes changed from serial 6")
        critical.append({"address": address, "all_attributes_equal_to_serial6": True, "attributes_sha256": sha(canonical(new[address]))})
    vm_proof = validate_vm(vm, disks, changes["google_compute_instance.postgres"]["change"]["after"], changes["google_compute_disk.postgres"]["change"]["after"])
    sink_proof = validate_sink(sink, changes["google_logging_project_sink.access"]["change"]["after"])
    receipt = {"schema": RECEIPT_SCHEMA, "issuer": {"kind": "local_postverification", "control_commit": new_commit, "observed_utc": observed_utc, "read_actor": read_actor},
        "facts": {
            "historical_native_execution": {**cfg["original_execution"], "producer_commit": PRODUCER, "plan_run_id": "44360231461",
                "plan_manifest": cfg["plan"]["manifest"], "plan_binary": cfg["plan"]["binary"], "native_apply_completed": True, "workflow_failure_preserved": True},
            "observed_foundation": {"state": state_proof, "critical_resources": critical, "unchanged_VM": vm_proof,
                "sink_convergence": sink_proof, "canonical_IAP_state_identity": IAP, "observed_utc": observed_utc},
            "administrative_history_and_retirement": {"history": history, "current_IAP": validate_iap_policy(iap_policy, cfg, baseline=baseline), "observed_utc": observed_utc},
            "independent_postverification": {"no_native_execution": True, "no_backend_writes": True, "no_IAM_writes": True,
                "new_GitHub_run_not_claimed": True, "original_workflow_conclusion": "failure", "operational_audit_coverage_not_inferred": True}},
        "runtime_authorized": False, "guest_authorized": False, "application_authorized": False}
    validate_receipt(receipt, cfg, new_commit)
    return receipt


def validate_receipt(receipt, cfg, new_commit):
    validate_contract(cfg)
    c.require(set(receipt) == {"schema", "issuer", "facts", "runtime_authorized", "guest_authorized", "application_authorized"}
              and receipt["schema"] == RECEIPT_SCHEMA and receipt["issuer"]["kind"] == "local_postverification"
              and receipt["issuer"]["control_commit"] == new_commit and re.fullmatch(r"[a-f0-9]{40}", new_commit)
              and new_commit not in {cfg["original_execution"]["control_commit"], PRODUCER}
              and set(receipt["facts"]) == {"historical_native_execution", "observed_foundation", "administrative_history_and_retirement", "independent_postverification"}
              and all(receipt[key] is False for key in ("runtime_authorized", "guest_authorized", "application_authorized")), "Only the closed four-fact postverification receipt may be published")
    issuer = receipt["issuer"]
    c.require(set(issuer) == {"kind", "control_commit", "observed_utc", "read_actor"} and issuer["read_actor"] == ADMIN_ACTOR
              and instant(issuer["observed_utc"]) >= instant(cfg["historical_observations"]["withdrawal_completed_utc"]), "Receipt issuer or external ADMIN metadata differs")
    native = {**cfg["original_execution"], "producer_commit": PRODUCER, "plan_run_id": "44360231461",
              "plan_manifest": cfg["plan"]["manifest"], "plan_binary": cfg["plan"]["binary"], "native_apply_completed": True, "workflow_failure_preserved": True}
    facts = receipt["facts"]
    c.require(facts["historical_native_execution"] == native, "Historical failed workflow fact differs")
    current = facts["observed_foundation"]
    c.require(set(current) == {"state", "critical_resources", "unchanged_VM", "sink_convergence", "canonical_IAP_state_identity", "observed_utc"}
              and current["state"] == {**cfg["state"], "managed_addresses": cfg["managed_addresses"], "current_lock_absent": True}
              and current["canonical_IAP_state_identity"] == IAP and current["observed_utc"] == issuer["observed_utc"], "Current foundation fact differs")
    c.require(isinstance(current["critical_resources"], list) and len(current["critical_resources"]) == 3, "Three complete critical resource comparisons required")
    for row, address in zip(current["critical_resources"], cfg["critical_unchanged_addresses"]):
        c.require(set(row) == {"address", "all_attributes_equal_to_serial6", "attributes_sha256"} and row["address"] == address
                  and row["all_attributes_equal_to_serial6"] is True and re.fullmatch(r"[a-f0-9]{64}", row["attributes_sha256"]), "Critical resource proof shape differs")
    vm = current["unchanged_VM"]
    c.require(set(vm) == {"instance_id", "configuration_sha256", "startup_unchanged", "two_retained_disks", "guest_access_performed"}
              and vm["instance_id"] == "1670495097211408131" and re.fullmatch(r"[a-f0-9]{64}", vm["configuration_sha256"])
              and vm["startup_unchanged"] is True and vm["two_retained_disks"] is True and vm["guest_access_performed"] is False, "Closed VM proof differs")
    sink = current["sink_convergence"]
    sink_hashes = {"destination_sha256", "filter_sha256", "stable_API_configuration_sha256"}
    sink_flags = {"enabled", "API_writer_identity_absent_or_empty", "provider_8_11_read_unique_writer_identity", "representation_converged_without_second_plan", "exclusive_writer_identity_not_inferred", "operational_audit_coverage_not_inferred"}
    c.require(set(sink) == {"name"} | sink_hashes | sink_flags and sink["name"] == "clipforge-int-access"
              and all(re.fullmatch(r"[a-f0-9]{64}", sink[key]) for key in sink_hashes) and all(sink[key] is True for key in sink_flags), "Closed sink proof differs")
    administrative = facts["administrative_history_and_retirement"]
    c.require(set(administrative) == {"history", "current_IAP", "observed_utc"} and administrative["history"] == expected_history(cfg)
              and administrative["observed_utc"] == issuer["observed_utc"], "Historical administrative proof differs")
    management = next(row for row in cfg["iam_package"]["bindings"] if row["binding_id"] == "iap_management")
    expected_iap = {"resource": IAP, "functional_role": close.FUNCTIONAL_ROLE, "functional_member": close.DEPLOY_MEMBER,
                    "functional_condition": None, "functional_present_exactly_once": True,
                    "retired_management_condition_sha256": management["condition_sha256"], "exact_management_binding_absent": True,
                    "only_reviewed_management_binding_checked": True, "effective_permissions_not_inferred": True,
                    "all_other_policy_bindings_preserved": True, "baseline_policy_sha256": BASELINE_SHA}
    c.require(administrative["current_IAP"] == expected_iap, "Full baseline IAP preservation and exact retirement required")
    c.require(facts["independent_postverification"] == {"no_native_execution": True, "no_backend_writes": True, "no_IAM_writes": True,
              "new_GitHub_run_not_claimed": True, "original_workflow_conclusion": "failure", "operational_audit_coverage_not_inferred": True}, "Independent verification capability fact differs")
    encoded = canonical(receipt)
    c.require(len(encoded) <= cfg["receipt"]["maximum_bytes"], "Allowlisted receipt exceeds its bound")
    forbidden = {"attributes", "outputs", "policy_data", "credentials", "access_token", "private_key", "policy"}
    def visit(value):
        if isinstance(value, dict):
            c.require(not (set(value) & forbidden), "Private payload field cannot enter a receipt")
            for item in value.values():
                visit(item)
        elif isinstance(value, list):
            for item in value:
                visit(item)
    visit(receipt)
    return encoded


def reference_url(cfg, reference):
    return "https://storage.googleapis.com/storage/v1/b/" + cfg["backend"]["bucket"] + "/o/" + quote(reference["name"], safe="") + "?" + urlencode(
        {"alt": "media", "generation": reference["generation"], "ifGenerationMatch": reference["generation"]})


def metadata_url(cfg):
    return "https://storage.googleapis.com/storage/v1/b/" + cfg["backend"]["bucket"] + "/o/" + quote(cfg["state"]["name"], safe="") + "?fields=name,generation,size"


def inventory_url(cfg):
    return "https://storage.googleapis.com/storage/v1/b/" + cfg["backend"]["bucket"] + "/o?" + urlencode(
        {"prefix": cfg["backend"]["prefix"] + "/", "maxResults": "10", "fields": "items(name,generation,size),nextPageToken"})


def bucket_url(cfg):
    return "https://storage.googleapis.com/storage/v1/b/" + cfg["backend"]["bucket"] + "?fields=name,projectNumber,iamConfiguration,versioning"


def validate_bucket(value, cfg):
    iam = value.get("iamConfiguration", {})
    c.require(value.get("name") == cfg["backend"]["bucket"] and str(value.get("projectNumber")) == cfg["project_number"]
              and iam.get("uniformBucketLevelAccess", {}).get("enabled") is True
              and iam.get("publicAccessPrevention") == "enforced" and value.get("versioning", {}).get("enabled") is True,
              "Existing receipt bucket privacy, versioning or project differs")


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("Postverification API redirects are forbidden")


class Client:
    def __init__(self, cfg, token_provider, *, read_actor=None):
        self.cfg = validate_contract(cfg)
        self.token_provider = token_provider
        self.read_actor = read_actor
        self.published = False
        self._armed_upload = None
        self._upload_consumed = False
        self._receipt_readback_url = None
        self.references = [cfg["state"], cfg["parent_state"], cfg["plan"]["manifest"], cfg["plan"]["json"]]
        self.reads = {VM_URL, *DISK_URLS, SINK_URL, metadata_url(cfg), inventory_url(cfg), bucket_url(cfg)} | {reference_url(cfg, ref) for ref in self.references}

    def _send(self, url, method, payload):
        upload = (method == "POST" and self._armed_upload is not None and not self._upload_consumed
                  and (url, sha(payload) if isinstance(payload, bytes) else None) == self._armed_upload)
        c.require((method == "GET" and payload is None and (url in self.reads or (self._receipt_readback_url is not None and url == self._receipt_readback_url)))
                  or (method == "POST" and url == IAP_URL and payload == canonical(IAP_BODY)) or upload,
                  "Cloud capability denied before authentication")
        if upload:
            self._upload_consumed = True
        token = self.token_provider()
        c.require(isinstance(token, str) and re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "Short-lived caller-supplied access token required")
        request = Request(url, data=payload, method=method, headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                          "X-Goog-Request-Reason": "ClipForge independent foundation serial7 postverification"})
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
                raw = response.read(LIMIT + 1)
            c.require(len(raw) <= LIMIT, "Private read exceeds the response bound")
            return raw
        except HTTPError as error:
            raise ValueError("Postverification HTTP " + str(error.code) + "; response body withheld") from None

    def read(self, url, *, method="GET", payload=None):
        c.require((method == "GET" and url in self.reads and payload is None)
                  or (method == "POST" and url == IAP_URL and payload == IAP_BODY), "Unreviewed postverification read endpoint, method or body")
        raw = self._send(url, method, canonical(payload) if payload is not None else None)
        return decode(raw)

    def fetch(self, reference):
        c.require(any(reference == known for known in self.references), "Unreviewed private byte reference")
        raw = self._send(reference_url(self.cfg, reference), "GET", None)
        verified(raw, reference)
        return raw

    def publish_receipt(self, receipt, new_commit):
        raw = validate_receipt(receipt, self.cfg, new_commit)
        c.require(not self.published and self.read_actor == ADMIN_ACTOR, "Only one externally guarded ADMIN receipt upload attempt is allowed")
        validate_bucket(self.read(bucket_url(self.cfg)), self.cfg)
        current_raw = self.fetch(self.cfg["state"])
        validate_current_state(current_raw, self.read(metadata_url(self.cfg)), self.read(inventory_url(self.cfg)), self.cfg)
        name = "private-plans/int/" + new_commit + "/" + RUN + "-1/foundation-state.json"
        c.require(not name.startswith(self.cfg["backend"]["prefix"] + "/"), "Backend writes are forbidden")
        url = "https://storage.googleapis.com/upload/storage/v1/b/" + self.cfg["backend"]["bucket"] + "/o?" + urlencode(
            {"uploadType": "media", "name": name, "ifGenerationMatch": "0"})
        self.published = True  # An unknown transport outcome is never retried.
        self._armed_upload = (url, sha(raw))
        result = decode(self._send(url, "POST", raw))
        c.require(result.get("name") == name and re.fullmatch(r"[1-9][0-9]*", result.get("generation", ""))
                  and str(result.get("size")) == str(len(raw)), "Immutable receipt result metadata differs")
        reference = {"name": name, "generation": result["generation"], "size": len(raw), "sha256": sha(raw)}
        self._receipt_readback_url = reference_url(self.cfg, reference)
        verified(self._send(self._receipt_readback_url, "GET", None), reference)
        return reference


def local_bytes(path):
    info = path.lstat()
    c.require(stat.S_ISREG(info.st_mode) and not path.is_symlink() and not getattr(info, "st_file_attributes", 0) & 0x400
              and info.st_nlink == 1 and 0 < info.st_size <= LIMIT, "Regular bounded local evidence file required")
    raw = path.read_bytes()
    after = path.lstat()
    c.require((info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns) == (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns)
              and len(raw) == info.st_size, "Local evidence changed during read")
    return raw


def _bundle(directory, reference, count):
    index_raw = local_bytes(directory / "receipt-index.json")
    index = verified(index_raw, reference)  # Hash authority before opening any indexed filename.
    c.require(isinstance(index, dict) and isinstance(index.get("files"), list) and len(index["files"]) == count,
              "Closed historical receipt count required")
    files = {}
    for number, row in enumerate(index["files"], 1):
        name = f"{number:04d}.json"
        c.require(set(row) == {"name", "sha256"} and row["name"] == name and re.fullmatch(r"[a-f0-9]{64}", row["sha256"]),
                  "Historical receipt filename or digest differs")
        raw = local_bytes(directory / name)
        c.require(sha(raw) == row["sha256"], "Historical receipt bytes differ")
        files[name] = raw.decode("utf-8")
    c.require({entry.name for entry in directory.iterdir()} == set(files) | {"receipt-index.json"}, "Unindexed historical receipt file")
    return {"index": index_raw.decode("utf-8"), "files": files}


def verify(cfg, *, new_commit, historical_execution_dir, admin_package_dir, baseline_iap_policy_file, client, observed_utc=None):
    execution, admin = Path(historical_execution_dir), Path(admin_package_dir)
    proposal = close.load_proposal()
    c.require(client.read_actor == ADMIN_ACTOR, "Caller must provide metadata from the existing usual ADMIN guard")
    history = validate_history(local_bytes(execution / cfg["local_evidence"]["owner_decision"]["name"]),
              _bundle(admin / "receipts", cfg["local_evidence"]["grant_index"], 97),
              _bundle(admin / "withdrawal-receipts", cfg["local_evidence"]["withdrawal_index"], 9), proposal,
              local_bytes(execution / cfg["local_evidence"]["close_summary"]["name"]), cfg)
    validate_bucket(client.read(bucket_url(cfg)), cfg)
    return verify_evidence(cfg, new_commit=new_commit, observed_utc=observed_utc or datetime.now(timezone.utc).isoformat(), history=history,
        manifest_raw=client.fetch(cfg["plan"]["manifest"]), plan_raw=client.fetch(cfg["plan"]["json"]),
        state6_raw=client.fetch(cfg["parent_state"]), state7_raw=client.fetch(cfg["state"]),
        state_metadata=client.read(metadata_url(cfg)), inventory=client.read(inventory_url(cfg)), vm=client.read(VM_URL),
        disks=[client.read(url) for url in DISK_URLS], sink=client.read(SINK_URL), iap_policy=client.read(IAP_URL, method="POST", payload=IAP_BODY),
        baseline_iap_policy_raw=local_bytes(Path(baseline_iap_policy_file)), read_actor=client.read_actor)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "verify"))
    parser.add_argument("--new-commit")
    parser.add_argument("--historical-execution-dir", type=Path)
    parser.add_argument("--admin-package-dir", type=Path)
    parser.add_argument("--baseline-iap-policy-file", type=Path)
    parser.add_argument("--output", type=Path)
    parser.add_argument("--publish", action="store_true")
    args = parser.parse_args()
    cfg = load_config()
    if args.operation == "check":
        print("Independent serial-7 postverification contract valid; no cloud or native execution.")
        return
    c.require(args.new_commit and args.historical_execution_dir and args.admin_package_dir and args.baseline_iap_policy_file and args.output,
              "Explicit verification commit, historical evidence directories and new local output required")
    c.require(not args.output.exists(), "Local receipt must not overwrite an existing file")
    actor = ADMIN_ACTOR if os.environ.get("INT_POSTVERIFY_ADMIN_GUARD_SHA256") == ADMIN_ACTOR["guard_source_sha256"] else None
    client = Client(cfg, lambda: os.environ.get("GCP_ACCESS_TOKEN", ""), read_actor=actor)
    receipt = verify(cfg, new_commit=args.new_commit, historical_execution_dir=args.historical_execution_dir, admin_package_dir=args.admin_package_dir,
                     baseline_iap_policy_file=args.baseline_iap_policy_file, client=client)
    raw = validate_receipt(receipt, cfg, args.new_commit)
    with args.output.open("xb") as stream:
        stream.write(raw)
    result = {"local_receipt_sha256": sha(raw), "runtime_authorized": False, "original_workflow_conclusion": "failure"}
    if args.publish:
        result["private_receipt"] = client.publish_receipt(receipt, args.new_commit)
    print(json.dumps(result))


if __name__ == "__main__":
    main()
