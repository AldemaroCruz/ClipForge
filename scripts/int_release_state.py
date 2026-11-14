"""Explicit post-apply provenance for phase two; never automatic state adoption.

The original empty-state pin stays separate and unchanged. Runtime dispatch must
name the private receipt generation/SHA reviewed by the owner. State payloads
are inspected in private memory only; no resource attributes leave this helper.
"""
import json
import os
import re
from urllib.parse import quote, urlencode
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, int_release as r, tf_int_plan as driver

SCHEMA = "clipforge-int-foundation-apply-receipt-1"


def state_contract(raw, *, lineage):
    value = json.loads(raw)
    c.require(value.get("version") == 4 and value.get("terraform_version") == "1.15.8"
              and value.get("lineage") == lineage and type(value.get("serial")) is int and value["serial"] >= 2,
              "Foundation state header differs from the approved backend lineage")
    addresses = set()
    for resource in value.get("resources", []):
        c.require(not resource.get("module"), "Unreviewed state module")
        if resource.get("mode") == "data":
            c.require(resource.get("type") in c.DATA_TYPES, "Unreviewed state data source")
            continue
        c.require(resource.get("mode") == "managed", "Unknown state resource mode")
        for instance in resource.get("instances", []):
            c.require(not instance.get("deposed"), "Deposed resources require review")
            address = resource["type"] + "." + resource["name"]
            if "index_key" in instance:
                key = instance["index_key"]
                c.require(type(key) in {int, str}, "Unknown state instance index")
                address += "[" + json.dumps(key, separators=(",", ":")) + "]"
            c.require(address not in addresses, "Duplicate state instance")
            addresses.add(address)
    c.require(addresses == c.FOUNDATION_ADDRESSES, "State must contain exactly the approved foundation addresses; unknown resources block runtime")
    c.require(set(value.get("outputs", {})) <= {"reviewed_boundary"}, "Unreviewed state outputs")
    return {"lineage": value["lineage"], "serial": value["serial"], "managed_addresses": sorted(addresses)}


def private_current_state(bucket):
    inventory = driver.backend_inventory(bucket)
    scoped = [o for o in inventory["live"] if o["name"].startswith(c.PREFIX + "/")]
    c.require(not any(o["name"].endswith(".tflock") for o in scoped), "A current Terraform lock blocks phase-two inspection")
    c.require(len(scoped) == 1 and scoped[0]["name"] == driver.STATE_NAME, "Unknown current backend object/workspace")
    obj = scoped[0]
    params = {"alt": "media", "generation": obj["generation"], "ifGenerationMatch": obj["generation"]}
    url = "https://storage.googleapis.com/storage/v1/b/" + c.BUCKET + "/o/" + quote(driver.STATE_NAME, safe="") + "?" + urlencode(params)
    request = Request(url, headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]})
    with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(r.LIMIT + 1)
    c.require(len(raw) <= r.LIMIT and len(raw) == int(obj["size"]), "Private state payload exceeds bound or differs from metadata")
    live_ids = {(o["name"], o["generation"]) for o in inventory["live"]}
    summary = {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "live": inventory["live"],
               "historical": [o for o in inventory["versions"] if (o["name"], o["generation"]) not in live_ids],
               "soft_deleted": inventory["soft_deleted"]}
    return raw, obj, summary


def verify_parent(receipt, parent, module, environ):
    c.require(receipt.get("schema") == SCHEMA and parent.get("schema") == r.SCHEMA, "Unknown provenance receipt or source plan")
    c.require(parent.get("inputs", {}).get("stage") == "foundation" and receipt.get("foundation_commit") == parent.get("commit")
              and receipt.get("source_plan_sha256") == parent.get("binary", {}).get("sha256"),
              "Receipt parent is not the exact approved foundation binary plan")
    binding = r.source_binding(module, environ)
    c.require(all(parent.get(k) == binding[k] for k in ("configuration_sha256", "provider_lock_sha256", "terraform_version", "repository", "branch")),
              "Foundation configuration/provider lineage differs; new provenance review is required")
    c.require(parent.get("backend") == {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
              "lineage": driver.INITIAL_STATE["lineage"], "serial": 1, "state_generation": driver.INITIAL_STATE["generation"],
              "state_sha256": driver.INITIAL_STATE["sha256"]}, "Foundation parent does not descend from the reviewed initial snapshot")
    c.require(receipt.get("managed_addresses") == sorted(c.FOUNDATION_ADDRESSES), "Receipt foundation address allowlist differs")
    issuer = receipt.get("issuer", {})
    control_commit = receipt.get("control_commit", parent["commit"])
    approval = receipt.get("control_approval")
    if control_commit != parent["commit"]:
        c.require(isinstance(approval, dict) and approval.get("plan_commit") == parent["commit"]
                  and approval.get("control_commit") == control_commit
                  and all(bool(re.fullmatch(r"[a-f0-9]{64}", approval.get(k, ""))) for k in ("decision_sha256", "evidence_sha256")),
                  "Cross-commit foundation provenance lacks the exact owner decision/evidence binding")
    c.require(issuer.get("repository") == "AldemaroCruz/ClipForge" and issuer.get("workflow") == ".github/workflows/int-e2e-apply.yml"
              and issuer.get("commit") == control_commit and bool(re.fullmatch(r"[1-9][0-9]*", issuer.get("run_id", ""))),
              "Unrecognized apply receipt issuer")


def verify_apply_run(receipt, environ):
    issuer = receipt["issuer"]
    c.require(bool(environ.get("GH_TOKEN")), "Read-only GitHub Actions token required for apply provenance")
    request = Request("https://api.github.com/repos/AldemaroCruz/ClipForge/actions/runs/" + issuer["run_id"], headers={
        "Authorization": "Bearer " + environ["GH_TOKEN"], "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=60) as response:
        raw = response.read(1024 * 1024 + 1)
    c.require(len(raw) <= 1024 * 1024, "Apply provenance response exceeds bound")
    run = json.loads(raw)
    c.require(str(run.get("id")) == issuer["run_id"] and run.get("head_sha") == issuer["commit"]
              and run.get("head_branch") == "ci/bootstrap-sec03" and run.get("event") == "workflow_dispatch"
              and run.get("path") == issuer["workflow"] and run.get("status") == "completed" and run.get("conclusion") == "success",
              "The exact protected foundation apply run has not completed successfully")


def inspect_approved_foundation(bucket, module, environ):
    reference = r.inputs(environ)["foundation_receipt"]
    receipt = json.loads(r.fetch_verified(reference))
    parent = json.loads(r.fetch_verified(receipt["foundation_plan_manifest"]))
    verify_parent(receipt, parent, module, environ)
    verify_apply_run(receipt, environ)
    raw, obj, summary = private_current_state(bucket)
    state = state_contract(raw, lineage=parent["backend"]["lineage"])
    c.require(receipt.get("state") == {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw),
              "sha256": r.sha256(raw), "lineage": state["lineage"], "serial": state["serial"]},
              "State generation/bytes/lineage/serial changed after the reviewed foundation receipt")
    summary.update(classification="recognized_approved_foundation_state", lineage=state["lineage"],
                   state_serial=state["serial"], state_sha256=r.sha256(raw), foundation_receipt=reference)
    return summary


def emit_foundation_receipt(work, parent_manifest, parent_reference, environ, *, approval=None):
    # Called only after native apply(saved binary) has returned success.
    c.require(parent_manifest.get("inputs", {}).get("stage") == "foundation", "Only a foundation apply can issue this receipt")
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    raw, obj, _ = private_current_state(bucket)
    state = state_contract(raw, lineage=parent_manifest["backend"]["lineage"])
    receipt = {"schema": SCHEMA, "foundation_commit": parent_manifest["commit"], "foundation_plan_manifest": parent_reference,
               "control_commit": environ["GITHUB_SHA"], "control_approval": approval,
               "source_plan_sha256": parent_manifest["binary"]["sha256"], "managed_addresses": state["managed_addresses"],
               "state": {"name": driver.STATE_NAME, "generation": obj["generation"], "size": len(raw), "sha256": r.sha256(raw),
                         "lineage": state["lineage"], "serial": state["serial"]},
               "issuer": {"repository": "AldemaroCruz/ClipForge", "workflow": ".github/workflows/int-e2e-apply.yml",
                          "commit": environ["GITHUB_SHA"], "run_id": environ["GITHUB_RUN_ID"]}}
    name = r.PREFIX + environ["GITHUB_SHA"] + "/" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"] + "/foundation-state.json"
    return r.upload(name, r.canonical(receipt))
