"""Close the exact attempted INT Noble creation by reading its evidence and live resources."""

import argparse
import base64
import io
import json
import os
import re
import sys
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener
from zipfile import ZipFile

from scripts import int_noble_apply as apply


c, custody, driver = apply.c, apply.custody, apply.driver
iam, foundation, noble = apply.iam, apply.foundation, apply.noble
ORIGINAL_RUN = "44761685941"
ORIGINAL_CONTROLS = "d9f071a921f7c226fd6662000a6b2269367495d0"
CORRECTED_CONTROLS = "3e97f8cd4616611d5dec9d2b5b6ef19ecc4750d9"
WORKFLOW = ".github/workflows/int-db01-noble-postverify.yml"
SCHEMA = "clipforge-db01-noble-postverification-receipt-1"
STATUS = "creation_postverified"
ORIGINAL_ARTIFACT = {
    "id": "14640259001",
    "sha256": "46a2983762e1f78d596ddc286e03f7733294c9397071bbb910ef502559ed46ac",
    "summary_sha256": "a29b40021fffb8e17a71825ed082c648edefb3db8f5bb50851170c34fffaf3cb",
}
ORIGINAL_INTENT = {
    "name": apply.PLAN_PREFIX + "foundation-state.json",
    "generation": "1795187905740174",
    "sha256": "5865944e844ee223fbbcdaf1dd57c1109b01d5e68294bb34d62e0097384fdf1c",
    "size": 960,
}
ORIGINAL_LOG = {
    "name": f"{custody.PREFIX}{ORIGINAL_CONTROLS}/{ORIGINAL_RUN}-1/int.json",
    "generation": "1795187957435648",
    "sha256": "e54e666adc095d419ac95eb7aa3ebc443fa952760ffdb89bd29b57e03f40f05e",
    "size": 6420,
}
EXPECTED_STATE = {
    "name": apply.PLAN_STATE["name"],
    "generation": "1795187957111147",
    "size": 182865,
    "sha256": "2cc1b5410d0f0f9eaf58a27ef3c61517a476582b8bede20c6f61010711bdc67d",
    "lineage": apply.PLAN_STATE["lineage"],
    "serial": 9,
    "managed_address_count": 53,
    "preserved_address_count": 42,
    "current_lock_absent": True,
}
EXPECTED_INSTANCE = "7365414160255801909"
EXPECTED_BOOT_DISK = "8897353356069952044"
EXPECTED_DATA_DISK = "7382984635240536620"
DEBIAN_CONFIGURATION_SHA256 = "67180b3e4d3233e768625b70ec86d5526ad8d05298b4b0664058602d521b3d26"
NATIVE_COUNTS = {"create": 11, "update": 0, "delete": 0}
CORRECTED_SOURCE_SHA256 = {
    "scripts/int_noble_apply.py": "061205bce55858d246d85c5d5c981af335a2b8e0ab53ad56ccf872f4570adbd8",
    "scripts/int_noble_guest_observation.py": "31f734b47e1c5f48c3aa56f309c396acf216e7061cb773a215808e825d01c196",
}
CANONICAL_APPLY_DIAGNOSTIC = {"operation": "verify_noble_post_apply", "error_type": "KeyError", "http_status": None}
GITHUB_ACTIONS = f"https://api.github.com/repos/{apply.REPOSITORY}/actions/"


def read_github(token, endpoint):
    opener = build_opener(ProxyHandler({}), driver.NoRedirect())
    with opener.open(github_request(token, endpoint), timeout=30) as response:
        raw = response.read(apply.ARTIFACT_LIMIT + 1)
    c.require(len(raw) <= apply.ARTIFACT_LIMIT, "GitHub evidence exceeded its bound")
    return foundation.decode(raw)


def github_request(token, endpoint):
    return Request(GITHUB_ACTIONS + endpoint, headers={"Authorization": "Bearer " + token,
                   "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})


def verify_github_run(run, controls, token, workflow, conclusion):
    apply.producer_prefix(controls, run)
    actual = read_github(token, f"runs/{run}/attempts/1")
    expected = {"id": int(run), "run_attempt": 1, "head_sha": controls, "head_branch": apply.WORKFLOW_BRANCH,
                "event": "workflow_dispatch", "path": workflow, "status": "completed", "conclusion": conclusion}
    c.require(all(actual.get(key) == value for key, value in expected.items())
              and actual.get("repository", {}).get("full_name") == apply.REPOSITORY, "Wrong GitHub run provenance")


def verify_original_run(token):
    verify_github_run(ORIGINAL_RUN, ORIGINAL_CONTROLS, token, apply.WORKFLOW, "failure")
    result = read_github(token, f"runs/{ORIGINAL_RUN}/attempts/1/jobs")
    c.require(result.get("total_count") == 1 and len(result["jobs"]) == 1, "Ambiguous original apply job")
    job = result["jobs"][0]
    c.require(job["name"] == "create-noble" and job["status"] == "completed" and job["conclusion"] == "failure",
              "Wrong original apply job")
    steps = {row["name"]: row for row in job["steps"]}
    operation = "Verify authorization, apply saved Noble binary once, and reconcile by read"
    required_steps = {operation: "failure", "Authenticate existing Terraform identity through protected WIF": "success",
                      "Retain only the sanitized creation or reconciliation summary": "success"}
    c.require(len(steps) == len(job["steps"])
              and all(steps.get(name, {}).get("conclusion") == conclusion for name, conclusion in required_steps.items()),
              "The reviewed native apply and postcheck step was not recorded")
    started = apply.utc(steps[operation]["started_at"])
    completed = apply.utc(steps[operation]["completed_at"])
    c.require(started < completed, "Original apply step timestamps are invalid")
    return started, completed


def verify_postverify_run(run, controls, token):
    c.require(run not in {ORIGINAL_RUN, apply.PLAN_RUN} and controls != ORIGINAL_CONTROLS,
              "Postverification must have independent run and controls")
    verify_github_run(run, controls, token, WORKFLOW, "success")


def load_original_summary(token):
    artifact = ORIGINAL_ARTIFACT
    endpoint = f"artifacts/{artifact['id']}"
    info = read_github(token, endpoint)
    expected_name = f"db01-noble-apply-summary-{ORIGINAL_CONTROLS}-{ORIGINAL_RUN}-1"
    c.require(info["id"] == int(artifact["id"]) and info["expired"] is False and info["name"] == expected_name
              and info["digest"] == "sha256:" + artifact["sha256"]
              and info["workflow_run"]["head_sha"] == ORIGINAL_CONTROLS
              and info["workflow_run"]["id"] == int(ORIGINAL_RUN), "Wrong original apply artifact provenance")
    opener = build_opener(ProxyHandler({}), apply.ArtifactRedirect())
    try:
        stream = opener.open(github_request(token, endpoint + "/zip"), timeout=30)
    except HTTPError as error:
        location = error.headers.get("Location", "")
        error.close()
        target = urlsplit(location)
        c.require(error.code == 302 and target.scheme == "https" and not target.username and not target.password
                  and not target.fragment and target.port in (None, 443) and target.hostname
                  and target.hostname.endswith((".blob.core.windows.net", ".actions.githubusercontent.com")),
                  "Unexpected original artifact redirect")
        stream = build_opener(ProxyHandler({}), driver.NoRedirect()).open(Request(location), timeout=30)
    with stream:
        raw = stream.read(apply.ARTIFACT_LIMIT + 1)
    c.require(len(raw) <= apply.ARTIFACT_LIMIT and custody.sha256(raw) == artifact["sha256"],
              "Original artifact bytes differ")
    with ZipFile(io.BytesIO(raw)) as archive:
        c.require(archive.namelist() == ["summary.json"] and archive.getinfo("summary.json").file_size <= apply.ARTIFACT_LIMIT,
                  "Original artifact must contain only the bounded apply summary")
        original = archive.read("summary.json")
    c.require(custody.sha256(original) == artifact["summary_sha256"], "Original apply summary bytes differ")
    report = foundation.decode(original)
    verify_original_summary(report)
    return report


def verify_original_summary(report):
    expected = {
        "schema": apply.CREATION_SCHEMA, "status": "postcheck_unconfirmed", "operation": "verify_noble_post_apply",
        "controls_commit": ORIGINAL_CONTROLS, "apply_run_id": ORIGINAL_RUN,
        "producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN, "plan_expires_utc": apply.PLAN_EXPIRY,
        "intent": ORIGINAL_INTENT, "native_log": ORIGINAL_LOG, "diagnostic": CANONICAL_APPLY_DIAGNOSTIC,
    }
    iam.check_fields(report, {*expected, "native_apply_attempted", "native_apply_completed",
                             "bootstrap_authorized", "application_authorized", "approval", "reconciliation"})
    c.require(all(report[name] == value for name, value in expected.items())
              and report["native_apply_attempted"] is True and report["native_apply_completed"] is True
              and report["bootstrap_authorized"] is False and report["application_authorized"] is False,
              "The failed run is not the reviewed completed native apply")
    approval = report["approval"]
    iam.check_fields(approval, {"decision", "write_receipt", "write_profile_sha256", "plan_manifest",
                               "iac_findings_sha256", "observation"})
    apply.verify_reference(approval["decision"], suffix="manifest.json", commit=ORIGINAL_CONTROLS)
    apply.verify_reference(approval["write_receipt"])
    c.require(approval["decision"]["name"] == apply.decision_name(ORIGINAL_CONTROLS, apply.PLAN_RUN)
              and approval["plan_manifest"] == apply.PLAN["manifest"] and approval["observation"] is True,
              "Original apply lacks the exact observation approval")
    initial = report["reconciliation"]
    iam.check_fields(initial, {"state", "resources"})
    expected_state = {key: value for key, value in EXPECTED_STATE.items()
                      if key not in {"name", "size", "preserved_address_count"}}
    c.require(initial["state"] == {**expected_state, "observed_candidate_addresses": sorted(noble.CREATES)}
              and initial["resources"]["vm"] == {"status": "observed", "id": EXPECTED_INSTANCE},
              "Original failed-run reconciliation does not describe the pinned Noble instance and state")


def verify_original_intent(intent, approval):
    expected = {"schema": "clipforge-db01-noble-apply-intent-2",
                "producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN,
                "controls_commit": ORIGINAL_CONTROLS, "apply_run_id": ORIGINAL_RUN, "decision": approval["decision"],
                "manifest": apply.PLAN["manifest"], "binary": apply.PLAN["binary"]}
    iam.check_fields(intent, {*expected, "intent_utc"})
    c.require(all(intent[key] == value for key, value in expected.items()), "Original one-shot intent differs")
    return apply.utc(intent["intent_utc"])


def verify_native_log(log):
    iam.check_fields(log, {"schema", "encoding", "size", "sha256", "output"})
    c.require(log["schema"] == "clipforge-db01-noble-apply-native-log-1" and log["encoding"] == "base64",
              "Unknown original native log format")
    output = base64.b64decode(log["output"], validate=True)
    c.require(0 < len(output) == log["size"] <= apply.diagnostic.MAX_NATIVE_BYTES
              and custody.sha256(output) == log["sha256"], "Original native log was altered or truncated")
    matches = re.findall(rb"(?m)^Apply complete! Resources: ([0-9]+) added, ([0-9]+) changed, ([0-9]+) destroyed\.\r?$", output)
    c.require(matches == [(b"11", b"0", b"0")], "Original native outcome is not the reviewed 11/0/0")


def verify_execution_window(manifest, started, attempted, completed):
    c.require(started <= attempted < completed, "Original intent is outside its recorded apply step")
    # The completed GitHub step is a conservative upper bound for the native write.
    apply.verify_plan_ttl(manifest, attempted)
    apply.verify_plan_ttl(manifest, completed)


def verify_live_intent():
    prefix = ORIGINAL_INTENT["name"]
    listing = driver.metadata("/b/" + c.BUCKET + "/o", {
        "prefix": prefix, "maxResults": "2", "fields": "nextPageToken,items(name,generation,size)",
    })
    expected = {"name": prefix, "generation": ORIGINAL_INTENT["generation"], "size": str(ORIGINAL_INTENT["size"])}
    c.require(not listing.get("nextPageToken") and listing.get("items") == [expected],
              "Current one-shot marker was removed, superseded, or is ambiguous")


def verify_corrected_sources():
    c.require(all(custody.sha256((apply.ROOT / path).read_bytes()) == checksum
                  for path, checksum in CORRECTED_SOURCE_SHA256.items()), "Reviewed postcheck corrections differ")


def verify_context(env):
    custody.hosted_context(env)
    c.validate_variables(env)
    commit, run = env["GITHUB_SHA"], env["GITHUB_RUN_ID"]
    apply.producer_prefix(commit, run)
    c.require(commit == env.get("DB01_NOBLE_POSTVERIFY_COMMIT") and commit != ORIGINAL_CONTROLS
              and run not in {ORIGINAL_RUN, apply.PLAN_RUN} and env.get("GITHUB_RUN_ATTEMPT") == "1"
              and env.get("GITHUB_WORKFLOW_REF") == f"{apply.REPOSITORY}/{WORKFLOW}@refs/heads/{apply.WORKFLOW_BRANCH}",
              "Only the exact reviewed first INT postverification dispatch is allowed")
    apply.historical.verify_wif(env)
    verify_corrected_sources()


def verify_envelope(report, controls, run):
    iam.check_fields(report, {"schema", "status", "verifier", "original_apply", "plan", "creation", "receipt"})
    evidence = {key: value for key, value in report.items() if key != "receipt"}
    verify_evidence(evidence, controls, run)
    ref = apply.verify_reference(report["receipt"])
    raw = custody.canonical(evidence)
    c.require(ref["name"] == apply.producer_prefix(controls, run) + "foundation-state.json"
              and ref["size"] == len(raw) and ref["sha256"] == custody.sha256(raw), "Postverification receipt was altered")


def verify_evidence(report, controls, run):
    iam.check_fields(report, {"schema", "status", "verifier", "original_apply", "plan", "creation"})
    c.require(report["schema"] == SCHEMA and report["status"] == STATUS
              and report["verifier"] == {"controls_commit": controls, "run_id": run, "attempt": "1", "workflow": WORKFLOW}
              and controls != ORIGINAL_CONTROLS and run not in {ORIGINAL_RUN, apply.PLAN_RUN},
              "Wrong postverification receipt provenance")
    original = report["original_apply"]
    fixed = original_apply_binding()
    iam.check_fields(original, {*fixed, "intent_at_utc", "operation_completed_at_utc"})
    c.require(all(original[key] == value for key, value in fixed.items())
              and apply.utc(original["intent_at_utc"]) < apply.utc(original["operation_completed_at_utc"])
              < apply.utc(apply.PLAN_EXPIRY), "Original completed native execution differs")
    c.require(report["plan"] == {"producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN, **apply.PLAN},
              "Postverification is not bound to the original saved plan")
    creation = report["creation"]
    iam.check_fields(creation, {"state", "candidate", "control_plane", "debian_preserved", "bootstrap_authorized",
                               "application_authorized", "guest_access_performed", "checks"})
    expected_ids = {"instance_id": EXPECTED_INSTANCE, "boot_disk_id": EXPECTED_BOOT_DISK, "data_disk_id": EXPECTED_DATA_DISK}
    c.require(creation["state"] == EXPECTED_STATE
              and all(creation[section][key] == value for section in ("candidate", "control_plane")
                      for key, value in expected_ids.items()) and creation["debian_preserved"] is True
              and all(creation[key] is False for key in ("bootstrap_authorized", "application_authorized", "guest_access_performed"))
              and creation["checks"] == observed_checks(), "Incomplete or unexpected postverification")


def original_apply_binding():
    return {"controls_commit": ORIGINAL_CONTROLS, "run_id": ORIGINAL_RUN, "attempt": "1", "conclusion": "failure",
            "artifact": ORIGINAL_ARTIFACT, "intent": ORIGINAL_INTENT, "native_log": ORIGINAL_LOG, "native_counts": NATIVE_COUNTS}


def observed_checks():
    return {
        "corrected_controls_commit": CORRECTED_CONTROLS,
        "state_v4_output_fields": ["type", "value"],
        "compute_project_id": apply.guest.COMPUTE_PROJECT_ID,
        "resource_manager_project_number": apply.guest.host.PROJECT_NUMBER,
        "debian_configuration_sha256": DEBIAN_CONFIGURATION_SHA256,
        "original_marker_preserved": True,
        "stable_iam_verified": True,
        "noble_bindings_verified": True,
    }


def verify_only(env, progress):
    verify_context(env)
    controls, run = env["GITHUB_SHA"], env["GITHUB_RUN_ID"]
    progress["operation"] = "original_apply_provenance"
    started, completed = verify_original_run(env["GH_TOKEN"])
    original = load_original_summary(env["GH_TOKEN"])
    approval = original["approval"]
    verify_live_intent()
    attempted = verify_original_intent(foundation.decode(custody.fetch_verified(ORIGINAL_INTENT)), approval)
    verify_native_log(foundation.decode(custody.fetch_verified(ORIGINAL_LOG)))

    progress["operation"] = "saved_plan_and_historical_authorization"
    selection = apply.plan_selection(apply.PRODUCER, apply.PLAN_RUN, apply.PLAN["manifest"],
                                     {"id": apply.PLAN_ARTIFACT, "sha256": apply.PLAN_ARTIFACT_SHA})
    manifest = foundation.decode(custody.fetch_verified(apply.PLAN["manifest"]))
    plan = apply.verify_manifest(manifest, selection)
    verify_execution_window(manifest, started, attempted, completed)
    findings = apply.verify_artifact_summary(apply.verify_producer_run(env, selection), manifest, plan)
    decision = foundation.decode(custody.fetch_verified(approval["decision"]))
    write_profile, write_proof, read_profile, read_proof, historical_etags, iam_receipt = apply.writer.load_stable_evidence(
        approval["write_receipt"])
    apply.verify_decision(decision, manifest, plan, selection["artifact"], write_profile, findings, ORIGINAL_CONTROLS, attempted)
    c.require(all(decision[key] == approval[key] for key in ("write_receipt", "write_profile_sha256", "iac_findings_sha256"))
              and {**iam_receipt, "etag_only_addresses": sorted(address for address, (saved, live) in historical_etags.items()
                                                               if saved != live)} == manifest["iam_refresh"],
              "Original apply summary, authorization and IAM proof differ")
    custody.fetch_verified(plan["binary"])
    native = foundation.decode(custody.fetch_verified(plan["json"]))
    apply.exact_plan_actions(native, manifest, historical_etags)

    progress["operation"] = "state_lineage_and_preserved_resources"
    origin = manifest["backend"]
    archived = apply.states.read_state_generation(origin["generation"], origin["size"])
    parent = foundation.verified(archived, origin)
    raw, obj, _ = apply.current_state()
    c.require(set(foundation.decode(raw)["outputs"]["db01_noble_candidate"]) == {"type", "value"},
              "Exact reconciled Terraform state v4 output representation differs")
    image = manifest["inputs"]["db01_noble_candidate"]
    state, candidate = apply.state_postcheck(raw, obj, parent, read_profile, read_proof, write_proof, image, origin=origin)
    c.require(state == EXPECTED_STATE and candidate["instance_id"] == EXPECTED_INSTANCE, "Unexpected reconciled state or VM")
    planned = native["output_changes"]["db01_noble_candidate"]["after"]
    resources = {row["address"]: row["change"]["after"] for row in native["resource_changes"] if row["mode"] == "managed"}
    c.require(all(candidate[key] == planned[key] for key in (*apply.OUTPUT_HASH_KEYS, "image_id", "image_name"))
              and custody.sha256(resources["google_compute_instance.noble[0]"]["metadata_startup_script"].encode("utf-8"))
              == planned["startup_sha256"], "Observed Noble image, startup or nonce differs from the original plan")

    progress["operation"] = "live_noble_debian_and_iam"
    token = env["GCP_ACCESS_TOKEN"]
    noble.verify_live_stable_iam(write_profile, write_proof, read_profile, read_proof, token)
    project_name = "projects/" + apply.guest.host.PROJECT_NUMBER
    project = iam.request_json("https://cloudresourcemanager.googleapis.com/v3/" + project_name, token)
    c.require(project["name"] == project_name and project["projectId"] == c.PROJECT,
              "Resource Manager project number differs")
    debian = apply.historical.vm_proof(resources["google_compute_instance.postgres"], resources["google_compute_disk.postgres"])
    c.require(debian["configuration_sha256"] == DEBIAN_CONFIGURATION_SHA256
              and debian["startup_unchanged"] is True and debian["two_retained_disks"] is True,
              "Debian configuration or retained disks differ from the reconciled baseline")
    candidate, control_plane = apply.observed_resources(candidate, token)
    c.require(attempted <= apply.guest.timestamp(candidate["creation_timestamp"]) <= completed,
              "Noble creation time is outside the original execution")
    c.require(apply.partial_observation(token) == original["reconciliation"],
              "Observed resources differ from the preserved original reconciliation")
    final_raw, final_obj, _ = apply.current_state()
    c.require(final_obj["generation"] == state["generation"] and custody.sha256(final_raw) == state["sha256"],
              "State changed during postverification")
    verify_live_intent()

    return {
        "schema": SCHEMA, "status": STATUS,
        "verifier": {"controls_commit": controls, "run_id": run, "attempt": "1", "workflow": WORKFLOW},
        "original_apply": {**original_apply_binding(), "intent_at_utc": attempted.isoformat(),
                           "operation_completed_at_utc": completed.isoformat()},
        "plan": {"producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN, **plan},
        "creation": {"state": state, "candidate": candidate, "control_plane": control_plane, "debian_preserved": True,
                     "bootstrap_authorized": False, "application_authorized": False, "guest_access_performed": False,
                     "checks": observed_checks()},
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("check", "verify"))
    args = parser.parse_args(argv)
    if args.operation == "check":
        verify_corrected_sources()
        return 0
    os.umask(0o077)
    work, reports = driver.private_paths()
    progress = {"operation": "protected_context"}
    try:
        report = verify_only(os.environ, progress)
        controls, run = report["verifier"]["controls_commit"], report["verifier"]["run_id"]
        progress["operation"] = "seal_separate_postverification_receipt"
        verify_evidence(report, controls, run)
        raw = custody.canonical(report)
        name = apply.producer_prefix(controls, run) + "foundation-state.json"
        ref = custody.upload(name, raw)
        c.require(custody.fetch_verified(ref) == raw, "Postverification receipt differs after create-only upload")
        report["receipt"] = ref
        verify_envelope(report, controls, run)
    except Exception as error:
        report = {"schema": SCHEMA, "status": "postverification_blocked",
                  "diagnostic": apply.error_receipt(error, progress["operation"], work)}
        apply.save_summary(reports, report)
        print(json.dumps(report), file=sys.stderr)
        return 1
    apply.save_summary(reports, report)
    print(json.dumps({"status": STATUS, "instance_id": EXPECTED_INSTANCE, "serial": EXPECTED_STATE["serial"]}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
