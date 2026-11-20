import copy
from datetime import datetime, timedelta
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch

from scripts import int_noble_apply as apply


CONTROLS = "a" * 40
NOW = datetime.fromisoformat("2026-11-20T22:15:00+00:00")
CLOCK = {"created_utc": "2026-11-20T01:05:19.179283+00:00", "expires_utc": apply.PLAN_EXPIRY}
PROFILE = {"not_before_utc": "2026-11-20T22:00:00Z", "expires_utc": "2026-11-21T00:00:00Z"}


def decision(profile=PROFILE):
    return {
        "schema": apply.DECISION_SCHEMA, "decision": apply.DECISION, "owner_approval_ref": "test-only",
        "issued_utc": NOW.isoformat(), "producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN,
        "controls_commit": CONTROLS, "project": apply.c.PROJECT, "plan": copy.deepcopy(apply.PLAN),
        "expires_utc": apply.PLAN_EXPIRY, "write_profile_sha256": apply.noble.digest(profile),
        "write_receipt": {"name": apply.writer.proof_name(CONTROLS), "generation": "1", "size": 32, "sha256": "f" * 64},
        "iac_findings_sha256": apply.IAC_FINDINGS_SHA,
        "iac_decisions": [{"finding_index": index, "decision": "reviewed_for_this_noble_creation", "rationale": "test-only"}
                          for index in apply.NOBLE_IAC_INDICES],
    }


def policy(etag, *, bindings=None):
    return {"version": 3, "etag": etag, "bindings": bindings or []}


def iam_fixture():
    project = apply.PROJECT_POLICY
    zone = apply.IAP_ZONE
    read_proof = {"policies": {project: {"after": policy("read-etag")}}}
    zone_empty = {"etag": "empty-etag"}
    additions = [{"role": "projects/clipforgebeta2/roles/fixture", "members": [apply.iam.MEMBER],
                  "condition": {"title": "temporary", "expression": "request.time < timestamp('2026-11-21T00:00:00Z')"}}]
    before = {project: read_proof["policies"][project]["after"], zone: zone_empty}
    profile = {**PROFILE, "policies": {
        name: {"baseline_policy_sha256": apply.noble.digest(value), "add_bindings": additions}
        for name, value in before.items()
    }}
    receipt = {"schema": apply.writer.RECEIPT_SCHEMA, "producer_commit": apply.PRODUCER, "controls_commit": CONTROLS,
               "profile_sha256": apply.noble.digest(profile), "issued_utc": NOW.isoformat(), "policies": {
                   name: {"before": value, "after": policy("write-etag", bindings=copy.deepcopy(additions))}
                   for name, value in before.items()
               }}
    return profile, read_proof, receipt


def tf_state(addresses, *, serial):
    rows = []
    for address in sorted(addresses):
        resource_type, indexed = address.split(".", 1)
        name, brackets, key = indexed.partition("[")
        instance = {"attributes": {"id": address}}
        if brackets:
            instance["index_key"] = json.loads(key.removesuffix("]"))
        rows.append({"type": resource_type, "name": name, "mode": "managed", "instances": [instance]})
    return {"version": 4, "terraform_version": "1.15.8", "serial": serial, "lineage": apply.PLAN_STATE["lineage"],
            "outputs": {}, "resources": rows}


class NobleApplyTests(unittest.TestCase):
    def test_exact_new_controls_decision_and_each_iac_review(self):
        value = decision()
        apply.verify_decision(value, CLOCK, PROFILE, {"GITHUB_SHA": CONTROLS}, NOW)
        for change in ({"decision": "pending"}, {"producer_commit": CONTROLS}, {"plan": {}},
                       {"controls_commit": apply.PRODUCER}, {"iac_decisions": []}, {"iac_findings_sha256": "0" * 64},
                       {"write_receipt": {**value["write_receipt"], "name": apply.PLAN["manifest"]["name"]}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                apply.verify_decision({**value, **change}, CLOCK, PROFILE, {"GITHUB_SHA": CONTROLS}, NOW)

    def test_expiry_and_insufficient_write_window_block_before_native_apply(self):
        with self.assertRaisesRegex(ValueError, "original_plan_expired"):
            apply.verify_window(CLOCK, PROFILE, apply.utc(apply.PLAN_EXPIRY))
        with self.assertRaisesRegex(ValueError, "write_window_unavailable"):
            apply.verify_window(CLOCK, PROFILE, apply.utc(PROFILE["expires_utc"]) - timedelta(minutes=19), must_fit_apply=True)
        with self.assertRaises(ValueError):
            apply.verify_window({**CLOCK, "expires_utc": "2026-11-22T01:05:19.179283+00:00"}, PROFILE, NOW)

    def test_write_transition_accepts_empty_zone_preserves_read_and_rejects_unrelated_bindings(self):
        profile, read, receipt = iam_fixture()
        apply.verify_write_receipt(receipt, profile, read, {"GITHUB_SHA": CONTROLS}, NOW)
        tainted = copy.deepcopy(receipt)
        tainted["policies"][apply.IAP_ZONE]["after"]["bindings"].append({"role": "roles/owner", "members": ["user:bad@example.test"]})
        with self.assertRaises(ValueError):
            apply.verify_write_receipt(tainted, profile, read, {"GITHUB_SHA": CONTROLS}, NOW)
        read["policies"][apply.PROJECT_POLICY]["after"]["etag"] = "unexpected-read"
        with self.assertRaises(ValueError):
            apply.verify_write_receipt(receipt, profile, read, {"GITHUB_SHA": CONTROLS}, NOW)

    def test_exact_new_generation_and_all_parent_addresses_preserved(self):
        parent = tf_state(apply.noble.EXISTING, serial=7)
        state = tf_state(apply.noble.EXISTING | apply.noble.CREATES, serial=9)
        state["outputs"]["db01_noble_candidate"] = {"sensitive": False, "value": {"name": "fixture"}}
        metadata = {"name": apply.PLAN_STATE["name"], "generation": "9"}
        with patch.object(apply, "verify_candidate") as check:
            proof, _ = apply.state_postcheck(json.dumps(state).encode(), metadata, parent, {"policies": {}}, {}, {})
            self.assertEqual(proof["managed_address_count"], 53)
            self.assertEqual(proof["preserved_address_count"], 42)
            check.assert_called_once()
            previous = next(row for row in state["resources"] if row["type"] == "google_compute_instance" and row["name"] == "postgres")
            previous["instances"][0]["attributes"]["id"] = "changed"
            with self.assertRaisesRegex(ValueError, "existing resource"):
                apply.state_postcheck(json.dumps(state).encode(), metadata, parent, {"policies": {}}, {}, {})

    def test_post_state_allows_only_verified_etag_transition(self):
        parent = tf_state(apply.noble.EXISTING, serial=7)
        state = tf_state(apply.noble.EXISTING | apply.noble.CREATES, serial=8)
        state["outputs"]["db01_noble_candidate"] = {"sensitive": False, "value": {"name": "fixture"}}
        scope = apply.PROJECT_POLICY
        address = "google_project_iam_member.bootstrap_reader"
        for item, etag in ((parent, "serial7"), (state, "approved-write")):
            row = next(record for record in item["resources"] if record["type"] == "google_project_iam_member"
                       and record["name"] == "bootstrap_reader")
            row["instances"][0]["attributes"]["etag"] = etag
        read_profile = {"policies": {scope: {"state_etags": [{"address": address, "sha256": apply.noble.digest("serial7")}]}}}
        read = {"policies": {scope: {"after": {"etag": "approved-read"}}}}
        write = {"policies": {scope: {"after": {"etag": "approved-write"}}}}
        meta = {"name": apply.PLAN_STATE["name"], "generation": "9"}
        with patch.object(apply, "verify_candidate"):
            apply.state_postcheck(json.dumps(state).encode(), meta, parent, read_profile, read, write)
            row["instances"][0]["attributes"]["etag"] = "not-reviewed"
            with self.assertRaisesRegex(ValueError, "IAM attribute"):
                apply.state_postcheck(json.dumps(state).encode(), meta, parent, read_profile, read, write)

    def test_native_failure_invokes_single_locked_apply_and_preserves_private_evidence(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            saved = scratch / "saved-noble.tfplan"
            report = {"native_apply_attempted": False, "native_apply_completed": False}
            error = apply.driver.FailedOperation(apply.NATIVE_OPERATION, "test private error", 1)
            with (patch.object(apply.driver, "run", side_effect=error) as run,
                  patch.object(apply, "persist_native_log", return_value={"name": "test-private-reference"}) as journal):
                with self.assertRaises(apply.driver.FailedOperation):
                    apply.execute_native(scratch, scratch, {}, report, "/local/terraform", saved)
                run.assert_called_once_with(["/local/terraform", "apply", "-input=false", "-no-color", "-lock=true",
                                             "-lock-timeout=120s", str(saved)], apply.NATIVE_OPERATION, scratch)
                journal.assert_called_once_with(scratch, {}, error)
            self.assertEqual(report["diagnostic"], {"operation": apply.NATIVE_OPERATION, "status": 1})
            self.assertTrue(report["native_apply_attempted"])
            self.assertFalse(report["native_apply_completed"])
            pending = json.loads((scratch / "summary.json").read_bytes())
            self.assertIsNone(pending["native_apply_attempted"])
            self.assertEqual(pending["status"], "native_apply_intent_confirmed")

    def test_one_shot_claim_keeps_original_manifest_and_binds_exact_saved_binary(self):
        environment = {"GITHUB_SHA": CONTROLS, "GITHUB_RUN_ID": "9"}
        report = {}
        with patch.object(apply.custody, "upload", side_effect=ValueError("already claimed")) as upload:
            with self.assertRaisesRegex(ValueError, "already claimed"):
                apply.claim_once(environment, {"name": "test-reference"}, report, NOW)
        name, encoded = upload.call_args.args
        self.assertEqual(name, apply.PLAN_PREFIX + "foundation-state.json")
        self.assertNotIn(name, [reference["name"] for reference in apply.PLAN.values()])
        self.assertEqual(json.loads(encoded)["binary"], apply.PLAN["binary"])
        self.assertEqual(report, {"operation": "claim_exact_saved_plan"})

    def test_new_iap_binding_is_checked_in_numeric_instance_policy(self):
        deploy = [apply.historical.DEPLOY_MEMBER]
        data = (
            {"etag": "vm-policy", "version": 1, "bindings": [{"role": "roles/compute.osAdminLogin", "members": deploy}]},
            {"etag": "sa-policy", "version": 1, "bindings": [{"role": "roles/iam.serviceAccountUser", "members": deploy}]},
            {"etag": "iap-policy", "version": 3, "bindings": [{"role": "roles/iap.tunnelResourceAccessor", "members": deploy,
                          "condition": {"title": "db01_noble_ssh_only", "expression": "destination.port == 22"}}]},
        )
        with patch.object(apply.iam, "request_json", side_effect=data) as read:
            apply.verify_new_bindings("projects/clipforgebeta2/serviceAccounts/current-noble@example.test", "1234", "fixture")
            self.assertIn("/iap_tunnel/zones/us-central1-a/instances/1234:getIamPolicy", read.call_args.args[0])
        with self.assertRaises(ValueError):
            apply.verify_new_bindings("not-used", "named-instance", "fixture")

    def test_new_binding_postcheck_uses_service_specific_http_contracts(self):
        sa = "projects/clipforgebeta2/serviceAccounts/clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
        deploy = [apply.historical.DEPLOY_MEMBER]
        responses = (
            policy("vm-policy", bindings=[{"role": "roles/compute.osAdminLogin", "members": deploy}]),
            policy("sa-policy", bindings=[{"role": "roles/iam.serviceAccountUser", "members": deploy}]),
            policy("iap-policy", bindings=[{
                "role": "roles/iap.tunnelResourceAccessor",
                "members": deploy,
                "condition": {"title": "db01_noble_ssh_only", "expression": "destination.port == 22"},
            }]),
        )
        with patch.object(apply.iam, "request_json", side_effect=responses) as read:
            apply.verify_new_bindings(sa, "1234", "fixture")

        self.assertEqual(list(read.call_args_list), [
            call("https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
                 "instances/clipforge-int-db01-noble/getIamPolicy?optionsRequestedPolicyVersion=3",
                 "fixture", "GET", None),
            call(f"https://iam.googleapis.com/v1/{sa}:getIamPolicy?options.requestedPolicyVersion=3",
                 "fixture", "POST", None),
            call("https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/"
                 "instances/1234:getIamPolicy",
                 "fixture", "POST", {"options": {"requestedPolicyVersion": 3}}),
        ])
