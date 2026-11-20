import copy
from datetime import datetime, timedelta
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import call, patch
from urllib.error import HTTPError
from zipfile import ZipFile

from scripts import int_noble_apply as apply


CONTROLS = "a" * 40
NOW = datetime.fromisoformat("2026-11-20T02:32:40+00:00")
CLOCK = {"created_utc": "2026-11-20T01:05:19.179283+00:00", "expires_utc": apply.PLAN_EXPIRY}
PROFILE = {"schema": "stable-fixture"}
ARTIFACT = {"id": apply.PLAN_ARTIFACT, "sha256": apply.PLAN_ARTIFACT_SHA}
FINDINGS = [
    {"id": rule, "severity": level, "resource": address}
    for rule, level, address in (
        ("GCP-0033", "LOW", "google_compute_instance.postgres"),
        ("GCP-0033", "LOW", "google_compute_instance.postgres"),
        ("GCP-0034", "LOW", "google_compute_disk.postgres"),
        ("GCP-0066", "LOW", 'google_storage_bucket.private["backups"]'),
        ("GCP-0066", "LOW", 'google_storage_bucket.private["media"]'),
        ("GCP-0077", "MEDIUM", 'google_storage_bucket.private["backups"]'),
        ("GCP-0077", "MEDIUM", 'google_storage_bucket.private["media"]'),
        ("GCP-0033", "LOW", "google_compute_instance.noble[0]"),
        ("GCP-0033", "LOW", "google_compute_instance.noble[0]"),
        ("GCP-0034", "LOW", "google_compute_disk.noble_boot[0]"),
        ("GCP-0034", "LOW", "google_compute_disk.noble_data[0]"),
    )
]
IMAGE = {
    "name": apply.IMAGE_NAME, "id": apply.IMAGE_ID, "status": "READY", "architecture": "X86_64",
    "family": apply.noble.FAMILY, "selfLink": f"{apply.noble.API}{apply.noble.IMAGE_ROOT}/images/{apply.IMAGE_NAME}",
    "creationTimestamp": "2026-11-05T08:00:00.000-08:00", "diskSizeGb": "10",
    "licenses": [apply.noble.API + apply.noble.IMAGE_ROOT + "/licenses/ubuntu-2404-lts"],
}
STABLE_REF = {"name": f"{apply.custody.PREFIX}{'b' * 40}/{apply.PLAN_RUN}-1/foundation-state.json",
              "generation": "1", "size": 32, "sha256": "f" * 64}


def decision():
    return {
        "schema": apply.DECISION_SCHEMA, "decision": apply.DECISION, "owner_approval_ref": "test-only",
        "issued_utc": NOW.isoformat(), "producer_commit": apply.PRODUCER, "producer_run": apply.PLAN_RUN,
        "controls_commit": CONTROLS, "project": apply.c.PROJECT, "plan": copy.deepcopy(apply.PLAN),
        "expires_utc": apply.PLAN_EXPIRY, "write_profile_sha256": apply.noble.digest(PROFILE),
        "write_receipt": STABLE_REF, "plan_artifact": ARTIFACT,
        "iac_findings_sha256": apply.IAC_FINDINGS_SHA,
        "iac_decisions": [{"finding_index": index, "decision": "reviewed_for_this_noble_creation", "rationale": "test-only"}
                          for index in (8, 9, 10, 11)],
    }


def policy(etag, *, bindings=None):
    return {"version": 3, "etag": etag, "bindings": bindings or []}


def plan_fixture(commit=apply.PRODUCER, run=apply.PLAN_RUN, artifact=ARTIFACT):
    plan = copy.deepcopy(apply.PLAN)
    if run != apply.PLAN_RUN:
        prefix = apply.producer_prefix(commit, run)
        for kind, file in apply.noble.PRIVATE_FILES.items():
            plan[kind]["name"] = prefix + file
    selection = apply.plan_selection(commit, run, plan["manifest"], artifact)
    actions = {"counts": {"create": 11, "no-op": 42}, "preserved_addresses": sorted(apply.noble.EXISTING),
               "candidate_addresses": sorted(apply.noble.CREATES), "deviations": {}, "refresh_drift": {}}
    iam = {"receipt": apply.READ_RECEIPT, "policies_checked": 6, "etag_only_addresses": [],
           "profile_sha256": "b" * 64, "owner_approval_sha256": "b" * 64}
    manifest = {
        "schema": apply.noble.SCHEMA, "commit": commit, "run_id": run, "run_attempt": "1", **CLOCK,
        "terraform_version": "1.15.8", "provider_version": "8.11.0",
        "inputs": {"stage": "foundation", "machine_type": "e2-micro", "db01_noble_candidate": IMAGE},
        "source_sha256": {path.as_posix(): "b" * 64 for path in apply.SOURCE_PATHS}, "backend": apply.PLAN_STATE,
        "actions": actions, "iam_refresh": iam, "apply_authorized": False, "binary": plan["binary"], "json": plan["json"],
    }
    if run != apply.PLAN_RUN:
        manifest["stable_write_receipt"] = STABLE_REF
    return manifest, plan, selection


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
        manifest, plan, _ = plan_fixture()
        value = decision()
        apply.verify_decision(value, manifest, plan, ARTIFACT, PROFILE, FINDINGS, CONTROLS, NOW)
        for change in ({"decision": "pending"}, {"producer_commit": CONTROLS}, {"plan": {}},
                       {"controls_commit": apply.PRODUCER}, {"iac_decisions": []}, {"iac_findings_sha256": "0" * 64},
                       {"plan_artifact": {"id": "13", "sha256": "0" * 64}}, {"expires_utc": CLOCK["created_utc"]}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                apply.verify_decision({**value, **change}, manifest, plan, ARTIFACT, PROFILE, FINDINGS, CONTROLS, NOW)

    def test_authorized_plan_admitted_around_clock_until_actual_expiry(self):
        manifest, plan, _ = plan_fixture()
        expiry = apply.utc(apply.PLAN_EXPIRY)
        for now in (NOW, NOW + timedelta(hours=12), expiry - timedelta(seconds=1)):
            with self.subTest(now=now):
                apply.verify_decision(decision(), manifest, plan, ARTIFACT, PROFILE, FINDINGS, CONTROLS, now)
        with self.assertRaisesRegex(ValueError, "noble_apply_plan_expired"):
            apply.verify_plan_ttl(manifest, expiry)
        with self.assertRaisesRegex(ValueError, "not_yet_created"):
            apply.verify_plan_ttl(manifest, apply.utc(CLOCK["created_utc"]) - timedelta(seconds=1))
        with self.assertRaisesRegex(ValueError, "lifetime was changed"):
            apply.verify_plan_ttl({**CLOCK, "expires_utc": "2026-11-22T01:05:19.179283+00:00"}, NOW)

    def test_historical_manifest_and_artifact_references_remain_immutable(self):
        manifest, plan, selection = plan_fixture()
        self.assertEqual(apply.verify_manifest(manifest, selection), plan)
        with self.assertRaisesRegex(ValueError, "Historical plan and artifact"):
            apply.plan_selection(apply.PRODUCER, apply.PLAN_RUN, plan["manifest"], {**ARTIFACT, "id": "5"})
        for changed in ({"expires_utc": "2026-11-22T01:05:19.179283+00:00"},
                        {"binary": {**plan["binary"], "generation": "9"}},
                        {"backend": {**apply.PLAN_STATE, "generation": "9"}}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                apply.verify_manifest({**manifest, **changed}, selection)

    def test_apply_requires_current_selected_origin_not_simply_the_same_lineage(self):
        original = apply.PLAN_STATE
        newer = {**original, "serial": original["serial"] + 1, "generation": str(int(original["generation"]) + 1)}
        newer_raw = json.dumps({"serial": newer["serial"]}).encode()
        with patch.object(apply.noble, "current_origin", return_value=(newer, newer_raw)) as live:
            self.assertEqual(apply.origin_state(newer), {"serial": newer["serial"]})
            live.assert_called_once_with(allow_successor=True)
            with self.assertRaisesRegex(ValueError, "no longer current"):
                apply.origin_state(original)

    def test_renewed_plan_can_use_same_controls_commit_and_pins_write_receipt(self):
        manifest, plan, selection = plan_fixture(CONTROLS, "1234")
        self.assertEqual(apply.verify_manifest(manifest, selection), plan)
        self.assertNotEqual(apply.decision_name(CONTROLS, "1234"), plan["manifest"]["name"])
        value = {**decision(), "producer_commit": CONTROLS, "producer_run": "1234", "plan": plan}
        apply.verify_decision(value, manifest, plan, ARTIFACT, PROFILE, FINDINGS, CONTROLS, NOW)
        with self.assertRaisesRegex(ValueError, "Stable WRITE receipt differs"):
            apply.verify_decision({**value, "write_receipt": {**STABLE_REF, "generation": "2"}},
                                  manifest, plan, ARTIFACT, PROFILE, FINDINGS, CONTROLS, NOW)
        with self.assertRaises(ValueError):
            apply.verify_manifest({**manifest, "json": {**plan["json"], "name": apply.PLAN["json"]["name"]}}, selection)

    def test_new_candidate_findings_need_individual_review_and_old_scope_is_preserved(self):
        manifest, plan, _ = plan_fixture(CONTROLS, "1234")
        value = {**decision(), "producer_commit": CONTROLS, "producer_run": "1234", "plan": plan}
        extra = {"id": "GCP-OTHER", "severity": "LOW", "resource": "google_compute_instance.noble[0]"}
        findings = [*FINDINGS, extra]
        with self.assertRaisesRegex(ValueError, "Individual Noble IaC decisions"):
            apply.verify_decision({**value, "iac_findings_sha256": apply.noble.digest(findings)},
                                  manifest, plan, ARTIFACT, PROFILE, findings, CONTROLS, NOW)
        for changed in ({**extra, "severity": "HIGH"}, {**extra, "resource": "google_compute_instance.postgres"}):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                apply.reviewed_findings([*FINDINGS, changed], historical_plan=False)

    def test_producer_artifact_digest_and_run_provenance(self):
        archive = io.BytesIO()
        with ZipFile(archive, "w") as zipped:
            for name in apply.ARTIFACT_FILES:
                zipped.writestr(name, '{"summary":"fixture"}')
        raw = archive.getvalue()
        receipt = {"id": "456", "sha256": apply.custody.sha256(raw)}
        _, _, selection = plan_fixture(CONTROLS, "1234", receipt)
        run = {"id": 1234, "run_attempt": 1, "head_sha": CONTROLS, "head_branch": apply.WORKFLOW_BRANCH,
               "event": "workflow_dispatch", "path": apply.PRODUCER_WORKFLOW, "status": "completed",
               "conclusion": "success", "repository": {"full_name": apply.REPOSITORY}}
        artifact = {"id": 456, "expired": False, "name": f"db01-noble-plan-summary-{CONTROLS}-1234-1",
                    "digest": "sha256:" + receipt["sha256"], "workflow_run": {"head_sha": CONTROLS, "id": 1234}}
        with patch.object(apply, "build_opener") as opener:
            read = opener.return_value.open
            read.side_effect = [io.BytesIO(json.dumps(run).encode()), io.BytesIO(json.dumps(artifact).encode()), io.BytesIO(raw)]
            summary = apply.verify_producer_run({"GH_TOKEN": "fixture"}, selection)
            self.assertEqual(summary, {"summary": "fixture"})
            read.side_effect = [io.BytesIO(json.dumps(run).encode()), io.BytesIO(json.dumps(artifact).encode()), io.BytesIO(raw + b"!")]
            with self.assertRaisesRegex(ValueError, "artifact bytes differ"):
                apply.verify_producer_run({"GH_TOKEN": "fixture"}, selection)
            for location, accepted in (("https://archive.blob.core.windows.net/files/archive", True),
                                       ("https://archive.blob.core.windows.net.example.test/files/archive", False)):
                read.reset_mock()
                redirect = HTTPError("https://api.github.com/artifacts/fixture", 302, "Redirect", {"Location": location}, None)
                read.side_effect = [io.BytesIO(json.dumps(run).encode()), io.BytesIO(json.dumps(artifact).encode()), redirect, io.BytesIO(raw)]
                if accepted:
                    apply.verify_producer_run({"GH_TOKEN": "fixture"}, selection)
                    self.assertEqual(read.call_count, 4)
                    destination = read.call_args.args[0]
                    self.assertEqual(destination.full_url, location)
                    self.assertIsNone(destination.get_header("Authorization"))
                else:
                    with self.assertRaisesRegex(ValueError, "Unexpected producer artifact storage redirect"):
                        apply.verify_producer_run({"GH_TOKEN": "fixture"}, selection)
                    self.assertEqual(read.call_count, 3)
            self.assertIsInstance(opener.call_args.args[-1], apply.ArtifactRedirect)
            self.assertIsNone(apply.ArtifactRedirect().redirect_request(None, None, 302, None, None, location))

    def test_plan_summary_binds_exact_manifest_and_producer_checks(self):
        manifest, plan, _ = plan_fixture()
        summary = {
            "schema": apply.noble.SUMMARY_SCHEMA, "status": "planned", "apply_authorized": False,
            "checks": {name: "passed" for name in ("fmt", "validate_init", "validate", "noble_native_mock", "noble_iac_security")},
            "backend": manifest["backend"], "image": IMAGE, "network": {"observed_available": True},
            "actions": manifest["actions"], "iam_refresh": manifest["iam_refresh"], "iac_findings": FINDINGS,
            "plan_exit_code": 2, "private_plan": {"bucket": apply.c.BUCKET, "expires_utc": manifest["expires_utc"], **plan},
        }
        self.assertEqual(apply.verify_artifact_summary(summary, manifest, plan), FINDINGS)
        with self.assertRaisesRegex(ValueError, "exact private plan"):
            apply.verify_artifact_summary(
                {**summary, "private_plan": {**summary["private_plan"], "manifest": {**plan["manifest"], "sha256": "0" * 64}}},
                manifest, plan,
            )
        with self.assertRaisesRegex(ValueError, "Incomplete producer configuration"):
            apply.verify_artifact_summary({**summary, "checks": {}}, manifest, plan)

    def test_exact_new_generation_and_all_parent_addresses_preserved(self):
        parent = tf_state(apply.noble.EXISTING, serial=7)
        state = tf_state(apply.noble.EXISTING | apply.noble.CREATES, serial=9)
        state["outputs"]["db01_noble_candidate"] = {"sensitive": False, "value": {"name": "fixture"}}
        metadata = {"name": apply.PLAN_STATE["name"], "generation": "9"}
        with patch.object(apply, "verify_candidate") as check:
            proof, _ = apply.state_postcheck(json.dumps(state).encode(), metadata, parent, {"policies": {}}, {}, {}, IMAGE)
            self.assertEqual(proof["managed_address_count"], 53)
            self.assertEqual(proof["preserved_address_count"], 42)
            check.assert_called_once()
            previous = next(row for row in state["resources"] if row["type"] == "google_compute_instance" and row["name"] == "postgres")
            previous["instances"][0]["attributes"]["id"] = "changed"
            with self.assertRaisesRegex(ValueError, "existing resource"):
                apply.state_postcheck(json.dumps(state).encode(), metadata, parent, {"policies": {}}, {}, {}, IMAGE)

    def test_post_state_uses_terraform_v4_default_for_omitted_output_sensitivity(self):
        parent = tf_state(apply.noble.EXISTING, serial=7)
        state = tf_state(apply.noble.EXISTING | apply.noble.CREATES, serial=9)
        output = {"value": {"name": "fixture"}, "type": ["object", {"name": "string"}]}
        state["outputs"]["db01_noble_candidate"] = output
        metadata = {"name": apply.PLAN_STATE["name"], "generation": "9"}

        def postcheck():
            return apply.state_postcheck(json.dumps(state).encode(), metadata, parent, {"policies": {}}, {}, {}, IMAGE)

        with patch.object(apply, "verify_candidate") as check:
            self.assertEqual(postcheck()[1], output["value"])
            output["sensitive"] = False
            self.assertEqual(postcheck()[1], output["value"])
            for value in (True, None, 0, "false"):
                output["sensitive"] = value
                with self.subTest(value=value), self.assertRaisesRegex(ValueError, "not publishable"):
                    postcheck()
            self.assertEqual(check.call_count, 2)

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
            apply.state_postcheck(json.dumps(state).encode(), meta, parent, read_profile, read, write, IMAGE)
            row["instances"][0]["attributes"]["etag"] = "not-reviewed"
            with self.assertRaisesRegex(ValueError, "IAM attribute"):
                apply.state_postcheck(json.dumps(state).encode(), meta, parent, read_profile, read, write, IMAGE)

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
        for run in (apply.PLAN_RUN, "1234"):
            manifest, plan, _ = plan_fixture(apply.PRODUCER if run == apply.PLAN_RUN else CONTROLS, run)
            with patch.object(apply.custody, "upload", side_effect=ValueError("already claimed")) as upload:
                with self.assertRaisesRegex(ValueError, "already claimed"):
                    apply.claim_once(environment, manifest, plan, {"name": "test-reference"}, report, NOW)
            name, encoded = upload.call_args.args
            self.assertEqual(name, apply.PLAN_PREFIX + "foundation-state.json")
            self.assertNotIn(name, [reference["name"] for reference in plan.values()])
            self.assertEqual(json.loads(encoded)["binary"], plan["binary"])
            self.assertEqual(json.loads(encoded)["manifest"], plan["manifest"])
            self.assertEqual(report, {"operation": "claim_exact_saved_plan"})

    def test_preflight_failure_is_sanitized_in_console_and_in_artifact(self):
        with tempfile.TemporaryDirectory() as tmp:
            scratch = Path(tmp)
            failure = ValueError("private native detail")
            with (patch.object(apply.driver, "private_paths", return_value=(scratch, scratch)),
                  patch.object(apply, "apply_saved", side_effect=failure),
                  patch.object(apply.sys, "stderr", io.StringIO()) as console,
                  patch.object(apply.os, "umask")):
                self.assertEqual(apply.main(["apply"]), 1)
            displayed = json.loads(console.getvalue())
            report = json.loads((scratch / "summary.json").read_bytes())
            self.assertFalse(report["native_apply_attempted"])
            self.assertEqual(report["diagnostic"], displayed["diagnostic"])
            self.assertEqual(report["status"], "blocked_preflight")
            self.assertNotIn(str(failure), console.getvalue())

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
