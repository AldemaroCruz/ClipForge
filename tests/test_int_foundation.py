"""Synthetic approval regressions and explicit current-source contract checks.

The numeric-IAP transition tests read only its versioned contract/module files.
No GCP or real state is read; fixtures never count as cloud readiness evidence.
"""
import copy
from datetime import datetime, timedelta, timezone
import json
import io
import os
from pathlib import Path
import sys
import tempfile
import types
import unittest
from unittest import mock
import zipfile

from scripts import check_int_foundation as f, check_tf_int as c, int_release as r
from scripts import int_release_state as state, tf_int_plan as driver


EXECUTION_SOURCE_FIXTURE = "70982d2f5867d0101a181967d182058514e8c82a77423e5eceb09eb0cf89761b"
PLAN_BINDING_FIXTURE_FIELDS = ("commit", "run_id", "manifest", "binary", "json", "created_utc", "configuration_sha256",
                               "provider_lock_sha256", "terraform_version", "inputs", "backend", "managed_addresses", "actions")


def acceptance_fixture(plan, deadline):
    """Authored adversarial-test input; never a real owner authorization."""
    return {"schema": "clipforge-int-foundation-owner-risk-acceptance-2", "owner": "AldemaroCruz",
            "source_commit": plan["commit"], "plan_run": plan["run_id"],
            "authorized_manifest": copy.deepcopy(plan["manifest"]), "authorized_binary": copy.deepcopy(plan["binary"]),
            "approved_plan_binding": {key: copy.deepcopy(plan[key]) for key in PLAN_BINDING_FIXTURE_FIELDS},
            "effective_apply_contract_activated": True, "owner_apply_deadline_utc": deadline,
            "maximum_risk_expiry_utc": "2026-11-28T05:59:59+00:00",
            "invalidates_earlier_if_conditions_change": True, "extends_plan_ttl": False,
            "acceptances": [
                {"id": "F-VM-XML", "decision": "temporarily_accepted_by_owner_for_exact_image",
                 "image": {"project": "debian-cloud", "name": "debian-13-trixie-v20261116", "image_id": "5913446147369107523"},
                 "responsible": "AldemaroCruz", "maximum_expiry_utc": "2026-11-28T05:59:59+00:00",
                 "remediation_or_scan_claimed": False,
                 "conditions": ["PostgreSQL remains masked", "No cluster", "No TCP/5432 listener", "No user data",
                                "No secret retrieval or payload load", "No SQL bootstrap, migrations or service activation"]},
                {"id": "F-SAST-EXEC", "source_sha256": EXECUTION_SOURCE_FIXTURE, "native_findings": [
                    {"rule": "B404", "severity": "LOW", "line": 16, "column": 0, "end_column": 17, "line_range": [16]},
                    {"rule": "B603", "severity": "LOW", "line": 169, "column": 13, "end_column": 122, "line_range": [169]},
                    {"rule": "B603", "severity": "LOW", "line": 180, "column": 13, "end_column": 81, "line_range": [180, 181]}]},
                {"id": "F-AUDIT-0077", "retention_days": 30, "operational": False, "gcs_server_access_logging": False,
                 "findings": [{"id": "GCP-0077", "severity": "MEDIUM", "resource": 'google_storage_bucket.private["backups"]'},
                              {"id": "GCP-0077", "severity": "MEDIUM", "resource": 'google_storage_bucket.private["media"]'}]}]}


class FoundationContract(unittest.TestCase):
    def setUp(self):
        self.now = datetime(2026, 11, 18, 12, 0, tzinfo=timezone.utc)
        fixed = self.now
        class FrozenDatetime(datetime):
            @classmethod
            def now(cls, tz=None):
                return fixed.astimezone(tz) if tz else fixed.replace(tzinfo=None)
        for module in (f, r):
            clock = mock.patch.object(module, "datetime", FrozenDatetime)
            clock.start()
            self.addCleanup(clock.stop)
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-foundation-fixture-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.module = self.root / "module"
        self.module.mkdir()
        for name in c.FILES:
            target = self.module / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("authored synthetic frozen source " + name)
        self.plan_commit, self.control_commit = "a" * 40, "b" * 40
        self.image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "c" * 64
        self.env = {"GITHUB_SHA": self.control_commit, "RUNTIME_IMAGE": self.image, "INT_STAGE": "foundation",
                    "INT_APPROVED_COMMIT": self.control_commit, "INT_APPROVED_PLAN_COMMIT": self.plan_commit,
                    "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted", "GCP_ACCESS_TOKEN": "authored-synthetic-not-a-token"}
        binding = r.source_binding(self.module, {**self.env, "GITHUB_SHA": self.plan_commit})
        base = r.PREFIX + self.plan_commit + "/123-1/"
        ref = lambda name: {"name": base + name, "generation": "123", "sha256": "d" * 64, "size": 100}
        self.backend = {"classification": "recognized_initial_state", "initial_lineage": "authored-lineage", "initial_state_sha256": "e" * 64,
                        "live": [{"name": c.PREFIX + "/default.tfstate", "generation": "11"}]}
        self.manifest = {"schema": r.SCHEMA, **binding, "created_utc": (self.now - timedelta(hours=1)).isoformat(),
                         "backend": r.backend_binding(self.backend), "binary": ref("int.tfplan"), "json": ref("int.json"), "run_id": "123", "run_attempt": "1"}
        self.reference = ref("manifest.json")
        self.contract = {"plan": {**self.manifest, "manifest": self.reference,
                                  "managed_addresses": sorted(c.FOUNDATION_ADDRESSES), "actions": {"create": 42}},
                         "residual_controls": [{"id": "F-AUDIT-0077", "status": "pending", "resources": ["authored-bucket"]},
                                               {"id": "F-VM-XML", "status": "pending", "resource": "authored-masked-vm", "advisory": "CVE-2026-6653"}]}
        self.contract["history"] = {"previous_contract": {"plan": copy.deepcopy(self.contract["plan"])}}
        self.contract["owner_risk_acceptance"] = acceptance_fixture(self.contract["plan"], (self.now + timedelta(hours=2)).isoformat())
        self.seal_acceptance(self.contract)

    @staticmethod
    def seal_acceptance(contract):
        contract["owner_risk_acceptance_sha256"] = r.sha256(r.canonical(contract["owner_risk_acceptance"]))

    def report(self):
        pending = [{"resource": "scripts/tf_int_plan.py", "rule": rule, "line": line, "severity": "LOW",
                    "source_sha256": EXECUTION_SOURCE_FIXTURE, "disposition": "risk_pending"} for rule, line in (("B404", 16), ("B603", 169), ("B603", 180))]
        return {"control_commit": self.control_commit, "control_sources_sha256": "f" * 64,
                "source_files": {"scripts/tf_int_plan.py": EXECUTION_SOURCE_FIXTURE},
                "integrity_status": "passed", "integrity": {name: {"status": "passed"} for name in f.REQUIRED_CHECKS},
                "readiness": "blocked", "sast": {"findings": pending}}

    def future_approved_fixture(self, report):
        """An adversarial-test input, never a persisted owner authorization."""
        value = f.decision_template(report, self.contract)
        value["apply_decision"] = "approve_exact_foundation_binary_once"
        value["evidence_sha256"] = r.sha256(r.canonical(report))
        for item in value["residual_decisions"]:
            item["decision"] = {"F-SAST-EXEC": "approve_exact_execution_sites_for_this_binary_only",
                                "F-AUDIT-0077": "approve_this_alternative_with_mandatory_operational_validation",
                                "F-VM-XML": "approve_expected_dependency_install_inactive_only_with_mandatory_vm_inventory_review"}[item["id"]]
        return value

    def test_same_binary_bridge_is_foundation_only_and_both_commits_are_explicit(self):
        f.verify_plan_bridge(self.manifest, self.module, self.env, self.reference, self.contract)
        for key, value in (("INT_APPROVED_PLAN_COMMIT", self.control_commit), ("INT_APPROVED_COMMIT", self.plan_commit),
                           ("GITHUB_SHA", "f" * 40), ("INT_STAGE", "runtime")):
            with self.subTest(key=key), self.assertRaises(ValueError):
                f.verify_plan_bridge(self.manifest, self.module, {**self.env, key: value}, self.reference, self.contract)

    def test_hcl_startup_lock_inputs_backend_and_object_generation_are_not_rebound(self):
        for key in ("configuration_sha256", "provider_lock_sha256", "inputs", "backend", "binary", "created_utc"):
            changed = {**self.manifest, key: "changed"}
            with self.subTest(key=key), self.assertRaises(ValueError): f.verify_plan_bridge(changed, self.module, self.env, self.reference, self.contract)
        with self.assertRaises(ValueError): f.verify_plan_bridge(self.manifest, self.module, self.env, {**self.reference, "generation": "124"}, self.contract)
        for name in ("main.tf", "postgres-install.sh", ".terraform.lock.hcl"):
            target = self.module / name; before = target.read_bytes(); target.write_text("changed")
            with self.subTest(name=name), self.assertRaises(ValueError): f.verify_plan_bridge(self.manifest, self.module, self.env, self.reference, self.contract)
            target.write_bytes(before)

    def test_new_control_commit_cannot_extend_original_twenty_four_hours(self):
        with mock.patch.object(f, "load_contract", return_value=self.contract):
            r.verify_manifest(self.manifest, self.module, self.env, self.backend, foundation_bridge=True)
            stale = copy.deepcopy(self.manifest)
            stale["created_utc"] = (self.now - timedelta(hours=25)).isoformat()
            old_contract = copy.deepcopy(self.contract); old_contract["plan"]["created_utc"] = stale["created_utc"]
            old_contract["owner_risk_acceptance"]["approved_plan_binding"]["created_utc"] = stale["created_utc"]
            self.seal_acceptance(old_contract)
            with mock.patch.object(f, "load_contract", return_value=old_contract), self.assertRaisesRegex(ValueError, "expired"):
                r.verify_manifest(stale, self.module, self.env, self.backend, foundation_bridge=True)
        with self.assertRaises(ValueError): r.verify_manifest(self.manifest, self.module, self.env, self.backend)

    def test_pending_or_generic_risk_authorization_never_grants_apply(self):
        report = self.report()
        pending = f.decision_template(report, self.contract)
        with self.assertRaises(ValueError): f.verify_owner_decision(pending, r.sha256(r.canonical(pending)), report, self.contract)
        approved = self.future_approved_fixture(report)
        f.verify_owner_decision(approved, r.sha256(r.canonical(approved)), report, self.contract)
        for field, value in (("control_commit", "c" * 40), ("plan_commit", self.control_commit),
                             ("evidence_sha256", "0" * 64), ("residual_decisions", [])):
            changed = {**approved, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError): f.verify_owner_decision(changed, r.sha256(r.canonical(changed)), report, self.contract)
        changed = {**approved, "expires_utc": (self.now + timedelta(hours=25)).isoformat()}
        with self.assertRaises(ValueError): f.verify_owner_decision(changed, r.sha256(r.canonical(changed)), report, self.contract)

    def test_exact_activation_binds_new_controls_without_mutating_plan_or_history(self):
        before = copy.deepcopy(self.contract)
        f.verify_activation(self.contract, now=self.now)
        report = self.report()
        decision = self.future_approved_fixture(report)
        f.verify_owner_decision(decision, r.sha256(r.canonical(decision)), report, self.contract)
        f.verify_plan_bridge(self.manifest, self.module, self.env, self.reference, self.contract)
        self.assertEqual(decision["owner_risk_acceptance_sha256"], self.contract["owner_risk_acceptance_sha256"])
        self.assertEqual(decision["expires_utc"], (self.now + timedelta(hours=2)).isoformat())
        fresh_report = copy.deepcopy(report)
        fresh_report.update(control_commit="c" * 40, control_sources_sha256="1" * 64)
        fresh_report["source_files"]["scripts/check_int_foundation.py"] = "2" * 64
        with self.assertRaises(ValueError):
            f.verify_owner_decision(decision, r.sha256(r.canonical(decision)), fresh_report, self.contract)
        fresh_decision = self.future_approved_fixture(fresh_report)
        f.verify_owner_decision(fresh_decision, r.sha256(r.canonical(fresh_decision)), fresh_report, self.contract)
        env = {**self.env, "GITHUB_SHA": "c" * 40, "INT_APPROVED_COMMIT": "c" * 40}
        f.verify_plan_bridge(self.manifest, self.module, env, self.reference, self.contract)
        self.assertNotEqual(fresh_decision["evidence_sha256"], decision["evidence_sha256"])
        self.assertEqual(self.contract, before)

    def test_activation_rejects_unapproved_candidate_or_changed_owner_and_custody(self):
        original = copy.deepcopy(self.contract)
        for field, value in (("owner", "another-owner"), ("effective_apply_contract_activated", False),
                             ("invalidates_earlier_if_conditions_change", False), ("extends_plan_ttl", True),
                             ("source_commit", "e" * 40), ("plan_run", "999")):
            contract = copy.deepcopy(original)
            contract["owner_risk_acceptance"][field] = value
            self.seal_acceptance(contract)
            with self.subTest(field=field), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        for reference in ("manifest", "binary", "json"):
            for field in ("name", "generation", "sha256", "size"):
                contract = copy.deepcopy(original)
                contract["plan"][reference][field] = 101 if field == "size" else "different"
                with self.subTest(reference=reference, field=field), self.assertRaises(ValueError):
                    f.verify_activation(contract, now=self.now)
        for field in ("configuration_sha256", "provider_lock_sha256", "terraform_version", "backend", "inputs", "created_utc"):
            contract = copy.deepcopy(original)
            contract["plan"][field] = "different"
            with self.subTest(binding=field), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        for candidate in ({"apply_authorized": False}, {"apply_authorized": True}):
            with self.subTest(candidate=candidate), self.assertRaises(ValueError):
                f.verify_activation({**original, "planning_candidate": candidate}, now=self.now)
        with self.assertRaises(ValueError):
            f.verify_activation({**original, "owner_risk_acceptance_sha256": "0" * 64}, now=self.now)

    def test_activation_enforces_individual_risks_and_exact_three_execution_sites(self):
        mutations = (
            (0, "responsible", "another-owner"), (0, "image", {"project": "debian-cloud", "name": "mobile", "image_id": "1"}),
            (0, "conditions", []), (0, "conditions", ["PostgreSQL enabled"]), (0, "remediation_or_scan_claimed", True),
            (1, "source_sha256", "0" * 64), (1, "native_findings", []),
            (1, "native_findings", self.contract["owner_risk_acceptance"]["acceptances"][1]["native_findings"][:2]),
            (2, "retention_days", 29), (2, "operational", True), (2, "gcs_server_access_logging", True), (2, "findings", []))
        for index, field, value in mutations:
            contract = copy.deepcopy(self.contract)
            contract["owner_risk_acceptance"]["acceptances"][index][field] = value
            self.seal_acceptance(contract)
            with self.subTest(residual=index, field=field), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        for field, value in (("column", 14), ("end_column", 121), ("severity", "HIGH"), ("line_range", [169, 170])):
            contract = copy.deepcopy(self.contract)
            contract["owner_risk_acceptance"]["acceptances"][1]["native_findings"][1][field] = value
            self.seal_acceptance(contract)
            with self.subTest(native_field=field), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        for count in (0, 2, 4):
            contract = copy.deepcopy(self.contract)
            risks = contract["owner_risk_acceptance"]["acceptances"]
            contract["owner_risk_acceptance"]["acceptances"] = (risks + [risks[0]])[:count]
            self.seal_acceptance(contract)
            with self.subTest(residual_count=count), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        for mutation in ("empty", "subset", "changed-source", "source-inventory"):
            report = self.report()
            if mutation == "empty": report["sast"]["findings"] = []
            elif mutation == "subset": report["sast"]["findings"].pop()
            elif mutation == "changed-source": report["sast"]["findings"][0]["source_sha256"] = "0" * 64
            else: report["source_files"]["scripts/tf_int_plan.py"] = "0" * 64
            decision = self.future_approved_fixture(report)
            with self.subTest(report_mutation=mutation), self.assertRaises(ValueError):
                f.verify_owner_decision(decision, r.sha256(r.canonical(decision)), report, self.contract)

    def test_expiry_and_scope_are_not_relaxed_even_with_a_resealed_record(self):
        created = datetime.fromisoformat(self.manifest["created_utc"])
        for instant in (created - timedelta(seconds=1), self.now + timedelta(hours=2), created + timedelta(hours=24)):
            with self.subTest(instant=instant), self.assertRaises(ValueError):
                f.verify_activation(self.contract, now=instant)
        mutations = (("owner_apply_deadline_utc", (created + timedelta(hours=24, seconds=1)).isoformat()),
                     ("owner_apply_deadline_utc", self.now.replace(tzinfo=None).isoformat()),
                     ("maximum_risk_expiry_utc", (self.now - timedelta(seconds=1)).isoformat()),
                     ("maximum_risk_expiry_utc", "2026-11-28T06:00:00+00:00"))
        for field, value in mutations:
            contract = copy.deepcopy(self.contract)
            contract["owner_risk_acceptance"][field] = value
            self.seal_acceptance(contract)
            with self.subTest(expiry_field=field, value=value), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        contract = copy.deepcopy(self.contract)
        contract["owner_risk_acceptance"]["acceptances"][0]["maximum_expiry_utc"] = self.now.isoformat()
        self.seal_acceptance(contract)
        with self.assertRaises(ValueError): f.verify_activation(contract, now=self.now)
        for field, value in (("actions", {"create": 42, "delete": 1}), ("managed_addresses", sorted(c.FOUNDATION_ADDRESSES)[:-1]),
                             ("inputs", {**self.contract["plan"]["inputs"], "stage": "runtime"}),
                             ("inputs", {**self.contract["plan"]["inputs"], "secret_versions": {"app_password": "1"}})):
            contract = copy.deepcopy(self.contract)
            contract["plan"][field] = value
            contract["owner_risk_acceptance"]["approved_plan_binding"][field] = copy.deepcopy(value)
            self.seal_acceptance(contract)
            with self.subTest(scope_field=field), self.assertRaises(ValueError):
                f.verify_activation(contract, now=self.now)
        report = self.report()
        expired_decision = self.future_approved_fixture(report)
        expired_decision["expires_utc"] = self.now.isoformat()
        with self.assertRaises(ValueError):
            f.verify_owner_decision(expired_decision, r.sha256(r.canonical(expired_decision)), report, self.contract)

    def test_live_image_lookup_follows_valid_decision_and_blocks_before_tools(self):
        # Explicit HTTP-boundary fixture: the authored-tests context intentionally
        # has no cloud helper module, credentials or HCL. This is not a live GET.
        image_module = types.ModuleType("scripts.review_int_foundation_plan")
        image_module.image_metadata = mock.Mock(return_value={"project": "debian-cloud", "name": "debian-13-trixie-v20261116",
                                                               "id": "5913446147369107523", "status": "READY"})
        report = self.report()
        decision = self.future_approved_fixture(report)
        env = {**self.env, "FOUNDATION_DECISION_JSON": json.dumps(decision), "FOUNDATION_DECISION_SHA256": r.sha256(r.canonical(decision))}
        with mock.patch.dict(sys.modules, {image_module.__name__: image_module}), \
                mock.patch.object(sys.modules["scripts"], "review_int_foundation_plan", image_module, create=True), \
                mock.patch.object(f, "fetch_evidence", return_value=report), mock.patch.object(f, "load_contract", return_value=self.contract):
            approval = f.require_foundation_ci(env)
            self.assertEqual(approval["plan_commit"], self.plan_commit)
            image_module.image_metadata.assert_called_once_with()
            image_module.image_metadata.reset_mock()
            with mock.patch.object(driver, "run") as commands, self.assertRaises(ValueError):
                r.apply_saved(self.root, self.root, self.reference, {**env, "FOUNDATION_DECISION_SHA256": "0" * 64})
            commands.assert_not_called()
            image_module.image_metadata.assert_not_called()
            for failure in (ValueError("Image GET denied 403"), ValueError("Image deprecated")):
                image_module.image_metadata.side_effect = failure
                with mock.patch.object(driver, "run") as commands, self.subTest(failure=str(failure)), self.assertRaises(ValueError):
                    r.apply_saved(self.root, self.root, self.reference, env)
                commands.assert_not_called()
            image_module.image_metadata.side_effect = None
            image_module.image_metadata.return_value["id"] = "5913446147369107524"
            with mock.patch.object(driver, "run") as commands, self.assertRaises(ValueError):
                r.apply_saved(self.root, self.root, self.reference, env)
            commands.assert_not_called()

    def test_exact_foundation_apply_uses_verified_saved_bytes_and_native_lock_once(self):
        from tests.test_tf_int import fixture
        source_plan = fixture()
        source_plan["resource_changes"] = [row for row in source_plan["resource_changes"] if row["address"] in c.FOUNDATION_ADDRESSES]
        source_plan["variables"].update(stage={"value": "foundation"}, secret_versions={"value": None}, runtime_image={"value": self.image})
        source_plan["terraform_version"] = self.manifest["terraform_version"]
        vm = next(row for row in source_plan["resource_changes"] if row["address"] == "google_compute_instance.postgres")
        vm["change"]["after"]["metadata_startup_script"] = (self.module / "postgres-install.sh").read_text()
        plan_json, binary = r.canonical(source_plan), b"synthetic exact saved binary"
        for key, raw in (("json", plan_json), ("binary", binary)):
            self.manifest[key].update(sha256=r.sha256(raw), size=len(raw))
        raw_manifest = r.canonical(self.manifest)
        self.reference.update(sha256=r.sha256(raw_manifest), size=len(raw_manifest))
        self.contract["owner_risk_acceptance"] = acceptance_fixture(self.contract["plan"], (self.now + timedelta(hours=2)).isoformat())
        self.seal_acceptance(self.contract)
        report = self.report()
        decision = self.future_approved_fixture(report)
        env = {**self.env, "FOUNDATION_DECISION_JSON": json.dumps(decision), "FOUNDATION_DECISION_SHA256": r.sha256(r.canonical(decision))}
        objects = {self.reference["name"]: raw_manifest, self.manifest["json"]["name"]: plan_json, self.manifest["binary"]["name"]: binary}
        def get(method, name, *, generation=None):
            self.assertEqual(method, "GET")
            self.assertEqual(generation, "123")
            return objects[name]
        image_module = types.ModuleType("scripts.review_int_foundation_plan")
        image_module.image_metadata = mock.Mock(return_value={"project": "debian-cloud", "name": "debian-13-trixie-v20261116", "id": "5913446147369107523"})
        with mock.patch.dict(sys.modules, {image_module.__name__: image_module}), \
                mock.patch.object(sys.modules["scripts"], "review_int_foundation_plan", image_module, create=True), \
                mock.patch.object(f, "fetch_evidence", return_value=report), mock.patch.object(f, "load_contract", return_value=self.contract), \
                mock.patch.object(r, "request", side_effect=get), mock.patch.object(driver, "metadata", return_value={}), \
                mock.patch.object(driver, "inspect_backend", return_value=self.backend) as inspect, \
                mock.patch.object(driver, "terraform_binary", return_value="synthetic-terraform"), \
                mock.patch.object(driver, "run", return_value=(0, b"")) as commands, \
                mock.patch.object(r, "require_application_ci") as app_gate, \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(state, "emit_foundation_receipt", return_value={"name": "synthetic-receipt"}):
            r.apply_saved(self.root, self.root, self.reference, env)
        self.assertEqual((self.root / "approved.tfplan").read_bytes(), binary)
        self.assertEqual(commands.call_count, 2)
        self.assertEqual(commands.call_args_list[0].args[0][1], "init")
        apply_argv = commands.call_args_list[1].args[0]
        self.assertEqual(apply_argv, ["synthetic-terraform", "apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(self.root / "approved.tfplan")])
        self.assertEqual(inspect.call_count, 2)
        app_gate.assert_not_called()

    def test_apply_wrapper_preserves_sanitized_native_failure_without_retry(self):
        failure = driver.FailedOperation("approved_same_plan_apply", "403 Permission 'compute.instances.create' denied on resource projects/clipforgebeta2/zones/us-central1-a/instances/synthetic\n403 Bearer synthetic-private-sentinel")
        env = {**self.env, "PLAN_MANIFEST_JSON": json.dumps(self.reference)}
        with mock.patch.object(r, "apply_saved", side_effect=failure) as saved, mock.patch.dict(os.environ, {}, clear=True):
            self.assertEqual(f.apply_reviewed(self.root, self.root, env), 1)
        saved.assert_called_once_with(self.root, self.root, self.reference, env)
        value = json.loads((self.root / "summary.json").read_bytes())
        self.assertEqual(value["error"], failure.receipt)
        self.assertEqual(value["status"], "apply_failed_preserve_state_no_retry")
        self.assertFalse(value["execution"]["automatic_retry"])
        self.assertNotIn("synthetic-private-sentinel", json.dumps(value))

    def test_apply_wrapper_publishes_only_receipt_metadata_and_foundation_addresses(self):
        state_metadata = {"name": c.PREFIX + "/default.tfstate", "lineage": "synthetic-lineage", "serial": 2, "generation": "124", "sha256": "d" * 64, "size": 100}
        private_receipt = {"control_commit": self.control_commit, "foundation_commit": self.plan_commit,
                           "state": state_metadata, "managed_addresses": sorted(c.FOUNDATION_ADDRESSES),
                           "private_resource_attributes": "synthetic-private-receipt-sentinel"}
        reference = {"name": "synthetic-receipt"}
        def applied(*_args):
            (self.root / "summary.json").write_text(json.dumps({"status": "foundation_applied_runtime_not_approved", "foundation_receipt": reference}))
        env = {**self.env, "PLAN_MANIFEST_JSON": json.dumps(self.reference)}
        with mock.patch.object(r, "apply_saved", side_effect=applied) as saved, \
                mock.patch.dict(os.environ, {}, clear=True), \
                mock.patch.object(r, "fetch_verified", return_value=r.canonical(private_receipt)) as fetch:
            self.assertEqual(f.apply_reviewed(self.root, self.root, env), 0)
        saved.assert_called_once()
        fetch.assert_called_once_with(reference)
        summary = json.loads((self.root / "summary.json").read_bytes())
        self.assertEqual(summary["resulting_state"], state_metadata)
        self.assertEqual(summary["created_addresses"], sorted(c.FOUNDATION_ADDRESSES))
        self.assertEqual(summary["runtime_deployment"], "not_authorized")
        self.assertNotIn("synthetic-private-receipt-sentinel", (self.root / "summary.json").read_text() + (self.root / "summary.md").read_text())

    def test_receipt_failure_after_apply_reports_completion_without_retry_or_private_state(self):
        reference = {"name": "synthetic-private-receipt"}
        def applied(*_args):
            (self.root / "summary.json").write_text(json.dumps({"status": "foundation_applied_runtime_not_approved", "foundation_receipt": reference}))
        env = {**self.env, "PLAN_MANIFEST_JSON": json.dumps(self.reference)}
        for outcome in ("fetch-error", "private-state-key", "missing-address"):
            state_metadata = {"name": c.PREFIX + "/default.tfstate", "lineage": "synthetic-lineage", "serial": 2, "generation": "124", "sha256": "d" * 64, "size": 100}
            receipt = {"control_commit": self.control_commit, "foundation_commit": self.plan_commit,
                       "state": state_metadata, "managed_addresses": sorted(c.FOUNDATION_ADDRESSES)}
            if outcome == "private-state-key": receipt["state"]["private_attributes"] = "synthetic-private-state-sentinel"
            if outcome == "missing-address": receipt["managed_addresses"].pop()
            with mock.patch.object(r, "apply_saved", side_effect=applied) as saved, \
                    mock.patch.dict(os.environ, {}, clear=True), \
                    mock.patch.object(r, "fetch_verified", return_value=r.canonical(receipt),
                                      side_effect=ValueError("synthetic-private-state-sentinel") if outcome == "fetch-error" else None), self.subTest(outcome=outcome):
                self.assertEqual(f.apply_reviewed(self.root, self.root, env), 1)
            saved.assert_called_once()
            summary = json.loads((self.root / "summary.json").read_bytes())
            self.assertEqual(summary["status"], "foundation_applied_post_summary_verification_failed_no_retry")
            self.assertTrue(summary["apply_completed"])
            self.assertEqual(summary["foundation_receipt"], reference)
            self.assertFalse(summary["execution"]["automatic_retry"])
            self.assertNotIn("resulting_state", summary)
            self.assertNotIn("synthetic-private-state-sentinel", (self.root / "summary.json").read_text() + (self.root / "summary.md").read_text())

    def test_unknown_high_findings_or_failed_integrity_cannot_be_accepted(self):
        for kind in ("high", "unknown", "failed-integrity"):
            report = self.report()
            if kind == "high": report["sast"]["findings"][0]["severity"] = "HIGH"
            if kind == "unknown": report["sast"]["findings"][0]["rule"] = "B999"
            if kind == "failed-integrity": report["integrity_status"] = "failed"
            decision = self.future_approved_fixture(report)
            with self.subTest(kind=kind), self.assertRaises(ValueError): f.verify_owner_decision(decision, r.sha256(r.canonical(decision)), report, self.contract)

    def test_foundation_uses_own_evidence_and_preserves_application_failure(self):
        app_report = {"conclusion": "failure", "errors": ["Bandit", "Trivy", "browser", "PostgreSQL"]}
        before = copy.deepcopy(app_report)
        with mock.patch.object(f, "require_foundation_ci", side_effect=ValueError("F-SAST-EXEC pending")), \
                mock.patch.object(r, "require_application_ci") as application, mock.patch.object(r, "fetch_verified") as fetch:
            with self.assertRaises(ValueError): r.apply_saved(self.root, self.root, self.reference, self.env)
        application.assert_not_called(); fetch.assert_not_called()
        self.assertEqual(app_report, before)

    def test_runtime_keeps_same_commit_and_application_ci_gate(self):
        env = {**self.env, "INT_STAGE": "runtime"}
        with mock.patch.object(f, "require_foundation_ci") as foundation, mock.patch.object(r, "fetch_verified") as fetch:
            with self.assertRaises(ValueError): r.apply_saved(self.root, self.root, self.reference, env)
        foundation.assert_not_called(); fetch.assert_not_called()
        env["INT_APPROVED_PLAN_COMMIT"] = env["GITHUB_SHA"]
        with mock.patch.object(r, "require_application_ci", side_effect=ValueError("app remains blocked")) as application:
            with self.assertRaisesRegex(ValueError, "app remains blocked"): r.apply_saved(self.root, self.root, self.reference, env)
        application.assert_called_once()

    def test_post_apply_receipt_records_plan_and_control_as_different_identities(self):
        parent = {**self.manifest, "backend": {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
                  "lineage": driver.INITIAL_STATE["lineage"], "serial": 1, "state_generation": driver.INITIAL_STATE["generation"],
                  "state_sha256": driver.INITIAL_STATE["sha256"]}}
        receipt = {"schema": state.SCHEMA, "foundation_commit": self.plan_commit, "source_plan_sha256": parent["binary"]["sha256"],
                   "managed_addresses": sorted(c.FOUNDATION_ADDRESSES), "control_commit": self.control_commit,
                   "control_approval": {"plan_commit": self.plan_commit, "control_commit": self.control_commit,
                                        "decision_sha256": "1" * 64, "evidence_sha256": "2" * 64},
                   "issuer": {"repository": "AldemaroCruz/ClipForge", "workflow": ".github/workflows/int-e2e-apply.yml", "commit": self.control_commit, "run_id": "456"}}
        state.verify_parent(receipt, parent, self.module, self.env)
        receipt["control_approval"]["plan_commit"] = self.control_commit
        with self.assertRaises(ValueError): state.verify_parent(receipt, parent, self.module, self.env)


class FoundationCurrentConfiguration(unittest.TestCase):
    def setUp(self):
        self.root = f.ROOT
        self.module = self.root / "infra/gcp/int-base"
        self.contract = f.load_contract(self.root)

    def test_exact_current_configuration_passes_without_rebinding_historical_plan_or_acceptance(self):
        before = copy.deepcopy(self.contract)
        binding = f.check_static(self.root, self.module, self.contract)
        self.assertEqual(binding["configuration_sha256"], "4f13120dc9165cd43881181eca6af95663df9d063d513bb4d776c59137d92aea")
        self.assertEqual(binding["commit"], self.contract["plan"]["commit"])
        self.assertNotEqual(binding["configuration_sha256"], self.contract["plan"]["configuration_sha256"])
        self.assertEqual(self.contract, before)
        with self.assertRaisesRegex(ValueError, "retired"):
            f.verify_activation(self.contract)

    def test_current_metadata_is_required_for_new_source_and_cannot_enable_other_modes(self):
        for mutation in ("absent", "active-mode", "candidate", "purpose", "configuration_sha256", "source_patch_sha256",
                         "historical_plan_configuration_sha256", "producer_binding", "history-path", "history-hash", "extra"):
            contract = copy.deepcopy(self.contract)
            current = contract["current_configuration"]
            if mutation == "absent": del contract["current_configuration"]
            elif mutation == "active-mode": contract["mode"] = "active_foundation"
            elif mutation == "candidate": contract["planning_candidate"] = {"purpose": "comparative_plan_only"}
            elif mutation == "history-path": current["historical_contract"]["path"] = "config/other.json"
            elif mutation == "history-hash": current["historical_contract"]["sha256"] = "0" * 64
            elif mutation == "extra": current["unreviewed"] = True
            else: current[mutation] = "0" * 64
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                f.check_static(self.root, self.module, contract)

    def test_full_historical_bytes_plan_producer_and_acceptance_must_remain_exact(self):
        for mutation in ("bytes", "plan-hash", "plan-producer", "plan-run", "acceptance", "acceptance-hash"):
            contract = copy.deepcopy(self.contract)
            if mutation == "plan-hash": contract["plan"]["configuration_sha256"] = contract["current_configuration"]["configuration_sha256"]
            elif mutation == "plan-producer": contract["plan"]["commit"] = "c" * 40
            elif mutation == "plan-run": contract["plan"]["run_id"] = "99999"
            elif mutation == "acceptance": contract["owner_risk_acceptance"]["source_commit"] = "c" * 40
            elif mutation == "acceptance-hash": contract["owner_risk_acceptance_sha256"] = "0" * 64
            native_read = Path.read_bytes
            def read(path):
                raw = native_read(path)
                return raw + b"\n" if mutation == "bytes" and path.name == "5800b4c-foundation-contract.json" else raw
            with self.subTest(mutation=mutation), mock.patch.object(Path, "read_bytes", read), self.assertRaises(ValueError):
                f.current_configuration_binding(self.root, self.module, contract)

    def test_recovery_activation_and_real_two_line_source_guard_are_required(self):
        from scripts import int_foundation_recovery as recovery
        recovered = recovery.load_contract(self.root)
        without_patch = copy.deepcopy(recovered)
        del without_patch["iap_identity_patch"]
        with mock.patch.object(recovery, "load_contract", return_value=without_patch), self.assertRaises(ValueError):
            f.current_configuration_binding(self.root, self.module, self.contract)
        with tempfile.TemporaryDirectory(prefix="clipforge-foundation-current-source-") as temporary:
            module = Path(temporary)
            for name in c.FILES:
                target = module / name
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((self.module / name).read_bytes())
            (module / "main.tf").write_bytes((module / "main.tf").read_bytes() + b"\n# extra change\n")
            with self.assertRaises(ValueError):
                f.current_configuration_binding(self.root, module, self.contract)

    def test_downloaded_evidence_must_bind_current_configuration_separately_from_historical_plan(self):
        # Authored archive/HTTP fixture only; scanner evaluation deliberately stops
        # immediately after source binding, so this cannot represent native evidence.
        commit = "c" * 40
        contract_bytes = (self.root / f.CONTRACT).read_bytes()
        for mutation in ("unchanged", "missing", "changed"):
            report = {"schema": f.REPORT_SCHEMA, "control_commit": commit, "contract_sha256": r.sha256(contract_bytes),
                      "control_sources_sha256": "a" * 64, "source_files": {}, "plan": self.contract["plan"],
                      "current_configuration": copy.deepcopy(self.contract["current_configuration"]),
                      "native_report_sha256": {name: r.sha256(b"{}") for name in f.BUNDLE[1:]}}
            if mutation == "missing": del report["current_configuration"]
            elif mutation == "changed": report["current_configuration"]["configuration_sha256"] = "0" * 64
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                for name in f.BUNDLE:
                    archive.writestr(name, r.canonical(report) if name == "foundation-report.json" else b"{}")
            run = {"id": 123, "head_sha": commit, "head_branch": self.contract["branch"], "path": f.WORKFLOW,
                   "run_number": 1, "run_attempt": 1, "status": "completed", "conclusion": "failure", "event": "push"}
            artifacts = {"artifacts": [{"id": 456, "name": "int-foundation-evidence-" + commit + "-123-1", "expired": False}]}
            opener = mock.Mock()
            opener.open.return_value = io.BytesIO(buffer.getvalue())
            with self.subTest(mutation=mutation), mock.patch.object(f, "github_json", side_effect=[{"workflow_runs": [run]}, artifacts]), \
                    mock.patch.object(f, "build_opener", return_value=opener), mock.patch.object(f, "fingerprint", return_value=("a" * 64, {})), \
                    mock.patch.object(f, "bandit_contract", side_effect=RuntimeError("binding accepted; fixture stops here")) as bandit:
                expected = RuntimeError if mutation == "unchanged" else ValueError
                with self.assertRaises(expected):
                    f.fetch_evidence({"GITHUB_SHA": commit, "GH_TOKEN": "synthetic-not-token"}, self.root)
                self.assertEqual(bandit.call_count, int(mutation == "unchanged"))


if __name__ == "__main__":
    unittest.main()
