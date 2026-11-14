"""Synthetic binding/approval regressions. No checkout config, GCP or real state.

Real source inventory, scanner execution and startup validation belong to the
foundation workflow. These fixtures never count as cloud readiness evidence.
"""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_int_foundation as f, check_tf_int as c, int_release as r
from scripts import int_release_state as state, tf_int_plan as driver


class FoundationContract(unittest.TestCase):
    def setUp(self):
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
        self.manifest = {"schema": r.SCHEMA, **binding, "created_utc": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
                         "backend": r.backend_binding(self.backend), "binary": ref("int.tfplan"), "json": ref("int.json"), "run_id": "123", "run_attempt": "1"}
        self.reference = ref("manifest.json")
        self.contract = {"plan": {**self.manifest, "manifest": self.reference},
                         "residual_controls": [{"id": "F-AUDIT-0077", "status": "pending", "resources": ["authored-bucket"]},
                                               {"id": "F-VM-XML", "status": "pending", "resource": "authored-masked-vm", "advisory": "CVE-2026-6653"}]}

    def report(self):
        pending = [{"resource": "scripts/tf_int_plan.py", "rule": rule, "line": line, "severity": "LOW",
                    "source_sha256": "f" * 64, "disposition": "risk_pending"} for rule, line in (("B404", 16), ("B603", 169), ("B603", 180))]
        return {"control_commit": self.control_commit, "control_sources_sha256": "f" * 64,
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
            stale["created_utc"] = (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()
            old_contract = copy.deepcopy(self.contract); old_contract["plan"]["created_utc"] = stale["created_utc"]
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
        changed = {**approved, "expires_utc": (datetime.now(timezone.utc) + timedelta(hours=25)).isoformat()}
        with self.assertRaises(ValueError): f.verify_owner_decision(changed, r.sha256(r.canonical(changed)), report, self.contract)

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


if __name__ == "__main__":
    unittest.main()
