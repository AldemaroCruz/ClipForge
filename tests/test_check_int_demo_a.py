"""Directed synthetic tests for the offline gate. None of these fixtures attest INT."""
from contextlib import redirect_stdout
from datetime import datetime, timedelta, timezone
from io import StringIO
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from scripts import check_int_demo_a as gate


AT = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc)
PKG = "pkg:deb/ubuntu/test-package@1?arch=amd64"


class DemoGate(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.source_root = self.root / "source"
        self.prepare("oci_publication")

    def prepare(self, operation, *, omit_tool=None):
        self.binding = {**gate.BOUNDARY, "source_commit": "a" * 40, "state_generation": "1795000000000",
                        "operation": operation, "plan_sha256": "e" * 64 if operation in gate.PLAN_BOUND else None,
                        "apply_receipt_sha256": None, "post_apply_generation": None}
        self.review = {"schema": gate.SCHEMA, "binding": self.binding, "operations": [operation],
                       "subjects": {}, "decisions": {}, "exclusions": {}, "apply_receipt": None}
        if operation in gate.POST_APPLY:
            self.binding["post_apply_generation"] = "1795000000001"
            receipt = self.write("applied.json", {
                "status": "applied_and_reconciled", "project": self.binding["project"], "environment": self.binding["environment"],
                "instance_id": self.binding["instance_id"], "data_disk_id": self.binding["data_disk_id"],
                "plan_sha256": self.binding["plan_sha256"], "previous_generation": self.binding["state_generation"],
                "current_generation": self.binding["post_apply_generation"],
            })
            self.review["apply_receipt"] = receipt
            self.binding["apply_receipt_sha256"] = receipt["sha256"]
        self.legacy = {name: {"image_id": value} for name, value in gate.LEGACY_IMAGES.items()}
        self.review["global_history"] = self.write("global.json", {**gate.LEGACY_RUN, "targets": self.legacy,
            "gate": {"status": "failed", "errors": [{"control": key, "category": "security_finding"}
                                                   for key in sorted(gate.LEGACY_CONTROLS)]}})
        roles = gate.OPERATION_ROLES[operation]
        for role in roles:
            analyses, checks = gate.role_contract(operation, role)
            artifact = "sha256:" + gate.digest(role.encode())
            chain = None
            if role == "credential_toolchain" and operation == "bootstrap":
                chain = self.bootstrap_chain(omit_tool=omit_tool)
                artifact = "sha256:" + chain["sha256"]
            records = [self.analysis(role, artifact, kind) for kind in analyses]
            receipts = {check: self.write(f"{role}-{check}.json", {"binding": self.binding,
                                                                  "role": role, "artifact": artifact,
                                                                  "check": check, "status": "passed",
                                                                  "checked_at": AT.isoformat(),
                                                                  "expires_at": (AT + timedelta(hours=2)).isoformat()}) for check in checks}
            self.review["subjects"][role] = {"identity": artifact, "analyses": records, "checks": receipts}
            if chain:
                self.review["subjects"][role]["toolchain"] = chain
        entrypoint = self.bootstrap_sources[gate.BOOTSTRAP_WORKFLOW] if operation == "bootstrap" else "d" * 64
        self.graph = {"binding": self.binding, "entrypoint_sha256": entrypoint,
                      "roles": {role: item["identity"] for role, item in self.review["subjects"].items()},
                      "operations": {operation: {"reads": sorted(roles), "produces": [],
                                                 "credentials": ["personal_windows" if operation == "human_sql_access"
                                                                 else "credential_toolchain"]}}}
        self.set_graph()
        for role, subject in self.review["subjects"].items():
            for entry in subject["analyses"]:
                for key, row in gate.native_rows(self.root, role, subject["identity"], self.binding, entry, AT):
                    control = "confirmed mitigated from exact runtime starting configuration"
                    disposition = "mitigation_verified"
                    ref = self.write(f"decision-{key}.json", {"finding_id": key, "binding": self.binding,
                                                              "control": control, "disposition": disposition, "result": "verified"})
                    self.review["decisions"][key] = {"finding": row, "owner": "reviewer@example.invalid", "control": control,
                                                     "approved_at": (AT - timedelta(minutes=1)).isoformat(),
                                                     "expires_at": (AT + timedelta(hours=1)).isoformat(),
                                                     "disposition": disposition, "evidence": ref}

    def bootstrap_chain(self, *, omit_tool):
        self.bootstrap_sources = {}
        for name in gate.REQUIRED_BOOTSTRAP_SOURCES:
            path = self.source_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = f"# synthetic source for {name}\n".encode()
            path.write_bytes(raw)
            self.bootstrap_sources[name] = gate.digest(raw)
        components = {}
        for role in sorted(gate.BOOTSTRAP_TOOL_ROLES - {omit_tool}):
            source, version = gate.BOOTSTRAP_TOOL_PINS.get(role, "fixture"), "fixture"
            raw = role.encode()
            if role == "gcloud":
                source, version = "pinned-sdk", gate.BOOTSTRAP_TOOL_PINS[role]
            if role == "runner_image":
                source, version = "github-hosted:ubuntu-24.04", "fixture-runner-1"
            if role == "bootstrap_sources":
                source, version = "reviewed-checkout", self.binding["source_commit"]
                raw = json.dumps(self.bootstrap_sources, sort_keys=True, separators=(",", ":")).encode()
            values = {"source": source, "version": version, "sha256": gate.digest(raw), "targets": ["target"]}
            proof = {**values, "binding": self.binding, "component": role, "checked_at": AT.isoformat(),
                     "expires_at": (AT + timedelta(hours=2)).isoformat()}
            if role == "bootstrap_sources":
                proof["files"] = self.bootstrap_sources
            components[role] = {**values, "evidence": self.write(role + "-receipt.json", proof)}
        return self.write("credential-chain.json", {"binding": self.binding, "components": components})

    def set_graph(self):
        graph = self.write("graph.json", self.graph)
        self.review["promotion_graph"] = graph
        for role, image in self.legacy.items():
            self.review["exclusions"][role] = self.write(f"{role}.json", {"binding": self.binding,
                "legacy_target": image["image_id"], "graph_sha256": graph["sha256"],
                "produced": [], "consumed": [], "credentials": []})

    def write(self, name, payload):
        raw = json.dumps(payload, sort_keys=True).encode()
        (self.root / name).write_bytes(raw)
        return {"path": name, "sha256": gate.digest(raw)}

    def analysis(self, role, artifact, kind, *, high=False, omit=False, wrong_config=False):
        prefix = role + "-" + kind
        scope = {"artifact": artifact, "kind": kind}
        if kind.startswith("trivy_"):
            findings = []
            if role == "api" or high:
                findings.append({"PkgIdentifier": {"PURL": PKG}, "InstalledVersion": "1",
                                 "VulnerabilityID": "TEST-ONLY-APAC", "Severity": "HIGH" if high else "LOW", "Fingerprint": "fixture"})
            config, layer = "sha256:" + "b" * 64, "sha256:" + "c" * 64
            report = {"SchemaVersion": 2, "Metadata": {"ImageID": "wrong" if wrong_config else config, "DiffIDs": [layer]},
                      "Results": [{"Target": "target", "Packages": [] if omit else [{"Identifier": {"PURL": PKG}}],
                                   "Vulnerabilities": findings}]}
            scope.update(targets={"target": [PKG]}, oci_config=config, oci_diff_ids=[layer])
        elif kind == "bandit":
            if self.binding["operation"] == "bootstrap" and role == "credential_toolchain":
                sources = {path: sha for path, sha in self.bootstrap_sources.items() if path.endswith(".py")}
            else:
                sources = {"app/main.py": "1" * 64}
            report = {"errors": [], "metrics": {**{"/app/" + path: {} for path in sources}, "_totals": {}}, "results": []}
            scope["sha256_by_source_path"] = sources
        elif kind == "gitleaks":
            report = []
            scope["source_snapshot_sha256"] = "f" * 64
            if self.binding["operation"] == "bootstrap" and role == "credential_toolchain":
                scope["sha256_by_source_path"] = self.bootstrap_sources
        else:
            scope["components"] = ["reviewed-component"]
            report = {"artifact": artifact, "covered": scope["components"], "findings": []}
        raw = self.write(prefix + "-native.json", report)
        receipt = self.write(prefix + "-receipt.json", {"kind": kind, "artifact": artifact, "binding": self.binding,
                            "native_sha256": raw["sha256"], "tool_identity": "2" * 64, "tool_version": "fixture",
                            "scope": self.write(prefix + "-scope.json", scope),
                            "db_sha256": "3" * 64 if kind.startswith("trivy_") else None,
                            "db_expires_at": (AT + timedelta(hours=4)).isoformat()})
        return {"kind": kind, "native": raw, "receipt": receipt}

    def verify(self, expected=None, at=AT, runner_version=None):
        return gate.verify_review(self.root, self.review, expected or self.binding, at,
                                  runner_version=runner_version, source_root=self.source_root)

    def test_closed_fixture_is_reviewable_only(self):
        self.assertEqual(self.verify(), 1)

    def test_unknown_oci_config_blocks_reusing_the_report(self):
        api = self.review["subjects"]["api"]
        api["analyses"][0] = self.analysis("api", api["identity"], "trivy_oci", wrong_config=True)
        with self.assertRaisesRegex(ValueError, "wrong_oci_config"):
            self.verify()

    def test_missing_scanner_target_is_not_zero_findings(self):
        api = self.review["subjects"]["api"]
        api["analyses"][0] = self.analysis("api", api["identity"], "trivy_oci", omit=True)
        with self.assertRaisesRegex(ValueError, "missing_or_duplicate_trivy_target"):
            self.verify()

    def test_scanner_database_hash_is_required(self):
        native = self.review["subjects"]["api"]["analyses"][0]
        old = json.loads((self.root / native["receipt"]["path"]).read_bytes())
        native["receipt"] = self.write("missing-db.json", {**old, "db_sha256": None})
        with self.assertRaisesRegex(ValueError, "trivy_db_or_report_invalid"):
            self.verify()

    def test_native_high_blocks_even_before_decision(self):
        api = self.review["subjects"]["api"]
        api["analyses"][0] = self.analysis("api", api["identity"], "trivy_oci", high=True)
        with self.assertRaisesRegex(ValueError, "native_image_threshold"):
            self.verify()

    def test_missing_wif_tool_is_not_an_exclusion(self):
        del self.review["subjects"]["credential_toolchain"]
        with self.assertRaisesRegex(ValueError, "required_role_missing"):
            self.verify()

    def test_legacy_image_touching_credentials_is_not_excludable(self):
        self.graph["operations"]["oci_publication"]["credentials"].append("legacy_ci_app")
        self.set_graph()
        with self.assertRaisesRegex(ValueError, "unreviewed_operation_participant"):
            self.verify()

    def test_legacy_archive_cannot_be_substituted(self):
        record = json.loads((self.root / self.review["global_history"]["path"]).read_bytes())
        self.review["global_history"] = self.write("substitute.json", {**record, "archive_sha256": "1" * 64})
        with self.assertRaisesRegex(ValueError, "global_history_missing"):
            self.verify()

    def test_new_finding_cannot_use_another_decision(self):
        self.review["decisions"].clear()
        with self.assertRaisesRegex(ValueError, "new_missing_or_stale_findings"):
            self.verify()

    def test_finding_expires_without_global_acceptance(self):
        with self.assertRaisesRegex(ValueError, "expired_or_pending_decision"):
            self.verify(at=AT + timedelta(hours=1))

    def test_plan_change_invalidates_the_review(self):
        self.prepare("locked_plan_apply")
        with self.assertRaisesRegex(ValueError, "wrong_demo_operation_binding"):
            self.verify(expected={**self.binding, "plan_sha256": "0" * 64})

    def test_guest_precedes_secrets_and_plan(self):
        self.prepare("guest_safety")
        self.assertIsNone(self.binding["plan_sha256"])
        self.assertNotIn("api", self.review["subjects"])
        self.assertEqual(self.verify(), 0)
        self.binding["plan_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "wrong_plan_binding_for_operation"):
            self.verify()

    def test_after_apply_requires_its_actual_reconciliation(self):
        self.prepare("migration_job")
        self.assertEqual(self.verify(), 0)
        self.binding["apply_receipt_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "post_apply_reconciliation_mismatch"):
            self.verify()

    def test_an_expired_wif_check_blocks_a_current_report(self):
        key = "isolated_credential_scope"
        checks = self.review["subjects"]["credential_toolchain"]["checks"]
        original = json.loads((self.root / checks[key]["path"]).read_bytes())
        checks[key] = self.write("expired-check.json", {**original, "expires_at": AT.isoformat()})
        with self.assertRaisesRegex(ValueError, "expired_check:" + key):
            self.verify()

    def test_checked_receipts_are_not_just_filenames(self):
        ref = self.review["subjects"]["api"]["checks"]["media_capability_closed"]
        path = self.root / ref["path"]
        path.write_bytes(path.read_bytes() + b" ")
        with self.assertRaisesRegex(ValueError, "evidence_digest_mismatch"):
            self.verify()

    def test_duplicate_json_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate_json_key"):
            gate.closed(b'{"schema":"first","schema":"second"}')

    def test_bootstrap_requires_every_credential_component(self):
        self.prepare("bootstrap", omit_tool="ssh")
        with self.assertRaisesRegex(ValueError, "bootstrap_toolchain_components_incomplete"):
            self.verify()

    def test_bootstrap_requires_matching_live_runner_and_source(self):
        self.prepare("bootstrap")
        self.assertEqual(self.verify(runner_version="fixture-runner-1"), 0)
        with self.assertRaisesRegex(ValueError, "runner_image_mismatch"):
            self.verify(runner_version="unreviewed")
        path = self.source_root / "scripts/int_noble_bootstrap_db.py"
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "changed_bootstrap_source"):
            self.verify()

    def test_bootstrap_rejects_an_uninventoried_transitive_import(self):
        self.prepare("bootstrap")
        name = "scripts/int_noble_bootstrap_db.py"
        raw = b"from scripts import unreviewed_transport\n"
        (self.source_root / name).write_bytes(raw)
        self.bootstrap_sources[name] = gate.digest(raw)
        with self.assertRaisesRegex(ValueError, "missing_bootstrap_import"):
            gate.verify_bootstrap_sources(self.source_root, self.bootstrap_sources, self.binding)

    def test_hosted_binding_rejects_result_from_another_source(self):
        with self.assertRaisesRegex(ValueError, "hosted_review_binding_mismatch"):
            gate.hosted_binding(self.binding, {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": gate.BOUNDARY["repository"],
                "GITHUB_REF": "refs/heads/" + gate.BOUNDARY["branch"],
                "GITHUB_SHA": "b" * 40, "GITHUB_EVENT_NAME": "workflow_dispatch",
                "RUNNER_ENVIRONMENT": "github-hosted"})

    def test_hosted_bootstrap_is_bound_to_the_workflow_file(self):
        self.prepare("bootstrap")
        head = "refs/heads/" + self.binding["branch"]
        hosted = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": self.binding["repository"], "GITHUB_REF": head,
                  "GITHUB_SHA": self.binding["source_commit"], "GITHUB_EVENT_NAME": "workflow_dispatch",
                  "RUNNER_ENVIRONMENT": "github-hosted",
                  "GITHUB_WORKFLOW_REF": f"{self.binding['repository']}/{gate.BOOTSTRAP_WORKFLOW}@{head}"}
        gate.hosted_binding(self.binding, hosted)
        hosted["GITHUB_WORKFLOW_REF"] = hosted["GITHUB_WORKFLOW_REF"].replace("noble-bootstrap", "e2e-bootstrap-db")
        with self.assertRaisesRegex(ValueError, "hosted_workflow_reference_mismatch"):
            gate.hosted_binding(self.binding, hosted)

    def test_cli_requested_operation_is_independent_of_evidence(self):
        review = self.write("review.json", self.review)
        binding = self.write("binding.json", self.binding)
        stdout = StringIO()
        with redirect_stdout(stdout):
            result = gate.main(["--review", str(self.root / review["path"]), "--review-sha256", review["sha256"],
                                "--binding", str(self.root / binding["path"]), "--operation", "bootstrap"])
        self.assertEqual(result, 1)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "blocked", "operation": "bootstrap",
                         "reason": "requested_operation_mismatch", "activation_authorized": False})

    def test_cli_valid_review_still_returns_no_activation_authority(self):
        review = self.write("review.json", self.review)
        binding = self.write("binding.json", self.binding)
        stdout = StringIO()
        with redirect_stdout(stdout), patch.object(gate, "datetime", wraps=datetime) as clock:
            clock.now.return_value = AT
            result = gate.main(["--review", str(self.root / review["path"]), "--review-sha256", review["sha256"],
                                "--binding", str(self.root / binding["path"]), "--operation", "oci_publication"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "coverage_ready_for_owner_review",
                         "operation": "oci_publication", "findings_bound": 1, "activation_authorized": False})


if __name__ == "__main__":
    unittest.main()
