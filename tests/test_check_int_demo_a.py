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
from scripts import int_demo_a_docker as docker
from scripts import int_demo_a_docker_prepare as docker_prepare
from test_int_demo_a_docker import fixture_receipt


AT = datetime(2026, 11, 20, 18, 0, tzinfo=timezone.utc)
PKG = "pkg:deb/ubuntu/test-package@1?arch=amd64"


class DemoGate(unittest.TestCase):
    def setUp(self):
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        self.root = Path(scratch.name).resolve()
        self.source_root = self.root / "source"
        self.baselines = dict(gate.GUEST_BASELINES)
        patcher = patch.object(gate, "GUEST_BASELINES", self.baselines)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.prepare("oci_publication")

    def prepare(self, operation, *, omit_tool=None, guest_action=None):
        self.guest_action = guest_action
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
        action = None
        for role in roles:
            analyses, checks = gate.role_contract(operation, role)
            artifact = "sha256:" + gate.digest(role.encode())
            extension = {}
            if role == "credential_toolchain" and operation == "bootstrap":
                chain = self.bootstrap_chain(omit_tool=omit_tool)
                artifact = "sha256:" + chain["sha256"]
                extension["toolchain"] = chain
            elif role == "credential_toolchain" and operation == "oci_publication":
                publication = self.publication_scope()
                artifact = "sha256:" + self.docker_ref["sha256"]
                extension["publication"] = publication
            elif role == "noble_guest":
                action = guest_action if operation == "guest_intervention" else ("review" if operation == "guest_safety" else "continue")
                guest_control = self.guest_control(action)
                artifact = "sha256:" + guest_control["sha256"]
                extension["guest_control"] = guest_control
            records = [self.analysis(role, artifact, kind) for kind in analyses]
            receipts = {check: self.write(f"{role}-{check}.json", {"binding": self.binding,
                                                                  "role": role, "artifact": artifact,
                                                                  "check": check, "status": "passed",
                                                                  "checked_at": AT.isoformat(),
                                                                  "expires_at": (AT + timedelta(hours=2)).isoformat(),
                                                                  **({"runner_image": "20261120.1.2"} if check in {
                                                                      "exact_guest_intervention_transport",
                                                                      "secret_target_and_version_receipt_protocol",
                                                                  } else {})})
                        for check in checks}
            self.review["subjects"][role] = {"identity": artifact, "analyses": records, "checks": receipts, **extension}
        entrypoint = "d" * 64
        if operation == "bootstrap":
            entrypoint = self.bootstrap_sources[gate.BOOTSTRAP_WORKFLOW]
        elif operation == "oci_publication":
            entrypoint = self.publication_sources[gate.PUBLICATION_WORKFLOW]
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
                    result, details = "verified", {}
                    specific = gate.decision_control(row, operation, action, self.review["subjects"])
                    if specific:
                        disposition, control, result, details = specific
                    ref = self.write(f"decision-{key}.json", {"finding_id": key, "binding": self.binding,
                                                              "control": control, "disposition": disposition, "result": result, **details})
                    self.review["decisions"][key] = {"finding": row, "owner": "reviewer@example.invalid", "control": control,
                                                     "approved_at": (AT - timedelta(minutes=1)).isoformat(),
                                                     "expires_at": (AT + timedelta(hours=1)).isoformat(),
                                                     "disposition": disposition, "evidence": ref}

    def publication_scope(self):
        self.publication_sources = {}
        for name in gate.PUBLICATION_SOURCES:
            path = self.source_root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            raw = f"# synthetic source for {name}\n".encode()
            if name == gate.DOCKER_SOURCE:
                raw += b"import subprocess\ndef synthetic(argv):\n    subprocess.run(argv)\n"
            path.write_bytes(raw)
            self.publication_sources[name] = gate.digest(raw)
        sources = self.write("pub-sources.json", {"binding": self.binding, "files": self.publication_sources})
        runtime = fixture_receipt()
        runtime["runner_image"] = "20261120.1.2"
        observed = runtime["observation"]
        for path, (size, digest) in docker_prepare.BINARIES.items():
            runtime["files"][path].update(bytes=size, sha256=digest)
            observed["files"][path]["bytes"] = size
        for unit, path in docker.SERVICE_BINARIES.items():
            runtime["services"][unit] = dict(runtime["files"][path])
            observed["processes"][unit]["executable"] = docker.live_from_file(observed["files"][path])
        self.docker_ref = self.write("fixture-docker-toolchain.json", runtime)
        projection = docker.projection_sha256(runtime)
        preparation = self.write("fixture-prepare.json", {"schema": docker_prepare.SCHEMA, "profile": "evaluate", "status": "prepared_verified",
            "publication_eligibility": "eligible", "cloud_credentials_used": False, "oidc_job_capability": False, "run": observed["run"],
            "attempt": observed["attempt"], "commit": observed["source_commit"], "after": {"toolchain": runtime},
            "comparison": {"after": {"toolchain": docker.stable_projection(runtime)}}})
        rehearsal = self.write("fixture-rehearsal.json", {"schema": "clipforge-int-demo-a-publisher-rehearsal-1", "status": "tls_copy_verified",
            **{name: observed[name] for name in ("source_commit", "run", "attempt", "job", "boot_id")},
            "source_sha256": self.publication_sources[gate.PUBLISHER_LAB_SOURCE],
            "docker_toolchain_sha256": self.docker_ref["sha256"], "docker_projection_sha256": projection, "preparation_sha256": preparation["sha256"],
            "publisher_manifest": gate.PUBLISHER_MANIFEST, "publisher_config": gate.PUBLISHER_CONFIG, "images": gate.PUBLICATION_IMAGES,
            "registry_image": "sha256:" + "e" * 64, "cloud_credentials_used": False,
            **dict.fromkeys(("isolated_network", "source_unchanged", "unknown_ca_rejected", "wrong_hostname_rejected",
                             "manifest_config_layers_verified", "owned_resources_removed"), True)})
        self.docker_targets = {target: ["target"] for target in gate.DOCKER_BINARIES | {"runner_kernel"}}
        return self.write("pub.json", {"binding": self.binding, "sources": sources, "docker_runtime": self.docker_ref,
                                       "docker_targets": self.docker_targets, "docker_projection_sha256": projection,
                                       "preparation": preparation, "rehearsal": rehearsal})

    def guest_control(self, action):
        self.guest_plane = {key: gate.NOBLE_TARGET[key] for key in ("instance_id", "data_disk_id", "boot_disk_id")}
        self.guest_snap = gate.digest(json.dumps(self.guest_plane, sort_keys=True, separators=(",", ":")).encode())
        self.guest_before = {
            "kernel": {"boot_id": gate.NOBLE_TARGET["boot_id"], "release": gate.NOBLE_TARGET["release"], "virtualization": "google",
                       "exports": {"active": None, "configured": 0},
                       "modules": dict.fromkeys(gate.KERNEL_MODULES, {"disk": "module_file", "loaded": False, "sysfs": False}),
                       "autoload": {"modules_load": dict.fromkeys(gate.KERNEL_MODULES, 0),
                                    "modprobe": dict.fromkeys(gate.KERNEL_MODULES, {"blacklist": 0, "install": "default"})}},
            "xen": {"private_nic_driver": "virtio_net", "backend_vifs": 0},
            "ceph": {"pid1_mounts": 0, "fstab_mounts": 0, "named_processes": 0, "pid1_canonical_remote_sockets": 0,
                     "packages": dict.fromkeys(("ceph-common", "ceph-fuse", "libcephfs2", "rbd-nbd"), False), "data_disk_relation": "expected_device_unmounted"},
            "kmod": {"scope_rule": "absent", "helper": "standard", "modules_disabled": False, "boot_blacklist": dict.fromkeys(gate.KERNEL_MODULES, False),
                     "dry_run": dict.fromkeys(gate.KERNEL_MODULES, {"direct": "would_insert", "aliases": ["would_insert"]})}}
        readiness = {"boot_id": gate.NOBLE_TARGET["boot_id"], "release": gate.NOBLE_TARGET["release"],
                     "exports": {"active_count": 0, "configured_count": 0, "nfsd_mounts": 0, "host_mount_namespace": True,
                                 "registered_filesystem": False, "module_loaded": False, "state": "server_unregistered_in_host_mount_namespace"}}
        baseline = {}
        for key, report in (("consumers", self.guest_before), ("readiness", readiness)):
            run, scope, _, _ = self.baselines[key]
            inventory = self.write(f"fixture-{key}-inventory.json", {"schema": "clipforge-int-noble-kernel-observation-receipt-1",
                "control_plane": self.guest_plane, "risk_accepted": False, "runtime_authorized": False, "controls_commit": "b" * 40, "guest": report})
            summary = self.write(f"fixture-{key}-summary.json", {"schema": "clipforge-int-noble-kernel-observation-summary-1", "status": "observation_complete",
                "observation_run_id": run, "scope": scope, "inventory_sha256": inventory["sha256"], "controls_commit": "b" * 40,
                "control_plane": self.guest_plane, "guest_exit_code": 0, "cleanup": {"status": "own_key_removed"}})
            self.baselines[key] = (run, scope, inventory["sha256"], summary["sha256"])
            baseline[key] = {"inventory": inventory, "summary": summary}
        apt = self.intervention_receipt("apt_upgrade") if action in {"kmod_apply", "kmod_withdraw", "continue"} else None
        kmod = self.intervention_receipt("kmod_apply") if action in {"kmod_withdraw", "continue"} else None
        return self.write("fixture-guest-control.json", {"binding": self.binding, "action": action, "baseline": baseline,
            "apt_receipt": apt, "kmod_receipt": kmod, "checked_at": AT.isoformat(), "expires_at": (AT + timedelta(hours=2)).isoformat()})

    def intervention_receipt(self, action):
        operation_id = "1" * 32
        native = {**gate.NOBLE_TARGET, "operation_id": "int-noble-" + operation_id, "approved_commit": "2" * 40, "intent_sha256": "3" * 64}
        if action == "apt_upgrade":
            native.update(schema="clipforge-int-noble-apt-receipt-1", status="updated_exact_package", kernel=gate.NOBLE_TARGET["release"],
                          package="linux-tools-common", owner_decision_sha256="4" * 64, package_sha256=gate.APT_DEB_SHA,
                          signed_index_sha256=gate.APT_SIGNED_INDEX_SHA, simulation={"exact_upgrade": True}, download_verified=True,
                          launch_intent=True, temp_released=True, postcheck={"installed": "6.8.0-151.151", "other_package_states_sha256": "0" * 64,
                              "dpkg_clean": True, "same_boot_and_kernel": True, "other_package_states_equal": True})
        else:
            after = json.loads(json.dumps(self.guest_before))
            after["kmod"]["scope_rule"] = "reviewed"
            for module in gate.KERNEL_MODULES:
                after["kmod"]["dry_run"][module] = {"direct": "deny_install", "aliases": ["no_action_reported"]}
                after["kernel"]["autoload"]["modprobe"][module].update(blacklist=1, install="deny")
            native.update(schema="clipforge-int-noble-kmod-receipt-1", status="applied_verified", operation="apply", snapshot_sha256=self.guest_snap,
                          rule_sha256=gate.KMOD_RULE_SHA, file={"uid": 0, "gid": 0, "mode": 0o100644, "size": 207, "nlink": 1, "sha256": gate.KMOD_RULE_SHA},
                          before=self.guest_before, after=after, runtime_authorized=False, bootstrap_authorized=False, risk_accepted=False, reboot_attempted=False)
        return self.write(f"fixture-{action}.json", {"schema": "clipforge-int-noble-intervention-result-1", "status": "completed_verified",
            "action": action, "operation_id": operation_id, "control_commit": native["approved_commit"], "decision_sha256": "4" * 64,
            "control_plane": self.guest_plane, "snapshot_sha256": self.guest_snap, "native_exit": 0, "runtime_authorized": False,
            "intent": {"sha256": "1" * 64}, "cleanup": {"status": "own_key_removed"}, "guest_receipt": native})

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
            if self.binding["operation"] == "oci_publication" and role == "credential_toolchain":
                scope.update(docker_toolchain_sha256=self.docker_ref["sha256"], docker_targets=self.docker_targets)
        elif kind == "bandit":
            findings = []
            if self.binding["operation"] == "bootstrap" and role == "credential_toolchain":
                sources = {path: sha for path, sha in self.bootstrap_sources.items() if path.endswith(".py")}
            elif self.binding["operation"] == "oci_publication" and role == "credential_toolchain":
                sources = {path: sha for path, sha in self.publication_sources.items() if path.endswith(".py")}
                findings = [{"filename": "/app/" + gate.DOCKER_SOURCE, "test_id": rule, "issue_severity": "LOW",
                             "line_number": line, "col_offset": 0} for rule, line in (("B404", 10), ("B603", 27))]
            else:
                sources = {"app/main.py": "1" * 64}
            report = {"errors": [], "metrics": {**{"/app/" + path: {} for path in sources}, "_totals": {}}, "results": findings}
            scope["sha256_by_source_path"] = sources
        elif kind == "gitleaks":
            report = []
            scope["source_snapshot_sha256"] = "f" * 64
            if self.binding["operation"] == "bootstrap" and role == "credential_toolchain":
                scope["sha256_by_source_path"] = self.bootstrap_sources
            elif self.binding["operation"] == "oci_publication" and role == "credential_toolchain":
                scope["sha256_by_source_path"] = self.publication_sources
        else:
            scope["components"] = ["reviewed-component"]
            findings = []
            if role == "noble_guest":
                scope["components"] = sorted(gate.KERNEL_MODULES)
                findings = [{"component": module, "version": gate.NOBLE_TARGET["release"], "advisory": cve,
                             "severity": "CRITICAL", "anchor": module} for cve, module in gate.KERNEL_CVES.items()]
            report = {"artifact": artifact, "covered": scope["components"], "findings": findings}
        raw = self.write(prefix + "-native.json", report)
        receipt = self.write(prefix + "-receipt.json", {"kind": kind, "artifact": artifact, "binding": self.binding,
                            "native_sha256": raw["sha256"], "tool_identity": "2" * 64, "tool_version": "fixture",
                            "scope": self.write(prefix + "-scope.json", scope),
                            "db_sha256": "3" * 64 if kind.startswith("trivy_") else None,
                            "db_expires_at": (AT + timedelta(hours=4)).isoformat()})
        return {"kind": kind, "native": raw, "receipt": receipt}

    def verify(self, expected=None, at=AT, runner_version=None, risk_summary=None):
        return gate.verify_review(self.root, self.review, expected or self.binding, at,
                                  runner_version=runner_version, source_root=self.source_root, guest_action=self.guest_action,
                                  risk_summary=risk_summary)

    def test_closed_fixture_is_reviewable_only(self):
        self.assertEqual(self.verify(), 3)

    def test_plan_generation_requires_the_closed_roles_and_no_plan_digest(self):
        self.prepare("plan_generation")
        self.assertEqual(set(self.review["subjects"]), {"api", "noble_guest", "credential_toolchain"})
        self.assertIsNone(self.binding["plan_sha256"])
        self.assertEqual(self.verify(), 4)
        self.binding["plan_sha256"] = "a" * 64
        with self.assertRaisesRegex(ValueError, "wrong_plan_binding_for_operation"):
            self.verify()

    def test_plan_generation_requires_both_locking_and_custody_receipts(self):
        for required in ("native_plan_generation_and_lock", "private_plan_custody"):
            with self.subTest(receipt=required):
                self.prepare("plan_generation")
                del self.review["subjects"]["credential_toolchain"]["checks"][required]
                with self.assertRaisesRegex(ValueError, "checks_incomplete:credential_toolchain"):
                    self.verify()

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

    def test_publication_requires_both_individual_docker_decisions(self):
        findings = self.review["decisions"]
        by_rule = {row["finding"]["advisory"]: row for row in findings.values() if row["finding"]["component"] == gate.DOCKER_SOURCE}
        self.assertEqual(set(by_rule), {"B404", "B603"})
        by_rule["B603"]["evidence"] = by_rule["B404"]["evidence"]
        with self.assertRaisesRegex(ValueError, "unbound_control_evidence"):
            self.verify()

    def test_publication_bandit_cannot_drop_a_docker_row_after_runner_rotation(self):
        self.assertEqual(self.verify(runner_version="20261121.1.2"), 3)
        scan = next(item for item in self.review["subjects"]["credential_toolchain"]["analyses"] if item["kind"] == "bandit")
        report = gate.evidence(self.root, scan["native"])
        report["results"].pop()
        receipt = gate.evidence(self.root, scan["receipt"])
        scan["native"] = self.write("bandit-omitted-native.json", report)
        receipt["native_sha256"] = scan["native"]["sha256"]
        scan["receipt"] = self.write("bandit-omitted-receipt.json", receipt)
        with self.assertRaisesRegex(ValueError, "publication_docker_sast_findings_missing"):
            self.verify()

    def test_publication_rehearsal_must_come_from_observed_host(self):
        subject = self.review["subjects"]["credential_toolchain"]
        proof = gate.evidence(self.root, subject["publication"])
        lab = gate.evidence(self.root, proof["rehearsal"])
        lab["boot_id"] = "99999999-8888-7777-6666-555555555555"
        proof["rehearsal"] = self.write("other-host-rehearsal.json", lab)
        subject["publication"] = self.write("other-host-publication.json", proof)
        with self.assertRaisesRegex(ValueError, "publication_rehearsal_receipt_unbound"):
            self.verify()

    def test_publication_cannot_claim_projection_or_preparation_from_other_bytes(self):
        subject = self.review["subjects"]["credential_toolchain"]
        proof = gate.evidence(self.root, subject["publication"])
        subject["publication"] = self.write("foreign-projection.json", {**proof, "docker_projection_sha256": "4" * 64})
        with self.assertRaisesRegex(ValueError, "publication_runner_or_artifact_mismatch"):
            self.verify()
        prepared = gate.evidence(self.root, proof["preparation"])
        prepared["oidc_job_capability"] = True
        proof["preparation"] = self.write("credentialed-preparation.json", prepared)
        subject["publication"] = self.write("foreign-preparation.json", proof)
        with self.assertRaisesRegex(ValueError, "publication_preparation_receipt_unbound"):
            self.verify()

    def test_publication_rehearsal_requires_exact_reviewed_source(self):
        subject = self.review["subjects"]["credential_toolchain"]
        proof = gate.evidence(self.root, subject["publication"])
        source = gate.evidence(self.root, proof["sources"])
        del source["files"][gate.PUBLISHER_LAB_SOURCE]
        foreign = {**proof, "sources": self.write("without-rehearsal-source.json", source)}
        subject["publication"] = self.write("without-rehearsal-publication.json", foreign)
        with self.assertRaisesRegex(ValueError, "missing_publication_source"):
            self.verify()
        lab = gate.evidence(self.root, proof["rehearsal"])
        lab["source_sha256"] = "a" * 64
        foreign = {**proof, "rehearsal": self.write("other-tool-rehearsal.json", lab)}
        subject["publication"] = self.write("other-tool-publication.json", foreign)
        with self.assertRaisesRegex(ValueError, "publication_rehearsal_source_mismatch"):
            self.verify()

    def test_hosted_runner_high_row_is_informational_without_a_finding_decision(self):
        subject = self.review["subjects"]["credential_toolchain"]
        entry = self.analysis("credential_toolchain", subject["identity"], "trivy_toolchain", high=True)
        report = gate.evidence(self.root, entry["native"])
        report["Results"][0]["Vulnerabilities"][0]["VulnerabilityID"] = "CVE-2026-81010"
        receipt = gate.evidence(self.root, entry["receipt"])
        entry["native"] = self.write("unresolved-native-attribution.json", report)
        receipt["native_sha256"] = entry["native"]["sha256"]
        entry["receipt"] = self.write("unresolved-native-receipt.json", receipt)
        subject["analyses"][0] = entry
        summary = {}
        self.assertEqual(self.verify(risk_summary=summary), 3)
        self.assertEqual(summary, {"hosted_runner_findings_informational": 1,
                                  "runner_risk_acceptance_sha256": gate.runner_risk.CONFIG_SHA256})

    def test_unknown_runner_severity_and_noncredential_toolchains_still_block(self):
        subject = self.review["subjects"]["credential_toolchain"]
        entry = self.analysis("credential_toolchain", subject["identity"], "trivy_toolchain", high=True)
        report = gate.evidence(self.root, entry["native"])
        report["Results"][0]["Vulnerabilities"][0]["Severity"] = "UNKNOWN"
        receipt = gate.evidence(self.root, entry["receipt"])
        entry["native"] = self.write("unknown-runner-native.json", report)
        receipt["native_sha256"] = entry["native"]["sha256"]
        entry["receipt"] = self.write("unknown-runner-receipt.json", receipt)
        subject["analyses"][0] = entry
        with self.assertRaisesRegex(ValueError, "native_image_threshold:credential_toolchain"):
            self.verify()

        self.prepare("oci_publication")
        subject = self.review["subjects"]["artifact_builder"]
        subject["analyses"][0] = self.analysis("artifact_builder", subject["identity"], "trivy_toolchain", high=True)
        with self.assertRaisesRegex(ValueError, "native_image_threshold:artifact_builder"):
            self.verify()

    def test_guest_admission_requires_action_and_does_not_certify_mitigation(self):
        self.prepare("guest_intervention", guest_action="apt_upgrade")
        self.assertEqual(self.verify(runner_version="20261120.1.2"), 3)
        self.assertEqual({d["disposition"] for d in self.review["decisions"].values()}, {"remediation_preflight_verified"})
        self.assertEqual(self.verify(runner_version="20261121.1.2"), 3)
        self.guest_action = "kmod_apply"
        with self.assertRaisesRegex(ValueError, "guest_control_binding_or_freshness"):
            self.verify()
        self.guest_action = None
        with self.assertRaisesRegex(ValueError, "requested_guest_action_mismatch"):
            self.verify()

    def test_bootstrap_requires_both_real_receipts_and_after_alias_control(self):
        self.prepare("bootstrap")
        subject = self.review["subjects"]["noble_guest"]
        control = gate.evidence(self.root, subject["guest_control"])

        def check_changed(value, reason):
            subject["guest_control"] = self.write("modified-guest-control.json", value)
            subject["identity"] = "sha256:" + subject["guest_control"]["sha256"]
            with self.assertRaisesRegex(ValueError, reason):
                gate.verify_guest_control(self.root, subject, self.binding, AT, None)

        check_changed({**control, "kmod_receipt": None}, "guest_intervention_predecessors_missing")
        kmod = gate.evidence(self.root, control["kmod_receipt"])
        kmod["guest_receipt"]["after"]["kmod"]["dry_run"]["ceph"]["aliases"] = ["would_insert"]
        check_changed({**control, "kmod_receipt": self.write("modified-kmod.json", kmod)}, "guest_kmod_name_or_alias_unverified")

    def test_kernel_conclusion_preserves_individual_residual_and_boot(self):
        self.prepare("bootstrap")
        row = next(d for d in self.review["decisions"].values() if d["finding"]["advisory"] == "CVE-2026-99310")
        proof = gate.evidence(self.root, row["evidence"])
        self.assertEqual(proof["residual"], gate.KMOD_RESIDUAL)
        row["evidence"] = self.write("residual-missing.json", {**proof, "residual": []})
        with self.assertRaisesRegex(ValueError, "unbound_control_evidence"):
            self.verify()

    def test_plan_change_invalidates_the_review(self):
        self.prepare("locked_plan_apply")
        with self.assertRaisesRegex(ValueError, "wrong_demo_operation_binding"):
            self.verify(expected={**self.binding, "plan_sha256": "0" * 64})

    def test_guest_precedes_secrets_and_plan(self):
        self.prepare("guest_safety")
        self.assertIsNone(self.binding["plan_sha256"])
        self.assertNotIn("api", self.review["subjects"])
        self.assertEqual(self.verify(), 3)
        self.binding["plan_sha256"] = "e" * 64
        with self.assertRaisesRegex(ValueError, "wrong_plan_binding_for_operation"):
            self.verify()

    def test_secret_versions_validate_each_runner_record_without_cross_job_equality(self):
        self.prepare("secret_versions")
        self.verify(runner_version="20261120.1.2")
        self.verify(runner_version="20261121.1.2")
        checks = self.review["subjects"]["credential_toolchain"]["checks"]
        name = "secret_target_and_version_receipt_protocol"
        old_receipt = gate.evidence(self.root, checks[name])
        del old_receipt["runner_image"]
        checks[name] = self.write("old-secret-check.json", old_receipt)
        with self.assertRaisesRegex(ValueError, "check_proof_fields"):
            self.verify()

    def test_after_apply_requires_its_actual_reconciliation(self):
        self.prepare("migration_job")
        self.assertEqual(self.verify(), 3)
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

    def test_bootstrap_allows_runner_rotation_but_requires_the_reviewed_source(self):
        self.prepare("bootstrap")
        self.assertEqual(self.verify(runner_version="fixture-runner-1"), 3)
        self.assertEqual(self.verify(runner_version="20261124.2.1"), 3)
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
            gate.verify_sources(self.source_root, self.bootstrap_sources, gate.REQUIRED_BOOTSTRAP_SOURCES, "bootstrap")

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
        verify = gate.verify_review
        with redirect_stdout(stdout), patch.object(gate, "datetime", wraps=datetime) as clock, \
                patch.object(gate, "verify_review", side_effect=lambda *args, **kwargs: verify(*args, **kwargs, source_root=self.source_root)):
            clock.now.return_value = AT
            result = gate.main(["--review", str(self.root / review["path"]), "--review-sha256", review["sha256"],
                                "--binding", str(self.root / binding["path"]), "--operation", "oci_publication"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(stdout.getvalue()), {"status": "coverage_ready_for_owner_review",
                         "operation": "oci_publication", "findings_bound": 3,
                         "hosted_runner_findings_informational": 0,
                         "runner_risk_acceptance_sha256": gate.runner_risk.CONFIG_SHA256,
                         "activation_authorized": False})


if __name__ == "__main__":
    unittest.main()
