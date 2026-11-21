"""Fail-closed offline review of the exact INT Demo A scope. Cannot authorize mutations."""
from argparse import ArgumentParser
import ast
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path, PurePosixPath
import re
from stat import S_ISREG


SCHEMA = "clipforge-int-demo-a-review-1"
BOUNDARY = {"project": "clipforgebeta2", "repository": "AldemaroCruz/ClipForge",
            "branch": "ci/bootstrap-sec03", "environment": "int", "profile": "demo-a",
            "instance_id": "7365414160255801909", "data_disk_id": "7382984635240536620"}
OPERATION_ROLES = {
    "guest_safety": {"noble_guest", "credential_toolchain"},
    "guest_intervention": {"noble_guest", "credential_toolchain"},
    "bootstrap": {"noble_guest", "credential_toolchain"},
    "human_sql_access": {"noble_guest", "personal_windows"},
    "secret_versions": {"credential_toolchain"},
    "oci_publication": {"api", "migration_client", "artifact_builder", "attestation_toolchain", "demo_tests", "credential_toolchain"},
    "plan_generation": {"api", "noble_guest", "credential_toolchain"},
    "locked_plan_apply": {"api", "noble_guest", "credential_toolchain"},
    "migration_job": {"migration_client", "noble_guest", "credential_toolchain"},
    "admin_job": {"api", "noble_guest", "credential_toolchain"},
    "api_demo": {"api", "noble_guest", "demo_tests", "credential_toolchain"},
}
POST_APPLY = {"migration_job", "admin_job", "api_demo"}
PLAN_BOUND = {"locked_plan_apply"} | POST_APPLY
CREDENTIAL_CHECKS = {
    "guest_safety": ("guest_package_scope_and_recovery",),
    "guest_intervention": ("guest_package_scope_and_recovery", "exact_guest_intervention_transport"),
    "bootstrap": ("controlled_bootstrap_and_stop", "scoped_iam_and_protected_inputs"),
    "secret_versions": ("secret_target_and_version_receipt_protocol",),
    "oci_publication": ("oci_bytes_before_wif", "registry_digest_and_custody", "pinned_docker_engine_runner"),
    "plan_generation": ("native_plan_generation_and_lock", "private_plan_custody"),
    "locked_plan_apply": ("native_plan_exact_and_locking",),
    "migration_job": ("pinned_job_identity_and_numeric_secrets",),
    "admin_job": ("pinned_admin_identity_and_protected_input",),
    "api_demo": ("iap_identity_and_revision",),
}
# Roles are fixed by the profile, independent of the reports a producer sends.
ROLES = {
    "api": (("trivy_oci", "bandit"), ("context_and_layers", "media_capability_closed", "frontend_session_sql")),
    "migration_client": (("trivy_oci", "bandit"), ("dependency_closure", "migrations_tls_identity")),
    "noble_guest": (("trivy_guest", "supplemental"), ("live_boot_packages", "kernel_coverage_and_controls")),
    "demo_tests": (("trivy_toolchain",), ("exact_candidate_contract", "browser_sql_negative_paths", "no_wif_or_secrets")),
    "artifact_builder": (("trivy_toolchain", "bandit", "gitleaks"), ("build_graph", "apt_wheels_model_hashes", "no_wif_or_secrets")),
    "attestation_toolchain": (("trivy_toolchain",), ("scanner_provenance_and_db", "inventory_is_independent")),
    "credential_toolchain": (("trivy_toolchain", "bandit", "gitleaks"), ("exact_runner_executables_actions", "isolated_credential_scope")),
    "personal_windows": (("supplemental",), ("human_iam_iap_oslogin", "trusted_client_versions", "strict_loopback_tls")),
}
LEGACY_IMAGES = {
    "legacy_ci_app": "sha256:ee408c5d0109a8bcc6a706124f27d2a63e19c82f1652cbb7ee9cefc11dc685b4",
    "legacy_ci_browser": "sha256:2298cf2cb4cc02134881533a93501d4eb6743332342b39535e3c0ad4839c9781",
    "legacy_ci_postgres": "sha256:8bca9649e52d948114ccc8164b55b7ab26b64e729893e420114bb5c87bf7c7cc",
}
LEGACY_RUN = {
    "run_id": 44790312930,
    "commit": "3ec6603ab7b9117a2c5b9c9fc1259a53547bc08a",
    "archive_sha256": "58035fcd30f7c3d15f5987e0e9c251eaae6ad91cc4b5da941a4321ed679780e6",
}
LEGACY_CONTROLS = {"bandit", "trivy", "browser-trivy", "postgres_trivy"}
HEX = re.compile(r"[0-9a-f]{64}")
GIT = re.compile(r"[0-9a-f]{40}")
SEVERITY = {"UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"}
MAX_RECORD = 32 * 1024 * 1024
BOOTSTRAP_TOOL_PINS = {
    "checkout": "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
    "download_artifact": "actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333",
    "setup_gcloud": "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
    "google_auth": "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
    "upload_artifact": "actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9",
    "gcloud": "582.0.0",
}
BOOTSTRAP_TOOL_ROLES = set(BOOTSTRAP_TOOL_PINS) | {"runner_image", "node", "python", "ssh", "ssh_keygen", "ca_bundle", "bootstrap_sources"}
BOOTSTRAP_WORKFLOW = ".github/workflows/int-db01-noble-bootstrap.yml"
REQUIRED_BOOTSTRAP_SOURCES = {
    BOOTSTRAP_WORKFLOW, "scripts/check_int_demo_a.py", "scripts/int_noble_bootstrap_db.py",
    "scripts/int_bootstrap_containment.py", "scripts/int_guest_inventory.py", "scripts/int_noble_first_observation.py",
    "scripts/int_demo_a_noble_policy.py", "config/int-demo-a-noble-policy.json",
}
PUBLICATION_WORKFLOW = ".github/workflows/int-demo-a-publish.yml"
DOCKER_SOURCE = "scripts/int_demo_a_docker.py"
PUBLICATION_SOURCES = {PUBLICATION_WORKFLOW, DOCKER_SOURCE, "scripts/int_demo_a_publish.py", "scripts/check_int_demo_a.py",
                       "scripts/int_demo_a_preflight.py", "scripts/int_demo_a_receipts.py"}
DOCKER_BINARIES = {"/usr/bin/docker", "/usr/bin/dockerd", "/usr/bin/containerd", "/usr/bin/containerd-shim-runc-v2", "/usr/bin/runc"}
DOCKER_SAST_CONTROLS = {"B404": "subprocess_import_bounded_by_reviewed_callers",
                        "B603": "fixed_argv_absolute_tools_pinned_local_daemon"}
NOBLE_TARGET = {"instance_id": BOUNDARY["instance_id"], "data_disk_id": BOUNDARY["data_disk_id"],
                "boot_disk_id": "8897353356069952044", "boot_id": "e1a4fb53-1970-490b-af37-5cccbbc99f32", "release": "7.0.0-1017-gcp"}
KERNEL_CVES = {"CVE-2026-99287": "xen_netback", "CVE-2026-99306": "ceph", "CVE-2026-99310": "nfsd"}
KERNEL_MODULES = set(KERNEL_CVES.values())
KMOD_RESIDUAL = ["direct_privileged_load", "install_rule_bypass", "initramfs_or_early_boot"]
KMOD_RULE_SHA = "4bf91a0780473f141bef96afec377c7f7d627fc4b207137544b7dd4bee034784"
APT_DEB_SHA = "953d51879d4690a59138d9f2ec933bd703c928d75c4448681a7880d323bc7579"
APT_SIGNED_INDEX_SHA = "c804e534950988a2af91a14e2d74a0f530b5458ba0354a8cbb61c68aeab3797e"
APT_CVES = {"CVE-2026-63825", "CVE-2026-64523", "CVE-2026-68426", "CVE-2026-90162", "CVE-2026-93221"}
GUEST_ACTIONS = ("apt_upgrade", "kmod_apply", "kmod_withdraw")
GUEST_BASELINES = {
    "consumers": ("44838313764", "demo-kernel-consumers", "46733606340d570b2fead7e1cab98f611417e433650a354c662bd9c68bc584eb",
                  "892c4444043d8bef1601be98b6cfd6990ba6b62a4035059432ae5e016d517ab1"),
    "readiness": ("44801426463", "demo-readiness", "63406f8a35d85e89ae83dacc437e76e922dd19b58eb820716ae5251df930000f",
                  "e69e99a1bf5dddf7bd918f6e0a2c7238d1f154f693c7a0978540bf95d219b797"),
}
REPO = Path(__file__).resolve().parents[1]


def role_contract(operation, role):
    analyses, checks = ROLES[role]
    return analyses, checks + (CREDENTIAL_CHECKS[operation] if role == "credential_toolchain" else ())


def require(condition, code):
    if not condition:
        raise ValueError(code)


def exact(value, fields, code):
    require(isinstance(value, dict) and set(value) == set(fields.split()), code)
    return value


def digest(raw):
    return sha256(raw).hexdigest()


def closed(raw):
    def no_duplicates(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result, "duplicate_json_key")
            result[key] = value
        return result
    def invalid_constant(_value):
        raise ValueError("non_json_constant")
    return json.loads(raw, object_pairs_hook=no_duplicates, parse_constant=invalid_constant)


def utc(value):
    value = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(value.utcoffset() == timezone.utc.utcoffset(None), "expected_utc")
    return value


def local_regular(path):
    info = path.lstat()
    require(S_ISREG(info.st_mode) and not (getattr(info, "st_file_attributes", 0) & 0x400)
            and 0 < info.st_size <= MAX_RECORD, "not_bounded_regular_file")
    with path.open("rb") as stream:
        raw = stream.read(info.st_size + 1)
    require(len(raw) == info.st_size, "evidence_changed_while_reading")
    return raw


def evidence(root, ref):
    exact(ref, "path sha256", "evidence_reference_fields")
    rel = PurePosixPath(ref["path"])
    require(not rel.is_absolute() and 0 < len(rel.parts) <= 6 and
            all(re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9._-]*", part) for part in rel.parts)
            and HEX.fullmatch(ref["sha256"]), "unsafe_evidence_reference")
    path = root.joinpath(*rel.parts)
    require(path.resolve() == path and path.is_relative_to(root), "indirect_evidence_reference")
    raw = local_regular(path)
    require(digest(raw) == ref["sha256"], "evidence_digest_mismatch")
    return closed(raw)


def identities(report):
    targets = {}
    for target in report["Results"]:
        key = target["Target"]
        require(key not in targets and target["Packages"], "missing_or_duplicate_trivy_target")
        rows = [package["Identifier"]["PURL"] for package in target["Packages"]]
        require(len(rows) == len(set(rows)) and all(value.startswith("pkg:") for value in rows), "incomplete_package_identity")
        targets[key] = sorted(rows)
    require(targets, "missing_trivy_targets")
    return targets


def finding(role, artifact, kind, component, version, advisory, severity, anchor, evidence_sha):
    require(severity in SEVERITY and all(isinstance(v, str) and 0 < len(v) < 400 for v in
                                       (component, version, advisory, anchor)), "incomplete_native_finding")
    row = {"role": role, "artifact": artifact, "kind": kind, "component": component, "version": version,
           "advisory": advisory, "severity": severity, "anchor": anchor, "native_sha256": evidence_sha}
    key = digest(json.dumps(row, sort_keys=True, separators=(",", ":")).encode("utf-8"))
    return key, row


def native_rows(root, role, artifact, binding, record, at):
    exact(record, "kind native receipt", "analysis_fields")
    kind = record["kind"]
    report = evidence(root, record["native"])
    receipt = evidence(root, record["receipt"])
    exact(receipt, "kind artifact binding native_sha256 tool_identity tool_version scope db_sha256 db_expires_at",
          "scan_receipt_fields")
    sha = record["native"]["sha256"]
    require(receipt["kind"] == kind and receipt["artifact"] == artifact and receipt["binding"] == binding
            and receipt["native_sha256"] == sha and HEX.fullmatch(receipt["tool_identity"])
            and isinstance(receipt["tool_version"], str) and receipt["tool_version"].strip(), "scan_identity_mismatch")
    scope = evidence(root, receipt["scope"])
    require(scope["artifact"] == artifact and scope["kind"] == kind, "independent_scope_mismatch")
    if kind.startswith("trivy_"):
        require(report["SchemaVersion"] == 2 and HEX.fullmatch(receipt["db_sha256"] or "")
                and utc(receipt["db_expires_at"]) > at, "trivy_db_or_report_invalid")
        if kind == "trivy_oci":
            require(artifact.startswith("sha256:") and report["Metadata"]["ImageID"] == scope["oci_config"], "wrong_oci_config")
            require(report["Metadata"]["DiffIDs"] == scope["oci_diff_ids"], "wrong_oci_layers")
        require(identities(report) == scope["targets"], "trivy_inventory_mismatch")
        for target in report["Results"]:
            for row in target.get("Vulnerabilities", []):
                package = row["PkgIdentifier"]["PURL"]
                require(package in scope["targets"][target["Target"]], "trivy_unbound_finding")
                yield finding(role, artifact, kind, package, row["InstalledVersion"], row["VulnerabilityID"],
                              row["Severity"], target["Target"] + ":" + row["Fingerprint"], sha)
    elif kind == "bandit":
        files = scope["sha256_by_source_path"]
        require(not report["errors"] and files and all(HEX.fullmatch(v) for v in files.values()), "bandit_coverage_incomplete")
        scanned = {name.removeprefix("/app/") for name in report["metrics"] if name != "_totals"}
        require(scanned == set(files), "bandit_source_closure_mismatch")
        for row in report["results"]:
            name = row["filename"].removeprefix("/app/")
            yield finding(role, artifact, kind, name, files[name], row["test_id"], row["issue_severity"],
                          f"{row['line_number']}:{row['col_offset']}", sha)
    elif kind == "gitleaks":
        require(scope["source_snapshot_sha256"] and HEX.fullmatch(scope["source_snapshot_sha256"])
                and isinstance(report, list), "gitleaks_snapshot_missing")
        require(not report, "gitleaks_finding_blocks")
    else:
        require(kind == "supplemental" and report["artifact"] == artifact and report["covered"] == scope["components"]
                and scope["components"], "supplemental_coverage_mismatch")
        for row in report["findings"]:
            exact(row, "component version advisory severity anchor", "supplemental_finding_fields")
            require(row["component"] in scope["components"], "supplemental_unbound_finding")
            yield finding(role, artifact, kind, row["component"], row["version"], row["advisory"],
                          row["severity"], row["anchor"], sha)


def verify_sources(source_root, rows, required, scope):
    require(isinstance(rows, dict) and required <= set(rows), "missing_" + scope + "_source")
    for name, expected in rows.items():
        require(re.fullmatch(r"(?:\.github/workflows/[a-z0-9-]+\.yml|scripts/[a-z0-9_]+\.py|config/[a-z0-9-]+\.json)", name)
                and HEX.fullmatch(expected), "invalid_" + scope + "_source")
        path = source_root / name
        require(path.resolve() == path, "changed_" + scope + "_source")
        raw = local_regular(path)
        require(digest(raw) == expected, "changed_" + scope + "_source")
        if path.suffix == ".py":
            for statement in ast.walk(ast.parse(raw, filename=name)):
                imports = []
                if isinstance(statement, ast.Import):
                    imports = [item.name for item in statement.names]
                if isinstance(statement, ast.ImportFrom):
                    imports = (["scripts." + item.name for item in statement.names] if statement.module == "scripts"
                               else [statement.module or ""])
                for module in imports:
                    if module.startswith("scripts."):
                        imported = module.replace(".", "/") + ".py"
                        require(imported in rows, "missing_" + scope + "_import")


def verify_bootstrap_toolchain(root, subject, binding, at, runner_version, source_root, entrypoint):
    chain = subject["toolchain"]
    value = exact(evidence(root, chain), "binding components", "toolchain_scope_fields")
    require(subject["identity"] == "sha256:" + chain["sha256"] and value["binding"] == binding,
            "toolchain_identity_mismatch")
    require(set(value["components"]) == BOOTSTRAP_TOOL_ROLES, "bootstrap_toolchain_components_incomplete")
    trivy = next(item for item in subject["analyses"] if item["kind"] == "trivy_toolchain")
    receipt = evidence(root, trivy["receipt"])
    inventory = evidence(root, receipt["scope"])
    scan_scopes = {item["kind"]: evidence(root, evidence(root, item["receipt"])["scope"]) for item in subject["analyses"]}
    expected_targets = set(inventory["targets"])
    covered = set()
    for role, component in value["components"].items():
        exact(component, "source version sha256 targets evidence", "toolchain_component_fields")
        require(isinstance(component["source"], str) and bool(component["source"].strip())
                and isinstance(component["version"], str) and bool(component["version"].strip())
                and HEX.fullmatch(component["sha256"]), "incomplete_bootstrap_tool:" + role)
        if role in BOOTSTRAP_TOOL_PINS:
            field = "version" if role == "gcloud" else "source"
            require(component[field] == BOOTSTRAP_TOOL_PINS[role], "changed_pinned_bootstrap_tool:" + role)
        elif role == "runner_image":
            require(component["source"] == "github-hosted:ubuntu-24.04" and
                    (runner_version is None or component["version"] == runner_version), "runner_image_mismatch")
        targets = component["targets"]
        require(isinstance(targets, list) and targets and len(targets) == len(set(targets))
                and set(targets) <= expected_targets, "toolchain_component_coverage_missing:" + role)
        proof = evidence(root, component["evidence"])
        fields = "binding component source version sha256 targets checked_at expires_at"
        if role == "bootstrap_sources":
            fields += " files"
        exact(proof, fields, "toolchain_component_receipt_fields")
        expected = {"binding": binding, "component": role, **{key: component[key] for key in ("source", "version", "sha256", "targets")}}
        require({key: proof[key] for key in expected} == expected, "toolchain_component_receipt_mismatch:" + role)
        require(utc(proof["checked_at"]) <= at < utc(proof["expires_at"]), "toolchain_component_receipt_expired:" + role)
        if role == "bootstrap_sources":
            require(component["source"] == "reviewed-checkout" and component["version"] == binding["source_commit"]
                    and component["sha256"] == digest(json.dumps(proof["files"], sort_keys=True, separators=(",", ":")).encode()),
                    "bootstrap_source_manifest_mismatch")
            verify_sources(source_root, proof["files"], REQUIRED_BOOTSTRAP_SOURCES, "bootstrap")
            files = proof["files"]
            require(files[BOOTSTRAP_WORKFLOW] == entrypoint, "bootstrap_promotion_entrypoint_mismatch")
            bandit_sources = scan_scopes["bandit"]["sha256_by_source_path"]
            gitleaks_sources = scan_scopes["gitleaks"]["sha256_by_source_path"]
            require(all(bandit_sources.get(name) == sha for name, sha in files.items() if name.endswith(".py")),
                    "bootstrap_bandit_scope_missing")
            require(all(gitleaks_sources.get(name) == sha for name, sha in files.items()), "bootstrap_gitleaks_scope_missing")
        covered.update(targets)
    require(covered == expected_targets, "toolchain_scan_targets_unbound")


def verify_publication_sources(root, subject, binding, source_root, entrypoint, runner_version):
    proof = exact(evidence(root, subject["publication"]), "binding sources docker_runtime docker_targets", "publication_scope_fields")
    runtime_ref = proof["docker_runtime"]
    runtime = exact(evidence(root, runtime_ref), "schema runner_image image_os socket files native components engine_settings kernel",
                    "publication_docker_receipt_fields")
    require(proof["binding"] == binding and subject["identity"] == "sha256:" + runtime_ref["sha256"]
            and runtime["schema"] == "clipforge-int-demo-a-docker-toolchain-2" and runtime["image_os"] == "ubuntu24"
            and runtime["socket"] == "/run/docker.sock" and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", runtime["runner_image"])
            and (runner_version is None or runtime["runner_image"] == runner_version), "publication_runner_or_artifact_mismatch")
    require(set(runtime["files"]) == DOCKER_BINARIES and set(runtime["native"]) == {"client", "server"}
            and {"Engine", "containerd", "runc"} <= set(runtime["components"])
            and all(row["path"].startswith("/usr/bin/") and HEX.fullmatch(row["sha256"]) and type(row["bytes"]) is int and row["bytes"] > 0
                    for row in runtime["files"].values())
            and runtime["kernel"]["package"] == "linux-image-" + runtime["kernel"]["release"]
            and runtime["kernel"]["version"], "publication_docker_or_kernel_closure")
    manifest = exact(evidence(root, proof["sources"]), "binding files", "publication_source_manifest_fields")
    files = manifest["files"]
    require(manifest["binding"] == binding, "publication_source_manifest_mismatch")
    verify_sources(source_root, files, PUBLICATION_SOURCES, "publication")
    require(files[PUBLICATION_WORKFLOW] == entrypoint, "publication_promotion_entrypoint_mismatch")
    scopes = {row["kind"]: evidence(root, evidence(root, row["receipt"])["scope"]) for row in subject["analyses"]}
    require(all(scopes["bandit"]["sha256_by_source_path"].get(name) == sha for name, sha in files.items() if name.endswith(".py"))
            and all(scopes["gitleaks"]["sha256_by_source_path"].get(name) == sha for name, sha in files.items()),
            "publication_source_scan_closure_missing")
    trivy = scopes["trivy_toolchain"]
    targets = proof["docker_targets"]
    require(set(targets) == DOCKER_BINARIES | {"runner_kernel"} and trivy["docker_targets"] == targets
            and trivy["docker_toolchain_sha256"] == runtime_ref["sha256"]
            and all(isinstance(names, list) and names and len(names) == len(set(names)) and set(names) <= set(trivy["targets"])
                    for names in targets.values()), "publication_docker_inventory_not_bound_to_scan")
    raw = local_regular(source_root / DOCKER_SOURCE)
    require(digest(raw) == files[DOCKER_SOURCE], "changed_publication_source")
    docker = ast.parse(raw, filename=DOCKER_SOURCE)
    rules = set()
    if any(isinstance(node, ast.Import) and any(name.name == "subprocess" for name in node.names) for node in ast.walk(docker)):
        rules.add("B404")
    if any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name)
           and node.func.value.id == "subprocess" and node.func.attr == "run" for node in ast.walk(docker)):
        rules.add("B603")
    return rules


def guest_baseline(root, baseline, binding):
    require(set(baseline) == set(GUEST_BASELINES), "guest_baseline_sources_missing")
    values = {}
    for key, (run, scope, inventory_sha, summary_sha) in GUEST_BASELINES.items():
        refs = exact(baseline[key], "inventory summary", "guest_baseline_reference_fields")
        require(refs["inventory"]["sha256"] == inventory_sha and refs["summary"]["sha256"] == summary_sha,
                "guest_baseline_source_mismatch")
        inventory, summary = (evidence(root, refs[name]) for name in ("inventory", "summary"))
        plane = inventory["control_plane"]
        require(inventory["schema"] == "clipforge-int-noble-kernel-observation-receipt-1"
                and inventory["runtime_authorized"] is False and inventory["risk_accepted"] is False
                and summary["schema"] == "clipforge-int-noble-kernel-observation-summary-1"
                and summary["observation_run_id"] == run and summary["scope"] == scope
                and summary["status"] == "observation_complete" and summary["guest_exit_code"] == 0
                and summary["cleanup"]["status"] in {"own_key_removed", "key_already_absent"}
                and summary["controls_commit"] == inventory["controls_commit"] and summary["inventory_sha256"] == inventory_sha
                and summary["control_plane"] == plane and binding["instance_id"] == plane["instance_id"] == NOBLE_TARGET["instance_id"]
                and binding["data_disk_id"] == plane["data_disk_id"] == NOBLE_TARGET["data_disk_id"]
                and plane["boot_disk_id"] == NOBLE_TARGET["boot_disk_id"], "guest_baseline_identity_mismatch")
        values[key] = inventory
    before, earlier = values["consumers"]["guest"], values["readiness"]["guest"]
    kernel, xen, ceph, kmod = (before[key] for key in ("kernel", "xen", "ceph", "kmod"))
    require(values["consumers"]["control_plane"] == values["readiness"]["control_plane"]
            and all(kernel[key] == earlier[key] == NOBLE_TARGET[key] for key in ("boot_id", "release")), "guest_baseline_boot_mismatch")
    require(earlier["exports"] == {"active_count": 0, "configured_count": 0, "nfsd_mounts": 0, "host_mount_namespace": True,
                                   "registered_filesystem": False, "module_loaded": False, "state": "server_unregistered_in_host_mount_namespace"}
            and kernel["exports"] == {"active": None, "configured": 0}, "guest_nfs_exports_not_attributed")
    require(kernel["virtualization"] == "google" and xen == {"private_nic_driver": "virtio_net", "backend_vifs": 0}
            and all(type(ceph[key]) is int and ceph[key] == 0 for key in ("pid1_mounts", "fstab_mounts", "named_processes", "pid1_canonical_remote_sockets"))
            and ceph["packages"] == dict.fromkeys(("ceph-common", "ceph-fuse", "libcephfs2", "rbd-nbd"), False)
            and ceph["data_disk_relation"] == "expected_device_unmounted", "guest_consumer_baseline_indeterminate")
    require(kmod["scope_rule"] == "absent" and kmod["helper"] == "standard" and kmod["modules_disabled"] is False
            and kmod["boot_blacklist"] == dict.fromkeys(KERNEL_MODULES, False)
            and kernel["modules"] == dict.fromkeys(KERNEL_MODULES, {"disk": "module_file", "loaded": False, "sysfs": False})
            and kernel["autoload"]["modules_load"] == dict.fromkeys(KERNEL_MODULES, 0)
            and set(kmod["dry_run"]) == KERNEL_MODULES and all(row["direct"] == "would_insert" and row["aliases"]
                and all(item == "would_insert" for item in row["aliases"]) for row in kmod["dry_run"].values()),
            "guest_kmod_baseline_indeterminate")
    return before, values["consumers"]["control_plane"]


def guest_result(root, ref, action, plane):
    receipt = evidence(root, ref)
    require(receipt["schema"] == "clipforge-int-noble-intervention-result-1" and receipt["status"] == "completed_verified"
            and receipt["action"] == action and GIT.fullmatch(receipt["control_commit"]) and HEX.fullmatch(receipt["decision_sha256"])
            and re.fullmatch(r"[0-9a-f]{32}", receipt["operation_id"]) and type(receipt["native_exit"]) is int and receipt["native_exit"] == 0
            and receipt["runtime_authorized"] is False and receipt["cleanup"]["status"] in {"own_key_removed", "key_already_absent"}
            and receipt["control_plane"] == plane
            and receipt["snapshot_sha256"] == digest(json.dumps(plane, sort_keys=True, separators=(",", ":")).encode())
            and isinstance(receipt["intent"], dict) and HEX.fullmatch(receipt["intent"]["sha256"]), "guest_intervention_receipt_mismatch")
    native = receipt["guest_receipt"]
    require(native["operation_id"] == "int-noble-" + receipt["operation_id"] and native["approved_commit"] == receipt["control_commit"]
            and all(native[key] == NOBLE_TARGET[key] for key in ("instance_id", "data_disk_id", "boot_disk_id", "boot_id"))
            and HEX.fullmatch(native["intent_sha256"]), "guest_native_receipt_identity_mismatch")
    return receipt, native


def verify_guest_control(root, subject, binding, at, guest_action):
    ref = subject["guest_control"]
    control = exact(evidence(root, ref), "binding action baseline apt_receipt kmod_receipt checked_at expires_at", "guest_control_fields")
    action = guest_action if binding["operation"] == "guest_intervention" else ("review" if binding["operation"] == "guest_safety" else "continue")
    require(control["binding"] == binding and control["action"] == action and subject["identity"] == "sha256:" + ref["sha256"]
            and utc(control["checked_at"]) <= at < utc(control["expires_at"]), "guest_control_binding_or_freshness")
    before, plane = guest_baseline(root, control["baseline"], binding)
    apt_needed = action in {"kmod_apply", "kmod_withdraw", "continue"}
    kmod_needed = action in {"kmod_withdraw", "continue"}
    require((control["apt_receipt"] is not None) == apt_needed and (control["kmod_receipt"] is not None) == kmod_needed,
            "guest_intervention_predecessors_missing")
    if apt_needed:
        apt, package = guest_result(root, control["apt_receipt"], "apt_upgrade", plane)
        checks = package["postcheck"]
        require(package["schema"] == "clipforge-int-noble-apt-receipt-1" and package["status"] == "updated_exact_package"
                and package["kernel"] == NOBLE_TARGET["release"] and package["package"] == "linux-tools-common"
                and package["owner_decision_sha256"] == apt["decision_sha256"] and package["package_sha256"] == APT_DEB_SHA
                and package["signed_index_sha256"] == APT_SIGNED_INDEX_SHA
                and package["simulation"]["exact_upgrade"] is True and package["download_verified"] is True and package["launch_intent"] is True
                and package["temp_released"] is True and checks["installed"] == "6.8.0-151.151"
                and all(checks[key] is True for key in ("dpkg_clean", "same_boot_and_kernel", "other_package_states_equal"))
                and HEX.fullmatch(checks["other_package_states_sha256"]), "guest_apt_exact_upgrade_unverified")
    if kmod_needed:
        result, native = guest_result(root, control["kmod_receipt"], "kmod_apply", plane)
        require(native["schema"] == "clipforge-int-noble-kmod-receipt-1" and native["status"] == "applied_verified"
                and native["operation"] == "apply" and native["release"] == NOBLE_TARGET["release"]
                and native["snapshot_sha256"] == result["snapshot_sha256"] == apt["snapshot_sha256"]
                and native["rule_sha256"] == KMOD_RULE_SHA and native["file"]["sha256"] == KMOD_RULE_SHA
                and native["file"]["uid"] == native["file"]["gid"] == 0 and native["file"]["mode"] == 0o100644
                and native["file"]["size"] == 207 and native["file"]["nlink"] == 1 and native["before"] == before
                and all(native[key] is False for key in ("runtime_authorized", "bootstrap_authorized", "risk_accepted", "reboot_attempted")),
                "guest_kmod_native_postcheck_unverified")
        expected = closed(json.dumps(before))
        expected["kmod"]["scope_rule"] = "reviewed"
        after = native["after"]
        for module in KERNEL_MODULES:
            old, new = before["kmod"]["dry_run"][module], after["kmod"]["dry_run"][module]
            require(new["direct"] == "deny_install" and isinstance(new["aliases"], list) and len(new["aliases"]) == len(old["aliases"])
                    and all(status in {"deny_install", "no_action_reported"} for status in new["aliases"]), "guest_kmod_name_or_alias_unverified")
            expected["kmod"]["dry_run"][module] = new
            expected["kernel"]["autoload"]["modprobe"][module].update(blacklist=1, install="deny")
        require(after == expected, "guest_kmod_postcheck_drift")
    return action


def decision_control(row, operation, action, subjects):
    """Return the evidence required beyond a generic per-finding decision."""
    if row["role"] == "noble_guest":
        detail = {"guest_control_sha256": subjects["noble_guest"]["guest_control"]["sha256"]}
        if row["kind"] == "supplemental" and row["advisory"] in KERNEL_CVES:
            module = KERNEL_CVES[row["advisory"]]
            require(row["component"] == module and row["version"] == NOBLE_TARGET["release"], "guest_kernel_finding_mismatch")
            detail.update(module=module, boot_id=NOBLE_TARGET["boot_id"], residual=KMOD_RESIDUAL)
            if action == "continue":
                return "mitigation_verified", "ordinary_kmod_name_and_alias_same_boot", "verified", detail
            return "remediation_preflight_verified", "bounded_guest_intervention_preflight", "preflight_verified", detail
        if (row["advisory"] in APT_CVES and re.match(r"pkg:deb/ubuntu/linux-tools-common@", row["component"])
                and row["version"] == "6.8.0-149.149"):
            detail["package_sha256"] = APT_DEB_SHA
            if action in {"review", "apt_upgrade"}:
                return "remediation_preflight_verified", "authenticated_package_and_native_simulation_required", "preflight_verified", detail
            return "fixed_verified", "exact_signed_apt_upgrade_postcheck", "verified", detail
    if (operation == "oci_publication" and row["role"] == "credential_toolchain" and row["kind"] == "bandit"
            and row["component"] == DOCKER_SOURCE and row["advisory"] in DOCKER_SAST_CONTROLS):
        detail = {"publication_scope_sha256": subjects["credential_toolchain"]["publication"]["sha256"]}
        return "mitigation_verified", DOCKER_SAST_CONTROLS[row["advisory"]], "verified", detail
    return None


def verify_review(root, review, expected_binding, at, *, runner_version=None, source_root=REPO, guest_action=None):
    exact(review, "schema binding operations global_history promotion_graph exclusions subjects decisions apply_receipt", "review_fields")
    binding = review["binding"]
    exact(binding, "project repository branch environment profile instance_id data_disk_id source_commit operation "
                   "state_generation plan_sha256 apply_receipt_sha256 post_apply_generation",
          "deployment_binding_fields")
    operation = binding["operation"]
    require(review["schema"] == SCHEMA and binding == expected_binding
            and all(binding[name] == value for name, value in BOUNDARY.items())
            and GIT.fullmatch(binding["source_commit"]) and operation in OPERATION_ROLES
            and re.fullmatch(r"[1-9][0-9]+", binding["state_generation"]), "wrong_demo_operation_binding")
    require(guest_action in GUEST_ACTIONS if operation == "guest_intervention" else guest_action is None,
            "requested_guest_action_mismatch")
    plan = binding["plan_sha256"]
    require(bool(HEX.fullmatch(plan or "")) if operation in PLAN_BOUND else plan is None, "wrong_plan_binding_for_operation")
    receipt, generation = binding["apply_receipt_sha256"], binding["post_apply_generation"]
    if operation in POST_APPLY:
        require(HEX.fullmatch(receipt or "") and re.fullmatch(r"[1-9][0-9]+", generation or "")
                and int(generation) > int(binding["state_generation"]), "post_apply_reconciliation_required")
        ref = review["apply_receipt"]
        proof = evidence(root, ref)
        require(ref["sha256"] == receipt and proof == {
            "status": "applied_and_reconciled", "project": binding["project"], "environment": binding["environment"],
            "instance_id": binding["instance_id"], "data_disk_id": binding["data_disk_id"], "plan_sha256": plan,
            "previous_generation": binding["state_generation"], "current_generation": generation,
        }, "post_apply_reconciliation_mismatch")
    else:
        require(receipt is None and generation is None and review["apply_receipt"] is None, "unexpected_apply_receipt_for_operation")
    require(review["operations"] == [operation], "operation_scope_mismatch")
    global_history = evidence(root, review["global_history"])
    global_gate = global_history["gate"]
    require(all(global_history[key] == value for key, value in LEGACY_RUN.items())
            and {key: value["image_id"] for key, value in global_history["targets"].items()} == LEGACY_IMAGES
            and global_gate["status"] == "failed"
            and {row["control"] for row in global_gate["errors"] if row["category"] == "security_finding"} == LEGACY_CONTROLS,
            "global_history_missing")
    expected_roles = OPERATION_ROLES[operation]
    require(set(review["subjects"]) == expected_roles, "required_role_missing")
    graph = exact(evidence(root, review["promotion_graph"]), "binding entrypoint_sha256 roles operations", "promotion_graph_fields")
    require(graph["binding"] == binding and HEX.fullmatch(graph["entrypoint_sha256"]) and
            graph["roles"] == {role: value["identity"] for role, value in review["subjects"].items()} and
            set(graph["operations"]) == {operation}, "promotion_graph_mismatch")
    chain = exact(graph["operations"][operation], "reads produces credentials", "operation_graph_fields")
    require(all(isinstance(values, list) and len(values) == len(set(values)) for values in chain.values()) and
            chain["reads"], "operation_graph_incomplete:" + operation)
    leaves = {role for values in chain.values() for role in values}
    require(leaves == expected_roles, "unreviewed_operation_participant:" + operation)
    credential_role = "personal_windows" if operation == "human_sql_access" else "credential_toolchain"
    require(chain["credentials"] == [credential_role], "missing_credential_toolchain:" + operation)
    require(set(review["exclusions"]) == set(LEGACY_IMAGES), "legacy_selection_changed")
    for role, ref in review["exclusions"].items():
        proof = exact(evidence(root, ref), "binding legacy_target graph_sha256 produced consumed credentials", "exclusion_proof_fields")
        require(proof["binding"] == binding and proof["legacy_target"] == global_history["targets"][role]["image_id"]
                and proof["graph_sha256"] == review["promotion_graph"]["sha256"] and proof["legacy_target"] not in graph["roles"].values()
                and proof["produced"] == proof["consumed"] == proof["credentials"] == [], "excluded_target_participates")
    required_findings = {}
    action = None
    publication_rules = set()
    for role in sorted(expected_roles):
        analyses, checks = role_contract(operation, role)
        toolchain = operation == "bootstrap" and role == "credential_toolchain"
        publication = operation == "oci_publication" and role == "credential_toolchain"
        fields = "identity analyses checks"
        if toolchain:
            fields += " toolchain"
        if publication:
            fields += " publication"
        if role == "noble_guest":
            fields += " guest_control"
        value = exact(review["subjects"][role], fields, "subject_fields")
        artifact = value["identity"]
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact or ""), "missing_exact_subject_identity")
        require(sorted(i["kind"] for i in value["analyses"]) == sorted(analyses), "analysis_closure_missing:" + role)
        if toolchain:
            verify_bootstrap_toolchain(root, value, binding, at, runner_version, source_root, graph["entrypoint_sha256"])
        if publication:
            publication_rules = verify_publication_sources(root, value, binding, source_root, graph["entrypoint_sha256"], runner_version)
        if role == "noble_guest":
            action = verify_guest_control(root, value, binding, at, guest_action)
        require(set(value["checks"]) == set(checks), "checks_incomplete:" + role)
        for key, ref in value["checks"].items():
            fields = "binding role artifact check status checked_at expires_at"
            if key == "exact_guest_intervention_transport":
                fields += " runner_image"
            proof = exact(evidence(root, ref), fields, "check_proof_fields")
            require(proof["binding"] == binding and proof["role"] == role and proof["artifact"] == artifact
                    and proof["check"] == key and proof["status"] == "passed", "check_proof_mismatch:" + key)
            require(utc(proof["checked_at"]) <= at < utc(proof["expires_at"]), "expired_check:" + key)
            if key == "exact_guest_intervention_transport":
                require(re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", proof["runner_image"])
                        and (runner_version is None or proof["runner_image"] == runner_version), "guest_intervention_runner_mismatch")
        for report in value["analyses"]:
            for key, row in native_rows(root, role, artifact, binding, report, at):
                require(key not in required_findings, "duplicate_native_finding_identity")
                if row["kind"] in {"trivy_oci", "trivy_toolchain"}:
                    require(row["severity"] not in {"HIGH", "CRITICAL", "UNKNOWN"}, "native_image_threshold:" + role)
                required_findings[key] = row
    if "noble_guest" in expected_roles:
        modules = {row["advisory"] for row in required_findings.values()
                   if row["role"] == "noble_guest" and row["kind"] == "supplemental" and row["advisory"] in KERNEL_CVES}
        require(modules == set(KERNEL_CVES), "guest_individual_kernel_findings_missing")
    if publication_rules:
        rules = {row["advisory"] for row in required_findings.values()
                 if row["role"] == "credential_toolchain" and row["kind"] == "bandit" and row["component"] == DOCKER_SOURCE}
        require(publication_rules <= rules, "publication_docker_sast_findings_missing")
    require(set(review["decisions"]) == set(required_findings), "new_missing_or_stale_findings")
    for key, row in required_findings.items():
        resolution = exact(review["decisions"][key], "finding owner approved_at expires_at control disposition evidence", "decision_fields")
        require(resolution["finding"] == row, "decision_finding_mismatch")
        control = decision_control(row, operation, action, review["subjects"])
        allowed = {"fixed_verified", "not_applicable_verified", "mitigation_verified"}
        if control:
            disposition, name, result, detail = control
            require((resolution["disposition"], resolution["control"]) == (disposition, name), "specific_finding_control_required")
            allowed = {disposition}
        else:
            result, detail = "verified", {}
        require(resolution["disposition"] in allowed and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", resolution["owner"])
                and isinstance(resolution["control"], str) and bool(resolution["control"].strip()), "unreviewed_finding")
        require(utc(resolution["approved_at"]) <= at < utc(resolution["expires_at"]), "expired_or_pending_decision")
        fields = "finding_id binding control disposition result" + (" " + " ".join(detail) if detail else "")
        proof = exact(evidence(root, resolution["evidence"]), fields, "decision_evidence_fields")
        require(proof == {"finding_id": key, "binding": binding, "control": resolution["control"],
                          "disposition": resolution["disposition"], "result": result, **detail}, "unbound_control_evidence")
    return len(required_findings)


def hosted_binding(binding, env):
    if env.get("GITHUB_ACTIONS") == "true":
        require(env.get("GITHUB_REPOSITORY") == binding["repository"]
                and env.get("GITHUB_REF") == "refs/heads/" + binding["branch"]
                and env.get("GITHUB_SHA") == binding["source_commit"]
                and env.get("GITHUB_EVENT_NAME") == "workflow_dispatch"
                and env.get("RUNNER_ENVIRONMENT") == "github-hosted", "hosted_review_binding_mismatch")
        if binding["operation"] == "bootstrap":
            workflow = f"{binding['repository']}/{BOOTSTRAP_WORKFLOW}@refs/heads/{binding['branch']}"
            require(env.get("GITHUB_WORKFLOW_REF") == workflow, "hosted_workflow_reference_mismatch")


def main(argv=None):
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("--review", type=Path, required=True)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--binding", type=Path, required=True, help="Independent expected operation (never taken from the review)")
    parser.add_argument("--operation", choices=sorted(OPERATION_ROLES), required=True)
    parser.add_argument("--guest-action", choices=GUEST_ACTIONS)
    parser.add_argument("--match-credential-runner", action="store_true", help="Require the measured runner revision used by bootstrap")
    args = parser.parse_args(argv)
    try:
        raw = local_regular(args.review)
        require(digest(raw) == args.review_sha256, "review_digest_mismatch")
        binding = closed(local_regular(args.binding))
        require(binding["operation"] == args.operation, "requested_operation_mismatch")
        hosted_binding(binding, os.environ)
        runner_version = None
        if args.match_credential_runner:
            runner_version = os.environ.get("ImageVersion")
            require(args.operation in {"bootstrap", "oci_publication", "guest_intervention"}
                    and os.environ.get("ImageOS") == "ubuntu24" and runner_version,
                    "missing_hosted_runner_identity")
        count = verify_review(args.review.resolve().parent, closed(raw), binding, datetime.now(timezone.utc),
                              runner_version=runner_version, guest_action=args.guest_action)
        result = {"status": "coverage_ready_for_owner_review", "operation": args.operation,
                  "findings_bound": count, "activation_authorized": False}
        print(json.dumps(result))
        return 0
    except (KeyError, TypeError, ValueError, AttributeError, OSError, SyntaxError) as error:
        code = str(error)
        safe = code if re.fullmatch(r"[a-z_:]{1,120}", code) else type(error).__name__
        print(json.dumps({"status": "blocked", "operation": args.operation, "reason": safe, "activation_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
