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
    "bootstrap": {"noble_guest", "credential_toolchain"},
    "human_sql_access": {"noble_guest", "personal_windows"},
    "secret_versions": {"credential_toolchain"},
    "oci_publication": {"api", "migration_client", "artifact_builder", "attestation_toolchain", "demo_tests", "credential_toolchain"},
    "locked_plan_apply": {"api", "noble_guest", "credential_toolchain"},
    "migration_job": {"migration_client", "noble_guest", "credential_toolchain"},
    "admin_job": {"api", "noble_guest", "credential_toolchain"},
    "api_demo": {"api", "noble_guest", "demo_tests", "credential_toolchain"},
}
POST_APPLY = {"migration_job", "admin_job", "api_demo"}
PLAN_BOUND = {"locked_plan_apply"} | POST_APPLY
CREDENTIAL_CHECKS = {
    "guest_safety": ("guest_package_scope_and_recovery",),
    "bootstrap": ("controlled_bootstrap_and_stop", "scoped_iam_and_protected_inputs"),
    "secret_versions": ("secret_target_and_version_receipt_protocol",),
    "oci_publication": ("oci_bytes_before_wif", "registry_digest_and_custody"),
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


def verify_bootstrap_sources(source_root, rows, binding):
    require(isinstance(rows, dict) and REQUIRED_BOOTSTRAP_SOURCES <= set(rows), "missing_bootstrap_source")
    for name, expected in rows.items():
        require(re.fullmatch(r"(?:\.github/workflows/[a-z0-9-]+\.yml|scripts/[a-z0-9_]+\.py|config/[a-z0-9-]+\.json)", name)
                and HEX.fullmatch(expected), "invalid_bootstrap_source")
        path = source_root / name
        require(path.resolve() == path, "changed_bootstrap_source")
        raw = local_regular(path)
        require(digest(raw) == expected, "changed_bootstrap_source")
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
                        require(imported in rows, "missing_bootstrap_import")
    require(GIT.fullmatch(binding["source_commit"]), "invalid_bootstrap_source_commit")


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
            verify_bootstrap_sources(source_root, proof["files"], binding)
            files = proof["files"]
            require(files[BOOTSTRAP_WORKFLOW] == entrypoint, "bootstrap_promotion_entrypoint_mismatch")
            bandit_sources = scan_scopes["bandit"]["sha256_by_source_path"]
            gitleaks_sources = scan_scopes["gitleaks"]["sha256_by_source_path"]
            require(all(bandit_sources.get(name) == sha for name, sha in files.items() if name.endswith(".py")),
                    "bootstrap_bandit_scope_missing")
            require(all(gitleaks_sources.get(name) == sha for name, sha in files.items()), "bootstrap_gitleaks_scope_missing")
        covered.update(targets)
    require(covered == expected_targets, "toolchain_scan_targets_unbound")


def verify_review(root, review, expected_binding, at, *, runner_version=None, source_root=REPO):
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
    for role in sorted(expected_roles):
        analyses, checks = role_contract(operation, role)
        toolchain = operation == "bootstrap" and role == "credential_toolchain"
        fields = "identity analyses checks toolchain" if toolchain else "identity analyses checks"
        value = exact(review["subjects"][role], fields, "subject_fields")
        artifact = value["identity"]
        require(re.fullmatch(r"sha256:[0-9a-f]{64}", artifact or ""), "missing_exact_subject_identity")
        require(sorted(i["kind"] for i in value["analyses"]) == sorted(analyses), "analysis_closure_missing:" + role)
        if toolchain:
            verify_bootstrap_toolchain(root, value, binding, at, runner_version, source_root, graph["entrypoint_sha256"])
        require(set(value["checks"]) == set(checks), "checks_incomplete:" + role)
        for key, ref in value["checks"].items():
            proof = exact(evidence(root, ref), "binding role artifact check status checked_at expires_at", "check_proof_fields")
            require(proof["binding"] == binding and proof["role"] == role and proof["artifact"] == artifact
                    and proof["check"] == key and proof["status"] == "passed", "check_proof_mismatch:" + key)
            require(utc(proof["checked_at"]) <= at < utc(proof["expires_at"]), "expired_check:" + key)
        for report in value["analyses"]:
            for key, row in native_rows(root, role, artifact, binding, report, at):
                require(key not in required_findings, "duplicate_native_finding_identity")
                if row["kind"] in {"trivy_oci", "trivy_toolchain"}:
                    require(row["severity"] not in {"HIGH", "CRITICAL", "UNKNOWN"}, "native_image_threshold:" + role)
                required_findings[key] = row
    require(set(review["decisions"]) == set(required_findings), "new_missing_or_stale_findings")
    for key, row in required_findings.items():
        resolution = exact(review["decisions"][key], "finding owner approved_at expires_at control disposition evidence", "decision_fields")
        require(resolution["finding"] == row, "decision_finding_mismatch")
        required = {"fixed_verified", "not_applicable_verified", "mitigation_verified"}
        require(resolution["disposition"] in required and re.fullmatch(r"[^@\s]+@[^@\s]+\.[^@\s]+", resolution["owner"])
                and isinstance(resolution["control"], str) and bool(resolution["control"].strip()), "unreviewed_finding")
        require(utc(resolution["approved_at"]) <= at < utc(resolution["expires_at"]), "expired_or_pending_decision")
        proof = exact(evidence(root, resolution["evidence"]), "finding_id binding control disposition result", "decision_evidence_fields")
        require(proof == {"finding_id": key, "binding": binding, "control": resolution["control"],
                          "disposition": resolution["disposition"], "result": "verified"}, "unbound_control_evidence")
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
            require(args.operation == "bootstrap" and os.environ.get("ImageOS") == "ubuntu24" and runner_version,
                    "missing_hosted_runner_identity")
        count = verify_review(args.review.resolve().parent, closed(raw), binding, datetime.now(timezone.utc),
                              runner_version=runner_version)
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
