"""Protected INT account-demo native plan and separate reviewed saved-plan apply."""

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as contract
from scripts import check_int_demo_a as activation_gate
from scripts import int_demo_a_plan_scope as scope
from scripts import int_demo_a_receipts as receipts
from scripts import int_foundation_close as historical
from scripts import int_foundation_verify as foundation
from scripts import int_noble_apply as noble
from scripts import int_noble_bootstrap_payloads as bootstrap_payload
from scripts import int_noble_write_iam as writer
from scripts import int_release as custody
from scripts import tf_int_plan as driver


ROOT = Path(__file__).resolve().parents[1]
MODULE = Path("infra/gcp/int-base")
DEMO_MODULE = Path("infra/gcp/int-demo-a")
BASE_SOURCES = {(MODULE / file).as_posix() for file in ("versions.tf", "variables.tf", "main.tf", "outputs.tf", "runtime.tf", "audit.tf",
           "noble-candidate.tf", "backend-int.hcl", ".terraform.lock.hcl", "postgres-install.sh", "db01-noble-startup.sh",
           "db01-noble-hostkey-template.sh")}
BASE_SOURCES |= {"scripts/int_vm_hostkey_guest.py", "scripts/int_noble_hostkey.py"}
OVERLAYS = {(MODULE / name).as_posix(): (DEMO_MODULE / name).as_posix() for name in ("runtime.tf", "noble-candidate.tf")}
SOURCES = BASE_SOURCES | set(OVERLAYS.values())
WORKFLOWS = {phase: f".github/workflows/int-demo-a-{phase}.yml" for phase in ("plan", "apply")}
REPOSITORY = "AldemaroCruz/ClipForge"
BRANCH = "ci/bootstrap-sec03"
MANIFEST = "sha256:40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15"
CONFIG = "sha256:9598185c5092a20d64e65d813e6cdbd1169cd4cb6b6e34ff4a84ddd7cd4fe4bb"
ARCHIVE = "4ccaa2ffe0a1b718641dfb71ef5745cf754713b43b293b92d7b455ad97247040"
LAYERS = ["sha256:" + value for value in (
    "21210938f5a37a9887b2d0a20428917b923a636ca6efe038c3c7d9cd9f1f9b61",
    "fa2a8ac27f7aec865c56dd237c63ff5f3fbb1b60844ebff5991523961bdadeb",
    "769e4fa309b3c6ae476afc25b3c2d5c8dd19d52437e849483c138aa4fb73cfe0",
    "2b49f458fc8010528cd61e1dadff0145b47650478f52d63dfd071fea7cd35297",
    "73f971026f5601b158c96ab55c35019ae6bb4308ff07e0613278aa863b0e79d9",
    "a9cfef5f9321b815ee3a05979ad01df380eefa3be9b07ba068b954fa41fe9dee",
    "2819bb5c87422dcce1267c6312973ac7c54b3e0d267489c6b6c1415da1970333",
    "6c492fccc205113fc8862cedaa2e2dcfeaf6778c57a563e868e316769e91676d",
    "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef")]
POSTVERIFY = {"name": "private-plans/int/d6915938ea056d6df6e15d29457c0f0c1f46a69e/44772432816-1/foundation-state.json",
              "generation": "1795191726103428", "sha256": "cf3236aa512cf30d59136fed3a5209448700be6401c345716db0a38f222288a3", "size": 4089}
NAMES = {"publish", "versions", "bootstrap", "iac", "stable_write", "postverify"}
NATIVE_HCL = {
    (MODULE / "runtime.tf").as_posix(): "f573d073f93d5bf2969548f1432a3d4cfa1f99e1030b14ed180dbb8ffea78abb",
    (MODULE / "noble-candidate.tf").as_posix(): "d1c89dfd11d99e68ac0ae9371597446c253c6ccc35de399ea53fd40515d7e8dd",
    (MODULE / ".terraform.lock.hcl").as_posix(): "89e2189a1b882ac5ad3ce74ad17a304e95cf7fa072b9ced86fce09e78b88b5fa",
    (DEMO_MODULE / "runtime.tf").as_posix(): "39326bfe49d0541ebb13042bd2bb9ecff470a750a215898883af9f32adbf4458",
    (DEMO_MODULE / "noble-candidate.tf").as_posix(): "bca3d815083eec680f0faf5210a80a41d82001c987994a9f8d30595a7e4ff6bc",
}
SCHEMA = "clipforge-int-demo-a-private-plan-1"
TTL = timedelta(hours=24)
require = scope.require


def write_new(path, raw):
    with path.open("xb") as stream:
        stream.write(raw)


def selected_sources(digests):
    selected = {target: OVERLAYS.get(target, target) for target in sorted(BASE_SOURCES)}
    return {target: {"source": name, "sha256": digests[name]} for target, name in selected.items()}


def verified_source(root, name, expected):
    path = root / name
    require(path.is_file() and not path.is_symlink(), "changed_iac_source")
    raw = path.read_bytes()
    require(custody.sha256(raw) == expected, "changed_iac_source")
    return raw


def decision_current(decision):
    require(datetime.now(timezone.utc) < aware(decision["expires_utc"]), "owner_decision_expired_before_native")


def aware(value):
    parsed = datetime.fromisoformat(value)
    require(parsed.tzinfo is not None, "timezone_required")
    return parsed


def reference(row, *, suffix=None):
    require(isinstance(row, dict) and set(row) == {"name", "generation", "sha256", "size"}
            and scope.NUMERIC.fullmatch(row["generation"]) and scope.HEX.fullmatch(row["sha256"])
            and type(row["size"]) is int and 0 < row["size"] <= custody.LIMIT, "exact_private_reference")
    path = row["name"]
    tail = path.rsplit("/", 1)[-1]
    if not receipts.NAME.fullmatch(path):
        custody.object_name(path)
    require(suffix is None or tail == suffix, "private_reference_purpose")
    return row


def read_reference(row):
    reference(row)
    if receipts.NAME.fullmatch(row["name"]):
        return receipts.Custody(os.environ["GCP_ACCESS_TOKEN"]).fetch(row)
    return custody.fetch_verified(row)


def validate_local(phase, env, raw, *, root=ROOT, now=None):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": "refs/heads/" + BRANCH,
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOWS[phase]}@refs/heads/{BRANCH}"}
    require(all(env.get(key) == value for key, value in expected.items()) and scope.NUMERIC.fullmatch(env.get("GITHUB_RUN_ID", ""))
            and scope.SHA.fullmatch(env.get("GITHUB_SHA", "")) and env["GITHUB_SHA"] == env.get("INT_APPROVED_COMMIT")
            and env.get("TF_WORKSPACE", "default") == "default" and not env.get("TF_REATTACH_PROVIDERS"), "protected_exact_dispatch")
    contract.validate_variables(env)
    require(0 < len(raw) <= 65536 and custody.sha256(raw) == env.get("DECISION_SHA") == env.get("PROTECTED_DECISION_SHA"),
            "independently_pinned_owner_decision")
    decision = foundation.decode(raw)
    names = {"schema", "phase", "owner", "decision_id", "controls_commit", "app_source", "image", "state", "sources", "gate",
             "issued_utc", "expires_utc", "approvals", "evidence", "publisher_digest", "publisher_controls", "secret_controls"}
    if phase == "apply":
        names |= {"plan_manifest", "plan_binary_sha256"}
    approval = {"native_backend_lock": True, "private_immutable_custody": True, "apply_saved_plan": phase == "apply"}
    require(set(decision) == names and decision["schema"] == "clipforge-int-demo-a-owner-decision-1" and decision["phase"] == phase
            and decision["owner"] == "admin@ixbalam.studio" and re.fullmatch(r"[1-9][0-9]{29}", decision["decision_id"])
            and decision["controls_commit"] == env["GITHUB_SHA"] and decision["state"] == scope.STATE
            and decision["app_source"] == scope.SOURCE and decision["image"] == scope.IMAGE and decision["approvals"] == approval,
            "owner_scope_or_phase")
    issued, deadline = (aware(decision[key]) for key in ("issued_utc", "expires_utc"))
    now = now or datetime.now(timezone.utc)
    require(issued <= now < deadline and deadline - issued <= TTL, "owner_decision_expired")
    evidence = decision["evidence"]
    require(set(evidence) == NAMES and evidence["postverify"] == POSTVERIFY, "required_source_evidence")
    for row in evidence.values():
        reference(row)
    reference(evidence["publish"], suffix="publication-runtime.json")
    reference(evidence["versions"], suffix="secret-versions.json")
    writer.verify_stable_reference(evidence["stable_write"])
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", decision["publisher_digest"])
            and scope.SHA.fullmatch(decision["publisher_controls"]) and scope.SHA.fullmatch(decision["secret_controls"]),
            "publisher_and_secret_producer_pins")
    require(set(decision["sources"]) == SOURCES, "exact_iac_source_set")
    for name, digest in decision["sources"].items():
        verified_source(root, name, digest)
    require(all(decision["sources"][name] == value for name, value in NATIVE_HCL.items()),
            "reviewed_demo_hcl_or_provider_lock_changed")
    if phase == "apply":
        reference(decision["plan_manifest"], suffix="manifest.json")
        require(decision["plan_manifest"]["name"].split("/")[2] == decision["controls_commit"]
                and scope.HEX.fullmatch(decision["plan_binary_sha256"]), "apply_requires_same_control_source_and_binary")
    return decision


def verify_activation_gate(phase, env, decision, *, root=ROOT):
    selected = decision["gate"]
    mode = env.get("INT_DEMO_A_PROTECTED_GATE_MODE") or "global"
    if mode == "global":
        require(selected == {"mode": "global"}, "protected_gate_mode_changed")
        custody.require_application_ci(env)
        return
    expected = {"mode", "run_id", "artifact_id", "review_sha256", "binding_sha256", "runner_version"}
    require(mode == "demo-a" and set(selected) == expected and selected["mode"] == mode
            and scope.NUMERIC.fullmatch(selected["run_id"]) and selected["run_id"] == env.get("INT_DEMO_A_GATE_RUN")
            and scope.NUMERIC.fullmatch(selected["artifact_id"]) and selected["artifact_id"] == env.get("INT_DEMO_A_GATE_ARTIFACT")
            and scope.HEX.fullmatch(selected["review_sha256"]) and selected["review_sha256"] == env.get("INT_DEMO_A_PROTECTED_REVIEW_SHA")
            and scope.HEX.fullmatch(selected["binding_sha256"]) and selected["binding_sha256"] == env.get("INT_DEMO_A_PROTECTED_BINDING_SHA")
            and env.get("ImageOS") == "ubuntu24" and re.fullmatch(r"[0-9.]+", selected["runner_version"])
            and selected["runner_version"] == env.get("ImageVersion"), "independent_demo_gate_approval_missing")
    bundle = Path(env["INT_DEMO_A_GATE_BUNDLE"]).resolve()
    require(bundle.parent == Path(env["RUNNER_TEMP"]).resolve() and bundle.name.startswith("clipforge-int-demo-a-review.")
            and bundle.is_dir(), "private_demo_gate_bundle")
    review_raw = activation_gate.local_regular(bundle / "review.json")
    binding_raw = activation_gate.local_regular(bundle / "binding.json")
    require(custody.sha256(review_raw) == selected["review_sha256"] and custody.sha256(binding_raw) == selected["binding_sha256"],
            "independent_gate_evidence_hashes")
    operation = "plan_generation" if phase == "plan" else "locked_plan_apply"
    binding = {**activation_gate.BOUNDARY, "source_commit": env["GITHUB_SHA"], "operation": operation,
               "state_generation": scope.STATE["generation"], "plan_sha256": decision.get("plan_binary_sha256"),
               "apply_receipt_sha256": None, "post_apply_generation": None}
    require(activation_gate.closed(binding_raw) == binding and operation in activation_gate.OPERATION_ROLES,
            "exact_demo_gate_operation_binding")
    review = activation_gate.closed(review_raw)
    activation_gate.verify_review(bundle, review, binding, datetime.now(timezone.utc), source_root=root)
    graph = activation_gate.evidence(bundle, review["promotion_graph"])
    require(graph["entrypoint_sha256"] == custody.sha256((root / "scripts/int_demo_a_native.py").read_bytes()),
            "reviewed_demo_native_entrypoint_changed")
    api = review["subjects"]["api"]
    require(api["identity"] == MANIFEST, "reviewed_demo_api_manifest_changed")
    for record in api["analyses"]:
        if record["kind"] == "trivy_oci":
            receipt = activation_gate.evidence(bundle, record["receipt"])
            target = activation_gate.evidence(bundle, receipt["scope"])
            require(target["oci_config"] == CONFIG and target["oci_diff_ids"] == LAYERS, "reviewed_demo_api_config_or_layers_changed")


def get(url, token, *, digest=None):
    headers = {"Authorization": "Bearer " + token, "Accept": "application/vnd.oci.image.manifest.v1+json" if digest else "application/json"}
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(Request(url, headers=headers), timeout=30) as response:
            raw = response.read(4 * 1024 * 1024 + 1)
            require(len(raw) <= 4 * 1024 * 1024, "remote_receipt_exceeded_bound")
            if digest:
                require("sha256:" + custody.sha256(raw) == response.headers.get("Docker-Content-Digest") == digest, "published_registry_manifest_changed")
    except HTTPError as error:
        raise driver.FailedOperation("read fixed INT evidence " + url, "HTTP " + str(error.code), error.code) from None
    return foundation.decode(raw)


def verify_inventory(oci):
    require(oci["config"]["digest"] == CONFIG and [row["digest"] for row in oci["layers"]] == LAYERS,
            "published_registry_layers_changed")


def verify_iac(review, native_raw, decision, *, now=None):
    now = now or datetime.now(timezone.utc)
    report_sha = custody.sha256(native_raw)
    selected = selected_sources(decision["sources"])
    require(review.get("schema") == "clipforge-int-demo-a-iac-review-1" and review.get("status") == "reviewed"
            and review.get("controls_commit") == decision["controls_commit"] and review.get("sources") == decision["sources"]
            and review.get("selected_sources") == selected
            and review.get("native_report_sha256") == report_sha == review["native_report"]["sha256"]
            and review.get("unresolved_count") == 0 and now < aware(review.get("expires_utc", "")), "exact_iac_review_required")
    native = foundation.decode(native_raw)
    require(native.get("ArtifactType") == "filesystem" and native["Trivy"]["Version"] == "0.76.2" and native["Results"], "exact_native_iac_scan")
    findings = set()
    for row in native["Results"]:
        require(row["Class"] == "config" and row["Type"] == "terraform", "native_iac_target_scope")
        count = 0
        for item in row.get("Misconfigurations", []):
            require(item["Status"] in {"PASS", "FAIL"}, "native_iac_suppression_or_unknown")
            if item["Status"] == "FAIL":
                cause = item["CauseMetadata"]
                identifier = (str(item["ID"]), row["Target"], cause["Resource"], cause["StartLine"], cause["EndLine"], item["Severity"])
                require(identifier not in findings, "duplicate_native_iac_finding")
                findings.add(identifier)
                count += 1
        require(row["MisconfSummary"]["Failures"] == count, "native_iac_incomplete_findings")
    checked = set()
    for row in review["decisions"]:
        fields = ("id", "target", "resource", "start_line", "end_line", "severity")
        identifier = tuple(row[key] for key in fields)
        target, expiry = identifier[1], aware(row["expires_utc"])
        module_file = MODULE.as_posix() + "/" + target
        require(identifier in findings and identifier not in checked and row["native_report_sha256"] == report_sha
                and row["source_sha256"] == selected[module_file]["sha256"] and now < expiry
                and row["status"] in {"control_verified", "authorized_residual"}
                and all(isinstance(row[key], str) and row[key].strip() for key in ("responsible", "control", "evidence")),
                "independent_iac_finding_decision")
        checked.add(identifier)
    require(checked == findings, "unresolved_native_iac_finding")


def verify_receipts(decision, inputs):
    published, versions, bootstrap, iac = (inputs[key] for key in ("publish", "versions", "bootstrap", "iac"))
    expected = {"status": "published_and_verified", "source_controls": decision["publisher_controls"], "target": scope.IMAGE,
                "manifest": MANIFEST, "config": CONFIG, "archive_sha256": ARCHIVE, "layers": LAYERS,
                "publisher_digest": decision["publisher_digest"]}
    require(all(published.get(key) == value for key, value in expected.items())
            and scope.NUMERIC.fullmatch(published.get("run", "")), "exact_publisher_receipt")
    reference(published["intent"], suffix="publication-runtime-intent.json")
    publication_root = f"private-plans/int/{decision['publisher_controls']}/{published['run']}-1/"
    require(decision["evidence"]["publish"]["name"] == publication_root + "publication-runtime.json", "publisher_receipt_scope")
    require(bootstrap.get("schema") == "clipforge-int-noble-bootstrap-result-1" and
            bootstrap.get("status") == "configured_guest_verified_external_acceptance_pending" and
            bootstrap.get("migrations_applied") is False and bootstrap.get("runtime_authorized") is False
            and bootstrap["cleanup"]["status"] in {"own_key_removed", "key_already_absent", "no_registered_key"},
            "independent_guest_bootstrap_receipt")
    operator = bootstrap_payload.operator_contract(bootstrap_payload.operator_bytes())
    guest = operator.validate_receipt(bootstrap["guest_receipt"])
    require(guest["status"] == bootstrap["status"] and guest["disk_id"] == bootstrap_payload.DATA
            and guest["operation_id"] == bootstrap["operation_id"] and guest["operator_sha256"] == bootstrap_payload.GUEST_SHA,
            "exact_bootstrap_guest_receipt")
    require(versions.get("status") == "published_and_verified" and versions.get("source_controls") == decision["secret_controls"]
            and scope.NUMERIC.fullmatch(versions.get("run", "")) and versions.get("bootstrap_receipt_sha256") ==
            decision["evidence"]["bootstrap"]["sha256"] and decision["evidence"]["versions"]["name"] ==
            f"private-plans/int/{decision['secret_controls']}/{versions['run']}-1/secret-versions.json", "exact_four_secret_receipt_bundle")
    reference(iac["native_report"], suffix="int.json")
    return scope.versions(versions["versions"])


def verify_producer_intents(decision, published, versions):
    def intent(ref, commit, leaf, common):
        reference(ref, suffix=leaf)
        allowed = custody.PREFIX + re.escape(commit) + r"/decisions/[a-f0-9]{32}/" + re.escape(leaf)
        require(re.fullmatch(allowed, ref["name"]), "producer_intent_scope")
        value = foundation.decode(read_reference(ref))
        require(all(value.get(key) == item for key, item in common.items()) and
                scope.HEX.fullmatch(value.get("owner_decision_sha256", "")), "producer_intent_contents")
        return ref["name"].rsplit("/", 1)[0], value["owner_decision_sha256"]

    publication_fields = {key: published[key] for key in ("target", "run", "source_controls", "manifest", "config", "archive_sha256", "layers", "publisher_digest")}
    intent(published["intent"], decision["publisher_controls"], "publication-runtime-intent.json", {**publication_fields, "status": "copy_intended"})

    secret_refs = versions["intents"]
    require(set(secret_refs) == set(scope.SECRET_NAMES), "four_secret_intent_references")
    secret_fields = {key: versions[key] for key in ("source_controls", "run", "bootstrap_receipt_sha256", "bootstrap_run", "bootstrap_artifact", "ca_certificate_sha256")}
    bindings = {intent(secret_refs[key], decision["secret_controls"], f"secret-{key}-intent.json",
                       {**secret_fields, "status": "secret_version_intended", "secret": name}) for key, name in scope.SECRET_NAMES.items()}
    require(len(bindings) == 1, "secret_intents_from_different_operations")


def verify_cloud(decision, env):
    historical.verify_wif(env)
    token = env["GCP_ACCESS_TOKEN"]
    refs = decision["evidence"]
    inputs = {key: foundation.decode(read_reference(refs[key])) for key in NAMES - {"stable_write"}}
    wanted = verify_receipts(decision, inputs)
    verify_iac(inputs["iac"], read_reference(inputs["iac"]["native_report"]), decision)
    verify_producer_intents(decision, inputs["publish"], inputs["versions"])
    verify_inventory(get("https://us-central1-docker.pkg.dev/v2/clipforgebeta2/clipforge-int/runtime/manifests/" + MANIFEST, token, digest=MANIFEST))
    for key, number in wanted.items():
        secret = scope.SECRET_NAMES[key]
        value = get(f"https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/{secret}/versions/{number}", token)
        require(value.get("state") == "ENABLED" and value.get("name") in {
            f"projects/{project}/secrets/{secret}/versions/{number}" for project in ("clipforgebeta2", "816643438938")},
            "secret_metadata_changed_or_disabled")
    profile, proof, read_profile, read_proof, _, _ = writer.load_stable_evidence(refs["stable_write"])
    writer.verify_live_policies(profile, proof, token)
    writer.verify_unaffected_read(read_profile, read_proof, token)
    return wanted


def state_binding():
    raw, obj, _ = noble.current_state()
    state = foundation.decode(raw)
    require(state["version"] == 4 and state["terraform_version"] == "1.15.8"
            and state["lineage"] == scope.STATE["lineage"] and type(state["serial"]) is int, "unexpected_state_lineage_or_version")
    attrs = {}
    for resource in state["resources"]:
        require(not resource.get("module") and resource["mode"] in {"managed", "data"}, "unknown_state_resource")
        if resource["mode"] == "managed":
            for item in resource["instances"]:
                require(not item.get("deposed") and item.get("status") in {None, "ready"}, "unmanaged_or_tainted_state")
                path = resource["type"] + "." + resource["name"]
                if "index_key" in item:
                    path += "[" + json.dumps(item["index_key"], ensure_ascii=True, separators=(",", ":")) + "]"
                require(path not in attrs, "duplicate_state_address")
                attrs[path] = item["attributes"]
    return {"name": obj["name"], "generation": obj["generation"], "serial": state["serial"], "lineage": state["lineage"],
            "sha256": custody.sha256(raw), "size": len(raw), "current_lock_absent": True}, attrs


def baseline_state():
    state, attrs = state_binding()
    require(state == scope.STATE and set(attrs) == scope.baseline(), "baseline_state_or_lock_changed")
    scope.check_pinned_vm(attrs)
    return state, attrs


def store(path, raw):
    row = custody.upload(path, raw)
    require(custody.fetch_verified(row) == raw, "private_object_readback_differs")
    return row


def materialize_module(decision, work, *, root=ROOT):
    destination = work / "module"
    destination.mkdir()
    # Keep the structural path from Noble HCL to its two historical helpers.
    for target, chosen in selected_sources(decision["sources"]).items():
        path = destination / target
        path.parent.mkdir(parents=True, exist_ok=True)
        write_new(path, verified_source(root, chosen["source"], chosen["sha256"]))
    return destination / MODULE


def init(decision, work):
    staged = materialize_module(decision, work)
    # The driver works in 'module'; global -chdir selects the pinned HCL subtree.
    binary = driver.terraform_binary()
    command = [binary, "-chdir=" + str(staged)]
    write_new(work / "terraform.rc", b"provider_installation {\n  direct {}\n}\n")
    backend = (staged / "backend-int.hcl").read_text(encoding="utf-8")
    require(dict(re.findall(r'^\s*(bucket|prefix)\s*=\s*"([^"]+)"\s*$', backend, re.M)) ==
            {"bucket": scope.BUCKET, "prefix": "terraform/int/tf-int-01"}, "reviewed_backend_configuration")
    driver.run(command + ["init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "demo_a_init", work)
    driver.run(command + ["validate", "-no-color"], "demo_a_validate", work)
    return command


def plan(decision, env, work, numbers, report):
    env_run = f"{env['GITHUB_SHA']}/{env['GITHUB_RUN_ID']}-1/"
    prefix = custody.PREFIX + env_run
    marker = custody.PREFIX + f"{env['GITHUB_SHA']}/{decision['decision_id']}-1/"
    state, _ = baseline_state()
    terraform = init(decision, work)
    require(baseline_state()[0] == state, "baseline_changed_after_init")
    flags = ["-input=false", "-no-color", "-lock=true", "-lock-timeout=120s"]
    out, values = work / "int.tfplan", work / "inputs.tfvars.json"
    inputs = scope.planned_variables(numbers)
    write_new(values, custody.canonical(inputs))
    decision_current(decision)
    report["stage"] = "claim_plan_once"
    report["intent"] = store(marker + "foundation-state.json", custody.canonical({"decision": env["DECISION_SHA"],
                          "controls_commit": env["GITHUB_SHA"], "run": env["GITHUB_RUN_ID"], "state": state}))
    report["stage"] = "native_plan"
    code, _ = driver.run(terraform + ["plan", *flags, "-refresh=true", "-detailed-exitcode", "-var-file=" + str(values),
                                      "-out=" + str(out)], "demo_a_native_plan", work, accepted=(2,))
    terminal, _ = baseline_state()
    _, raw = driver.run(terraform + ["show", "-json", str(out)], "demo_a_native_show", work)
    binary = out.read_bytes()
    report["scope"] = scope.verify_diff(foundation.decode(raw), numbers)
    report["stage"] = "private_custody"
    binding = {"controls_commit": env["GITHUB_SHA"], "iac_patch_sha256": scope.IAC_PATCH_SHA, "environment": "int",
               "operation": "plan-native-demo-a", "identity": env["GCP_TERRAFORM_SA"], "completed_steps": scope.GATEWAY,
               "run_id": env["GITHUB_RUN_ID"], "run_attempt": "1", "lock": True, "native_plan_exit": code, "plan_attempted": 1,
               "backend_bucket": scope.BUCKET, "workspace": "default", "backend_pre": state, "backend_after_init": state,
               "backend_post": terminal, "secret_receipt_sha256": decision["evidence"]["versions"]["sha256"],
               "plan_binary_sha256": custody.sha256(binary), "native_json_sha256": custody.sha256(raw)}
    refs = {"int.tfplan": store(prefix + "int.tfplan", binary), "int.json": store(prefix + "int.json", raw)}
    created = datetime.now(timezone.utc)
    manifest = custody.canonical({"schema": SCHEMA, "binding": binding, "inputs": inputs, "sources": decision["sources"],
                    "selected_sources": selected_sources(decision["sources"]),
                    "evidence": decision["evidence"], "plan_owner_decision_sha256": env["DECISION_SHA"], "intent": report["intent"],
                    "created_utc": created.isoformat(), "expires_utc": (created + TTL).isoformat(), "objects": refs})
    receipt = store(prefix + "manifest.json", manifest)
    scope.verify_custody({"completed_steps": scope.GATEWAY_COMPLETE, "bucket": scope.BUCKET,
                          "objects": {**refs, "manifest.json": receipt}}, binding, raw, binary, manifest)
    report.update(status="planned_verified", plan_manifest=receipt, plan_expires_utc=(created + TTL).isoformat())


def verified_plan(decision, env, numbers):
    ref = decision["plan_manifest"]
    content = foundation.decode(custody.fetch_verified(ref))
    binding = content["binding"]
    run = binding["run_id"]
    require(scope.NUMERIC.fullmatch(run) and run != env["GITHUB_RUN_ID"] and binding["run_attempt"] == "1"
            and ref["name"] == f"{custody.PREFIX}{env['GITHUB_SHA']}/{run}-1/manifest.json" and content["schema"] == SCHEMA
            and content["inputs"] == scope.planned_variables(numbers) and content["evidence"] == decision["evidence"]
            and content["sources"] == decision["sources"] and content["selected_sources"] == selected_sources(decision["sources"]), "saved_plan_provenance")
    issued, expiry = aware(content["created_utc"]), aware(content["expires_utc"])
    require(issued <= datetime.now(timezone.utc) < expiry and expiry - issued == TTL, "saved_plan_expired")
    result = get(f"https://api.github.com/repos/{REPOSITORY}/actions/runs/{run}", env["GH_TOKEN"])
    expected = {"id": int(run), "run_attempt": 1, "status": "completed", "conclusion": "success", "head_sha": env["GITHUB_SHA"],
                "head_branch": BRANCH, "event": "workflow_dispatch", "path": WORKFLOWS["plan"]}
    require(all(result.get(key) == value for key, value in expected.items()), "exact_successful_plan_producer_run")
    intent = reference(content["intent"], suffix="foundation-state.json")
    require(re.fullmatch(r"private-plans/int/" + env["GITHUB_SHA"] + r"/[1-9][0-9]{29}-1/foundation-state\.json", intent["name"])
            and scope.HEX.fullmatch(content["plan_owner_decision_sha256"]), "saved_plan_intent_reference")
    expected_intent = {"decision": content["plan_owner_decision_sha256"], "controls_commit": env["GITHUB_SHA"],
                       "run": run, "state": scope.STATE}
    require(foundation.decode(custody.fetch_verified(intent)) == expected_intent, "saved_plan_intent_contents")
    refs = content["objects"]
    require(set(refs) == {"int.tfplan", "int.json"}, "exact_saved_plan_objects")
    binary = custody.fetch_verified(reference(refs["int.tfplan"], suffix="int.tfplan"))
    raw = custody.fetch_verified(reference(refs["int.json"], suffix="int.json"))
    prefix = ref["name"].removesuffix("manifest.json")
    require(all(row["name"] == prefix + name for name, row in refs.items()) and
            custody.sha256(binary) == decision["plan_binary_sha256"], "approved_saved_plan_binary")
    scope.verify_production_receipt(binding, raw, binary, env["GITHUB_SHA"], read_reference(decision["evidence"]["versions"]))
    scope.verify_diff(foundation.decode(raw), numbers)
    return binary, raw, expiry


def verify_live_firewall(token):
    path = "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/global/firewalls/clipforge-int-db01-noble-postgres-from-run"
    value = get(path, token)
    require(value.get("name") == "clipforge-int-db01-noble-postgres-from-run" and value.get("network", "").endswith(
            "/projects/clipforgebeta2/global/networks/clipforge-int-base") and value.get("direction") == "INGRESS"
            and value.get("priority") == 1000 and value.get("sourceRanges") == ["10.80.0.0/26"]
            and value.get("targetServiceAccounts") == ["clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"]
            and value.get("allowed") == [{"IPProtocol": "tcp", "ports": ["5432"]}] and not value.get("disabled")
            and not any(value.get(key) for key in ("denied", "sourceTags", "sourceServiceAccounts", "targetTags", "destinationRanges"))
            and value.get("logConfig") == {"enable": True, "metadata": "EXCLUDE_ALL_METADATA"}, "live_firewall_changed")


def apply(decision, env, work, numbers, report):
    binary, raw, expiry = verified_plan(decision, env, numbers)
    state, existing = baseline_state()
    terraform = init(decision, work)
    require(baseline_state() == (state, existing), "baseline_changed_after_init")
    saved = work / "int.tfplan"
    write_new(saved, binary)
    _, reread = driver.run(terraform + ["show", "-json", str(saved)], "demo_a_verify_saved_native", work)
    require(reread == raw, "saved_binary_native_json_mismatch")
    decision_current(decision)
    require(datetime.now(timezone.utc) < expiry, "saved_plan_expired_before_native")
    plan_ref = decision["plan_manifest"]
    report["stage"] = "claim_apply_once"
    marker = plan_ref["name"].removesuffix("manifest.json") + "foundation-state.json"
    report["intent"] = store(marker, custody.canonical({"decision": env["DECISION_SHA"], "plan_manifest": plan_ref,
                            "apply_run": env["GITHUB_RUN_ID"], "state": state, "binary_sha256": custody.sha256(binary)}))
    report["stage"] = "native_apply"
    driver.run(terraform + ["apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(saved)], noble.NATIVE_OPERATION, work)
    report["stage"] = "post_apply_reconciliation"
    updated, attrs = state_binding()
    require(updated["serial"] > state["serial"] and updated["generation"] != state["generation"] and updated["name"] == state["name"]
            and set(attrs) == set(existing) | scope.ADDRESSES and all(attrs[path] == value for path, value in existing.items()),
            "apply_poststate_unreconciled")
    scope.check_pinned_vm(attrs)
    scope.check_firewall({**attrs[scope.FIREWALL], "network": attrs[scope.FIREWALL]["network"].rsplit("/", 1)[-1]})
    verify_live_firewall(env["GCP_ACCESS_TOKEN"])
    refs = decision["evidence"]
    report.update(status="applied_verified", plan_manifest=plan_ref, state_after=updated, managed_count=len(attrs), firewall_verified=True,
                  plan_sha256=custody.sha256(binary), state_before_generation=state["generation"],
                  bootstrap_receipt_sha256=refs["bootstrap"]["sha256"], secret_receipt_sha256=refs["versions"]["sha256"],
                  publication_receipt_sha256=refs["publish"]["sha256"])


def retain_plan_failure(decision, env, work, error):
    log = work / "demo_a_native_plan.log"
    if log.is_file():
        raw = log.read_bytes()
    else:
        raw = b"\n".join(part for part in (getattr(error, "stdout", b""), getattr(error, "stderr", b"")) if isinstance(part, bytes))
    require(0 < len(raw) <= 16 * 1024 * 1024, "private_native_plan_log_unavailable")
    marker = custody.PREFIX + f"{env['GITHUB_SHA']}/{decision['decision_id']}-1/int.json"
    return store(marker, raw)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("invocation", choices=("local", "cloud"))
    parser.add_argument("phase", choices=("plan", "apply"))
    args = parser.parse_args(argv)
    os.umask(0o077)
    env = dict(os.environ)
    raw = env.pop("INT_DEMO_A_OWNER_DECISION_JSON", "").encode("utf-8")
    os.environ.pop("INT_DEMO_A_OWNER_DECISION_JSON", None)
    work, reports = driver.private_paths()
    report = {"schema": "clipforge-int-demo-a-result-1", "status": "blocked", "stage": "local_preflight", "phase": args.phase,
              "controls_commit": env.get("GITHUB_SHA"), "run": env.get("GITHUB_RUN_ID")}
    error = None
    try:
        decision = validate_local(args.phase, env, raw)
        if args.invocation == "local":
            require(not os.environ.get("GCP_ACCESS_TOKEN") and not os.environ.get("GOOGLE_APPLICATION_CREDENTIALS"),
                    "preflight_must_precede_wif")
        verify_activation_gate(args.phase, env, decision)
        if args.invocation == "local":
            report["status"] = "local_preflight_verified_wif_not_used"
            print(json.dumps({"status": "local_preflight_passed", "phase": args.phase}))
            return 0
        report["stage"] = "verify_wif_and_cloud_evidence"
        numbers = verify_cloud(decision, env)
        (plan if args.phase == "plan" else apply)(decision, env, work, numbers, report)
    except Exception as exc:
        error = exc
        if report["stage"] in {"claim_plan_once", "native_plan", "private_custody", "claim_apply_once", "native_apply", "post_apply_reconciliation"}:
            report["status"] = "unknown_preserve_and_review"
        report["failure"] = str(exc) if type(exc) is ValueError and re.fullmatch(r"[a-z0-9_]+", str(exc)) else type(exc).__name__
        if isinstance(exc, driver.FailedOperation):
            report["native"] = exc.receipt
    finally:
        try:
            if args.invocation == "cloud" and args.phase == "apply" and report["stage"] in {"native_apply", "post_apply_reconciliation"}:
                report["native_log"] = noble.persist_native_log(work, env, error)
                require(report["native_log"] is not None, "native_log_unavailable")
                if report["status"] == "applied_verified":
                    report["result_receipt"] = store(noble.prefix(env) + "manifest.json", custody.canonical(report))
            elif args.invocation == "cloud" and args.phase == "plan" and error and report["stage"] in {"native_plan", "private_custody"}:
                report["native_log"] = retain_plan_failure(decision, env, work, error)
        except Exception as secondary:
            report.update(status="unknown_preserve_and_review", secondary_failure=type(secondary).__name__)
        (reports / "summary.json").write_bytes(custody.canonical(report))
    print(json.dumps({"status": report["status"], "phase": args.phase, "stage": report["stage"]}))
    return int(report["status"] not in {"planned_verified", "applied_verified"})


if __name__ == "__main__":
    raise SystemExit(main())
