"""Prepare, create and execute exactly one reviewed Noble database Job."""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
from stat import S_ISREG
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts import int_db_acceptance_noble as client
from scripts import int_release
from scripts import int_demo_a_receipts as receipts
from scripts import int_demo_a_plan_scope as scope
from scripts import int_noble_bootstrap_payloads as payloads
from scripts import check_int_demo_a as evidence_gate
from scripts.check_tf_int import BUCKET
from scripts.int_secrets import TARGETS
from scripts.tf_int_plan import NoRedirect


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/int-db01-noble-jobs.yml"
PROJECT = "clipforgebeta2"
PROJECT_NUMBER = "816643438938"
DEPLOY = "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
TERRAFORM = "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com"
LOCATION = f"projects/{PROJECT}/locations/us-central1"
RUN = "https://run.googleapis.com/v2/"
SOURCE_SHA256 = "57a7ceb9c4da47ac5c5b33a829f1c13be6bc0be2c2b4d8a97e404d7b71db82bb"
CONFIG = "sha256:c51186988e6d7cf886527fb6bc695309fd24b7d085bed255af70acf7ea0fb855"
ARCHIVE = "sha256:350d9623e3920455052f9274f34cb2136c68c82f48ff7396126a599d3d20f8d4"
ADMIN_JOB = LOCATION + "/jobs/clipforge-int-bootstrap"
ADMIN_CONFIG = "sha256:9598185c5092a20d64e65d813e6cdbd1169cd4cb6b6e34ff4a84ddd7cd4fe4bb"
ADMIN_ARCHIVE = "sha256:4ccaa2ffe0a1b718641dfb71ef5745cf754713b43b293b92d7b455ad97247040"
LAYERS = tuple("sha256:" + item for item in (
    "332636d0635ddf971812ed52505c346c18e5a8383007dd269d72794a64aecb62",
    "5ae09833ebb72bb9ed6dc26e10a95daa2ffa87ffabf7d02a56122d0137d74f76",
    "1732bc6560de5bb7870cc3e0174829c2e3c37f425ac1fdea9f22d887504c40aa",
    "847474228d2e44a607f29ef460b846d03b795785a71327bbbb559ecd2622eae2",
    "6b0c1d5b1b20f427fa02b75d6211ff9066ce197b46103b87c59894ae6dd8fd97",
    "1a40e7627370ff8518b68cf9c437adba69cb02f76db8fb0bb8ed5b588e319fd0",
    "bd9ddc54bea929a22b334e73e026d4136e5b73f5cc29942896c72e4ece69b13d",
))
ADMIN_LAYERS = tuple("sha256:" + item for item in (
    "21210938f5a37a9887b2d0a20428917b923a636ca6efe038c3c7d9cd9f1f9b61",
    "fa2a8ac27f7aec865c56dd237c63ff5ff3fbb1b60844ebff5991523961bdadeb",
    "769e4fa309b3c6ae476afc25b3c2d5c8dd19d52437e849483c138aa4fb73cfe0",
    "2b49f458fc8010528cd61e1dadff0145b47650478f52d63dfd071fea7cd35297",
    "73f971026f5601b158c96ab55c35019ae6bb4308ff07e0613278aa863b0e79d9",
    "a9cfef5f9321b815ee3a05979ad01df380eefa3be9b07ba068b954fa41fe9dee",
    "2819bb5c87422dcce1267c6312973ac7c54b3e0d267489c6b6c1415da1970333",
    "6c492fccc205113fc8862cedaa2e2dcfeaf6778c57a563e868e316769e91676d",
    "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
))
MIGRATION_REVISIONS = ["auth01_0001", "auth02_0002", "cloud01_0001"]
SUCCESS = "configured_guest_verified_external_acceptance_pending"
READ_LIMIT = 1024 * 1024
STATE_NAME = "terraform/int/tf-int-01/default.tfstate"
LOCK_NAME = "terraform/int/tf-int-01/default.tflock"
STATE_LINEAGE = "813c84a2-2ef1-ceb3-177e-3a2c3b815066"
MAX_BACKEND_AGE = timedelta(minutes=2)
RESOURCE_MANAGER = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:testIamPermissions"
IAM = f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/"
COMPUTE = f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}/zones/us-central1-a/"
FIELDS = {"schema", "status", "owner", "source_controls", "action", "phase", "operation_id",
          "issued_utc", "expires_utc", "receipts", "definition_sha256", "gate"}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def hex_id(value, size=64):
    return isinstance(value, str) and re.fullmatch(r"[0-9a-f]{" + str(size) + "}", value)


def number(value):
    return isinstance(value, str) and re.fullmatch(r"[1-9][0-9]*", value)


def local(directory, filename):
    path = directory / filename
    info = path.lstat()
    require(path.resolve() == path and S_ISREG(info.st_mode)
            and not getattr(info, "st_file_attributes", 0) & 0x400
            and 0 < info.st_size <= READ_LIMIT, "invalid_receipt_file")
    with path.open("rb") as reader:
        raw = reader.read(READ_LIMIT + 1)
    require(len(raw) == info.st_size, "receipt_file_size_changed")
    return raw


def source_run(receipt):
    require(hex_id(receipt["source_controls"], 40) and number(receipt["run"]), "invalid_producer_identity")


def bootstrap_receipt(value):
    require(value["schema"] == "clipforge-int-noble-bootstrap-result-1" and value["status"] == SUCCESS
            and value["cleanup"]["status"] in {"own_key_removed", "key_already_absent"}
            and any(row["phase"] == "postcheck" and row["status"] == "completed" for row in value["phases"]),
            "bootstrap_not_verified")
    result = value["guest_receipt"]
    require(result["status"] == SUCCESS and result["exit_code"] == 0 and result["phase"] == "guest_verified"
            and result["disk_id"] == client.NOBLE_SCOPE["data_disk_id"]
            and result["operator_sha256"] == payloads.GUEST_SHA
            and result["operation_id"] == value["operation_id"]
            and all(result["checks"].get(key) is True for key in (
                "identity_verified", "mount_verified", "configuration_verified", "roles_verified",
                "local_tls_handshake_verified", "boot_persistence_configured")),
            "bootstrap_guest_proof_mismatch")


def publication_receipt(value, *, image=client.NOBLE_IMAGE, config=CONFIG, archive=ARCHIVE, layers=LAYERS):
    source_run(value)
    leaf = image.split("@")[0].rsplit("/", 1)[1]
    intent = value["intent"]
    intent_path = f"{receipts.PREFIX}{value['source_controls']}/decisions/{value['operation_id']}/publication-{leaf}-intent.json"
    require(isinstance(intent, dict) and set(intent) == {"name", "generation", "sha256", "size"}
            and hex_id(value["operation_id"], 32) and hex_id(value["owner_decision_sha256"]) and intent["name"] == intent_path
            and number(intent["generation"]) and hex_id(intent["sha256"]) and type(intent["size"]) is int and intent["size"] > 0,
            "publication_intent_scope_mismatch")
    require(value["status"] == "published_and_verified" and value["target"] == image
            and value["manifest"] == image.split("@")[1] and value["config"] == config
            and value["archive_sha256"] in {archive, archive[7:]} and value["layers"] == list(layers)
            and re.fullmatch(r"sha256:[0-9a-f]{64}", value["publisher_digest"]),
            "noble_client_publication_mismatch")


def secret_receipt(value, bootstrap_sha):
    source_run(value)
    require(value["status"] == "published_and_verified" and value["bootstrap_receipt_sha256"] == bootstrap_sha
            and set(value["versions"]) == set(TARGETS), "secret_receipt_scope_mismatch")
    for key, item in value["versions"].items():
        require(set(item) == {"secret", "version"} and item["secret"] == TARGETS[key] and number(item["version"]),
                "secret_version_not_numeric_or_wrong_resource")
    return {key: item["version"] for key, item in value["versions"].items()}


def apply_reference(ref, commit):
    require(isinstance(ref, dict) and set(ref) == {"name", "generation", "sha256", "size"}
            and number(ref["generation"]) and hex_id(ref["sha256"]) and type(ref["size"]) is int
            and 0 < ref["size"] <= int_release.LIMIT, "invalid_demo_a_private_apply_reference")
    path = re.fullmatch(re.escape(f"{int_release.PREFIX}{commit}/") + r"([1-9][0-9]*)-1/manifest\.json", ref["name"])
    require(path is not None, "invalid_demo_a_private_apply_reference")
    return path[1]


def apply_receipt(value, prior, refs):
    commit, service = value["controls_commit"], value["run_service"]
    require(hex_id(commit, 40) and isinstance(service, dict) and set(service) == {"uid", "generation"}
            and isinstance(service["uid"], str) and bool(service["uid"]) and number(service["generation"]),
            "demo_a_apply_service_or_controls_not_verified")
    plan_runs = []
    for receipt in (prior, value):
        require(receipt["schema"] == "clipforge-int-demo-a-result-2" and receipt["phase"] == "apply"
                and receipt["status"] == "applied_verified" and receipt["controls_commit"] == commit
                and number(receipt["run"]) and receipt["firewall_verified"] is True and receipt["iap_verified"] is True
                and receipt["bootstrap_receipt_sha256"] == refs["bootstrap"] and receipt["secret_receipt_sha256"] == refs["secrets"]
                and all(hex_id(receipt[key]) for key in ("plan_sha256", "publication_receipt_sha256"))
                and receipt["run_service"] == service,
                "demo_a_apply_firewall_not_verified")
        plan_runs.append(apply_reference(receipt["plan_manifest"], commit))
    before = scope.phase_state(scope.HUMAN_ACCESS, prior)
    after = value["state_after"]
    prior_ref = value.get("protected_runtime_apply")
    require(value["deployment_phase"] == scope.HUMAN_ACCESS and value["managed_count"] == 59
            and len({value["run"], prior["run"], *plan_runs}) == 4 and value["plan_sha256"] != prior["plan_sha256"]
            and value["publication_receipt_sha256"] == prior["publication_receipt_sha256"]
            and apply_reference(prior_ref, commit) == prior["run"] and prior_ref["sha256"] == refs["protected-runtime-apply"]
            and prior_ref["sha256"] == value["protected_runtime_receipt_sha256"] == scope.phase_receipt_sha(prior)
            and prior_ref["size"] == len(canonical(prior)), "demo_a_final_apply_chain_not_verified")
    require(value["state_before_generation"] == before["generation"] and set(after) == set(before)
            and after["name"] == before["name"] and after["lineage"] == before["lineage"] and after["current_lock_absent"] is True
            and number(after["generation"]) and int(after["generation"]) > int(before["generation"])
            and type(after["serial"]) is int and after["serial"] > before["serial"] and type(after["size"]) is int and after["size"] > 0
            and hex_id(after["sha256"]) and after["sha256"] != before["sha256"], "demo_a_final_apply_state_not_reconciled")


def validate_admin_predecessors(values, refs, versions):
    publication_receipt(values["runtime-publication"], image=scope.IMAGE, config=ADMIN_CONFIG, archive=ADMIN_ARCHIVE, layers=ADMIN_LAYERS)
    require(values["apply"]["publication_receipt_sha256"] == refs["runtime-publication"], "admin_runtime_apply_mismatch")
    accepted = values["acceptance"]
    require(accepted["schema"] == "clipforge-int-noble-job-result-1" and accepted["status"] == "execution_verified"
            and accepted["phase"] == "app" and accepted["action"] == "run"
            and accepted["effect"] == "tls_and_dml_without_data_changes"
            and all(accepted["receipts"].get(key) == refs[key]
                    for key in ("bootstrap", "publication", "secrets", "protected-runtime-apply", "apply", "tls", "migration")),
            "admin_external_acceptance_not_verified")
    mounts = {"database": "migrator_password", "postgres-ca": "postgres_ca", "admin": "bootstrap_admin"}
    env = {**scope.RUNTIME_ENV, "CLIPFORGE_DATABASE_USER": "clipforge_migrator",
           "CLIPFORGE_BOOTSTRAP_ADMIN_FILE": "/secrets/admin/value"}
    task = {"serviceAccount": client.ACCOUNTS["migrate"], "maxRetries": 0, "timeout": "600s",
            "executionEnvironment": "EXECUTION_ENVIRONMENT_GEN2",
            "vpcAccess": {"egress": "PRIVATE_RANGES_ONLY", "networkInterfaces": [{"network": "clipforge-int-base", "subnetwork": "clipforge-int-base-run"}]},
            "containers": [{"image": scope.IMAGE, "command": ["python"], "args": scope.ADMIN_ARGS,
                            "env": [{"name": key, "value": value} for key, value in sorted(env.items())],
                            "resources": {"limits": {"cpu": "1", "memory": "1Gi"}},
                            "volumeMounts": [{"name": name, "mountPath": "/secrets/" + name} for name in mounts]}],
            "volumes": [{"name": name, "secret": {"secret": TARGETS[slot], "items": [{"version": versions[slot], "path": "value"}]}}
                        for name, slot in mounts.items()]}
    return {"name": ADMIN_JOB, "labels": {"application": "clipforge", "environment": "int", "managed_by": "tf-int-01"},
            "template": {"taskCount": 1, "parallelism": 1, "template": task}}


def decision_bundle(directory, expected_sha, env, action, phase, *, now=None):
    require(phase != "admin" or action == "run", "admin_job_requires_reviewed_terraform_creation")
    directory = directory.resolve()
    raw = local(directory, "decision.json")
    require(hex_id(expected_sha) and digest(raw) == expected_sha, "owner_decision_digest_mismatch")
    decision = client.decode(raw.decode("ascii"))
    require(set(decision) == FIELDS and decision["schema"] == "clipforge-int-noble-jobs-decision-1"
            and decision["status"] == "authorized_exact_noble_job_operation" and decision["owner"] == "admin@ixbalam.studio"
            and decision["action"] == action and decision["phase"] == phase and hex_id(decision["operation_id"], 32)
            and decision["gate"] in {"global", "demo-a"}
            and decision["source_controls"] == env.get("GITHUB_SHA") == env.get("INT_APPROVED_COMMIT")
            and hex_id(decision["source_controls"], 40), "job_owner_decision_scope_mismatch")
    at = datetime.now(timezone.utc) if now is None else now
    issued, expires = client.utc(decision["issued_utc"]), client.utc(decision["expires_utc"])
    require(issued <= at and 0 < (expires - issued).total_seconds() <= 3600
            and (expires - at).total_seconds() >= (720 if action == "run" else 300), "job_decision_expired")
    refs = {"bootstrap", "publication", "secrets", "protected-runtime-apply", "apply", "tls"}
    if decision["gate"] == "demo-a":
        refs |= {"review", "binding"}
    if phase == "admin":
        refs |= {"runtime-publication", "acceptance"}
    elif action == "run":
        refs |= {"created", "client-decision"}
    if phase in {"app", "admin"}:
        refs.add("migration")
    require(set(decision["receipts"]) == refs, "job_predecessor_set_mismatch")
    values = {}
    for name in sorted(refs):
        raw = local(directory, name + ".json")
        require(digest(raw) == decision["receipts"][name], "job_predecessor_digest_mismatch")
        values[name] = raw.decode("ascii") if name == "client-decision" else client.decode(raw.decode("ascii"))
    bootstrap_sha = decision["receipts"]["bootstrap"]
    bootstrap_receipt(values["bootstrap"])
    publication_receipt(values["publication"])
    versions = secret_receipt(values["secrets"], bootstrap_sha)
    apply_receipt(values["apply"], values["protected-runtime-apply"], decision["receipts"])
    tls = values["tls"]
    require(tls["status"] == "verified" and tls["bootstrap_receipt_sha256"] == bootstrap_sha
            and tls["host"] == client.NOBLE_SCOPE["database_host"] and tls["mode"] == "verify-full"
            and tls["secret_version"] == versions["postgres_ca"] and hex_id(tls["public_ca_sha256"])
            and tls["secret_receipt_sha256"] == decision["receipts"]["secrets"], "noble_ca_receipt_mismatch")
    if phase in {"app", "admin"}:
        migration = values["migration"]
        require(migration["schema"] == "clipforge-int-noble-job-result-1" and migration["status"] == "execution_verified"
                and migration["action"] == "run" and migration["phase"] == "migrate"
                and migration["database_revisions"] == MIGRATION_REVISIONS
                and all(migration["receipts"].get(key) == decision["receipts"][key]
                        for key in ("bootstrap", "publication", "secrets", "protected-runtime-apply", "apply", "tls")),
                "noble_migration_not_verified")
    if phase == "admin":
        spec = validate_admin_predecessors(values, decision["receipts"], versions)
        require(digest(canonical(spec)) == decision["definition_sha256"], "admin_job_definition_mismatch")
        return decision, spec, {}, None, values["apply"]
    versions = {key: version for key, version in versions.items() if key != "bootstrap_admin"}
    source = local(ROOT / "scripts", "int_db_acceptance_noble.py")
    require(digest(source) == SOURCE_SHA256, "noble_job_client_source_mismatch")
    sources = [{"path": name, "sha256": sha} for name, sha in sorted(client.NOBLE_SOURCES.items())]
    evidence = {"target": "noble", "guest_receipt_sha256": client.NOBLE_GUEST_RECEIPT_SHA256, "bootstrap_receipt_sha256": bootstrap_sha}
    spec = client.job_spec(phase, client.NOBLE_IMAGE, versions, sources, source=source, **evidence)
    require(digest(canonical(spec)) == decision["definition_sha256"], "noble_job_definition_mismatch")
    body, created = None, None
    if action == "run":
        created = values["created"]
        require(created["schema"] == "clipforge-int-noble-job-result-1" and created["status"] == "created_verified"
                and created["action"] == "create" and created["phase"] == phase and created["definition_sha256"] == decision["definition_sha256"]
                and created["job"] == spec["name"]
                and all(created["receipts"].get(key) == decision["receipts"][key]
                        for key in refs - {"created", "client-decision", "review", "binding"}),
                "noble_job_creation_not_verified")
        req = client.job_run_request(values["client-decision"], decision["receipts"]["client-decision"], phase=phase,
                                     image=client.NOBLE_IMAGE, versions=versions, app_sources=sources,
                                     source_sha256=SOURCE_SHA256, now=at, **evidence)
        require(client.decode(values["client-decision"])["operation_id"] == decision["operation_id"], "job_operation_id_mismatch")
        body = req["body"]
    return decision, spec, body, created, values["apply"]


def check_security(directory, decision, applied, env, decision_sha, *, protected):
    mode = decision["gate"]
    if protected:
        require(env.get("INT_NOBLE_JOBS_PROTECTED_GATE_MODE", "global") == mode
                and env.get("INT_NOBLE_JOBS_PROTECTED_DECISION_SHA256") == decision_sha,
                "protected_noble_job_decision_or_gate_mismatch")
    if mode == "global":
        try:
            int_release.require_application_ci(env)
        except HTTPError as error:
            raise ValueError(f"existing_application_ci_http_{error.code}") from None
        except ValueError:
            raise ValueError("existing_application_ci_blocks_noble_jobs") from None
        return
    directory = directory.resolve()
    refs = decision["receipts"]
    if protected:
        require(env.get("INT_NOBLE_JOBS_PROTECTED_REVIEW_SHA256") == refs["review"]
                and env.get("INT_NOBLE_JOBS_PROTECTED_BINDING_SHA256") == refs["binding"],
                "protected_noble_job_review_digests_mismatch")
    review_raw, binding_raw = (local(directory, f"{name}.json") for name in ("review", "binding"))
    require(digest(review_raw) == refs["review"] and digest(binding_raw) == refs["binding"], "job_gate_bytes_changed")
    review, binding = evidence_gate.closed(review_raw), evidence_gate.closed(binding_raw)
    evidence_gate.hosted_binding(binding, env)
    admin = decision["phase"] == "admin"
    require(binding["operation"] == ("admin_job" if admin else "migration_job") and binding["source_commit"] == decision["source_controls"]
            and digest(canonical(applied)) == refs["apply"]
            and binding["plan_sha256"] == applied["plan_sha256"] and binding["state_generation"] == applied["state_before_generation"]
            and binding["post_apply_generation"] == applied["state_after"]["generation"],
            "job_gate_apply_binding_mismatch")
    graph = evidence_gate.evidence(directory, review["promotion_graph"])
    role, image = ("api", admin_image()) if admin else ("migration_client", client.NOBLE_IMAGE)
    require(graph["entrypoint_sha256"] == digest(local(ROOT, WORKFLOW))
            and review["subjects"][role]["identity"] == image.split("@")[1],
            "job_gate_consumer_identity_mismatch")
    evidence_gate.verify_review(directory, review, binding, datetime.now(timezone.utc))


def admin_image():
    from scripts import int_demo_a_plan_scope
    return int_demo_a_plan_scope.IMAGE


def request_json(opener, token, method, url, value=None, *, missing=False):
    raw = None if value is None else canonical(value)
    req = Request(url, data=raw, method=method, headers={"Authorization": "Bearer " + token,
                  "Content-Type": "application/json", "Accept": "application/json"})
    try:
        with opener.open(req, timeout=30) as response:
            body = response.read(READ_LIMIT + 1)
        require(0 < len(body) <= READ_LIMIT, "cloud_response_size")
        return client.decode(body.decode("utf-8"))
    except HTTPError as error:
        status = error.code
        error.close()
        if missing and status == 404:
            return None
        raise ValueError("cloud_http_" + str(status)) from None


class Transport:
    def __init__(self, token, phase, action):
        self.token = token
        self.opener = build_opener(ProxyHandler({}), NoRedirect())
        self.names = receipts.job_names(phase, action)
        self.custody = receipts.Custody(token, names=self.names.values())

    def call(self, method, url, value=None, *, missing=False):
        require(method in {"GET", "POST"} and (url == RESOURCE_MANAGER or url.startswith((RUN + LOCATION + "/", IAM, COMPUTE))),
                "deploy_job_api_scope")
        return request_json(self.opener, self.token, method, url, value, missing=missing)

    def retain(self, kind, value):
        return self.custody.create(self.names[kind], value)


def verify_job_definition(actual, expected):
    allowed_output = {"uid", "generation", "observedGeneration", "terminalCondition", "conditions", "createTime",
                      "updateTime", "creator", "lastModifier", "launchStage", "reconciling", "satisfiesPzs", "etag",
                      "executionCount", "latestCreatedExecution", "client", "clientVersion"}
    observed = {key: value for key, value in actual.items() if key not in allowed_output}
    observed["name"] = resource_name(observed["name"])
    admin = expected["name"] == ADMIN_JOB
    if admin and observed["labels"].get("goog-terraform-provisioned") == "true":
        observed["labels"] = {key: value for key, value in observed["labels"].items() if key != "goog-terraform-provisioned"}
    observed["template"] = {**observed["template"], "template": comparable_task(observed["template"]["template"], admin=admin)}
    normalized = {**expected, "template": {**expected["template"], "template": comparable_task(expected["template"]["template"], admin=admin)}}
    require(observed == normalized
            and actual.get("launchStage", "GA") == "GA" and actual.get("reconciling", False) is False
            and actual["terminalCondition"]["state"] == "CONDITION_SUCCEEDED" and number(actual["generation"])
            and actual["generation"] == actual["observedGeneration"] and actual["uid"] and actual["etag"],
            "installed_noble_job_definition_drift")
    require(type(actual.get("executionCount", 0)) is int and actual.get("executionCount", 0) == 0
            and not actual.get("latestCreatedExecution"), "job_execution_already_exists")


def operation(transport, receipt, *, attempts, wait):
    name = resource_name(receipt["name"])
    require(re.fullmatch(re.escape(LOCATION) + r"/operations/[A-Za-z0-9_-]+", name), "unexpected_noble_job_operation")
    for _ in range(attempts):
        if receipt.get("done") is True:
            if "error" in receipt:
                code = receipt["error"].get("code")
                raise ValueError(f"cloud_operation_failed_{code}" if type(code) is int else "cloud_operation_failed")
            require(isinstance(receipt.get("response"), dict), "cloud_operation_result_missing")
            return name, receipt["response"]
        wait(5)
        receipt = transport.call("GET", RUN + name)
        require(resource_name(receipt["name"]) == name, "job_operation_identity_changed")
    raise ValueError("job_operation_unknown_preserve")


def resource_name(value):
    return value.replace(f"projects/{PROJECT_NUMBER}/", f"projects/{PROJECT}/", 1) if value.startswith(f"projects/{PROJECT_NUMBER}/") else value


def comparable_task(value, *, admin=False):
    result = json.loads(json.dumps(value))
    for container in result["containers"]:
        container["env"] = sorted(container["env"], key=lambda item: item["name"])
        container["volumeMounts"].sort(key=lambda item: item["name"])
        if admin:
            container.pop("name", None)
    result["volumes"].sort(key=lambda item: item["name"])
    for volume in result["volumes"]:
        require(isinstance(volume.get("secret"), dict) and isinstance(volume["secret"].get("secret"), str),
                "unexpected_noble_volume_source")
        volume["secret"]["secret"] = resource_name(volume["secret"]["secret"]).removeprefix(f"projects/{PROJECT}/secrets/")
    for interface in result["vpcAccess"]["networkInterfaces"]:
        for key, scope in (("network", "global/networks"), ("subnetwork", "regions/us-central1/subnetworks")):
            name = resource_name(interface[key])
            interface[key] = name.removeprefix(f"projects/{PROJECT}/{scope}/")
    return result


def verify_execution(transport, name, execution, spec, body):
    require(re.fullmatch(re.escape(spec["name"]) + r"/executions/[a-z0-9-]+", name), "unexpected_execution_identity")
    row = transport.call("GET", RUN + name)
    require(resource_name(row["name"]) == name and resource_name(row["job"]) == spec["name"] and row.get("completionTime")
            and row["uid"] == execution["uid"] and row.get("reconciling", False) is False
            and row["taskCount"] == row["parallelism"] == row["succeededCount"] == 1
            and all(row.get(key, 0) == 0 for key in ("runningCount", "cancelledCount", "failedCount", "retriedCount")),
            "noble_job_execution_not_successful")
    expected = json.loads(json.dumps(spec["template"]["template"]))
    if "overrides" in body:
        expected["containers"][0]["env"].extend(body["overrides"]["containerOverrides"][0]["env"])
    admin = spec["name"] == ADMIN_JOB
    require(comparable_task(row["template"], admin=admin) == comparable_task(expected, admin=admin), "noble_execution_template_drift")


def backend_binding(env, decision, applied, decision_sha):
    run = env.get("GITHUB_RUN_ID", "")
    attempt = env.get("GITHUB_RUN_ATTEMPT")
    require(number(run) and attempt == "1" and hex_id(decision_sha), "invalid_backend_observation_dispatch")
    state = applied["state_after"]
    return {"schema": "clipforge-int-noble-job-backend-observation-1", "identity": TERRAFORM,
            "controls_commit": decision["source_controls"], "run": run, "attempt": attempt,
            "action": decision["action"], "phase": decision["phase"], "operation_id": decision["operation_id"],
            "decision_sha256": decision_sha, "apply_receipt_sha256": decision["receipts"]["apply"],
            "phase2_plan_sha256": applied["plan_sha256"], "phase2_state_before_generation": applied["state_before_generation"],
            "protected_runtime_apply_sha256": decision["receipts"]["protected-runtime-apply"],
            "bucket": BUCKET, "state": {key: state[key] for key in ("name", "generation", "size")},
            "lock": {"name": LOCK_NAME, "http_status": 404}}


def observe_backend(token, binding, *, opener=None, clock=lambda: datetime.now(timezone.utc)):
    opener = opener or build_opener(ProxyHandler({}), NoRedirect())
    base = f"https://storage.googleapis.com/storage/v1/b/{BUCKET}/o/"
    state_url = base + quote(STATE_NAME, safe="") + "?fields=name,generation,size"
    lock_url = base + quote(LOCK_NAME, safe="") + "?fields=name"
    legacy_intent = f"private-plans/int/noble-jobs/{binding['phase']}/{binding['action']}/intent.json"
    legacy = request_json(opener, token, "GET", base + quote(legacy_intent, safe="") + "?fields=name", missing=True)
    require(legacy is None, "legacy_noble_job_intent_requires_reconciliation")
    started = clock()
    before = request_json(opener, token, "GET", state_url)
    lock = request_json(opener, token, "GET", lock_url, missing=True)
    observed = clock()
    after = request_json(opener, token, "GET", state_url)
    expected = {**binding["state"], "size": str(binding["state"]["size"])}
    require(before == after == expected and lock is None, "apply_backend_or_lock_changed")
    finished = clock()
    require(started <= observed <= finished <= started + MAX_BACKEND_AGE, "backend_observation_window")
    return {**binding, "lock_observed_utc": observed.isoformat(), "completed_utc": finished.isoformat(), "legacy_intent_http_status": 404}


def verify_backend_observation(proof, binding, *, now):
    require(isinstance(proof, dict) and set(proof) == set(binding) | {"lock_observed_utc", "completed_utc", "legacy_intent_http_status"}
            and all(proof[key] == value for key, value in binding.items()) and proof["legacy_intent_http_status"] == 404,
            "job_backend_observation_binding")
    observed = client.utc(proof["lock_observed_utc"])
    completed = client.utc(proof["completed_utc"])
    require(observed <= completed <= now <= observed + MAX_BACKEND_AGE, "job_backend_observation_expired_or_future")


def backend_path(path, env):
    runner = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    require(path is not None and path.name == "backend.json" and path.parent.parent == runner
            and path.parent.is_dir() and path.parent.resolve() == path.parent
            and re.fullmatch(r"clipforge-noble-backend\.[a-zA-Z0-9]{8}", path.parent.name),
            "restricted_backend_observation_path")
    return path


def verify_live_scope(transport):
    vm = transport.call("GET", COMPUTE + "instances/clipforge-int-db01-noble")
    require(vm["id"] == client.NOBLE_SCOPE["instance_id"] and vm["status"] == "RUNNING"
            and len(vm["networkInterfaces"]) == 1 and vm["networkInterfaces"][0]["networkIP"] == client.NOBLE_SCOPE["database_host"]
            and not vm["networkInterfaces"][0].get("accessConfigs"), "noble_instance_or_private_network_changed")
    attached = [row for row in vm["disks"] if row["deviceName"] == "clipforge-noble-pg-data"]
    require(len(attached) == 1 and attached[0]["source"].endswith("/disks/clipforge-int-db01-noble-data")
            and attached[0]["autoDelete"] is False and attached[0]["boot"] is False, "noble_data_attachment_changed")
    disk = transport.call("GET", COMPUTE + "disks/clipforge-int-db01-noble-data")
    require(disk["id"] == client.NOBLE_SCOPE["data_disk_id"], "noble_data_disk_changed")


def verify_permissions(transport, action, job, phase):
    project_permissions = ["run.operations.get"] + (["run.jobs.create"] if action == "create" else [])
    scopes = [(RESOURCE_MANAGER, project_permissions, "project")]
    if action == "create":
        scopes.append((IAM + client.ACCOUNTS[phase] + ":testIamPermissions",
                       ["iam.serviceAccounts.actAs"], "job_service_account"))
    else:
        run_permission = "run.jobs.run" if phase == "admin" else "run.jobs.runWithOverrides"
        scopes.append((RUN + job + ":testIamPermissions", ["run.jobs.get", run_permission, "run.executions.get"], "job"))
    for route, permissions, label in scopes:
        result = transport.call("POST", route, {"permissions": permissions})
        missing = sorted(set(permissions) - set(result.get("permissions", [])))
        require(not missing, f"permissions_missing_{label}:" + ",".join(missing))


def execute(transport, ready, proof, binding, *, notice, wait=time.sleep, clock=lambda: datetime.now(timezone.utc)):
    decision, spec, body, created, _ = ready
    action, phase = decision["action"], decision["phase"]
    job = spec["name"]
    report = {"schema": "clipforge-int-noble-job-result-1", "action": action, "phase": phase, "job": job,
              "operation_id": decision["operation_id"], "controls_commit": decision["source_controls"],
              "definition_sha256": decision["definition_sha256"], "receipts": decision["receipts"],
              "backend_observation": proof, "backend_observation_sha256": digest(canonical(proof))}
    verify_backend_observation(proof, binding, now=clock())
    verify_live_scope(transport)
    verify_permissions(transport, action, job, phase)
    actual = transport.call("GET", RUN + job, missing=True)
    if action == "create":
        require(actual is None, "existing_noble_job_requires_reconciliation")
        route = RUN + LOCATION + "/jobs?" + urlencode({"jobId": job.rsplit("/", 1)[1]})
        payload = {key: value for key, value in spec.items() if key != "name"}
    else:
        require(actual is not None, "noble_job_missing")
        verify_job_definition(actual, spec)
        if phase == "admin":
            created = actual
        else:
            require(created["uid"] == actual["uid"] and created["generation"] == actual["generation"]
                    and created["etag"] == actual["etag"], "noble_job_create_receipt_drift")
        route, payload = RUN + job + ":run", {**body, "etag": actual["etag"]}
    verify_backend_observation(proof, binding, now=clock())
    intent = transport.retain("intent", {**report, "status": "intent_recorded"})
    notice({**report, "status": "intent_recorded", "intent": intent})
    verify_backend_observation(proof, binding, now=clock())
    notice({**report, "status": "mutation_pending_reconciliation", "intent": intent})
    response = transport.call("POST", route, payload)
    name = resource_name(response.get("name", ""))
    if re.fullmatch(re.escape(LOCATION) + r"/operations/[A-Za-z0-9_-]+", name):
        notice({**report, "status": "operation_observed", "intent": intent, "operation": name})
    name, result = operation(transport, response, attempts=135, wait=wait)
    report.update(intent=intent, operation=name)
    if action == "create":
        actual = transport.call("GET", RUN + job)
        verify_job_definition(actual, spec)
        require(resource_name(result["name"]) == job and actual["uid"] == result["uid"], "create_result_job_mismatch")
        report.update(status="created_verified", uid=actual["uid"], generation=actual["generation"], etag=actual["etag"])
    else:
        execution = resource_name(result["name"])
        verify_execution(transport, execution, result, spec, body)
        job_after = transport.call("GET", RUN + job)
        require(resource_name(job_after["name"]) == job and job_after["uid"] == created["uid"]
                and job_after["generation"] == created["generation"] and job_after["executionCount"] == 1
                and resource_name(job_after["latestCreatedExecution"]["name"]) == execution,
                "noble_job_concurrent_execution_or_drift")
        effect = {"migrate": "locked_idempotent_migrations", "app": "tls_and_dml_without_data_changes",
                  "admin": "one_time_first_administrator"}[phase]
        report.update(status="execution_verified", execution=execution, revision_evidence="exact_executed_client_contract", effect=effect)
        if phase == "migrate":
            report["database_revisions"] = MIGRATION_REVISIONS
    custody = transport.retain("result", report)
    return {**report, "custody": custody}


def hosted(env):
    expected = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_WORKFLOW_REF": "AldemaroCruz/ClipForge/" + WORKFLOW + "@refs/heads/ci/bootstrap-sec03"}
    require(all(env.get(key) == value for key, value in expected.items()), "invalid_noble_job_workflow_context")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("step", choices=("preflight", "observe-backend", "execute"))
    parser.add_argument("--action", choices=("create", "run"), required=True)
    parser.add_argument("--phase", choices=(*client.NOBLE_JOBS, "admin"), required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--decision-sha256", required=True)
    parser.add_argument("--protected", action="store_true")
    parser.add_argument("--backend-observation", type=Path)
    args = parser.parse_args()
    try:
        hosted(os.environ)
        ready = decision_bundle(args.bundle, args.decision_sha256, os.environ, args.action, args.phase)
        check_security(args.bundle, ready[0], ready[4], os.environ, args.decision_sha256,
                       protected=args.protected or args.step != "preflight")
        if args.step == "preflight":
            print(json.dumps({"status": "preflight_verified", "job": ready[1]["name"], "activation_authorized": False}))
            return 0
        int_release.hosted_context(os.environ)
        path = backend_path(args.backend_observation, os.environ)
        binding = backend_binding(os.environ, ready[0], ready[4], args.decision_sha256)
        if args.step == "observe-backend":
            require(os.environ.get("NOBLE_JOBS_TERRAFORM_EMAIL") == TERRAFORM and not os.environ.get("NOBLE_JOBS_DEPLOY_EMAIL"),
                    "job_backend_wif_identity_mismatch")
            observation = observe_backend(os.environ["GCP_ACCESS_TOKEN"], binding)
            os.umask(0o077)
            with path.open("xb") as stream:
                stream.write(canonical(observation))
            print(json.dumps({"status": "backend_observation_verified", **observation}))
            return 0
        require(os.environ.get("NOBLE_JOBS_DEPLOY_EMAIL") == DEPLOY and not os.environ.get("NOBLE_JOBS_TERRAFORM_EMAIL"),
                "job_wif_identity_mismatch")
        proof = client.decode(local(path.parent, path.name).decode("ascii"))
        output = execute(Transport(os.environ["GCP_ACCESS_TOKEN"], args.phase, args.action), ready, proof, binding,
                         notice=lambda value: print(json.dumps(value), flush=True))
        print(json.dumps(output))
        return 0
    except (AttributeError, KeyError, TypeError, ValueError, OSError) as error:
        reason = str(error)
        safe = reason if re.fullmatch(r"[a-z0-9_]{1,100}|permissions_missing_(?:project|job|job_service_account):[a-zA-Z.,]+", reason) else type(error).__name__
        print(json.dumps({"status": "blocked_or_indeterminate", "reason": safe, "retry_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
