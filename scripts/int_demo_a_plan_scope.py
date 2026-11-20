"""Offline scope checker for the proposed locked INT account-demo plan."""
from hashlib import sha256
import argparse
import json
from pathlib import Path
import re

from scripts.check_tf_int import FOUNDATION_ADDRESSES
from scripts.db01_noble_plan import CREATES

BASE_ADDRESSES_SHA = "a25b16aa50bb05c97e5f59dd307f34f2b90a14ebafed8bf2dc9943452069567c"
IAC_PATCH_SHA = "19a023137053940f79ee364ad1f2e79bb3871d1c834f91c08878cbca4989bcbb"
SOURCE = "6c1bf38c92e2bfa1d6949d5e54fb5508d4df83fd"
PROJECT = "clipforgebeta2"
REGION = "us-central1"
BUCKET = "clipforgebeta2-tfstate-int"
STATE_NAME = "terraform/int/tf-int-01/default.tfstate"
IMAGE = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15"
CA = "clipforge-int-postgres-ca"
SECRET_NAMES = {"app_password": "clipforge-int-pg-app-password", "migrator_password": "clipforge-int-pg-migrator-password",
                "postgres_ca": CA, "bootstrap_admin": "clipforge-int-bootstrap-admin"}
STATE = {"name": STATE_NAME, "generation": "1795187957111147", "serial": 9, "lineage": "813c84a2-2ef1-ceb3-177e-3a2c3b815066",
         "sha256": "2cc1b5410d0f0f9eaf58a27ef3c61517a476582b8bede20c6f61010711bdc67d", "size": 182865,
         "current_lock_absent": True}
SERVICE = "google_cloud_run_v2_service.api[0]"
BOOTSTRAP = 'google_cloud_run_v2_job.task["bootstrap"]'
FIREWALL = "google_compute_firewall.noble_postgres_from_run[0]"
INVOKER = "google_cloud_run_v2_service_iam_member.iap_invoker[0]"
HUMAN = "google_iap_web_cloud_run_service_iam_member.pilot_admin[0]"
JOB_OPERATOR = 'google_cloud_run_v2_job_iam_member.protected_operator["bootstrap"]'
ADDRESSES = {SERVICE, BOOTSTRAP, FIREWALL, INVOKER, HUMAN, JOB_OPERATOR}
API_ARGS = ["-m", "uvicorn", "app.int_demo:app", "--host", "0.0.0.0", "--port", "8080", "--no-access-log", "--proxy-headers", "--forwarded-allow-ips=*"]
ADMIN_ARGS = ["-m", "app.cloud.bootstrap_admin"]
RUNTIME_ENV = {"CLIPFORGE_DATABASE_POOL_SIZE": "2", "CLIPFORGE_DATABASE_POOL_OVERFLOW": "1",
               "CLIPFORGE_ENVIRONMENT": "INT", "MAX_UPLOAD_MB": "30", "CLIPFORGE_STORAGE_BACKEND": "local",
               "CLIPFORGE_CLOUD_PROJECT": PROJECT, "CLIPFORGE_CLOUD_REGION": REGION,
               "CLIPFORGE_DATABASE_HOST": "10.80.1.3", "CLIPFORGE_DATABASE_PORT": "5432", "CLIPFORGE_DATABASE_NAME": "clipforge",
               "CLIPFORGE_DATABASE_SSL_MODE": "verify-full", "CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE": "/secrets/postgres-ca/value",
               "CLIPFORGE_ALLOW_INSECURE_HTTP": "0", "CLIPFORGE_LLM_ENABLED": "0", "CLIPFORGE_AUTH_PROFILE": "https",
               "CLIPFORGE_AUTH_ORIGIN": "https://clipforge-int-api-816643438938.us-central1.run.app",
               "CLIPFORGE_RUNTIME_PROFILE": "int-demo-a", "CLIPFORGE_REVISION": SOURCE,
               "CLIPFORGE_DATABASE_PASSWORD_FILE": "/secrets/database/value"}
GATEWAY = ["verify_preapproved_native_input", "wif_clipforge_terraform_int", "precheck_state_and_lock", "terraform_init", "terraform_validate",
           "recheck_state_and_lock", "terraform_plan_locked", "postcheck_state_and_lock", "terraform_show_json"]
GATEWAY_COMPLETE = [*GATEWAY, "verify_demo_a_native_scope", "custody_create_only", "custody_verify_by_generation"]
NUMERIC = re.compile(r"[1-9][0-9]*")
HEX = re.compile(r"[a-f0-9]{64}")
SHA = re.compile(r"[a-f0-9]{40}")


def require(condition, label):
    if not condition:
        raise ValueError(label)


def single(items, label):
    require(isinstance(items, list) and len(items) == 1 and isinstance(items[0], dict), label)
    return items[0]


def baseline():
    rows = sorted(FOUNDATION_ADDRESSES | CREATES)
    raw = (json.dumps(rows, indent=2) + "\n").encode("ascii")
    require(sha256(raw).hexdigest() == BASE_ADDRESSES_SHA, "baseline_address_receipt_hash")
    require(isinstance(rows, list) and len(rows) == len(set(rows)) == 53, "baseline_address_set")
    return set(rows)


def versions(replies):
    require(set(replies) == set(SECRET_NAMES), "four_version_receipts_required")
    result = {}
    for key, name in SECRET_NAMES.items():
        row = replies[key]
        require(set(row) == {"secret", "version"} and row["secret"] == name
                and NUMERIC.fullmatch(row["version"]), "version_receipt_target_or_number")
        result[key] = row["version"]
    return result


def planned_variables(numbers):
    return {"project_id": PROJECT, "machine_type": "e2-micro", "run_subnet_cidr": "10.80.0.0/26",
            "postgres_subnet_cidr": "10.80.1.0/28", "data_disk_gb": 20, "runtime_image": IMAGE,
            "secret_versions": numbers, "stage": "runtime", "int_runtime_profile": "demo-a",
            "demo_source_revision": SOURCE, "noble_postgres_from_run": True,
            "db01_noble_candidate": {"image_name": "ubuntu-2404-noble-amd64-v20261105", "image_id": "1892012953239034119"}}


def live_rows(module):
    require(not module.get("child_modules"), "unexpected_module")
    resource = {}
    for row in module["resources"]:
        if row["mode"] == "managed":
            require(row["address"] not in resource, "duplicate_managed_address")
            resource[row["address"]] = row["values"]
        else:
            require(row["mode"] == "data", "unexpected_resource_mode")
    return resource


def drift_absent(plan):
    require(plan.get("terraform_version") == "1.15.8" and plan.get("format_version", "").startswith("1.")
            and plan.get("complete") is True and plan.get("applyable") is True and plan.get("errored") is False,
            "native_plan_incomplete")
    require(not plan.get("resource_drift") and not plan.get("deferred_changes") and not plan.get("action_invocations"),
            "native_drift_deferred_or_action_invocation")


def check_pinned_vm(prior):
    vm = prior["google_compute_instance.noble[0]"]
    boot = prior["google_compute_disk.noble_boot[0]"]
    data = prior["google_compute_disk.noble_data[0]"]
    require(str(vm["instance_id"]) == "7365414160255801909" and vm["name"] == "clipforge-int-db01-noble"
            and vm["deletion_protection"] is True
            and str(boot["disk_id"]) == "8897353356069952044" and str(data["disk_id"]) == "7382984635240536620",
            "noble_instance_or_disks_differ")
    require(str(prior["google_compute_instance.postgres"]["instance_id"]) == "1670495097211408131"
            and str(prior["google_compute_disk.postgres"]["disk_id"]) == "6427691858848206684", "debian_instance_or_disk_differ")
    nic = single(vm["network_interface"], "noble_single_nic")
    require(nic["network_ip"] == "10.80.1.3" and not nic.get("access_config"), "noble_private_nic")
    boot_cfg = single(vm["boot_disk"], "noble_boot_attachment")
    data_cfg = single(vm["attached_disk"], "noble_data_attachment")
    require(boot_cfg["auto_delete"] is False and boot_cfg["source"].endswith("/disks/clipforge-int-db01-noble-boot")
            and data_cfg["device_name"] == "clipforge-noble-pg-data" and data_cfg["mode"] == "READ_WRITE"
            and data_cfg["source"].endswith("/disks/clipforge-int-db01-noble-data"), "noble_protected_disk_attachment")


def check_binding(value, subject, role, attribute, target):
    require(value["project"] == PROJECT and value["location"] == REGION and value[attribute] == target
            and value["role"] == role and value["member"] == subject and not value.get("condition"), "protected_iam_binding")


def check_firewall(values):
    port = single(values["allow"], "firewall_one_allow")
    require(values["project"] == PROJECT and values["name"] == "clipforge-int-db01-noble-postgres-from-run"
            and values["network"] == "clipforge-int-base" and values["direction"] == "INGRESS" and values["priority"] == 1000
            and values["source_ranges"] == ["10.80.0.0/26"] and values["target_service_accounts"] ==
            ["clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"]
            and port["protocol"] == "tcp" and port["ports"] == ["5432"] and not values.get("disabled")
            and not any(values.get(key) for key in ("deny", "source_tags", "source_service_accounts", "target_tags", "destination_ranges"))
            and single(values["log_config"], "firewall_log")["metadata"] == "EXCLUDE_ALL_METADATA", "noble_firewall_scope")


def verify_runtime(template, secret_versions, *, admin):
    service = "migrate" if admin else "api"
    require(template["service_account"] == f"clipforge-{service}-int@clipforgebeta2.iam.gserviceaccount.com"
            and template["execution_environment"] == "EXECUTION_ENVIRONMENT_GEN2", "runtime_identity_and_execution")
    vpc = single(template["vpc_access"], "runtime_vpc")
    interface = single(vpc["network_interfaces"], "runtime_vpc_interface")
    require(vpc["egress"] == "PRIVATE_RANGES_ONLY" and interface["network"] == "clipforge-int-base"
            and interface["subnetwork"] == "clipforge-int-base-run" and not interface.get("tags"), "runtime_vpc_scope")
    container = single(template["containers"], "runtime_container")
    require(container["image"] == IMAGE and container["command"] == ["python"]
            and container["args"] == (ADMIN_ARGS if admin else API_ARGS), "exact_runtime_image_and_commands")
    slots = "migrator_password" if admin else "app_password"
    secrets = {"database": slots, "postgres-ca": "postgres_ca"}
    env = {**RUNTIME_ENV, "CLIPFORGE_DATABASE_USER": "clipforge_migrator" if admin else "clipforge_app"}
    if admin:
        secrets["admin"] = "bootstrap_admin"
        env["CLIPFORGE_BOOTSTRAP_ADMIN_FILE"] = "/secrets/admin/value"
    rows = container["env"]
    require({item["name"]: item["value"] for item in rows} == env and len(rows) == len(env)
            and not any(item.get("value_source") for item in rows), "runtime_env_or_multimedia")
    volumes = template["volumes"]
    mounts = container["volume_mounts"]
    require(len(volumes) == len(mounts) == len(secrets) and {item["name"] for item in volumes} == set(secrets)
            and {item["name"]: item["mount_path"] for item in mounts} == {name: "/secrets/" + name for name in secrets},
            "runtime_only_reviewed_secret_mounts")
    for volume in volumes:
        spec = single(volume["secret"], "runtime_volume_one_secret")
        item = single(spec["items"], "runtime_secret_one_version")
        slot = secrets[volume["name"]]
        require(spec["secret"] == SECRET_NAMES[slot] and item["version"] == secret_versions[slot] and item["path"] == "value",
                "runtime_receipt_version_mount")


def verify_diff(plan, secret_versions):
    drift_absent(plan)
    require({key: row["value"] for key, row in plan["variables"].items()} == planned_variables(secret_versions), "native_plan_variables")
    prior = live_rows(plan["prior_state"]["values"]["root_module"])
    planned = live_rows(plan["planned_values"]["root_module"])
    fixed = baseline()
    require(set(prior) == fixed and set(planned) == fixed | ADDRESSES, "exact_prior_and_planned_addresses")
    require(all(prior[path] == planned[path] for path in fixed), "existing_planned_attributes_changed")
    check_pinned_vm(prior)
    seen = set()
    for row in plan["resource_changes"]:
        if row["mode"] == "data":
            require(row["change"]["actions"] in (["read"], ["no-op"]), "unexpected_data_operation")
            continue
        path, change = row["address"], row["change"]
        require(row["mode"] == "managed" and path not in seen and path in planned
                and not row.get("previous_address") and not row.get("deposed")
                and not change.get("importing") and not change.get("replace_paths"), "native_address_or_move_replace_import")
        seen.add(path)
        if path in fixed:
            require(change["actions"] == ["no-op"] and change["before"] == change["after"] == prior[path]
                    and not change.get("after_unknown"), "existing_resource_not_exact_noop")
        else:
            require(change["actions"] == ["create"] and change.get("before") is None and change["after"] == planned[path],
                    "new_resource_not_exact_create")
    require(seen == set(planned), "native_managed_actions_incomplete")
    outputs = plan.get("output_changes", {})
    require(set(outputs) <= {"reviewed_boundary", "db01_noble_candidate"}
            and all(row["actions"] in (["no-op"], ["update"]) for row in outputs.values()), "unreviewed_output_change")
    candidate_output = outputs.get("db01_noble_candidate")
    require(candidate_output is None or (candidate_output["actions"] == ["no-op"] and
            candidate_output["before"] == candidate_output["after"] and not candidate_output.get("after_unknown")), "noble_output_changed")
    service, job = planned[SERVICE], planned[BOOTSTRAP]
    require(service["name"] == "clipforge-int-api" and service["project"] == PROJECT and service["location"] == REGION
            and service["deletion_protection"] is True and service["iap_enabled"] is True
            and service["ingress"] == "INGRESS_TRAFFIC_ALL" and not service.get("invoker_iam_disabled"), "api_iap_and_invoker_enforced")
    verify_runtime(single(service["template"], "api_one_template"), secret_versions, admin=False)
    require(job["name"] == "clipforge-int-bootstrap" and job["project"] == PROJECT and job["location"] == REGION
            and job["deletion_protection"] is True, "bootstrap_job_identity")
    outer = single(job["template"], "bootstrap_one_template")
    inner = single(outer["template"], "bootstrap_one_task_template")
    require(outer["task_count"] == outer["parallelism"] == 1 and inner["max_retries"] == 0 and inner["timeout"] == "600s",
            "bootstrap_one_task_without_retry")
    verify_runtime(inner, secret_versions, admin=True)
    check_firewall(planned[FIREWALL])
    check_binding(planned[INVOKER], "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com", "roles/run.invoker", "name", "clipforge-int-api")
    check_binding(planned[HUMAN], "user:admin@ixbalam.studio", "roles/iap.httpsResourceAccessor", "cloud_run_service_name", "clipforge-int-api")
    check_binding(planned[JOB_OPERATOR], "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com", "roles/run.invoker", "name", "clipforge-int-bootstrap")
    return {"managed_noop": len(fixed), "managed_create": sorted(ADDRESSES), "managed_total": len(planned)}


def verify_production_receipt(receipt, plan_raw, binary, commit, secret_receipt_raw):
    require(SHA.fullmatch(commit) and receipt.get("controls_commit") == commit and receipt.get("iac_patch_sha256") == IAC_PATCH_SHA,
            "approved_plan_source_or_patch_binding")
    require(receipt.get("environment") == "int" and receipt.get("identity") == "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com"
            and receipt.get("operation") == "plan-native-demo-a" and NUMERIC.fullmatch(receipt.get("run_id", ""))
            and NUMERIC.fullmatch(receipt.get("run_attempt", "")), "gateway_identity_or_operation")
    require(receipt.get("completed_steps") == GATEWAY, "gateway_commands_missing_or_out_of_order")
    require(receipt.get("backend_bucket") == BUCKET and receipt.get("workspace") == "default"
            and all(receipt.get(key) == STATE for key in ("backend_pre", "backend_after_init", "backend_post")), "backend_pin_or_lock_differ")
    require(receipt.get("lock") is True and receipt.get("native_plan_exit") == 2 and receipt.get("plan_attempted") == 1,
            "locked_native_plan_once")
    require(receipt.get("secret_receipt_sha256") == sha256(secret_receipt_raw).hexdigest(), "exact_secret_receipt_bundle")
    require(receipt.get("plan_binary_sha256") == sha256(binary).hexdigest()
            and receipt.get("native_json_sha256") == sha256(plan_raw).hexdigest()
            and 0 < len(binary) <= 64 * 1024 * 1024 and 0 < len(plan_raw) <= 64 * 1024 * 1024, "native_plan_files_differ")


def verify_custody(terminal, preflight, plan_raw, binary, manifest):
    require(terminal.get("completed_steps") == GATEWAY_COMPLETE and terminal.get("bucket") == BUCKET,
            "terminal_gateway_scope")
    prefix = f"private-plans/int/{preflight['controls_commit']}/{preflight['run_id']}-{preflight['run_attempt']}/"
    for name, body in (("int.tfplan", binary), ("int.json", plan_raw), ("manifest.json", manifest)):
        row = terminal["objects"][name]
        require(set(row) == {"name", "generation", "sha256", "size"} and row["name"] == prefix + name
                and NUMERIC.fullmatch(row["generation"]) and row["size"] == len(body)
                and row["sha256"] == sha256(body).hexdigest(), "immutable_custody_reference")
    require(set(terminal["objects"]) == {"int.tfplan", "int.json", "manifest.json"}, "only_three_custody_objects")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-json", required=True, type=Path)
    parser.add_argument("--native-binary", required=True, type=Path)
    parser.add_argument("--native-receipt", required=True, type=Path)
    parser.add_argument("--versions-from-receipts", required=True, type=Path)
    parser.add_argument("--approved-controls-commit", required=True)
    parser.add_argument("--custody-receipt", type=Path)
    parser.add_argument("--custody-manifest", type=Path)
    args = parser.parse_args()
    try:
        plan_raw = args.native_json.read_bytes()
        receipt_raw = args.versions_from_receipts.read_bytes()
        gateway_receipt = json.loads(args.native_receipt.read_bytes())
        binary = args.native_binary.read_bytes()
        verify_production_receipt(gateway_receipt, plan_raw, binary, args.approved_controls_commit, receipt_raw)
        result = verify_diff(json.loads(plan_raw), versions(json.loads(receipt_raw)))
        require(bool(args.custody_manifest) == bool(args.custody_receipt), "both_custody_inputs_required")
        if args.custody_receipt:
            verify_custody(json.loads(args.custody_receipt.read_bytes()), gateway_receipt, plan_raw, binary,
                           args.custody_manifest.read_bytes())
        print(json.dumps({"status": "scope_verified_for_review", **result, "custody_still_required": not args.custody_receipt,
                          "plan_apply_authorized": False}))
        return 0
    except (ValueError, TypeError, KeyError, AttributeError, OSError) as error:
        label = str(error) if type(error) is ValueError and re.fullmatch(r"[a-z0-9_]+", str(error)) else type(error).__name__
        print(json.dumps({"status": "blocked", "failure": label, "plan_apply_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
