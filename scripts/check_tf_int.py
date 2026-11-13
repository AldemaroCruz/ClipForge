"""Pure contracts for the plan-only INT root and its public summary.

No cloud calls, application imports, credential discovery or state access.
"""
from __future__ import annotations

from collections import Counter
import ipaddress
import re


PROJECT = "clipforgebeta2"
NUMBER = "816643438938"
REGION = "us-central1"
BUCKET = "clipforgebeta2-tfstate-int"
PREFIX = "terraform/int/tf-int-01"
VARIABLES = {"project_id", "machine_type", "run_subnet_cidr", "postgres_subnet_cidr", "data_disk_gb", "runtime_image", "secret_versions", "stage"}
FILES = ("versions.tf", "variables.tf", "main.tf", "outputs.tf", "backend-int.hcl",
         "runtime.tf", "audit.tf", ".terraform.lock.hcl", "postgres-install.sh", "tests/contracts.tftest.hcl")
ADDRESSES = {
    "terraform_data.boundary", "google_compute_network.int",
    'google_compute_subnetwork.private["run"]', 'google_compute_subnetwork.private["postgres"]',
    "google_compute_route.egress", "google_compute_router.egress", "google_compute_router_nat.maintenance",
    "google_compute_address.postgres", "google_compute_firewall.postgres", "google_compute_firewall.iap",
    "google_compute_firewall.https", "google_compute_firewall.deny_egress", "google_compute_disk.postgres",
    "google_compute_instance.postgres", 'google_storage_bucket.private["media"]',
    'google_storage_bucket.private["backups"]',
}
ADDRESSES |= {
    *{'google_secret_manager_secret_iam_member.version_publisher["' + key + '"]' for key in
      ("app_password", "migrator_password", "postgres_ca", "bootstrap_admin")},
    "google_compute_instance_iam_member.protected_bootstrap", "google_iap_tunnel_instance_iam_member.protected_bootstrap",
    "google_service_account_iam_member.protected_bootstrap", "google_project_iam_custom_role.bootstrap_reader",
    "google_project_iam_member.bootstrap_reader",
    'google_secret_manager_secret.runtime["postgres-ca"]', 'google_secret_manager_secret.runtime["bootstrap-admin"]',
    *{'google_secret_manager_secret_iam_member.runtime["' + key + '"]' for key in
      ("api_password", "worker_password", "migrate_password", "api_ca", "worker_ca", "migrate_ca", "bootstrap_admin")},
    'google_storage_bucket_iam_member.media["api"]', 'google_storage_bucket_iam_member.media["worker"]',
    "google_storage_bucket_iam_member.backup_writer", "google_cloud_run_v2_service.api[0]",
    "google_cloud_run_v2_service_iam_member.iap_invoker[0]", "google_iap_web_cloud_run_service_iam_member.pilot_admin[0]",
    *{'google_cloud_run_v2_job.task["' + key + '"]' for key in ("worker", "migrate", "bootstrap")},
    "google_cloud_run_v2_job_iam_member.api_worker[0]", "google_project_iam_audit_config.storage_access",
    *{'google_cloud_run_v2_job_iam_member.protected_operator["' + key + '"]' for key in ("worker", "migrate", "bootstrap")},
    "google_logging_project_bucket_config.access", "google_logging_project_sink.access",
    "google_logging_log_view.access", "google_logging_log_view_iam_member.audit_reader",
}
RUNTIME_ADDRESSES = {a for a in ADDRESSES if a.startswith(("google_cloud_run_", "google_iap_web_cloud_run_"))}
FOUNDATION_ADDRESSES = ADDRESSES - RUNTIME_ADDRESSES
DATA_TYPES = {"google_project", "google_storage_bucket", "google_artifact_registry_repository",
              "google_iam_workload_identity_pool_provider", "google_service_account",
              "google_secret_manager_secret", "google_compute_image"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_contract(root):
    """Read only the small explicit module inventory; never traverse sibling drafts."""
    sources = {name: (root / name).read_text(encoding="utf-8") for name in FILES}
    hcl = "\n".join(sources[name] for name in ("main.tf", "runtime.tf", "audit.tf", "variables.tf", "outputs.tf", "versions.tf"))
    require(set(re.findall(r'variable\s+"([^"]+)"', hcl)) == VARIABLES, "Unexpected Terraform inputs")
    resources = re.findall(r'resource\s+"([^"]+)"\s+"([^"]+)"', hcl)
    expected = {re.sub(r'\[.*', '', a) for a in ADDRESSES}
    require({kind + "." + name for kind, name in resources} == expected, "Unexpected or missing managed resources")
    require(set(re.findall(r'data\s+"([^"]+)"', hcl)) == DATA_TYPES, "Only bootstrap metadata and image data sources are allowed")
    require(not re.search(r'\b(provisioner|module)\s+"', hcl), "No provisioners or external modules are allowed")
    require('required_version = "= 1.15.8"' in hcl and 'version = "= 8.11.0"' in hcl,
            "Terraform and Google provider versions must stay pinned")
    require(len(re.findall(r'prevent_destroy\s*=\s*true', sources['main.tf'])) == 3,
            "VM, data disk and both bucket instances require prevent_destroy")
    return sources


def runtime_inputs(image, versions, stage="runtime"):
    require(bool(re.fullmatch(r"us-central1-docker\.pkg\.dev/clipforgebeta2/clipforge-int/runtime@sha256:[a-f0-9]{64}", image)),
            "Runtime must use the reviewed repository and exact OCI manifest digest")
    valid = (isinstance(versions, dict) and set(versions) == {"app_password", "migrator_password", "postgres_ca", "bootstrap_admin"}
             and all(isinstance(v, str) and re.fullmatch(r"[1-9][0-9]*", v) for v in versions.values()))
    require((stage == "foundation" and versions is None) or valid,
            "Only pinned nonsecret Secret Manager version numbers may enter Terraform")
    return {"runtime_image": image, "secret_versions": versions}


def backend_contract(bucket):
    require(bucket.get("name") == BUCKET and str(bucket.get("projectNumber")) == NUMBER,
            "State bucket project identity differs from bootstrap")
    iam = bucket.get("iamConfiguration", {})
    require(iam.get("uniformBucketLevelAccess", {}).get("enabled") is True
            and iam.get("publicAccessPrevention") == "enforced"
            and bucket.get("versioning", {}).get("enabled") is True,
            "Backend requires uniform access, public access prevention and versioning")


def detailed_exit(code):
    require(type(code) is int and code in (0, 1, 2), "Unexpected Terraform plan exit status")
    return {0: "no_changes", 1: "error", 2: "changes"}[code]


def validate_variables(environ):
    expected = {"GCP_PROJECT_ID": PROJECT, "GCP_PROJECT_NUMBER": NUMBER, "GCP_REGION": REGION,
                "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
                "GCP_WIF_PROVIDER": "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
                "TF_STATE_BUCKET": BUCKET, "TF_STATE_PREFIX": "terraform/int"}
    require(all(environ.get(k) == v for k, v in expected.items()), "GitHub INT variables differ from bootstrap")
    require(environ.get("MACHINE_TYPE", "e2-micro") in {"e2-micro", "e2-small"}, "Unreviewed machine profile")
    require(not any(k.startswith(("TF_VAR_", "TF_CLI_ARGS", "TF_LOG")) for k in environ),
            "Ambient Terraform variables, CLI arguments and debug logs are forbidden")


def diagnostic(operation, message, status=None):
    """Publish identifiers and bounded deny messages, never arbitrary command output."""
    permissions = sorted(set(re.findall(
        r'\b(?:storage|compute|iam|artifactregistry|secretmanager|resourcemanager|serviceusage)\.[A-Za-z0-9_.]+', message)))
    resources = sorted(set(re.findall(r'\b(?:projects|buckets)/[A-Za-z0-9_./@:-]+', message)))
    lines = []
    for line in message.splitlines():
        if re.search(r'403|PERMISSION_DENIED|[Pp]ermission .{0,180}denied|googleapi: Error', line):
            if re.search(r'(?i)bearer|ya29\.|eyJ|password|credential|access.?token|private.?key', line):
                continue
            lines.append(re.sub(r'\x1b\[[0-9;]*m', '', line).strip()[:600])
    return {"operation": operation, "status": status, "permissions": permissions[:20],
            "resources": resources[:20], "messages": lines[:10]}


def plan_contract(plan, startup):
    require(set(plan.get("variables", {})) == VARIABLES, "Plan contains undeclared or secret inputs")
    require(set(plan.get("output_changes", {})) <= {"reviewed_boundary"}, "Unreviewed plan outputs")
    changes = [r for r in plan.get("resource_changes", []) if r["mode"] == "managed"]
    stage = plan["variables"]["stage"]["value"]
    require(stage in {"foundation", "runtime"}, "Unknown deployment phase")
    require({r["address"] for r in changes} == (ADDRESSES if stage == "runtime" else FOUNDATION_ADDRESSES),
            "Plan must include the complete reviewed phase; targeting is forbidden")
    require(all(r["type"] in DATA_TYPES for r in plan.get("resource_changes", []) if r["mode"] == "data"),
            "Plan must not read secret versions or external data")
    for row in changes:
        change = row["change"]
        require(change["actions"] in (["create"], ["update"], ["no-op"]), "Destructive or replacement action detected")
        after, before = change.get("after") or {}, change.get("before") or {}
        if row["type"] == "google_compute_instance":
            interfaces = after.get("network_interface", [])
            require(len(interfaces) == 1 and not interfaces[0].get("access_config")
                    and not interfaces[0].get("ipv6_access_config"), "Public PostgreSQL address is forbidden")
            require(after.get("deletion_protection") is True and after.get("can_ip_forward") is False,
                    "VM protections are missing")
            require(after.get("machine_type") in {"e2-micro", "e2-small"}, "Unexpected VM capacity profile")
            require(len(after.get("attached_disk", [])) == 1 and after["attached_disk"][0].get("device_name") == "clipforge-pg-data",
                    "Separate persistent data disk is required")
            require(len(after.get("boot_disk", [])) == 1 and after["boot_disk"][0].get("auto_delete") is False,
                    "Boot disk must not auto-delete")
            expected_metadata = {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE",
                                 "disable-legacy-endpoints": "TRUE", "serial-port-enable": "FALSE"}
            require(after.get("metadata") == expected_metadata and after.get("metadata_startup_script") == startup,
                    "VM metadata must contain only the reviewed nonsecret configuration")
            shielded = after.get("shielded_instance_config", [])
            require(len(shielded) == 1 and all(shielded[0].get(k) is True for k in ["enable_secure_boot", "enable_vtpm", "enable_integrity_monitoring"]),
                    "Shielded VM protections are required")
        elif row["type"] == "google_compute_disk":
            require(after.get("size", 0) >= max(20, before.get("size", 0)) and after.get("type") == "pd-standard",
                    "Data disk removal, shrink or unreviewed storage profile is forbidden")
        elif row["type"] == "google_storage_bucket":
            require(after.get("force_destroy") is False and after.get("uniform_bucket_level_access") is True
                    and after.get("public_access_prevention") == "enforced", "Private nondestructive bucket settings are required")
            require(after.get("versioning") == [{"enabled": True}], "Bucket versioning is required")
        elif row["type"] == "google_compute_subnetwork":
            require(ipaddress.ip_network(after["ip_cidr_range"]).is_private and after.get("private_ip_google_access") is True
                    and after.get("stack_type") == "IPV4_ONLY", "Only private IPv4 subnets are allowed")
        elif row["type"] == "google_compute_firewall":
            role = row["name"]
            require(after.get("target_service_accounts") == ["clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"],
                    "Firewall must target only the PostgreSQL identity")
            if role in {"postgres", "iap"}:
                ranges = after.get("source_ranges", [])
                require(after.get("direction") == "INGRESS" and len(ranges) == 1, "Unexpected ingress rule")
                require((role == "iap" and ranges == ["35.235.240.0/20"])
                        or (role == "postgres" and ipaddress.ip_network(ranges[0]).is_private), "Public database or SSH ingress is forbidden")
                require(after.get("allow") == [{"protocol": "tcp", "ports": ["22" if role == "iap" else "5432"]}],
                        "Ingress allows unreviewed ports")
            elif role == "https":
                require(after.get("direction") == "EGRESS" and after.get("allow") == [{"protocol": "tcp", "ports": ["443"]}],
                        "Maintenance egress must be HTTPS only")
            else:
                rules = after.get("deny", [])
                require(after.get("direction") == "EGRESS" and len(rules) == 1
                        and rules[0].get("protocol") == "all" and not rules[0].get("ports"),
                        "Other egress must be denied")
        elif row["type"] == "google_compute_address":
            require(after.get("address_type") == "INTERNAL", "VM address must be internal")
        elif row["type"] == "google_compute_network":
            require(after.get("auto_create_subnetworks") is False, "No default or automatic subnets")
        elif row["type"] == "google_compute_router_nat":
            require(after.get("source_subnetwork_ip_ranges_to_nat") == "LIST_OF_SUBNETWORKS"
                    and len(after.get("subnetwork", [])) == 1, "NAT must cover only the PostgreSQL subnet")
        elif row["type"] == "google_cloud_run_v2_service":
            require(after.get("iap_enabled") is True and after.get("invoker_iam_disabled") is not True,
                    "Built-in IAP and native IAM invocation checks are mandatory")
            templates = after.get("template", [])
            scaling = templates[0].get("scaling", [{}])[0] if len(templates) == 1 else {}
            require(len(templates) == 1 and scaling.get("min_instance_count") == 0 and scaling.get("max_instance_count") == 1,
                    "API must scale only from zero to one instance")
            runtime_template(templates[0], plan["variables"])
        elif row["type"] == "google_cloud_run_v2_job":
            templates = after.get("template", [])
            require(len(templates) == 1 and templates[0].get("task_count") == 1 and templates[0].get("parallelism") == 1,
                    "Jobs must have one task; the worker also uses a persistent global DB lock")
            tasks = templates[0].get("template", [])
            require(len(tasks) == 1 and tasks[0].get("max_retries") == 0, "No automatic multimedia retry storm")
            runtime_template(tasks[0], plan["variables"])
        elif row["type"] == "google_project_iam_audit_config":
            require(after.get("service") == "storage.googleapis.com" and
                    {r.get("log_type") for r in after.get("audit_log_config", [])} == {"ADMIN_READ", "DATA_READ", "DATA_WRITE"}
                    and not any(r.get("exempted_members") for r in after.get("audit_log_config", [])),
                    "GCS Data Access must cover reads and writes without exemptions")
        elif row["type"] == "google_logging_project_bucket_config":
            require(after.get("retention_days") == 30, "Pilot audit retention must be explicit: 30 days")
        elif "_iam_member" in row["type"]:
            member = after.get("member", "")
            require(member not in {"allUsers", "allAuthenticatedUsers"}, "Public IAM principals are forbidden")
            require(member == expected_iam_member(row["address"]), "IAM principal differs from the explicitly proposed identity")
            if row["name"] in {"pilot_admin", "audit_reader"}:
                require(member == "user:admin@ixbalam.studio", "Only the pilot owner may receive IAP/audit access")
            elif row["name"] == "iap_invoker":
                require(member == "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com"
                        and after.get("role") == "roles/run.invoker", "Only the IAP agent may invoke the API")
            require(after.get("role") == expected_iam_role(row["address"])
                    or (row["address"] == "google_project_iam_member.bootstrap_reader"
                        and after.get("role") is None and row["change"].get("after_unknown", {}).get("role") is True),
                    "IAM role differs from the explicitly proposed least-privilege grant")
        elif row["type"] == "google_project_iam_custom_role":
            require(set(after.get("permissions", [])) == {"compute.instances.get", "compute.disks.get", "compute.projects.get", "run.operations.get"},
                    "Bootstrap custom role must remain four metadata GET operations only")
    counts = Counter(action for r in changes for action in r["change"]["actions"])
    return {"counts": dict(counts), "destructive_actions": False,
            "resources": [{"address": r["address"], "type": r["type"], "actions": r["change"]["actions"],
                           "after": public_after(r)} for r in changes]}


def expected_iam_role(address):
    exact = {"google_storage_bucket_iam_member.backup_writer": "roles/storage.objectCreator",
             "google_compute_instance_iam_member.protected_bootstrap": "roles/compute.osAdminLogin",
             "google_iap_tunnel_instance_iam_member.protected_bootstrap": "roles/iap.tunnelResourceAccessor",
             "google_service_account_iam_member.protected_bootstrap": "roles/iam.serviceAccountUser",
             "google_project_iam_member.bootstrap_reader": "projects/clipforgebeta2/roles/clipforgeIntBootstrapReader",
             "google_cloud_run_v2_service_iam_member.iap_invoker[0]": "roles/run.invoker",
             "google_iap_web_cloud_run_service_iam_member.pilot_admin[0]": "roles/iap.httpsResourceAccessor",
             "google_cloud_run_v2_job_iam_member.api_worker[0]": "roles/run.invoker",
             "google_logging_log_view_iam_member.audit_reader": "roles/logging.viewAccessor"}
    if address in exact:
        return exact[address]
    for prefix, role in {"google_secret_manager_secret_iam_member.runtime[": "roles/secretmanager.secretAccessor",
                         "google_secret_manager_secret_iam_member.version_publisher[": "roles/secretmanager.secretVersionAdder",
                         "google_storage_bucket_iam_member.media[": "roles/storage.objectUser",
                         "google_cloud_run_v2_job_iam_member.protected_operator[": "roles/run.invoker"}.items():
        if address.startswith(prefix):
            return role
    raise ValueError("Unexpected IAM grant")


def expected_iam_member(address):
    if address in {"google_iap_web_cloud_run_service_iam_member.pilot_admin[0]", "google_logging_log_view_iam_member.audit_reader"}:
        return "user:admin@ixbalam.studio"
    if address == "google_cloud_run_v2_service_iam_member.iap_invoker[0]":
        return "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com"
    account = "deploy"
    if address.startswith("google_secret_manager_secret_iam_member.runtime["):
        key = address.split('["', 1)[1].split('"', 1)[0]
        account = "migrate" if key == "bootstrap_admin" else key.split("_", 1)[0]
    elif address.startswith("google_storage_bucket_iam_member.media["):
        account = address.split('["', 1)[1].split('"', 1)[0]
    elif address == "google_storage_bucket_iam_member.backup_writer":
        account = "postgres"
    elif address == "google_cloud_run_v2_job_iam_member.api_worker[0]":
        account = "api"
    require(account in {"deploy", "api", "worker", "migrate", "postgres"}, "Unexpected service identity")
    return "serviceAccount:clipforge-" + account + "-int@clipforgebeta2.iam.gserviceaccount.com"


def runtime_template(template, variables):
    """Never permit inline secret values or local-only laboratory switches."""
    image = variables["runtime_image"]["value"]
    runtime_inputs(image, variables["secret_versions"]["value"])
    containers = template.get("containers", [])
    require(len(containers) == 1 and containers[0].get("image") == image, "Every runtime must use the same reviewed digest")
    for env in containers[0].get("env", []):
        name = env.get("name", "")
        require(name not in {"CLIPFORGE_CLOUD_LOCAL_TEST", "CLIPFORGE_DATABASE_URL", "GOOGLE_APPLICATION_CREDENTIALS"}
                and (not re.search(r"PASSWORD|TOKEN|KEY|CREDENTIAL", name) or name.endswith("_FILE")),
                "Inline secrets and local laboratory switches are forbidden")
    vpc = template.get("vpc_access", [])
    require(len(vpc) == 1 and vpc[0].get("egress") == "PRIVATE_RANGES_ONLY", "Runtime must use private Direct VPC egress")


def public_after(row):
    """An allowlist, never recursive copying of unknown plan values."""
    value = row["change"].get("after") or {}
    fields = ("name", "project", "location", "region", "zone", "machine_type", "size", "type", "address_type",
              "address", "ip_cidr_range", "direction", "source_ranges", "destination_ranges", "allow", "deny",
              "deletion_protection", "iap_enabled", "ingress", "force_destroy", "uniform_bucket_level_access",
              "public_access_prevention", "versioning", "retention_policy", "soft_delete_policy", "lifecycle_rule",
              "role", "member", "bucket", "secret_id", "retention_days", "bucket_id", "service", "audit_log_config",
              "filter", "destination", "network", "subnetwork", "auto_create_subnetworks", "permissions")
    safe = {k: value[k] for k in fields if k in value}
    if row["type"] == "google_compute_instance":
        safe["boot_disk"] = [{"auto_delete": b.get("auto_delete"), "initialize_params": b.get("initialize_params")}
                             for b in value.get("boot_disk", [])]
        safe["network_exposure"] = "private IP only; IAP SSH; TCP5432 only from Run subnet"
    if row["type"] in {"google_cloud_run_v2_service", "google_cloud_run_v2_job"}:
        top = value.get("template", [{}])[0]
        template = top.get("template", [top])[0]
        safe["runtime"] = {"service_account": template.get("service_account"), "scaling": template.get("scaling"),
                           "task_count": top.get("task_count"), "parallelism": top.get("parallelism"),
                           "timeout": template.get("timeout"), "max_retries": template.get("max_retries"),
                           "containers": [{"image": c.get("image"), "command": c.get("command"), "args": c.get("args"),
                                           "resources": c.get("resources")} for c in template.get("containers", [])]}
    return safe
