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
VARIABLES = {"project_id", "machine_type", "run_subnet_cidr", "postgres_subnet_cidr", "data_disk_gb"}
FILES = ("versions.tf", "variables.tf", "main.tf", "outputs.tf", "backend-int.hcl",
         ".terraform.lock.hcl", "postgres-install.sh", "tests/contracts.tftest.hcl")
ADDRESSES = {
    "terraform_data.boundary", "google_compute_network.int",
    'google_compute_subnetwork.private["run"]', 'google_compute_subnetwork.private["postgres"]',
    "google_compute_route.egress", "google_compute_router.egress", "google_compute_router_nat.maintenance",
    "google_compute_address.postgres", "google_compute_firewall.postgres", "google_compute_firewall.iap",
    "google_compute_firewall.https", "google_compute_firewall.deny_egress", "google_compute_disk.postgres",
    "google_compute_instance.postgres", 'google_storage_bucket.private["media"]',
    'google_storage_bucket.private["backups"]',
}
DATA_TYPES = {"google_project", "google_storage_bucket", "google_artifact_registry_repository",
              "google_iam_workload_identity_pool_provider", "google_service_account",
              "google_secret_manager_secret", "google_compute_image"}


def require(condition, message):
    if not condition:
        raise ValueError(message)


def source_contract(root):
    """Read only the small explicit module inventory; never traverse sibling drafts."""
    sources = {name: (root / name).read_text(encoding="utf-8") for name in FILES}
    hcl = "\n".join(sources[name] for name in ("main.tf", "variables.tf", "outputs.tf", "versions.tf"))
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


def backend_contract(bucket, listing):
    require(bucket.get("name") == BUCKET and str(bucket.get("projectNumber")) == NUMBER,
            "State bucket project identity differs from bootstrap")
    iam = bucket.get("iamConfiguration", {})
    require(iam.get("uniformBucketLevelAccess", {}).get("enabled") is True
            and iam.get("publicAccessPrevention") == "enforced"
            and bucket.get("versioning", {}).get("enabled") is True,
            "Backend requires uniform access, public access prevention and versioning")
    require(not listing.get("items") and not listing.get("nextPageToken"),
            "The TF-INT-01 prefix is occupied; no state adoption, deletion or force-unlock is allowed")


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
    require({r["address"] for r in changes} == ADDRESSES, "Plan must include the complete reviewed root")
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
    counts = Counter(action for r in changes for action in r["change"]["actions"])
    return {"counts": dict(counts), "destructive_actions": False,
            "resources": [{"address": r["address"], "actions": r["change"]["actions"]} for r in changes]}
