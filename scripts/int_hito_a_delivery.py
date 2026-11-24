"""Single protected Hito A delivery entry point for INT.

The GitHub environment approval is the one deployment decision.  Every phase
is bound to the checked-out commit and the exact OCI archive; sensitive values
are accepted only through environment variables and are never written to the
delivery state or command line.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tarfile
from urllib.request import Request, build_opener, ProxyHandler

from scripts import int_bootstrap_vm as legacy_operator
from scripts import int_hito_a_db_credentials as db_credentials
from scripts import int_hito_a_db_probe as db_probe
from scripts import int_noble_hostkey as noble_hostkey
from scripts import int_noble_bootstrap_payloads as noble_payloads
from scripts import int_release
from scripts import int_release_image
from scripts import int_secrets


PROJECT = "clipforgebeta2"
PROJECT_NUMBER = "816643438938"
REGION = "us-central1"
ZONE = "us-central1-a"
INSTANCE = "clipforge-int-db01-noble"
INSTANCE_ID = "7365414160255801909"
BOOT_DISK_ID = "8897353356069952044"
DATA_DISK = "clipforge-int-db01-noble-data"
DATA_DISK_ID = "7382984635240536620"
DATA_DEVICE = "clipforge-noble-pg-data"
PRIVATE_IP = "10.80.1.3"
SERVICE = "clipforge-int-api"
MIGRATION_JOB = "clipforge-int-migrate"
BOOTSTRAP_JOB = "clipforge-int-bootstrap"
IMAGE_PREFIX = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:"
TERRAFORM_VERSION = "1.15.8"
GCLOUD_VERSION = "582.0.0"
NOBLE_HOST_RECORD_NONCE = "c17af30d152fe6991cae09fdbff8db31c08dcac6360abb73084e2c3737c0cdf8"
NOBLE_HOST_RECORD_PUBLISHER_SHA256 = "0400c905a0cf8578d8315e608afdca3a87aed6521f8ae36b449b9d675cd87cc5"
STATE_SCHEMA = "clipforge-int-hito-a-delivery-state-1"
RECEIPT_SCHEMA = "clipforge-int-hito-a-delivery-receipt-1"
HEX64 = re.compile(r"[a-f0-9]{64}")
SHA = re.compile(r"[a-f0-9]{40}")
NUMBER = re.compile(r"[1-9][0-9]*")

BASE_FILES = (
    "versions.tf", "variables.tf", "main.tf", "outputs.tf", "audit.tf",
    "backend-int.hcl", ".terraform.lock.hcl", "postgres-install.sh",
    "db01-noble-startup.sh", "db01-noble-hostkey-template.sh",
)
OVERLAYS = ("runtime.tf", "noble-candidate.tf")
ALLOWED_CREATES = {
    "google_compute_firewall.noble_postgres_from_run[0]",
    "google_cloud_run_v2_service.api[0]",
    "google_cloud_run_v2_service_iam_member.iap_invoker[0]",
    "google_iap_web_cloud_run_service_iam_member.pilot_admin[0]",
    "google_iap_web_cloud_run_service_iam_member.deploy_acceptance[0]",
    "google_secret_manager_secret_iam_member.bootstrap_admin_human[0]",
    'google_cloud_run_v2_job.task["migrate"]',
    'google_cloud_run_v2_job.task["bootstrap"]',
    'google_cloud_run_v2_job_iam_member.protected_operator["migrate"]',
    'google_cloud_run_v2_job_iam_member.protected_operator["bootstrap"]',
}
ALLOWED_UPDATES = {
    "google_cloud_run_v2_service.api[0]",
    'google_cloud_run_v2_job.task["migrate"]',
    'google_cloud_run_v2_job.task["bootstrap"]',
}
REQUIRED_RUNTIME = ALLOWED_CREATES
SECRET_ENV = {
    "app_password": "INT_PG_APP_PASSWORD",
    "migrator_password": "INT_PG_MIGRATOR_PASSWORD",
    "ca_cert": "INT_PG_CA_CERT",
    "server_cert": "INT_PG_SERVER_CERT",
    "server_key": "INT_PG_SERVER_KEY",
    "bootstrap_admin": "INT_BOOTSTRAP_ADMIN",
}


class DeliveryBlocked(ValueError):
    """Closed diagnostic code; protected payloads never enter the message."""


def require(condition, code):
    if not condition:
        raise DeliveryBlocked(code)


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def root():
    return Path(__file__).resolve().parents[1]


def context(env):
    expected = {
        "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
        "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF":
            "AldemaroCruz/ClipForge/.github/workflows/int-hito-a.yml@refs/heads/ci/bootstrap-sec03",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_JOB": "deploy",
        "GITHUB_RUN_ATTEMPT": "1",
        "GCP_WIF_PROVIDER":
            "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
        "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
        "GCP_DEPLOY_SA": "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com",
        "ARTIFACT_REGISTRY_REPOSITORY": "clipforge-int",
        "CLOUD_RUN_SERVICE": SERVICE,
        "INT_MIGRATION_JOB": MIGRATION_JOB,
        "INT_BOOTSTRAP_JOB": BOOTSTRAP_JOB,
        "TF_STATE_BUCKET": "clipforgebeta2-tfstate-int",
        "TF_STATE_PREFIX": "terraform/int",
    }
    require(all(env.get(key) == value for key, value in expected.items()), "protected_deploy_context")
    commit = env.get("GITHUB_SHA", "")
    require(SHA.fullmatch(commit) and env.get("INT_APPROVED_COMMIT") == commit,
            "exact_delivery_commit")
    require(NUMBER.fullmatch(env.get("GITHUB_RUN_ID", "")) and
            NUMBER.fullmatch(env.get("GITHUB_RUN_ATTEMPT", "")), "delivery_run_identity")
    require(env.get("GCP_PROJECT_ID") == PROJECT and env.get("GCP_PROJECT_NUMBER") == PROJECT_NUMBER
            and env.get("GCP_REGION") == REGION, "delivery_project_scope")
    return commit


def scratch(env):
    runner = Path(env["RUNNER_TEMP"]).resolve()
    value = Path(env["INT_HITO_A_SCRATCH"]).resolve()
    require(value.parent == runner and value.name.startswith("clipforge-int-hito-a.")
            and value.is_dir() and not value.is_symlink(), "private_delivery_scratch")
    return value


def state_path(env):
    return scratch(env) / "delivery-state.json"


def _write_json(path, value):
    raw = canonical(value) + b"\n"
    temporary = path.with_name("." + path.name + "." + os.urandom(8).hex())
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(raw)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary.exists():
            temporary.unlink()


def load_state(env, phases=None):
    path = state_path(env)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 65536,
            "delivery_state_missing")
    value = json.loads(path.read_bytes())
    require(isinstance(value, dict) and value.get("schema") == STATE_SCHEMA
            and value.get("commit") == context(env)
            and value.get("run_id") == env["GITHUB_RUN_ID"]
            and value.get("run_attempt") == env["GITHUB_RUN_ATTEMPT"]
            and value.get("image", "").startswith(IMAGE_PREFIX), "delivery_state_binding")
    if phases is not None:
        require(value.get("phase") in phases, "delivery_phase_order")
    return value


def save_state(env, value):
    value["updated_utc"] = datetime.now(timezone.utc).isoformat()
    _write_json(state_path(env), value)
    receipt = {
        "schema": RECEIPT_SCHEMA,
        "status": value["phase"],
        "commit": value["commit"],
        "run_id": value["run_id"],
        "run_attempt": value["run_attempt"],
        "image": value["image"],
        "manifest_digest": value["manifest_digest"],
        "archive_sha256": value["archive_sha256"],
        "database": value.get("database"),
        "terraform_plan_sha256": value.get("terraform_plan_sha256"),
        "migration": value.get("migration"),
        "acceptance": value.get("acceptance"),
        "browser_acceptance": value.get("browser_acceptance"),
        "rollback": value.get("rollback"),
        "updated_utc": value["updated_utc"],
    }
    _write_json(scratch(env) / "delivery-receipt.json", receipt)


def verify_artifact(env):
    commit = context(env)
    require(env.get("INT_HITO_A_API_RESULT") == "success"
            and env.get("INT_HITO_A_SCANS_PASSED") == "true", "api_candidate_gates")
    target = Path(env["INT_RUNTIME_ARCHIVE"]).resolve()
    private = scratch(env)
    require(target == private / "runtime.oci.tar" and target.is_file() and not target.is_symlink(),
            "runtime_archive_path")
    expected_sha = env.get("EXPECTED_ARCHIVE_SHA256", "")
    expected_size = env.get("EXPECTED_ARCHIVE_SIZE", "")
    require(HEX64.fullmatch(expected_sha) and expected_size.isdigit() and int(expected_size) > 0,
            "runtime_archive_identity")
    with target.open("rb") as stream:
        actual_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    digest = int_release_image.archive_digest(target)
    image = env.get("RUNTIME_IMAGE", "")
    require(actual_sha == expected_sha and target.stat().st_size == int(expected_size)
            and image == IMAGE_PREFIX + digest.removeprefix("sha256:"), "runtime_archive_changed")
    value = {
        "schema": STATE_SCHEMA,
        "phase": "artifact_verified",
        "commit": commit,
        "run_id": env["GITHUB_RUN_ID"],
        "run_attempt": env["GITHUB_RUN_ATTEMPT"],
        "image": image,
        "manifest_digest": digest,
        "archive_sha256": actual_sha,
        "archive_size": target.stat().st_size,
        "api_result": "success",
        "runtime_scans_passed": True,
    }
    save_state(env, value)
    return value


def publish(env):
    value = load_state(env, {"cloud_preflighted"})
    require(env.get("RUNTIME_IMAGE") == value["image"], "publish_image_binding")
    require(value.get("api_result") == "success" and value.get("runtime_scans_passed") is True,
            "publish_scan_binding")
    int_release_image.publish(Path(env["INT_RUNTIME_ARCHIVE"]), env, delivery="int-hito-a")
    value["phase"] = "published"
    value["publication_verified"] = True
    save_state(env, value)
    return value


def preflight(env):
    value = load_state(env, {"artifact_verified"})
    _require_delivery_iam_permissions(env)
    value["phase"] = "cloud_preflighted"
    value["bootstrap_access_grant_permission"] = True
    value["iap_policy_permissions"] = True
    save_state(env, value)
    return value


def _gcloud_binary():
    binary = shutil.which("gcloud")
    require(binary is not None and Path(binary).is_absolute(), "gcloud_required")
    result = subprocess.run([binary, "version", "--format=json"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False)
    require(result.returncode == 0 and len(result.stdout) <= 65536
            and json.loads(result.stdout).get("Google Cloud SDK") == GCLOUD_VERSION,
            "gcloud_version")
    return binary


def _run(command, *, input_data=None, timeout=300, output_limit=2 * 1024 * 1024):
    result = subprocess.run(command, input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            timeout=timeout, check=False)
    require(len(result.stdout) <= output_limit and len(result.stderr) <= 65536, "bounded_command_output")
    if result.returncode != 0:
        raise DeliveryBlocked("protected_command_failed")
    return result.stdout


def _gcloud_json(arguments):
    raw = _run([_gcloud_binary(), *arguments, "--quiet"], timeout=120, output_limit=1024 * 1024)
    try:
        value = json.loads(raw)
    except (ValueError, UnicodeError):
        raise DeliveryBlocked("gcloud_json_response") from None
    require(isinstance(value, dict), "gcloud_json_object")
    return value


def _remote_loader(source, digest):
    require(HEX64.fullmatch(digest) and sha256(source) == digest, "remote_source_binding")
    encoded = base64.b64encode(source).decode("ascii")
    code = ("import base64;exec(compile(base64.b64decode(\"" + encoded +
            "\"),\"clipforge-int-hito-a-guest.py\",\"exec\"),"
            "{\"__name__\":\"__main__\",\"DB01_OPERATOR_SHA256\":\"" + digest + "\"})")
    return "/usr/bin/sudo -n /usr/bin/python3 -I -c '" + code + "'"


def _noble_host_pin(env):
    serial = _gcloud_json([
        "compute", "instances", "get-serial-port-output", INSTANCE,
        "--project=" + PROJECT, "--zone=" + ZONE, "--port=1", "--start=0",
        "--format=json",
    ])
    try:
        record = noble_hostkey.serial_record(
            serial, instance_id=INSTANCE_ID, nonce=NOBLE_HOST_RECORD_NONCE,
            publisher_sha256=NOBLE_HOST_RECORD_PUBLISHER_SHA256,
        )
    except (TypeError, ValueError, KeyError):
        raise DeliveryBlocked("noble_host_pin") from None
    line = (INSTANCE + "." + INSTANCE_ID + " " + record["public_key"] + "\n").encode("ascii")
    path = scratch(env) / "noble-known-hosts"
    if not path.exists():
        descriptor = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o400)
        with os.fdopen(descriptor, "wb") as stream:
            stream.write(line)
            stream.flush()
            os.fsync(stream.fileno())
    require(path.is_file() and not path.is_symlink()
            and (os.name != "posix" or path.stat().st_mode & 0o077 == 0)
            and path.read_bytes() == line, "noble_known_hosts")
    return path, record


def _ssh_public(source, env, *, protected_input=None, timeout=720):
    digest = sha256(source)
    known_hosts, host_record = _noble_host_pin(env)
    private_key = scratch(env) / "noble-id-ed25519"
    command = [
        _gcloud_binary(), "compute", "ssh", INSTANCE,
        "--project=" + PROJECT, "--zone=" + ZONE, "--tunnel-through-iap", "--quiet",
        "--verbosity=error", "--ssh-key-expire-after=10m",
        "--ssh-key-file=" + str(private_key),
        "--command=" + _remote_loader(source, digest),
        "--ssh-flag=-F=/dev/null",
        "--ssh-flag=-o=HostKeyAlias=" + INSTANCE + "." + INSTANCE_ID,
        "--ssh-flag=-o=StrictHostKeyChecking=yes",
        "--ssh-flag=-o=UserKnownHostsFile=" + str(known_hosts),
        "--ssh-flag=-o=GlobalKnownHostsFile=/dev/null",
        "--ssh-flag=-o=HostKeyAlgorithms=ssh-ed25519",
        "--ssh-flag=-o=UpdateHostKeys=no",
        "--ssh-flag=-o=BatchMode=yes", "--ssh-flag=-o=PasswordAuthentication=no",
        "--ssh-flag=-o=KbdInteractiveAuthentication=no",
        "--ssh-flag=-o=IdentitiesOnly=yes", "--ssh-flag=-o=IdentityAgent=none",
        "--ssh-flag=-o=PreferredAuthentications=publickey",
        "--ssh-flag=-o=ForwardAgent=no", "--ssh-flag=-o=CheckHostIP=no",
        "--ssh-flag=-o=ClearAllForwardings=yes", "--ssh-flag=-o=PermitLocalCommand=no",
        "--ssh-flag=-o=ConnectTimeout=30", "--ssh-flag=-o=ConnectionAttempts=1",
        "--ssh-flag=-o=ServerAliveInterval=10", "--ssh-flag=-o=ServerAliveCountMax=3",
    ]
    raw = _run(command, input_data=protected_input, timeout=timeout)
    lines = [line for line in raw.splitlines() if line.strip().startswith(b"{")]
    require(len(lines) == 1 and len(lines[0]) <= 2 * 1024 * 1024, "guest_json_receipt")
    try:
        return json.loads(lines[0]), host_record
    except (ValueError, UnicodeError):
        raise DeliveryBlocked("guest_json_receipt") from None


def _probe_database(env):
    source = Path(db_probe.__file__).read_bytes()
    value, host_record = _ssh_public(source, env, timeout=240)
    require(value.get("schema") == "clipforge-int-hito-a-db-probe-1"
            and value.get("state") in {"blank", "configured"}
            and value.get("read_only") is True
            and value.get("identity") == {"instance_id": INSTANCE_ID, "project_id": PROJECT,
                                           "project_number": PROJECT_NUMBER, "zone": ZONE},
            "database_probe_blocked")
    require(value.get("boot_id") == host_record.get("guest_boot_id"),
            "noble_first_boot_changed")
    return value, source


def _verify_existing_credentials(values, env, boot_id):
    source = Path(db_credentials.__file__).read_bytes()
    request = canonical({"app_password": values["app_password"],
                         "migrator_password": values["migrator_password"]})
    result, host_record = _ssh_public(source, env, protected_input=request, timeout=240)
    require(host_record.get("guest_boot_id") == boot_id
            and result == {
                "schema": "clipforge-int-hito-a-db-credentials-1",
                "status": "verified",
                "roles": ["clipforge_app", "clipforge_migrator"],
                "read_only": True,
            }, "configured_database_credentials_mismatch")


def _compute_proof(probe, probe_source, env):
    vm = _gcloud_json([
        "compute", "instances", "describe", INSTANCE, "--project=" + PROJECT, "--zone=" + ZONE,
        "--format=json(id,lastStartTimestamp,status,disks,networkInterfaces)",
    ])
    disk = _gcloud_json([
        "compute", "disks", "describe", DATA_DISK, "--project=" + PROJECT, "--zone=" + ZONE,
        "--format=json(id,name,sizeGb,status,type,users)",
    ])
    require(str(vm.get("id")) == INSTANCE_ID and vm.get("status") == "RUNNING"
            and str(disk.get("id")) == DATA_DISK_ID and disk.get("name") == DATA_DISK
            and str(disk.get("sizeGb")) == "20" and disk.get("status") == "READY",
            "noble_compute_identity")
    interfaces = vm.get("networkInterfaces", [])
    require(len(interfaces) == 1 and interfaces[0].get("networkIP") == PRIVATE_IP
            and not interfaces[0].get("accessConfigs"), "noble_private_network")
    attachments = [row for row in vm.get("disks", []) if row.get("deviceName") == DATA_DEVICE]
    require(len(attachments) == 1, "noble_data_attachment")
    attachment = attachments[0]
    require(str(attachment.get("source", "")).endswith("/disks/" + DATA_DISK)
            and attachment.get("interface") == "SCSI" and attachment.get("index") == 1
            and attachment.get("mode") == "READ_WRITE" and attachment.get("boot") is False
            and attachment.get("autoDelete") is False, "noble_data_attachment")
    disk_type = str(disk.get("type", ""))
    require(disk_type.endswith("/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard"),
            "noble_disk_type")
    disk_info = probe["disk"]
    require(re.fullmatch(r"[0-9]+:[0-9]+", disk_info.get("major_minor", ""))
            and disk_info.get("serial") == DATA_DEVICE, "noble_guest_disk_identity")
    return {
        "project_id": PROJECT,
        "project_number": PROJECT_NUMBER,
        "zone": ZONE,
        "instance_id": INSTANCE_ID,
        "boot_timestamp": vm["lastStartTimestamp"],
        "disk_id": DATA_DISK_ID,
        "disk_name": DATA_DISK,
        "device_name": DATA_DEVICE,
        "size_bytes": 20 * 1024 ** 3,
        "disk_type": "https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/diskTypes/pd-standard",
        "interface": "SCSI",
        "index": 1,
        "mode": "READ_WRITE",
        "boot": False,
        "auto_delete": False,
        "observed_utc": probe["observed_utc"],
        "guest_major_minor": disk_info["major_minor"],
        "guest_serial": disk_info["serial"],
        "guest_by_id": "/dev/disk/by-id/google-" + DATA_DEVICE,
        "guest_read_receipt_sha256": sha256(canonical(probe) + b"\n"),
        "guest_read_source_sha256": sha256(probe_source),
        "guest_boot_id": probe["boot_id"],
    }


def _bootstrap_database(values, env):
    probe, probe_source = _probe_database(env)
    ca_sha = sha256(values["ca_cert"].encode("ascii"))
    if probe["state"] == "configured":
        require(probe.get("ca_sha256") == ca_sha and probe.get("postgres_active") is True,
                "configured_database_secret_mismatch")
        _verify_existing_credentials(values, env, probe["boot_id"])
        return {"status": "existing_verified", "ca_certificate_sha256": ca_sha}
    proof = _compute_proof(probe, probe_source, env)
    operator_source = noble_payloads.operator_bytes()
    operator_sha = sha256(operator_source)
    operation = sha256((env["GITHUB_SHA"] + ":" + env["GITHUB_RUN_ID"] + ":" +
                        env["GITHUB_RUN_ATTEMPT"]).encode("ascii"))[:32]
    request = {
        "schema": "clipforge-db01-bootstrap-input-1",
        "operation_id": operation,
        "approved_commit": env["GITHUB_SHA"],
        "proposal_sha256": sha256(b"clipforge-int-hito-a-environment-approval-1"),
        "operator_sha256": operator_sha,
        "confirmation": "INITIALIZE_NEW_DISK_" + DATA_DISK_ID,
        "disk_proof": proof,
        "secrets": {key: values[key] for key in ("app_password", "migrator_password", "server_cert", "server_key", "ca_cert")},
    }
    operator = noble_payloads.operator_contract(operator_source)
    operator.validate_input(request, operator_sha)
    receipt, host_record = _ssh_public(operator_source, env,
                                       protected_input=canonical(request), timeout=720)
    receipt = operator.validate_receipt(receipt)
    require(host_record.get("guest_boot_id") == proof["guest_boot_id"]
            and receipt.get("exit_code") == 0
            and receipt.get("status") == "configured_guest_verified_external_acceptance_pending"
            and receipt.get("operation_id") == operation
            and receipt.get("approved_commit") == env["GITHUB_SHA"], "database_bootstrap_failed")
    return {"status": "initialized", "receipt_sha256": sha256(canonical(receipt)),
            "ca_certificate_sha256": ca_sha}


def _protected_values(env):
    values = {}
    for key, name in SECRET_ENV.items():
        values[key] = env.pop(name, "")
        os.environ.pop(name, None)
    legacy_operator.validate_secrets({key: values[key] for key in
                                      ("app_password", "migrator_password", "server_cert", "server_key", "ca_cert")})
    int_secrets.validate_payload("bootstrap_admin", values["bootstrap_admin"].encode("utf-8"))
    require(values["app_password"] != values["migrator_password"], "database_passwords_must_differ")
    return values


def configure(env):
    value = load_state(env, {"published"})
    values = _protected_values(env)
    database = _bootstrap_database(values, env)
    publications = {}
    for key, payload_key in (("app_password", "app_password"),
                             ("migrator_password", "migrator_password"),
                             ("postgres_ca", "ca_cert"),
                             ("bootstrap_admin", "bootstrap_admin")):
        publications[key] = int_secrets.add_version(
            key, values[payload_key].encode("utf-8"), env, delivery="int-hito-a"
        )
    versions = {key: row["version"] for key, row in publications.items()}
    require(set(versions) == {"app_password", "migrator_password", "postgres_ca", "bootstrap_admin"}
            and all(NUMBER.fullmatch(item) for item in versions.values()), "secret_version_receipts")
    value.update(phase="configured", database=database, secret_versions=versions)
    save_state(env, value)
    return value


def _copy_exact(source, destination):
    require(source.is_file() and not source.is_symlink() and source.stat().st_size <= 2 * 1024 * 1024,
            "terraform_source_file")
    destination.parent.mkdir(parents=True, exist_ok=True)
    with source.open("rb") as incoming, destination.open("xb") as outgoing:
        outgoing.write(incoming.read())


def _terraform_module(private):
    checkout = root()
    tree = private / "terraform-module"
    module = tree / "infra/gcp/int-base"
    require(not tree.exists(), "terraform_private_tree_exists")
    for name in BASE_FILES:
        _copy_exact(checkout / "infra/gcp/int-base" / name, module / name)
    for name in OVERLAYS:
        _copy_exact(checkout / "infra/gcp/int-demo-a" / name, module / name)
    for name in ("int_vm_hostkey_guest.py", "int_noble_hostkey.py"):
        _copy_exact(checkout / "scripts" / name, tree / "scripts" / name)
    return module


def _terraform_binary():
    binary = shutil.which("terraform")
    require(binary is not None and Path(binary).is_absolute(), "terraform_required")
    result = subprocess.run([binary, "version", "-json"], stdin=subprocess.DEVNULL,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30, check=False,
                            env={**os.environ, "TF_CLI_CONFIG_FILE": os.devnull})
    require(result.returncode == 0 and json.loads(result.stdout).get("terraform_version") == TERRAFORM_VERSION,
            "terraform_version")
    return binary


def _tf_run(command, module, private, name, *, accepted=(0,), timeout=1200):
    environment = dict(os.environ)
    require(not any(key.startswith(("TF_VAR_", "TF_CLI_ARGS", "TF_LOG")) for key in environment),
            "ambient_terraform_options")
    environment.update(TF_INPUT="false", TF_IN_AUTOMATION="true", CHECKPOINT_DISABLE="1",
                       TF_DATA_DIR=str(private / "terraform-data"),
                       TF_CLI_CONFIG_FILE=str(private / "terraform.rc"))
    result = subprocess.run(command, cwd=module, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, timeout=timeout, check=False, env=environment)
    raw = result.stdout + b"\n" + result.stderr
    (private / (name + ".log")).write_bytes(raw)
    require(result.returncode in accepted, "terraform_" + name + "_failed")
    return result.returncode, result.stdout


def _one(rows, code):
    require(isinstance(rows, list) and len(rows) == 1 and isinstance(rows[0], dict), code)
    return rows[0]


def _resources(module):
    require(isinstance(module, dict) and not module.get("child_modules"), "terraform_root_module_only")
    result = {}
    for row in module.get("resources", []):
        if row.get("mode") == "managed":
            require(row.get("address") not in result, "terraform_duplicate_address")
            result[row["address"]] = row.get("values", {})
    return result


def _env_map(container):
    rows = container.get("env", [])
    require(isinstance(rows, list) and all(isinstance(row.get("name"), str) for row in rows),
            "runtime_environment_shape")
    result = {row["name"]: row.get("value") for row in rows}
    require(len(result) == len(rows) and not any(row.get("value_source") for row in rows),
            "runtime_environment_source")
    return result


def _verify_plan(plan, state, acceptance_nonce):
    require(plan.get("terraform_version") == TERRAFORM_VERSION
            and str(plan.get("format_version", "")).startswith("1.")
            and plan.get("complete") is True and plan.get("applyable") is True
            and plan.get("errored") is False and not plan.get("deferred_changes")
            and not plan.get("action_invocations"), "terraform_plan_incomplete")
    require(set(plan.get("output_changes", {})) <= {"reviewed_boundary", "db01_noble_candidate"},
            "terraform_unreviewed_output")
    actions = {}
    for row in plan.get("resource_changes", []):
        change = row.get("change", {})
        selected = change.get("actions")
        if row.get("mode") == "data":
            require(selected in (["read"], ["no-op"]), "terraform_data_action")
            continue
        address = row.get("address")
        require(row.get("mode") == "managed" and address not in actions
                and not row.get("previous_address") and not row.get("deposed")
                and not change.get("importing") and not change.get("replace_paths"),
                "terraform_managed_action")
        require(selected in (["no-op"], ["create"], ["update"]), "terraform_destructive_action")
        if selected == ["create"]:
            require(address in ALLOWED_CREATES, "terraform_unreviewed_create")
        if selected == ["update"]:
            require(address in ALLOWED_UPDATES, "terraform_unreviewed_update")
        actions[address] = selected
    planned = _resources(plan["planned_values"]["root_module"])
    require(REQUIRED_RUNTIME <= set(planned), "terraform_runtime_resources_missing")
    require(len([row for row in planned if row.startswith("google_cloud_run_v2_service.api")]) == 1
            and {row for row in planned if row.startswith("google_cloud_run_v2_job.task[")} == {
                'google_cloud_run_v2_job.task["migrate"]',
                'google_cloud_run_v2_job.task["bootstrap"]',
            }, "terraform_single_service_two_jobs")
    image = state["image"]
    service = planned["google_cloud_run_v2_service.api[0]"]
    require(service.get("name") == SERVICE and service.get("project") == PROJECT
            and service.get("location") == REGION and service.get("deletion_protection") is True
            and service.get("iap_enabled") is True and service.get("invoker_iam_disabled") is False,
            "terraform_service_protection")
    template = _one(service.get("template"), "terraform_service_template")
    require(template.get("service_account") == "clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com"
            and _one(template.get("scaling"), "terraform_service_scaling") == {
                "max_instance_count": 1, "min_instance_count": 0
            }, "terraform_service_identity_or_scaling")
    container = _one(template.get("containers"), "terraform_service_container")
    require(container.get("image") == image and container.get("command") == ["python"]
            and "app.int_demo:app" in container.get("args", []), "terraform_service_image")
    runtime_env = _env_map(container)
    require(runtime_env.get("CLIPFORGE_DATABASE_HOST") == PRIVATE_IP
            and runtime_env.get("CLIPFORGE_DATABASE_SSL_MODE") == "verify-full"
            and runtime_env.get("CLIPFORGE_RUNTIME_PROFILE") == "int-demo-a"
            and runtime_env.get("CLIPFORGE_REVISION") == state["commit"]
            and runtime_env.get("CLIPFORGE_ACCEPTANCE_NONCE") == acceptance_nonce
            and runtime_env.get("CLIPFORGE_AUTH_PROFILE") == "https"
            and runtime_env.get("CLIPFORGE_ALLOW_INSECURE_HTTP") == "0",
            "terraform_service_environment")
    for name, arguments in (("migrate", ["-m", "app.cloud.migrate"]),
                            ("bootstrap", ["-m", "app.cloud.bootstrap_admin"])):
        job = planned[f'google_cloud_run_v2_job.task["{name}"]']
        require(job.get("name") == "clipforge-int-" + name and job.get("deletion_protection") is True,
                "terraform_job_identity")
        outer = _one(job.get("template"), "terraform_job_outer")
        inner = _one(outer.get("template"), "terraform_job_inner")
        task = _one(inner.get("containers"), "terraform_job_container")
        require(outer.get("task_count") == 1 and outer.get("parallelism") == 1
                and inner.get("max_retries") == 0
                and inner.get("service_account") == "clipforge-migrate-int@clipforgebeta2.iam.gserviceaccount.com"
                and task.get("image") == image and task.get("command") == ["python"]
                and task.get("args") == arguments, "terraform_job_execution")
    human = planned["google_iap_web_cloud_run_service_iam_member.pilot_admin[0]"]
    deploy = planned["google_iap_web_cloud_run_service_iam_member.deploy_acceptance[0]"]
    require(human.get("member") == "user:admin@ixbalam.studio"
            and deploy.get("member") == "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
            and human.get("role") == deploy.get("role") == "roles/iap.httpsResourceAccessor",
            "terraform_iap_access")
    credential_reader = planned["google_secret_manager_secret_iam_member.bootstrap_admin_human[0]"]
    require(credential_reader.get("secret_id") == "clipforge-int-bootstrap-admin"
            and credential_reader.get("member") == "user:admin@ixbalam.studio"
            and credential_reader.get("role") == "roles/secretmanager.secretAccessor",
            "terraform_bootstrap_credential_access")
    return {"actions": {key: value[0] for key, value in sorted(actions.items()) if value != ["no-op"]},
            "managed": len(planned)}


def _variables(state, acceptance_nonce):
    require(re.fullmatch(r"[a-z0-9][a-z0-9-]{0,63}", acceptance_nonce),
            "acceptance_nonce")
    return {
        "project_id": PROJECT,
        "machine_type": "e2-micro",
        "run_subnet_cidr": "10.80.0.0/26",
        "postgres_subnet_cidr": "10.80.1.0/28",
        "data_disk_gb": 20,
        "runtime_image": state["image"],
        "secret_versions": state["secret_versions"],
        "stage": "runtime",
        "int_runtime_profile": "demo-a",
        "demo_source_revision": state["commit"],
        "demo_a_acceptance_nonce": acceptance_nonce,
        "noble_postgres_from_run": True,
        "demo_a_iap_human_enabled": True,
        "db01_noble_candidate": {
            "image_name": "ubuntu-2404-noble-amd64-v20261105",
            "image_id": "1892012953239034119",
        },
    }


def _require_bootstrap_access_grant_permission(env):
    _require_permissions(
        "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/"
        "clipforge-int-bootstrap-admin:testIamPermissions",
        ["secretmanager.secrets.getIamPolicy", "secretmanager.secrets.setIamPolicy"],
        env["GCP_ACCESS_TOKEN"],
        "terraform_cannot_grant_bootstrap_credential_access",
    )


def _require_iap_policy_permissions(env):
    _require_permissions(
        "https://cloudresourcemanager.googleapis.com/v1/projects/816643438938:testIamPermissions",
        ["iap.webServices.getIamPolicy", "iap.webServices.setIamPolicy"],
        env["GCP_ACCESS_TOKEN"],
        "terraform_cannot_manage_iap_policy",
    )


def _require_delivery_iam_permissions(env):
    missing = []
    for name, check in (("bootstrap", _require_bootstrap_access_grant_permission),
                        ("iap", _require_iap_policy_permissions)):
        try:
            check(env)
        except DeliveryBlocked:
            missing.append(name)
    if missing == ["bootstrap"]:
        raise DeliveryBlocked("terraform_cannot_grant_bootstrap_credential_access")
    if missing == ["iap"]:
        raise DeliveryBlocked("terraform_cannot_manage_iap_policy")
    if missing:
        raise DeliveryBlocked("terraform_delivery_iam_permissions_missing")


def _require_permissions(url, permissions, token, code):
    from scripts.tf_int_plan import NoRedirect
    request = Request(
        url,
        data=canonical({"permissions": permissions}),
        method="POST",
        headers={"Authorization": "Bearer " + token,
                 "Content-Type": "application/json"},
    )
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(65537)
        result = json.loads(raw) if len(raw) <= 65536 else None
    except (OSError, ValueError, TypeError):
        raise DeliveryBlocked(code) from None
    require(isinstance(result, dict) and set(result.get("permissions", [])) == set(permissions), code)


def _require_service_update_permission(env):
    _require_permissions(
        "https://run.googleapis.com/v2/projects/clipforgebeta2/locations/us-central1/"
        "services/clipforge-int-api:testIamPermissions",
        ["run.services.update"],
        env["GCP_ACCESS_TOKEN"],
        "terraform_cannot_rollback_service_traffic",
    )


def infra(env):
    state = load_state(env, {"configured"})
    _require_delivery_iam_permissions(env)
    private = scratch(env) / "terraform"
    private.mkdir(mode=0o700)
    module = _terraform_module(private)
    (private / "terraform.rc").write_text("provider_installation {\n  direct {}\n}\n", encoding="ascii")
    acceptance_nonce = "prepare-" + state["run_id"] + "-" + state["run_attempt"]
    variables = _variables(state, acceptance_nonce)
    var_file = private / "inputs.tfvars.json"
    _write_json(var_file, variables)
    terraform = _terraform_binary()
    _tf_run([terraform, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color",
             "-backend-config=backend-int.hcl"], module, private, "init")
    _tf_run([terraform, "validate", "-no-color"], module, private, "validate")
    plan_path = private / "int.tfplan"
    code, _ = _tf_run([terraform, "plan", "-input=false", "-no-color", "-lock=true",
                       "-lock-timeout=120s", "-refresh=true", "-detailed-exitcode",
                       "-var-file=" + str(var_file), "-out=" + str(plan_path)],
                      module, private, "plan", accepted=(0, 2))
    _, raw = _tf_run([terraform, "show", "-json", str(plan_path)], module, private, "show")
    require(len(raw) <= 64 * 1024 * 1024, "terraform_plan_json_bound")
    summary = _verify_plan(json.loads(raw), state, acceptance_nonce)
    binary = plan_path.read_bytes()
    plan_sha = sha256(binary)
    require(code in {0, 2} and binary, "terraform_saved_plan")
    _tf_run([terraform, "apply", "-input=false", "-no-color", "-lock=true",
             "-lock-timeout=120s", str(plan_path)], module, private, "apply")
    require(sha256(plan_path.read_bytes()) == plan_sha, "terraform_saved_plan_changed")
    state.update(phase="deployed", terraform_plan_sha256=plan_sha,
                 terraform_actions=summary["actions"], terraform_managed=summary["managed"],
                 acceptance_nonce=acceptance_nonce)
    save_state(env, state)
    return state


def migrate(env):
    state = load_state(env, {"deployed"})
    completed = []
    for name in ("migrate", "bootstrap"):
        operation = dict(env)
        operation["INT_JOB"] = name
        int_release.execute_job(operation, delivery="int-hito-a")
        completed.append("clipforge-int-" + name)
    state.update(phase="migrated", migration={"status": "completed", "jobs": completed})
    save_state(env, state)
    return state


def replace(env):
    state = load_state(env, {"acceptance_prepared"})
    _require_service_update_permission(env)
    private = scratch(env) / "terraform"
    module = private / "terraform-module/infra/gcp/int-base"
    require(module.is_dir() and not module.is_symlink(), "terraform_replacement_module")
    acceptance_nonce = "verify-" + state["run_id"] + "-" + state["run_attempt"]
    variables = _variables(state, acceptance_nonce)
    var_file = private / "replacement-inputs.tfvars.json"
    _write_json(var_file, variables)
    terraform = _terraform_binary()
    plan_path = private / "replacement.tfplan"
    code, _ = _tf_run([terraform, "plan", "-input=false", "-no-color", "-lock=true",
                       "-lock-timeout=120s", "-refresh=true", "-detailed-exitcode",
                       "-var-file=" + str(var_file), "-out=" + str(plan_path)],
                      module, private, "replacement-plan", accepted=(2,))
    _, raw = _tf_run([terraform, "show", "-json", str(plan_path)],
                     module, private, "replacement-show")
    summary = _verify_plan(json.loads(raw), state, acceptance_nonce)
    require(code == 2 and summary["actions"] == {
        "google_cloud_run_v2_service.api[0]": "update"
    }, "replacement_must_only_update_service_revision")
    binary = plan_path.read_bytes()
    plan_sha = sha256(binary)
    state.update(phase="replacement_started", replacement_plan_sha256=plan_sha,
                 replacement_actions=summary["actions"], acceptance_nonce=acceptance_nonce)
    save_state(env, state)
    _tf_run([terraform, "apply", "-input=false", "-no-color", "-lock=true",
             "-lock-timeout=120s", str(plan_path)], module, private, "replacement-apply")
    require(sha256(plan_path.read_bytes()) == plan_sha, "replacement_saved_plan_changed")
    state.update(phase="replaced", replacement_plan_sha256=plan_sha,
                 replacement_actions=summary["actions"], acceptance_nonce=acceptance_nonce)
    save_state(env, state)
    return state


def accept(env):
    phase = env.get("INT_HITO_A_ACCEPTANCE_PHASE")
    require(phase in {"prepare", "verify"}, "acceptance_phase")
    expected = {"prepare": {"migrated"}, "verify": {"replaced"}}
    state = load_state(env, expected[phase])
    from scripts import int_hito_a_acceptance
    private_state = scratch(env) / "acceptance-private.json"
    request = {"operation": phase, "expected_commit": state["commit"],
               "expected_image": state["image"], "expected_digest": state["manifest_digest"],
               "private_state_path": str(private_state)}
    result = int_hito_a_acceptance.run(env, request)
    report_name = "api-demo-prepare.json" if phase == "prepare" else "api-demo-acceptance.json"
    _write_json(scratch(env) / report_name, result)
    wanted = "prepared_for_revision_replacement" if phase == "prepare" else "passed"
    expected_steps = {
        "prepare": ["cloud_ready_revision_digest_traffic", "https_iap_unauthorized_rejection",
                    "frontend_health_environment_admin_login",
                    "admin_create_list_and_secret_free_audit", "ordinary_rejections_and_logout"],
        "verify": ["replacement_revision_ready_digest_traffic", "https_iap_unauthorized_rejection",
                   "persistent_account_login_and_rejections",
                   "persistent_admin_list_and_secret_free_audit", "post_replacement_logout"],
    }
    require(isinstance(result, dict) and result.get("schema") == int_hito_a_acceptance.REPORT_SCHEMA
            and result.get("operation") == phase and result.get("status") == wanted
            and result.get("stage") == "complete" and result.get("controls_commit") == state["commit"]
            and result.get("steps") == [{"id": step, "status": "passed"}
                                         for step in expected_steps[phase]],
            "remote_acceptance_receipt")
    service = result.get("service", {})
    digest = state["manifest_digest"].removeprefix("sha256:")
    require(service.get("uri") == "https://clipforge-int-api-816643438938.us-central1.run.app"
            and service.get("image") == state["image"] and service.get("digest") == digest
            and re.fullmatch(r"clipforge-int-api-[a-z0-9-]+", service.get("revision", ""))
            and service.get("traffic") == [{"revision": service.get("revision"), "percent": 100}]
            and service.get("iap_enabled") is True
            and service.get("owner_member") == "user:admin@ixbalam.studio",
            "remote_acceptance_service_identity")
    require(result.get("application") == {"environment": "INT", "commit": state["commit"],
                                           "health": "ok", "profile": "int-demo-a"}
            and result.get("iap", {}).get("protected") is True
            and result.get("iap", {}).get("owner_member_verified") is True
            and result.get("audit_receipt", {}).get("credentials_present") is False,
            "remote_acceptance_application_controls")
    persistence = result.get("persistence", {})
    if phase == "prepare":
        require(persistence == {"prepared": True, "revision_replaced": False, "verified": False},
                "remote_acceptance_prepare_persistence")
    else:
        require(persistence.get("prepared") is True and persistence.get("revision_replaced") is True
                and persistence.get("verified") is True
                and persistence.get("after_revision") == service["revision"]
                and persistence.get("before_revision") != service["revision"]
                and result.get("account", {}).get("persisted") is True,
                "remote_acceptance_verify_persistence")
    browser_result = None
    if phase == "verify":
        from scripts import int_hito_a_browser
        browser_result = int_hito_a_browser.run(env, {
            "expected_commit": state["commit"],
            "expected_revision": service["revision"],
            "expected_digest": state["manifest_digest"],
            "private_state_path": str(private_state),
        })
        _write_json(scratch(env) / "api-demo-browser.json", browser_result)
        browser_checks = [
            "private_persistence_state_bound",
            "pinned_playwright_preinstalled_browser",
            "iap_scoped_css_javascript_loaded",
            "admin_ui_login_users_audit_logout",
            "persistent_account_ui_login_logout",
            "zero_page_console_request_errors",
        ]
        require(isinstance(browser_result, dict)
                and browser_result.get("schema") == int_hito_a_browser.SCHEMA
                and browser_result.get("operation") == "post_replacement_browser"
                and browser_result.get("status") == "passed"
                and browser_result.get("stage") == "complete"
                and browser_result.get("controls_commit") == state["commit"]
                and browser_result.get("origin") == service["uri"]
                and browser_result.get("revision") == service["revision"]
                and browser_result.get("digest") == digest
                and browser_result.get("checks") == [
                    {"id": check, "status": "passed"} for check in browser_checks
                ], "remote_browser_acceptance_receipt")
        require(browser_result.get("toolchain") == {
                    "playwright_version": int_hito_a_browser.PLAYWRIGHT_VERSION,
                    "browser_family": "chromium",
                    "preinstalled_browser": True,
                }
                and browser_result.get("assets") == {
                    "css": ["/static/account.css"],
                    "javascript": ["/static/account.js", "/static/auth.js"],
                    "contexts_verified": 2,
                }
                and browser_result.get("errors") == {
                    "page": 0, "console": 0, "request": 0, "observer": 0,
                }
                and browser_result.get("iap") == {
                    "bearer_scoped_to_origin": True, "external_requests": 0,
                }
                and browser_result.get("admin_ui") == {
                    "login": True, "users": True, "audit": True, "logout": True,
                }
                and browser_result.get("persistent_account_ui") == {
                    "login": True, "admin_panels_hidden": True, "logout": True,
                }
                and browser_result.get("persistence") == {
                    "revision_replaced": True, "account_verified": True,
                }
                and browser_result.get("credentials_present") is False,
                "remote_browser_acceptance_controls")
    if phase == "prepare":
        state.update(phase="acceptance_prepared", acceptance_prepare=result)
    else:
        state.update(phase="accepted", acceptance=result, browser_acceptance=browser_result)
    save_state(env, state)
    return state


def rollback(env):
    state = load_state(env, {"acceptance_prepared", "replacement_started", "replaced"})
    prepared = state.get("acceptance_prepare", {})
    previous = prepared.get("service", {}).get("revision")
    require(isinstance(previous, str) and re.fullmatch(r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?", previous),
            "rollback_revision")
    if state["phase"] == "acceptance_prepared":
        state.update(phase="rolled_back", rollback={"status": "not_required",
                     "revision": previous, "traffic_percent": 100})
        save_state(env, state)
        return state
    _run([
        _gcloud_binary(), "run", "services", "update-traffic", SERVICE,
        "--project=" + PROJECT, "--region=" + REGION,
        "--to-revisions=" + previous + "=100", "--quiet", "--verbosity=error",
    ], timeout=300, output_limit=1024 * 1024)
    service = _gcloud_json([
        "run", "services", "describe", SERVICE, "--project=" + PROJECT,
        "--region=" + REGION, "--format=json(status.traffic,status.url)",
    ])
    traffic = service.get("status", {}).get("traffic", [])
    active = [row for row in traffic if row.get("percent")]
    require(len(active) == 1 and active[0].get("revisionName") == previous
            and active[0].get("percent") == 100, "rollback_traffic_not_confirmed")
    state.update(phase="rolled_back", rollback={"status": "completed",
                 "revision": previous, "traffic_percent": 100})
    save_state(env, state)
    return state


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("verify-artifact", "preflight", "publish", "configure", "infra", "migrate", "replace", "accept", "rollback"))
    args = parser.parse_args(argv)
    os.umask(0o077)
    env = dict(os.environ)
    operations = {
        "verify-artifact": verify_artifact,
        "preflight": preflight,
        "publish": publish,
        "configure": configure,
        "infra": infra,
        "migrate": migrate,
        "replace": replace,
        "accept": accept,
        "rollback": rollback,
    }
    try:
        value = operations[args.operation](env)
        print(json.dumps({"status": value["phase"], "commit": value["commit"],
                          "image": value["image"]}, sort_keys=True))
        return 0
    except (DeliveryBlocked, legacy_operator.Blocked, ValueError, TypeError, KeyError,
            OSError, subprocess.SubprocessError, tarfile.TarError) as error:
        authored = str(error) if isinstance(error, DeliveryBlocked) else ""
        failed_check = authored if re.fullmatch(r"[a-z0-9_]+", authored) else args.operation.replace("-", "_") + "_failed"
        failure = {"schema": "clipforge-int-hito-a-delivery-failure-1", "status": "blocked",
                   "operation": args.operation, "failed_check": failed_check}
        if SHA.fullmatch(env.get("GITHUB_SHA", "")):
            failure["commit"] = env["GITHUB_SHA"]
        if env.get("RUNTIME_IMAGE", "").startswith(IMAGE_PREFIX):
            failure["image"] = env["RUNTIME_IMAGE"]
        try:
            _write_json(scratch(env) / ("delivery-failure-" + args.operation + ".json"), failure)
        except (DeliveryBlocked, ValueError, TypeError, KeyError, OSError):
            pass
        print(json.dumps(failure, sort_keys=True))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
