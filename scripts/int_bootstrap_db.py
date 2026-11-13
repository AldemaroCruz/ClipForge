"""Protected future IAP launcher; no personal gcloud session, token/secret arguments.

Metadata reads confirm the exact disk ID from the owner's initialization dispatch.
SSH host identity is pinned out of band; it is never accepted automatically.
"""
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile

from scripts import int_release
from scripts.check_tf_int import require
from scripts.int_bootstrap_vm import validate_secrets


def disk_contract(value, expected_id):
    require(str(value.get("id")) == expected_id and value.get("name") == "clipforge-int-base-postgres-data"
            and value.get("zone", "").endswith("/zones/us-central1-a")
            and value.get("type", "").endswith("/diskTypes/pd-standard")
            and value.get("labels", {}).get("managed_by") == "tf-int-01"
            and 20 <= int(value.get("sizeGb", 0)) <= 200 and value.get("status") == "READY"
            and value.get("users") == ["https://www.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/instances/clipforge-int-base-postgres"],
            "The attached disk does not match the reviewed new INT disk identity")


def main():
    int_release.hosted_context(os.environ)
    int_release.require_application_ci(os.environ)
    require(os.environ.get("INT_APPROVED_COMMIT") == os.environ.get("GITHUB_SHA"), "Exact owner-approved commit required")
    disk_id = os.environ.get("INT_NEW_DISK_ID", "")
    require(bool(re.fullmatch(r"[1-9][0-9]*", disk_id)) and os.environ.get("INT_DISK_CONFIRMATION") == "INITIALIZE_NEW_DISK_" + disk_id,
            "Explicit initialization confirmation for the new numeric disk ID is required")
    host_key = os.environ.get("INT_VM_SSH_HOST_KEY", "")
    require(bool(re.fullmatch(r"ssh-ed25519 [A-Za-z0-9+/=]{40,200}", host_key)), "Reviewed VM SSH host-key pin required")
    secrets = {key: os.environ.pop(name, "") for key, name in {
        "app_password": "INT_PG_APP_PASSWORD", "migrator_password": "INT_PG_MIGRATOR_PASSWORD",
        "server_cert": "INT_PG_SERVER_CERT", "server_key": "INT_PG_SERVER_KEY", "ca_cert": "INT_PG_CA_CERT"}.items()}
    validate_secrets(secrets)
    adc = Path(os.environ.get("GOOGLE_APPLICATION_CREDENTIALS", ""))
    require(adc.is_file() and adc.name.startswith("gha-creds-") and adc.suffix == ".json", "Only current Actions WIF credentials are supported")
    scratch = Path(tempfile.mkdtemp(prefix="clipforge-int-db.", dir=os.environ["RUNNER_TEMP"]))
    scratch.chmod(0o700)
    env = {**os.environ, "CLOUDSDK_CONFIG": str(scratch / "gcloud"), "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE": str(adc),
           "CLOUDSDK_CORE_DISABLE_PROMPTS": "1"}
    try:
        command = ["gcloud", "compute", "disks", "describe", "clipforge-int-base-postgres-data", "--project=clipforgebeta2",
                   "--zone=us-central1-a", "--format=json", "--quiet"]
        result = subprocess.run(command, env=env, capture_output=True, timeout=120, check=False)
        require(result.returncode == 0 and len(result.stdout) <= 65536, "Cannot verify reviewed disk metadata; no initialization attempted")
        disk_contract(json.loads(result.stdout), disk_id)
        known_hosts = scratch / "known_hosts"
        known_hosts.write_text("clipforge-int-base-postgres " + host_key + "\n")
        known_hosts.chmod(0o600)
        # Only public reviewed code is encoded in the command. Values travel in
        # stdin over the pinned encrypted channel, never in argv or metadata.
        code = base64.b64encode(Path(__file__).with_name("int_bootstrap_vm.py").read_bytes()).decode()
        remote = "sudo python3 -c 'import base64;exec(compile(base64.b64decode(\"" + code + "\"),\"int_bootstrap_vm.py\",\"exec\"))' --disk-id " + disk_id + " --confirmation INITIALIZE_NEW_DISK_" + disk_id
        args = ["gcloud", "compute", "ssh", "clipforge-int-base-postgres", "--project=clipforgebeta2", "--zone=us-central1-a",
                "--tunnel-through-iap", "--quiet", "--ssh-key-file=" + str(scratch / "ephemeral_ssh"),
                "--strict-host-key-checking=yes", "--ssh-flag=-oHostKeyAlias=clipforge-int-base-postgres",
                "--ssh-flag=-oUserKnownHostsFile=" + str(known_hosts), "--command=" + remote]
        result = subprocess.run(args, input=json.dumps(secrets).encode(), env=env, stdout=subprocess.DEVNULL,
                                stderr=subprocess.DEVNULL, timeout=600, check=False)
        require(result.returncode == 0, "Protected VM initialization failed; preserve disk and investigate privately")
        print("Protected new-disk initialization completed; migrate/bootstrap/restore acceptance remains pending.")
    finally:
        # A direct mkdtemp child only, owned by this invocation.
        import shutil
        require(scratch.parent.resolve() == Path(os.environ["RUNNER_TEMP"]).resolve() and scratch.name.startswith("clipforge-int-db."), "Unsafe scratch cleanup refused")
        shutil.rmtree(scratch)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("INT DB bootstrap blocked; no secret, SQL, credential file or SSH log was published.")
        raise SystemExit(1)
