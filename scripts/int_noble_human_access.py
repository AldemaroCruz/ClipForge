"""Operate only the reviewed human's temporary OS Login key and exact Noble TCP probe."""

import argparse
import base64
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import time
from urllib.error import HTTPError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener


PROJECT, NUMBER, ZONE = "clipforgebeta2", "816643438938", "us-central1-a"
INSTANCE, INSTANCE_ID = "clipforge-int-db01-noble", "7365414160255801909"
BOOT_DISK, DATA_DISK = "8897353356069952044", "7382984635240536620"
ACCOUNT, POSIX = "admin@ixbalam.studio", "admin_ixbalam_studio"
SA = "clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
COMPUTE = f"https://compute.googleapis.com/compute/v1/projects/{PROJECT}"
VM_ROUTE = f"{COMPUTE}/zones/{ZONE}/instances/{INSTANCE}"
BOOT_ROUTE, DATA_ROUTE = (f"{COMPUTE}/zones/{ZONE}/disks/{INSTANCE}-{name}" for name in ("boot", "data"))
PROFILE = f"https://oslogin.googleapis.com/v1/users/{quote(ACCOUNT, safe='')}"
GET_PROFILE = PROFILE + f"/loginProfile?projectId={PROJECT}"
IMPORT = PROFILE + f":importSshPublicKey?projectId={PROJECT}"
IAP = f"https://iap.googleapis.com/v1/projects/{NUMBER}/iap_tunnel/zones/{ZONE}/instances/{INSTANCE_ID}:testIamPermissions"
SA_IAM = f"https://iam.googleapis.com/v1/projects/{PROJECT}/serviceAccounts/{SA}:testIamPermissions"
POLICY_ROUTE = f"https://cloudresourcemanager.googleapis.com/v1/projects/{PROJECT}:getEffectiveOrgPolicy"
TTL = 7200
NOBLE_PIN = "331284966f2f0b3d226899ce61a7a9af80d728ed59df89f194ee2cabe8291ea1"
PUBKEY_BLOB = re.compile(r"(ssh-ed25519|ssh-rsa) ([A-Za-z0-9+/=]{32,1200})")
HEX = re.compile(r"[a-f0-9]{64}")


class Blocked(ValueError):
    """An operation blocked before mutation or requiring reconciliation."""


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, *_args, **_kwargs):
        raise Blocked("human_google_redirect")


def require(condition, code):
    if not condition:
        raise Blocked(code)


def sha(raw):
    return sha256(raw).hexdigest()


def canonical(value):
    return json.dumps(value, ensure_ascii=True, separators=(",", ":"), sort_keys=True).encode("ascii")


def scoped_json(path, size):
    require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= size, "human_scoped_file")
    return path.read_bytes()


def key_line(raw):
    require(len(raw) <= 2048 and len(raw.splitlines()) == 1, "human_public_key_size")
    fields = raw.decode("ascii").strip().split(None, 2)
    require(len(fields) >= 2 and PUBKEY_BLOB.fullmatch(" ".join(fields[:2])), "human_public_key_type")
    algorithm, encoded = fields[:2]
    blob = base64.b64decode(encoded, validate=True)
    tag = algorithm.encode("ascii")
    require(len(blob) < 1200 and blob.startswith(len(tag).to_bytes(4, "big") + tag)
            and (algorithm != "ssh-ed25519" or len(blob) == 51 and blob[15:19] == b"\x00\x00\x00\x20"), "human_public_key_wire_format")
    if algorithm == "ssh-rsa":
        pos = 4 + len(tag)
        exponent_size = int.from_bytes(blob[pos:pos + 4], "big")
        modulus_start = pos + 4 + exponent_size
        modulus_size = int.from_bytes(blob[modulus_start:modulus_start + 4], "big")
        modulus = blob[modulus_start + 4:]
        require(1 <= exponent_size <= 8 and len(modulus) == modulus_size
                and 2048 <= int.from_bytes(modulus, "big").bit_length() <= 8192, "human_rsa_public_key_size")
    return algorithm + " " + encoded, sha(blob), "SHA256:" + base64.b64encode(sha256(blob).digest()).decode().rstrip("=")


def decision(raw, expected, public_sha):
    require(HEX.fullmatch(expected) and sha(raw) == expected, "human_owner_decision_digest")
    value = json.loads(raw)
    exact = {"schema": "clipforge-int-noble-human-access-decision-1", "account": ACCOUNT, "posix": POSIX,
             "project": PROJECT, "zone": ZONE, "instance_id": INSTANCE_ID, "boot_disk_id": BOOT_DISK,
             "data_disk_id": DATA_DISK, "public_key_sha256": public_sha, "key_ttl_seconds": TTL,
             "personal_temporary_key_approved": True}
    require(set(value) == set(exact) | {"approved_commit", "authorization_reference"}
            and all(value[k] == v for k, v in exact.items())
            and re.fullmatch(r"[a-f0-9]{40}", value["approved_commit"])
            and re.fullmatch(r"[A-Za-z0-9. /_-]{8,160}", value["authorization_reference"]), "human_owner_decision_scope")
    return value


def command(program, *args):
    return subprocess.check_output([program, *args], timeout=20, stdin=subprocess.DEVNULL,
                                   stderr=subprocess.DEVNULL).decode("ascii").strip()


def human_token(gcloud):
    overrides = ("CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
                 "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "CLOUDSDK_CORE_LOG_HTTP")
    require(not any(os.environ.get(key) for key in overrides), "human_gcloud_override")
    for key in ("auth/credential_file_override", "auth/access_token_file", "auth/impersonate_service_account", "core/log_http"):
        require(command(gcloud, "config", "get-value", str(key), "--quiet") in {"", "(unset)", "False", "false"}, "human_gcloud_override")
    require(command(gcloud, "auth", "list", "--filter=status:ACTIVE", "--format=value(account)") == ACCOUNT,
            "human_wrong_active_account")
    token = command(gcloud, "auth", "print-access-token", "--account=" + ACCOUNT)
    require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "human_gcloud_token_format")
    return token


class Client:
    def __init__(self, token):
        self.token = token

    def request(self, method, url, value=None):
        get_routes = {VM_ROUTE, BOOT_ROUTE, DATA_ROUTE, GET_PROFILE}
        post_routes = {IMPORT, IAP, SA_IAM, VM_ROUTE + "/testIamPermissions", POLICY_ROUTE}
        read_operation = re.fullmatch(re.escape(f"{COMPUTE}/zones/{ZONE}/operations/operation-") + r"[A-Za-z0-9-]{3,200}", url)
        serial_update = re.fullmatch(re.escape(VM_ROUTE + "/setMetadata?requestId=") + r"[a-f0-9-]{36}", url)
        delete_key = re.fullmatch(re.escape(PROFILE + "/sshPublicKeys/") + r"[A-Za-z0-9_.%~-]{12,450}", url)
        require((method == "GET" and value is None and (url in get_routes or read_operation))
                or (method == "POST" and isinstance(value, dict) and (url in post_routes or serial_update))
                or (method == "DELETE" and value is None and delete_key), "human_unreviewed_api")
        request = Request(url, data=canonical(value) if value is not None else None, method=method,
                          headers={"Authorization": "Bearer " + self.token, "Content-Type": "application/json",
                                   "X-Goog-Request-Reason": "ClipForge INT exact Noble human operation"})
        try:
            with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=18) as response:
                body = response.read(262145)
                require(len(body) <= 262144, "human_api_body_limit")
                return json.loads(body) if body else {}
        except HTTPError as error:
            error.close()
            raise Blocked("human_api_http_" + str(error.code)) from None

    def profile(self):
        result = self.request("GET", GET_PROFILE)
        profiles = result.get("posixAccounts", [])
        require(re.fullmatch(r"users/[A-Za-z0-9._@-]{3,254}", result["name"])
                and sum(account.get("primary") is True and account.get("username") == POSIX
                        and account.get("operatingSystemType") == "LINUX" for account in profiles) == 1,
                "human_oslogin_posix")
        return result


def checked_target(client):
    vm = client.request("GET", VM_ROUTE)
    boot = client.request("GET", BOOT_ROUTE)
    data = client.request("GET", DATA_ROUTE)
    ident = lambda row, expected: str(row["id"]) == expected
    metadata = vm.get("metadata", {}).get("items", [])
    settings = {item["key"]: item["value"] for item in metadata}
    interfaces = vm.get("networkInterfaces", [])
    require(ident(vm, INSTANCE_ID) and vm["name"] == INSTANCE and vm["status"] == "RUNNING"
            and vm["zone"].endswith("/zones/" + ZONE) and vm["deletionProtection"] is True
            and len(interfaces) == 1 and interfaces[0]["networkIP"] == "10.80.1.3" and not interfaces[0].get("accessConfigs")
            and [item["email"] for item in vm["serviceAccounts"]] == [SA]
            and len(settings) == len(metadata) and settings.get("enable-oslogin") == "TRUE"
            and settings.get("block-project-ssh-keys") == "TRUE" and ident(boot, BOOT_DISK) and ident(data, DATA_DISK), "human_unexpected_target")
    require(len(vm["disks"]) == 2 and vm["disks"][0]["boot"] is True and vm["disks"][1]["boot"] is False
            and vm["disks"][0]["source"].endswith("/disks/" + INSTANCE + "-boot")
            and vm["disks"][1]["source"].endswith("/disks/" + INSTANCE + "-data")
            and not any(disk.get("autoDelete") for disk in vm["disks"]), "human_unexpected_disk_attachment")
    return vm


def preflight(client):
    vm = checked_target(client)
    for url, permissions in ((VM_ROUTE + "/testIamPermissions", {"compute.instances.get", "compute.instances.osLogin"}),
                             (IAP, {"iap.tunnelInstances.accessViaIAP"}), (SA_IAM, {"iam.serviceAccounts.actAs"})):
        observed = client.request("POST", url, {"permissions": sorted(permissions)})
        require(set(observed.get("permissions", [])) == permissions, "human_required_access_missing")
    return vm, client.profile()


def profile_key(profile, approved_sha):
    keys = profile.get("sshPublicKeys", {})
    require(isinstance(keys, dict) and len(keys) <= 100, "human_oslogin_keys_shape")
    matched = []
    for fingerprint, value in keys.items():
        try:
            _, key_digest, _ = key_line(value["key"].encode("ascii"))
        except (AttributeError, KeyError, TypeError, ValueError):
            continue
        if key_digest == approved_sha:
            # The profile-issued resource fingerprint is used for DELETE, never a guessed fingerprint.
            require(re.fullmatch(r"[A-Za-z0-9_+./:=-]{12,150}", fingerprint) and value.get("fingerprint", fingerprint) == fingerprint,
                    "human_oslogin_fingerprint")
            matched.append((fingerprint, str(value.get("expirationTimeUsec", ""))))
    require(len(matched) <= 1, "human_oslogin_duplicate_key")
    return matched[0] if matched else None


def write_once(path, row):
    require(not path.is_symlink() and path.parent.is_dir() and not path.parent.is_symlink(), "human_journal_path")
    with path.open("xb") as stream:
        stream.write(canonical(row) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())


def register(client, path, key, digest, authority):
    _, before = preflight(client)
    require(profile_key(before, digest) is None, "human_public_key_already_present")
    expires = time.time_ns() // 1000 + TTL * 1_000_000
    intent = {"schema": "clipforge-noble-human-key-intent-1", "profile_sha256": sha(before["name"].encode()),
              "approved_key_sha256": digest, "authorization_sha256": authority, "expiry_us": expires, "confirmed_absent": True}
    write_once(path, intent)
    # If the POST is uncertain, the durable intent is reconciled with this exact profile before proceeding.
    answer = client.request("POST", IMPORT, {"key": key, "expirationTimeUsec": str(expires)})
    reported = answer["loginProfile"]
    confirmed = client.profile()
    found = profile_key(confirmed, digest)
    require(confirmed["name"] == reported["name"] == before["name"] and found is not None and found[1] == str(expires)
            and profile_key(reported, digest) == found, "human_import_result_uncertain")
    return {"status": "registered_exact_temporary_key", "key_sha256": digest, "expiry_us": expires}


def owned_key(client, path, digest, authority, *, active=False):
    raw = scoped_json(path, 8192)
    row = json.loads(raw)
    require(set(row) == {"schema", "profile_sha256", "approved_key_sha256", "authorization_sha256", "expiry_us", "confirmed_absent"}
            and row["schema"] == "clipforge-noble-human-key-intent-1" and row["approved_key_sha256"] == digest
            and row["authorization_sha256"] == authority and row["confirmed_absent"] is True and type(row["expiry_us"]) is int
            and row["expiry_us"] <= time.time_ns() // 1000 + TTL * 1_000_000, "human_journal_scope")
    profile = client.profile()
    require(sha(profile["name"].encode()) == row["profile_sha256"], "human_journal_profile_drift")
    found = profile_key(profile, digest)
    require(found is None or found[1] == str(row["expiry_us"]), "human_key_ownership_uncertain")
    if active:
        require(found is not None and row["expiry_us"] > time.time_ns() // 1000 + 60_000_000, "human_key_not_live")
    return found


def remove(client, path, digest, authority):
    found = owned_key(client, path, digest, authority)
    if found is None:
        return {"status": "owned_key_already_absent", "key_sha256": digest}
    client.request("DELETE", PROFILE + "/sshPublicKeys/" + quote(found[0], safe=""))
    require(owned_key(client, path, digest, authority) is None, "human_key_removal_unconfirmed")
    return {"status": "owned_key_removed_absence_verified", "key_sha256": digest}


def ssh_probe(ssh, gcloud, private, known, fingerprint):
    require(sha(scoped_json(known, 1024)) == NOBLE_PIN and private.is_file() and not private.is_symlink(), "human_ssh_local_files")
    require(re.fullmatch(r"[A-Za-z0-9_. :/\\-]+", gcloud) and '"' not in str(known), "human_ssh_path_syntax")
    proxy = (f'"{gcloud}" compute start-iap-tunnel {INSTANCE} 22 --listen-on-stdin '
             f'--project={PROJECT} --zone={ZONE} --account={ACCOUNT} --quiet --verbosity=warning')
    arguments = [ssh, "-v", "-F", "NUL", "-T", "-p", "22", "-i", str(private),
                 "-o", "ProxyCommand=" + proxy, "-o", f'UserKnownHostsFile="{known}"', "-o", "GlobalKnownHostsFile=NUL",
                 "-o", "HostKeyAlias=" + INSTANCE + "." + INSTANCE_ID, "-o", "StrictHostKeyChecking=yes",
                 "-o", "HostKeyAlgorithms=ssh-ed25519", "-o", "UpdateHostKeys=no", "-o", "CheckHostIP=no",
                 "-o", "IdentitiesOnly=yes", "-o", "IdentityAgent=none", "-o", "CertificateFile=none",
                 "-o", "PreferredAuthentications=publickey", "-o", "BatchMode=yes", "-o", "ForwardAgent=no",
                 "-o", "ConnectTimeout=15", "-o", "ConnectionAttempts=1", "-W", "127.0.0.1:5432", "-l", POSIX, INSTANCE]
    try:
        completed = subprocess.run(arguments, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL, timeout=25)
    except subprocess.TimeoutExpired:
        return {"status": "human_forwarding_indeterminate", "ssh_exit": None}
    diagnostic = completed.stderr.decode("ascii", errors="replace").splitlines()
    good_key = any("Server accepts key:" in line and fingerprint in line for line in diagnostic)
    authenticated = good_key and any("Authenticated to " in line and "publickey" in line for line in diagnostic)
    if authenticated and any("open failed: connect failed: Connection refused" in line for line in diagnostic):
        status = "forwarding_allowed_target_not_listening"
    elif authenticated and any("open failed: administratively prohibited" in line for line in diagnostic):
        status = "forwarding_denied"
    elif authenticated and completed.returncode == 0:
        status = "forwarding_allowed_target_connected"
    else:
        status = "human_forwarding_indeterminate"
    return {"status": status, "ssh_exit": completed.returncode, "approved_key_authenticated": authenticated}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("register", "probe", "remove"))
    parser.add_argument("--approval", type=Path, required=True)
    parser.add_argument("--approval-sha256", required=True)
    parser.add_argument("--public-key", type=Path, required=True)
    parser.add_argument("--intent", type=Path, required=True)
    parser.add_argument("--private-key", type=Path)
    parser.add_argument("--known-hosts", type=Path)
    args = parser.parse_args()
    try:
        key, digest, fingerprint = key_line(scoped_json(args.public_key, 2048))
        authority = args.approval_sha256
        decision(scoped_json(args.approval, 8192), authority, digest)
        gcloud = shutil.which("gcloud.cmd")
        require(gcloud is not None, "human_windows_gcloud")
        client = Client(human_token(gcloud))
        if args.operation == "register":
            status = register(client, args.intent, key, digest, authority)
        elif args.operation == "remove":
            status = remove(client, args.intent, digest, authority)
        else:
            preflight(client)
            owned_key(client, args.intent, digest, authority, active=True)
            ssh = shutil.which("ssh.exe")
            require(ssh and args.private_key and args.known_hosts and args.public_key.resolve() == Path(str(args.private_key.resolve()) + ".pub"),
                    "human_probe_key_pair_or_ssh")
            status = ssh_probe(ssh, gcloud, args.private_key.resolve(), args.known_hosts.resolve(), fingerprint)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError) as error:
        status = {"status": "human_access_blocked_or_reconcile",
                  "error": str(error) if isinstance(error, Blocked) else type(error).__name__}
    print(canonical(status).decode("ascii"))
    return int(status["status"] not in {"registered_exact_temporary_key", "owned_key_already_absent", "owned_key_removed_absence_verified",
                                        "forwarding_allowed_target_not_listening", "forwarding_allowed_target_connected"})


if __name__ == "__main__":
    raise SystemExit(main())
