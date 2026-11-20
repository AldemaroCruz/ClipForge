"""Pin the authorized Noble first-boot host key and collect one Deploy inventory."""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import stat
import time
from urllib.error import HTTPError
from urllib.parse import parse_qsl, quote, unquote, urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from scripts import int_guest_inventory as transport
from scripts import int_noble_guest_observation as guest
from scripts import int_noble_hostkey as host
from scripts import int_vm_hostkey_guest
from scripts import int_release as custody
from scripts.int_foundation_verify import STATE_PIN
from scripts import db01_guest_sca as sca


PRODUCER = "c302dcc366ed450f91c1693072eb9008e7975e4c"
IMAGE = "ubuntu-2404-noble-amd64-v20261105"
IMAGE_ID = "1892012953239034119"
APPLY_PATH = ".github/workflows/int-db01-noble-apply.yml"
OBSERVE_PATH = ".github/workflows/int-db01-noble-observe.yml"
PIN_SCHEMA = "clipforge-db01-noble-first-boot-pin-1"
PAYLOAD_SHA256 = "c13727b4c62a5b449f94bc26b1e824241cdb109d4fd0a3b9d23849865449f7d9"
PUBLISHER_SHA256 = "0400c905a0cf8578d8315e608afdca3a87aed6521f8ae36b449b9d675cd87cc5"
CREATION_SCHEMA = "clipforge-db01-noble-creation-receipt-1"
MAX_PIN = 16384
API = "https://compute.googleapis.com/compute/v1/"
VM = API + guest.INSTANCE_PATH
BOOT = API + guest.ZONE_PATH + "/disks/" + guest.BOOT_DISK
DATA = API + guest.ZONE_PATH + "/disks/" + guest.DATA_DISK
PROJECT = API + guest.PROJECT_PATH + "?fields=name,id,commonInstanceMetadata"
SERIAL = VM + "/serialPort?port=1&start=0"
SNAPSHOT_ROUTES = (VM, BOOT, DATA, PROJECT)
CANDIDATE_CONSTANTS = {
    "instance_name": host.INSTANCE, "boot_disk": guest.BOOT_DISK, "data_disk": guest.DATA_DISK,
    "data_device": guest.DEVICE_NAME, "private_ip": guest.PRIVATE_IP, "service_email": guest.GUEST_EMAIL,
    "image_name": IMAGE, "image_id": IMAGE_ID,
}
CANDIDATE_IDS = ("instance_id", "boot_disk_id", "data_disk_id")
CANDIDATE_HASHES = ("hostkey_nonce", "startup_sha256")
CANDIDATE_TIMES = ("creation_timestamp", "first_boot_timestamp")
require = host.require


def exact_summary(raw, expected_sha, controls, run):
    require(re.fullmatch(r"[0-9a-f]{40}", controls or "") and controls != PRODUCER
            and re.fullmatch(host.NUMBER, run or "") and re.fullmatch(host.HEX, expected_sha or "")
            and 0 < len(raw) <= 262144 and host.sha(raw) == expected_sha, "NOBLE_APPLY_SUMMARY_HASH")
    summary = host.closed_json(raw)
    require(isinstance(summary, dict) and summary.get("schema") == CREATION_SCHEMA and summary.get("status") == "created_verified"
            and summary.get("producer_commit") == PRODUCER and summary.get("controls_commit") == controls
            and str(summary.get("apply_run_id")) == run and summary["approval"].get("observation") is True
            and summary["native_apply_completed"] is True and summary["debian_preserved"] is True,
            "NOBLE_APPLY_SUMMARY_ORIGIN")
    state = summary["state"]
    require(state["name"] == STATE_PIN["name"] and state["lineage"] == STATE_PIN["lineage"]
            and state["generation"] != STATE_PIN["generation"] and re.fullmatch(host.NUMBER, state["generation"])
            and re.fullmatch(host.HEX, state["sha256"]) and type(state["serial"]) is int and state["serial"] > 7
            and state["managed_address_count"] == 53 and state["preserved_address_count"] == 42
            and state["current_lock_absent"] is True, "NOBLE_APPLY_SUMMARY_BACKEND")
    candidate = summary["candidate"]
    require(isinstance(candidate, dict) and candidate.keys() == (set(CANDIDATE_CONSTANTS) | set(CANDIDATE_IDS)
            | set(CANDIDATE_HASHES) | set(CANDIDATE_TIMES))
            and all(candidate[k] == v for k, v in CANDIDATE_CONSTANTS.items())
            and all(isinstance(candidate[k], str) and re.fullmatch(host.NUMBER, candidate[k]) for k in CANDIDATE_IDS)
            and len({candidate[k] for k in CANDIDATE_IDS}) == 3
            and not guest.LEGACY_IDS.intersection(candidate[k] for k in CANDIDATE_IDS)
            and all(isinstance(candidate[k], str) and re.fullmatch(host.HEX, candidate[k]) for k in CANDIDATE_HASHES)
            and guest.timestamp(candidate["first_boot_timestamp"]) >= guest.timestamp(candidate["creation_timestamp"]),
            "NOBLE_APPLY_SUMMARY_TARGET")
    ref = summary["receipt"]
    require(isinstance(ref, dict) and ref.keys() == {"name", "generation", "sha256", "size"}
            and ref["name"] == f"{custody.PREFIX}{controls}/{run}-1/foundation-state.json"
            and isinstance(ref["generation"], str) and re.fullmatch(host.NUMBER, ref["generation"])
            and isinstance(ref["sha256"], str) and re.fullmatch(host.HEX, ref["sha256"])
            and type(ref["size"]) is int and 0 < ref["size"] <= 262144, "NOBLE_CREATION_RECEIPT_REFERENCE")
    return summary


def checked_apply_run(run, controls, token):
    """Verify the sanitized artifact came from the protected successful apply workflow."""
    require(re.fullmatch(host.NUMBER, run or "") and re.fullmatch(r"[0-9a-f]{40}", controls or "")
            and isinstance(token, str) and 20 <= len(token) <= 512, "NOBLE_APPLY_RUN_READ")
    endpoint = f"https://api.github.com/repos/AldemaroCruz/ClipForge/actions/runs/{run}"
    req = Request(endpoint, headers={"Authorization": "Bearer " + token,
                  "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"})
    with build_opener(ProxyHandler({}), transport.NoRedirect()).open(req, timeout=20) as stream:
        raw = stream.read(262145)
    require(len(raw) <= 262144, "NOBLE_APPLY_RUN_RESPONSE_BOUND")
    result = host.closed_json(raw)
    require(str(result.get("id")) == run and result.get("run_attempt") == 1
            and result.get("path", "").split("@", 1)[0] == APPLY_PATH
            and result.get("head_sha") == controls and result.get("head_branch") == "ci/bootstrap-sec03"
            and result.get("event") == "workflow_dispatch" and result.get("status") == "completed"
            and result.get("conclusion") == "success"
            and result.get("repository", {}).get("full_name") == "AldemaroCruz/ClipForge", "NOBLE_APPLY_RUN_UNVERIFIED")


def read_compute(url, token):
    require(url in (*SNAPSHOT_ROUTES, SERIAL) and isinstance(token, str)
            and re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "NOBLE_COMPUTE_READ_BOUNDARY")
    resource = url.split("?", 1)[0].removeprefix(API)
    limit = 3 * 1024 * 1024 if url == SERIAL else 2 * 1024 * 1024
    req = Request(url, headers={"Authorization": "Bearer " + token,
                  "X-Goog-Request-Reason": "ClipForge DB01 verified Noble first boot"})
    try:
        with build_opener(ProxyHandler({}), transport.NoRedirect()).open(req, timeout=25) as stream:
            raw = stream.read(limit + 1)
    except HTTPError as error:
        error.close()
        operation = "compute.instances.getSerialPortOutput" if url == SERIAL else "compute.snapshot.get"
        raise transport.Failure("noble_compute_read_failed", {"operation": operation,
                                "resource": resource, "http_status": error.code}) from None
    require(len(raw) <= limit, "NOBLE_COMPUTE_RESPONSE_BOUND")
    value = host.closed_json(raw)
    require(isinstance(value, dict), "NOBLE_COMPUTE_RESPONSE")
    return value


def snapshot(reader, candidate):
    target = {key: candidate[key] for key in (*CANDIDATE_IDS, *CANDIDATE_TIMES, "image_id", "image_name", "startup_sha256")}
    return guest.control_snapshot(*(reader(route) for route in SNAPSHOT_ROUTES), target)


def make_pin(summary, summary_sha, reader):
    cand = summary["candidate"]
    before = snapshot(reader, cand)
    require(before == summary["control_plane"], "NOBLE_POST_APPLY_CONTROL_PLANE_CHANGED")
    serial = reader(SERIAL)
    after = snapshot(reader, cand)
    pin = guest.host_receipt(serial, before=before, after=after, nonce=cand["hostkey_nonce"],
                             publisher_sha256=PUBLISHER_SHA256)
    return {"schema": PIN_SCHEMA, "producer_commit": PRODUCER, "controls_commit": summary["controls_commit"],
            "apply_run_id": str(summary["apply_run_id"]), "apply_summary_sha256": summary_sha,
            "creation_receipt": summary["receipt"], "pin": pin}


def check_pin(raw, expected_sha, summary, summary_sha):
    require(re.fullmatch(host.HEX, expected_sha or "") and 0 < len(raw) <= MAX_PIN
            and host.sha(raw) == expected_sha, "NOBLE_PIN_HASH")
    envelope = host.closed_json(raw)
    require(isinstance(envelope, dict) and envelope.keys() == {"schema", "producer_commit", "controls_commit",
            "apply_run_id", "apply_summary_sha256", "creation_receipt", "pin"}
            and envelope["schema"] == PIN_SCHEMA and envelope["producer_commit"] == PRODUCER
            and envelope["controls_commit"] == summary["controls_commit"]
            and envelope["apply_run_id"] == str(summary["apply_run_id"])
            and envelope["apply_summary_sha256"] == summary_sha and envelope["creation_receipt"] == summary["receipt"],
            "NOBLE_PIN_APPLY_BINDING")
    cand, pin = summary["candidate"], envelope["pin"]
    require(isinstance(pin, dict) and pin.keys() == {"schema", "control_plane", "record", "known_hosts_line"}
            and pin["schema"] == "clipforge-int-noble-hostkey-evidence-1"
            and pin["control_plane"] == summary["control_plane"], "NOBLE_PIN_SCHEMA")
    record = pin["record"]
    require(isinstance(record, dict) and record.keys() == host.RECORD_FIELDS
            and all(record[key] == value for key, value in host.IDENTITY.items())
            and record["schema"] == host.SCHEMA and record["instance_id"] == cand["instance_id"]
            and record["nonce"] == cand["hostkey_nonce"] and record["script_sha256"] == PUBLISHER_SHA256
            and record["publisher_dependency_sha256"] == host.LEGACY_SHA256
            and re.fullmatch(host.BOOT, record["guest_boot_id"]), "NOBLE_PIN_RECORD")
    public_key, fingerprint = int_vm_hostkey_guest.public_key(record["public_key"].encode("ascii"))
    require(record["public_key"] == public_key and record["fingerprint"] == fingerprint
            and pin["known_hosts_line"] == f"{host.INSTANCE}.{cand['instance_id']} {public_key}\n", "NOBLE_PIN_KEY")
    return pin


def ssh_builder(instance_id):
    require(re.fullmatch(host.NUMBER, instance_id), "NOBLE_SSH_ID")
    def command(work, username, port):
        args = transport.ssh_command(work, username, port)
        alias = [i for i, value in enumerate(args) if value.startswith("-oHostKeyAlias=")]
        require(len(alias) == 1, "NOBLE_SSH_ALIAS")
        args[alias[0]] = f"-oHostKeyAlias={host.INSTANCE}.{instance_id}"
        return args
    return command


def noble_tunnel(gcloud, port):
    argv = transport.tunnel_command(gcloud, port)
    require(argv[3] == transport.VM_NAME and argv[4] == "22", "NOBLE_TUNNEL_ROUTE")
    argv[3] = host.INSTANCE
    return argv


def check_hosted_context(env):
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("GITHUB_RUN_ATTEMPT") == "1"
            and env.get("GITHUB_WORKFLOW_REF") == f"AldemaroCruz/ClipForge/{OBSERVE_PATH}@refs/heads/ci/bootstrap-sec03"
            and env.get("GITHUB_SHA") == env.get("GUEST_APPROVED_COMMIT"), "NOBLE_OBSERVATION_HOSTED_BOUNDARY")
    require(host.sha((guest.ROOT / "scripts/int_noble_hostkey.py").read_bytes()) == PUBLISHER_SHA256,
            "NOBLE_HOST_PUBLISHER_SOURCE")


def collect(env, work, reports, summary, pin, *, reader, client, runner=None):
    """Observe one unchanged first boot, with the GUEST own-key journal and cleanup."""
    candidate = summary["candidate"]
    payload = guest.payload_bytes()
    require(host.sha(payload) == PAYLOAD_SHA256 and len(payload) <= 262144, "NOBLE_PAYLOAD_SOURCE")
    require(not any(entry.name != "gcloud" for entry in work.iterdir()), "NOBLE_RUN_FRESH_SCRATCH")
    journal = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": env["GITHUB_REPOSITORY"],
               "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"],
               "public_key": None, "created_us": None, "expiration_us": None, "fingerprint": None,
               "import_attempted": False, "key_absent_before_import": False, "profile_name": None, "processes": []}
    transport._save_journal(work, journal)
    result = {"schema": "clipforge-db01-noble-first-observation-1", "status": "blocked",
              "producer_commit": PRODUCER, "controls_commit": env["GITHUB_SHA"],
              "apply_run_id": str(summary["apply_run_id"]), "observation_run_id": env["GITHUB_RUN_ID"],
              "creation_receipt": summary["receipt"], "runtime_authorized": False, "database_initialized": False}
    stage, previous_signals = "control_plane_before", {}
    def interrupted(_signum, _frame):
        raise transport.Blocked("noble_runner_interrupted")
    def record_process(row):
        journal["processes"].append(row)
        transport._save_journal(work, journal)
    try:
        for number in (signal.SIGINT, signal.SIGTERM):
            previous_signals[number] = signal.signal(number, interrupted)
        before = snapshot(reader, candidate)
        require(before == pin["control_plane"], "NOBLE_FIRST_BOOT_OR_METADATA_CHANGED_BEFORE_SSH")
        stage = "oslogin_profile"
        profile = client.profile()
        result["deploy_identity"] = transport.validate_deploy_profile(profile)
        journal["profile_name"] = client.profile_name
        transport._save_journal(work, journal)
        stage = "sdk_and_key"
        gcloud = shutil.which("gcloud")
        require(gcloud and Path(gcloud).is_absolute() and Path(gcloud).name == "gcloud", "NOBLE_GCLOUD")
        ssh = ssh_builder(candidate["instance_id"])
        runner = runner or transport.ProcessRunner(work, gcloud, payload,
            f"clipforge-noble-{env['GITHUB_RUN_ID']}-1", record_process, ssh_builder=ssh, tunnel_builder=noble_tunnel)
        code, raw, _ = runner.run([gcloud, "version", "--format=json"])
        require(code == 0 and transport.decode(raw).get("Google Cloud SDK") == "582.0.0", "NOBLE_SDK_VERSION")
        code, _, _ = runner.run(runner.keygen_command())
        local_key = work / "id_ed25519"
        require(code == 0 and not local_key.is_symlink()
                and stat.S_IMODE(local_key.stat().st_mode) == 0o600, "NOBLE_EPHEMERAL_KEY")
        public_key, _ = int_vm_hostkey_guest.public_key(transport._local_bytes(work / "id_ed25519.pub", 1024))
        created = int(time.time() * 1_000_000)
        expiration = created + transport.KEY_TTL_SECONDS * 1_000_000
        client.arm_key(public_key, expiration)
        client.prepare_import()
        journal.update(public_key=public_key, created_us=created, expiration_us=expiration,
                       import_attempted=True, key_absent_before_import=True)
        transport._save_journal(work, journal)
        stage = "oslogin_own_key_import"
        own = client.import_key()
        journal["fingerprint"] = own["fingerprint"]
        transport._save_journal(work, journal)
        result["own_key"] = {"ttl_seconds": transport.KEY_TTL_SECONDS, "public_key_sha256": host.sha(public_key.encode()),
                             "expires_utc": datetime.fromtimestamp(expiration / 1_000_000, timezone.utc).isoformat()}
        known = work / "known_hosts"
        with known.open("xb") as stream:
            os.chmod(known, 0o400)
            stream.write(pin["known_hosts_line"].encode("ascii"))
        with socket.socket() as reservation:
            reservation.bind(("127.0.0.1", 0))
            local_port = reservation.getsockname()[1]
        runner.username = own["username"]
        stage = "iap_tunnel"
        runner.start_tunnel(local_port)
        stage = "strict_ssh_guest"
        code, raw, stderr = runner.run(ssh(work, own["username"], local_port), payload,
                                        timeout=180, stdout_limit=guest.MAX_OUTPUT)
        result["ssh_diagnostic"] = transport.process_diagnostic(stderr)
        result["guest_exit_code"] = code
        require(code in {0, 2}, "NOBLE_GUEST_TRANSPORT_EXIT")
        validated = guest.validate_guest(raw, code, host_record=pin["record"], expected_payload_sha256=PAYLOAD_SHA256)
        if code != 0:
            transport._write_report(reports, "inventory.json", validated)
            result["guest_error"] = validated["error_code"]
            raise transport.Blocked("noble_guest_observation_blocked")
        stage = "control_plane_after"
        after = snapshot(reader, candidate)
        require(transport._local_bytes(known, 1024) == pin["known_hosts_line"].encode("ascii"), "NOBLE_PIN_CHANGED")
        evidence = guest.linked_observation(raw, code, before=before, after=after, pin_receipt=pin,
                                            workflow_commit=env["GITHUB_SHA"], expected_payload_sha256=PAYLOAD_SHA256)
        stage = "inventory_metadata"
        transport._write_report(reports, "inventory.json", evidence)
        result.update(status="observation_complete", inventory_sha256=host.sha(
            transport.canonical(evidence) + b"\n"), control_plane=after, host_fingerprint=pin["record"]["fingerprint"])
    except Exception as error:
        result["failure_phase"] = stage
        code = str(error)
        result["error_code"] = code if isinstance(error, transport.Blocked) or re.fullmatch(r"[A-Z_]{3,100}", code) else type(error).__name__
        if isinstance(error, transport.Failure):
            result["failure"] = error.receipt
    finally:
        try:
            if runner:
                runner.close()
        except Exception:
            result.update(status="blocked", process_cleanup_error="own_process_cleanup_unconfirmed")
        try:
            result["cleanup"] = transport.cleanup(environ=env, workdir=work, reports=reports, client=client)
        except Exception:
            result["cleanup"] = {"status": "cleanup_unconfirmed_TTL_pending"}
        finally:
            for number, previous in previous_signals.items():
                signal.signal(number, previous)
    if result["cleanup"]["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"}:
        result["status"] = "blocked_cleanup_unconfirmed"
    result["oslogin_http"] = client.http_receipts
    transport._write_report(reports, "guest-summary.json", result)
    return result


SCA_LIMITS = [
    "Only observed installed Ubuntu dpkg binary and source identities in this VM were submitted.",
    "No filesystem, dependencies outside dpkg, runtime reachability or disk-content coverage is inferred.",
    "PGDG packages remain explicitly listed and require an upstream advisory review if the scanner lacks matching source coverage.",
    "A kernel package correlated by release is an inventory association, not proof of running binary build, backports or reachability.",
]
SCANNER_IMAGE = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6"


def package_purl(row):
    binary = row["binary_name"].split(":", 1)[0]
    epoch, separator, version = row["binary_version"].partition(":")
    suffix = ""
    if separator:
        require(re.fullmatch(r"[0-9]+", epoch) and version, "NOBLE_SCA_BINARY_EPOCH")
        suffix = f"&epoch={int(epoch)}" if int(epoch) else ""
    else:
        version = epoch
    return f"pkg:deb/ubuntu/{quote(binary, safe='')}@{quote(version, safe='')}?arch={row['architecture']}&distro=ubuntu-24.04{suffix}"


def noble_sbom(raw, expected_sha):
    require(host.sha(raw) == expected_sha and 0 < len(raw) <= guest.MAX_OUTPUT, "NOBLE_INVENTORY_DIGEST")
    evidence = host.closed_json(raw)
    require(evidence["schema"] == "clipforge-int-db01-noble-evidence-1" and evidence["read_only"] is True
            and evidence["runtime_authorized"] is False and evidence["payload_sha256"] == PAYLOAD_SHA256
            and evidence["target"] == {"project": host.PROJECT, "project_number": host.PROJECT_NUMBER,
                                        "zone": host.ZONE, "name": host.INSTANCE}
            and re.fullmatch(r"[0-9a-f]{40}", evidence["workflow_commit"])
            and re.fullmatch(host.NUMBER, evidence["control_plane"]["instance_id"])
            and re.fullmatch(host.HEX, evidence["control_plane"]["snapshot_sha256"]),
            "NOBLE_BOUND_INVENTORY_REQUIRED")
    observed = evidence["guest"]
    require(host.sha(transport.canonical(observed) + b"\n") == evidence["guest_sha256"], "NOBLE_GUEST_INTEGRITY")
    report = guest.validate_guest(transport.canonical(observed) + b"\n", 0,
                                  host_record={"guest_boot_id": observed["guest_boot_id"]},
                                  expected_payload_sha256=PAYLOAD_SHA256)
    kernel = report["base_inventory"]["inventory"]["kernel"]
    packages = report["packages_source"]
    components = []
    kernel_rows = []
    pgdg = []
    for row in packages:
        wanted, error, current = row["status"].split()
        require(error == "ok" and current in {"installed", "config-files", "not-installed"}, "NOBLE_DPKG_PARTIAL_STATE")
        if current != "installed":
            continue
        binary = row["binary_name"].split(":", 1)[0]
        require(wanted in {"install", "hold"} and row["source_name"] and row["source_version"], "NOBLE_OBSERVED_SOURCE_REQUIRED")
        purl = package_purl(row)
        components.append({"type": "library", "bom-ref": purl, "name": binary, "version": row["binary_version"],
                           "purl": purl, "properties": [
                               {"name": "aquasecurity:trivy:SrcName", "value": row["source_name"]},
                               {"name": "aquasecurity:trivy:SrcVersion", "value": row["source_version"]},
                           ]})
        if binary in {"linux-image-" + kernel["release"], "linux-image-unsigned-" + kernel["release"]}:
            kernel_rows.append(row)
        if ".pgdg" in row["binary_version"]:
            pgdg.append(purl)
    components.sort(key=lambda item: item["purl"])
    require(components and len({item["purl"] for item in components}) == len(components), "NOBLE_SBOM_IDENTITIES")
    os_ref = "clipforge-observed-os-ubuntu-24.04"
    sbom = {"bomFormat": "CycloneDX", "specVersion": "1.6", "version": 1,
            "metadata": {"component": {"type": "operating-system", "bom-ref": os_ref, "name": "ubuntu", "version": "24.04"},
                         "properties": [{"name": "clipforge:inventory-sha256", "value": expected_sha}]},
            "components": components, "dependencies": [{"ref": os_ref, "dependsOn": [item["purl"] for item in components]}]}
    return sbom, {"schema": "clipforge-db01-noble-sca-input-1", "inventory_sha256": expected_sha,
                  "sbom_sha256": host.sha(sca.encoded(sbom)), "installed_binary_count": len(components),
                  "instance_id": evidence["control_plane"]["instance_id"],
                  "snapshot_sha256": evidence["control_plane"]["snapshot_sha256"],
                  "observation_commit": evidence["workflow_commit"],
                  "guest_boot_id": observed["guest_boot_id"],
                  "kernel": kernel, "kernel_release_package_candidates": kernel_rows, "pgdg_packages": sorted(pgdg),
                  "coverage_limits": SCA_LIMITS, "status": "scanner_not_run"}


def noble_purl_identity(value):
    require(isinstance(value, str) and len(value) <= 2048, "NOBLE_NATIVE_PURL")
    uri = urlsplit(value)
    require(uri.scheme == "pkg" and not uri.netloc and not uri.fragment and uri.path.startswith("deb/ubuntu/")
            and uri.path.count("/") == 2 and uri.path.count("@") == 1, "NOBLE_NATIVE_PURL")
    pairs = parse_qsl(uri.query, keep_blank_values=True, strict_parsing=True)
    fields = dict(pairs)
    require(len(pairs) == len(fields) and {"arch", "distro"} <= fields.keys() <= {"arch", "distro", "epoch"}
            and fields["distro"] == "ubuntu-24.04" and re.fullmatch(r"[0-9]+", fields.get("epoch", "0")),
            "NOBLE_NATIVE_PURL_FIELDS")
    name, version = (unquote(part) for part in uri.path.removeprefix("deb/ubuntu/").split("@"))
    epoch = int(fields.get("epoch", "0"))
    require("epoch" not in fields or ":" not in version, "NOBLE_NATIVE_EPOCH_AMBIGUOUS")
    return name, f"{epoch}:{version}" if epoch else version, fields["arch"], fields["distro"]


def verify_sca(inventory_raw, inventory_sha, report_raw, db_raw, database_sha):
    """Require the native report to preserve each submitted binary/source tuple."""
    sbom, receipt = noble_sbom(inventory_raw, inventory_sha)
    require(re.fullmatch(host.HEX, database_sha or "") and 0 < len(db_raw) <= 16384, "NOBLE_SCA_DB_PROVENANCE")
    metadata = host.closed_json(db_raw)
    require(metadata["Version"] == 2 and guest.timestamp(metadata["UpdatedAt"]) <= datetime.now(timezone.utc), "NOBLE_SCA_DB_METADATA")
    report = sca.decode(report_raw, limit=16 * 1024 * 1024)
    os_data = report.get("Metadata", {}).get("OS", {})
    require(report["SchemaVersion"] == 2 and report["ArtifactType"] == "cyclonedx"
            and os_data["Family"] == "ubuntu" and os_data["Name"] == "24.04"
            and len(report["Results"]) == 1, "NOBLE_SCA_NATIVE_OS_OR_TARGET")
    row = report["Results"][0]
    require(row["Class"] == "os-pkgs" and row["Type"] == "ubuntu" and isinstance(row["Packages"], list), "NOBLE_SCA_NATIVE_PACKAGE_COVERAGE")
    expected = {noble_purl_identity(component["purl"]): tuple(prop["value"] for prop in component["properties"])
                for component in sbom["components"]}
    native = {}
    for package in row["Packages"]:
        identity = noble_purl_identity(package["Identifier"]["PURL"])
        require(identity not in native, "NOBLE_SCA_DUPLICATE_NATIVE_PACKAGE")
        epoch, release = package.get("SrcEpoch", 0), package.get("SrcRelease", "")
        require(type(epoch) is int and epoch >= 0 and isinstance(release, str), "NOBLE_SCA_NATIVE_SOURCE")
        version = (f"{epoch}:" if epoch else "") + package["SrcVersion"] + ("-" + release if release else "")
        native[identity] = package["SrcName"], version
    require(expected == native, "NOBLE_SCA_NATIVE_PACKAGE_OR_SOURCE_DIFFERENCE")
    vulns = row.get("Vulnerabilities", [])
    require(isinstance(vulns, list), "NOBLE_SCA_NATIVE_FINDINGS")
    return {**receipt, "status": "findings_review_pending" if vulns else "no_native_findings_in_submitted_scope",
            "expected_scanner_image": SCANNER_IMAGE, "scanner_native_sha256": host.sha(report_raw), "db_sha256": database_sha,
            "db_metadata_sha256": host.sha(db_raw), "db_updated_at": metadata["UpdatedAt"],
            "native_findings_by_severity": dict(Counter(x.get("Severity", "UNKNOWN") for x in vulns))}


def write_new(path, raw):
    with Path(path).open("xb") as stream:
        os.chmod(path, 0o600)
        stream.write(raw)


def local_input(path, limit):
    """Require bounded content; Unix write-bit checks do not model Windows ACLs."""
    if os.name != "nt":
        return transport._local_bytes(path, limit)
    info = path.lstat()
    require(not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT
            and stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and 0 < info.st_size <= limit, "NOBLE_LOCAL_INPUT")
    with path.open("rb") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) == info.st_size, "NOBLE_LOCAL_INPUT_SIZE")
    return raw


def verify_database_file(path, expected_sha):
    info = path.lstat()
    require(not path.is_symlink() and stat.S_ISREG(info.st_mode) and 0 < info.st_size <= 4 * 1024 ** 3,
            "NOBLE_SCA_DB_FILE")
    with path.open("rb") as stream:
        actual_sha = hashlib.file_digest(stream, "sha256").hexdigest()
    require(actual_sha == expected_sha, "NOBLE_SCA_DB_DIGEST")


def staged_inputs(env):
    check_hosted_context(env)
    controls, run = env["GITHUB_SHA"], env["NOBLE_APPLY_RUN"]
    summary_raw = transport._local_bytes(Path(env["NOBLE_HANDOFF"]) / "summary.json", 262144)
    summary_sha = env["NOBLE_APPLY_SUMMARY_SHA256"]
    summary = exact_summary(summary_raw, summary_sha, controls, run)
    pin = check_pin(env["NOBLE_HOST_PIN_JSON"].encode("ascii"), env["NOBLE_HOST_PIN_SHA256"], summary, summary_sha)
    require(host.sha(guest.payload_bytes()) == PAYLOAD_SHA256, "NOBLE_PAYLOAD_SOURCE")
    return summary, pin


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    pin_args = commands.add_parser("pin")
    pin_args.add_argument("--apply-summary", type=Path, required=True)
    pin_args.add_argument("--summary-sha256", required=True)
    pin_args.add_argument("--controls", required=True)
    pin_args.add_argument("--apply-run", required=True)
    pin_args.add_argument("--output", type=Path, required=True)
    for operation in ("verify-apply-run", "check", "run", "cleanup"):
        commands.add_parser(operation)
    scan_args = commands.add_parser("verify-sca")
    for argument in ("inventory", "native-report", "db", "db-metadata", "output"):
        scan_args.add_argument("--" + argument, type=Path, required=True)
    scan_args.add_argument("--inventory-sha256", required=True)
    scan_args.add_argument("--db-sha256", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        if args.operation == "pin":
            from scripts import int_db01_noble_read_iam as iam
            iam.verify_checkout(args.controls)
            iam.verify_receipt_location(args.output)
            require(not args.output.exists(), "NOBLE_PIN_OUTPUT_EXISTS")
            summary = exact_summary(local_input(args.apply_summary, 262144), args.summary_sha256, args.controls, args.apply_run)
            token = iam.admin_token()
            env["GCP_ACCESS_TOKEN"] = token
            try:
                proof = host.closed_json(custody.fetch_verified(summary["receipt"]))
                require(proof == {key: value for key, value in summary.items() if key != "receipt"}, "NOBLE_CREATED_RECEIPT_ORIGIN")
                value = make_pin(summary, args.summary_sha256, lambda route: read_compute(route, token))
            finally:
                env.pop("GCP_ACCESS_TOKEN", None)
            raw = transport.canonical(value) + b"\n"
            write_new(args.output, raw)
            print(json.dumps({"status": "first_boot_pin_verified", "sha256": host.sha(raw)}))
        elif args.operation == "verify-sca":
            verify_database_file(args.db, args.db_sha256)
            report = verify_sca(local_input(args.inventory, guest.MAX_OUTPUT), args.inventory_sha256,
                               local_input(args.native_report, 16 * 1024 * 1024),
                               local_input(args.db_metadata, 16384), args.db_sha256)
            write_new(args.output, sca.encoded(report))
            print(json.dumps({"status": report["status"], "packages": report["installed_binary_count"]}))
        else:
            check_hosted_context(env)
            if args.operation == "verify-apply-run":
                checked_apply_run(env["NOBLE_APPLY_RUN"], env["GITHUB_SHA"], env["GH_TOKEN"])
                return 0
            work, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
            if args.operation == "cleanup":
                result = transport.cleanup(environ=env, workdir=work, reports=reports)
                return int(result["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"})
            summary, pin = staged_inputs(env)
            if args.operation == "check":
                return 0
            transport.validate_deploy_credentials(env, transport._credential_document(env))
            token = env["GCP_ACCESS_TOKEN"]
            result = collect(env, work, reports, summary, pin, reader=lambda route: read_compute(route, token),
                             client=transport.Client(lambda: token))
            if result["status"] != "observation_complete":
                return 1
            raw = transport._local_bytes(reports / "inventory.json")
            sbom, receipt = noble_sbom(raw, result["inventory_sha256"])
            write_new(reports / "noble.cdx.json", sca.encoded(sbom))
            write_new(reports / "sca-input.json", sca.encoded(receipt))
        return 0
    except Exception as error:
        code = str(error)
        report = {"status": "blocked", "operation": args.operation,
                  "error_code": code if re.fullmatch(r"[A-Z_]{3,100}", code) else type(error).__name__}
        if isinstance(error, transport.Failure):
            report["failure"] = error.receipt
        print(json.dumps(report))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
