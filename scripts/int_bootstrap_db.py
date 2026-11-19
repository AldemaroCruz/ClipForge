"""Candidate DB-01 launcher. Proposal and owner approval block activation by default.

One operation, pinned guest and source, expiring own OS Login key, encrypted stdin.
No migration, secret publication, deploy, automatic repair or mutation retry.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import ssl
import time
from urllib.error import HTTPError

from scripts import int_guest_inventory as t
from scripts import int_release

ROOT = Path(__file__).resolve().parents[1]
PROPOSAL = ROOT / "config/db01-bootstrap-proposal.json"
OPERATOR = ROOT / "scripts/int_bootstrap_vm.py"
DISK_ID = "6427691858848206684"
MAX_OPERATION_SECONDS = 600
CLEANUP_MARGIN_SECONDS = 180
MIN_TLS_SECONDS = 604800
SECRET_FIELDS = {"app_password": "INT_PG_APP_PASSWORD", "migrator_password": "INT_PG_MIGRATOR_PASSWORD",
                 "server_cert": "INT_PG_SERVER_CERT", "server_key": "INT_PG_SERVER_KEY", "ca_cert": "INT_PG_CA_CERT"}
DECISION_FIELDS = {"schema", "status", "owner", "repository", "branch", "approved_commit", "operation_id", "proposal_sha256",
                   "host_evidence_sha256", "baseline_evidence_sha256", "baseline_run_id", "baseline_artifact_id", "issued_utc", "expires_utc", "confirmation"}
require = t.require


def instant(value):
    require(isinstance(value, str), "db01_timestamp_required")
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    require(result.tzinfo is not None and result.utcoffset() is not None, "db01_aware_timestamp_required")
    return result


def source_bindings(proposal):
    rows = proposal.get("source_sha256")
    require(isinstance(rows, list) and rows and all(isinstance(row, dict) and set(row) == {"path", "sha256"} for row in rows), "db01_source_bindings_required")
    result = {}
    for row in rows:
        name, digest = row["path"], row["sha256"]
        require(isinstance(name, str) and re.fullmatch(r"(?:scripts|app|infra/gcp/int-base|\.github/workflows)/[A-Za-z0-9_./-]+", name)
                and ".." not in Path(name).parts and name not in result and re.fullmatch(r"[a-f0-9]{64}", digest), "db01_source_binding_invalid")
        require(t.sha(t._local_bytes(ROOT / name, 2 * 1024 * 1024)) == digest, "db01_reviewed_source_changed")
        result[name] = digest
    require({"scripts/int_bootstrap_db.py", "scripts/int_bootstrap_vm.py", "scripts/int_guest_inventory.py",
             "scripts/int_guest_inventory_guest.py", "scripts/int_guest_db_observe.py", ".github/workflows/int-e2e-bootstrap-db.yml"} <= set(result), "db01_complete_source_closure_required")
    return result


def validate_decision(raw, expected_sha, proposal_raw, env, *, now=None):
    require(re.fullmatch(r"[a-f0-9]{64}", expected_sha or "") and t.sha(raw) == expected_sha, "db01_owner_decision_digest")
    value, proposal = t.decode(raw), t.decode(proposal_raw)
    require(isinstance(value, dict) and set(value) == DECISION_FIELDS and value["schema"] == "clipforge-db01-activation-decision-1"
            and value["status"] == "authorized_single_guest_initialization" and value["owner"] == "admin@ixbalam.studio"
            and value["repository"] == "AldemaroCruz/ClipForge" and value["branch"] == "ci/bootstrap-sec03", "db01_closed_owner_decision_required")
    require(proposal.get("schema") == "clipforge-db01-bootstrap-proposal-1"
            and proposal.get("status") == "authorized_single_guest_initialization"
            and proposal.get("execution_authorized") is True and proposal.get("cloud_writes_authorized") is True
            and proposal.get("VM_operations_authorized") is True and proposal.get("SQL_on_INT_authorized") is True,
            "db01_proposal_blocks_activation")
    formatting = proposal.get("format_operation")
    require(isinstance(formatting, dict) and formatting.get("authorized") is True
        and formatting.get("one_invocation_only") is True and formatting == {
        "status": "authorized_single_initialization", "authorized": True,
        "argv": ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", "/dev/disk/by-id/google-clipforge-pg-data"],
        "confirmation": "INITIALIZE_NEW_DISK_" + DISK_ID, "disk_id": DISK_ID, "one_invocation_only": True},
        "db01_exact_format_authorization_required")
    require(value["approved_commit"] == env.get("GITHUB_SHA") == env.get("INT_APPROVED_COMMIT")
            and re.fullmatch(r"[a-f0-9]{40}", value["approved_commit"]) and value["proposal_sha256"] == t.sha(proposal_raw)
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and value["host_evidence_sha256"] == t.HOST_EVIDENCE_SHA
            and re.fullmatch(r"[a-f0-9]{64}", value["baseline_evidence_sha256"])
            and value["baseline_run_id"] == env.get("INT_BASELINE_RUN_ID") and re.fullmatch(r"[1-9][0-9]*", value["baseline_run_id"])
            and value["baseline_artifact_id"] == env.get("INT_BASELINE_ARTIFACT_ID") and re.fullmatch(r"[1-9][0-9]*", value["baseline_artifact_id"]), "db01_decision_scope_mismatch")
    target = proposal.get("target", {})
    require(target.get("project_id") == "clipforgebeta2" and target.get("project_number") == "816643438938"
            and target.get("instance_id") == t.host.IDENTITY["instance_id"] and target.get("disk_id") == DISK_ID
            and target.get("disk_size_bytes") == 21474836480 and target.get("attachment_device_name") == "clipforge-pg-data"
            and value["confirmation"] == "INITIALIZE_NEW_DISK_" + DISK_ID, "db01_exact_target_required")
    at = datetime.now(timezone.utc) if now is None else now
    issued, expires = instant(value["issued_utc"]), instant(value["expires_utc"])
    require(0 < (expires - issued).total_seconds() <= 3600 and issued <= at
            and (expires - at).total_seconds() >= MAX_OPERATION_SECONDS + CLEANUP_MARGIN_SECONDS, "db01_decision_window_or_cleanup_margin")
    return value, proposal


def preflight(env, decision_raw, decision_sha, host_raw, baseline_raw):
    selection = t.validate_deploy_credentials(env, t._credential_document(env))
    decision, proposal = validate_decision(decision_raw, decision_sha, t._local_bytes(PROPOSAL), env)
    bindings = source_bindings(proposal)
    pin = t.validate_hostkey_bundle(host_raw, decision["host_evidence_sha256"])
    require(t.sha(baseline_raw) == decision["baseline_evidence_sha256"], "db01_baseline_evidence_digest")
    from scripts import int_guest_db_observe as observer
    baseline = t.decode(baseline_raw)
    proof = observer.disk_proof(baseline)
    require(str(proof["disk_id"]) == DISK_ID and proof["instance_id"] == t.host.IDENTITY["instance_id"], "db01_baseline_identity_mismatch")
    try:
        int_release.require_application_ci(env)
    except HTTPError as error:
        raise t.Failure("db01_application_ci_read_denied", {"operation": "read_exact_commit_application_CI", "http_status": error.code, "response_body_withheld": True}) from None
    except ValueError:
        raise t.Blocked("db01_existing_application_ci_blocks_activation") from None
    client = t.Client(lambda: env.get("GCP_ACCESS_TOKEN", ""))
    vm, boot, data = (client.request("GET", url) for url in (t.VM_URL, t.BOOT_URL, t.DATA_URL))
    current = t.validate_compute_snapshot(vm, boot, data, pin)
    profile = client.profile()
    return {"decision": decision, "proposal": proposal, "source_bindings": bindings, "pin": pin,
            "baseline": baseline, "baseline_proof": proof, "credential_selection": selection,
            "current_compute_snapshot": current, "oslogin_profile": t.validate_deploy_profile(profile)}


def validate_tls(values, work, *, now=None):
    """A local MemoryBIO handshake checks CA, key pair, serverAuth and IP SAN."""
    from scripts.int_bootstrap_vm import validate_secrets
    validate_secrets(values)
    require(values["app_password"] != values["migrator_password"], "db01_passwords_must_be_distinct")
    for name, field in (("db01-server.crt", "server_cert"), ("db01-server.key", "server_key")):
        with (work / name).open("xb") as stream:
            os.chmod(work / name, 0o600); stream.write(values[field].encode("ascii"))
    try:
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); server.minimum_version = ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(str(work / "db01-server.crt"), str(work / "db01-server.key"), password=lambda: "")
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT); client.minimum_version = ssl.TLSVersion.TLSv1_2
        client.check_hostname, client.verify_mode = True, ssl.CERT_REQUIRED
        client.load_verify_locations(cadata=values["ca_cert"])
        si, so, ci, co = ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO(), ssl.MemoryBIO()
        peer = server.wrap_bio(si, so, server_side=True)
        connection = client.wrap_bio(ci, co, server_side=False, server_hostname="10.80.1.2")
        done = set()
        for _ in range(32):
            for label, endpoint in (("client", connection), ("server", peer)):
                if label not in done:
                    try:
                        endpoint.do_handshake(); done.add(label)
                    except ssl.SSLWantReadError:
                        pass
            for outgoing, incoming in ((co, si), (so, ci)):
                raw = outgoing.read(); require(len(raw) <= 65536, "db01_tls_handshake_bound")
                if raw: incoming.write(raw)
            if len(done) == 2: break
        require(len(done) == 2, "db01_tls_handshake_incomplete")
        cert, roots = connection.getpeercert(), client.get_ca_certs()
        at = time.time() if now is None else now
        require(len(roots) == 1 and all(ssl.cert_time_to_seconds(row["notAfter"]) - at >= MIN_TLS_SECONDS for row in [cert, *roots]), "db01_tls_minimum_validity")
        return {"status": "verified", "host": "10.80.1.2", "minimum_remaining_seconds": MIN_TLS_SECONDS,
                "protocol": connection.version(), "server_certificate_sha256": t.sha(values["server_cert"].encode()),
                "ca_certificate_sha256": t.sha(values["ca_cert"].encode())}
    except (ssl.SSLError, KeyError, UnicodeError, ValueError):
        raise t.Blocked("db01_tls_prevalidation_failed") from None


def remote_loader(source, expected_sha):
    require(t.sha(source) == expected_sha and re.fullmatch(r"[a-f0-9]{64}", expected_sha), "db01_operator_source_digest")
    encoded = base64.b64encode(source).decode("ascii")
    code = "import base64;exec(compile(base64.b64decode(\"" + encoded + "\"),\"int_bootstrap_vm.py\",\"exec\"),{\"__name__\":\"__main__\",\"DB01_OPERATOR_SHA256\":\"" + expected_sha + "\"})"
    return "/usr/bin/sudo -n /usr/bin/python3 -I -c '" + code + "'"


def bootstrap_ssh_command(work, username, port, loader):
    result = t.ssh_command(work, username, port); result[-1] = loader
    return result


class BootstrapProcesses(t.ProcessRunner):
    def __init__(self, *args, operator_source, operator_sha, **kwargs):
        super().__init__(*args, **kwargs)
        self.loader = remote_loader(operator_source, operator_sha)
        self.bootstrap_input = None

    def _kind(self, argv, input_data):
        if self.username is not None and self.bootstrap_input is not None and input_data == self.bootstrap_input:
            try: port = int(argv[argv.index("-p") + 1])
            except (ValueError, TypeError, IndexError): raise t.Blocked("db01_unreviewed_process") from None
            if argv == bootstrap_ssh_command(self.work, self.username, port, self.loader): return "ssh"
        return super()._kind(argv, input_data)

    def _start(self, argv, kind):
        if kind == "ssh" and self.bootstrap_input is not None and argv and argv[-1] == self.loader:
            original = self.payload; self.payload = self.bootstrap_input
            try: return super()._start(argv, kind)
            finally: self.payload = original
        return super()._start(argv, kind)


def phase(work, journal, name, status, **metadata):
    require(name in {"preflight", "tls", "key", "observe", "bootstrap", "postcheck", "cleanup"}
            and status in {"started", "completed", "unknown", "blocked"}, "db01_phase_status")
    journal["phases"].append({"phase": name, "status": status, "observed_utc": datetime.now(timezone.utc).isoformat(), **metadata})
    target, pending = work / "db01-journal.json", work / "db01-journal.next.json"
    require(not pending.exists() and not pending.is_symlink() and not target.is_symlink(), "db01_journal_collision")
    with pending.open("xb") as stream:
        os.chmod(pending, 0o600); stream.write(t.canonical(journal)); stream.flush(); os.fsync(stream.fileno())
    os.replace(pending, target)


def same_disk_identity(baseline, fresh):
    changing = {"observed_utc", "guest_read_receipt_sha256", "guest_read_source_sha256"}
    require(set(baseline) == set(fresh) and {k: v for k, v in baseline.items() if k not in changing}
            == {k: v for k, v in fresh.items() if k not in changing}, "db01_disk_or_boot_changed_from_review")
    require(0 <= (datetime.now(timezone.utc) - instant(fresh["observed_utc"])).total_seconds() <= 300, "db01_fresh_observation_expired")


def same_observed_inputs(baseline, fresh):
    require(baseline["guest"]["packages_source"] == fresh["guest"]["packages_source"], "db01_reviewed_package_sources_changed")
    old, new = baseline["guest"]["base_inventory"]["inventory"], fresh["guest"]["base_inventory"]["inventory"]
    require(all(old[key] == new[key] for key in ("packages", "os_release", "kernel")), "db01_reviewed_guest_inputs_changed")


def checked_guest_result(receipt, code, expected):
    core = {"operation_id", "approved_commit", "proposal_sha256", "operator_sha256"}
    allowed = core | {"disk_id", "guest_boot_id", "disk_proof_sha256", "guest_read_receipt_sha256", "guest_read_source_sha256"}
    require(core <= set(expected) <= allowed and code in {0, 2, 3} and code == receipt["exit_code"]
            and all(receipt[key] == value for key, value in expected.items()), "db01_guest_receipt_scope_or_exit_mismatch")
    return receipt


def failure_status(journal):
    return "unknown_preserve_and_review" if any(p["phase"] == "bootstrap" and p["status"] == "started" for p in journal["phases"]) else "blocked"


def cleanup(env, workdir, reports, *, client=None):
    work, output = t._validate_paths(env, workdir, reports)
    try:
        result = t.cleanup(environ=env, workdir=work, reports=output, client=client)
    except Exception:
        result = {"status": "cleanup_unconfirmed_TTL_pending", "error_code": "db01_own_key_cleanup_unconfirmed"}
    for name in ("db01-server.crt", "db01-server.key"):
        path = work / name
        try:
            if path.exists():
                require(path.is_file() and not path.is_symlink(), "db01_tls_cleanup_target"); path.unlink()
        except Exception:
            result.update(status="cleanup_unconfirmed_TTL_pending", local_private_file_cleanup="unconfirmed")
    return result


def run(env, *, workdir, reports, decision_raw, decision_sha, host_raw, baseline_raw, protected_values=None):
    ready = preflight(env, decision_raw, decision_sha, host_raw, baseline_raw)
    work, output = t._validate_paths(env, workdir, reports)
    require(not (work / "db01-journal.json").exists() and not (work / "cleanup-journal.json").exists(), "db01_operation_must_not_be_replayed")
    from scripts import int_guest_db_observe as observer
    from scripts import int_bootstrap_vm as operator
    operator_sha = ready["source_bindings"]["scripts/int_bootstrap_vm.py"]
    operator_source = t._local_bytes(OPERATOR, 131072)
    observation = t.readinesscheck(host_raw, ready["decision"]["host_evidence_sha256"],
        env.get("INT_DB_OBSERVATION_PAYLOAD_SHA256", ""), inspection_mode="db01-observe")
    journal = {"schema": "clipforge-db01-launcher-journal-1", "operation_id": ready["decision"]["operation_id"],
               "approved_commit": env["GITHUB_SHA"], "owner_decision_sha256": decision_sha, "phases": []}
    own = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": env["GITHUB_REPOSITORY"], "run_id": env["GITHUB_RUN_ID"],
           "run_attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"], "public_key": None, "created_us": None,
           "expiration_us": None, "fingerprint": None, "import_attempted": False, "key_absent_before_import": False, "profile_name": None, "processes": []}
    t._save_journal(work, own); phase(work, journal, "preflight", "completed")
    result = {"schema": "clipforge-db01-launcher-result-1", "status": "blocked", "operation_id": journal["operation_id"],
              "owner_decision_sha256": decision_sha, "runtime_authorized": False, "migrations_applied": False,
              "external_client_acceptance": False, "restore_verified": False}
    processes, previous = None, {}
    client = t.Client(lambda: env.get("GCP_ACCESS_TOKEN", ""))
    try:
        def interrupted(signum, frame):
            raise t.Blocked("db01_interrupted_outcome_requires_review")
        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, interrupted)
        values = protected_values if protected_values is not None else {key: env.pop(name, "") for key, name in SECRET_FIELDS.items()}
        for name in SECRET_FIELDS.values(): os.environ.pop(name, None)
        phase(work, journal, "tls", "started")
        result["tls"] = validate_tls(values, work)
        phase(work, journal, "tls", "completed")
        vm, boot, data = (client.request("GET", url) for url in (t.VM_URL, t.BOOT_URL, t.DATA_URL))
        before = t.validate_compute_snapshot(vm, boot, data, ready["pin"])
        result["oslogin_profile"] = t.validate_deploy_profile(client.profile())
        require(client.actor_verified and client.profile_name is not None, "db01_sdk_email_profile_required")
        own["profile_name"] = client.profile_name
        program = shutil.which("gcloud")
        require(program and Path(program).is_absolute() and Path(program).name == "gcloud", "db01_pinned_sdk_required")
        def process_record(row):
            alive = {p.pid for p in processes.owned if p.poll() is None}
            own["processes"] = [p for p in own["processes"] if p["pid"] in alive and p["pid"] != row["pid"]] + [row]
            t._save_journal(work, own)
        processes = BootstrapProcesses(work, program, observation["payload"], "clipforge-db01-" + env["GITHUB_RUN_ID"], process_record,
            operator_source=operator_source, operator_sha=operator_sha, maximum_process_seconds=600)
        code, raw, _ = processes.run([program, "version", "--format=json"])
        require(code == 0 and t.decode(raw).get("Google Cloud SDK") == "582.0.0", "db01_sdk_version_changed")
        phase(work, journal, "key", "started")
        code, _, _ = processes.run(processes.keygen_command()); require(code == 0, "db01_own_key_generation_failed")
        public, _ = t.host_guest.public_key(t._local_bytes(work / "id_ed25519.pub", 1024))
        require((work / "id_ed25519").stat().st_mode & 0o777 == 0o600, "db01_private_key_mode")
        created = int(time.time() * 1000000); expiration = created + 900000000
        client.arm_key(public, expiration); client.prepare_import()
        own.update(public_key=public, created_us=created, expiration_us=expiration, key_absent_before_import=True, import_attempted=True)
        t._save_journal(work, own)
        selected = client.import_key(); own["fingerprint"] = selected["fingerprint"]; t._save_journal(work, own)
        result["ssh_posix_username"] = selected["username"]
        phase(work, journal, "key", "completed", maximum_ttl_seconds=900)
        with (work / "known_hosts").open("xb") as stream:
            os.chmod(work / "known_hosts", 0o400); stream.write(ready["pin"]["known_hosts"])
        with socket.socket() as reserved:
            reserved.bind(("127.0.0.1", 0)); port = reserved.getsockname()[1]
        processes.username = selected["username"]; processes.start_tunnel(port)
        phase(work, journal, "observe", "started")
        code, raw, stderr = processes.run(t.ssh_command(work, selected["username"], port), observation["payload"], timeout=180, stdout_limit=t.MAX_JSON)
        result["observation_ssh"] = {"exit_code": code, **t.process_diagnostic(stderr)}
        guest = t.parse_inventory(raw, code, inspection_mode="db01-observe")
        vm, boot, data = (client.request("GET", url) for url in (t.VM_URL, t.BOOT_URL, t.DATA_URL))
        require(t.validate_compute_snapshot(vm, boot, data, ready["pin"]) == before, "db01_compute_changed_before_bootstrap")
        evidence = observer.make_evidence(guest, vm, boot, data, observed_utc=datetime.now(timezone.utc).isoformat(),
            commit=env["GITHUB_SHA"], payload_sha256=env["INT_DB_OBSERVATION_PAYLOAD_SHA256"])
        fresh = observer.disk_proof(evidence); same_disk_identity(ready["baseline_proof"], fresh)
        same_observed_inputs(ready["baseline"], evidence)
        phase(work, journal, "observe", "completed", receipt_sha256=t.sha(t.canonical(evidence) + b"\n"))
        validate_decision(decision_raw, decision_sha, t._local_bytes(PROPOSAL), env)
        require(expiration / 1000000 - time.time() >= MAX_OPERATION_SECONDS + CLEANUP_MARGIN_SECONDS, "db01_key_cleanup_margin_insufficient")
        token_start = env.get("INT_GCP_AUTH_STARTED_EPOCH", "")
        require(re.fullmatch(r"[1-9][0-9]{9,11}", token_start) and 0 <= time.time() - int(token_start)
                and int(token_start) + 900 - time.time() >= MAX_OPERATION_SECONDS + CLEANUP_MARGIN_SECONDS,
                "db01_access_token_cleanup_margin_insufficient")
        request = {"schema": "clipforge-db01-bootstrap-input-1", "operation_id": journal["operation_id"], "approved_commit": env["GITHUB_SHA"],
            "proposal_sha256": ready["decision"]["proposal_sha256"], "operator_sha256": operator_sha,
            "confirmation": ready["decision"]["confirmation"], "disk_proof": fresh, "secrets": values}
        private = t.canonical(request); require(len(private) <= 65536, "db01_protected_input_bound")
        processes.bootstrap_input = private
        phase(work, journal, "bootstrap", "started")
        code, raw, stderr = processes.run(bootstrap_ssh_command(work, selected["username"], port, processes.loader), private,
                                     timeout=600, stdout_limit=65536, stderr_limit=8192)
        result["bootstrap_ssh"] = {"exit_code": code, **t.process_diagnostic(stderr)}
        receipt = operator.validate_receipt(t.decode(raw))
        result.update(guest_receipt=receipt, guest_receipt_scope_verified=False)
        checked_guest_result(receipt, code, {"operation_id": journal["operation_id"], "approved_commit": env["GITHUB_SHA"],
            "proposal_sha256": ready["decision"]["proposal_sha256"], "operator_sha256": operator_sha,
            "disk_id": DISK_ID, "guest_boot_id": fresh["guest_boot_id"], "disk_proof_sha256": t.sha(t.canonical(fresh)),
            "guest_read_receipt_sha256": fresh["guest_read_receipt_sha256"], "guest_read_source_sha256": fresh["guest_read_source_sha256"]})
        result["guest_receipt_scope_verified"] = True
        phase(work, journal, "bootstrap", "completed", native_exit=code, receipt_sha256=t.sha(raw))
        vm, boot, data = (client.request("GET", url) for url in (t.VM_URL, t.BOOT_URL, t.DATA_URL))
        require(t.validate_compute_snapshot(vm, boot, data, ready["pin"]) == before, "db01_compute_changed_during_bootstrap")
        phase(work, journal, "postcheck", "completed"); result["status"] = receipt["status"]
    except BaseException as error:
        result["status"] = failure_status(journal)
        result["error_code"] = str(error) if isinstance(error, t.Blocked) else "db01_private_failure_details_withheld"
        if isinstance(error, t.Failure): result["failure"] = error.receipt
    finally:
        try:
            if processes is not None: processes.close()
        except Exception:
            result["process_cleanup"] = "unconfirmed"
        finally:
            try:
                result["cleanup"] = cleanup(env, work, output, client=client)
            finally:
                for number, handler in previous.items():
                    try: signal.signal(number, handler)
                    except Exception: result["signal_handler_restore"] = "unconfirmed"
    if result["cleanup"]["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"} or result.get("process_cleanup") == "unconfirmed":
        result["status"] = "unknown_preserve_and_review"
    try:
        phase(work, journal, "cleanup", "completed" if result["cleanup"]["status"] in {"own_key_removed", "key_already_absent", "no_registered_key"} else "unknown", key_status=result["cleanup"]["status"])
    except Exception:
        result.update(status="unknown_preserve_and_review", phase_journal="cleanup_write_unconfirmed")
    result["phases"] = journal["phases"]
    with (output / "db01-result.json").open("xb") as stream: stream.write(t.canonical(result) + b"\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("preflight", "run", "cleanup"))
    parser.add_argument("--workdir", type=Path, required=True); parser.add_argument("--reports", type=Path, required=True)
    parser.add_argument("--decision", type=Path); parser.add_argument("--decision-sha256")
    parser.add_argument("--host-evidence", type=Path); parser.add_argument("--baseline-evidence", type=Path)
    args = parser.parse_args()
    if args.operation == "cleanup":
        result = cleanup(os.environ, args.workdir, args.reports)
        return 0 if result["status"] in {"own_key_removed", "key_already_absent", "no_registered_key"} else 1
    require(all((args.decision, args.decision_sha256, args.host_evidence, args.baseline_evidence)), "db01_explicit_evidence_required")
    values = {"decision_raw": t._local_bytes(args.decision, 65536), "decision_sha": args.decision_sha256,
              "host_raw": t._local_bytes(args.host_evidence, 65536), "baseline_raw": t._local_bytes(args.baseline_evidence)}
    if args.operation == "preflight":
        preflight(os.environ, **values)
        print("Exact DB-01 proposal, owner decision, WIF and application CI passed; no key registration or guest mutation.")
        return 0
    result = run(os.environ, workdir=args.workdir, reports=args.reports, **values)
    print(json.dumps({"status": result["status"], "runtime_authorized": False, "external_client_acceptance": False}))
    return 0 if result["status"] == "configured_guest_verified_external_acceptance_pending" else 1


if __name__ == "__main__":
    try: raise SystemExit(main())
    except t.Failure as error:
        print(json.dumps({"status": "blocked_or_unknown_preserve_and_review", "error_code": str(error), "failure": error.receipt}))
        raise SystemExit(1)
    except t.Blocked as error:
        print(json.dumps({"status": "blocked_or_unknown_preserve_and_review", "error_code": str(error)}))
        raise SystemExit(1)
    except Exception:
        print(json.dumps({"status": "blocked_or_unknown_preserve_and_review", "error_code": "db01_control_failed_preserve_review"}))
        raise SystemExit(1)
