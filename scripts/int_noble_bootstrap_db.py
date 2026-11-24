"""Protected Noble launcher backed by the DB-01 read, journal and containment contracts."""

import argparse
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

from scripts import int_bootstrap_containment as containment
from scripts import int_bootstrap_db as legacy
from scripts import int_bootstrap_vm as guest_contract
from scripts import int_demo_a_db_runner as db_runner
from scripts import check_int_demo_a as gate
from scripts import int_db01_noble_read_iam as iam
from scripts import int_demo_a_noble_policy as noble_policy
from scripts import int_guest_inventory as transport
from scripts import int_noble_bootstrap_payloads as payloads
from scripts import int_noble_first_observation as first
from scripts import int_noble_guest_observation as guest
from scripts import int_noble_kernel_observation as handoff
from scripts import int_release as release


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/int-db01-noble-bootstrap.yml"
CONTROL = "config/int-db01-noble-bootstrap.json"
TARGET = {"project_id": "clipforgebeta2", "project_number": "816643438938", "zone": "us-central1-a",
          "instance_id": payloads.INSTANCE, "boot_disk_id": payloads.BOOT, "disk_id": payloads.DATA,
          "instance_name": first.host.INSTANCE, "disk_name": guest.DATA_DISK, "attachment_device_name": guest.DEVICE_NAME,
          "postgres_private_ip": guest.PRIVATE_IP, "disk_size_bytes": guest.SIZE_BYTES}
CONFIRMATION = "INITIALIZE_NEW_DISK_" + payloads.DATA
BASELINE_RUN, BASELINE_ARTIFACT = "44772950030", "14649080312"
BASELINE_SHA = "8ac056907faca259ed21c394a53c46d290dc99496dc7fe618512b1bb9c65329b"
DEMO_SHA = "40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15"
MIGRATOR_SHA = "24e4d9ccea365859c6f455c3780c8abe6a0df3f1150e60380e2b2cc73e0dc5b5"
APPROVED_APP_SOURCE = "6c1bf38c92e2bfa1d6949d5e54fb5508d4df83fd"
PROPOSAL_FIELDS = {"schema", "status", "execution_authorized", "cloud_writes_authorized", "VM_operations_authorized",
                   "SQL_on_INT_authorized", "risk_acceptance", "target", "format_operation", "containment", "controls",
                   "gate", "operator_sha256", "containment_sha256", "images", "source_sha256", "deploy_policy_receipt_sha256"}
REQUIRED_SOURCES = {WORKFLOW, CONTROL, "scripts/int_noble_bootstrap_db.py", "scripts/int_noble_bootstrap_payloads.py",
                    noble_policy.CONFIG, "scripts/int_demo_a_noble_policy.py",
                    "scripts/check_int_demo_a.py", "scripts/int_bootstrap_db.py", "scripts/int_bootstrap_vm.py",
                    "scripts/int_bootstrap_containment.py", "scripts/int_guest_inventory.py", "scripts/int_guest_inventory_guest.py",
                    "scripts/int_guest_db_observe.py", "scripts/int_vm_hostkey_guest.py", "scripts/int_noble_guest_observation.py",
                    "scripts/int_noble_first_observation.py", "scripts/int_noble_hostkey.py", "scripts/int_noble_kernel_observation.py",
                    "scripts/int_noble_apply.py", "scripts/int_db01_noble_read_iam.py", "scripts/int_release.py",
                    "scripts/int_demo_a_db_runner.py", "scripts/int_demo_a_publication_host.py"}
MAX_OPERATION = legacy.MAX_OPERATION_SECONDS
CLEANUP_MARGIN = legacy.CLEANUP_MARGIN_SECONDS
require = transport.require


def exact_local_hash(path, expected, maximum=2 * 1024 * 1024):
    require(isinstance(expected, str) and re.fullmatch(r"[a-f0-9]{64}", expected), "noble_expected_digest")
    raw = transport._local_bytes(path, maximum)
    require(transport.sha(raw) == expected, "noble_artifact_digest")
    return raw


def proof(raw, *, before, after, pin, commit):
    linked = guest.linked_observation(raw, 0, before=before, after=after, pin_receipt=pin, workflow_commit=commit,
                                      expected_payload_sha256=first.PAYLOAD_SHA256)
    observation = linked["guest"]
    disk = observation["disk"]
    return linked, {
        "project_id": TARGET["project_id"], "project_number": TARGET["project_number"], "zone": TARGET["zone"],
        "instance_id": before["instance_id"], "disk_id": before["data_disk_id"], "disk_name": TARGET["disk_name"],
        "disk_type": "https://www.googleapis.com/compute/v1/" + guest.ZONE_PATH + "/diskTypes/pd-standard",
        "device_name": guest.DEVICE_NAME, "size_bytes": before["attachment_size_bytes"],
        "interface": before["attachment_interface"], "index": before["attachment_index"], "mode": before["attachment_mode"],
        "boot": before["attachment_boot"], "auto_delete": before["attachment_auto_delete"],
        "guest_major_minor": disk["before"]["major_minor"], "guest_serial": guest.DEVICE_NAME,
        "guest_by_id": guest.BY_ID, "guest_boot_id": observation["guest_boot_id"], "boot_timestamp": before["boot_timestamp"],
        "observed_utc": observation["observed_utc"], "guest_read_receipt_sha256": transport.sha(transport.canonical(linked) + b"\n"),
        "guest_read_source_sha256": first.PAYLOAD_SHA256,
    }


def check_window(decision, now=None, minimum=MAX_OPERATION + CLEANUP_MARGIN):
    at = now or datetime.now(timezone.utc)
    issued, expires = (legacy.instant(decision[key]) for key in ("issued_utc", "expires_utc"))
    require(0 < (expires - issued).total_seconds() <= 3600 and issued <= at
            and (expires - at).total_seconds() >= minimum, "noble_decision_or_cleanup_margin")


def validate_local(env, bundle, sha, *, root=ROOT, now=None):
    """No WIF, subprocess, or cloud client is used during contract validation."""
    expected_context = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
                        "GITHUB_REF": "refs/heads/ci/bootstrap-sec03", "GITHUB_WORKFLOW_REF": f"AldemaroCruz/ClipForge/{WORKFLOW}@refs/heads/ci/bootstrap-sec03",
                        "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1"}
    require(all(env.get(k) == v for k, v in expected_context.items()) and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", "")) and env.get("GITHUB_SHA") == env.get("INT_APPROVED_COMMIT"),
            "noble_bootstrap_context")
    decision_raw = exact_local_hash(bundle / "decision.json", sha, 65536)
    decision = transport.decode(decision_raw)
    require(set(decision) == legacy.DECISION_FIELDS and decision["schema"] == "clipforge-db01-activation-decision-1"
            and decision["status"] == "authorized_single_guest_initialization" and decision["owner"] == "admin@ixbalam.studio"
            and decision["repository"] == env["GITHUB_REPOSITORY"] and decision["branch"] == "ci/bootstrap-sec03"
            and decision["approved_commit"] == env["GITHUB_SHA"] and decision["confirmation"] == CONFIRMATION
            and re.fullmatch(r"[a-f0-9]{32}", decision["operation_id"]) and decision["host_evidence_sha256"] == handoff.PIN_SHA
            and decision["baseline_evidence_sha256"] == BASELINE_SHA and decision["baseline_run_id"] == BASELINE_RUN
            and decision["baseline_artifact_id"] == BASELINE_ARTIFACT, "noble_closed_owner_decision")
    check_window(decision, now=now)
    proposal_raw = exact_local_hash(bundle / "proposal.json", decision["proposal_sha256"], 65536)
    proposal = transport.decode(proposal_raw)
    require(set(proposal) == PROPOSAL_FIELDS and proposal["schema"] == "clipforge-int-noble-bootstrap-proposal-2"
            and proposal["status"] == decision["status"] and all(proposal[key] is True for key in
                ("execution_authorized", "cloud_writes_authorized", "VM_operations_authorized", "SQL_on_INT_authorized"))
            and proposal["risk_acceptance"] is False and proposal["target"] == TARGET, "noble_bootstrap_exact_target")
    controls_raw = exact_local_hash(root / CONTROL, proposal["controls"])
    controls = transport.decode(controls_raw)
    expected_controls = {"schema": "clipforge-int-noble-bootstrap-controls-1", "activation_authorized": False,
                         "application_ci_gate": "global", "project": TARGET["project_id"], "project_number": TARGET["project_number"],
                         "zone": TARGET["zone"], "instance_id": payloads.INSTANCE, "boot_disk_id": payloads.BOOT, "data_disk_id": payloads.DATA,
                         "baseline_run_id": BASELINE_RUN, "baseline_artifact_id": BASELINE_ARTIFACT, "baseline_sha256": BASELINE_SHA,
                         "demo_source_commit": APPROVED_APP_SOURCE, "demo_oci": "sha256:" + DEMO_SHA, "migrator_oci": "sha256:" + MIGRATOR_SHA}
    require(controls == expected_controls and controls["activation_authorized"] is False
            and proposal["gate"] in {"global", "demo-a"}, "noble_bootstrap_exact_control_or_gate")
    require(proposal["format_operation"] == {"status": "authorized_single_initialization", "authorized": True,
                "argv": ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", guest.BY_ID], "confirmation": CONFIRMATION,
                "disk_id": payloads.DATA, "one_invocation_only": True}
            and proposal["operator_sha256"] == payloads.GUEST_SHA and proposal["containment_sha256"] == payloads.CONTAINMENT_SHA
            and proposal["containment"] == containment.containment_policy(payloads.CONTAINMENT_SHA, payloads.GUEST_SHA, authorized=True),
            "noble_reviewed_bootstrap_and_containment")
    require(proposal["images"] == {"demo_commit": APPROVED_APP_SOURCE, "demo_manifest": "sha256:" + DEMO_SHA,
                "migrator_manifest": "sha256:" + MIGRATOR_SHA}, "noble_bootstrap_exact_images")
    digests = proposal["source_sha256"]
    require(isinstance(digests, dict) and set(digests) == REQUIRED_SOURCES, "noble_bootstrap_source_closure")
    for filename, digest in digests.items():
        exact_local_hash(root / filename, digest)
    policy_config = transport.decode(exact_local_hash(root / noble_policy.CONFIG, digests[noble_policy.CONFIG], 65536))
    policy_raw = exact_local_hash(bundle / "deploy-policy-receipt.json", proposal["deploy_policy_receipt_sha256"], 65536)
    policy_receipt = transport.decode(policy_raw)
    require(policy_raw == transport.canonical(policy_receipt), "noble_deploy_policy_receipt_canonical")
    expected_policy = noble_policy.expected_policy(policy_config, policy_receipt)
    summary, pin = handoff.checked_inputs(exact_local_hash(bundle / "summary.json", handoff.SUMMARY_SHA),
                                         exact_local_hash(bundle / "host-pin.json", handoff.PIN_SHA))
    baseline = transport.decode(exact_local_hash(bundle / "inventory.json", BASELINE_SHA))
    linked, old_proof = proof(transport.canonical(baseline["guest"]) + b"\n", before=baseline["control_plane"],
                             after=pin["control_plane"], pin=pin, commit=baseline["workflow_commit"])
    require(linked == baseline and old_proof["guest_read_receipt_sha256"] == BASELINE_SHA, "noble_bootstrap_evidence_relationship")
    operator, stop = payloads.operator_bytes(), payloads.containment_bytes()
    return {"decision": decision, "decision_raw": decision_raw, "proposal_raw": proposal_raw, "pin": pin, "summary": summary,
            "baseline_proof": old_proof, "baseline": baseline, "gate": proposal["gate"], "operator": operator, "containment": stop,
            "deploy_policy": expected_policy, "noble_iam_receipt_sha256": proposal["deploy_policy_receipt_sha256"]}


def check_cloud(env, ready, *, reader=first.read_compute, policies=noble_policy.verify_live, client_factory=transport.Client):
    """Pin the effective Deploy identity, permissions and target before key creation."""
    require(env.get("INT_NOBLE_PROTECTED_DECISION_SHA256") == transport.sha(ready["decision_raw"]), "noble_protected_decision_digest")
    transport.validate_deploy_credentials(env, transport._credential_document(env))
    token = env.get("GCP_ACCESS_TOKEN", "")
    before = first.snapshot(lambda url: reader(url, token), ready["summary"]["candidate"])
    require(before == ready["pin"]["control_plane"], "noble_current_disk_boot_or_metadata_changed")
    if ready["gate"] == "global":
        try:
            release.require_application_ci(env)
        except ValueError:
            raise transport.Blocked("noble_global_application_ci_blocks_activation") from None
    # OS Login and port-conditioned IAP are proved by the fresh, pinned SSH read in launch.
    missing = policies(ready["deploy_policy"], token)
    permission = "iam.serviceAccounts.actAs"
    try:
        effective = iam.request_json(f"https://iam.googleapis.com/v1/{noble_policy.ACCOUNT}:testIamPermissions", token,
                                     "POST", {"permissions": [permission]})
        if permission not in effective.get("permissions", []):
            missing.append({"operation": "testIamPermissions", "resource": noble_policy.ACCOUNT,
                            "missing_permissions": [permission], "http_status": 200})
    except iam.CloudError as error:
        missing.append({"operation": "testIamPermissions", "resource": noble_policy.ACCOUNT,
                        "permissions": [permission], "http_status": error.status})
    if missing:
        raise transport.Failure("noble_deploy_policy_or_permissions_blocked", {"checks": missing})
    client = client_factory(lambda: token)
    profile = transport.validate_deploy_profile(client.profile())
    require(client.actor_verified and client.profile_name is not None, "noble_effective_deploy_profile")
    return before, client, profile


def check_tls(env, work):
    values = {key: env.get(name, "") for key, name in legacy.SECRET_FIELDS.items()}
    guest_contract.validate_secrets(values)
    require(values["app_password"] != values["migrator_password"], "noble_distinct_sql_passwords")
    paths = (work / "db01-server.crt", work / "db01-server.key")
    created = []
    try:
        for path, field in zip(paths, ("server_cert", "server_key"), strict=True):
            descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            created.append(path)
            with os.fdopen(descriptor, "wb") as out:
                out.write(values[field].encode("ascii"))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.minimum_version = ssl.TLSVersion.TLSv1_2
        server.load_cert_chain(*paths, password=lambda: "")
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.minimum_version = ssl.TLSVersion.TLSv1_2
        client.load_verify_locations(cadata=values["ca_cert"])
        server_in, server_out, client_in, client_out = (ssl.MemoryBIO() for _ in range(4))
        peer = server.wrap_bio(server_in, server_out, server_side=True)
        connection = client.wrap_bio(client_in, client_out, server_hostname=guest.PRIVATE_IP)
        pending = [peer, connection]
        for _ in range(32):
            for endpoint in tuple(pending):
                try:
                    endpoint.do_handshake()
                    pending.remove(endpoint)
                except ssl.SSLWantReadError:
                    continue
            for source, destination in ((client_out, server_in), (server_out, client_in)):
                raw = source.read()
                require(len(raw) <= 65536, "noble_tls_handshake_limit")
                if raw:
                    destination.write(raw)
            if not pending:
                break
        require(not pending, "noble_tls_handshake_incomplete")
        roots = client.get_ca_certs()
        require(len(roots) == 1 and all(ssl.cert_time_to_seconds(cert["notAfter"]) - time.time() >= legacy.MIN_TLS_SECONDS
                for cert in (connection.getpeercert(), *roots)), "noble_tls_expiry")
        return values
    except (ssl.SSLError, UnicodeError, KeyError):
        raise transport.Blocked("noble_tls_validation") from None
    finally:
        for path in created:
            path.unlink(missing_ok=True)


class NobleProcesses(transport.ProcessRunner):
    """Send only the fixed read payload or one bound protected stdin per phase."""

    def __init__(self, work, gcloud, payload, run_tag, record):
        super().__init__(work, gcloud, payload, run_tag, record, maximum_process_seconds=MAX_OPERATION,
                         ssh_builder=first.ssh_builder(payloads.INSTANCE), tunnel_builder=first.noble_tunnel)
        self.mutation_command = None
        self.invoked = set()

    def _kind(self, argv, input_data):
        if self.mutation_command is not None and argv == self.mutation_command and input_data == self.payload:
            return "ssh"
        return super()._kind(argv, input_data)

    def invoke_once(self, operation, port, public, private):
        require(operation in {"bootstrap", "containment"} and operation not in self.invoked
                and (operation == "bootstrap" or "bootstrap" in self.invoked), "noble_mutation_replay")
        loader = legacy.remote_loader(public, transport.sha(public))
        self.mutation_command = self.ssh_builder(self.work, self.username, port)
        self.mutation_command[-1] = loader
        old = self.payload
        self.invoked.add(operation)
        self.payload = private
        try:
            timeout = MAX_OPERATION if operation == "bootstrap" else legacy.CONTAINMENT_SSH_SECONDS
            return self.run(self.mutation_command, private, timeout=timeout, stdout_limit=65536)
        finally:
            self.mutation_command = None
            self.payload = old


def token_margin(env, expiration, seconds):
    token_start = env.get("INT_GCP_AUTH_STARTED_EPOCH", "")
    now = time.time()
    require(re.fullmatch(r"[1-9][0-9]{9,11}", token_start) and 0 <= now - int(token_start) <= 900 - seconds
            and expiration / 1_000_000 - now >= seconds, "noble_key_or_token_cleanup_margin")


def run_containment(env, ready, processes, port, expiration, checked, operator, work, journal):
    require(checked["status"] == "partial_preserved" and checked["exit_code"] == 3 and checked["journal_error_code"] is None
            and checked["finished_utc"] and sum(row["operation"] == "start" for row in checked["native_operations"]) == 1,
            "noble_containment_requires_scoped_finished_start")
    token_margin(env, expiration, legacy.CONTAINMENT_SSH_SECONDS + CLEANUP_MARGIN)
    check_window(ready["decision"], minimum=legacy.CONTAINMENT_SSH_SECONDS + CLEANUP_MARGIN)
    raw_decision = ready["decision_raw"]
    decision_sha = transport.sha(raw_decision)
    private = transport.canonical({"schema": "clipforge-db01-containment-input-1", "owner_decision_json": raw_decision.decode("ascii"),
             "owner_decision_sha256": decision_sha, "proposal_json": ready["proposal_raw"].decode("ascii"),
             "journal_sha256": checked["journal_sha256"]})
    require(len(private) <= 65536, "noble_containment_input_bound")
    public = containment.public_payload(ready["operator"], ready["containment"], payloads.GUEST_SHA, payloads.CONTAINMENT_SHA)
    legacy.phase(work, journal, "containment", "started")
    code, raw, _ = processes.invoke_once("containment", port, public, private)
    value = transport.decode(raw)
    expected = {key: checked[key] for key in ("operation_id", "approved_commit", "journal_sha256")}
    expected["owner_decision_sha256"] = decision_sha
    require(isinstance(value, dict) and value["schema"] == "clipforge-db01-containment-receipt-1"
            and value["status"] in {"created_cluster_stopped_preserved", "blocked_before_stop", "stop_outcome_unknown_preserve_and_review"}
            and code == (0 if value["status"] == "created_cluster_stopped_preserved" else 1)
            and all(value.get(k, v) == v for k, v in expected.items()), "noble_containment_receipt_scope_or_exit")
    require(all(value.get(k) is False for k in ("data_reinitialized", "configuration_restored", "restart_attempted", "IAM_or_state_written"))
            and value.get("intent_path") == containment.INTENT.as_posix(), "noble_containment_forbidden_effect")
    operator.validate_receipt({**checked, "native_operations": value["native_operations"]})
    stops = [row for row in value["native_operations"] if row["operation"] == "containment_stop"]
    require(len(stops) <= 1 and (not stops or value["stop_attempted"] is True)
            and (value["stop_attempted"] is False or value["intent_created"] is True and all(value.get(k) == v for k, v in expected.items())),
            "noble_containment_one_stop_or_intent")
    if code == 0:
        require(len(stops) == 1 and stops[0]["exit_code"] == 0 and value["mount_preserved"] is True
                and value["configuration_and_journal_preserved"] is True
                and value["filesystem_uuid"] == checked["filesystem_uuid"], "noble_containment_success_incomplete")
    legacy.phase(work, journal, "containment", "completed", native_exit=code, receipt_sha256=transport.sha(raw))
    return {"status": value["status"], "stop_attempted": value["stop_attempted"], "receipt_sha256": transport.sha(raw)}


def launch(env, ready, work, reports):
    require(not (work / "db01-journal.json").exists() and not (work / "cleanup-journal.json").exists(), "noble_bootstrap_must_not_replay")
    before, client, profile = check_cloud(env, ready)
    raw_token = env["GCP_ACCESS_TOKEN"]
    snapshot = lambda: first.snapshot(lambda url: first.read_compute(url, raw_token), ready["summary"]["candidate"])
    operator = payloads.operator_contract(ready["operator"])
    journal = {"schema": "clipforge-db01-launcher-journal-1", "operation_id": ready["decision"]["operation_id"],
               "approved_commit": env["GITHUB_SHA"], "owner_decision_sha256": transport.sha(ready["decision_raw"]), "phases": []}
    key_journal = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": env["GITHUB_REPOSITORY"],
                   "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"],
                   "public_key": None, "created_us": None, "expiration_us": None, "fingerprint": None,
                   "import_attempted": False, "key_absent_before_import": False, "profile_name": client.profile_name, "processes": []}
    result = {"schema": "clipforge-int-noble-bootstrap-result-1", "operation_id": journal["operation_id"],
              "owner_decision_sha256": journal["owner_decision_sha256"], "status": "blocked", "runtime_authorized": False,
              "migrations_applied": False, "external_client_acceptance": False, "oslogin_profile": profile,
              "noble_iam_receipt_sha256": ready["noble_iam_receipt_sha256"]}
    transport._save_journal(work, key_journal)
    legacy.phase(work, journal, "preflight", "completed")
    processes = None
    previous = {}
    try:
        def interrupted(_signal, _frame):
            raise transport.Blocked("noble_interrupted_requires_reconciliation")

        for number in (signal.SIGTERM, signal.SIGINT):
            previous[number] = signal.signal(number, interrupted)
        values = check_tls(env, work)
        for field in legacy.SECRET_FIELDS.values():
            os.environ.pop(field, None)
        legacy.phase(work, journal, "tls", "completed")
        gcloud = shutil.which("gcloud")
        require(gcloud and Path(gcloud).is_absolute() and Path(gcloud).name == "gcloud", "noble_pinned_sdk_required")

        def record_process(row):
            live = {process.pid for process in processes.owned if process.poll() is None}
            key_journal["processes"] = [item for item in key_journal["processes"] if item["pid"] in live and item["pid"] != row["pid"]] + [row]
            transport._save_journal(work, key_journal)

        public_observer = guest.payload_bytes()
        processes = NobleProcesses(work, gcloud, public_observer, f"clipforge-noble-bootstrap-{env['GITHUB_RUN_ID']}", record_process)
        code, output, _ = processes.run([gcloud, "version", "--format=json"])
        require(code == 0 and transport.decode(output).get("Google Cloud SDK") == "582.0.0", "noble_sdk_version_changed")
        code, _, _ = processes.run(processes.keygen_command())
        private_key = work / "id_ed25519"
        require(code == 0 and not private_key.is_symlink() and private_key.stat().st_mode & 0o777 == 0o600, "noble_ephemeral_key")
        public, _ = first.int_vm_hostkey_guest.public_key(transport._local_bytes(work / "id_ed25519.pub", 1024))
        created = int(time.time() * 1_000_000)
        expiration = created + transport.KEY_TTL_SECONDS * 1_000_000
        token_margin(env, expiration, MAX_OPERATION + CLEANUP_MARGIN)
        client.arm_key(public, expiration)
        client.prepare_import()
        key_journal.update(public_key=public, created_us=created, expiration_us=expiration, import_attempted=True, key_absent_before_import=True)
        transport._save_journal(work, key_journal)
        legacy.phase(work, journal, "key", "started")
        selected = client.import_key()
        key_journal["fingerprint"] = selected["fingerprint"]
        transport._save_journal(work, key_journal)
        legacy.phase(work, journal, "key", "completed")
        with (work / "known_hosts").open("xb") as out:
            os.chmod(work / "known_hosts", 0o400)
            out.write(ready["pin"]["known_hosts_line"].encode("ascii"))
        with socket.socket() as local:
            local.bind(("127.0.0.1", 0))
            port = local.getsockname()[1]
        processes.username = selected["username"]
        processes.start_tunnel(port)
        legacy.phase(work, journal, "observe", "started")
        code, raw, stderr = processes.run(processes.ssh_builder(work, processes.username, port), public_observer,
                                           timeout=180, stdout_limit=guest.MAX_OUTPUT)
        result["observation_ssh"] = {"exit_code": code, **transport.process_diagnostic(stderr)}
        require(code == 0, "noble_fresh_guest_observation_failed")
        linked, fresh = proof(raw, before=before, after=snapshot(), pin=ready["pin"], commit=env["GITHUB_SHA"])
        legacy.same_disk_identity(ready["baseline_proof"], fresh)
        require(linked["guest"]["base_inventory"]["inventory"]["kernel"] == ready["baseline"]["guest"]["base_inventory"]["inventory"]["kernel"],
                "noble_reviewed_kernel_changed")
        legacy.phase(work, journal, "observe", "completed", receipt_sha256=fresh["guest_read_receipt_sha256"])
        check_window(ready["decision"])
        token_margin(env, expiration, MAX_OPERATION + CLEANUP_MARGIN)
        expected = {"operation_id": journal["operation_id"], "approved_commit": env["GITHUB_SHA"],
                    "proposal_sha256": ready["decision"]["proposal_sha256"], "operator_sha256": payloads.GUEST_SHA}
        request = {"schema": "clipforge-db01-bootstrap-input-1", **expected, "confirmation": CONFIRMATION, "disk_proof": fresh,
                   "secrets": values}
        operator.validate_input(request, payloads.GUEST_SHA)
        private_input = transport.canonical(request)
        require(len(private_input) <= 65536, "noble_protected_input_bound")
        legacy.phase(work, journal, "bootstrap", "started")
        code, raw, stderr = processes.invoke_once("bootstrap", port, ready["operator"], private_input)
        result["bootstrap_ssh"] = {"exit_code": code, **transport.process_diagnostic(stderr)}
        receipt = operator.validate_receipt(transport.decode(raw))
        expected.update(disk_id=payloads.DATA, guest_boot_id=fresh["guest_boot_id"], disk_proof_sha256=transport.sha(transport.canonical(fresh)),
                        guest_read_receipt_sha256=fresh["guest_read_receipt_sha256"], guest_read_source_sha256=fresh["guest_read_source_sha256"])
        legacy.checked_guest_result(receipt, code, expected)
        result["guest_receipt"] = receipt
        legacy.phase(work, journal, "bootstrap", "completed", native_exit=code, receipt_sha256=transport.sha(raw))
        require(snapshot() == before, "noble_compute_changed_during_bootstrap")
        result["status"] = receipt["status"]
        if receipt["status"] == "configured_guest_verified_external_acceptance_pending":
            result["ca_certificate_sha256"] = transport.sha(values["ca_cert"].encode("ascii"))
        legacy.phase(work, journal, "postcheck", "completed")
        if receipt["status"] == "partial_preserved":
            try:
                result["containment"] = run_containment(env, ready, processes, port, expiration, receipt, operator, work, journal)
            except BaseException as error:
                result["containment"] = {"status": "stopped_or_unknown_preserve_and_review" if "containment" in processes.invoked else "not_attempted",
                                         "error_code": str(error) if isinstance(error, transport.Blocked) else type(error).__name__}
    except BaseException as error:
        result["status"] = legacy.failure_status(journal)
        result["error_code"] = str(error) if isinstance(error, transport.Blocked) else type(error).__name__
        if isinstance(error, transport.Failure):
            result["failure"] = error.receipt
    finally:
        try:
            if processes is not None:
                processes.close()
        except Exception:
            result["status"] = "unknown_preserve_and_review"
            result["process_cleanup"] = "unconfirmed"
        finally:
            result["cleanup"] = legacy.cleanup(env, work, reports, client=client)
            for number, handler in previous.items():
                signal.signal(number, handler)
        if result["cleanup"]["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"}:
            result["status"] = "unknown_preserve_and_review"
        result["phases"] = journal["phases"]
        with (reports / "db01-result.json").open("xb") as out:
            out.write(transport.canonical(result) + b"\n")
    return result


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("local", "protected-admit", "protected-local", "cloud", "run", "cleanup"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--decision-sha256")
    parser.add_argument("--review-sha256")
    parser.add_argument("--binding-sha256")
    parser.add_argument("--workdir", type=Path)
    parser.add_argument("--reports", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.operation == "cleanup":
            result = legacy.cleanup(env, args.workdir, args.reports)
            return int(result["status"] not in {"own_key_removed", "key_already_absent", "no_registered_key"})
        if args.operation == "protected-admit":
            db_runner.require_secretless_admission(env)
        require(args.bundle is not None, "noble_bundle_required")
        ready = validate_local(env, args.bundle, args.decision_sha256, root=ROOT)
        binding_path = args.bundle / "binding.json"
        exact_local_hash(binding_path, args.binding_sha256)
        exact_local_hash(args.bundle / "review.json", args.review_sha256)
        protected = args.operation != "local"
        if protected:
            expected = {"INT_NOBLE_PROTECTED_DECISION_SHA256": args.decision_sha256,
                        "INT_NOBLE_PROTECTED_REVIEW_SHA256": args.review_sha256,
                        "INT_NOBLE_PROTECTED_BINDING_SHA256": args.binding_sha256,
                        "INT_NOBLE_PROTECTED_GATE_MODE": ready["gate"]}
            require(all(env.get(k) == v for k, v in expected.items()), "noble_independent_protected_input_digest")
        arguments = ["--review", str(args.bundle / "review.json"), "--review-sha256", args.review_sha256,
                     "--binding", str(binding_path), "--operation", "bootstrap"]
        if protected:
            arguments.append("--match-credential-runner")
        require(gate.main(arguments) == 0, "noble_activation_evidence_blocked")
        if args.operation in {"local", "protected-admit"}:
            return 0
        work, reports = transport._validate_paths(env, args.workdir, args.reports)
        if args.operation == "protected-local":
            check_tls(env, work)
            return 0
        if args.operation == "cloud":
            check_cloud(env, ready)
            return 0
        result = launch(env, ready, work, reports)
        print(json.dumps({"status": result["status"], "runtime_authorized": False}))
        return int(result["status"] != "configured_guest_verified_external_acceptance_pending")
    except (transport.Failure, transport.Blocked, ValueError, TypeError, OSError, KeyError, HTTPError) as error:
        code = str(error)
        output = {"status": "blocked", "phase": args.operation, "error_code": code if re.fullmatch(r"[A-Za-z0-9_]{1,120}", code) else type(error).__name__}
        if isinstance(error, transport.Failure):
            output["failure"] = error.receipt
        if isinstance(error, HTTPError):
            output["http_status"] = error.code
            error.close()
        print(json.dumps(output))
        if args.operation in {"cloud", "run"} and args.workdir is not None and args.reports is not None:
            try:
                _, reports = transport._validate_paths(env, args.workdir, args.reports)
                with (reports / "db01-preflight-failure.json").open("xb") as out:
                    out.write(transport.canonical(output) + b"\n")
            except (OSError, ValueError):
                print('{"secondary_error":"noble_preflight_report_unavailable"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
