"""Protected APT/kmod transport for the existing Noble INT guest."""

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import shutil
import signal
import socket
import time
from urllib.error import HTTPError

from scripts import check_int_demo_a as gate
from scripts import int_demo_a_noble_policy as policies
from scripts import int_demo_a_receipts as custody
from scripts import int_guest_inventory as transport
from scripts import int_noble_bootstrap_db as bootstrap
from scripts import int_noble_first_observation as first
from scripts import int_noble_guest_apt as apt
from scripts import int_noble_guest_intervention_backend as backend
from scripts import int_noble_guest_intervention_kmod as kmod
from scripts import int_noble_guest_intervention_kmod_contract as kmod_contract
from scripts import int_noble_guest_intervention_kmod_render as kmod_render
from scripts import int_noble_kernel_observation as handoff


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ".github/workflows/int-db01-noble-intervention.yml"
OPERATION = "guest_intervention"
ACTIONS = {"apt_upgrade", "kmod_apply", "kmod_withdraw"}
INTENT = "noble-intervention-intent.json"
RESULT = "noble-intervention-result.json"
RESULT_SCHEMA = "clipforge-int-noble-intervention-result-1"
KMOD_INVENTORY = "46733606340d570b2fead7e1cab98f611417e433650a354c662bd9c68bc584eb"
READINESS_PAYLOAD = "972eee8c5fe832f07e4b3a2ff529f5cdfd5352141336a2dad34b8bca155bca38"
MAX_WORK = 600
STATE_FILE = "backend.json"
NO_ACTIVE_KEY = {"own_key_removed", "key_already_absent"}
require = transport.require


def now_utc():
    return datetime.now(timezone.utc)


def read(bundle, filename, digest, maximum=65536):
    return bootstrap.exact_local_hash(bundle / filename, digest, maximum)


def validate_local(env, bundle, decision_sha256, review_sha256, binding_sha256, *, protected=False, now=None):
    from scripts import int_demo_a_preflight as preflight

    # Preserve the shared closed owner-decision format while passing the exact intervention to its checker.
    decision_raw = read(bundle, "decision.json", decision_sha256)
    decision = transport.decode(decision_raw)
    inputs = decision["inputs"]
    action = inputs["action"]
    require(action in ACTIONS and set(inputs) == {"action", "payload_sha256", "deploy_policy_receipt_sha256",
                    "policy_config_sha256", "previous_kmod", "snapshot_sha256", "readiness_sha256", "consumer_inventory_sha256"},
            "intervention_closed_inputs")
    require(decision["review_sha256"] == review_sha256 and decision["binding_sha256"] == binding_sha256,
            "intervention_review_or_binding_digest")
    require(preflight.local_decision(bundle, decision_sha256, OPERATION, WORKFLOW, env, protected=protected, now=now,
                                     guest_action=action) == decision, "intervention_owner_decision_drift")
    binding = transport.decode(read(bundle, "binding.json", binding_sha256))
    require(binding["state_generation"] == backend.scope.STATE["generation"], "intervention_review_backend_generation")
    if protected:
        require(env.get("INT_NOBLE_INTERVENTION_REVIEW_SHA256") == review_sha256
                and env.get("INT_NOBLE_INTERVENTION_BINDING_SHA256") == binding_sha256 and env.get("ImageVersion"),
                "intervention_independent_protected_review")
        review = transport.decode(read(bundle, "review.json", review_sha256, gate.MAX_RECORD))
        gate.verify_review(bundle, review, binding, now or now_utc(), runner_version=env["ImageVersion"], guest_action=action)
    require((inputs["readiness_sha256"], inputs["consumer_inventory_sha256"]) == (apt.READINESS, KMOD_INVENTORY),
            "intervention_exact_observation_inputs")
    summary_raw, pin_raw = read(bundle, "summary.json", handoff.SUMMARY_SHA), read(bundle, "host-pin.json", handoff.PIN_SHA)
    summary, pin = handoff.checked_inputs(summary_raw, pin_raw)
    snapshot = pin["control_plane"]
    require(kmod.object_sha(snapshot) == inputs["snapshot_sha256"], "intervention_snapshot_sha256")
    readiness = transport.decode(read(bundle, "apt-readiness.json", inputs["readiness_sha256"]))
    consumers = transport.decode(read(bundle, "kernel-consumers.json", inputs["consumer_inventory_sha256"]))
    require(readiness["payload_sha256"] == READINESS_PAYLOAD and readiness["control_plane"] == snapshot
            and readiness["risk_accepted"] is False and readiness["runtime_authorized"] is False,
            "intervention_readiness_snapshot")
    inspected = handoff.check_guest(transport.canonical(readiness["guest"]), 0, pin["record"]["guest_boot_id"], handoff.DEMO_SCOPE)
    require(inspected["release"] == apt.RELEASE and inspected["package"]["installed"] == apt.apt_checks.CURRENT
            and inspected["exports"]["active_count"] == 0 and inspected["exports"]["host_mount_namespace"] is True,
            "intervention_readiness_apt_or_nfs_scope")
    kmod.verify_unmitigated(kmod.checked_baseline(consumers, inputs["snapshot_sha256"]))
    require((action == "kmod_withdraw") == isinstance(inputs["previous_kmod"], dict)
            and (action == "kmod_withdraw" or inputs["previous_kmod"] is None), "intervention_previous_kmod_scope")
    executable = apt.build_payload(ROOT / "scripts") if action == "apt_upgrade" else kmod_render.payload_bytes(ROOT / "scripts")
    require(transport.sha(executable) == inputs["payload_sha256"], "intervention_exact_payload")
    config = transport.decode(bootstrap.exact_local_hash(ROOT / policies.CONFIG, inputs["policy_config_sha256"], 65536))
    policy_raw = read(bundle, "deploy-policy-receipt.json", inputs["deploy_policy_receipt_sha256"])
    transition = transport.decode(policy_raw)
    require(policy_raw == transport.canonical(transition), "intervention_deploy_policy_receipt_canonical")
    return {"decision": decision, "decision_raw": decision_raw, "summary": summary, "pin": pin,
            "summary_raw": summary_raw, "pin_raw": pin_raw, "gate": decision["gate_mode"], "snapshot": snapshot,
            "consumers": consumers, "deploy_policy": policies.expected_policy(config, transition), "executable": executable}


def packet(ready, previous=None):
    chosen = ready["decision"]
    inputs = chosen["inputs"]
    digest = transport.sha(ready["decision_raw"])
    operation_id = "int-noble-" + chosen["operation_id"]
    if inputs["action"] == "apt_upgrade":
        request = {"schema": apt.INPUT, "operation": "upgrade_reviewed_linux_tools_common_once", "operation_id": operation_id,
                   "instance_id": apt.INSTANCE, "boot_disk_id": apt.BOOT_DISK, "data_disk_id": apt.DATA_DISK,
                   "boot_id": apt.GUEST_BOOT, "readiness_sha256": apt.READINESS, "operator_sha256": inputs["payload_sha256"],
                   "signed_index_sha256": apt.SIGNED_INDEX, "package_sha256": apt.DIGEST, "owner_decision_sha256": digest,
                   "approved_commit": chosen["control_commit"]}
        raw = apt.canonical(request)
        apt.request(raw, inputs["payload_sha256"])
        return raw, request
    if inputs["action"] == "kmod_withdraw":
        require(previous["schema"] == RESULT_SCHEMA and previous["status"] == "completed_verified"
                and previous["action"] == "kmod_apply" and previous["snapshot_sha256"] == inputs["snapshot_sha256"]
                and previous["control_plane"] == ready["snapshot"] and previous["cleanup"]["status"] in NO_ACTIVE_KEY
                and previous["guest_receipt"]["status"] == "applied_verified" and previous["native_exit"] == 0,
                "intervention_withdraw_requires_verified_apply")
        evidence = previous["guest_receipt"]
    else:
        evidence = ready["consumers"]
    authority = {"schema": kmod.AUTHORIZATION, **kmod.IDENTITY, "operation_id": operation_id,
                 "operation": "apply" if inputs["action"] == "kmod_apply" else "withdraw", "approved_commit": chosen["control_commit"],
                 "snapshot_sha256": inputs["snapshot_sha256"], "expires_utc": chosen["expires_utc"], "pin_sha256": handoff.PIN_SHA,
                 "payload_sha256": inputs["payload_sha256"], "rule_sha256": kmod.RULE_SHA256, "evidence_sha256": kmod.object_sha(evidence)}
    value = {"schema": kmod.INPUT, "authority": authority, "authority_sha256": kmod.object_sha(authority), "evidence": evidence}
    raw = kmod.canonical(value)
    kmod_contract.admit(raw, ready["executable"], protected_authority_sha256=value["authority_sha256"],
                        protected_payload_sha256=inputs["payload_sha256"], controls_commit=chosen["control_commit"],
                        handoff=ready["summary_raw"], pin_bytes=ready["pin_raw"], snapshot=ready["snapshot"])
    return raw, value


def check_success(raw, exit_code, before, after, ready, request):
    require(exit_code == 0 and before == after == ready["snapshot"], "intervention_native_exit_or_snapshot")
    if ready["decision"]["inputs"]["action"] != "apt_upgrade":
        return kmod_contract.accept_success(raw, exit_code, before, after, request["authority"], request["authority_sha256"])
    receipt = kmod.decode(raw)
    fixed = {"schema": "clipforge-int-noble-apt-receipt-1", "status": "updated_exact_package", "launch_intent": True,
             "operation_id": request["operation_id"], "approved_commit": request["approved_commit"],
             "owner_decision_sha256": request["owner_decision_sha256"], "request_sha256": transport.sha(apt.canonical(request)),
             "instance_id": apt.INSTANCE, "boot_disk_id": apt.BOOT_DISK, "data_disk_id": apt.DATA_DISK, "boot_id": apt.GUEST_BOOT,
             "kernel": apt.RELEASE, "package": apt.apt_checks.PACKAGE, "package_sha256": apt.DIGEST,
             "signed_index_sha256": apt.SIGNED_INDEX, "download_verified": True, "temp_released": True}
    require(set(receipt) == set(fixed) | {"simulation", "install", "postcheck", "intent_sha256"}
            and all(receipt[key] == value for key, value in fixed.items()), "intervention_apt_receipt_fields")
    apt.apt_checks.check_upgrade(receipt["simulation"], apt.apt_checks.CURRENT)
    install, post = receipt["install"], receipt["postcheck"]
    require(install.get("tool") == "dpkg", "intervention_apt_install_tool")
    apt.apt_checks.check_diagnostic({key: value for key, value in install.items() if key != "tool"}, apt.INSTALL_ERRORS)
    hash_rest = post["other_package_states_sha256"]
    intent = {"schema": "clipforge-int-noble-apt-intent-1", **{name: receipt[name] for name in
              ("request_sha256", "approved_commit", "owner_decision_sha256", "simulation", "operation_id", "package_sha256", "boot_id")},
              "other_package_states_sha256": hash_rest}
    require(receipt["intent_sha256"] == transport.sha(apt.canonical(intent) + b"\n") and kmod.HEX.fullmatch(hash_rest)
            and receipt["simulation"]["exact_upgrade"] is True and install["exit"] == 0
            and post == {"installed": apt.apt_checks.TARGET, "other_package_states_equal": True, "other_package_states_sha256": hash_rest,
                         "dpkg_clean": True, "same_boot_and_kernel": True}, "intervention_apt_postcheck")
    return receipt


class InterventionProcesses(transport.ProcessRunner):
    def invoke(self, port, executable, payload_sha256, private):
        require(not getattr(self, "intervention_attempted", False) and 0 < len(private) <= 65536, "intervention_process_already_used")
        loader = kmod_contract.command(executable, payload_sha256)
        require(len(loader) < 131072, "intervention_transport_argument_bound")
        original_builder, original_payload = self.ssh_builder, self.payload

        def exact_command(work, username, actual_port):
            require(actual_port == port, "intervention_transport_port_changed")
            return [*original_builder(work, username, actual_port)[:-1], loader]

        self.intervention_attempted = True
        try:
            self.ssh_builder, self.payload = exact_command, private
            return self.run(exact_command(self.work, self.username, port), private, timeout=MAX_WORK, stdout_limit=65536)
        finally:
            self.ssh_builder, self.payload = original_builder, original_payload


def start_channel(env, work, journal, make_processes):
    gcloud = shutil.which("gcloud")
    require(gcloud and Path(gcloud).is_absolute() and Path(gcloud).name == "gcloud", "intervention_pinned_sdk_required")
    public_observer = bootstrap.guest.payload_bytes()
    processes = None

    def record(row):
        live = {process.pid for process in processes.owned if process.poll() is None}
        journal["processes"] = [item for item in journal["processes"] if item["pid"] in live and item["pid"] != row["pid"]] + [row]
        transport._save_journal(work, journal)

    processes = make_processes(work, gcloud, public_observer, f"clipforge-noble-intervention-{env['GITHUB_RUN_ID']}-1", record,
                               maximum_process_seconds=MAX_WORK, ssh_builder=first.ssh_builder(apt.INSTANCE), tunnel_builder=first.noble_tunnel)
    return processes


def open_channel(env, work, ready, client, journal, processes):
    code, output, _ = processes.run([processes.gcloud, "version", "--format=json"])
    require(code == 0 and transport.decode(output).get("Google Cloud SDK") == "582.0.0", "intervention_sdk_changed")
    code, _, _ = processes.run(processes.keygen_command())
    private_key = work / "id_ed25519"
    require(code == 0 and not private_key.is_symlink() and private_key.stat().st_mode & 0o777 == 0o600, "intervention_ephemeral_key")
    public, _ = first.int_vm_hostkey_guest.public_key(transport._local_bytes(work / "id_ed25519.pub", 1024))
    created = int(time.time() * 1_000_000)
    expiration = created + transport.KEY_TTL_SECONDS * 1_000_000
    bootstrap.token_margin(env, expiration, MAX_WORK + bootstrap.CLEANUP_MARGIN)
    client.arm_key(public, expiration)
    client.prepare_import()
    journal.update(public_key=public, created_us=created, expiration_us=expiration, import_attempted=True, key_absent_before_import=True)
    transport._save_journal(work, journal)
    selected = client.import_key()
    journal["fingerprint"] = selected["fingerprint"]
    transport._save_journal(work, journal)
    with (work / "known_hosts").open("xb") as output:
        os.chmod(output.fileno(), 0o400)
        output.write(ready["pin"]["known_hosts_line"].encode("ascii"))
    with socket.socket() as local:
        local.bind(("127.0.0.1", 0))
        port = local.getsockname()[1]
    processes.username = selected["username"]
    processes.start_tunnel(port)
    return port, expiration


def safe_error(error):
    label = str(error)
    result = {"error_code": label if re.fullmatch(r"[A-Za-z0-9_]{1,120}", label) else type(error).__name__}
    if isinstance(error, transport.Failure):
        result["failure"] = error.receipt
    if isinstance(error, HTTPError):
        result["http_status"] = error.code
        error.close()
    return result


def launch(env, ready, proof, work, reports, *, reader=first.read_compute, make_processes=InterventionProcesses,
           check_cloud=bootstrap.check_cloud, make_custody=custody.Custody):
    require(not os.path.lexists(work / "cleanup-journal.json"), "intervention_run_cannot_replay")
    decision, raw = ready["decision"], ready["decision_raw"]
    inputs = decision["inputs"]
    action, digest = inputs["action"], transport.sha(raw)
    expected = backend.binding(env, decision, digest)
    token = env["GCP_ACCESS_TOKEN"]
    require(not env.get("GCP_TERRAFORM_SA"), "intervention_deploy_must_not_receive_terraform_identity")
    checked_env = {**env, "INT_NOBLE_PROTECTED_DECISION_SHA256": env["INT_DEMO_A_PROTECTED_DECISION_SHA256"]}
    before, client, _ = check_cloud(checked_env, ready, reader=reader)
    snapshot = lambda: first.snapshot(lambda route: reader(route, token), ready["summary"]["candidate"])
    names = custody.producer_names(env, OPERATION, decision["operation_id"])
    cloud = make_custody(token, names=names.values())
    result = {"schema": RESULT_SCHEMA, "status": "blocked_before_intent", "action": action, "operation_id": decision["operation_id"],
              "control_commit": env["GITHUB_SHA"], "decision_sha256": digest, "snapshot_sha256": inputs["snapshot_sha256"],
              "control_plane": before, "runtime_authorized": False, "backend_observation_sha256": kmod.object_sha(proof)}
    journal = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": env["GITHUB_REPOSITORY"],
               "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"],
               "public_key": None, "created_us": None, "expiration_us": None, "fingerprint": None,
               "import_attempted": False, "key_absent_before_import": False, "profile_name": client.profile_name, "processes": []}
    transport._save_journal(work, journal)
    processes, signals, requested, native = None, {}, False, None
    try:
        def interrupted(_signum, _frame):
            raise transport.Blocked("intervention_interrupted_reconcile")

        for number in (signal.SIGTERM, signal.SIGINT):
            signals[number] = signal.signal(number, interrupted)
        previous = None
        if action == "kmod_withdraw":
            reference = inputs["previous_kmod"]
            require(re.fullmatch(re.escape(custody.PREFIX) + r"[a-f0-9]{40}/[1-9][0-9]*-1/" + re.escape(RESULT), reference["name"]),
                    "intervention_previous_receipt_scope")
            previous = kmod.decode(make_custody(token).fetch(reference))
        private, request = packet(ready, previous)
        bootstrap.check_window(decision, minimum=MAX_WORK + bootstrap.CLEANUP_MARGIN)
        require(before == ready["snapshot"] == snapshot(), "intervention_pre_snapshot_drift")
        backend.verify(proof, expected, now=now_utc())
        result["status"] = "intent_outcome_unknown_reconcile"
        result["intent"] = cloud.create(names[INTENT], {**result, "status": "intended_once", "request_sha256": transport.sha(private),
                                                       "payload_sha256": inputs["payload_sha256"]})
        result["status"] = "blocked_after_intent_before_guest"
        processes = start_channel(env, work, journal, make_processes)
        port, expiration = open_channel(env, work, ready, client, journal, processes)
        argv = processes.ssh_builder(work, processes.username, port)
        code, observed, stderr = processes.run(argv, processes.payload, timeout=180, stdout_limit=bootstrap.guest.MAX_OUTPUT)
        result["observation_ssh"] = {"exit_code": code, **transport.process_diagnostic(stderr)}
        require(code == 0, "intervention_fresh_ssh_read_failed")
        linked, fresh = bootstrap.proof(observed, before=before, after=snapshot(), pin=ready["pin"], commit=env["GITHUB_SHA"])
        result["precheck_sha256"] = kmod.object_sha(linked)
        require(fresh["guest_boot_id"] == apt.GUEST_BOOT and fresh["disk_id"] == apt.DATA_DISK, "intervention_guest_disk_or_boot_mismatch")
        bootstrap.check_window(decision, minimum=MAX_WORK + bootstrap.CLEANUP_MARGIN)
        bootstrap.token_margin(env, expiration, MAX_WORK + bootstrap.CLEANUP_MARGIN)
        backend.verify(proof, expected, now=now_utc())
        requested = True
        result["status"] = "guest_outcome_unknown_reconcile"
        code, observed, stderr = processes.invoke(port, ready["executable"], inputs["payload_sha256"], private)
        native = (code, observed, request)
        result.update(native_exit=code, guest_stdout_sha256=transport.sha(observed), guest_ssh=transport.process_diagnostic(stderr))
        if code != 0:
            try:
                rejected = kmod.decode(observed)
                label = rejected.get("error", "")
                if re.fullmatch(r"[A-Za-z0-9_]{1,120}", label):
                    result["guest_error_code"] = label
            except (ValueError, TypeError, UnicodeError):
                pass
            raise transport.Blocked("intervention_native_failure_requires_reconciliation")
    except Exception as error:
        result.update(safe_error(error))
    finally:
        if requested:
            try:
                after = snapshot()
                result["post_snapshot_unchanged"] = after == before
                require(result["post_snapshot_unchanged"], "intervention_post_snapshot_drift")
            except Exception as error:
                result["post_snapshot_error"] = safe_error(error)
                result["status"] = "guest_outcome_unknown_reconcile"
            else:
                if native is not None and native[0] == 0 and "error_code" not in result:
                    try:
                        result["guest_receipt"] = check_success(native[1], native[0], before, after, ready, native[2])
                        result["status"] = "guest_verified_cleanup_pending"
                    except Exception as error:
                        result.update(safe_error(error))
        try:
            if processes is not None:
                processes.close()
        except Exception as error:
            result["process_cleanup_error"] = safe_error(error)
            result["status"] = "guest_outcome_unknown_reconcile"
        try:
            result["cleanup"] = transport.cleanup(environ=env, workdir=work, reports=reports, client=client)
        except Exception as error:
            result["cleanup"] = {"status": "cleanup_unconfirmed_TTL_pending", **safe_error(error)}
        if result["status"] == "guest_verified_cleanup_pending":
            result["status"] = "completed_verified" if result["cleanup"]["status"] in NO_ACTIVE_KEY else "cleanup_unconfirmed_reconcile"
        for number, handler in signals.items():
            signal.signal(number, handler)
        try:
            result["result_reference"] = cloud.create(names[RESULT], result)
        except Exception as error:
            result["custody_error"] = safe_error(error)
            if result["status"] == "completed_verified":
                result["status"] = "result_custody_indeterminate_reconcile"
        try:
            with (reports / "intervention-result.json").open("xb") as output:
                output.write(transport.canonical(result) + b"\n")
        except OSError as error:
            result["local_report_error"] = safe_error(error)
            if result["status"] == "completed_verified":
                result["status"] = "local_report_failure_reconcile"
    return result


def backend_receipt_path(path, env):
    runner = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    require(path is not None and path.name == STATE_FILE and path.parent.parent == runner
            and path.parent.resolve() == path.parent and path.parent.is_dir()
            and re.fullmatch(r"clipforge-noble-backend\.[A-Za-z0-9]{8}", path.parent.name), "intervention_backend_receipt_path")
    return path


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "protected-local", "observe-backend", "run", "cleanup"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--decision-sha256")
    parser.add_argument("--review-sha256")
    parser.add_argument("--binding-sha256")
    parser.add_argument("--backend-observation", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase == "cleanup":
            result = transport.cleanup(environ=env, workdir=env["GUEST_WORK"], reports=env["GUEST_REPORTS"])
            return int(result["status"] not in NO_ACTIVE_KEY | {"no_registered_key"})
        ready = validate_local(env, args.bundle, args.decision_sha256, args.review_sha256, args.binding_sha256,
                               protected=args.phase != "local")
        if args.phase in {"local", "protected-local"}:
            if args.backend_observation is not None:
                require(args.phase == "protected-local", "intervention_backend_proof_protected_only")
                path = backend_receipt_path(args.backend_observation, env)
                expected = backend.binding(env, ready["decision"], args.decision_sha256)
                backend.verify(transport.decode(transport._local_bytes(path, 65536)), expected, now=now_utc())
            print('{"status":"preflight_verified","runtime_authorized":false}')
            return 0
        path = backend_receipt_path(args.backend_observation, env)
        expected = backend.binding(env, ready["decision"], args.decision_sha256)
        if args.phase == "observe-backend":
            proof = backend.observe_for_run(env, expected)
            with path.open("xb") as output:
                output.write(transport.canonical(proof) + b"\n")
            print('{"status":"backend_metadata_verified","lock_acquired":false}')
            return 0
        proof = transport.decode(transport._local_bytes(path, 65536))
        backend.verify(proof, expected, now=now_utc())
        work, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
        result = launch(env, ready, proof, work, reports)
        print(json.dumps({key: result[key] for key in ("status", "error_code", "native_exit", "runtime_authorized") if key in result}))
        return int(result["status"] != "completed_verified")
    except (ValueError, TypeError, AttributeError, KeyError, OSError, HTTPError, transport.Failure) as error:
        report = {"status": "blocked", "phase": args.phase, **safe_error(error), "runtime_authorized": False}
        print(json.dumps(report))
        if args.phase == "run" and "GUEST_REPORTS" in env:
            try:
                _, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
                with (reports / "intervention-failure.json").open("xb") as output:
                    output.write(transport.canonical(report) + b"\n")
            except (ValueError, OSError):
                print('{"secondary_error":"intervention_failure_report_unavailable"}')
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
