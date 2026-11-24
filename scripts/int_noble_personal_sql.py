"""Run one separately approved personal SQL action over the existing INT Deploy channel."""

import argparse
import json
import os
from pathlib import Path
import re
import signal
from urllib.error import HTTPError

from scripts import check_int_demo_a as gate
from scripts import int_db01_noble_jobs as jobs
from scripts import int_demo_a_noble_policy as policies
from scripts import int_demo_a_preflight as preflight
from scripts import int_demo_a_receipts as custody
from scripts import int_guest_inventory as transport
from scripts import int_noble_bootstrap_db as bootstrap
from scripts import int_noble_first_observation as first
from scripts import int_noble_guest_intervention as channel
from scripts import int_noble_guest_intervention_backend as backend
from scripts import int_noble_kernel_observation as handoff
from scripts import int_noble_personal_sql_contract as contract
from scripts import int_noble_personal_sql_guest as guest
from scripts import int_release as plans


OPERATION = "personal_sql_intervention"
INTENT = "personal-sql-intent.json"
RESULT = "personal-sql-result.json"
SCHEMA = contract.RESULT
MARGIN = channel.MAX_WORK + bootstrap.CLEANUP_MARGIN
NO_ACTIVE_KEY = channel.NO_ACTIVE_KEY
require = transport.require


def exact_reference(ref, name):
    require(isinstance(ref, dict) and set(ref) == {"name", "generation", "size", "sha256"}
            and re.fullmatch(name, ref["name"]) and jobs.number(ref["generation"])
            and type(ref["size"]) is int and 0 < ref["size"] <= contract.MAX_RECEIPT
            and jobs.hex_id(ref["sha256"]), "personal_native_receipt_reference")
    return ref


def receipt_references(refs, action):
    require(isinstance(refs, dict) and "tls" not in refs, "personal_native_receipt_set")
    contract.predecessor_names(action, set(refs) | {"tls"})
    prefix = re.escape(custody.PREFIX)
    run_scope = prefix + r"[a-f0-9]{40}/[1-9][0-9]*-1/"
    expressions = {"bootstrap": run_scope + r"noble-bootstrap\.json",
                   "apply": re.escape(plans.PREFIX) + r"[a-f0-9]{40}/[1-9][0-9]*-1/manifest\.json",
                   "activation": run_scope + re.escape(RESULT),
                   "activation_intent": prefix + r"[a-f0-9]{40}/decisions/[a-f0-9]{32}/" + re.escape(INTENT),
                   "activation_partial": run_scope + re.escape(RESULT),
                   "activation_observation": run_scope + re.escape(RESULT),
                   **{phase: re.escape(custody.job_names(phase, "run")["result"]) for phase in contract.JOBS}}
    return {key: exact_reference(ref, expressions[key]) for key, ref in sorted(refs.items())}


def validate_local(env, bundle, decision_sha, review_sha, binding_sha, *, protected, now=None):
    now = now or channel.now_utc()
    raw = channel.read(bundle, "decision.json", decision_sha)
    decision = transport.decode(raw)
    inputs = decision["inputs"]
    fields = {"action", "authority_sha256", "snapshot_sha256", "payload_sha256", "tls_sha256", "phase_two_state_size",
              "receipt_references", "deploy_policy_receipt_sha256", "policy_config_sha256"}
    action = inputs["action"]
    if action == "revoke":
        fields.add("activation_marker")
    require(set(inputs) == fields and action in guest.MODES and env.get("INT_NOBLE_OPERATION") == "personal_" + action,
            "personal_exact_dispatch_action")
    require(decision["review_sha256"] == review_sha and decision["binding_sha256"] == binding_sha,
            "personal_dispatch_review_or_binding")
    require(preflight.local_decision(bundle, decision_sha, OPERATION, channel.WORKFLOW, env,
                                     protected=protected, now=now) == decision, "personal_owner_decision_drift")
    binding = transport.decode(channel.read(bundle, "binding.json", binding_sha))
    if protected:
        require(env.get("INT_NOBLE_INTERVENTION_REVIEW_SHA256") == review_sha
                and env.get("INT_NOBLE_INTERVENTION_BINDING_SHA256") == binding_sha
                and env.get("ImageOS") == "ubuntu24" and env.get("ImageVersion"), "personal_independent_protected_review")
        review = transport.decode(channel.read(bundle, "review.json", review_sha, gate.MAX_RECORD))
        gate.verify_review(bundle, review, binding, now, runner_version=env["ImageVersion"])
    summary, pin = handoff.checked_inputs(channel.read(bundle, "summary.json", handoff.SUMMARY_SHA),
                                         channel.read(bundle, "host-pin.json", handoff.PIN_SHA))
    snapshot = {**pin["control_plane"], "guest_boot_id": pin["record"]["guest_boot_id"]}
    require(contract.digest(guest.canonical(snapshot)) == inputs["snapshot_sha256"], "personal_pinned_snapshot")
    refs = receipt_references(inputs["receipt_references"], action)
    expected_state = {"name": contract.STATE, "generation": binding["post_apply_generation"], "size": inputs["phase_two_state_size"]}
    require(jobs.number(expected_state["generation"]) and type(expected_state["size"]) is int and expected_state["size"] > 0,
            "personal_reviewed_phase_two_state")
    tls_raw = channel.read(bundle, "tls.json", inputs["tls_sha256"])
    tls = guest.decode(tls_raw)
    require(tls["status"] == "verified" and tls["mode"] == "verify-full" and tls["host"] == "10.80.1.3"
            and jobs.hex_id(tls["public_ca_sha256"]) and tls["bootstrap_receipt_sha256"] == refs["bootstrap"]["sha256"],
            "personal_reviewed_tls_provenance")
    authority = channel.read(bundle, "personal-authority.json", inputs["authority_sha256"])
    executable = contract.payload()
    selected = contract.check_authority(authority, inputs["authority_sha256"], executable, env["GITHUB_SHA"], now)
    require(selected["action"] == action and selected["operation_id"] == decision["operation_id"]
            and (selected["valid_from"], selected["expires"]) == (decision["issued_utc"], decision["expires_utc"])
            and selected["snapshot_sha256"] == inputs["snapshot_sha256"] and selected["payload_sha256"] == inputs["payload_sha256"]
            and selected["evidence"] == {**{key: ref["sha256"] for key, ref in refs.items()}, "tls": inputs["tls_sha256"]},
            "personal_authority_not_independently_bound")
    scope = {
        "boot_id": snapshot["guest_boot_id"], "state_generation": expected_state["generation"],
        "public_ca_sha256": tls["public_ca_sha256"], "prior_evidence_sha256": contract.digest(guest.canonical(selected["evidence"]))}
    if action == "revoke":
        scope["activation_marker"] = inputs["activation_marker"]
    request = contract.request_bytes(selected, inputs["authority_sha256"], scope)
    config = transport.decode(bootstrap.exact_local_hash(channel.ROOT / policies.CONFIG, inputs["policy_config_sha256"], 65536))
    policy = channel.read(bundle, "deploy-policy-receipt.json", inputs["deploy_policy_receipt_sha256"])
    native_policy = transport.decode(policy)
    require(policy == transport.canonical(native_policy), "personal_deploy_policy_receipt_canonical")
    return {"decision": decision, "decision_raw": raw, "summary": summary, "pin": pin, "snapshot": snapshot,
            "gate": decision["gate_mode"], "request": request, "tls": tls_raw, "state": expected_state,
            "review_binding": binding, "references": refs, "authority": authority,
            "executable": executable, "deploy_policy": policies.expected_policy(config, native_policy)}


def live_state(metadata):
    return {"name": metadata["name"], "generation": metadata["generation"], "current_lock_absent": True}


def backend_binding(env, ready, decision_sha, phase):
    return {**backend.binding(env, ready["decision"], decision_sha), "state": ready["state"], "observation_phase": phase}


def validate_apply(raw, ready):
    ref = ready["references"]["apply"]
    apply = transport.decode(raw)
    state = apply["state_after"]
    binding = ready["review_binding"]
    require(len(raw) == ref["size"] and transport.sha(raw) == ref["sha256"]
            and apply["schema"] == "clipforge-int-demo-a-result-2" and apply["phase"] == "apply"
            and apply["status"] == "applied_verified" and apply["deployment_phase"] == "human_access"
            and jobs.apply_reference(ref, apply["controls_commit"]) == apply["run"]
            and (binding["state_generation"], binding["post_apply_generation"], binding["plan_sha256"])
            == (apply["state_before_generation"], state["generation"], apply["plan_sha256"])
            and {key: state[key] for key in ready["state"]} == ready["state"], "personal_phase_two_review_reconciliation")


def native_readbacks(ready, cloud, apply, env, proof):
    validate_apply(apply, ready)
    artifacts = {"apply": apply, "tls": ready["tls"],
                 **{key: cloud.fetch(ref) for key, ref in ready["references"].items() if key != "apply"}}
    jobs.bootstrap_receipt(transport.decode(artifacts["bootstrap"]))
    request, recovery = contract.admission_details(
        ready["authority"], ready["decision"]["inputs"]["authority_sha256"], ready["executable"], artifacts,
        ready["snapshot"], live_state(proof["state"]), env["GITHUB_SHA"], channel.now_utc(), references=ready["references"])
    require(request == ready["request"], "personal_custody_native_bytes")
    return recovery


def activation_origin(env, journal, decision_sha):
    require(journal["import_attempted"] is True and journal["key_absent_before_import"] is True
            and re.fullmatch(r"[A-Za-z0-9_:+/=-]{16,128}", journal["fingerprint"]), "personal_original_key_not_confirmed")
    identity = transport.validate_deploy_profile({"name": journal["profile_name"]})
    return contract.activation_origin({
        "run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "decision_sha256": decision_sha,
        "key": {"public_key_sha256": transport.sha(journal["public_key"].encode("ascii")),
                "fingerprint_sha256": transport.sha(journal["fingerprint"].encode("ascii")),
                "profile_name_sha256": identity["profile_name_sha256"],
                "created_us": journal["created_us"], "expiration_us": journal["expiration_us"]},
    })


def verify_original_key_withdrawal(client, original):
    profile = client.profile()
    identity = transport.validate_deploy_profile(profile)
    require(identity["profile_name_sha256"] == original["profile_name_sha256"], "personal_original_deploy_profile_changed")
    for fingerprint, row in profile.get("sshPublicKeys", {}).items():
        canonical_key = " ".join(str(row["key"]).split()[:2])
        require(transport.sha(canonical_key.encode("utf-8")) != original["public_key_sha256"]
                and transport.sha(fingerprint.encode("ascii")) != original["fingerprint_sha256"]
                and transport.sha(str(row.get("fingerprint", fingerprint)).encode("utf-8")) != original["fingerprint_sha256"],
                "personal_original_key_still_present")
    return {**original, "status": contract.ABSENT}


def write_private(path, value):
    with path.open("xb") as stream:
        stream.write(transport.canonical(value))


def record_result(report, cloud, names, reports):
    try:
        report["result_reference"] = cloud.create(names[RESULT], report)
    except (ValueError, TypeError, OSError, HTTPError) as error:
        report["custody_error"] = channel.safe_error(error)
        if report["status"] in {"completed_verified", contract.RECOVERED}:
            report["status"] = "result_custody_indeterminate_reconcile"
    write_private(reports / "personal-sql-result.json", public_report(report))
    return report


def public_report(report):
    return {key: report[key] for key in ("schema", "status", "action", "error_code", "retry_authorized",
                                         "cleanup_status", "sql_started") if key in report}


def launch(env, ready, proof, binding, work, reports, *, apply, password=None, reader=first.read_compute,
           check_cloud=bootstrap.check_cloud, make_custody=custody.Custody,
           start_channel=channel.start_channel, open_channel=channel.open_channel, clean=transport.cleanup):
    require(not os.path.lexists(work / "cleanup-journal.json") and not env.get("GCP_TERRAFORM_SA"), "personal_run_or_identity_changed")
    request = guest.decode(ready["request"])
    action = request["action"]
    require((action == "activate") == (password is not None), "personal_protected_password_scope")
    if action == "activate":
        require(re.fullmatch(r"[A-Za-z0-9_-]{32,128}", password), "personal_password_format")
    token = env["GCP_ACCESS_TOKEN"]
    names = custody.producer_names(env, OPERATION, request["operation_id"])
    cloud = make_custody(token, names=names.values())
    checked_env = {**env, "INT_NOBLE_PROTECTED_DECISION_SHA256": env["INT_DEMO_A_PROTECTED_DECISION_SHA256"]}
    before, client, _ = check_cloud(checked_env, ready, reader=reader)
    recovery = native_readbacks(ready, make_custody(token), apply, env, proof)
    read_snapshot = lambda: first.snapshot(lambda route: reader(route, token), ready["summary"]["candidate"])
    require({**before, "guest_boot_id": request["boot_id"]} == ready["snapshot"], "personal_initial_target_changed")
    backend.verify(proof, binding, now=channel.now_utc())
    bootstrap.check_window(ready["decision"], minimum=MARGIN)
    if recovery is not None:
        require(recovery["origin"]["run"] != env["GITHUB_RUN_ID"]
                and recovery["operation_id"] != request["operation_id"], "personal_reconciliation_reused_origin")
        if recovery["partial"] is None:
            name = recovery["original_result_name"]
            make_custody(token, names=(name,)).require_absent(name)
        verify_original_key_withdrawal(client, recovery["origin"]["key"])
    journal = {"schema": "clipforge-int-guest-cleanup-journal-1", "repository": env["GITHUB_REPOSITORY"],
               "run_id": env["GITHUB_RUN_ID"], "run_attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"],
               "public_key": None, "created_us": None, "expiration_us": None, "fingerprint": None,
               "import_attempted": False, "key_absent_before_import": False, "profile_name": client.profile_name, "processes": []}
    transport._save_journal(work, journal)
    report = {"schema": SCHEMA, "status": "blocked_before_guest", "action": action, "operation_id": request["operation_id"],
              "run": env["GITHUB_RUN_ID"], "decision_sha256": transport.sha(ready["decision_raw"]),
              "request_sha256": contract.digest(ready["request"]), "control_commit": env["GITHUB_SHA"], "retry_authorized": False,
              "prior_backend_sha256": contract.digest(transport.canonical(proof)), "sql_started": False}
    processes, handlers, outcome, after = None, {}, None, None
    try:
        def interrupted(_number, _frame):
            raise transport.Blocked("personal_signal_reconcile")

        for number in (signal.SIGTERM, signal.SIGINT):
            handlers[number] = signal.signal(number, interrupted)
        processes = start_channel(env, work, journal, channel.InterventionProcesses)
        port, expiration = open_channel(env, work, ready, client, journal, processes)
        origin = activation_origin(env, journal, report["decision_sha256"]) if action == "activate" else None

        def ready_for_sql():
            require(read_snapshot() == before, "personal_pre_sql_target_changed")
            backend.verify(proof, binding, now=channel.now_utc())
            bootstrap.check_window(ready["decision"], minimum=MARGIN)
            bootstrap.token_margin(env, expiration, MARGIN)

        def intent(name, raw):
            require(name == names[INTENT] and action in contract.MUTATIONS, "personal_only_owned_intent")
            report["status"] = "intent_outcome_unknown_reconcile"
            ref = cloud.create_bytes(name, raw)
            report["intent"] = ref
            report["status"] = "intent_recorded_sql_not_started"
            ready_for_sql()
            report.update(status="guest_outcome_unknown_reconcile", sql_started=True)
            return ref

        ready_for_sql()
        if action == "observe":
            report.update(status="guest_outcome_unknown_reconcile", sql_started=True)
        outcome = contract.protected_invocation(processes, port, ready["executable"], ready["request"], intent, password, origin=origin)
        after = read_snapshot()
        require(after == before, "personal_post_sql_target_changed")
        if action == "observe" and recovery is not None:
            observation = outcome["guest"]["observation"]
            guest.check_observation("activate", observation)
            require(observation["activation_marker"] == recovery["marker"], "personal_reconciled_activation_marker")
            report.update(recovery=recovery, original_key_withdrawal=verify_original_key_withdrawal(client, recovery["origin"]["key"]),
                          observed_utc=channel.now_utc().isoformat())
        report.update(outcome=outcome, before=before, after=after, status="guest_verified_pending_backend")
    except (guest.Blocked, ValueError, TypeError, OSError, HTTPError) as error:
        report.update(channel.safe_error(error))
    finally:
        try:
            if processes is not None:
                processes.close()
        except (OSError, ValueError) as error:
            report["process_cleanup_error"] = channel.safe_error(error)
        try:
            cleanup = clean(environ=env, workdir=work, reports=reports, client=client)
        except (ValueError, OSError, HTTPError) as error:
            cleanup = {"status": "cleanup_unconfirmed_TTL_pending", **channel.safe_error(error)}
        report["cleanup_status"] = cleanup["status"]
        if report["status"] == "guest_verified_pending_backend" and (
                cleanup["status"] not in NO_ACTIVE_KEY or "process_cleanup_error" in report):
            report["status"] = "guest_cleanup_pending_reconcile"
        for number, handler in handlers.items():
            signal.signal(number, handler)
        if report["status"] == "guest_verified_pending_backend":
            write_private(work / "personal-sql-pending.json", report)
        elif "intent" in report or report["sql_started"] or report["status"] == "intent_outcome_unknown_reconcile":
            record_result(report, cloud, names, reports)
        write_private(reports / "personal-sql-progress.json", public_report(report))
    return report


def finalize(env, ready, proof, binding, work, reports, *, make_custody=custody.Custody):
    transport.validate_deploy_credentials(env, transport._credential_document(env))
    backend.verify(proof, binding, now=channel.now_utc())
    draft = transport.decode(transport._local_bytes(work / "personal-sql-pending.json", 65536))
    request = guest.decode(ready["request"])
    require(draft["status"] == "guest_verified_pending_backend" and draft["schema"] == SCHEMA
            and draft["decision_sha256"] == binding["decision_sha256"] and draft["operation_id"] == binding["operation_id"]
            and draft["run"] == binding["run"] and draft["control_commit"] == binding["control_commit"]
            and draft["request_sha256"] == contract.digest(ready["request"])
            and (draft["action"], draft["outcome"]["guest"]["authority_sha256"]) == (request["action"], request["authority_sha256"]),
            "personal_provisional_run_or_decision_changed")
    before = {**draft["before"], "guest_boot_id": request["boot_id"]}
    after = {**draft["after"], "guest_boot_id": request["boot_id"]}
    final = contract.verified_terminal(draft["outcome"], before, after, live_state(proof["state"]),
                                       {"status": draft["cleanup_status"]})
    report = {**draft, **final, "post_backend_sha256": contract.digest(transport.canonical(proof))}
    report.pop("outcome")
    if request["action"] == "observe" and "activation_intent" in ready["references"]:
        recovery = report["recovery"]
        require(recovery["intent"] == ready["references"]["activation_intent"]
                and recovery["partial"] == ready["references"].get("activation_partial")
                and report["original_key_withdrawal"] == {**recovery["origin"]["key"], "status": contract.ABSENT}
                and final["intent"] is None and final["guest"]["observation"]["activation_marker"] == recovery["marker"],
                "personal_reconciliation_provisional_binding")
        report["status"] = contract.RECOVERED
    names = custody.producer_names(env, OPERATION, draft["operation_id"])
    return record_result(report, make_custody(env["GCP_ACCESS_TOKEN"], names=names.values()), names, reports)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "protected-local", "observe-backend", "run", "cleanup", "post-backend", "finalize"))
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--decision-sha256")
    parser.add_argument("--review-sha256")
    parser.add_argument("--binding-sha256")
    parser.add_argument("--backend-observation", type=Path)
    args = parser.parse_args(argv)
    env = dict(os.environ)
    password = env.pop("INT_NOBLE_PERSONAL_SQL_PASSWORD", None) or None
    os.environ.pop("INT_NOBLE_PERSONAL_SQL_PASSWORD", None)
    try:
        if args.phase == "cleanup":
            return channel.main(["cleanup"], env=env)
        ready = validate_local(env, args.bundle, args.decision_sha256, args.review_sha256, args.binding_sha256,
                               protected=args.phase != "local")
        if args.phase in {"local", "protected-local"} and args.backend_observation is None:
            print('{"status":"personal_sql_preflight_verified","retry_authorized":false}')
            return 0
        path = channel.backend_receipt_path(args.backend_observation, env)
        timing = "after" if args.phase in {"post-backend", "finalize"} else "before"
        binding = backend_binding(env, ready, args.decision_sha256, timing)
        if timing == "after":
            path = path.with_name("backend-after.json")
        if args.phase in {"observe-backend", "post-backend"}:
            proof = backend.observe_for_run(env, binding)
            if timing == "before":
                raw_apply = plans.fetch_verified(ready["references"]["apply"])
                validate_apply(raw_apply, ready)
                with path.with_name("personal-sql-apply.json").open("xb") as stream:
                    stream.write(raw_apply)
            backend.verify(proof, binding, now=channel.now_utc())
            write_private(path, proof)
            print('{"status":"personal_sql_backend_metadata_verified","lock_acquired":false}')
            return 0
        proof = transport.decode(transport._local_bytes(path, 65536))
        backend.verify(proof, binding, now=channel.now_utc())
        if args.phase == "protected-local":
            return 0
        work, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
        if args.phase == "run":
            applied = transport._local_bytes(path.with_name("personal-sql-apply.json"), contract.MAX_RECEIPT)
            result = launch(env, ready, proof, binding, work, reports, password=password, apply=applied)
            expected = "guest_verified_pending_backend"
        else:
            require(password is None, "unexpected_personal_password")
            result = finalize(env, ready, proof, binding, work, reports)
            expected = (contract.RECOVERED if ready["decision"]["inputs"]["action"] == "observe"
                        and "activation_intent" in ready["references"] else "completed_verified")
        print(json.dumps(public_report(result)))
        return int(result["status"] != expected)
    except (guest.Blocked, ValueError, TypeError, AttributeError, KeyError, OSError, HTTPError) as error:
        print(json.dumps({"status": "personal_sql_blocked_or_indeterminate", "phase": args.phase,
                          "error_code": channel.safe_error(error)["error_code"], "retry_authorized": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
