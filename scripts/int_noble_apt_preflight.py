"""Query only the two approved WIF scopes needed before INT Noble APT."""

from argparse import ArgumentParser
import json
import os
from pathlib import Path
from urllib.error import HTTPError

from scripts import int_demo_a_db_runner as db_runner
from scripts import int_demo_a_noble_policy as policies
from scripts import int_demo_a_preflight as preflight
from scripts import int_demo_a_wif_read as wif_read
from scripts import int_guest_inventory as transport
from scripts import int_noble_first_observation as first
from scripts import int_noble_guest_intervention as intervention
from scripts import int_noble_guest_intervention_backend as backend
from scripts import int_noble_kernel_observation as handoff


OPERATION = "apt_preflight"
WORKFLOW = intervention.WORKFLOW
SCHEMA = "clipforge-int-noble-apt-preflight-1"
ORIGIN = "9a140372057ef9bd7a6254c02f5e61b52936a76f"
DEPLOY_RECEIPT = "5f3028c264c207c3ff82834f64dc878aa6f06449c9916d4f87b455b767838767"
NATIVE_RECEIPT = "1840d20bcc10553569c40cc384fb6b4c189eb542b4acd2ed948a1f8daeb47af9"
RECEIPTS = {"deploy-policy-receipt.json": DEPLOY_RECEIPT, "native-iam-receipt.json": NATIVE_RECEIPT}
POLICY_RESOURCES = {"instance": wif_read.NOBLE, "tunnel": wif_read.IAP_TUNNEL, "account": policies.ACCOUNT}
require = transport.require


def validate_local(env, bundle, decision_sha256, review_sha256, binding_sha256, *, protected=False, now=None):
    require(env.get("INT_NOBLE_OPERATION") == OPERATION, "apt_preflight_exact_selector")
    decision = preflight.local_decision(bundle, decision_sha256, OPERATION, WORKFLOW, env, protected=protected, now=now)
    require(decision["review_sha256"] == review_sha256 and decision["binding_sha256"] == binding_sha256,
            "apt_preflight_review_or_binding_digest")
    if protected:
        require(env.get("INT_NOBLE_INTERVENTION_REVIEW_SHA256") == review_sha256
                and env.get("INT_NOBLE_INTERVENTION_BINDING_SHA256") == binding_sha256,
                "apt_preflight_independent_protected_review")
    binding = preflight.json_bytes(bundle, "binding.json", binding_sha256, limit=65536)
    require(binding["state_generation"] == backend.scope.STATE["generation"], "apt_preflight_backend_generation")
    inputs = decision["inputs"]
    require(isinstance(inputs, dict) and set(inputs) == {"action", "snapshot_sha256", "policy_config_sha256",
            "deploy_policy_receipt_sha256", "native_iam_receipt_sha256"} and inputs["action"] == OPERATION
            and inputs["deploy_policy_receipt_sha256"] == DEPLOY_RECEIPT and inputs["native_iam_receipt_sha256"] == NATIVE_RECEIPT,
            "apt_preflight_read_only_inputs")
    deploy = preflight.json_bytes(bundle, "deploy-policy-receipt.json", DEPLOY_RECEIPT, limit=65536)
    native = preflight.json_bytes(bundle, "native-iam-receipt.json", NATIVE_RECEIPT, limit=65536)
    require(native["schema"] == "clipforge-int-demo-a-native-iam-receipt-1" and native["controls_commit"] == ORIGIN
            and native["deployment_phase"] == backend.scope.PROTECTED_RUNTIME
            and native["backend_generation"] == binding["state_generation"] and native["noble_policies"] == deploy
            and native["iap_policy"] is None and native["protected_runtime_apply"] is None,
            "apt_preflight_original_iam_receipt_binding")
    summary, pin = handoff.checked_inputs(intervention.read(bundle, "summary.json", handoff.SUMMARY_SHA),
                                         intervention.read(bundle, "host-pin.json", handoff.PIN_SHA))
    snapshot = pin["control_plane"]
    require(transport.sha(transport.canonical(snapshot)) == inputs["snapshot_sha256"], "apt_preflight_snapshot_binding")
    config = transport.decode(intervention.bootstrap.exact_local_hash(intervention.ROOT / policies.CONFIG,
                                                                     inputs["policy_config_sha256"], 65536))
    return {"decision": decision, "approval_sha256": decision_sha256, "summary": summary, "snapshot": snapshot,
            "deploy_policy": policies.expected_policy(config, deploy)}


def on_read(checks, operation, resource, call, *, evidence="read"):
    row = {"operation": operation, "resource": resource, "evidence": evidence, "write_executed": False}
    try:
        value = call()
    except (transport.Failure, policies.iam.CloudError, HTTPError, ValueError, OSError, TypeError, AttributeError, KeyError) as error:
        detail = intervention.safe_error(error)
        failure = detail.get("failure", {})
        if isinstance(error, policies.iam.CloudError):
            detail["http_status"] = error.status
        elif "http_status" in failure:
            detail["http_status"] = failure["http_status"]
        checks.append({**row, **detail, "result": "blocked"})
        return None
    checks.append({**row, "http_status": 200, "result": "read_verified_wif"})
    return value


def read_deploy(env, ready, proof, *, reader=first.read_compute, policy_reader=policies.iam.request_json,
                evaluate=wif_read.observe, client_factory=transport.Client):
    require(not env.get("GCP_TERRAFORM_SA"), "apt_preflight_deploy_scope")
    token = preflight.deploy_after_wif(env, ready["decision"])
    checks = []
    for name, (method, url, body) in policies.ROUTES.items():
        def current():
            return policies.canonical(policy_reader(url, token, method, body))

        value = on_read(checks, "getIamPolicy", POLICY_RESOURCES[name], current, evidence="policy")
        if value is not None:
            checks[-1].update(policy_etag=value["etag"], policy_sha256=transport.sha(transport.canonical(value)))
            checks[-1]["result"] = "policy_read_wif" if value == ready["deploy_policy"][name] else "full_policy_or_etag_drift"
    resources = {first.VM: "compute.instances.get", first.BOOT: "compute.disks.get",
                 first.DATA: "compute.disks.get", first.PROJECT: "compute.projects.get"}
    observed = {url: on_read(checks, operation, url.split("?", 1)[0].removeprefix(first.API), lambda url=url: reader(url, token))
                for url, operation in resources.items()}
    if all(value is not None for value in observed.values()):
        try:
            same_target = first.snapshot(observed.__getitem__, ready["summary"]["candidate"]) == ready["snapshot"]
        except (KeyError, TypeError, ValueError):
            same_target = False
        checks.append({"operation": "verify_control_plane_snapshot", "resource": wif_read.NOBLE, "evidence": "target",
                       "result": "target_verified" if same_target else "noble_target_or_metadata_drift", "write_executed": False})
    probes = (
        wif_read.evaluate(policies.ACCOUNT, wif_read.IAM + policies.ACCOUNT + ":testIamPermissions", ("iam.serviceAccounts.actAs",)),
        wif_read.evaluate(wif_read.NOBLE, wif_read.COMPUTE + wif_read.NOBLE + "/testIamPermissions", ("compute.instances.osAdminLogin",)),
        wif_read.evaluate(wif_read.IAP_TUNNEL, wif_read.IAP_API + wif_read.IAP_TUNNEL + ":testIamPermissions",
                          ("iap.tunnelInstances.accessViaIAP",)),
    )
    for probe in probes:
        row = evaluate(probe, token, transport.DEPLOY)
        if probe.resource == wif_read.IAP_TUNNEL and row["http_status"] == 200 and row["result"] in {
                "permission_indicated_by_evaluation", "no_permission_confirmed_by_evaluation"}:
            row["condition_context"] = "no_tunnel_port_evaluated_by_this_call"
            row["result"] = "iap_permission_evaluated_tunnel_pending"
        checks.append(row)
    profile = on_read(checks, "oslogin.users.getLoginProfile", transport.DEPLOY,
                      lambda: transport.validate_deploy_profile(client_factory(lambda: token).profile()))
    if profile is not None:
        checks[-1]["profile_name_sha256"] = profile["profile_name_sha256"]
    passed = {"read_verified_wif", "policy_read_wif", "target_verified", "permission_indicated_by_evaluation",
              "iap_permission_evaluated_tunnel_pending"}
    return {"schema": SCHEMA, "status": "read_preflight_verified" if all(row["result"] in passed for row in checks) else "blocked",
            "run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "controls_commit": env["GITHUB_SHA"],
            "operation": OPERATION, "operation_id": ready["decision"]["operation_id"], "approval_sha256": ready["approval_sha256"],
            "identity": transport.DEPLOY, "backend_observation": proof, "receipt_inputs_read_locally": RECEIPTS, "checks": checks,
            "pending": ["conditioned_tcp_22_tunnel", "os_login_key_import_and_removal", "ssh_and_guest_boot_recheck", "own_receipt_object_create_and_read",
                        "apt_simulation_install_and_postcheck", "secret_version_metadata_when_real_versions_exist"],
            "write_executed": False, "apt_authorized": False, "runtime_authorized": False}


def retain(env, name, result):
    _, reports = transport._validate_paths(env, env["GUEST_WORK"], env["GUEST_REPORTS"])
    with (reports / name).open("xb") as output:
        output.write(transport.canonical(result) + b"\n")


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "protected-local", "observe-backend", "read"))
    parser.add_argument("--bundle", required=True, type=Path)
    parser.add_argument("--decision-sha256", required=True)
    parser.add_argument("--review-sha256", required=True)
    parser.add_argument("--binding-sha256", required=True)
    parser.add_argument("--backend-observation", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.phase in {"local", "protected-local"}:
            db_runner.require_secretless_admission(env)
        if args.phase == "protected-local":
            require((env.get("INT_DB_RUNNER_REQUIRE_EXISTING") == "1") == (args.backend_observation is not None),
                    "apt_preflight_continuation_checkpoint_required")
        require(not any(env.get(name) for name in ("INT_PG_APP_PASSWORD", "INT_PG_MIGRATOR_PASSWORD", "INT_PG_SERVER_KEY",
                                                  "INT_NOBLE_PERSONAL_SQL_PASSWORD")), "apt_preflight_unexpected_payload_secret")
        ready = validate_local(env, args.bundle, args.decision_sha256, args.review_sha256, args.binding_sha256,
                               protected=args.phase != "local")
        if args.backend_observation is None:
            require(args.phase in {"local", "protected-local"}, "apt_preflight_backend_proof_required")
            print('{"status":"apt_read_scope_verified","apt_authorized":false}')
            return 0
        require(args.phase != "local", "apt_preflight_backend_protected_only")
        path = intervention.backend_receipt_path(args.backend_observation, env)
        expected = backend.binding(env, ready["decision"], args.decision_sha256)
        if args.phase == "observe-backend":
            proof = backend.observe_for_run(env, expected)
            with path.open("xb") as output:
                output.write(transport.canonical(proof) + b"\n")
            retain(env, "apt-preflight-backend.json", proof)
            print('{"status":"backend_metadata_verified","lock_acquired":false}')
            return 0
        proof = transport.decode(transport._local_bytes(path, 65536))
        backend.verify(proof, expected, now=intervention.now_utc())
        if args.phase == "protected-local":
            print('{"status":"apt_read_continuity_verified","apt_authorized":false}')
            return 0
        result = read_deploy(env, ready, proof)
        retain(env, "apt-preflight.json", result)
        print(json.dumps(result))
        return int(result["status"] != "read_preflight_verified")
    except (transport.Failure, HTTPError, ValueError, TypeError, AttributeError, KeyError, OSError) as error:
        report = {"schema": SCHEMA, "operation": OPERATION, "status": "blocked", "phase": args.phase,
                  **intervention.safe_error(error), "apt_authorized": False, "runtime_authorized": False, "write_executed": False}
        if args.phase != "local" and "GUEST_REPORTS" in env:
            try:
                retain(env, "apt-preflight-failure.json", report)
            except (ValueError, OSError):
                report["secondary_error"] = "apt_preflight_report_unavailable"
        print(json.dumps(report))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
