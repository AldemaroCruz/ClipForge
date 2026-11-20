"""Allocate one numeric version per approved Hito A secret, with private intents."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from scripts import int_demo_a_preflight as preflight
from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport
from scripts import int_noble_postverify as github
from scripts import int_secrets as historical


WORKFLOW = ".github/workflows/int-demo-a-secrets.yml"
OPERATION = "secret_versions"
TARGETS = historical.TARGETS
SLOTS = {"app_password": "INT_PG_APP_PASSWORD", "migrator_password": "INT_PG_MIGRATOR_PASSWORD",
         "postgres_ca": "INT_PG_CA_CERT", "bootstrap_admin": "INT_BOOTSTRAP_ADMIN"}
require = transport.require


def prerequisite(bundle, value):
    required = {"bootstrap_receipt_sha256", "bootstrap_controls", "bootstrap_run", "bootstrap_artifact",
                "bootstrap_artifact_sha256", "ca_certificate_sha256"}
    require(isinstance(value, dict) and set(value) == required and re.fullmatch(r"[a-f0-9]{40}", value["bootstrap_controls"])
            and all(re.fullmatch(r"[1-9][0-9]*", value[key]) for key in ("bootstrap_run", "bootstrap_artifact"))
            and all(re.fullmatch(preflight.SHA, value[key]) for key in ("ca_certificate_sha256", "bootstrap_artifact_sha256",
                                                                     "bootstrap_receipt_sha256")), "demo_a_bootstrap_binding")
    report = preflight.json_bytes(bundle, "bootstrap.json", value["bootstrap_receipt_sha256"], limit=65536)
    outcome = "configured_guest_verified_external_acceptance_pending"
    expected = {"schema": "clipforge-int-noble-bootstrap-result-1", "status": outcome, "runtime_authorized": False,
                "migrations_applied": False, "external_client_acceptance": False}
    native = report["guest_receipt"]
    require(all(report.get(k) == v for k, v in expected.items()) and native["status"] == outcome
            and native["approved_commit"] == value["bootstrap_controls"] and native["disk_id"] == "7382984635240536620"
            and native["operation_id"] == report["operation_id"] and native["exit_code"] == 0
            and report["cleanup"]["status"] in {"own_key_removed", "key_already_absent"}, "demo_a_bootstrap_not_ready")
    return report


def bootstrap_provenance(value, token):
    require(isinstance(token, str) and bool(token), "demo_a_bootstrap_provenance_requires_actions_read")
    run, commit = value["bootstrap_run"], value["bootstrap_controls"]
    github.verify_github_run(run, commit, token, ".github/workflows/int-db01-noble-bootstrap.yml", "success")
    artifact = github.read_github(token, f"artifacts/{value['bootstrap_artifact']}")
    require(artifact["name"] == f"int-db01-noble-bootstrap-{commit}-{run}-1" and artifact["expired"] is False
            and artifact["digest"] == "sha256:" + value["bootstrap_artifact_sha256"]
            and artifact["workflow_run"]["id"] == int(run) and artifact["workflow_run"]["head_sha"] == commit,
            "demo_a_bootstrap_artifact_provenance")


def protected_values(env, expected_ca):
    raw = {key: env.get(name, "").encode("utf-8") for key, name in SLOTS.items()}
    for name, value in raw.items():
        historical.validate_payload(name, value)
    require(raw["app_password"] != raw["migrator_password"] and transport.sha(raw["postgres_ca"]) == expected_ca, "demo_a_distinct_db_credentials_and_ca")
    return raw


def add_version(key, value, token):
    name = TARGETS[key]
    url = f"https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/{name}:addVersion"
    body = json.dumps({"payload": {"data": base64.b64encode(value).decode("ascii")}}).encode()
    request = Request(url, data=body, method="POST", headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"})
    try:
        with build_opener(ProxyHandler({}), transport.NoRedirect()).open(request, timeout=60) as response:
            raw = response.read(32769)
        require(len(raw) <= 32768, "demo_a_version_response_bound")
    except HTTPError as error:
        status = error.code
        error.close()
        raise transport.Failure("demo_a_add_secret_version_failed", {"secret": name, "http_status": status}) from None
    version = json.loads(raw).get("name", "")
    require(re.fullmatch(r"projects/(?:clipforgebeta2|816643438938)/secrets/" + name + r"/versions/[1-9][0-9]*", version),
            "demo_a_secret_version_receipt")
    return {"secret": name, "version": version.rsplit("/", 1)[1]}


def execute(bundle, env, decision, approval_hash, values, bootstrap):
    token = preflight.deploy_after_wif(env, decision)
    cloud = receipts.Custody(token)
    refs = {}
    versions = {}
    status = {"status": "preflight_complete", "intent": refs, "versions": versions}
    inputs = decision["inputs"]
    evidence = {"bootstrap_receipt_sha256": inputs["bootstrap_receipt_sha256"], "source_controls": env["GITHUB_SHA"],
                "run": env["GITHUB_RUN_ID"], "bootstrap_run": inputs["bootstrap_run"], "bootstrap_artifact": inputs["bootstrap_artifact"],
                "ca_certificate_sha256": inputs["ca_certificate_sha256"]}
    try:
        raw = transport._local_bytes(bundle / "bootstrap.json", 65536)
        require(transport.sha(raw) == inputs["bootstrap_receipt_sha256"], "demo_a_bootstrap_bytes_changed")
        status["bootstrap_receipt"] = cloud.create_bytes(receipts.name_for(env, "noble-bootstrap.json"), raw)
        for key in TARGETS:
            status.update(phase=key, status="secret_version_intent_pending")
            name = receipts.name_for(env, f"secret-{key}-intent.json", intent=decision["operation_id"])
            refs[key] = cloud.create(name, {**evidence, "status": "secret_version_intended",
                                           "secret": TARGETS[key], "owner_decision_sha256": approval_hash})
            status["status"] = "secret_version_outcome_requires_reconciliation"
            versions[key] = add_version(key, values[key], token)
        name = receipts.name_for(env, "secret-versions.json")
        reference = {"status": "published_and_verified", **evidence, "versions": versions, "intents": refs,
                     "bootstrap_operation": bootstrap["operation_id"], "bootstrap_ref": status["bootstrap_receipt"]}
        status["receipt"] = cloud.create(name, reference)
        status["status"] = "published_and_verified"
    except (transport.Failure, ValueError, OSError, KeyError) as error:
        status["error_code"] = str(error) if isinstance(error, transport.Blocked) else type(error).__name__
        if isinstance(error, transport.Failure):
            status["failure"] = error.receipt
    return status


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "protected-local", "execute"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--decision-sha256", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        decision = preflight.local_decision(args.bundle, args.decision_sha256, OPERATION, WORKFLOW, env, protected=args.phase != "local")
        bootstrap = prerequisite(args.bundle, decision["inputs"])
        bootstrap_provenance(decision["inputs"], env.get("GH_TOKEN", ""))
        if args.phase == "local":
            print('{"status":"validated","activation_authorized":false}')
            return 0
        values = protected_values(env, decision["inputs"]["ca_certificate_sha256"])
        for name in SLOTS.values():
            env.pop(name, None)
        if args.phase == "protected-local":
            print('{"status":"validated","activation_authorized":false}')
            return 0
        result = execute(args.bundle, env, decision, args.decision_sha256, values, bootstrap)
        print(json.dumps(result))
        return int(result["status"] != "published_and_verified")
    except (transport.Blocked, OSError, TypeError, KeyError, ValueError) as error:
        # Some native parsers include input bytes in errors. Preserve only a closed diagnostic label.
        code = str(error)
        print(json.dumps({"status": "blocked", "error_code": code if re.fullmatch(r"[a-z0-9_]{1,120}", code) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
