"""Publish the exact reviewed Hito A OCI artifacts using native Skopeo."""

import argparse
import base64
from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import tarfile
import time

from scripts import int_demo_a_native_skopeo as skopeo
from scripts import int_demo_a_preflight as preflight
from scripts import int_demo_a_publication_host as host
from scripts import int_demo_a_publication_input as custody_input
from scripts import int_demo_a_publish_common as common
from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport
from scripts import int_release


PROFILE = "native-skopeo"
HOST_FILE = "native-publication-host.json"
REHEARSAL = "native-publication-rehearsal.json"
CHECKPOINT = "native-publication-before-wif.json"
INPUT_CHECKPOINT = "native-publication-before-private-read.json"
STAGING = "native-skopeo"
COMPLETED_TARGET = "runtime"
PENDING_TARGET = "db01-noble-client"
WIF_SECONDS = 900
CUSTODY_SECONDS = 90
COPY_SECONDS = 360
READBACK_SECONDS = 120
LOCAL_CHECK_SECONDS = 30
FINISH_MARGIN_SECONDS = 15
COPY_BUDGET_SECONDS = COPY_SECONDS + READBACK_SECONDS + LOCAL_CHECK_SECONDS + CUSTODY_SECONDS + FINISH_MARGIN_SECONDS
INTENT_BUDGET_SECONDS = CUSTODY_SECONDS + LOCAL_CHECK_SECONDS + COPY_BUDGET_SECONDS
require = transport.require


def write_exclusive(path, data, mode=0o600):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode), "wb") as output:
        output.write(data)


def scope(env, decision_sha, pointer_sha):
    expected = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": preflight.REPO,
                "GITHUB_REF": "refs/heads/" + preflight.BRANCH, "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_WORKFLOW_REF": f"{preflight.REPO}/{common.WORKFLOW}@refs/heads/{preflight.BRANCH}"}
    require(all(env.get(key) == value for key, value in expected.items())
            and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))
            and env.get("GITHUB_SHA") == env.get("INT_APPROVED_COMMIT")
            and re.fullmatch(receipts.RUN, env.get("GITHUB_RUN_ID", ""))
            and re.fullmatch(receipts.SHA, decision_sha) and re.fullmatch(receipts.SHA, pointer_sha),
            "native_publication_exact_hosted_scope")


def protected_pointer(env, decision_sha, pointer_sha):
    google = {"GCP_PROJECT_ID": "clipforgebeta2", "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1",
              "GCP_WIF_PROVIDER": transport.PROVIDER, "GCP_DEPLOY_SA": transport.DEPLOY, "GUEST_ENVIRONMENT": "int"}
    require(all(env.get(key) == value for key, value in google.items())
            and env.get("INT_DEMO_A_PROTECTED_DECISION_SHA256") == decision_sha
            and not any(env.get(name) for name in ("SSL_CERT_FILE", "SSL_CERT_DIR", "GOOGLE_CREDENTIALS", "DOCKER_HOST")),
            "native_publication_independent_protection")
    pointer = custody_input.pointer(env.get("INT_DEMO_A_PUBLISH_POINTER_JSON"), pointer_sha, env["GITHUB_SHA"], decision_sha)
    require(env.get("INT_DEMO_A_PROTECTED_GATE_MODE", "global") == pointer["gate_mode"],
            "native_publication_protected_gate_mode")
    host.checked(pointer["host"])
    return pointer


def input_checkpoint(work, env, expected):
    previous = preflight.json_bytes(work, INPUT_CHECKPOINT, limit=65536)
    return host.verify(env, expected, previous)


def fetch_bundle(work, env, pointer):
    input_checkpoint(work, env, pointer["host"])
    archive = work / "private-publication-input.tar"
    custody_input.download(pointer["input"], env.get("GCP_READ_ACCESS_TOKEN", ""), archive)
    custody_input.unpack(archive, work / "bundle")
    archive.unlink()
    input_checkpoint(work, env, pointer["host"])


def publication_scope(decision, env, approval_hash):
    inputs = decision["inputs"]
    fields = {"publisher", "targets", "transport", "native_host_sha256", "native_rehearsal_sha256"}
    continuation = "continuation" in inputs
    require(set(inputs) == (fields | {"continuation"} if continuation else fields)
            and inputs["targets"] == ([PENDING_TARGET] if continuation else list(common.TARGETS))
            and inputs["transport"] == PROFILE,
            "native_publication_closed_decision_inputs")
    if not continuation:
        return None
    previous = inputs["continuation"]
    require(isinstance(previous, dict) and set(previous) == {"previous_run", "previous_decision_sha256", "receipt"}
            and isinstance(previous["previous_run"], str) and re.fullmatch(receipts.RUN, previous["previous_run"])
            and int(previous["previous_run"]) < int(env["GITHUB_RUN_ID"])
            and isinstance(previous["previous_decision_sha256"], str)
            and re.fullmatch(receipts.SHA, previous["previous_decision_sha256"])
            and previous["previous_decision_sha256"] != approval_hash,
            "native_publication_continuation_requires_fresh_run_and_decision")
    names = receipts.producer_names({**env, "GITHUB_RUN_ID": previous["previous_run"]}, "publish", decision["operation_id"])
    ref = previous["receipt"]
    require(isinstance(ref, dict) and ref.get("name") == names["publication-" + COMPLETED_TARGET + ".json"],
            "native_publication_continuation_receipt_scope")
    return names["publication-" + COMPLETED_TARGET + "-intent.json"]


def checked_inputs(bundle, decision, env, approval_hash):
    publication_scope(decision, env, approval_hash)
    inputs = decision["inputs"]
    expected = host.checked(preflight.json_bytes(bundle, HOST_FILE, inputs["native_host_sha256"], limit=65536))
    review = preflight.json_bytes(bundle, "review.json", decision["review_sha256"])
    subject = review["subjects"]["credential_toolchain"]
    reference = subject["publication"]
    proof = preflight.json_bytes(bundle, reference["path"], reference["sha256"])
    require(proof["host"] == {"path": HOST_FILE, "sha256": inputs["native_host_sha256"]}
            and proof["rehearsal"] == {"path": REHEARSAL, "sha256": inputs["native_rehearsal_sha256"]}
            and subject["identity"] == "sha256:" + inputs["native_host_sha256"], "native_publication_review_not_bound")
    tool = common.verify_tool(bundle, inputs["publisher"])
    require(tool["manifest"] == "sha256:" + skopeo.MANIFEST and tool["archive_sha256"] == skopeo.ARCHIVE_SHA256,
            "native_publication_publisher_changed")
    images = {target: common.archive_inventory(bundle / (target + ".oci.tar"), pin) for target, pin in common.TARGETS.items()}
    return expected, tool, images


def stage(bundle, work, env, expected, images):
    require(not any(env.get(key) for key in ("GCP_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                                            "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "GOOGLE_GHA_CREDS_PATH")),
            "native_publication_stage_requires_no_google_credentials")
    before = input_checkpoint(work, env, expected)
    tool = skopeo.stage(bundle / "publisher.oci.tar", work / STAGING)
    for name, image in images.items():
        staged = work / (name + ".oci.tar")
        common.verified_staging_archive(bundle / staged.name, staged, image, os.getuid(), os.getgid())
        staged.chmod(0o400)
    checkpoint = {"runner": host.verify(env, expected, before), "tool": tool}
    require(tool["setpriv_sha256"] == expected["tools"]["setpriv"]["sha256"] and tool["uid"] == expected["uid"],
            "native_publication_staged_execution_identity")
    write_exclusive(work / CHECKPOINT, transport.canonical(checkpoint))
    return checkpoint


def verify_checkpoint(work, env, expected):
    checkpoint = preflight.json_bytes(work, CHECKPOINT, limit=65536)
    live = host.verify(env, expected, checkpoint["runner"])
    tool = skopeo.verify(work / STAGING)
    require(tool == checkpoint["tool"] and tool["setpriv_sha256"] == expected["tools"]["setpriv"]["sha256"]
            and tool["uid"] == expected["uid"], "native_publication_tool_changed_since_wif")
    return {"runner": live, "tool": tool}


def credential_budget(env, decision, *, required=INTENT_BUDGET_SECONDS):
    started = env.get("INT_DEMO_A_AUTH_STARTED_EPOCH", "")
    require(re.fullmatch(r"[1-9][0-9]{9,11}", started) and 0 <= time.time() - int(started) <= WIF_SECONDS - required,
            "native_publication_credential_margin")
    require(datetime.now(timezone.utc) < datetime.fromisoformat(decision["expires_utc"]),
            "native_publication_owner_decision_expired")


@contextmanager
def phase_deadline(seconds, code):
    """Bound the entire native Linux phase, including streams with per-read timeouts."""
    require(signal.getitimer(signal.ITIMER_REAL) == (0.0, 0.0), "native_publication_timer_already_active")

    def expired(signum, frame):
        raise transport.Blocked(code)

    previous = signal.signal(signal.SIGALRM, expired)
    try:
        signal.setitimer(signal.ITIMER_REAL, seconds)
        yield
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)


def metadata(target, image, env, operation_id, approval_hash, tool):
    return {"target": f"{common.HOST}/{common.REPOSITORY}/{target}@{image['manifest']}",
            "run": env["GITHUB_RUN_ID"], "source_controls": env["GITHUB_SHA"],
            "manifest": image["manifest"], "operation_id": operation_id, "owner_decision_sha256": approval_hash,
            "config": image["config"][0], "archive_sha256": image["archive_sha256"],
            "layers": [row[0] for row in image["layers"]], "publisher_digest": tool["manifest"]}


def verify_previous_publication(reader, decision, env, images, tool, expected_intent):
    previous = decision["inputs"]["continuation"]
    ref = previous["receipt"]
    recorded = transport.decode(reader.fetch(ref))
    require(isinstance(recorded, dict), "native_publication_continuation_receipt_contents")
    intent = recorded.get("intent")
    expected = metadata(COMPLETED_TARGET, images[COMPLETED_TARGET], {**env, "GITHUB_RUN_ID": previous["previous_run"]},
                        decision["operation_id"], previous["previous_decision_sha256"], tool)
    require(isinstance(intent, dict) and intent.get("name") == expected_intent
            and recorded == {**expected, "status": "published_and_verified", "intent": intent},
            "native_publication_continuation_receipt_contents")
    require(transport.decode(reader.fetch(intent)) == {**expected, "status": "copy_intended"},
            "native_publication_continuation_intent_contents")
    return ref, intent


def execute(bundle, work, env, decision, approval_hash, expected, tool, images):
    verify_checkpoint(work, env, expected)
    credential_budget(env, decision)
    previous_intent = publication_scope(decision, env, approval_hash)
    token = preflight.deploy_after_wif(env, decision)
    names = receipts.producer_names(env, "publish", decision["operation_id"])
    targets = decision["inputs"]["targets"]
    cloud = receipts.Custody(token, names=[names[f"publication-{target}{leaf}"]
                                         for target in targets for leaf in ("-intent.json", ".json")])
    report = {"status": "publication_pending", "references": {}, "intent": {}, "native_exit": {},
              "operation_id": decision["operation_id"]}
    auth = work / "publisher-auth.json"
    auth_data = {"auths": {common.HOST: {"auth": base64.b64encode(("oauth2accesstoken:" + token).encode()).decode()}}}
    owned = False
    try:
        if previous_intent is not None:
            with phase_deadline(CUSTODY_SECONDS, "native_publication_continuation_evidence_deadline"):
                report["phase"] = PENDING_TARGET
                ref, intent = verify_previous_publication(receipts.Custody(token), decision, env, images, tool, previous_intent)
                report["references"][COMPLETED_TARGET] = ref
                report["intent"][COMPLETED_TARGET] = intent
                report["status"] = "continuation_requires_reconciliation"
                cloud.require_absent(names["publication-" + PENDING_TARGET + "-intent.json"])
                report["status"] = "publication_pending"
        # An intent must be durable before invoking the only write-capable copy for a target.
        with os.fdopen(os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as output:
            owned = True
            output.write(transport.canonical(auth_data))
        for target in targets:
            image = images[target]
            archive = bundle / (target + ".oci.tar")
            staged = work / (target + ".oci.tar")
            report.update(phase=target, status="publication_pending")
            common.check_staging_archive(staged, image)
            publication = metadata(target, image, env, decision["operation_id"], approval_hash, tool)
            destination = publication["target"]
            verify_checkpoint(work, env, expected)
            credential_budget(env, decision)
            intent = names["publication-" + target + "-intent.json"]
            with phase_deadline(CUSTODY_SECONDS, "native_publication_intent_deadline"):
                report["status"] = "intent_outcome_requires_reconciliation"
                report["intent"][target] = cloud.create(intent, {**publication, "status": "copy_intended"})
            report["status"] = "intent_recorded_no_copy_started"
            with phase_deadline(LOCAL_CHECK_SECONDS, "native_publication_before_copy_check_deadline"):
                verify_checkpoint(work, env, expected)
            credential_budget(env, decision, required=COPY_BUDGET_SECONDS)
            with phase_deadline(COPY_SECONDS, "native_publication_copy_deadline"):
                report["status"] = "copy_outcome_requires_reconciliation"
                code = skopeo.copy(work / STAGING, staged, auth, destination)
            report["native_exit"][target] = code
            require(code == 0, "native_publication_copy_failed_review_before_retry")
            with phase_deadline(READBACK_SECONDS, "native_publication_readback_deadline"):
                common.verify_registry(destination, image, "Bearer " + token, ca=str(work / STAGING / "ca.pem"))
            with phase_deadline(LOCAL_CHECK_SECONDS, "native_publication_after_copy_check_deadline"):
                require(common.digest_file(archive) == image["archive_sha256"], "demo_a_oci_source_changed")
                verify_checkpoint(work, env, expected)
            receipt = names["publication-" + target + ".json"]
            with phase_deadline(CUSTODY_SECONDS, "native_publication_result_receipt_deadline"):
                report["status"] = "verified_copy_receipt_outcome_requires_reconciliation"
                report["references"][target] = cloud.create(
                    receipt, {**publication, "status": "published_and_verified", "intent": report["intent"][target]})
        report["status"] = "published_and_verified"
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        report["error_code"] = error_code(error)
        if isinstance(error, transport.Failure):
            report["failure"] = error.receipt
    finally:
        if owned:
            try:
                auth.unlink(missing_ok=True)
            except OSError:
                report["cleanup_error_code"] = "native_publication_auth_cleanup_failed"
                if report["status"] == "published_and_verified":
                    report["status"] = "publication_verified_cleanup_failed"
    return report


def error_code(error):
    if isinstance(error, (transport.Blocked, host.HostBlocked)):
        return str(error)
    return type(error).__name__


def public_result(report):
    public = {key: report[key] for key in ("status", "phase", "native_exit", "error_code", "cleanup_error_code")
              if key in report}
    public.update(intents_verified=sorted(report["intent"]), receipts_verified=sorted(report["references"]))
    if "failure" in report:
        public["failure"] = {key: value for key, value in report["failure"].items()
                             if key in {"http_status", "record", "method"}}
    return public


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "preauth", "fetch", "stage", "execute"))
    parser.add_argument("--decision-sha256", required=True)
    parser.add_argument("--pointer-sha256", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        scope(env, args.decision_sha256, args.pointer_sha256)
        if args.phase == "local":
            require(not any(env.get(key) for key in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL")),
                    "native_publication_validation_job_uncredentialed")
            print(json.dumps({"status": "dispatch_scope_verified", "activation_authorized": False}))
            return 0
        pointer = protected_pointer(env, args.decision_sha256, args.pointer_sha256)
        work = preflight.runtime_scratch(env)
        if args.phase == "preauth":
            require(not any(env.get(key) for key in ("GCP_ACCESS_TOKEN", "GCP_READ_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS")),
                    "native_publication_preauth_already_credentialed")
            if pointer["gate_mode"] == "global":
                int_release.require_application_ci(env)
            observed = host.verify(env, pointer["host"])
            write_exclusive(work / INPUT_CHECKPOINT, transport.canonical(observed))
        elif args.phase == "fetch":
            fetch_bundle(work, env, pointer)
        else:
            bundle = work / "bundle"
            decision = preflight.local_decision(bundle, args.decision_sha256, common.OPERATION, common.WORKFLOW, env,
                                                protected=True, publication_profile=PROFILE)
            expected, tool, images = checked_inputs(bundle, decision, env, args.decision_sha256)
            continuation_sha = args.decision_sha256 if "continuation" in decision["inputs"] else None
            owner_input = custody_input.name(env["GITHUB_SHA"], decision["operation_id"], continuation_sha=continuation_sha)
            require(expected == pointer["host"] and all(decision[key] == pointer[key]
                    for key in ("operation_id", "gate_mode", "issued_utc", "expires_utc"))
                    and pointer["input"]["name"] == owner_input,
                    "native_publication_private_review_differs_from_pointer")
            if args.phase == "stage":
                stage(bundle, work, env, expected, {target: images[target] for target in decision["inputs"]["targets"]})
                protected_pointer(env, args.decision_sha256, args.pointer_sha256)
            else:
                report = execute(bundle, work, env, decision, args.decision_sha256, expected, tool, images)
                print(json.dumps(public_result(report)))
                return int(report["status"] != "published_and_verified")
        print(json.dumps({"status": args.phase + "_verified", "activation_authorized": False}))
        return 0
    except (OSError, ValueError, TypeError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        details = {}
        if isinstance(error, transport.Failure):
            details["failure"] = {key: value for key, value in error.receipt.items() if key in {"http_status", "method"}}
        print(json.dumps({"status": "blocked", "error_code": error_code(error), **details}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
