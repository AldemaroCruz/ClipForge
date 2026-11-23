"""Publish the two prebuilt A images using an independently reviewed Skopeo image."""

import argparse
import base64
import json
import os
from pathlib import Path
import re
import subprocess
import tarfile
import time

from scripts import int_demo_a_docker as docker_identity
from scripts import int_demo_a_docker_prepare as docker_prepare
from scripts import int_demo_a_preflight as preflight
from scripts.int_demo_a_publish_common import (
    DIGEST, HOST, INPUT_LIMIT, MANIFEST, OPERATION, PUBLISHER_BUILD_INFO_SHA256,
    PUBLISHER_BUILD_SHA256, PUBLISHER_FILES, PUBLISHER_REVISION, REPOSITORY, TARGETS, WORKFLOW,
    archive_inventory, check_staging_archive, descriptor, digest_file, digest_stream, require, verified_staging_archive,
    verify_build, verify_registry, verify_tool,
)
from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport


def copy_args(image_id, archive, authfile, destination, *, network=None, trust=None, user=None, engine=None):
    require(DIGEST.fullmatch(image_id), "demo_a_local_publisher_config_digest")
    user = user or f"{os.getuid()}:{os.getgid()}"
    argv = [*(engine or ["docker"]), "run", "--rm", "--pull=never", "--init=false", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
            "--user=" + user, "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=384m",
            "--mount=type=bind,source=" + str(archive) + ",target=/input/image.oci.tar,readonly",
            "--mount=type=bind,source=" + str(authfile) + ",target=/authorization/auth.json,readonly"]
    if network is not None:
        argv += ["--network", network]
    if trust is not None:
        argv += ["--mount=type=bind,source=" + str(trust) + ",target=/etc/ssl/certs/ca-certificates.crt,readonly"]
    return argv + [image_id, "--tmpdir=/tmp", "copy", "--preserve-digests", "--dest-tls-verify=true",
                   "--dest-authfile=/authorization/auth.json", "oci-archive:/input/image.oci.tar", "docker://" + destination]


def stage(bundle, env, image_id, images):
    work = preflight.runtime_scratch(env)
    config = work / "docker-config"
    config.mkdir(mode=0o700)
    engine = docker_identity.endpoint(config)
    command_env = {"PATH": "/usr/bin:/bin", "HOME": str(work)}
    command = [*engine, "load", "--input", str(bundle / "publisher.oci.tar")]
    require(subprocess.run(command, env=command_env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           timeout=180, check=False).returncode == 0, "demo_a_load_verified_publisher")
    result = subprocess.run([*engine, "image", "inspect", "--format={{.Id}}", image_id], env=command_env, capture_output=True, timeout=10, check=False)
    require(result.returncode == 0 and result.stdout.decode().strip() == image_id, "demo_a_staged_publisher_changed")
    for target, expected in images.items():
        verified_staging_archive(bundle / (target + ".oci.tar"), work / (target + ".oci.tar"), expected, os.getuid(), os.getgid())


def execute(bundle, env, decision, approval_hash, tool, images, *, verify_host):
    work = preflight.runtime_scratch(env)
    token = preflight.deploy_after_wif(env, decision)
    names = receipts.producer_names(env, "publish", decision["operation_id"])
    cloud = receipts.Custody(token, names=names.values())
    config = work / "docker-config"
    require(config.is_dir() and not config.is_symlink() and not any(config.iterdir()), "demo_a_empty_docker_config")
    engine = docker_identity.endpoint(config)
    command_env = {"PATH": "/usr/bin:/bin", "HOME": str(work)}
    report = {"status": "publication_pending", "references": {}, "intent": {}, "operation_id": decision["operation_id"]}
    auth = work / "publisher-auth.json"
    creds = {"auths": {HOST: {"auth": base64.b64encode(("oauth2accesstoken:" + token).encode()).decode()}}}
    owned = False
    try:
        with os.fdopen(os.open(auth, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb") as output:
            owned = True
            output.write(receipts.custody.canonical(creds))
        for target, image in images.items():
            artifact = bundle / (target + ".oci.tar")
            staged = work / (target + ".oci.tar")
            check_staging_archive(staged, image)
            destination = f"{HOST}/{REPOSITORY}/{target}@{image['manifest']}"
            report.update(phase=target, status="intent_pending")
            run = env["GITHUB_RUN_ID"]
            metadata = {"target": destination, "run": run, "source_controls": env["GITHUB_SHA"], "manifest": image["manifest"],
                        "operation_id": decision["operation_id"], "owner_decision_sha256": approval_hash,
                        "config": image["config"][0], "archive_sha256": image["archive_sha256"], "layers": [row[0] for row in image["layers"]],
                        "publisher_digest": tool["manifest"]}
            verify_host()
            at = time.time()
            started = env.get("INT_DEMO_A_AUTH_STARTED_EPOCH", "")
            require(re.fullmatch(r"[1-9][0-9]{9,11}", started) and 0 <= at - int(started) <= 900 - 300, "demo_a_publisher_credential_margin")
            intent_name = names["publication-" + target + "-intent.json"]
            report["intent"][target] = cloud.create(intent_name, {**metadata, "status": "copy_intended"})
            report["status"] = "copy_outcome_requires_reconciliation"
            code = subprocess.run(copy_args(tool["config"], staged, auth, destination, engine=engine), env=command_env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=360, check=False).returncode
            report["native_exit"] = code
            require(code == 0, "demo_a_copy_failed_review_before_retry")
            verify_registry(destination, image, "Bearer " + token)
            require(digest_file(artifact) == image["archive_sha256"], "demo_a_oci_source_changed")
            receipt_name = names["publication-" + target + ".json"]
            report["references"][target] = cloud.create(receipt_name, {**metadata, "status": "published_and_verified", "intent": report["intent"][target]})
        report["status"] = "published_and_verified"
        return report
    except (transport.Failure, ValueError, OSError, KeyError, subprocess.SubprocessError) as error:
        report["error_code"] = str(error) if isinstance(error, (transport.Blocked, docker_identity.ToolchainBlocked)) else type(error).__name__
        if isinstance(error, transport.Failure):
            report["failure"] = error.receipt
        return report
    finally:
        if owned:
            try:
                auth.unlink(missing_ok=True)
            except OSError:
                report["cleanup_error_code"] = "demo_a_private_auth_cleanup_failed"
                if report["status"] == "published_and_verified":
                    report["status"] = "publication_verified_cleanup_failed"


def checked_host_inputs(bundle, decision):
    inputs = decision["inputs"]
    require(set(inputs) == {"publisher", "targets", "docker_toolchain_sha256", "docker_preparation_sha256", "docker_rehearsal_sha256"}
            and inputs["targets"] == list(TARGETS), "demo_a_two_targets_and_preparation_bound")
    engine_proof = preflight.json_bytes(bundle, "docker-toolchain.json", inputs["docker_toolchain_sha256"], limit=65536)
    require(engine_proof["schema"] == docker_identity.SCHEMA, "demo_a_docker_proof_schema")
    review = preflight.json_bytes(bundle, "review.json", decision["review_sha256"])
    subject = review["subjects"]["credential_toolchain"]
    require(subject["identity"] == "sha256:" + inputs["docker_toolchain_sha256"], "demo_a_docker_gate_inventory_unbound")
    coverage = subject["publication"]
    scope = preflight.json_bytes(bundle, coverage["path"], coverage["sha256"])
    require(scope["docker_projection_sha256"] == docker_identity.projection_sha256(engine_proof)
            and scope["preparation"] == {"path": "docker-prepare.json", "sha256": inputs["docker_preparation_sha256"]}
            and scope["rehearsal"] == {"path": "publisher-rehearsal.json", "sha256": inputs["docker_rehearsal_sha256"]},
            "demo_a_docker_gate_preparation_unbound")
    docker_identity.verify_maintained(engine_proof)
    return inputs, engine_proof


def prepare(bundle, env, inputs):
    path = Path(env["RUNNER_TEMP"]) / "int-demo-a-docker-prepare.json"
    result = docker_prepare.main(["--profile", "protected", "--approved-commit", env["GITHUB_SHA"], "--report", str(path),
                                  "--expected", str(bundle / "docker-prepare.json"),
                                  "--expected-sha256", inputs["docker_preparation_sha256"]])
    require(result == 0, "demo_a_reproducible_docker_preparation_blocked")


def verify_prepared_host(env, current):
    path = Path(env["RUNNER_TEMP"]) / "int-demo-a-docker-prepare.json"
    proof = transport.decode(transport._local_bytes(path, docker_prepare.MAX_RECEIPT))
    require(proof["schema"] == docker_prepare.SCHEMA and proof["profile"] == "protected"
            and proof["status"] == "prepared_verified" and proof["publication_eligibility"] == "eligible"
            and proof["cloud_credentials_used"] is False and proof["oidc_job_capability"] is True
            and all(proof[key] == env[name] for key, name in (("run", "GITHUB_RUN_ID"), ("attempt", "GITHUB_RUN_ATTEMPT"),
                                                            ("commit", "GITHUB_SHA"))), "demo_a_current_docker_preparation_unbound")
    docker_identity.verify_same_host(proof["after"]["toolchain"], current)


def preauth_checkpoint(env, expected):
    work = preflight.runtime_scratch(env)
    current = docker_identity.verify(expected)
    snapshot = transport.decode(transport._local_bytes(work / "docker-toolchain-before-auth.json", 65536))
    docker_identity.verify_same_host(snapshot, current)
    return current


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "prepare", "stage", "execute"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--decision-sha256", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        if args.phase in {"prepare", "stage"}:
            require(not env.get("GCP_ACCESS_TOKEN") and not env.get("GOOGLE_APPLICATION_CREDENTIALS"),
                    "demo_a_docker_staging_precedes_google_credentials")
        decision = preflight.local_decision(args.bundle, args.decision_sha256, OPERATION, WORKFLOW, env, protected=args.phase != "local")
        inputs, engine_proof = checked_host_inputs(args.bundle, decision)
        if args.phase == "prepare":
            prepare(args.bundle, env, inputs)
            return 0
        tool = verify_tool(args.bundle, inputs["publisher"])
        images = {target: archive_inventory(args.bundle / (target + ".oci.tar"), approved) for target, approved in TARGETS.items()}
        if args.phase == "stage":
            before = docker_identity.verify(engine_proof)
            verify_prepared_host(env, before)
            stage(args.bundle, env, tool["config"], images)
            current = docker_identity.verify(engine_proof)
            docker_identity.verify_same_host(before, current)
            work = preflight.runtime_scratch(env)
            with os.fdopen(os.open(work / "docker-toolchain-before-auth.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as record:
                record.write(transport.canonical(current))
        if args.phase != "execute":
            print(json.dumps({"status": "validated", "targets": list(images), "activation_authorized": False}))
            return 0
        current = preauth_checkpoint(env, engine_proof)
        work = preflight.runtime_scratch(env)
        with os.fdopen(os.open(work / "docker-toolchain-before-publication.json", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as record:
            record.write(transport.canonical(current))
        report = execute(args.bundle, env, decision, args.decision_sha256, tool, images, verify_host=lambda: preauth_checkpoint(env, engine_proof))
        print(json.dumps(report))
        return int(report["status"] != "published_and_verified")
    except (transport.Blocked, ValueError, TypeError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, (transport.Blocked, docker_identity.ToolchainBlocked)) else type(error).__name__
        print(json.dumps({"status": "blocked", "error_code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
