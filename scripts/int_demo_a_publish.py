"""Publish the two prebuilt A images using an independently reviewed Skopeo image."""

import argparse
import base64
from contextlib import closing
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import tarfile
import time
from urllib.error import HTTPError
from urllib.request import HTTPSHandler, ProxyHandler, Request, build_opener

from scripts import int_demo_a_docker as docker_identity
from scripts import int_demo_a_preflight as preflight
from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport
from scripts import int_release_image as historical


OPERATION = "oci_publication"
WORKFLOW = ".github/workflows/int-demo-a-publish.yml"
HOST = "us-central1-docker.pkg.dev"
REPOSITORY = "clipforgebeta2/clipforge-int"
MANIFEST = "application/vnd.oci.image.manifest.v1+json"
DIGEST = re.compile(r"sha256:[a-f0-9]{64}")
INPUT_LIMIT = 256 * 1024 * 1024
PUBLISHER_REVISION = "bd981d14098835b559d02e7ca46d2a9696490e12"
PUBLISHER_BUILD_SHA256 = "ee2c9e8f4a02284433b5c0459e558b0460ba7c56e24efb4bfff4c79855736ad6"
PUBLISHER_BUILD_INFO_SHA256 = "89cfcd7dadf9d918dccb9689139a23b540e62f45464d66d3a79f1b2f92db6699"
PUBLISHER_FILES = {
    "usr/bin/skopeo": "fcb3f82e81d4f4aafe81a6aa4121d6f9fb06cb2fc884a69ded306966c723ee0c",
    "etc/ssl/certs/ca-certificates.crt": "64e7c24b0536b525fb19b145768bd5e6e12ced0df3db837c34553ea789acd143",
    "etc/containers/policy.json": "e69fc43eb736c76f09e39e6439a21a14b3cd7c2132c985c7b3dde8f2b6f219d5",
}
TARGETS = {
    "runtime": ("sha256:40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15",
                "4ccaa2ffe0a1b718641dfb71ef5745cf754713b43b293b92d7b455ad97247040"),
    "db01-noble-client": ("sha256:24e4d9ccea365859c6f455c3780c8abe6a0df3f1150e60380e2b2cc73e0dc5b5",
                         "350d9623e3920455052f9274f34cb2136c68c82f48ff7396126a599d3d20f8d4"),
}
require = transport.require


def digest_stream(stream, maximum):
    size = 0
    digest = sha256()
    while block := stream.read(1024 * 1024):
        size += len(block)
        require(size <= maximum, "demo_a_image_size_bound")
        digest.update(block)
    return digest.hexdigest(), size


def digest_file(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not path.is_symlink()
            and 0 < info.st_size <= INPUT_LIMIT, "demo_a_oci_private_file_shape")
    with path.open("rb") as stream:
        digest, size = digest_stream(stream, info.st_size)
    later = path.lstat()
    identity = ("st_dev", "st_ino", "st_size", "st_ctime_ns", "st_mtime_ns")
    require(size == info.st_size and all(getattr(info, field) == getattr(later, field) for field in identity),
            "demo_a_oci_source_changed")
    return digest


def descriptor(value):
    require(isinstance(value, dict) and isinstance(value.get("digest"), str) and DIGEST.fullmatch(value["digest"])
            and type(value.get("size")) is int and 0 < value["size"] <= INPUT_LIMIT and not value.get("urls"),
            "demo_a_oci_blob_descriptor")
    return value["digest"], value["size"]


def archive_inventory(path, expected):
    """The approved scopes are single manifests. Reject indexes before selecting children."""
    manifest_hash, archive_hash = expected
    require(digest_file(path) == archive_hash, "demo_a_archive_digest_changed")
    with tarfile.open(path, "r:") as archive:
        entries = archive.getmembers()
        names = [row.name for row in entries]
        require(0 < len(entries) <= 4096 and len(names) == len(set(names)) and all(
            (row.isdir() or row.isfile()) and not row.name.startswith("/") and ".." not in row.name.split("/") for row in entries
        ), "demo_a_unsafe_or_duplicate_oci_archive_member")
        entry = archive.getmember("index.json")
        require(entry.isfile() and 0 < entry.size <= 65536, "demo_a_oci_index_bound")
        index = transport.decode(archive.extractfile(entry).read())
        manifests = index.get("manifests")
        require(isinstance(manifests, list) and len(manifests) == 1 and manifests[0].get("mediaType") in
                {MANIFEST, "application/vnd.docker.distribution.manifest.v2+json"}, "demo_a_index_or_platform_fanout_not_authorized")
        require(historical.archive_digest(path) == manifest_hash and descriptor(manifests[0])[0] == manifest_hash, "demo_a_exact_oci_manifest")

        def blob(value):
            digest, size = descriptor(value)
            member = archive.getmember("blobs/sha256/" + digest.removeprefix("sha256:"))
            require(member.isfile() and member.size == size, "demo_a_oci_blob_member_size")
            return archive.extractfile(member)

        with blob(manifests[0]) as stream:
            manifest = transport.decode(stream.read(4 * 1024 * 1024 + 1))
        require(manifest["schemaVersion"] == 2 and manifest["mediaType"] == manifests[0]["mediaType"]
                and isinstance(manifest["layers"], list) and 0 < len(manifest["layers"]) <= 48, "demo_a_oci_manifest_schema")
        with blob(manifest["config"]) as stream:
            config_bytes = stream.read(1024 * 1024 + 1)
        require("sha256:" + sha256(config_bytes).hexdigest() == manifest["config"]["digest"], "demo_a_oci_config_hash")
        config = transport.decode(config_bytes)
        require(config["os"] == "linux" and config["architecture"] == "amd64" and config["rootfs"]["type"] == "layers"
                and len(config["rootfs"]["diff_ids"]) == len(manifest["layers"]), "demo_a_only_linux_amd64")
        for layer in manifest["layers"]:
            digest, size = descriptor(layer)
            with blob(layer) as stream:
                got, length = digest_stream(stream, size)
            require("sha256:" + got == digest and length == size, "demo_a_oci_layer_hash")
    return {"media_type": manifest["mediaType"], "manifest": manifest_hash, "manifest_size": manifests[0]["size"], "archive_sha256": archive_hash,
            "config": descriptor(manifest["config"]), "layers": [descriptor(layer) for layer in manifest["layers"]]}


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


def verified_staging_archive(archive, staged, expected, uid, gid):
    """Stage only the verified OCI objects with tar ownership matching the publisher UID."""
    blob_digests = [expected["manifest"], expected["config"][0], *(layer[0] for layer in expected["layers"])]
    members = ["oci-layout", "index.json", *("blobs/sha256/" + digest[7:] for digest in dict.fromkeys(blob_digests))]
    require(digest_file(archive) == expected["archive_sha256"], "demo_a_oci_source_changed")
    with tarfile.open(archive, "r:") as source, tarfile.open(staged, "x:", format=tarfile.USTAR_FORMAT) as output:
        for name in ("blobs", "blobs/sha256"):
            directory = tarfile.TarInfo(name)
            directory.type, directory.mode, directory.uid, directory.gid = tarfile.DIRTYPE, 0o755, uid, gid
            output.addfile(directory)
        for name in members:
            original = source.getmember(name)
            require(original.isfile() and 0 < original.size <= INPUT_LIMIT, "demo_a_oci_staging_member")
            clean = tarfile.TarInfo(name)
            clean.size, clean.mode, clean.uid, clean.gid = original.size, 0o444, uid, gid
            with source.extractfile(original) as body:
                output.addfile(clean, body)
    check_staging_archive(staged, expected)
    require(digest_file(archive) == expected["archive_sha256"], "demo_a_oci_source_changed")


def check_staging_archive(staged, expected):
    staged_hash = digest_file(staged)
    require(archive_inventory(staged, (expected["manifest"], staged_hash)) == {**expected, "archive_sha256": staged_hash},
            "demo_a_oci_staging_content_changed")


def verify_registry(destination, expected, authorization=None, *, ca=None):
    host, path = destination.split("/", 1)
    repository, digest = path.rsplit("@", 1)
    require(re.fullmatch(r"[a-z0-9.-]+(?::[0-9]+)?", host) and re.fullmatch(r"[a-z0-9/_-]+", repository)
            and digest == expected["manifest"], "demo_a_registry_postcheck_target")
    opener = build_opener(ProxyHandler({}), transport.NoRedirect(), HTTPSHandler(context=ssl.create_default_context(cafile=ca)))
    headers = {"Accept": expected["media_type"]}
    if authorization is not None:
        headers["Authorization"] = authorization
    base = f"https://{host}/v2/{repository}/"
    resources = [("manifests", expected["manifest"], expected["manifest_size"]),
                 ("blobs", *expected["config"]), *(("blobs", *layer) for layer in expected["layers"])]
    for kind, wanted, size in resources:
        url = base + kind + "/" + wanted
        try:
            with closing(opener.open(Request(url, headers=headers), timeout=60)) as response:
                claimed = response.headers.get("Docker-Content-Digest")
                require(claimed in {None, wanted}, "demo_a_registry_header_digest")
                got, length = digest_stream(response, size)
            require("sha256:" + got == wanted and length == size, "demo_a_registry_content_digest")
        except HTTPError as error:
            status = error.code
            error.close()
            raise transport.Failure("demo_a_registry_read_failed", {"http_status": status, "digest": wanted, "record": kind}) from None


def verify_build(bundle, proof, inventory):
    require(proof["build_sha256"] == PUBLISHER_BUILD_SHA256, "demo_a_exact_publisher_build_receipt")
    provenance = preflight.json_bytes(bundle, "publisher-build.json", proof["build_sha256"], limit=65536)
    require(provenance["schema"] == "clipforge-int-demo-a-publisher-build-1"
            and provenance["skopeo_release"] == "1.25.2" and provenance["source_commit"] == PUBLISHER_REVISION
            and provenance["manifest"] == proof["manifest"] and provenance["config"] == proof["config"]
            and provenance["offline_build"] is True and provenance["runtime_files"] == PUBLISHER_FILES
            and provenance["build_info_sha256"] == PUBLISHER_BUILD_INFO_SHA256, "demo_a_publisher_build_provenance")
    raw = transport._local_bytes(bundle / "publisher-go-build-info.txt", limit=65536)
    info = raw.decode().splitlines()
    modules = {tuple(line.split()[1:3]) for line in info if line.split()[:1] == ["dep"]}
    require(transport.sha(raw) == PUBLISHER_BUILD_INFO_SHA256 and info[0] == "/build/skopeo: go1.27.4"
            and ("github.com/go-jose/go-jose/v4", "v4.1.9") in modules
            and ("go.opentelemetry.io/otel/trace", "v1.47.0") in modules,
            "demo_a_publisher_compiled_go_closure")
    observed = {}
    with tarfile.open(bundle / "publisher.oci.tar", "r:") as archive:
        for digest, _ in inventory["layers"]:
            with archive.extractfile("blobs/sha256/" + digest[7:]) as layer:
                with tarfile.open(fileobj=layer, mode="r|*") as files:
                    for member in files:
                        name = member.name.removeprefix("./")
                        if name in PUBLISHER_FILES:
                            require(member.isfile() and name not in observed, "demo_a_publisher_file_layer_shape")
                            with files.extractfile(member) as data:
                                observed[name] = digest_stream(data, member.size)[0]
    require(observed == PUBLISHER_FILES, "demo_a_publisher_runtime_files_changed")


def verify_tool(bundle, proof):
    fields = {"manifest", "archive_sha256", "config", "build_sha256", "scan_sha256", "lab_sha256"}
    require(isinstance(proof, dict) and set(proof) == fields and all(re.fullmatch(preflight.SHA, proof[k])
            for k in ("archive_sha256", "build_sha256", "scan_sha256", "lab_sha256")) and DIGEST.fullmatch(proof["manifest"])
            and DIGEST.fullmatch(proof["config"]), "demo_a_exact_publisher_review")
    manifest, archived = proof["manifest"], proof["archive_sha256"]
    inventory = archive_inventory(bundle / "publisher.oci.tar", (manifest, archived))
    require(inventory["config"][0] == proof["config"], "demo_a_publisher_config_scope")
    verify_build(bundle, proof, inventory)
    scan = preflight.json_bytes(bundle, "publisher-grype.json", proof["scan_sha256"])
    require(scan["source"]["target"]["imageID"] == proof["config"] and scan["source"]["target"]["manifestDigest"] == manifest
            and scan["descriptor"]["name"] == "grype" and scan["descriptor"]["version"] == "0.122.1"
            and scan["descriptor"]["db"]["status"]["valid"] is True
            and isinstance(scan["matches"], list) and not scan.get("ignoredMatches"), "demo_a_publisher_scan_scope")
    require(all(row["vulnerability"]["severity"] in {"Low", "Medium", "Negligible"} for row in scan["matches"]),
            "demo_a_publisher_blocking_vulnerability")
    lab = preflight.json_bytes(bundle, "publisher-lab.json", proof["lab_sha256"], limit=65536)
    require(lab["status"] == "tls_copy_verified" and lab["publisher_manifest"] == manifest and lab["publisher_config"] == proof["config"]
            and lab["images"] == {target: list(expected) for target, expected in TARGETS.items()}
            and all(lab[k] is True for k in ("read_only_source", "bad_authority_rejected", "wrong_hostname_rejected",
                                             "manifest_config_layers_verified", "index_fanout_rejected", "source_unchanged"))
            and lab["cloud_credentials_used"] is False, "demo_a_publisher_lab_requirements")
    return proof


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


def execute(bundle, env, decision, approval_hash, tool, images):
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
        report["error_code"] = str(error) if isinstance(error, transport.Blocked) else type(error).__name__
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


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "stage", "execute"))
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--decision-sha256", required=True)
    args = parser.parse_args(argv)
    env = os.environ
    try:
        decision = preflight.local_decision(args.bundle, args.decision_sha256, OPERATION, WORKFLOW, env, protected=args.phase != "local")
        inputs = decision["inputs"]
        require(set(inputs) == {"publisher", "targets", "docker_toolchain_sha256"} and inputs["targets"] == list(TARGETS), "demo_a_two_targets_bound")
        engine_proof = preflight.json_bytes(args.bundle, "docker-toolchain.json", inputs["docker_toolchain_sha256"], limit=65536)
        require(engine_proof["schema"] == docker_identity.SCHEMA, "demo_a_docker_proof_schema")
        tool = verify_tool(args.bundle, inputs["publisher"])
        images = {target: archive_inventory(args.bundle / (target + ".oci.tar"), approved) for target, approved in TARGETS.items()}
        if args.phase != "local":
            docker_identity.verify(engine_proof)
        if args.phase == "stage":
            stage(args.bundle, env, tool["config"], images)
        if args.phase != "execute":
            print(json.dumps({"status": "validated", "targets": list(images), "activation_authorized": False}))
            return 0
        report = execute(args.bundle, env, decision, args.decision_sha256, tool, images)
        print(json.dumps(report))
        return int(report["status"] != "published_and_verified")
    except (transport.Blocked, ValueError, TypeError, OSError, KeyError, tarfile.TarError, subprocess.SubprocessError) as error:
        code = str(error) if isinstance(error, transport.Blocked) else type(error).__name__
        print(json.dumps({"status": "blocked", "error_code": code}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
