"""Scope the beta rollout and bind scan results to the published OCI archives."""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import tarfile

from scripts.int_hito_a_scan import (
    BLOCKING, CONFIG_MEDIA_TYPES, MAX_CONFIG, TRIVY_VERSION, ScanBlocked,
)
from scripts.int_hito_a_scan import parse_time, read_descriptor, require, tar_members
from scripts.int_release_image import archive_digest


TARGETS = ("web", "worker")
ADDRESSES = {
    "google_cloud_run_v2_service.api",
    "google_cloud_run_v2_service.frontend",
    "google_cloud_run_v2_service_iam_member.frontend_invokes_api",
    'google_cloud_run_v2_job.task["worker"]',
    'google_cloud_run_v2_job.task["migrate"]',
    "google_cloud_run_v2_job_iam_member.api_invokes_worker",
    "google_cloud_run_v2_job_iam_member.deploy_invokes_migrate",
}
REGISTRY = "us-central1-docker.pkg.dev"
REPOSITORY = REGISTRY + "/clipforgebeta2/clipforge-int"


def json_text(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def file_hash(path):
    require(path.is_file() and not path.is_symlink(), "candidate_file")
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def report_hashes(images, reports, commit, check_scans):
    require(re.fullmatch(r"[0-9a-f]{40}", commit), "candidate_commit")
    require({path.name for path in images.iterdir()} == {f"{target}.tar" for target in TARGETS},
            "candidate_archive_inventory")
    result = {"commit": commit, "images": {}}
    for target in TARGETS:
        path = images / f"{target}.tar"
        digest = archive_digest(path)
        with tarfile.open(path, "r") as archive:
            members = tar_members(archive)
            manifest = json.load(archive.extractfile(members["blobs/sha256/" + digest[7:]]))
            config_descriptor = manifest["config"]
            config_raw, _ = read_descriptor(archive, members, config_descriptor, MAX_CONFIG, "candidate_config")
            config = json.loads(config_raw)
        require(config_descriptor["mediaType"] in CONFIG_MEDIA_TYPES
                and config["os"] == "linux" and config["architecture"] == "amd64"
                and config["config"].get("User") == "10001:10001"
                and config["config"]["Labels"]["org.opencontainers.image.revision"] == commit,
                "candidate_image_config")
        if check_scans:
            scan_check(reports, target, config_descriptor["digest"], config)
        result["images"][target] = {
            "archive_sha256": file_hash(path), "bytes": path.stat().st_size,
            "image": f"{REPOSITORY}/beta-{target}@{digest}",
        }
    return result


def scan_check(reports, target, config_digest, config):
    report = json.loads((reports / f"trivy-{target}.json").read_bytes())
    require(report["SchemaVersion"] == 2 and report["Trivy"]["Version"] == TRIVY_VERSION,
            "candidate_trivy_version")
    metadata = report["Metadata"]
    require(metadata["ImageID"] == config_digest and metadata["DiffIDs"] == config["rootfs"]["diff_ids"]
            and metadata["OS"]["Family"] == "ubuntu" and metadata["OS"]["Name"].startswith("24.04"),
            "candidate_trivy_identity")
    created = parse_time(report["CreatedAt"], "trivy_created")
    delta = datetime.now(timezone.utc) - created
    require(-timedelta(minutes=5) <= delta <= timedelta(hours=2), "candidate_trivy_freshness")
    results = report["Results"]
    inventory = {row["Type"] for row in results if row.get("Packages")}
    require({"ubuntu", "python-pkg"} <= inventory, "candidate_trivy_inventory")
    allowed = all(not row.get("Secrets") and not row.get("Misconfigurations")
                  and all(vuln["Severity"] not in BLOCKING for vuln in (row.get("Vulnerabilities") or ()))
                  for row in results)
    require(allowed, "candidate_trivy_findings_" + target)
    sbom = json.loads((reports / f"sbom-{target}.cdx.json").read_bytes())
    require(sbom["bomFormat"] == "CycloneDX" and len(sbom["components"]) >= 2,
            "candidate_sbom")


def plan_summary(plan, output):
    require(not plan.get("errored") and plan.get("complete") is True, "beta_plan_incomplete")
    rows = []
    addresses = set()
    for row in plan["resource_changes"]:
        actions = row["change"]["actions"]
        require(row["address"] in ADDRESSES and row["address"] not in addresses
                and actions in (["create"], ["update"], ["no-op"]), "beta_plan_scope")
        addresses.add(row["address"])
        rows.append({"address": row["address"], "actions": actions})
    require(addresses == ADDRESSES, "beta_plan_resource_inventory")
    output.write_text(json_text(rows) + "\n", encoding="utf-8")


def registry_auth(path):
    token = os.environ["GCP_ACCESS_TOKEN"]
    require(1 <= len(token) <= 8192 and not any(value.isspace() for value in token), "registry_token")
    value = base64.b64encode(("oauth2accesstoken:" + token).encode()).decode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
        json.dump({"auths": {REGISTRY: {"auth": value}}}, stream)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("receipt", "verify", "plan", "registry-auth"))
    parser.add_argument("path", type=Path)
    parser.add_argument("reports", nargs="?", type=Path)
    args = parser.parse_args()
    try:
        if args.action == "plan":
            plan_summary(json.load(sys.stdin), args.path)
        elif args.action == "registry-auth":
            registry_auth(args.path)
        else:
            receipt = report_hashes(args.path, args.reports, os.environ["GITHUB_SHA"], args.action == "receipt")
            if args.action == "receipt":
                with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8") as stream:
                    print("receipt=" + json_text(receipt), file=stream)
            else:
                require(receipt == json.loads(os.environ["CANDIDATE_RECEIPT"]), "artifact_changed")
            (args.reports / "candidate.json").write_text(json_text(receipt) + "\n", encoding="utf-8")
        return 0
    except ScanBlocked as error:
        print("Hito B delivery evidence rejected: " + str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, KeyError, TypeError, tarfile.TarError):
        print("Hito B delivery evidence rejected during " + args.action, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
