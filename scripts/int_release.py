"""Private immutable INT plan custody and explicit, same-plan release preparation.

No command runs on import. Cloud calls require the current Actions WIF token.
Only the authorized bucket/private-plans/int namespace can receive plan objects;
state writes, object replacement/deletion and public artifacts are not supported.
"""
from __future__ import annotations

import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from datetime import datetime, timezone
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, build_opener, ProxyHandler

try:
    from scripts import check_tf_int as c
except ModuleNotFoundError:
    import check_tf_int as c

PREFIX = "private-plans/int/"
LIMIT = 64 * 1024 * 1024
SCHEMA = "clipforge-int-e2e-private-plan-1"


def sha256(value):
    return hashlib.sha256(value).hexdigest()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def inputs(environ):
    stage = environ.get("INT_STAGE", "foundation")
    c.require(stage in {"foundation", "runtime"}, "Unknown reviewed phase")
    value = c.runtime_inputs(environ.get("RUNTIME_IMAGE", ""), json.loads(environ.get("SECRET_VERSIONS_JSON", "null")), stage)
    machine = environ.get("MACHINE_TYPE", "e2-micro")
    c.require(machine in {"e2-micro", "e2-small"}, "Unexpected machine profile")
    result = {**value, "machine_type": machine, "stage": stage}
    if stage == "runtime":
        reference = json.loads(environ.get("FOUNDATION_RECEIPT_JSON", "null"))
        c.require(isinstance(reference, dict) and set(reference) == {"name", "generation", "sha256", "size"},
                  "Runtime requires an explicit owner-reviewed foundation receipt reference")
        object_name(reference["name"])
        c.require(reference["name"].endswith("/foundation-state.json") and bool(re.fullmatch(r"[1-9][0-9]*", reference["generation"]))
                  and bool(re.fullmatch(r"[a-f0-9]{64}", reference["sha256"])) and 0 < reference["size"] <= 65536,
                  "Runtime requires the exact owner-reviewed foundation receipt name/generation/SHA/size")
        result["foundation_receipt"] = reference
    return result


def source_binding(module, environ):
    commit = environ.get("GITHUB_SHA", "")
    c.require(bool(re.fullmatch(r"[a-f0-9]{40}", commit)), "An exact source commit is required")
    config = {name: sha256((module / name).read_bytes()) for name in c.FILES}
    return {"commit": commit, "inputs": inputs(environ), "configuration_sha256": sha256(canonical(config)),
            "provider_lock_sha256": config[".terraform.lock.hcl"], "terraform_version": "1.15.8",
            "repository": "AldemaroCruz/ClipForge", "branch": "ci/bootstrap-sec03"}


def hosted_context(environ):
    expected = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted"}
    c.require(all(environ.get(k) == v for k, v in expected.items()), "Only the protected hosted INT dispatch is supported")
    c.require(bool(environ.get("GCP_ACCESS_TOKEN")), "Current WIF access token is required")


def object_name(name):
    c.require(isinstance(name, str) and bool(re.fullmatch(
        r"private-plans/int/[a-f0-9]{40}/[1-9][0-9]*-[1-9][0-9]*/(?:int\.tfplan|int\.json|manifest\.json|foundation-state\.json)", name)),
        "Unreviewed private plan object name")
    return name


def request(method, name, *, generation=None, payload=None):
    """Restricted Storage JSON API; create-only uploads and generation-pinned reads."""
    from scripts.tf_int_plan import NoRedirect
    object_name(name)
    c.require(method in {"GET", "POST"}, "Plan custody forbids replacement, deletion and state writes")
    headers = {"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]}
    if method == "POST":
        c.require(payload is not None and len(payload) <= LIMIT, "Private plan exceeds the upload bound")
        url = "https://storage.googleapis.com/upload/storage/v1/b/" + c.BUCKET + "/o?" + urlencode(
            {"uploadType": "media", "name": name, "ifGenerationMatch": "0", "fields": "name,generation,size"})
        headers["Content-Type"] = "application/octet-stream"
    elif method == "GET":
        c.require(bool(re.fullmatch(r"[1-9][0-9]*", str(generation))), "Read must pin an immutable generation")
        url = "https://storage.googleapis.com/storage/v1/b/" + c.BUCKET + "/o/" + quote(name, safe="") + "?" + urlencode(
            {"alt": "media", "generation": generation, "ifGenerationMatch": generation})
    else:
        raise ValueError("Plan custody supports create-only POST and pinned GET, never state writes or deletion")
    try:
        with build_opener(ProxyHandler({}), NoRedirect()).open(Request(url, data=payload, method=method, headers=headers), timeout=120) as response:
            raw = response.read(LIMIT + 1)
        c.require(len(raw) <= LIMIT, "Private plan response exceeds bound")
        return raw
    except HTTPError as error:
        # Response bodies can contain configuration; never send them to logs.
        raise ValueError("Private plan storage " + method + " failed with HTTP " + str(error.code)) from None


def upload(name, raw):
    result = json.loads(request("POST", name, payload=raw))
    c.require(result.get("name") == name and bool(re.fullmatch(r"[1-9][0-9]*", str(result.get("generation", ""))))
              and str(result.get("size")) == str(len(raw)), "Immutable upload receipt mismatch")
    return {"name": name, "generation": str(result["generation"]), "sha256": sha256(raw), "size": len(raw)}


def retain_plan(work, backend, environ):
    hosted_context(environ)
    expected = "recognized_initial_state" if environ.get("INT_STAGE", "foundation") == "foundation" else "recognized_approved_foundation_state"
    c.require(backend.get("classification") == expected, "Only the explicitly reviewed phase backend may be bound")
    binding = source_binding(work / "module", environ)
    run, attempt = environ.get("GITHUB_RUN_ID", ""), environ.get("GITHUB_RUN_ATTEMPT", "")
    c.require(bool(re.fullmatch(r"[1-9][0-9]*", run)) and bool(re.fullmatch(r"[1-9][0-9]*", attempt)), "Exact run/attempt required")
    base = PREFIX + binding["commit"] + "/" + run + "-" + attempt + "/"
    manifest = {"schema": SCHEMA, **binding,
                "backend": backend_binding(backend),
                "created_utc": datetime.now(timezone.utc).isoformat(), "run_id": run, "run_attempt": attempt,
                "runtime_published": False, "approval": "pending_new_manual_int_approval"}
    # Separate namespace in the existing private bucket; never in the backend prefix.
    manifest["binary"] = upload(base + "int.tfplan", (work / "int.tfplan").read_bytes())
    manifest["json"] = upload(base + "int.json", (work / "private-plan.json").read_bytes())
    reference = upload(base + "manifest.json", canonical(manifest))
    return {"bucket": c.BUCKET, "manifest": reference, "binary": manifest["binary"], "json": manifest["json"],
            "commit": binding["commit"], "backend_lineage": manifest["backend"]["lineage"],
            "backend_serial": manifest["backend"]["serial"], "runtime_published": False,
            "apply_requires": "new manual INT approval, current application CI success, reviewed findings and exact digest publication"}


def fetch_verified(reference):
    c.require(set(reference) == {"name", "generation", "sha256", "size"}, "Unexpected private object reference")
    c.require(bool(re.fullmatch(r"[a-f0-9]{64}", reference["sha256"])), "Expected SHA-256 is required")
    raw = request("GET", reference["name"], generation=reference["generation"])
    c.require(len(raw) == reference["size"] and sha256(raw) == reference["sha256"], "Private object generation or SHA-256 mismatch")
    return raw


def backend_binding(backend):
    return {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
            "lineage": backend.get("initial_lineage", backend.get("lineage")),
            "serial": backend.get("state_serial", 1),
            "state_generation": next((o["generation"] for o in backend.get("live", []) if o["name"] == c.PREFIX + "/default.tfstate"), None),
            "state_sha256": backend.get("initial_state_sha256", backend.get("state_sha256"))}


def verify_manifest(manifest, module, environ, backend):
    c.require(manifest.get("schema") == SCHEMA, "Unexpected private plan manifest")
    for key, value in source_binding(module, environ).items():
        c.require(manifest.get(key) == value, "Stale or incompatible plan binding: " + key)
    expected_class = "recognized_initial_state" if manifest["inputs"]["stage"] == "foundation" else "recognized_approved_foundation_state"
    c.require(backend.get("classification") == expected_class and manifest.get("backend") == backend_binding(backend),
              "Backend generation, lineage, serial or state bytes changed after planning")
    created = datetime.fromisoformat(manifest["created_utc"])
    age = (datetime.now(timezone.utc) - created).total_seconds()
    c.require(0 <= age <= 24 * 3600, "Plan expired; review a new plan instead of silently replanning")
    prefix = PREFIX + manifest["commit"] + "/" + manifest["run_id"] + "-" + manifest["run_attempt"] + "/"
    c.require(manifest["binary"]["name"] == prefix + "int.tfplan" and manifest["json"]["name"] == prefix + "int.json",
              "Private manifest object bindings differ")


def require_application_ci(environ):
    """Every mutating workflow verifies the existing application CI for this SHA."""
    token = environ.get("GH_TOKEN", "")
    c.require(bool(token), "Read-only GitHub Actions token required to verify existing application CI")
    url = "https://api.github.com/repos/AldemaroCruz/ClipForge/actions/workflows/ci.yml/runs?" + urlencode(
        {"head_sha": environ["GITHUB_SHA"], "branch": "ci/bootstrap-sec03", "per_page": "100"})
    from scripts.tf_int_plan import NoRedirect
    with build_opener(ProxyHandler({}), NoRedirect()).open(Request(url, headers={"Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}), timeout=60) as response:
        raw = response.read(1024 * 1024 + 1)
    c.require(len(raw) <= 1024 * 1024, "CI verification response exceeds bound")
    runs = json.loads(raw).get("workflow_runs", [])
    matching = [r for r in runs if r.get("head_sha") == environ["GITHUB_SHA"] and r.get("head_branch") == "ci/bootstrap-sec03"]
    c.require(bool(matching), "No existing application CI evidence for this exact commit")
    latest = max(matching, key=lambda row: (row["run_number"], row["run_attempt"]))
    c.require(latest.get("status") == "completed" and latest.get("conclusion") == "success",
              "Existing application CI blocks INT mutation; scanners and thresholds remain unchanged")


def execute_job(environ):
    """Fixed job, no overrides; retries/interruption are handled by durable app state."""
    import time
    from scripts.tf_int_plan import NoRedirect
    hosted_context(environ)
    c.require(environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"), "Exact owner-approved commit required")
    require_application_ci(environ)
    name = environ.get("INT_JOB", "")
    c.require(name in {"worker", "migrate", "bootstrap"}, "Only reviewed INT jobs are allowed")
    base = "https://run.googleapis.com/v2/"
    resource = "projects/clipforgebeta2/locations/us-central1/jobs/clipforge-int-" + name
    headers = {"Authorization": "Bearer " + environ["GCP_ACCESS_TOKEN"], "Content-Type": "application/json"}
    opener = build_opener(ProxyHandler({}), NoRedirect())
    with opener.open(Request(base + resource + ":run", data=b"{}", headers=headers, method="POST"), timeout=60) as response:
        result = json.loads(response.read(65537))
    operation = result.get("name", "")
    c.require(bool(re.fullmatch(r"projects/clipforgebeta2/locations/us-central1/operations/[A-Za-z0-9_-]+", operation)), "Unreviewed Job operation")
    for _ in range(180):
        if result.get("done"):
            c.require(not result.get("error"), "Cloud Run Job failed; preserve its private execution diagnostics")
            print(json.dumps({"job": "clipforge-int-" + name, "operation": operation, "status": "completed"}))
            return
        time.sleep(5)
        with opener.open(Request(base + operation, headers=headers), timeout=60) as response:
            result = json.loads(response.read(65537))
    raise ValueError("Cloud Run Job completion not confirmed; do not retry automatically")


def apply_saved(work, reports, manifest_reference, environ):
    """Prepared only. Call solely after explicit owner dispatch + a NEW int approval."""
    from scripts import tf_int_plan as driver
    hosted_context(environ)
    c.require(environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"), "Explicit owner confirmation must name this exact commit")
    require_application_ci(environ)
    manifest = json.loads(fetch_verified(manifest_reference))
    bucket = driver.metadata("/b/" + c.BUCKET, {"fields": "name,projectNumber,iamConfiguration,versioning,softDeletePolicy"})
    receipt = {"status": "apply_preflight", "checks": {}}
    from scripts import int_release_state
    def inspect():
        if manifest.get("inputs", {}).get("stage") == "runtime":
            return int_release_state.inspect_approved_foundation(bucket, work / "module", environ)
        return driver.inspect_backend(bucket, work, reports, receipt)
    backend = inspect()
    verify_manifest(manifest, work / "module", environ, backend)
    # Publication is checked against the registry manifest itself, never an image ID.
    if manifest["inputs"]["stage"] == "runtime":
        verify_published_runtime(manifest["inputs"]["runtime_image"], environ)
    target = work / "approved.tfplan"
    with target.open("xb") as stream:
        stream.write(fetch_verified(manifest["binary"]))
    target.chmod(0o600)
    binary = driver.terraform_binary()
    driver.run([binary, "init", "-input=false", "-lockfile=readonly", "-reconfigure", "-no-color", "-backend-config=backend-int.hcl"], "apply_init", work)
    # Detect changes during init; Terraform also checks stale state under its native lock.
    verify_manifest(manifest, work / "module", environ, inspect())
    driver.run([binary, "apply", "-input=false", "-no-color", "-lock=true", "-lock-timeout=120s", str(target)], "approved_same_plan_apply", work)
    if manifest["inputs"]["stage"] == "foundation":
        receipt["foundation_receipt"] = int_release_state.emit_foundation_receipt(work, manifest, manifest_reference, environ)
        receipt["status"] = "foundation_applied_runtime_not_approved"
        driver.save_summary(reports, receipt)
    print("Applied only the exact approved immutable binary plan; cloud acceptance remains separate.")


def verify_published_runtime(image, environ):
    c.runtime_inputs(image, inputs(environ)["secret_versions"])
    digest = image.rsplit("@", 1)[1]
    url = "https://us-central1-docker.pkg.dev/v2/clipforgebeta2/clipforge-int/runtime/manifests/" + digest
    from scripts.tf_int_plan import NoRedirect
    with build_opener(ProxyHandler({}), NoRedirect()).open(Request(url, headers={"Authorization": "Bearer " + environ["GCP_ACCESS_TOKEN"],
            "Accept": "application/vnd.oci.image.manifest.v1+json, application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.v2+json"}), timeout=60) as response:
        raw = response.read(4 * 1024 * 1024 + 1)
        header_digest = response.headers.get("Docker-Content-Digest")
    c.require(len(raw) <= 4 * 1024 * 1024 and "sha256:" + sha256(raw) == digest and header_digest == digest,
              "The exact reviewed OCI manifest is not published or its registry digest differs")


def main(argv=None):
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=["apply", "gate", "job"])
    args = parser.parse_args(argv)
    os.umask(0o077)
    hosted_context(os.environ)
    if args.operation == "gate":
        c.require(os.environ.get("INT_APPROVED_COMMIT") == os.environ.get("GITHUB_SHA"), "Exact owner-approved commit required")
        require_application_ci(os.environ)
    elif args.operation == "job":
        execute_job(os.environ)
    else:
        from scripts.tf_int_plan import private_paths
        work, reports = private_paths()
        reference = json.loads(os.environ["PLAN_MANIFEST_JSON"])
        apply_saved(work, reports, reference, os.environ)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, HTTPError, KeyError, subprocess.SubprocessError):
        # No raw HTTP/plan/secret/registry response reaches workflow logs.
        print("INT release blocked; private preflight failed. No automatic retry or replacement plan.")
        raise SystemExit(1)
