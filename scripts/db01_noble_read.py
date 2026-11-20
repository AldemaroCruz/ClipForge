"""Observe the exact Noble refresh reads and serial-7 state without invoking Terraform."""

from concurrent.futures import ThreadPoolExecutor
import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.request import ProxyHandler, Request, build_opener

from scripts import db01_noble_plan as noble
from scripts import int_iap_diagnostic as historical


C = noble.contract
DRIVER = noble.driver
PROJECT = f"projects/{C.PROJECT}"
ZONE = f"{PROJECT}/zones/{historical.IDENTITY['zone']}"
REGION = f"{PROJECT}/regions/{C.REGION}"
COMPUTE = "https://compute.googleapis.com/compute/v1/"
SECRET = "https://secretmanager.googleapis.com/v1/"
STORAGE = "https://storage.googleapis.com/storage/v1/b/"
POLICY_QUERY = "?options.requestedPolicyVersion=3"
POLICY_BODY = {"options": {"requestedPolicyVersion": 3}}
BODY_LIMIT = 1024 * 1024
BOOT_DISK = ZONE + "/disks/clipforge-int-base-postgres"
NUMERIC_PROJECT = "projects/816643438938"
OPTIONAL = {BOOT_DISK, NUMERIC_PROJECT}


def get(permission, resource, url, query=""):
    return permission, resource, "GET", url + query, None


def policy(permission, resource, url):
    return permission, resource, "POST", url + ":getIamPolicy", POLICY_BODY


STABLE_PROBES = (
    *((permission, resource, method, url, body) for _, method, url, body, permission, resource in historical.READ_TARGETS),
    policy("iap.tunnelInstances.getIamPolicy", historical.ROUTES["numeric"],
           "https://iap.googleapis.com/v1/" + historical.ROUTES["numeric"]),
)
PROBES = (
    *STABLE_PROBES,
    get("resourcemanager.projects.get", PROJECT, "https://cloudresourcemanager.googleapis.com/v1/" + PROJECT),
    get("resourcemanager.projects.get", PROJECT, "https://cloudbilling.googleapis.com/v1/" + PROJECT + "/billingInfo",
        "?fields=projectId,billingEnabled"),
    policy("resourcemanager.projects.getIamPolicy", PROJECT, "https://cloudresourcemanager.googleapis.com/v1/" + PROJECT),
    get("artifactregistry.repositories.get", PROJECT + "/locations/us-central1/repositories/clipforge-int",
        "https://artifactregistry.googleapis.com/v1/" + PROJECT + "/locations/us-central1/repositories/clipforge-int"),
    get("iam.workloadIdentityPoolProviders.get", PROJECT + "/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
        "https://iam.googleapis.com/v1/projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github"),
    *(get("iam.serviceAccounts.get", f"{PROJECT}/serviceAccounts/{account}",
          "https://iam.googleapis.com/v1/projects/-/serviceAccounts/" + account)
      for account in (f"clipforge-{name}-int@{C.PROJECT}.iam.gserviceaccount.com"
                      for name in ("terraform", "deploy", "api", "worker", "migrate", "postgres"))),
    *(probe for resource in (f"{PROJECT}/secrets/clipforge-int-pg-{kind}-password" for kind in ("app", "migrator"))
      for probe in (get("secretmanager.secrets.get", resource, SECRET + resource),
                    get("secretmanager.secrets.getIamPolicy", resource, SECRET + resource + ":getIamPolicy", POLICY_QUERY))),
    *(probe for bucket in (f"clipforgebeta2-int-{name}" for name in ("media", "backups"))
      for probe in (get("storage.buckets.get", "buckets/" + bucket, STORAGE + bucket, "?fields=name"),
                    get("storage.buckets.getIamPolicy", "buckets/" + bucket, STORAGE + bucket + "/iam", "?optionsRequestedPolicyVersion=3"))),
    *(get("compute." + collection + ".get", scope + "/" + collection + "/" + name,
          COMPUTE + scope + "/" + collection + "/" + name, "?fields=name,id")
      for scope, collection, name in (
          (PROJECT + "/global", "networks", "clipforge-int-base"),
          (PROJECT + "/global", "routes", "clipforge-int-base-egress"),
          (PROJECT + "/global", "firewalls", "clipforge-int-base-deny-other-egress"),
          (PROJECT + "/global", "firewalls", "clipforge-int-base-iap-ssh"),
          (PROJECT + "/global", "firewalls", "clipforge-int-base-maintenance-https"),
          (PROJECT + "/global", "firewalls", "clipforge-int-base-pg-from-run"),
          (REGION, "subnetworks", "clipforge-int-base-run"),
          (REGION, "subnetworks", "clipforge-int-base-postgres"),
          (REGION, "routers", "clipforge-int-base-egress"),
          (REGION, "addresses", "clipforge-int-base-postgres"),
          (ZONE, "instances", "clipforge-int-base-postgres"),
          (ZONE, "disks", "clipforge-int-base-postgres-data"),
      )),
    get("compute.disks.get", BOOT_DISK, COMPUTE + BOOT_DISK, "?fields=name,id"),
    get("compute.projects.get", NUMERIC_PROJECT, COMPUTE + NUMERIC_PROJECT, "?fields=name,id"),
    get("compute.instances.getIamPolicy", ZONE + "/instances/clipforge-int-base-postgres",
        COMPUTE + ZONE + "/instances/clipforge-int-base-postgres/getIamPolicy", "?optionsRequestedPolicyVersion=3"),
    *(get("compute.images.get", resource, COMPUTE + resource, "?fields=name,id,status")
      for resource in ("projects/debian-cloud/global/images/debian-13-trixie-v20261116",
                       "projects/ubuntu-os-cloud/global/images/ubuntu-2404-noble-amd64-v20261105")),
)


def timestamp():
    return datetime.now(timezone.utc).isoformat()


def explicit_denial(raw, permission):
    """Attribute only literal IAM errors for the permission tied to the fixed request."""
    try:
        error = json.loads(raw)["error"]
        if any(isinstance(detail, dict) and detail.get("reason") == "IAM_PERMISSION_DENIED"
               and detail.get("metadata", {}).get("permission") == permission for detail in error.get("details", [])):
            return True
        return bool(re.search(r"\bPermission ['\"]" + re.escape(permission) + r"['\"] (?:denied|is denied)\b",
                              error.get("message", ""), re.IGNORECASE))
    except (KeyError, AttributeError, TypeError, ValueError):
        return False


def probe(target, token, reason):
    permission, resource, method, url, body = target
    request = Request(url, method=method, data=noble.custody.canonical(body) if body else None,
                      headers={"Authorization": "Bearer " + token, "Content-Type": "application/json",
                               "X-Goog-Request-Reason": reason})
    row = {"permission": permission, "resource": resource, "method": method, "endpoint": url.split("?")[0],
           "required_for_refresh": resource not in OPTIONAL,
           "observed_utc": timestamp()}
    try:
        with build_opener(ProxyHandler({}), DRIVER.NoRedirect()).open(request, timeout=15) as response:
            raw = response.read(BODY_LIMIT + 1)
            code = response.status
        result = "allowed" if code == 200 and len(raw) <= BODY_LIMIT and isinstance(json.loads(raw), dict) else "invalid"
        return {**row, "http_status": code, "result": result}
    except HTTPError as error:
        raw = b""
        try:
            with error:
                raw = error.read(16385)
        except OSError:
            pass
        denied = error.code == 403 and len(raw) <= 16384 and explicit_denial(raw, permission)
        return {**row, "http_status": error.code, "result": "denied" if denied else "http_error"}
    except (OSError, ValueError) as error:
        return {**row, "result": "unverified", "error_type": type(error).__name__}


def state_postcheck():
    """Validate the pinned payload in memory and recheck live state and lock after reading."""
    try:
        identity = noble.state_identity()
    except Exception as error:
        state = {"result": "unverified", "error_type": type(error).__name__}
        if isinstance(error, HTTPError):
            state["http_status"] = error.code
        elif isinstance(error, DRIVER.FailedOperation):
            state["http_status"] = error.receipt["status"]
        identity = None
    else:
        state = {"result": "verified", **identity}
    try:
        live = DRIVER.metadata("/b/" + C.BUCKET + "/o", {
            "prefix": C.PREFIX + "/", "maxResults": "10", "fields": "nextPageToken,items(name,generation,size)",
        })
        rows = live.get("items", [])
        C.require(not live.get("nextPageToken") and isinstance(rows, list), "Incomplete postcheck inventory")
        state["current_lock_absent"] = not any(row["name"] == DRIVER.LOCK_NAME for row in rows)
        if identity:
            expected = [{"name": identity["name"], "generation": identity["generation"], "size": str(identity["size"])}]
            C.require(rows == expected, "State or lock changed during postcheck")
    except Exception as error:
        state.update(result="unverified", inventory_error=type(error).__name__)
        # A preliminary check is not proof of current absence.
        if state.get("current_lock_absent") is not False:
            state.pop("current_lock_absent", None)
    return {**state, "observed_utc": timestamp()}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", nargs="?", choices=("observe", "stable-precheck"), default="observe")
    operation = parser.parse_args(argv).operation
    noble.custody.hosted_context(os.environ)
    C.validate_variables(os.environ)
    commit = os.environ["GITHUB_SHA"]
    run = os.environ["GITHUB_RUN_ID"]
    attempt = os.environ["GITHUB_RUN_ATTEMPT"]
    stable = operation == "stable-precheck"
    workflow = "int-db01-noble-plan.yml" if stable else "int-db01-noble-read.yml"
    C.require(os.environ.get("GITHUB_WORKFLOW_REF") ==
              f"AldemaroCruz/ClipForge/.github/workflows/{workflow}@refs/heads/ci/bootstrap-sec03"
              and re.fullmatch(r"[a-f0-9]{40}", commit) and commit == os.environ["DB01_NOBLE_APPROVED_COMMIT"]
              and all(re.fullmatch(r"[1-9][0-9]*", value) for value in (run, attempt)), "Exact protected read dispatch required")
    path = Path(os.environ["DB01_NOBLE_READ_REPORT"])
    token = os.environ["GCP_ACCESS_TOKEN"]
    targets = STABLE_PROBES if stable else PROBES
    state = None if stable else state_postcheck()
    with ThreadPoolExecutor(max_workers=4) as workers:
        results = list(workers.map(lambda target: probe(target, token, f"DB01 Noble READ {run} {attempt}"), targets))
    report = {"schema": "clipforge-db01-noble-stable-precheck-1" if stable else "clipforge-db01-noble-read-1",
              "commit": commit, "run_id": run, "attempt": attempt,
              "principal": historical.TF_SA, "authentication": "protected_wif_access_token",
              "reads": results, "plan_executed": False, "mutations_executed": False}
    if state is not None:
        report["state_postcheck"] = state
    path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    return int((state is not None and state["result"] != "verified")
               or any(row["required_for_refresh"] and row["result"] != "allowed" for row in results))


if __name__ == "__main__":
    raise SystemExit(main())
