"""Observe the exact INT Demo A operator scopes with the two existing WIF identities."""

import argparse
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts.check_tf_int import BUCKET
from scripts.tf_int_plan import NoRedirect


PROJECT = "clipforgebeta2"
NUMBER = "816643438938"
REGION = "us-central1"
ZONE = "us-central1-a"
PROVIDER = f"projects/{NUMBER}/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github"
REF = "refs/heads/ci/bootstrap-sec03"
WORKFLOW = ".github/workflows/int-demo-a-wif-read.yml"
REPO = "AldemaroCruz/ClipForge"
RUN_PARENT = f"projects/{PROJECT}/locations/{REGION}"
RUN_API = "https://run.googleapis.com/v2/"
IAP_API = "https://iap.googleapis.com/v1/"
GCS = f"https://storage.googleapis.com/storage/v1/b/{BUCKET}"
COMPUTE = "https://compute.googleapis.com/compute/v1/"
IAM = "https://iam.googleapis.com/v1/"
CRM = "https://cloudresourcemanager.googleapis.com/v3/"
SECRETS = "https://secretmanager.googleapis.com/v1/"
AR_API = "https://artifactregistry.googleapis.com/v1/"
REGISTRY = f"https://{REGION}-docker.pkg.dev/v2/{PROJECT}/clipforge-int/"
AR_RESOURCE = RUN_PARENT + "/repositories/clipforge-int"
SA = {key: f"clipforge-{key}-int@{PROJECT}.iam.gserviceaccount.com" for key in ("terraform", "deploy", "api", "migrate")}
SA["noble"] = f"clipforge-db01-noble-int@{PROJECT}.iam.gserviceaccount.com"
SECRET_NAMES = ("clipforge-int-pg-app-password", "clipforge-int-pg-migrator-password", "clipforge-int-postgres-ca", "clipforge-int-bootstrap-admin")
OCI = {"runtime": "sha256:40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15",
       "db01-noble-client": "sha256:24e4d9ccea365859c6f455c3780c8abe6a0df3f1150e60380e2b2cc73e0dc5b5"}
JOBS = ("clipforge-int-bootstrap", "clipforge-int-db01-noble-migration", "clipforge-int-db01-noble-acceptance")
STATE_ROOT = "terraform/int/tf-int-01/default."
POSTVERIFY = "private-plans/int/d6915938ea056d6df6e15d29457c0f0c1f46a69e/44772432816-1/foundation-state.json"
POSTVERIFY_SHA = "cf3236aa512cf30d59136fed3a5209448700be6401c345716db0a38f222288a3"
NOBLE = f"projects/{PROJECT}/zones/{ZONE}/instances/clipforge-int-db01-noble"
IAP_TUNNEL = f"projects/{NUMBER}/iap_tunnel/zones/{ZONE}/instances/7365414160255801909"
IAP_API_RESOURCE = f"projects/{NUMBER}/iap_web/cloud_run-{REGION}/services/clipforge-int-api"
INSTALLED_IDS = {"clipforge-int-db01-noble": "7365414160255801909", "clipforge-int-db01-noble-data": "7382984635240536620",
                 "clipforge-int-db01-noble-boot": "8897353356069952044"}
BODY_LIMIT = 1024 * 1024
POLICY_VERSION = (("options.requestedPolicyVersion", "3"),)


@dataclass(frozen=True)
class Probe:
    operation: str
    resource: str
    url: str
    permissions: tuple[str, ...]
    method: str = "GET"
    body: dict | None = None
    kind: str = "read"
    expected: str | None = None


def query(url, fields):
    return url + "?" + urlencode(fields)


def read(resource, url, permission, *, kind="read", expected=None):
    return Probe("read:" + permission, resource, url, (permission,), kind=kind, expected=expected)


def policy(resource, url, permission, *, method="GET", body=None):
    return Probe("policy:" + permission, resource, url, (permission,), method, body, "policy")


def evaluate(resource, url, permissions, *, query_parameters=False):
    if query_parameters:
        url = query(url, [("permissions", permission) for permission in permissions])
        return Probe("evaluate:testIamPermissions", resource, url, tuple(permissions), kind="evaluate")
    return Probe("evaluate:testIamPermissions", resource, url, tuple(permissions), "POST", {"permissions": list(permissions)}, "evaluate")


def run_probes(identity):
    targets = [("services", "clipforge-int-api"), *(("jobs", name) for name in JOBS)]
    for kind, name in targets:
        resource = f"{RUN_PARENT}/{kind}/{name}"
        url = RUN_API + resource
        permission = "run." + kind
        fields, evidence_kind = ("name,uid,generation", "job") if kind == "jobs" else ("name", "regional_name")
        yield read(resource, query(url, {"fields": fields}), permission + ".get", kind=evidence_kind, expected=resource)
        if kind == "jobs":
            actions = ("get", "getIamPolicy", "setIamPolicy") if identity == "terraform" else ("get", "run", "runWithOverrides")
        else:
            actions = ("get", "getIamPolicy", "setIamPolicy") if identity == "terraform" else ("get",)
        yield evaluate(resource, url + ":testIamPermissions", [permission + "." + action for action in actions])
        if identity == "terraform":
            yield policy(resource, query(url + ":getIamPolicy", POLICY_VERSION), permission + ".getIamPolicy")


def probes(identity):
    bucket = "buckets/" + BUCKET
    registry = AR_API + AR_RESOURCE
    crm_url = CRM + "projects/" + NUMBER
    yield read(AR_RESOURCE, query(registry, {"fields": "name,format"}), "artifactregistry.repositories.get", kind="regional_name", expected=AR_RESOURCE)
    yield policy(AR_RESOURCE, query(registry + ":getIamPolicy", POLICY_VERSION), "artifactregistry.repositories.getIamPolicy")
    ar = ("artifactregistry.repositories.get", "artifactregistry.repositories.downloadArtifacts")
    yield evaluate(AR_RESOURCE, registry + ":testIamPermissions", ar + (("artifactregistry.repositories.uploadArtifacts",) if identity == "deploy" else ()))
    for name, digest in OCI.items():
        yield read(f"{AR_RESOURCE}/{name}@{digest}", f"{REGISTRY}{name}/manifests/{digest}", "artifactregistry.repositories.downloadArtifacts", kind="oci", expected=digest)
    yield read(bucket, query(GCS, {"fields": "name,projectNumber,versioning,iamConfiguration"}), "storage.buckets.get", kind="bucket")
    yield policy(bucket, query(GCS + "/iam", {"optionsRequestedPolicyVersion": "3"}), "storage.buckets.getIamPolicy")
    custody_permissions = ("storage.objects.get", "storage.objects.create", "storage.objects.list", "storage.objects.delete") if identity == "terraform" else ("storage.objects.get", "storage.objects.create")
    yield evaluate(bucket, GCS + "/iam/testPermissions", custody_permissions, query_parameters=True)
    receipt = query(GCS + "/o/" + quote(POSTVERIFY, safe=""), {"alt": "media", "generation": "1795191726103428", "ifGenerationMatch": "1795191726103428"})
    yield read(bucket + "/objects/" + POSTVERIFY, receipt, "storage.objects.get", kind="immutable_receipt", expected=POSTVERIFY_SHA)
    if identity == "terraform":
        workspace = query(GCS + "/o", {"prefix": STATE_ROOT, "maxResults": "16", "fields": "items(name,generation,size),nextPageToken"})
        yield read(bucket + "/objects/" + STATE_ROOT, workspace, "storage.objects.list", kind="backend")
    yield read("projects/" + NUMBER, query(crm_url, {"fields": "name,projectId,state"}), "resourcemanager.projects.get", kind="named", expected="projects/" + NUMBER)
    yield read(PROVIDER, query(IAM + PROVIDER, {"fields": "name,state,disabled"}), "iam.workloadIdentityPoolProviders.get", kind="provider", expected=PROVIDER)
    yield policy("projects/" + NUMBER, crm_url + ":getIamPolicy", "resourcemanager.projects.getIamPolicy", method="POST", body={"options": {"requestedPolicyVersion": 3}})
    parent_permissions = ("run.services.create", "run.jobs.create", "run.operations.get", "compute.firewalls.create", "iap.webServices.setIamPolicy") if identity == "terraform" else ("run.jobs.create", "run.operations.get", "run.jobs.runWithOverrides")
    yield evaluate("projects/" + NUMBER, crm_url + ":testIamPermissions", parent_permissions)
    for name in SECRET_NAMES:
        resource = f"projects/{PROJECT}/secrets/{name}"
        url = SECRETS + resource
        yield read(resource, query(url, {"fields": "name"}), "secretmanager.secrets.get", kind="regional_name", expected=resource)
        yield policy(resource, query(url + ":getIamPolicy", POLICY_VERSION), "secretmanager.secrets.getIamPolicy")
        needed = "secretmanager.versions.add" if identity == "deploy" else "secretmanager.versions.get"
        yield evaluate(resource, url + ":testIamPermissions", ("secretmanager.secrets.get", needed))
    for service in ("api", "migrate", "noble"):
        resource = f"projects/{PROJECT}/serviceAccounts/{SA[service]}"
        url = IAM + resource
        yield read(resource, query(url, {"fields": "email"}), "iam.serviceAccounts.get", kind="sa", expected=SA[service])
        yield policy(resource, query(url + ":getIamPolicy", POLICY_VERSION), "iam.serviceAccounts.getIamPolicy", method="POST")
        yield evaluate(resource, url + ":testIamPermissions", ("iam.serviceAccounts.get", "iam.serviceAccounts.actAs"))
    yield from run_probes(identity)
    subnet = RUN_PARENT.replace("/locations/", "/regions/") + "/subnetworks/clipforge-int-base-run"
    for resource, permission, fields in (
        (NOBLE, "compute.instances.get", "id,name"),
        (f"projects/{PROJECT}/zones/{ZONE}/disks/clipforge-int-db01-noble-data", "compute.disks.get", "id,name"),
        (f"projects/{PROJECT}/zones/{ZONE}/disks/clipforge-int-db01-noble-boot", "compute.disks.get", "id,name"),
        (f"projects/{PROJECT}/global/networks/clipforge-int-base", "compute.networks.get", "name"),
        (subnet, "compute.subnetworks.get", "name,ipCidrRange"),
        (f"projects/{PROJECT}/global/firewalls/clipforge-int-db01-noble-postgres-from-run", "compute.firewalls.get", "name"),
    ):
        yield read(resource, query(COMPUTE + resource, {"fields": fields}), permission, kind="leaf_name", expected=resource.rsplit("/", 1)[-1])
    yield evaluate(subnet, COMPUTE + subnet + "/testIamPermissions", ("compute.subnetworks.get", "compute.subnetworks.use"))
    if identity == "deploy":
        yield evaluate(NOBLE, COMPUTE + NOBLE + "/testIamPermissions", ("compute.instances.get", "compute.instances.osAdminLogin"))
        yield evaluate(IAP_TUNNEL, IAP_API + IAP_TUNNEL + ":testIamPermissions", ("iap.tunnelInstances.accessViaIAP",))
    else:
        yield policy(IAP_API_RESOURCE, IAP_API + IAP_API_RESOURCE + ":getIamPolicy", "iap.webServices.getIamPolicy",
                     method="POST", body={"options": {"requestedPolicyVersion": 3}})
        yield evaluate(IAP_API_RESOURCE, IAP_API + IAP_API_RESOURCE + ":testIamPermissions",
                       ("iap.webServices.getIamPolicy", "iap.webServices.setIamPolicy"))


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def hosted_context(env):
    expected = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": REF, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
                "GITHUB_WORKFLOW_REF": f"{REPO}/{WORKFLOW}@{REF}", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_ACTIONS": "true"}
    require(all(env.get(key) == value for key, value in expected.items()), "fixed_hosted_context")
    require(re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", "")) and env["GITHUB_SHA"] == env.get("INT_APPROVED_COMMIT")
            and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")), "exact_dispatch_source")
    require(not any(env.get(key) for key in ("GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE")),
            "observer_must_not_use_adc_file")


def preflight(identity, env):
    hosted_context(env)
    expected = {"GCP_PROJECT_ID": PROJECT, "GCP_PROJECT_NUMBER": NUMBER, "GCP_REGION": REGION, "GCP_WIF_PROVIDER": PROVIDER,
                "GCP_TERRAFORM_SA": SA["terraform"], "GCP_DEPLOY_SA": SA["deploy"], "INT_DEMO_A_WIF_IDENTITY": identity}
    require(all(env.get(key) == value for key, value in expected.items()), "fixed_wif_identity_and_provider")


def read_observation(probe, value):
    if probe.kind in {"regional_name", "job"}:
        valid = probe.expected.replace(f"projects/{PROJECT}/", f"projects/{NUMBER}/", 1)
        require(value.get("name") in {probe.expected, valid}, "resource_identity_mismatch")
        if probe.kind == "job":
            result = {"job_present": True}
            if "uid" in value:
                uid = value["uid"]
                require(re.fullmatch(r"[a-f0-9]{8}-[a-f0-9]{4}-4[a-f0-9]{3}-[89ab][a-f0-9]{3}-[a-f0-9]{12}", uid, re.I), "job_uid_invalid")
                result["uid"] = uid
            if "generation" in value:
                generation = value["generation"]
                require(re.fullmatch(r"[1-9][0-9]{0,18}", generation) and int(generation) <= 2 ** 63 - 1, "job_generation_invalid")
                result["generation"] = generation
            return result
    elif probe.kind in {"named", "leaf_name", "sa"}:
        require(value.get("email" if probe.kind == "sa" else "name") == probe.expected, "resource_identity_mismatch")
        if probe.expected in INSTALLED_IDS:
            require(str(value.get("id")) == INSTALLED_IDS[probe.expected], "installed_noble_id_mismatch")
        if probe.expected == "clipforge-int-base-run":
            require(value.get("ipCidrRange") == "10.80.0.0/26", "run_subnet_cidr_changed")
    elif probe.kind == "provider":
        require(value.get("name") == probe.expected and value.get("state") == "ACTIVE" and not value.get("disabled"), "wif_provider_metadata_changed")
    elif probe.kind == "bucket":
        require(value.get("name") == BUCKET and str(value.get("projectNumber")) == NUMBER, "storage_bucket_mismatch")
        return {"versioning_enabled": value.get("versioning", {}).get("enabled") is True,
                "uniform_bucket_access": value.get("iamConfiguration", {}).get("uniformBucketLevelAccess", {}).get("enabled") is True}
    elif probe.kind == "backend":
        rows = value.get("items", [])
        require(not value.get("nextPageToken") and len(rows) <= 2 and len({row["name"] for row in rows}) == len(rows)
                and all(row["name"] in {STATE_ROOT + "tfstate", STATE_ROOT + "tflock"} for row in rows), "unknown_workspace_or_truncated_list")
        return {"state_visible": any(row["name"].endswith(".tfstate") for row in rows),
                "pinned_generation_visible": any(row["name"].endswith(".tfstate") and row.get("generation") == "1795187957111147" for row in rows),
                "lock_visible": any(row["name"].endswith(".tflock") for row in rows)}
    return {"fixed_resource_read": True}


def observe(probe, token, principal, *, opener=None):
    row = {"operation": probe.operation, "resource": probe.resource, "method": probe.method,
           "permissions": list(probe.permissions), "principal": principal, "evidence": probe.kind, "write_executed": False}
    headers = {"Authorization": "Bearer " + token}
    if probe.kind == "oci":
        headers["Accept"] = "application/vnd.oci.image.manifest.v1+json"
    data = None
    if probe.body is not None:
        headers["Content-Type"] = "application/json"
        data = json.dumps(probe.body, separators=(",", ":")).encode("ascii")
    status = None
    try:
        opener = opener or build_opener(ProxyHandler({}), NoRedirect())
        with opener.open(Request(probe.url, method=probe.method, data=data, headers=headers), timeout=12) as response:
            status = response.status
            require(status == 200, "unexpected_success_status")
            raw = response.read(BODY_LIMIT + 1)
            require(0 < len(raw) <= BODY_LIMIT, "bounded_response")
            if probe.kind in {"immutable_receipt", "oci"}:
                digest = sha256(raw).hexdigest()
                expected = probe.expected
                require(digest == expected if probe.kind == "immutable_receipt" else
                        "sha256:" + digest == expected == response.headers.get("Docker-Content-Digest"), "immutable_read_mismatch")
                return {**row, "http_status": status, "result": "read_verified_wif", "sha256_verified": True}
        value = json.loads(raw)
        if probe.kind == "evaluate":
            granted = value.get("permissions", [])
            require(isinstance(granted, list) and all(perm in probe.permissions for perm in granted), "unexpected_permission_in_evaluation")
            missing = set(probe.permissions) - set(granted)
            return {**row, "http_status": status, "result": "permission_indicated_by_evaluation" if granted else "no_permission_confirmed_by_evaluation",
                    "permissions_indicated": sorted(set(granted)), "permissions_not_confirmed": sorted(missing)}
        if probe.kind == "policy":
            direct = []
            for entry in value.get("bindings", []):
                if "serviceAccount:" + principal in entry.get("members", []):
                    role = entry["role"]
                    require(re.fullmatch(r"(?:roles/|projects/[A-Za-z0-9_-]+/roles/|organizations/[0-9]+/roles/)[A-Za-z0-9_.]+", role), "unrecognized_role")
                    direct.append({"role": role, "conditional": bool(entry.get("condition"))})
            return {**row, "http_status": status, "result": "policy_read_wif", "direct_policy_roles": direct}
        return {**row, "http_status": status, "result": "read_verified_wif", **read_observation(probe, value)}
    except HTTPError as error:
        status = error.code
        error.close()
        result = {401: "unauthenticated", 403: "denied", 404: "not_found_or_not_visible"}.get(status, "indeterminate_http")
        return {**row, "http_status": status, "result": result, "failure_scope": "this_request_only"}
    except (AttributeError, KeyError, OSError, TypeError, ValueError):
        return {**row, "http_status": status, "result": "indeterminate_response"}


def not_attempted(identity):
    if identity == "terraform":
        return {"native_lock": ["storage.objects.create", "storage.objects.delete"], "private_plan_custody": ["storage.objects.create"],
                "six_resource_apply": ["compute.firewalls.create", "run.services.create", "run.jobs.create", "run.services.setIamPolicy",
                 "run.jobs.setIamPolicy", "iap.webServices.setIamPolicy"],
                "state_successor": ["storage.objects.create", "storage.objects.delete"]}
    return {"oci_publication": ["artifactregistry.repositories.uploadArtifacts"], "private_intentions_and_receipts": ["storage.objects.create"],
            "exact_secret_versions": ["secretmanager.versions.add"], "dedicated_job_create_and_run": ["run.jobs.create", "run.jobs.runWithOverrides"],
            "admin_job_execution": ["run.jobs.run"]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("local", "preflight", "observe"))
    parser.add_argument("identity", nargs="?", choices=("terraform", "deploy"))
    parser.add_argument("--output", type=Path)
    args = parser.parse_args(argv)
    try:
        token = os.environ.get("GCP_ACCESS_TOKEN", "")
        if args.phase == "local":
            hosted_context(os.environ)
            require(not token and args.identity is None and args.output is None, "local_scope_before_wif")
            return 0
        require(args.identity is not None, "exact_observer_identity_required")
        preflight(args.identity, os.environ)
        if args.phase == "preflight":
            require(not token and args.output is None, "preflight_must_precede_wif")
            return 0
        require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "missing_wif_token")
        base = Path(os.environ["RUNNER_TEMP"]).resolve()
        require(args.output is not None and args.output.parent.resolve() == base and
                re.fullmatch(r"clipforge-demo-a-wif\.[A-Za-z0-9]+\.json", args.output.name), "restricted_summary_path")
        principal = SA[args.identity]
        with ThreadPoolExecutor(max_workers=5) as pool:
            rows = list(pool.map(lambda probe: observe(probe, token, principal), probes(args.identity)))
        report = {"schema": "clipforge-int-demo-a-wif-observation-1", "status": "read_only_evidence_collected",
                  "identity": args.identity, "principal": principal, "project": PROJECT, "environment": "int", "provider": PROVIDER,
                  "source_commit": os.environ["GITHUB_SHA"], "run": os.environ["GITHUB_RUN_ID"], "attempt": "1",
                  "observed_utc": datetime.now(timezone.utc).isoformat(), "reads_and_evaluations": rows, "write_executed": False,
                  "writes_not_attempted": not_attempted(args.identity), "authorizes_write": False,
                  "effective_permissions_note": "Policy rows are direct bindings only. Evaluations use their named resource and context. "
                  "They do not prove future per-object conditions, writes, secret access or the existence of a prospective resource. "
                  "The historical custody read does not substitute for verifying a producer's future object scope.",
                  "exact_secret_version_get": "deferred_until_native_numeric_version_receipts",
                  "dedicated_job_removal": {"permission": "run.jobs.delete", "status": "future_with_separate_authorization",
                                            "included_in_pilot_delta": False}}
        os.umask(0o077)
        with args.output.open("xb") as stream:
            stream.write((json.dumps(report, indent=2) + "\n").encode("utf-8"))
        print(json.dumps({"identity": args.identity, "status": report["status"], "observations": len(rows), "write_executed": False}))
        return 0
    except (KeyError, OSError, ValueError) as error:
        safe = str(error) if type(error) is ValueError and re.fullmatch(r"[a-z_]+", str(error)) else type(error).__name__
        print(json.dumps({"identity": args.identity, "status": "blocked", "reason": safe, "write_executed": False}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
