"""Single-run Terraform metadata observation for the dedicated guest intervention."""

from datetime import datetime, timezone
import re
from urllib.parse import quote
from urllib.request import ProxyHandler, build_opener

from scripts import int_db01_noble_jobs as jobs
from scripts import int_demo_a_plan_scope as scope
from scripts import int_guest_inventory as transport
from scripts import int_release as release


SCHEMA = "clipforge-int-noble-intervention-backend-1"
require = transport.require


def binding(env, decision, decision_sha256):
    return {"schema": SCHEMA, "identity": jobs.TERRAFORM, "run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"],
            "control_commit": env["GITHUB_SHA"], "decision_sha256": decision_sha256, "operation_id": decision["operation_id"],
            "action": decision["inputs"]["action"], "bucket": scope.BUCKET,
            "state": {name: scope.STATE[name] for name in ("name", "generation", "size")},
            "lock": {"name": jobs.LOCK_NAME, "http_status": 404}, "state_content_read": False, "lock_acquired": False}


def observe(token, expected, *, opener=None, clock=lambda: datetime.now(timezone.utc)):
    opener = opener or build_opener(ProxyHandler({}), jobs.NoRedirect())
    prefix = f"https://storage.googleapis.com/storage/v1/b/{scope.BUCKET}/o/"
    state_url = prefix + quote(scope.STATE["name"], safe="") + "?fields=name,generation,size"
    lock_url = prefix + quote(jobs.LOCK_NAME, safe="") + "?fields=name"

    def read(url, name, *, missing=False):
        try:
            return jobs.request_json(opener, token, "GET", url, missing=True) if missing else jobs.request_json(opener, token, "GET", url)
        except (OSError, ValueError) as error:
            if expected["action"] != "apt_preflight":
                raise
            detail = {"operation": "storage.objects.get_metadata", "resource": f"gs://{scope.BUCKET}/{name}"}
            status = re.fullmatch(r"cloud_http_([1-5][0-9]{2})", str(error))
            if status:
                detail["http_status"] = int(status[1])
            else:
                detail["error_type"] = type(error).__name__
            raise transport.Failure("apt_preflight_backend_read_failed", detail) from None

    started = clock()
    before = read(state_url, scope.STATE["name"])
    lock = read(lock_url, jobs.LOCK_NAME, missing=True)
    observed = clock()
    after = read(state_url, scope.STATE["name"])
    finished = clock()
    metadata_matches = before == after == {**expected["state"], "size": str(expected["state"]["size"])}
    if expected["action"] == "apt_preflight" and not (metadata_matches and lock is None):
        name = jobs.LOCK_NAME if lock is not None else scope.STATE["name"]
        raise transport.Failure("intervention_backend_or_lock_changed", {
            "operation": "storage.objects.get_metadata", "resource": f"gs://{scope.BUCKET}/{name}",
            "http_status": 200, "result": "lock_present" if lock is not None else "state_metadata_mismatch"})
    require(metadata_matches and lock is None, "intervention_backend_or_lock_changed")
    proof = {**expected, "started_utc": started.isoformat(), "lock_observed_utc": observed.isoformat(), "completed_utc": finished.isoformat()}
    verify(proof, expected, now=finished)
    return proof


def verify(proof, expected, *, now):
    times = ("started_utc", "lock_observed_utc", "completed_utc")
    require(isinstance(proof, dict) and set(proof) == set(expected) | set(times)
            and all(proof[key] == value for key, value in expected.items()), "intervention_backend_binding_changed")
    started, observed, completed = (jobs.client.utc(proof[key]) for key in times)
    require(started <= observed <= completed <= now <= observed + jobs.MAX_BACKEND_AGE
            and completed <= started + jobs.MAX_BACKEND_AGE, "intervention_backend_observation_expired_or_future")


def observe_for_run(env, expected):
    release.hosted_context(env)
    token = env["GCP_ACCESS_TOKEN"]
    require(env.get("GCP_TERRAFORM_SA") == jobs.TERRAFORM and env.get("GCP_WIF_PROVIDER") == transport.PROVIDER
            and not any(env.get(name) for name in ("GCP_DEPLOY_SA", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH",
                        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN"))
            and re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "intervention_backend_wif_scope")
    return observe(token, expected)
