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
    started = clock()
    before = jobs.request_json(opener, token, "GET", state_url)
    lock = jobs.request_json(opener, token, "GET", lock_url, missing=True)
    observed = clock()
    after = jobs.request_json(opener, token, "GET", state_url)
    finished = clock()
    require(before == after == {**expected["state"], "size": str(expected["state"]["size"])}
            and lock is None, "intervention_backend_or_lock_changed")
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
