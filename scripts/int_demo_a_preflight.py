"""Validate independently approved Hito A decisions before any cloud operation."""

from datetime import datetime, timezone
import os
from pathlib import Path
import re

from scripts import check_int_demo_a as gate
from scripts import int_guest_inventory as transport
from scripts import int_release


REPO = "AldemaroCruz/ClipForge"
BRANCH = "ci/bootstrap-sec03"
PROJECT = "clipforgebeta2"
SCHEMA = "clipforge-int-demo-a-operation-decision-1"
SHA = r"[a-f0-9]{64}"
require = transport.require


def json_bytes(bundle, filename, expected=None, *, limit=32 * 1024 * 1024):
    raw = transport._local_bytes(bundle / filename, limit)
    if expected is not None:
        require(re.fullmatch(SHA, expected) and transport.sha(raw) == expected, "demo_a_pinned_document_changed")
    return transport.decode(raw)


def local_decision(bundle, digest, operation, workflow, env, *, protected=False, now=None, guest_action=None,
                   publication_profile=None):
    """Check the static scope in the job that has no OIDC permission."""
    expected = {"GITHUB_REPOSITORY": REPO, "GITHUB_REF": "refs/heads/" + BRANCH,
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted",
                "GITHUB_WORKFLOW_REF": f"{REPO}/{workflow}@refs/heads/{BRANCH}"}
    commit = env.get("GITHUB_SHA", "")
    require(all(env.get(key) == value for key, value in expected.items()) and re.fullmatch(r"[a-f0-9]{40}", commit)
            and env.get("INT_APPROVED_COMMIT") == commit and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", "")), "demo_a_hosted_scope")
    require(isinstance(digest, str) and re.fullmatch(SHA, digest), "demo_a_decision_digest")
    value = json_bytes(bundle, "decision.json", digest, limit=65536)
    fields = {"schema", "status", "owner", "repository", "branch", "environment", "project", "control_commit", "operation",
              "operation_id", "issued_utc", "expires_utc", "gate_mode", "review_sha256", "binding_sha256", "inputs"}
    scope = {"schema": SCHEMA, "status": "authorized_one_operation", "owner": "admin@ixbalam.studio", "repository": REPO,
             "branch": BRANCH, "environment": "int", "project": PROJECT, "control_commit": commit, "operation": operation}
    require(isinstance(value, dict) and set(value) == fields and all(value[k] == v for k, v in scope.items())
            and re.fullmatch(r"[a-f0-9]{32}", value["operation_id"]) and value["gate_mode"] in {"global", "demo-a"}
            and all(re.fullmatch(SHA, value[key]) for key in ("review_sha256", "binding_sha256")), "demo_a_closed_owner_decision")
    issued, expires = [datetime.fromisoformat(value[key]) for key in ("issued_utc", "expires_utc")]
    now = now or datetime.now(timezone.utc)
    require(issued.utcoffset() == expires.utcoffset() == timezone.utc.utcoffset(None) and issued <= now < expires
            and 0 < (expires - issued).total_seconds() <= 3600, "demo_a_decision_time_boundary")
    if protected:
        require(env.get("INT_DEMO_A_PROTECTED_DECISION_SHA256") == digest
                and env.get("INT_DEMO_A_PROTECTED_GATE_MODE", "global") == value["gate_mode"], "demo_a_independent_protected_approval")
    json_bytes(bundle, "binding.json", value["binding_sha256"], limit=65536)
    review_args = ["--review", str(bundle / "review.json"), "--review-sha256", value["review_sha256"],
                   "--binding", str(bundle / "binding.json"), "--operation", operation]
    if protected and operation in gate.DB_RUNNER_OPERATIONS:
        review_args.append("--match-credential-runner")
    if guest_action is not None:
        require(value["inputs"]["action"] == guest_action, "demo_a_guest_action_mismatch")
        review_args.extend(("--guest-action", guest_action))
    if publication_profile is not None:
        review_args.extend(("--publication-profile", publication_profile))
    require(gate.main(review_args) == 0, "demo_a_operation_evidence_blocked")
    return value


def deploy_after_wif(env, decision):
    """Validate the exact hosted Deploy identity immediately before external writes."""
    int_release.hosted_context(env)
    transport.validate_deploy_credentials(env, transport._credential_document(env))
    if decision["gate_mode"] == "global":
        int_release.require_application_ci(env)
    token = env["GCP_ACCESS_TOKEN"]
    require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "demo_a_token_shape")
    return token


def runtime_scratch(env):
    runner = Path(env["RUNNER_TEMP"]).resolve()
    work = Path(env["INT_DEMO_A_WORK"])
    require(work.is_absolute() and work.resolve() == work and work.parent == runner and work.name.startswith("clipforge-demo-a.")
            and not work.is_symlink() and work.is_dir() and work.stat().st_uid == os.getuid()
            and not work.stat().st_mode & 0o077, "demo_a_private_scratch_required")
    return work
