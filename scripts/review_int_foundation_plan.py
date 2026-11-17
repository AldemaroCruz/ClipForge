"""Read and compare one retained foundation candidate; never authorize apply.

Only pinned GCS generations and fixed public image metadata can be read. Full
plans/responses stay in private memory. The public output is the comparator's
allowlisted evidence plus custody/backend metadata, never state or credentials.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import Request, ProxyHandler, build_opener

from scripts import check_tf_int as c, int_release as custody, tf_int_plan as driver
from scripts import compare_int_foundation_plans as comparison

ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "clipforge-int-foundation-candidate-review-1"
BASELINE = "aa68d4a3228bf6a1092703285f05022c8727d99c"
CONTROL_ORIGIN = "d93e21224f15886762f1f87bbcf917f51d801a42"
IMAGE = "debian-13-trixie-v20261116"
IMAGE_ID = "5913446147369107523"
IMAGE_URL = "https://compute.googleapis.com/compute/v1/projects/debian-cloud/global/images/" + IMAGE


class ReviewFailure(ValueError):
    def __init__(self, operation, message, *, status=None, resource=None):
        self.receipt = c.diagnostic(operation, message, status)
        self.receipt["resource"] = resource
        super().__init__("Candidate review stopped; only sanitized diagnostics may be published")


def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            c.require(key not in result, "Duplicate JSON key in private evidence")
            result[key] = value
        return result
    def finite(_value):
        raise ValueError("Non-finite JSON in private evidence")
    return json.loads(raw, object_pairs_hook=unique, parse_constant=finite)


def read_private(url, limit, operation, resource):
    request = Request(url, headers={"Authorization": "Bearer " + os.environ["GCP_ACCESS_TOKEN"]})
    try:
        with build_opener(ProxyHandler({}), driver.NoRedirect()).open(request, timeout=120) as response:
            raw = response.read(limit + 1)
        c.require(len(raw) <= limit, "Private response exceeds bound")
        return raw
    except HTTPError as error:
        # Inspect only the bounded structured error message, never dump a body,
        # request, token, signed URL, credential file or complete environment.
        body = error.read(16384)
        try:
            message = decode(body).get("error", {}).get("message", "Cloud request denied")
        except (ValueError, TypeError, AttributeError):
            message = "Cloud request denied"
        raise ReviewFailure(operation, "HTTP " + str(error.code) + ": " + str(message),
                            status=error.code, resource=resource) from None


def fetch(reference):
    c.require(isinstance(reference, dict) and set(reference) == {"name", "generation", "sha256", "size"}, "Invalid custody reference")
    custody.object_name(reference["name"])
    c.require(isinstance(reference["generation"], str) and bool(re.fullmatch(r"[1-9][0-9]*", reference["generation"]))
              and isinstance(reference["sha256"], str) and bool(re.fullmatch(r"[a-f0-9]{64}", reference["sha256"]))
              and type(reference["size"]) is int and 0 < reference["size"] <= comparison.MAX_BYTES, "Incomplete immutable custody binding")
    url = "https://storage.googleapis.com/storage/v1/b/" + c.BUCKET + "/o/" + quote(reference["name"], safe="") + "?" + urlencode(
        {"alt": "media", "generation": reference["generation"], "ifGenerationMatch": reference["generation"]})
    raw = read_private(url, comparison.MAX_BYTES, "read pinned plan evidence", reference["name"])
    c.require(len(raw) == reference["size"] and custody.sha256(raw) == reference["sha256"], "Custody generation/size/SHA verification failed")
    return raw


def image_metadata():
    raw = read_private(IMAGE_URL + "?" + urlencode({"fields": "name,id,status,architecture,selfLink,deprecated"}),
                       65536, "read pinned candidate image metadata", "projects/debian-cloud/global/images/" + IMAGE)
    value = decode(raw)
    c.require(isinstance(value, dict) and value.get("name") == IMAGE and str(value.get("id")) == IMAGE_ID
              and value.get("status") == "READY" and value.get("architecture") == "X86_64", "Candidate image identity/status differs from the authorized pin")
    deprecated = value.get("deprecated", {})
    if deprecated is None:
        deprecated = {}
    c.require(isinstance(deprecated, dict) and deprecated.get("state") in {None, "ACTIVE"}
              and not any(deprecated.get(key) for key in ("deprecated", "obsolete", "deleted", "replacement")),
              "Candidate image is deprecated or has an unreviewed deprecation schedule")
    return {"project": "debian-cloud", "name": IMAGE, "id": IMAGE_ID, "status": "READY", "architecture": "X86_64",
            "deprecation": "not_deprecated_no_schedule"}


def instant(value):
    result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    c.require(result.tzinfo is not None, "Plan timestamp requires a timezone")
    return result


def backend_proof(summary, baseline, manifest):
    expected = baseline["backend"]
    backend = summary.get("backend", {})
    current = [row for row in backend.get("live", []) if row.get("name", "").startswith(c.PREFIX + "/")]
    c.require(backend.get("classification") == "recognized_initial_state" and backend.get("bucket") == c.BUCKET
              and backend.get("prefix") == c.PREFIX and backend.get("workspace") == "default"
              and len(current) == 1 and current[0].get("name") == driver.STATE_NAME
              and current[0].get("generation") == driver.INITIAL_STATE["generation"] == expected["state_generation"]
              and str(current[0].get("size")) == driver.INITIAL_STATE["size"]
              and backend.get("initial_lineage") == driver.INITIAL_STATE["lineage"] == expected["lineage"]
              and backend.get("initial_state_sha256") == driver.INITIAL_STATE["sha256"] == expected["state_sha256"]
              and expected["serial"] == 1 and manifest.get("backend") == expected,
              "The existing driver did not prove the identical recognized initial backend")
    return {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "state_object": driver.STATE_NAME,
            "current_generation": current[0]["generation"], "baseline_generation": expected["state_generation"],
            "reference_generation_is_current": True, "reference_category": "current_live_generation",
            "bytes": int(current[0]["size"]), "sha256": expected["state_sha256"], "lineage": expected["lineage"], "serial": 1,
            "proof": "Current generation-pinned bytes were verified by the unchanged Terraform driver before and after its plan",
            "state_payload_published": False, "state_adopted": False}


def review(summary, contract, module, environ, *, fetcher=fetch, image_reader=image_metadata):
    baseline = contract["plan"]
    c.require(baseline.get("commit") == BASELINE, "The original AA68 reference must remain intact")
    c.require(summary.get("status") == "planned" and summary.get("full_plan_retained") is True
              and summary.get("private_plan", {}).get("bucket") == c.BUCKET, "No successfully retained candidate plan exists")
    reference = summary["private_plan"]["manifest"]
    old_manifest = decode(fetcher(baseline["manifest"]))
    new_manifest = decode(fetcher(reference))
    c.require(old_manifest.get("commit") == BASELINE and all(old_manifest.get(key) == baseline[key] for key in
              ("binary", "json", "configuration_sha256", "provider_lock_sha256", "terraform_version", "inputs", "backend"))
              and instant(old_manifest["created_utc"]) == instant(baseline["created_utc"]), "Baseline manifest differs from its reviewed custody")
    binding = custody.source_binding(module, environ)
    c.require(all(new_manifest.get(key) == value for key, value in binding.items()) and new_manifest.get("schema") == custody.SCHEMA
              and new_manifest.get("run_id") == environ.get("GITHUB_RUN_ID") and new_manifest.get("run_attempt") == environ.get("GITHUB_RUN_ATTEMPT")
              and new_manifest.get("inputs") == baseline["inputs"] and new_manifest.get("provider_lock_sha256") == baseline["provider_lock_sha256"],
              "Candidate source commit/inputs/provider/run binding differs")
    expected_base = custody.PREFIX + environ["GITHUB_SHA"] + "/" + environ["GITHUB_RUN_ID"] + "-" + environ["GITHUB_RUN_ATTEMPT"] + "/"
    c.require(reference["name"] == expected_base + "manifest.json"
              and new_manifest["binary"]["name"] == expected_base + "int.tfplan" and new_manifest["json"]["name"] == expected_base + "int.json"
              and all(summary["private_plan"].get(key) == new_manifest[key] for key in ("binary", "json")), "Candidate custody references disagree")
    created = instant(new_manifest["created_utc"])
    expires = created + timedelta(hours=24)
    c.require(created <= datetime.now(timezone.utc) < expires, "Candidate plan is not currently within its original24-hour TTL")
    proof = backend_proof(summary, baseline, new_manifest)
    pinned_image = image_reader()
    old_raw, new_raw = fetcher(old_manifest["json"]), fetcher(new_manifest["json"])
    # Download and verify the saved candidate binary as bytes without displaying
    # or interpreting it. No replacement plan or credential discovery is allowed.
    fetcher(new_manifest["binary"])
    result = comparison.compare(decode(old_raw), decode(new_raw), old_manifest, new_manifest)
    c.require(result.get("guards") == [] and result.get("managed_count") == {"old": 42, "new": 42},
              "Complete plans failed the foundation comparison guards")
    cost = summary.get("cost", {})
    c.require(all(type(cost.get(key)) in {int, float} for key in ("foundation_monthly_usd", "monthly_usd")), "Candidate cost estimate is incomplete")
    return {"schema": SCHEMA, "status": "candidate_requires_owner_review", "comparison_complete": True,
            "configuration_commit": environ["GITHUB_SHA"], "controls_commit": environ["GITHUB_SHA"],
            "configuration_origin": BASELINE, "controls_origin": CONTROL_ORIGIN,
            "baseline": {"manifest": baseline["manifest"], "binary": old_manifest["binary"], "json": old_manifest["json"],
                         "created_utc": old_manifest["created_utc"], "expired_reference_not_applicable": True},
            "candidate": {"manifest": reference, "binary": new_manifest["binary"], "json": new_manifest["json"],
                          "configuration_sha256": new_manifest["configuration_sha256"], "provider_lock_sha256": new_manifest["provider_lock_sha256"],
                          "terraform_version": new_manifest["terraform_version"], "created_utc": new_manifest["created_utc"],
                          "expires_utc": expires.isoformat(), "maximum_age_seconds": 86400},
            "raw_json_binding": "Both remote JSON objects and the candidate binary verified by exact generation, byte size and SHA256",
            "backend": proof, "candidate_image": pinned_image, "comparison": result,
            "configuration_sha_changed": old_manifest["configuration_sha256"] != new_manifest["configuration_sha256"],
            "cost": {"currency": "USD", "foundation_monthly_usd": cost["foundation_monthly_usd"],
                     "reference_foundation_monthly_usd": contract["cost_usd_month"]["foundation_example"],
                     "delta_foundation_usd": round(cost["foundation_monthly_usd"] - contract["cost_usd_month"]["foundation_example"], 2),
                     "full_runtime_projection_monthly_usd": cost["monthly_usd"], "full_runtime_not_authorized": True,
                     "assumptions": cost.get("assumptions", []), "sources": cost.get("sources", [])},
            "security_approved": False, "apply_authorized": False, "active_apply_contract_updated": False,
            "next_step": "Review every effective delta, cost and scoped risk conditions; this planning candidate cannot be applied by the active contract"}


def write_report(reports, report):
    (reports / "comparison.json").write_text(json.dumps(report, indent=2, allow_nan=False) + "\n", encoding="utf-8")
    if os.environ.get("GITHUB_STEP_SUMMARY"):
        with Path(os.environ["GITHUB_STEP_SUMMARY"]).open("a", encoding="utf-8") as stream:
            stream.write("\n## Foundation candidate comparison\n\nStatus: **" + report["status"] + "**. Comparison completion is not security or apply approval.\n\n")
            if report.get("comparison_complete"):
                stream.write("Native comparison: `" + report["comparison"]["status"] + "`; effective differences: "
                             + str(len(report["comparison"]["differences"])) + ".\n\n")
                stream.write("```json\n" + json.dumps({key: report[key] for key in ("configuration_commit", "controls_commit", "candidate", "backend", "candidate_image", "cost")}, indent=2) + "\n```\n")
                stream.write("All allowlisted differences and unchanged native guard results are retained in comparison.json. No full plan, state or credentials are artifacts.\n")


def main():
    os.umask(0o077)
    custody.hosted_context(os.environ)
    c.validate_variables(os.environ)
    work, reports = driver.private_paths()
    try:
        contract = decode((ROOT / "config/int-foundation-contract.json").read_bytes())
        summary = decode((reports / "summary.json").read_bytes())
        report = review(summary, contract, work / "module", os.environ)
        code = 0
    except Exception as error:
        report = {"schema": SCHEMA, "status": "blocked_review_error", "comparison_complete": False,
                  "apply_authorized": False, "security_approved": False,
                  "error": error.receipt if isinstance(error, ReviewFailure) else {"operation": "validate candidate evidence", "type": type(error).__name__,
                              "message": str(error)[:400] if isinstance(error, ValueError) else "Private candidate evidence failed validation; no raw payload published"}}
        code = 1
    write_report(reports, report)
    print(json.dumps({"status": report["status"], "comparison_complete": report["comparison_complete"], "apply_authorized": False}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
