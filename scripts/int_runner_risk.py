"""Closed owner acceptance for the ephemeral GitHub-hosted INT runner only."""

from hashlib import sha256
import json
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CONFIG = ROOT / "config/int-runner-risk-acceptance.json"
CONFIG_SHA256 = "1fcdde7b06eb9bea9ccee8422edc4817e9d21ea131f847c3db7ea16ab1bfa95a"
SCHEMA = "clipforge-int-hosted-runner-risk-acceptance-1"
INFORMATIONAL_SEVERITIES = {"LOW", "MEDIUM", "HIGH", "CRITICAL"}
PRESERVED = {
    "application_and_migration_oci_thresholds",
    "noncredential_toolchain_thresholds",
    "bandit_and_gitleaks",
    "source_and_artifact_digests",
    "same_job_checkpoint_continuity",
    "secrets_before_wif_boundaries",
    "iam_oidc_tls_and_numeric_secret_versions",
    "noble_guest_controls",
    "historical_host_rejected_evidence",
    "environment_int_manual_approval",
}


def require(condition, code):
    if not condition:
        raise ValueError(code)


def closed(raw):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "runner_risk_duplicate_json_key")
            value[key] = item
        return value

    return json.loads(raw, object_pairs_hook=unique)


def load(path=CONFIG):
    path = path.resolve(strict=True)
    require(path == CONFIG.resolve(strict=True) and path.is_file() and not path.is_symlink(),
            "runner_risk_config_path")
    raw = path.read_bytes()
    require(sha256(raw).hexdigest() == CONFIG_SHA256, "runner_risk_config_digest")
    value = closed(raw)
    require(isinstance(value, dict) and set(value) == {
        "schema", "status", "authorization", "scope", "findings", "cross_job_continuity",
        "same_job_continuity_required", "preserved_controls",
    } and value["schema"] == SCHEMA and value["status"] == "accepted_informational",
            "runner_risk_config_fields")
    require(value["authorization"] == {
        "owner": "AldemaroCruz",
        "decision": "accept_github_hosted_ubuntu_24_04_runner_platform_risk_for_int",
        "recorded_date": "2026-11-24",
    }, "runner_risk_authorization")
    require(value["scope"] == {
        "repository": "AldemaroCruz/ClipForge",
        "branch": "ci/bootstrap-sec03",
        "environment": "int",
        "runner_environment": "github-hosted",
        "runner_label": "ubuntu-24.04",
        "image_os": "ubuntu24",
        "architecture": "x86_64",
    }, "runner_risk_scope")
    findings = value["findings"]
    require(isinstance(findings, dict) and set(findings) == {
        "role", "kind", "severities", "components", "treatment",
    } and findings["role"] == "credential_toolchain" and findings["kind"] == "trivy_toolchain"
            and findings["severities"] == ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
            and findings["components"] == [
                "host_operating_system", "host_running_kernel", "host_preinstalled_packages",
                "hosted_credential_toolchain_metadata",
            ] and findings["treatment"] == "risk_accepted_informational",
            "runner_risk_finding_scope")
    require(value["cross_job_continuity"] == {
        "image_version_required": False,
        "boot_id_required": False,
        "kernel_identity_required": False,
        "tool_fingerprints_required": False,
    } and value["same_job_continuity_required"] is True,
            "runner_risk_continuity_scope")
    controls = value["preserved_controls"]
    require(isinstance(controls, list) and len(controls) == len(PRESERVED) and set(controls) == PRESERVED,
            "runner_risk_preserved_controls")
    return value


def informational_finding(row):
    policy = POLICY["findings"]
    return (isinstance(row, dict) and row.get("role") == policy["role"]
            and row.get("kind") == policy["kind"]
            and row.get("severity") in INFORMATIONAL_SEVERITIES)


def cross_job_identity_required():
    return any(POLICY["cross_job_continuity"].values())


POLICY = load()
