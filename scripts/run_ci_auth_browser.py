"""Run real AUTH or recovery browser acceptance in fresh copied sources."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import sys
import tempfile

try:
    from scripts.run_ci_browser import copy_browser_sources, inspect_toolchain, execute_browser_script
    from scripts.validate_ci_reports import validate_browser_auth, validate_browser_auth_recovery, load
except ModuleNotFoundError:
    from run_ci_browser import copy_browser_sources, inspect_toolchain, execute_browser_script
    from validate_ci_reports import validate_browser_auth, validate_browser_auth_recovery, load


SCENARIOS = {
    "auth": ("browser_auth.py", "browser-auth-summary.json", validate_browser_auth),
    "recovery": ("browser_auth_recovery.py", "browser-auth-recovery-summary.json", validate_browser_auth_recovery),
}
PUBLIC_FIELDS = ("schema_version", "status", "exit_code", "script", "steps", "details",
                 "timed_out", "transport", "postgresql", "process_restart", "auth_mocked", "external_network")


def run_auth_browser(source, artifacts, image_id, postgres_image_id, manifest_hash, *,
                     scenario="auth", environ=None, inspector=inspect_toolchain, executor=execute_browser_script):
    """Failures remain failures even if the subprocess left an apparent pass report."""
    selected = SCENARIOS.get(scenario) if type(scenario) is str else None
    report = {"schema_version": 1, "status": "failed", "exit_code": 1,
              "script": selected[0] if selected else "", "image_id": image_id,
              "postgres_image_id": postgres_image_id, "context_manifest_sha256": manifest_hash,
              "steps": 0, "details": [], "timed_out": False}
    environment = dict(os.environ if environ is None else environ)
    try:
        if selected is None:
            raise ValueError("Unknown AUTH browser scenario")
        script_name, report_name, validator = selected
        artifacts.mkdir(parents=True, exist_ok=False)
        if environment.get("CLIPFORGE_AUTH_TEST_DATABASE") != "1":
            raise ValueError("Explicit isolated PostgreSQL test profile is required")
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-" + scenario + "-browser-") as temporary:
            source_copy = Path(temporary) / "source"
            copy_browser_sources(source, source_copy)
            safe = {**environment, "CLIPFORGE_DATA_DIR": str(Path(temporary) / "bootstrap-data"),
                    "CLIPFORGE_AI_PROVIDER": "disabled", "CLIPFORGE_MODEL_LOCK": "",
                    "CLIPFORGE_BROWSER_BRIDGE": "0", "PYTHONDONTWRITEBYTECODE": "1",
                    "HF_HOME": str(Path(temporary) / "huggingface"), "HF_HUB_OFFLINE": "1",
                    "TRANSFORMERS_OFFLINE": "1", "HF_HUB_DISABLE_TELEMETRY": "1", "PIP_NO_INDEX": "1"}
            toolchain = inspector()
            safe["CHROMIUM_EXECUTABLE"] = toolchain.pop("executable")
            outcome = executor(source_copy / "tests" / script_name, source_copy, safe,
                               artifacts / "stdout.log", artifacts / "stderr.log", 900)
            report["timed_out"] = outcome["timed_out"]
            if type(outcome["returncode"]) is not int or outcome["returncode"] != 0 or outcome["timed_out"] is not False:
                raise RuntimeError("AUTH browser execution did not succeed")
            original = source_copy / "test-output" / report_name
            if original.is_symlink() or not original.is_file() or original.stat().st_size > 65536:
                raise ValueError("AUTH browser report missing or unsafe")
            raw = load(original)
            if type(raw) is not dict or {"error", "errors", "error_type"} & raw.keys():
                raise ValueError("AUTH browser report contains execution errors")
            if scenario == "recovery" and set(raw) != set(PUBLIC_FIELDS):
                raise ValueError("Recovery browser report fields are missing or unexpected")
            # Only public, purpose-specific evidence is exported. No trace/HAR/storage state.
            candidate = {**report, **{field: raw.get(field) for field in PUBLIC_FIELDS}, "toolchain": toolchain}
            validator(candidate, image_id, postgres_image_id, manifest_hash)
            report = candidate
    except Exception as exc:
        report.update(status="failed", exit_code=1, error_type=type(exc).__name__)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--image-id", required=True)
    parser.add_argument("--postgres-image-id", required=True)
    parser.add_argument("--context-manifest-sha256", required=True)
    parser.add_argument("--scenario", choices=SCENARIOS, default="auth")
    args = parser.parse_args(argv)
    artifacts_name = "auth-recovery-artifacts" if args.scenario == "recovery" else "auth-artifacts"
    result = run_auth_browser(Path(__file__).resolve().parents[1], args.report.parent / artifacts_name,
                              args.image_id, args.postgres_image_id, args.context_manifest_sha256,
                              scenario=args.scenario)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    with args.report.open("x", encoding="utf-8") as stream:
        json.dump(result, stream, indent=2, sort_keys=True)
        stream.write("\n")
    print(json.dumps({"status": result["status"], "exit_code": result["exit_code"], "steps": result["steps"]}))
    return result["exit_code"]


if __name__ == "__main__":
    sys.exit(main())
