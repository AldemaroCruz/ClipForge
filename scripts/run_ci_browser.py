"""Run six existing browser scenarios in copied sources and fresh fixture data.

This command belongs in the separate browser CI image with --init and no
published ports. AUTH-01 uses an explicitly verified internal Docker network
for isolated PostgreSQL, not --network none. Provider/ASR remain fixtures.
Five scenarios use actual loopback HTTP; browser_smoke mocks API responses.
No bridge fallback is accepted. Nothing executes when this module is imported.
"""
from __future__ import annotations

import argparse
import importlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Callable, Mapping


SCENARIOS = (
    ("smoke", "browser_smoke.py", "simulated_fetch"),
    ("workflow", "browser_workflow.py", "direct_http"),
    ("editorial", "browser_editorial.py", "direct_http"),
    ("delivery", "browser_delivery.py", "direct_http"),
    ("ai", "browser_ai.py", "direct_http"),
    ("operations", "browser_operations.py", "direct_http"),
)
SOURCE_DIRECTORIES = (
    ("app", {".py"}), ("app/static", {".html", ".js", ".css"}),
    ("scripts", {".py"}), ("tests", {".py"}),
)
BRIDGE_MARKERS = ("bridge in use", "http bridge", "python-to-http test bridge")


def copy_browser_sources(source: Path, destination: Path) -> None:
    """Copy only direct code/static files; never traverse data or configuration."""
    destination.mkdir(parents=True, exist_ok=False)
    for directory, suffixes in SOURCE_DIRECTORIES:
        origin = source / directory
        if origin.is_symlink() or not origin.is_dir():
            raise ValueError("Browser source directory is unavailable or linked")
        target = destination / directory
        target.mkdir(parents=True, exist_ok=True)
        for path in sorted(origin.iterdir()):
            if path.suffix not in suffixes:
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError("Browser source must be a regular file")
            shutil.copyfile(path, target / path.name)


def inspect_toolchain() -> dict:
    """Verify the installed Playwright package and its own Chromium manifest."""
    package = importlib.import_module("playwright")
    api = importlib.import_module("playwright.sync_api")
    manifest = Path(package.__file__).parent / "driver" / "package" / "browsers.json"
    declared = next(item for item in json.loads(manifest.read_text(encoding="utf-8"))["browsers"]
                    if item["name"] == "chromium")
    with api.sync_playwright() as playwright:
        executable = Path(playwright.chromium.executable_path)
        if not executable.is_file():
            raise FileNotFoundError("The pinned Chromium browser has not been prepared")
        browser = playwright.chromium.launch(
            executable_path=str(executable), headless=True,
            args=["--no-sandbox", "--disable-dev-shm-usage"],
        )
        try:
            version = browser.version
        finally:
            browser.close()
    if version != declared["browserVersion"]:
        raise ValueError("Chromium does not match the installed Playwright manifest")
    return {
        "playwright_version": importlib.metadata.version("playwright"),
        "chromium_version": version, "chromium_revision": declared["revision"],
        "system": platform.system(), "machine": platform.machine(),
        "executable": str(executable),
    }


def execute_browser_script(script: Path, source: Path, environment: Mapping[str, str],
                           stdout: Path, stderr: Path, timeout: int) -> dict:
    """Own one process group so a timed-out fixture API cannot be left running."""
    with stdout.open("x", encoding="utf-8") as out, stderr.open("x", encoding="utf-8") as err:
        process = subprocess.Popen(
            [sys.executable, "-B", str(script)], cwd=source, env=dict(environment),
            stdout=out, stderr=err, start_new_session=True,
        )
        try:
            return {"returncode": process.wait(timeout=timeout), "timed_out": False}
        except subprocess.TimeoutExpired:
            if os.name == "posix":
                os.killpg(process.pid, signal.SIGTERM)
            else:
                process.terminate()
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                if os.name == "posix":
                    os.killpg(process.pid, signal.SIGKILL)
                else:
                    process.kill()
                process.wait(timeout=5)
            return {"returncode": process.returncode, "timed_out": True}


def collect_generated_artifacts(source: Path, destination: Path) -> None:
    output = source / "test-output"
    if not output.exists():
        return
    if output.is_symlink() or not output.is_dir():
        raise ValueError("Unexpected generated browser artifact root")
    destination.mkdir(exist_ok=False)
    for path in sorted(output.iterdir()):
        if path.suffix not in {".png", ".log", ".json", ".txt", ".srt", ".vtt"}:
            continue
        if path.is_symlink() or not path.is_file():
            raise ValueError("Unexpected linked browser artifact")
        shutil.copyfile(path, destination / path.name)


def run_browsers(source_root: Path, artifact_directory: Path, *,
                 environ: Mapping[str, str] | None = None,
                 toolchain_inspector: Callable = inspect_toolchain,
                 script_executor: Callable = execute_browser_script,
                 which: Callable = shutil.which) -> dict:
    environment = dict(os.environ if environ is None else environ)
    report = {
        "schema_version": 1, "status": "failed", "exit_code": 1,
        "external_network_isolation_required": True,
        "bridge_allowed": False, "real_asr_inference_tested": False,
        "real_llm_inference_tested": False, "checks": [], "scenarios": [],
    }
    try:
        artifact_directory.mkdir(parents=True, exist_ok=False)
        for binary in ("ffmpeg", "ffprobe"):
            report["checks"].append({"name": binary, "status": "passed" if which(binary) else "failed"})
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-browser-") as temporary:
            workspace = Path(temporary) / "sources"
            copy_browser_sources(source_root, workspace)
            safe_environment = {
                **environment,
                "CLIPFORGE_DATA_DIR": str(Path(temporary) / "bootstrap-data"),
                "CLIPFORGE_AI_PROVIDER": "disabled", "CLIPFORGE_MODEL_LOCK": "",
                "CLIPFORGE_BROWSER_BRIDGE": "0", "PYTHONDONTWRITEBYTECODE": "1",
                "HF_HOME": str(Path(temporary) / "huggingface"),
                "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1", "PIP_NO_INDEX": "1",
            }
            try:
                toolchain = toolchain_inspector()
                safe_environment["CHROMIUM_EXECUTABLE"] = toolchain.pop("executable")
                report["toolchain"] = toolchain
                report["checks"].append({"name": "browser_toolchain", "status": "passed"})
            except Exception as exc:
                report["checks"].append({"name": "browser_toolchain", "status": "failed", "error_type": type(exc).__name__})
            ready = all(check["status"] == "passed" for check in report["checks"])
            for name, filename, transport in SCENARIOS:
                scenario = {"name": name, "script": filename, "transport": transport,
                            "status": "blocked", "reported_steps": 0}
                if ready:
                    stdout = artifact_directory / (name + ".stdout.log")
                    stderr = artifact_directory / (name + ".stderr.log")
                    try:
                        outcome = script_executor(workspace / "tests" / filename, workspace,
                                                  safe_environment, stdout, stderr, 300)
                        scenario.update(outcome)
                        text = stdout.read_text(encoding="utf-8") + "\n" + stderr.read_text(encoding="utf-8")
                        bridge_used = any(marker in text.lower() for marker in BRIDGE_MARKERS)
                        scenario["bridge_detected"] = bridge_used
                        scenario["reported_steps"] = sum(line.startswith("PASS:") for line in text.splitlines())
                        scenario["status"] = (
                            "passed" if outcome["returncode"] == 0 and not outcome["timed_out"]
                            and not bridge_used and scenario["reported_steps"] > 0 else "failed"
                        )
                    except Exception as exc:
                        scenario.update(status="failed", error_type=type(exc).__name__)
                report["scenarios"].append(scenario)
            collect_generated_artifacts(workspace, artifact_directory / "generated")
    except Exception as exc:
        report["checks"].append({"name": "browser_isolation", "status": "failed", "error_type": type(exc).__name__})
    if (report["checks"] and all(check["status"] == "passed" for check in report["checks"])
            and len(report["scenarios"]) == len(SCENARIOS)
            and all(scenario["status"] == "passed" for scenario in report["scenarios"])):
        report.update(status="passed", exit_code=0)
    report["direct_http_scenarios_passed"] = sum(
        scenario["status"] == "passed" and scenario["transport"] == "direct_http"
        for scenario in report["scenarios"]
    )
    report["simulated_api_scenarios_passed"] = sum(
        scenario["status"] == "passed" and scenario["transport"] == "simulated_fetch"
        for scenario in report["scenarios"]
    )
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    report = run_browsers(Path(__file__).resolve().parents[1], args.report.parent / "browser-artifacts")
    try:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        with args.report.open("x", encoding="utf-8") as output:
            json.dump(report, output, indent=2, sort_keys=True)
            output.write("\n")
    except Exception as exc:
        report.update(status="failed", exit_code=1)
        report["checks"].append({"name": "report_write", "status": "failed", "error_type": type(exc).__name__})
    print(json.dumps(report, indent=2, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
