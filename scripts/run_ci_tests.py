"""Strict CI gate over disposable data; never imports the application on import.

Run in the CI image with external networking disabled (``--network none``).
Localhost remains available for the suite's explicitly simulated HTTP providers.
The configured data path must be below the system temporary directory; a fresh,
separate temporary directory is actually used so existing data is never opened.
Only the optional JSON report is retained after execution.
"""
from __future__ import annotations

import argparse
from collections import Counter
from contextlib import contextmanager, redirect_stderr, redirect_stdout
import hashlib
import importlib
import json
import math
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
from typing import Callable, Mapping, TextIO
import unittest


CHECK_COMMANDS = (
    ("pip_check", ("pip", "check"), 60),
    ("runtime", ("app.check_runtime",), 180),
    ("media", ("app.check_media",), 180),
    ("presentation", ("app.check_presentation",), 240),
    ("branding", ("app.check_branding",), 240),
)


def environment_check(environ: Mapping[str, str]) -> dict:
    """Validate configuration without opening or enumerating the data directory."""
    valid = environ.get("CLIPFORGE_AI_PROVIDER") == "disabled"
    raw_path = environ.get("CLIPFORGE_DATA_DIR", "")
    try:
        path = Path(raw_path)
        temporary = Path(tempfile.gettempdir()).resolve()
        # Check containment before resolving an input outside the allowed area.
        temporary_path = (bool(raw_path) and path.is_absolute()
                          and path != temporary and path.is_relative_to(temporary))
        if temporary_path:
            resolved = path.resolve()
            temporary_path = resolved != temporary and resolved.is_relative_to(temporary)
        valid = valid and temporary_path
    except (OSError, ValueError, RuntimeError):
        valid = False
    return {"name": "isolated_environment", "status": "passed" if valid else "failed"}


@contextmanager
def isolated_process(environ: Mapping[str, str], source_root: Path):
    """Install safe settings before a checker or test can import app.main."""
    previous_environment = dict(os.environ)
    previous_path = sys.path[:]
    previous_bytecode = sys.dont_write_bytecode
    try:
        os.environ.clear()
        os.environ.update(environ)
        sys.path.insert(0, str(source_root))
        sys.dont_write_bytecode = True
        yield
    finally:
        os.environ.clear()
        os.environ.update(previous_environment)
        sys.path[:] = previous_path
        sys.dont_write_bytecode = previous_bytecode


def discover_suite(source_root: Path) -> unittest.TestSuite:
    return unittest.TestLoader().discover(str(source_root / "tests"), pattern="test_*.py")


def execute_suite(suite: unittest.TestSuite, stream: TextIO) -> unittest.TestResult:
    return unittest.TextTestRunner(stream=stream, verbosity=2).run(suite)


def test_inventory(suite: unittest.TestSuite) -> dict:
    """Collect actual discovered IDs before unittest consumes its suite."""
    def identifiers(node):
        if isinstance(node, unittest.TestCase):
            yield node.id()
        else:
            for child in node:
                yield from identifiers(child)
    ids = sorted(identifiers(suite))
    frequencies = Counter(ids)
    return {
        "ids": ids,
        "discovered": len(ids),
        "unique": len(frequencies),
        "duplicate_ids": sorted(name for name, count in frequencies.items() if count > 1),
        "modules": dict(sorted(Counter(name.rsplit(".", 2)[0] for name in ids).items())),
        "sha256_utf8_lf": hashlib.sha256(("\n".join(ids) + "\n").encode("utf-8")).hexdigest(),
    }


def start_coverage(source_root: Path, destination: Path, factory: Callable | None = None):
    """Measure all app/scripts sources with no repository omit configuration."""
    destination.mkdir(parents=True, exist_ok=False)
    if factory is None:
        factory = importlib.import_module("coverage").Coverage
    collector = factory(
        source=[str(source_root / "app"), str(source_root / "scripts")],
        branch=True, config_file=False, omit=[],
        data_file=str(destination / ".coverage"), check_preimported=True,
    )
    collector.start()
    return collector


def finish_coverage(collector, destination: Path) -> dict:
    collector.stop()
    collector.save()
    percent = collector.json_report(outfile=str(destination / "coverage.json"), pretty_print=True)
    collector.xml_report(outfile=str(destination / "coverage.xml"))
    if not isinstance(percent, (int, float)) or not math.isfinite(percent) or not 0 <= percent <= 100:
        raise ValueError("Invalid coverage percentage")
    return {
        "requested": True, "measured": True, "status": "passed",
        "percent_covered": percent, "source": ["app", "scripts"], "branch": True,
        "omit": [], "threshold": None,
        "scope": "current_process_unittest_with_explicit_mocks_and_threads",
        "browser_included": False, "subprocesses_included": False,
        "native_checker_subprocesses_included": False,
    }


def test_counts(result: unittest.TestResult) -> dict:
    return {
        "tests_run": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "expected_failures": len(result.expectedFailures),
        "unexpected_successes": len(result.unexpectedSuccesses),
    }


def suite_passed(counts: Mapping[str, int]) -> bool:
    return counts["tests_run"] > 0 and not any(
        counts[name] for name in (
            "failures", "errors", "skipped", "expected_failures", "unexpected_successes"
        )
    )


def run_ci(
    source_root: Path,
    *,
    environ: Mapping[str, str] | None = None,
    command_runner: Callable = subprocess.run,
    which: Callable = shutil.which,
    discover: Callable = discover_suite,
    suite_executor: Callable = execute_suite,
    coverage_directory: Path | None = None,
    coverage_factory: Callable | None = None,
    stream: TextIO | None = None,
) -> dict:
    """Run every check and the whole suite, retaining only non-sensitive counts."""
    environment = dict(os.environ if environ is None else environ)
    output = sys.stderr if stream is None else stream
    report = {
        "schema_version": 1,
        "status": "failed",
        "checks": [environment_check(environment)],
        "tests": {
            "tests_run": 0, "failures": 0, "errors": 0, "skipped": 0,
            "expected_failures": 0, "unexpected_successes": 0,
        },
        "suite_status": "not_started",
        "test_inventory": {"ids": [], "discovered": 0, "unique": 0, "duplicate_ids": []},
        "coverage": {
            "requested": coverage_directory is not None, "measured": False,
            "status": "not_requested" if coverage_directory is None else "not_started",
            "source": ["app", "scripts"], "threshold": None,
        },
        "policy": {
            "require_nonempty": True,
            "allow_skips": False,
            "allow_expected_failures": False,
            "allow_unexpected_successes": False,
            "external_network_isolation_required": True,
        },
        "real_asr_inference_tested": False,
        "real_llm_inference_tested": False,
        "exit_code": 1,
    }
    for binary in ("ffmpeg", "ffprobe"):
        try:
            present = bool(which(binary))
            report["checks"].append({
                "name": binary, "status": "passed" if present else "failed",
            })
        except Exception as exc:
            report["checks"].append({
                "name": binary, "status": "failed", "error_type": type(exc).__name__,
            })

    try:
        with tempfile.TemporaryDirectory(prefix="clipforge-ci-") as temporary:
            # Never reuse the configured path, even if it already contains files.
            safe_environment = {
                **environment,
                "CLIPFORGE_DATA_DIR": str(Path(temporary) / "data"),
                "CLIPFORGE_AI_PROVIDER": "disabled",
                "CLIPFORGE_MODEL_LOCK": "",
                "HF_HOME": str(Path(temporary) / "huggingface"),
                "HF_HUB_OFFLINE": "1",
                "HF_HUB_DISABLE_TELEMETRY": "1",
                "TRANSFORMERS_OFFLINE": "1",
                "PIP_NO_INDEX": "1",
                "PIP_DISABLE_PIP_VERSION_CHECK": "1",
                "PYTHONDONTWRITEBYTECODE": "1",
            }
            with isolated_process(safe_environment, source_root):
                for name, arguments, timeout in CHECK_COMMANDS:
                    check = {"name": name, "status": "failed"}
                    try:
                        completed = command_runner(
                            [sys.executable, "-B", "-m", *arguments],
                            cwd=source_root, env=safe_environment,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                            timeout=timeout, check=False,
                        )
                        check["returncode"] = completed.returncode
                        if completed.returncode == 0:
                            check["status"] = "passed"
                    except Exception as exc:
                        # Exceptions/checker output may contain arbitrary text.
                        check["error_type"] = type(exc).__name__
                    report["checks"].append(check)
                    print(f"CI check {name}: {check['status']}", file=output)

                collector = None
                if coverage_directory is not None:
                    try:
                        collector = start_coverage(source_root, coverage_directory, coverage_factory)
                    except Exception as exc:
                        report["coverage"]["status"] = "failed"
                        report["checks"].append({
                            "name": "coverage", "status": "failed", "error_type": type(exc).__name__,
                        })
                try:
                    with redirect_stdout(output), redirect_stderr(output):
                        suite = discover(source_root)
                        report["test_inventory"] = test_inventory(suite)
                        inventory_ok = (report["test_inventory"]["discovered"] > 0
                                        and not report["test_inventory"]["duplicate_ids"])
                        report["checks"].append({
                            "name": "test_inventory", "status": "passed" if inventory_ok else "failed",
                        })
                        result = suite_executor(suite, output)
                    report["tests"] = test_counts(result)
                    report["checks"].append({
                        "name": "test_execution_completeness",
                        "status": ("passed" if report["tests"]["tests_run"]
                                   == report["test_inventory"]["discovered"] else "failed"),
                    })
                    report["suite_status"] = (
                        "passed" if suite_passed(report["tests"]) else "failed"
                    )
                except (Exception, SystemExit) as exc:
                    report["suite_status"] = "discovery_or_runner_error"
                    report["tests"]["errors"] += 1
                    report["suite_error_type"] = type(exc).__name__
                finally:
                    if collector is not None:
                        try:
                            report["coverage"] = finish_coverage(collector, coverage_directory)
                            report["checks"].append({"name": "coverage", "status": "passed"})
                        except Exception as exc:
                            report["coverage"]["status"] = "failed"
                            report["checks"].append({
                                "name": "coverage", "status": "failed", "error_type": type(exc).__name__,
                            })
    except Exception as exc:
        report["checks"].append({
            "name": "isolated_execution", "status": "failed",
            "error_type": type(exc).__name__,
        })

    if (all(check["status"] == "passed" for check in report["checks"])
            and report["suite_status"] == "passed"):
        report["status"] = "passed"
        report["exit_code"] = 0
    return report


def write_report(report: dict, destination: Path) -> None:
    """Create one report exclusively; never replace an existing artifact."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    with destination.open("x", encoding="utf-8") as output:
        json.dump(report, output, indent=2, sort_keys=True)
        output.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--report", type=Path, help="New JSON artifact; existing files are rejected.")
    parser.add_argument("--coverage", type=Path,
                        help="Coverage artifact directory; defaults to report-parent/coverage in CI.")
    args = parser.parse_args(argv)
    coverage_directory = args.coverage
    if coverage_directory is None and args.report is not None:
        coverage_directory = args.report.parent / "coverage"
    report = run_ci(Path(__file__).resolve().parents[1], coverage_directory=coverage_directory)
    if args.report is not None:
        try:
            write_report(report, args.report)
        except Exception as exc:
            report["status"] = "failed"
            report["exit_code"] = 1
            report["checks"].append({
                "name": "report_write", "status": "failed", "error_type": type(exc).__name__,
            })
    print(json.dumps(report, indent=2, sort_keys=True))
    return report["exit_code"]


if __name__ == "__main__":
    raise SystemExit(main())
