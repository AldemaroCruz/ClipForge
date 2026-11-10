"""Branding guard boundaries with synthetic metrics, including Python -O.

black_source, render_clip and pixel decoding are mocked. These regressions do
not execute FFmpeg, inspect user media, download a model or contact a provider.
The separate mandatory branding smoke remains responsible for real rendering.
"""
from __future__ import annotations

from contextlib import redirect_stdout
import copy
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

from app import check_branding as branding


SOURCE_ROOT = Path(__file__).resolve().parents[1]


def valid_metrics():
    def metric(y_min, y_max, cyan=0):
        return {"white_pixels": 128, "text_y_min": y_min, "text_y_max": y_max,
                "cyan_outline_pixels": cyan}
    return {
        "top": metric(60, 100), "center": metric(220, 250),
        "bottom": metric(360, 400), "top_margin400": metric(110, 150),
        "center_margin400": metric(220, 250), "border10": metric(60, 100, 201),
    }


def boundary_cases():
    """Named, manually expected outcomes, independent of the checker code."""
    cases = [("valid", valid_metrics(), True, None)]
    for value, passed in ((139, True), (140, False), (141, False)):
        metrics = valid_metrics()
        metrics["top"]["text_y_max"] = value
        cases.append((f"top_max_{value}", metrics, passed, "top"))
    for value, passed in ((179, False), (180, False), (181, True),
                          (279, True), (280, False), (281, False)):
        metrics = valid_metrics()
        for name in ("center", "center_margin400"):
            metrics[name]["text_y_min"] = value
            metrics[name]["text_y_max"] = value + 20
        cases.append((f"center_min_{value}", metrics, passed, "center"))
    for value, passed in ((349, False), (350, False), (351, True)):
        metrics = valid_metrics()
        metrics["bottom"]["text_y_min"] = value
        cases.append((f"bottom_min_{value}", metrics, passed, "bottom"))
    for offset, passed in ((46, False), (47, True), (50, True), (53, True), (54, False)):
        metrics = valid_metrics()
        metrics["top_margin400"]["text_y_min"] = metrics["top"]["text_y_min"] + offset
        cases.append((f"top_margin_offset_{offset}", metrics, passed, None))
    for offset, passed in ((-2, False), (-1, True), (0, True), (1, True), (2, False)):
        metrics = valid_metrics()
        metrics["center_margin400"]["text_y_min"] += offset
        cases.append((f"center_margin_offset_{offset}", metrics, passed, None))
    for value, passed in ((199, False), (200, False), (201, True)):
        metrics = valid_metrics()
        metrics["border10"]["cyan_outline_pixels"] = value
        cases.append((f"border_cyan_{value}", metrics, passed, "border10"))
    for value, passed in ((9, True), (10, False), (11, False)):
        metrics = valid_metrics()
        metrics["top"]["cyan_outline_pixels"] = value
        cases.append((f"top_cyan_{value}", metrics, passed, "top"))
    return cases


def expected_errors(metrics, passed, message_key):
    if passed:
        return []
    message = str(metrics[message_key]) if message_key is not None else ""
    return ["AssertionError: " + message]


def run_metrics(metrics, *, cli=False):
    def decoded_fixture(path):
        return copy.deepcopy(metrics[path.stem])
    with patch.object(branding, "black_source"), patch.object(branding, "render_clip"), \
            patch.object(branding, "pixels", side_effect=decoded_fixture):
        if not cli:
            return branding.check_branding()
        output = io.StringIO()
        with redirect_stdout(output):
            exit_code = branding.main()
        report, _ = json.JSONDecoder().raw_decode(output.getvalue())
        return exit_code, report


class BrandingCheckerTests(unittest.TestCase):
    def check_family(self, prefix):
        selected = [case for case in boundary_cases() if case[0].startswith(prefix)]
        self.assertGreater(len(selected), 0)
        for name, metrics, passed, message_key in selected:
            with self.subTest(case=name):
                report = run_metrics(metrics)
                self.assertEqual(report["status"], "ok" if passed else "failed")
                self.assertEqual(report["errors"], expected_errors(metrics, passed, message_key))
                self.assertEqual(report["checks"], metrics)
                self.assertFalse(report["transcription_tested"])

    def test_valid_fixture_reports_all_six_configurations(self):
        metrics = valid_metrics()
        report = run_metrics(metrics)
        self.assertEqual(report["status"], "ok")
        self.assertEqual(report["errors"], [])
        self.assertEqual(set(report["checks"]), set(metrics))
        self.assertEqual(len(report["checks"]), 6)

    def test_top_position_strict_boundary(self):
        self.check_family("top_max_")

    def test_center_position_both_strict_boundaries(self):
        self.check_family("center_min_")

    def test_bottom_position_strict_boundary(self):
        self.check_family("bottom_min_")

    def test_top_margin_inclusive_tolerance_in_both_directions(self):
        self.check_family("top_margin_offset_")

    def test_center_margin_inclusive_tolerance_in_both_directions(self):
        self.check_family("center_margin_offset_")

    def test_border_cyan_strict_boundary(self):
        self.check_family("border_cyan_")

    def test_top_cyan_strict_boundary(self):
        self.check_family("top_cyan_")

    def test_margin_failures_preserve_empty_assertion_messages(self):
        cases = [case for case in boundary_cases()
                 if "margin_offset_" in case[0] and not case[2]]
        self.assertEqual(len(cases), 4)
        for name, metrics, _, _ in cases:
            with self.subTest(case=name):
                self.assertEqual(run_metrics(metrics)["errors"], ["AssertionError: "])

    def subprocess_matrix(self, *, optimized):
        code = """
import json
import sys
sys.path.insert(0, sys.argv[1])
from test_branding_checker import boundary_cases, run_metrics
results = []
for name, metrics, passed, message_key in boundary_cases():
    exit_code, report = run_metrics(metrics, cli=True)
    results.append({'case': name, 'exit_code': exit_code, 'status': report['status'],
                    'errors': report['errors'], 'checks': len(report['checks'])})
print(json.dumps({'optimized': not __debug__, 'results': results}))
"""
        environment = {**os.environ, "PYTHONDONTWRITEBYTECODE": "1",
                       "CLIPFORGE_AI_PROVIDER": "disabled", "HF_HUB_OFFLINE": "1"}
        flags = ["-O"] if optimized else []
        result = subprocess.run(
            [sys.executable, "-B", *flags, "-c", code, str(SOURCE_ROOT / "tests")],
            cwd=SOURCE_ROOT, env=environment, capture_output=True, text=True,
            timeout=30, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        observed = json.loads(result.stdout)
        self.assertIs(observed["optimized"], optimized)
        cases = boundary_cases()
        self.assertEqual(len(observed["results"]), len(cases))
        for observed_case, (name, metrics, passed, message_key) in zip(observed["results"], cases):
            with self.subTest(optimized=optimized, case=name):
                self.assertEqual(observed_case, {
                    "case": name, "exit_code": 0 if passed else 1,
                    "status": "ok" if passed else "failed",
                    "errors": expected_errors(metrics, passed, message_key), "checks": 6,
                })

    def test_subprocess_matrix_normal_python(self):
        self.subprocess_matrix(optimized=False)

    def test_subprocess_matrix_optimized_python(self):
        self.subprocess_matrix(optimized=True)


if __name__ == "__main__":
    unittest.main()
