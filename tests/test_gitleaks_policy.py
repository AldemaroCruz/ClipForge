"""Policy/receipt contracts over authored fixtures; no scanner is executed."""
from __future__ import annotations

import ast
import contextlib
import copy
import hashlib
import io
import json
from pathlib import Path
import re
import tempfile
import tomllib
import unittest

from scripts import gitleaks_policy as policy
from scripts import prepare_ci_scan as scan


def fixture_policy_bytes():
    """Recreate the public approved policy without duplicating the frozen literal."""
    reference = Path(__file__).with_name("test_auth_recovery.py")
    tree = ast.parse(reference.read_text(encoding="utf-8"))
    values = [ast.literal_eval(node.value) for node in tree.body if isinstance(node, ast.Assign)
              and any(isinstance(target, ast.Name) and target.id == "FROZEN_AUTH01_DDL_SHA256"
                      for target in node.targets)]
    if len(values) != 1 or type(values[0]) is not str or not re.fullmatch(r"[0-9a-f]{64}", values[0]):
        raise ValueError("Public frozen-DDL fixture reference is missing or malformed")
    template = (
        '# AUTH-02: owner-approved public DDL checksum only. Preserve every default rule.\n'
        'title = "ClipForge: exact AUTH-01 DDL checksum classification"\n'
        'minVersion = "v8.30.1"\n\n[extend]\nuseDefault = true\n\n'
        '[[rules]]\nid = "generic-api-key"\n\n[[rules.allowlists]]\n'
        'description = "Approved public DDL checksum; review again if literal or assignment changes"\n'
        'condition = "AND"\nregexTarget = "line"\n'
        "paths = ['''^/source/tests/test_auth_recovery\\.py$''']\n"
        "regexes = ['''^\\n?FROZEN_AUTH01_DDL_SHA256 = '{ddl_sha256}'$''']\n"
    )
    return template.format(ddl_sha256=values[0]).encode("utf-8")


class GitleaksPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="gitleaks-policy-fixture-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.config = self.root / ".gitleaks.toml"
        self.approved = fixture_policy_bytes()
        self.config.write_bytes(self.approved)
        self.manifest = self.root / "source-scan-manifest.json"
        self.raw = self.root / "gitleaks-source.json"
        self.version = self.root / "gitleaks-version.txt"
        self.version.write_text("8.30.1\n", encoding="utf-8")
        self.raw.write_text("[]\n", encoding="utf-8")
        self.manifest_value = {"schema": scan.SCHEMA, "files": [{"path": ".gitleaks.toml",
            "bytes": len(self.approved), "sha256": hashlib.sha256(self.approved).hexdigest()}]}
        self.manifest.write_text(json.dumps(self.manifest_value), encoding="utf-8")
        self.calls = 0

    def record(self, raw_exit=0, **kwargs):
        self.calls += 1
        directory = self.root / f"receipt-{self.calls}"
        return policy.record_execution(config=self.config, source_manifest=self.manifest,
            raw_report=self.raw, raw_exit=raw_exit, scanner_image=kwargs.pop("scanner_image", policy.GITLEAKS_IMAGE),
            version_file=self.version, policy_copy=directory / "gitleaks-policy.toml",
            output=directory / "gitleaks-execution.json", **kwargs)

    def validate(self, report):
        policy.validate_execution(report, policy_path=self.root / f"receipt-{self.calls}" / "gitleaks-policy.toml",
            source_manifest_raw=self.manifest.read_bytes(), raw_report=self.raw.read_bytes(),
            version_text=self.version.read_text())

    def test_exact_policy_retains_defaults_and_matches_owner_fingerprint(self):
        self.assertEqual(hashlib.sha256(self.approved).hexdigest(), policy.POLICY_SHA256)
        self.assertEqual(policy.validate_policy(self.config),
                         {"sha256": policy.POLICY_SHA256, "bytes": len(self.approved), "defaults_retained": True})

    def test_policy_structure_rejects_broader_flags_paths_rules_and_line_classification(self):
        original = tomllib.loads(self.approved.decode())
        for mutation in ("defaults", "global", "rule", "extra_rule", "or", "target", "path", "extra_path", "regex", "extra_regex", "rule_override",
                         "framing_space", "framing_any", "framing_many", "framing_removed"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                item = value["rules"][0]["allowlists"][0]
                if mutation == "defaults": value["extend"]["useDefault"] = False
                elif mutation == "global": value["allowlist"] = {}
                elif mutation == "rule": value["rules"][0]["id"] = "github-pat"
                elif mutation == "extra_rule": value["rules"].append(copy.deepcopy(value["rules"][0]))
                elif mutation == "or": item["condition"] = "OR"
                elif mutation == "target": item["regexTarget"] = "secret"
                elif mutation == "path": item["paths"] = [".*"]
                elif mutation == "extra_path": item["paths"].append("other")
                elif mutation == "regex": item["regexes"] = [".*"]
                elif mutation == "extra_regex": item["regexes"].append("other")
                elif mutation.startswith("framing_"):
                    prefix = {"framing_space": r"^\s*", "framing_any": "^.*",
                              "framing_many": r"^\n*", "framing_removed": "^"}[mutation]
                    item["regexes"][0] = item["regexes"][0].replace(r"^\n?", prefix, 1)
                else: value["rules"][0]["regex"] = ".*"
                with self.assertRaises(policy.PolicyError): policy.validate_policy_structure(value)

    def test_whitespace_or_modified_policy_flags_do_not_match_reviewed_fingerprint(self):
        for raw in (self.approved + b"\n", self.approved.replace(b"useDefault = true", b"useDefault = false"),
                    self.approved.replace(b'condition = "AND"', b'condition = "OR"')):
            with self.subTest(raw_hash=hashlib.sha256(raw).hexdigest()):
                self.config.write_bytes(raw)
                with self.assertRaises(policy.PolicyError): policy.validate_policy(self.config)

    def test_record_copies_exact_policy_and_binds_all_input_hashes(self):
        report = self.record()
        self.assertEqual(report["status"], "passed")
        self.assertEqual(report["errors"], [])
        self.assertEqual(report["findings_count"], 0)
        self.assertEqual(report["source_manifest_sha256"], hashlib.sha256(self.manifest.read_bytes()).hexdigest())
        self.assertEqual(report["raw_report_sha256"], hashlib.sha256(self.raw.read_bytes()).hexdigest())
        self.assertEqual((self.root / "receipt-1/gitleaks-policy.toml").read_bytes(), self.approved)
        self.validate(report)

    def test_complete_unknown_findings_are_recorded_without_classifying_them_away(self):
        self.raw.write_text(json.dumps([{"RuleID": "unclassified-fixture", "Secret": "REDACTED"}]))
        report = self.record(1)
        self.assertEqual(report["status"], "security_findings")
        self.assertEqual(report["findings_count"], 1)
        self.assertEqual(report["errors"], [])
        self.validate(report)

    def test_nonzero_empty_zero_findings_and_invalid_exit_codes_are_errors(self):
        for code, findings in ((1, []), (2, []), (False, []), (0, [{}])):
            with self.subTest(code=code, findings=findings):
                self.raw.write_text(json.dumps(findings))
                report = self.record(code)
                self.assertEqual(report["status"], "error")
                self.assertEqual(report["raw_exit_code"], code)
                self.assertTrue(report["errors"])
                self.assertTrue((self.root / f"receipt-{self.calls}/gitleaks-execution.json").is_file())
                with self.assertRaises(policy.PolicyError): self.validate(report)

    def test_missing_report_still_preserves_scanner_failure_receipt(self):
        self.raw.unlink()
        report = self.record(125)
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["raw_exit_code"], 125)
        self.assertEqual(report["errors"][0]["stage"], "raw_report")
        self.assertIsNone(report["raw_report_sha256"])

    def test_wrong_scanner_or_version_is_rejected_without_echoing_untrusted_values(self):
        report = self.record(scanner_image="DO_NOT_EXPORT_FIXTURE")
        self.assertEqual(report["status"], "error")
        self.assertNotIn("DO_NOT_EXPORT_FIXTURE", json.dumps(report))
        self.version.write_text("v8.30.0")
        report = self.record()
        self.assertEqual(report["status"], "error")
        self.assertEqual(report["errors"][0]["stage"], "scanner_version")

    def test_manifest_requires_approved_policy_and_rejects_private_or_duplicate_names(self):
        original = copy.deepcopy(self.manifest_value)
        for mutation in ("missing", "hash", "bytes", "private", "duplicate"):
            with self.subTest(mutation=mutation):
                value = copy.deepcopy(original)
                if mutation == "missing": value["files"] = []
                elif mutation == "hash": value["files"][0]["sha256"] = "0" * 64
                elif mutation == "bytes": value["files"][0]["bytes"] = True
                elif mutation == "private": value["files"].append({**value["files"][0], "path": ".env.ai"})
                else: value["files"].append(copy.deepcopy(value["files"][0]))
                self.manifest.write_text(json.dumps(value))
                report = self.record()
                self.assertEqual(report["status"], "error")
                self.assertEqual(report["errors"][0]["stage"], "source_manifest")

    def test_execution_metadata_cannot_be_incomplete_forged_or_wrong_typed(self):
        original = self.record()
        for field in original:
            with self.subTest(missing=field):
                report = copy.deepcopy(original);del report[field]
                with self.assertRaises(policy.PolicyError): self.validate(report)
        for field, value in [("schema_version", True), ("status", "error"), ("raw_exit_code", False),
                             ("policy_sha256", "0" * 64), ("source_manifest_sha256", "0" * 64),
                             ("raw_report_sha256", "0" * 64), ("scanner_image", "latest"),
                             ("scanner_version", "8.30.0"), ("findings_count", False), ("errors", {})]:
            with self.subTest(field=field):
                report = copy.deepcopy(original);report[field] = value
                with self.assertRaises(policy.PolicyError): self.validate(report)

    def test_duplicate_or_malformed_raw_json_fails_closed(self):
        for raw in ('{}', '["not a finding"]', '[{"RuleID":"a","RuleID":"b"}]', '[NaN]'):
            with self.subTest(raw=raw):
                self.raw.write_text(raw)
                self.assertEqual(self.record(1)["status"], "error")

    def test_cli_preserves_failure_metadata_and_nonzero_status(self):
        directory = self.root / "cli-reports"
        with contextlib.redirect_stdout(io.StringIO()):
            code = policy.main(["record", "--config", str(self.config), "--source-manifest", str(self.manifest),
                "--raw-report", str(self.raw), "--exit-code", "2", "--version-file", str(self.version),
                "--scanner-image", policy.GITLEAKS_IMAGE, "--policy-copy", str(directory/'gitleaks-policy.toml'),
                "--output", str(directory/'gitleaks-execution.json')])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads((directory/'gitleaks-execution.json').read_text())["raw_exit_code"], 2)


if __name__ == "__main__":
    unittest.main()
