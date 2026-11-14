"""Proof regressions, including adversarial changes to classified source sites."""
import ast
from pathlib import Path
import tempfile
import unittest

from scripts import classify_int_foundation_sast as review


ROOT = Path(__file__).resolve().parents[1]


class FoundationSastReview(unittest.TestCase):
    def evaluate(self, name, rule, line, root=ROOT):
        tree = ast.parse((root / name).read_text())
        candidates = [node for node in ast.walk(tree) if isinstance(node, ast.Import if rule == "B404" else ast.Constant)
                      and node.lineno == line and (rule != "B108" or isinstance(node.value, str) and node.value.startswith("/"))]
        node = candidates[0] if candidates else tree.body[0]
        text = ""
        if rule == "B105":
            for mapping in ast.walk(tree):
                if isinstance(mapping, ast.Dict):
                    for key, value in zip(mapping.keys, mapping.values):
                        if key is node and isinstance(value, ast.Constant):
                            text = "Possible hardcoded password: '" + str(value.value) + "'"
        return review.evaluate(root, {"errors": [], "metrics": {"_totals": {"loc": 1}, name: {"loc": 1}},
            "results": [{"filename": name, "test_id": rule, "line_number": line,
                         "col_offset": node.col_offset, "end_col_offset": node.end_col_offset,
                         "issue_text": text, "issue_severity": "LOW"}]})

    def test_public_role_is_not_a_password_and_changed_value_stays_pending(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-sast-proof-") as temporary:
            root = Path(temporary)
            target = root / "scripts/check_tf_int.py"
            target.parent.mkdir()
            target.write_text('def expected_iam_role(address):\n    return {"google_secret_manager_secret_iam_member.runtime[": "roles/secretmanager.secretAccessor"}\n')
            self.assertEqual(self.evaluate("scripts/check_tf_int.py", "B105", 2, root)["findings"][0]["disposition"], "false_positive_proven")
            target.write_text('def expected_iam_role(address):\n    return "synthetic-changed-value"\n')
            self.assertEqual(self.evaluate("scripts/check_tf_int.py", "B105", 2, root)["status"], "blocked")
            target.write_text('def expected_iam_role(address):\n    password = "synthetic-changed-value"; public = "roles/secretmanager.secretAccessor"\n')
            self.assertEqual(self.evaluate("scripts/check_tf_int.py", "B105", 2, root)["status"], "blocked")

    def test_real_isolated_tmpfs_sites_and_shared_host_filename_are_distinct(self):
        source = (ROOT / "scripts/tf_int_plan.py").read_text()
        tree = ast.parse(source)
        sites = [node.lineno for node in ast.walk(tree) if isinstance(node, ast.Constant)
                 and isinstance(node.value, str) and node.value.endswith("noexec,size=128m")]
        self.assertEqual(len(sites), 2)
        for line in sites:
            self.assertEqual(self.evaluate("scripts/tf_int_plan.py", "B108", line)["findings"][0]["disposition"], "false_positive_proven")
        with tempfile.TemporaryDirectory(prefix="clipforge-sast-proof-") as temporary:
            root = Path(temporary); target = root / "scripts/tf_int_plan.py"; target.parent.mkdir()
            target.write_text('path = "/shared/synthetic.tmp"\n')
            self.assertEqual(self.evaluate("scripts/tf_int_plan.py", "B108", 1, root)["status"], "blocked")
            for before, after in (('"--network", "none"', '"--network", "bridge"'),
                                  ('"--cap-drop", "ALL"', '"--cap-drop", "NET_ADMIN"'),
                                  ('"--read-only", ', ''), ('uid + ":" + gid', '"0:0"')):
                target.write_text(source.replace(before, after))
                for line in sites:
                    self.assertEqual(self.evaluate("scripts/tf_int_plan.py", "B108", line, root)["status"], "blocked")

    def test_exception_only_import_does_not_classify_process_invocation(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-sast-proof-") as temporary:
            root = Path(temporary); target = root / "scripts/int_release.py"; target.parent.mkdir()
            target.write_text('import subprocess\ntry:\n    pass\nexcept subprocess.SubprocessError:\n    pass\n')
            self.assertEqual(self.evaluate("scripts/int_release.py", "B404", 1, root)["findings"][0]["disposition"], "control_verified")
            target.write_text(target.read_text() + 'subprocess.run(["synthetic"] )\n')
            self.assertEqual(self.evaluate("scripts/int_release.py", "B404", 1, root)["status"], "blocked")
            target.write_text('import subprocess\nsubprocess.SubprocessError = unsafe_callable\n')
            self.assertEqual(self.evaluate("scripts/int_release.py", "B404", 1, root)["status"], "blocked")
            target.write_text("import subprocess\nsetattr(subprocess.SubprocessError, '__init__', unsafe_callable)\n")
            self.assertEqual(self.evaluate("scripts/int_release.py", "B404", 1, root)["status"], "blocked")

    def test_foundation_checker_tmpfs_has_its_own_structural_evidence(self):
        name = "scripts/check_int_foundation.py"
        source = (ROOT / name).read_text()
        sites = [node.lineno for node in ast.walk(ast.parse(source)) if isinstance(node, ast.Constant)
                 and isinstance(node.value, str) and node.value.endswith("noexec,size=128m")]
        self.assertEqual(len(sites), 1)
        self.assertEqual(self.evaluate(name, "B108", sites[0])["findings"][0]["disposition"], "false_positive_proven")
        with tempfile.TemporaryDirectory(prefix="clipforge-sast-proof-") as temporary:
            root = Path(temporary); target = root / name; target.parent.mkdir()
            for before, after in (('--network=none', '--network=host'), ('--cap-drop=ALL', '--cap-drop=NET_ADMIN'),
                                  ('"--read-only", ', ''), ('size=128m', 'size=8g'),
                                  ('"--cap-drop=ALL",', '"--cap-drop=ALL", "--privileged",')):
                target.write_text(source.replace(before, after))
                self.assertEqual(self.evaluate(name, "B108", sites[0], root)["status"], "blocked")

    def test_process_calls_unknown_findings_and_scanner_errors_stay_blocked(self):
        for rule in ("B603", "B404", "B999"):
            self.assertEqual(self.evaluate("scripts/tf_int_plan.py", rule, 169)["status"], "blocked")
        for report in ({}, {"errors": [], "results": []}, {"errors": ["scanner error"], "results": []}):
            self.assertEqual(review.evaluate(ROOT, report)["status"], "blocked")


if __name__ == "__main__":
    unittest.main()
