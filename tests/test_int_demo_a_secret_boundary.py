"""Verify the protected job graph avoids secret expansion and execution on host rejection."""

from contextlib import redirect_stdout
from io import StringIO
from pathlib import Path
import re
import unittest
from unittest.mock import patch

from scripts import int_demo_a_secrets as versions


ROOT = Path(__file__).resolve().parents[1]
HOST_OK = "steps.host_admission.outcome == 'success'"
BOOTSTRAP = "int-db01-noble-bootstrap.yml"
VERSIONS = "int-demo-a-secrets.yml"
INTERVENTION = "int-db01-noble-intervention.yml"


class SecretBoundaryTests(unittest.TestCase):
    def read_steps(self, name):
        text = (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        sections = re.split(r"(?m)^      - name: ", text)
        self.assertNotIn("secrets.", sections[0])
        return sections[1:]

    def check_bindings(self, block, aliases, guard):
        # StepsRunner can evaluate step.env before step.if. The expression must
        # short-circuit the secret lookup itself, even when the step is skipped.
        lines = [line.strip() for line in block.splitlines() if "secrets." in line]
        prefix = "${{ " + " && ".join(guard) + " && secrets."
        expected = [f"{variable}: {prefix}{secret} || '' " + "}}"
                    for variable, secret in aliases.items()]
        self.assertCountEqual(lines, expected)
        condition = re.search(r"(?m)^        if: (.+)$", block)
        if condition:
            self.assertIn("success()", condition[1])
            self.assertIn(HOST_OK, condition[1])

    def test_bootstrap_and_versions_require_successful_secretless_admission(self):
        common = {"INT_PG_APP_PASSWORD": "INT_APP_PASSWORD", "INT_PG_MIGRATOR_PASSWORD": "INT_MIGRATOR_PASSWORD",
                  "INT_PG_CA_CERT": "INT_POSTGRES_CA"}
        operations = {
            BOOTSTRAP: ({**common, "INT_PG_SERVER_CERT": "INT_PG_SERVER_CERT", "INT_PG_SERVER_KEY": "INT_PG_SERVER_KEY"},
                        "cloud_preflight"),
            VERSIONS: ({**common, "INT_BOOTSTRAP_ADMIN": "INT_BOOTSTRAP_ADMIN_JSON"}, "auth"),
        }
        for name, (aliases, last_guard) in operations.items():
            with self.subTest(workflow=name):
                steps = self.read_steps(name)
                [admit] = [i for i, step in enumerate(steps) if "\n        id: host_admission\n" in step]
                [auth] = [i for i, step in enumerate(steps) if "\n        id: auth\n" in step]
                self.assertIn(" protected-admit ", steps[admit])
                self.assertNotIn("continue-on-error:", steps[admit])
                self.assertNotIn("secrets.", steps[admit])
                self.assertNotIn("GCP_ACCESS_TOKEN:", steps[admit])
                [first, last] = [i for i, step in enumerate(steps) if "secrets." in step]
                self.assertLess(admit, first)
                self.assertLess(first, auth)
                self.assertLess(auth, last)
                self.assertIn("if: ${{ success() && " + HOST_OK, steps[first])
                self.assertIn("steps.protected_inputs.outcome == 'success'", steps[auth])
                self.check_bindings(steps[first], aliases, [HOST_OK])
                self.check_bindings(steps[last], aliases, [HOST_OK, f"steps.{last_guard}.outcome == 'success'"])

    def test_personal_secret_lookup_requires_late_runner_recheck_and_activate(self):
        steps = self.read_steps(INTERVENTION)
        [admit] = [i for i, step in enumerate(steps) if "\n        id: host_admission\n" in step]
        [native] = [i for i, step in enumerate(steps) if "secrets." in step]
        self.assertLess(admit, native)
        self.assertIn(" protected-local ", steps[admit])
        self.assertIn("--backend-observation", steps[admit])
        self.assertNotIn("continue-on-error:", steps[admit])
        self.check_bindings(steps[native], {"INT_NOBLE_PERSONAL_SQL_PASSWORD": "INT_NOBLE_PERSONAL_SQL_PASSWORD"},
                            ["inputs.operation == 'personal_activate'", HOST_OK, "steps.auth.outcome == 'success'"])

    def test_secretless_versions_admission_stops_before_values_and_bootstrap_on_host_failure(self):
        with (patch.dict(versions.os.environ, {"GH_TOKEN": "fixture-actions-read"}, clear=True),
              patch.object(versions.preflight, "local_decision",
                           side_effect=versions.transport.Blocked("db_runner_actual_projection_mismatch")) as admission,
              patch.object(versions, "prerequisite") as prior,
              patch.object(versions, "protected_values") as values,
              redirect_stdout(StringIO()) as output):
            code = versions.main(["protected-admit", "--bundle", "/fixture", "--decision-sha256", "a" * 64])
        self.assertEqual(code, 1)
        self.assertIn("db_runner_actual_projection_mismatch", output.getvalue())
        self.assertTrue(admission.call_args.kwargs["protected"])
        prior.assert_not_called()
        values.assert_not_called()


if __name__ == "__main__":
    unittest.main()
