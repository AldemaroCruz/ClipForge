from copy import deepcopy
from datetime import datetime, timezone
import json
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import check_int_demo_a as gate
from scripts import int_demo_a_db_runner as runner
from scripts import int_demo_a_preflight as preflight


def facts(operation):
    release = "7.0.0-1018-aws"
    version = "7.0.0-1018.19~24.04.1"
    return {"schema": runner.SCHEMA, "image": "20261122.23.1", "os": "ubuntu24", "architecture": "x86_64",
            "kernel": {"release": release, "family": "aws", "signature": f"Ubuntu {version}-aws 7.0.5",
                       "packages": [["linux-image-" + release, version, "linux-signed-aws-7.0", version],
                                    ["linux-modules-" + release, version, "linux-aws-7.0", version]]},
            "tools": dict.fromkeys(runner.tool_names(operation), "b" * 64)}


def record(operation):
    return {"facts": facts(operation), "boot_id": "3f957269-13d3-4467-abc9-76d6e6118dfa", "run": "123",
            "attempt": "1", "job": runner.OPERATIONS[operation][1], "operation": operation, "commit": "a" * 40}


class DatabaseRunnerTests(unittest.TestCase):
    def test_exact_tools_follow_workflow_operation(self):
        secrets = facts("secret_versions")
        self.assertEqual(secrets, runner.checked(secrets, "secret_versions"))
        for operation in runner.OPERATIONS:
            self.assertFalse({"docker", "skopeo", "setpriv"} & runner.tool_names(operation))
        extras = ["ssh", "gcloud", "action_setup_gcloud", "action_upload_artifact"]
        self.assertTrue(set(extras).isdisjoint(secrets["tools"]))
        self.assertTrue(set(extras) <= runner.tool_names("guest_intervention"))
        for extra in extras:
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "db_runner_exact_tool_scope"):
                runner.checked({**secrets, "tools": {**secrets["tools"], extra: "a" * 64}}, "secret_versions")

    def test_action_refs_match_the_workflows_measured_for_each_operation(self):
        workflows = Path(__file__).resolve().parents[1] / ".github/workflows"
        for operation, (name, _) in runner.OPERATIONS.items():
            workflow = (workflows / name).read_text(encoding="utf-8")
            for action, (ref, _) in runner.ACTIONS.items():
                if f"action_{action}" in runner.tool_names(operation):
                    with self.subTest(operation=operation, action=action):
                        self.assertRegex(workflow, rf"(?m)^\s+uses: {ref}(?:\s+#.*)?$")

    def test_changed_actual_bytes_and_kernel_block_even_with_same_image(self):
        expected = facts("bootstrap")
        actual = record("bootstrap")
        with TemporaryDirectory() as tmp:
            path = Path(tmp)
            altered = deepcopy(actual)
            altered["facts"]["tools"]["gcloud_entry"] = "a" * 64
            with patch.object(runner, "observe", return_value=(path, altered)):
                with self.assertRaisesRegex(ValueError, "db_runner_actual_projection_mismatch"):
                    runner.verify(expected, "bootstrap", {}, {})
            altered = deepcopy(actual)
            altered["facts"]["kernel"]["signature"] = actual["facts"]["kernel"]["signature"].replace(".19~", ".20~")
            with self.assertRaisesRegex(ValueError, "db_runner_kernel_signature_match"):
                runner.checked(altered["facts"], "bootstrap")
            self.assertEqual(list(path.iterdir()), [])

    def test_checkpoint_precedes_credentials_and_compares_live_boot(self):
        actual = record("guest_intervention")
        expected = actual["facts"]
        with TemporaryDirectory() as tmp:
            path = Path(tmp)
            with patch.object(runner, "observe", return_value=(path, actual)):
                with self.assertRaisesRegex(ValueError, "db_runner_missing_preauth_checkpoint"):
                    runner.verify(expected, "guest_intervention", {"GCP_ACCESS_TOKEN": "test"}, {})
                runner.verify(expected, "guest_intervention", {}, {})
                runner.verify(expected, "guest_intervention", {"GCP_ACCESS_TOKEN": "test"}, {})
            checkpoint, = path.iterdir()
            self.assertEqual(checkpoint.stat().st_mode & 0o777, 0o600)
            with patch.object(runner, "observe", return_value=(path, {**actual, "boot_id": "another-boot"})):
                with self.assertRaisesRegex(ValueError, "db_runner_continuity_changed"):
                    runner.verify(expected, "guest_intervention", {"GCP_ACCESS_TOKEN": "test"}, {})

    def test_a_secret_bearing_process_cannot_start_the_admission_checkpoint(self):
        for operation, name in (("bootstrap", "INT_PG_SERVER_KEY"), ("bootstrap", "INT_PG_APP_PASSWORD"),
                                ("secret_versions", "INT_BOOTSTRAP_ADMIN"),
                                ("personal_sql_intervention", "INT_NOBLE_PERSONAL_SQL_PASSWORD")):
            with self.subTest(operation=operation), TemporaryDirectory() as tmp:
                target = Path(tmp)
                active = record(operation)
                with patch.object(runner, "observe", return_value=(target, active)):
                    with self.assertRaisesRegex(ValueError, "db_runner_missing_preauth_checkpoint"):
                        runner.verify(active["facts"], operation, {name: "fixture-input"}, {})
                    self.assertEqual(list(target.iterdir()), [])
                    runner.verify(active["facts"], operation, {}, {})
                    runner.verify(active["facts"], operation, {name: "fixture-input"}, {})

    def test_protected_db_routes_request_live_runner_binding_only_for_db(self):
        now = datetime(2026, 11, 23, 9, 0, tzinfo=timezone.utc)
        sha = "a" * 64
        for operation, workflow in [(name, f".github/workflows/{target[0]}")
                                    for name, target in runner.OPERATIONS.items()] + [
                                        ("oci_publication", ".github/workflows/int-demo-a-publish.yml")]:
            env = {"GITHUB_REPOSITORY": preflight.REPO, "GITHUB_REF": "refs/heads/" + preflight.BRANCH,
                   "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "RUNNER_ENVIRONMENT": "github-hosted",
                   "GITHUB_WORKFLOW_REF": f"{preflight.REPO}/{workflow}@refs/heads/{preflight.BRANCH}",
                   "GITHUB_SHA": "b" * 40, "INT_APPROVED_COMMIT": "b" * 40, "GITHUB_RUN_ID": "42",
                   "INT_DEMO_A_PROTECTED_DECISION_SHA256": sha}
            document = {"schema": preflight.SCHEMA, "status": "authorized_one_operation", "owner": "admin@ixbalam.studio",
                        "repository": preflight.REPO, "branch": preflight.BRANCH, "environment": "int",
                        "project": preflight.PROJECT, "control_commit": env["GITHUB_SHA"], "operation": operation,
                        "operation_id": "d" * 32, "issued_utc": now.isoformat(), "expires_utc": "2026-11-23T09:30:00+00:00",
                        "gate_mode": "global", "review_sha256": sha, "binding_sha256": sha, "inputs": {}}
            for protected in (False, True):
                with (self.subTest(operation=operation, protected=protected),
                      patch.object(preflight, "json_bytes", return_value=document), patch.object(gate, "main", return_value=0) as check):
                    preflight.local_decision(Path("."), sha, operation, workflow, env, protected=protected, now=now)
                    self.assertEqual("--match-credential-runner" in check.call_args.args[0],
                                     protected and operation in runner.OPERATIONS)

    def test_bootstrap_measures_sdk_before_wif(self):
        path = Path(__file__).resolve().parent.parent / gate.BOOTSTRAP_WORKFLOW
        workflow = path.read_text(encoding="utf-8")
        self.assertLess(workflow.index("Prepare the reviewed Cloud SDK version"), workflow.index("protected-admit --bundle"))
        self.assertLess(workflow.index("protected-admit --bundle"), workflow.index("protected-local --bundle"))
        self.assertLess(workflow.index("protected-local --bundle"), workflow.index("Federate solely as the existing Deploy"))

    def test_runner_review_binds_exact_native_kernel_targets_and_sources(self):
        root = Path(__file__).resolve().parent.parent
        at = gate.utc("2026-11-23T09:00:00+00:00")
        binding = {"operation": "secret_versions"}
        expected = facts(binding["operation"])
        sources = {name: gate.digest((root / name).read_bytes()) for name in (gate.NATIVE_HOST, gate.DB_RUNNER_SOURCE)}
        targets = {**dict.fromkeys(expected["tools"], ["tools"]), "runner_kernel": ["kernel"]}
        valid = [f"pkg:deb/ubuntu/{name}@{revision}" for name, revision, _, _ in expected["kernel"]["packages"]]
        with TemporaryDirectory() as tmp:
            folder = Path(tmp).resolve()

            def artifact(name, value):
                raw = json.dumps(value, sort_keys=True).encode()
                (folder / name).write_bytes(raw)
                return {"path": name, "sha256": gate.digest(raw)}

            subject = {"runner_host": artifact("runner.json", {"binding": binding, "facts": expected, "sources": sources,
                         "targets": targets, "checked_at": at.isoformat(), "expires_at": "2026-11-23T10:00:00+00:00"}),
                         "analyses": []}
            for kind, document in (
                ("trivy_toolchain", {"targets": {"kernel": valid, "tools": []}, "db_runner_targets": targets,
                                     "db_runner_host_sha256": subject["runner_host"]["sha256"]}),
                ("bandit", {"sha256_by_source_path": sources}),
                ("gitleaks", {"sha256_by_source_path": sources}),
            ):
                subject["analyses"].append({"kind": kind, "receipt": artifact(f"{kind}.json", {
                    "scope": artifact(f"{kind}-scope.json", document)})})
            with patch.object(runner, "verify") as live:
                gate.verify_db_runner(folder, subject, binding, at, root, {"run": "approved fixture"})
                live.assert_called_once_with(expected, binding["operation"], {"run": "approved fixture"}, binding)
            valid.pop()
            stale = {"targets": {"kernel": valid, "tools": []}, "db_runner_targets": targets,
                     "db_runner_host_sha256": subject["runner_host"]["sha256"]}
            subject["analyses"][0]["receipt"] = artifact("trivy-changed.json", {"scope": artifact("trivy-changed-scope.json", stale)})
            with self.assertRaisesRegex(ValueError, "db_runner_running_kernel_scan"):
                gate.verify_db_runner(folder, subject, binding, at, root, None)


if __name__ == "__main__":
    unittest.main()
