"""Synthetic TF-INT-01 contracts; no cloud, local state or credential access."""
from __future__ import annotations

import copy
import hashlib
import io
import json
import os
import re
import subprocess
import sys
from pathlib import Path
import tempfile
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scripts import check_tf_int as c, tf_int_plan as driver


IMAGE = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "a" * 64
VERSIONS = {key: "1" for key in ("app_password", "migrator_password", "postgres_ca", "bootstrap_admin")}


def runtime_template_fixture():
    return {"containers": [{"image": IMAGE, "env": []}], "vpc_access": [{"egress": "PRIVATE_RANGES_ONLY"}]}


def fixture():
    rows = []
    for address in sorted(c.ADDRESSES):
        kind, name = address.split(".", 1)
        name = re.sub(r"\[.*", "", name)
        values = {}
        if kind == "google_compute_instance":
            values = {"network_interface": [{"access_config": [], "ipv6_access_config": []}],
                      "deletion_protection": True, "can_ip_forward": False, "machine_type": "e2-micro",
                      "attached_disk": [{"device_name": "clipforge-pg-data"}], "boot_disk": [{"auto_delete": False}],
                      "metadata": {"enable-oslogin": "TRUE", "block-project-ssh-keys": "TRUE",
                                   "disable-legacy-endpoints": "TRUE", "serial-port-enable": "FALSE"},
                      "metadata_startup_script": "# authored startup fixture",
                      "shielded_instance_config": [{"enable_secure_boot": True, "enable_vtpm": True, "enable_integrity_monitoring": True}]}
        elif kind == "google_compute_disk":
            values = {"size": 20, "type": "pd-standard"}
        elif kind == "google_storage_bucket":
            values = {"force_destroy": False, "uniform_bucket_level_access": True,
                      "public_access_prevention": "enforced", "versioning": [{"enabled": True}]}
        elif kind == "google_compute_subnetwork":
            values = {"ip_cidr_range": "10.80.0.0/26", "private_ip_google_access": True, "stack_type": "IPV4_ONLY"}
        elif kind == "google_compute_address":
            values = {"address_type": "INTERNAL"}
        elif kind == "google_compute_network":
            values = {"auto_create_subnetworks": False}
        elif kind == "google_compute_router_nat":
            values = {"source_subnetwork_ip_ranges_to_nat": "LIST_OF_SUBNETWORKS", "subnetwork": [{}]}
        elif kind == "google_compute_firewall":
            values = {"target_service_accounts": ["clipforge-postgres-int@clipforgebeta2.iam.gserviceaccount.com"]}
            if name in {"postgres", "iap"}:
                values.update(direction="INGRESS", source_ranges=["35.235.240.0/20" if name == "iap" else "10.80.0.0/26"],
                              allow=[{"protocol": "tcp", "ports": ["22" if name == "iap" else "5432"]}])
            elif name == "https":
                values.update(direction="EGRESS", allow=[{"protocol": "tcp", "ports": ["443"]}])
            else:
                values.update(direction="EGRESS", deny=[{"protocol": "all", "ports": []}])
        elif kind == "google_cloud_run_v2_service":
            values = {"iap_enabled": True, "template": [{"scaling": [{"min_instance_count": 0, "max_instance_count": 1}], **runtime_template_fixture()}]}
        elif kind == "google_cloud_run_v2_job":
            values = {"template": [{"task_count": 1, "parallelism": 1, "template": [{"max_retries": 0, **runtime_template_fixture()}]}]}
        elif kind == "google_project_iam_audit_config":
            values = {"service": "storage.googleapis.com", "audit_log_config": [{"log_type": "ADMIN_READ"}, {"log_type": "DATA_READ"}, {"log_type": "DATA_WRITE"}]}
        elif kind == "google_logging_project_bucket_config":
            values = {"retention_days": 30}
        elif kind == "google_project_iam_custom_role":
            values = {"permissions": ["compute.instances.get", "compute.disks.get", "compute.projects.get", "run.operations.get"]}
        elif "_iam_member" in kind:
            values = {"member": c.expected_iam_member(address), "role": c.expected_iam_role(address)}
            if name in {"pilot_admin", "audit_reader"}:
                values["member"] = "user:admin@ixbalam.studio"
            elif name == "iap_invoker":
                values.update(member="serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com", role="roles/run.invoker")
        rows.append({"address": address, "mode": "managed", "type": kind, "name": name,
                     "change": {"actions": ["create"], "before": None, "after": values}})
    return {"variables": {**{v: {"value": "authored input"} for v in c.VARIABLES}, "stage": {"value": "runtime"}, "runtime_image": {"value": IMAGE}, "secret_versions": {"value": VERSIONS}},
            "output_changes": {"reviewed_boundary": {}}, "resource_changes": rows}


class TFIntContracts(unittest.TestCase):
    def test_direct_cli_can_import_custody_from_an_unrelated_directory(self):
        # Reproduce Actions' scripts-only import path without PYTHONPATH or cwd
        # assistance. Importing these helpers must never make a cloud request.
        program = """
import importlib,json,os,runpy,socket,sys
def no_network(*args, **kwargs):
    raise AssertionError('CLI import attempted a network operation')
socket.socket.connect=no_network
script=sys.argv[1]
sys.path.insert(0,os.path.dirname(script))
runpy.run_path(script,run_name='tf_int_cli_fixture')
for name in ('scripts.int_release','scripts.int_release_state'):
    importlib.import_module(name)
print(json.dumps({'cli_imports':True}))
"""
        with tempfile.TemporaryDirectory(prefix="clipforge-cli-contract-") as directory:
            env = {name: os.environ[name] for name in ("SYSTEMROOT",) if name in os.environ}
            result = subprocess.run([sys.executable, "-I", "-B", "-c", program,
                                     str(driver.ROOT / "scripts/tf_int_plan.py")],
                                    cwd=directory, env=env, capture_output=True, text=True, timeout=30)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), {"cli_imports": True})

    def setUp(self):
        self.plan = fixture()

    def row(self, kind):
        return next(r for r in self.plan["resource_changes"] if r["address"] == kind)

    def check(self):
        return c.plan_contract(self.plan, "# authored startup fixture")

    def test_complete_safe_plan_produces_only_explicit_addresses_and_counts(self):
        summary = self.check()
        self.assertEqual(summary["counts"], {"create": 52})
        self.assertFalse(summary["destructive_actions"])
        self.assertNotIn("authored input", json.dumps(summary))

    def test_detailed_exit_codes_are_distinct_and_unexpected_status_fails(self):
        self.assertEqual([c.detailed_exit(v) for v in [0, 1, 2]], ["no_changes", "error", "changes"])
        for value in [-1, 3, True, "2"]:
            with self.subTest(value=value), self.assertRaises(ValueError):
                c.detailed_exit(value)

    def test_rejects_ipv4_and_ipv6_public_vm_addresses(self):
        for field in ["access_config", "ipv6_access_config"]:
            with self.subTest(field=field):
                self.setUp()
                self.row("google_compute_instance.postgres")["change"]["after"]["network_interface"][0][field] = [{}]
                with self.assertRaises(ValueError): self.check()

    def test_rejects_public_postgres_and_non_iap_ssh_sources(self):
        for name in ["postgres", "iap"]:
            with self.subTest(name=name):
                self.setUp()
                self.row("google_compute_firewall." + name)["change"]["after"]["source_ranges"] = ["0.0.0.0/0"]
                with self.assertRaises(ValueError): self.check()

    def test_rejects_removal_replacement_and_incomplete_or_iam_plans(self):
        for actions in [["delete"], ["delete", "create"], ["create", "delete"]]:
            with self.subTest(actions=actions):
                self.setUp()
                self.row("google_compute_disk.postgres")["change"]["actions"] = actions
                with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.plan["resource_changes"].pop()
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.plan["resource_changes"].append({"mode": "managed", "address": "google_project_iam_member.extra"})
        with self.assertRaises(ValueError): self.check()

    def test_rejects_disk_shrink_auto_delete_and_missing_attachment(self):
        self.row("google_compute_disk.postgres")["change"]["before"] = {"size": 30}
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        vm = self.row("google_compute_instance.postgres")["change"]["after"]
        vm["boot_disk"][0]["auto_delete"] = True
        with self.assertRaises(ValueError): self.check()
        vm["boot_disk"][0]["auto_delete"] = False
        vm["attached_disk"] = []
        with self.assertRaises(ValueError): self.check()

    def test_rejects_public_buckets_force_destroy_and_disabled_versioning(self):
        for field, value in [("force_destroy", True), ("public_access_prevention", "inherited"),
                             ("uniform_bucket_level_access", False), ("versioning", [{"enabled": False}])]:
            with self.subTest(field=field):
                self.setUp()
                self.row('google_storage_bucket.private["media"]')["change"]["after"][field] = value
                with self.assertRaises(ValueError): self.check()

    def test_rejects_secret_inputs_metadata_outputs_and_secret_version_reads(self):
        self.plan["variables"]["password"] = {"value": "synthetic-private-sentinel"}
        with self.assertRaises(ValueError) as error: self.check()
        self.assertNotIn("synthetic-private-sentinel", str(error.exception))
        self.setUp()
        self.row("google_compute_instance.postgres")["change"]["after"]["metadata"]["password"] = "synthetic-private-sentinel"
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.plan["output_changes"]["secret"] = {}
        with self.assertRaises(ValueError): self.check()
        self.setUp()
        self.plan["resource_changes"].append({"mode": "data", "type": "google_secret_manager_secret_version"})
        with self.assertRaises(ValueError): self.check()

    def test_backend_requires_matching_private_versioned_bucket(self):
        bucket = {"name": c.BUCKET, "projectNumber": c.NUMBER, "versioning": {"enabled": True},
                  "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"}}
        c.backend_contract(bucket)
        for field in ["name", "projectNumber", "versioning", "iamConfiguration"]:
            bad = copy.deepcopy(bucket); bad.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError): c.backend_contract(bad)

    def test_diagnostics_keep_operation_permission_resource_and_redact_secrets(self):
        message = "googleapi: Error 403: Permission 'compute.networks.get' denied on resource projects/clipforgebeta2/global/networks/test\n403 Bearer synthetic-private-sentinel"
        result = c.diagnostic("plan", message, 403)
        self.assertEqual(result["permissions"], ["compute.networks.get"])
        self.assertEqual(result["status"], 403)
        self.assertNotIn("synthetic-private-sentinel", json.dumps(result))
        self.assertIn("projects/clipforgebeta2/global/networks/test", result["resources"])

    def test_api_cannot_read_object_payloads_or_other_buckets(self):
        for path in ["/b/another-bucket", "/b/" + c.BUCKET + "/o/default.tfstate", "/secrets/value"]:
            with self.subTest(path=path), self.assertRaises(ValueError): driver.metadata(path)

    def test_nonsecret_inputs_reject_drift_and_ambient_secret_variables(self):
        env = {"GCP_PROJECT_ID": c.PROJECT, "GCP_PROJECT_NUMBER": c.NUMBER, "GCP_REGION": c.REGION,
               "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
               "GCP_WIF_PROVIDER": "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
               "TF_STATE_BUCKET": c.BUCKET, "TF_STATE_PREFIX": "terraform/int"}
        c.validate_variables(env)
        for key in env:
            altered = dict(env); altered[key] = "authored-wrong-reference"
            with self.subTest(key=key), self.assertRaises(ValueError): c.validate_variables(altered)
        for key in ["TF_VAR_password", "TF_CLI_ARGS_plan", "TF_LOG"]:
            with self.subTest(key=key), self.assertRaises(ValueError) as error:
                c.validate_variables({**env, key: "synthetic-private-sentinel"})
            self.assertNotIn("synthetic-private-sentinel", str(error.exception))

    def test_process_permission_error_preserves_a_sanitized_receipt(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-authored-error-") as temporary:
            work = Path(temporary); (work / "module").mkdir()
            result = mock.Mock(returncode=1, stdout=b"googleapi: Error 403: Permission 'storage.objects.list' denied on resource buckets/clipforgebeta2-tfstate-int", stderr=b"")
            with mock.patch.dict(os.environ, {}, clear=True), mock.patch.object(driver.subprocess, "run", return_value=result):
                with self.assertRaises(driver.FailedOperation) as failure:
                    driver.run(["authored-binary", "init"], "init", work)
            self.assertEqual(failure.exception.receipt["operation"], "init")
            self.assertEqual(failure.exception.receipt["permissions"], ["storage.objects.list"])
            self.assertTrue((work / "init.log").is_file())

    def test_cleanup_refuses_checkout_or_non_dedicated_paths(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-authored-tf-") as temporary:
            env = {"RUNNER_TEMP": temporary, "TF_INT_WORK_DIR": str(driver.ROOT),
                   "TF_INT_REPORT_DIR": str(Path(temporary) / "clipforge-tf-report.authored")}
            with mock.patch.dict(os.environ, env), self.assertRaises(ValueError): driver.private_paths()


class TFIntBackendRerun(unittest.TestCase):
    def setUp(self):
        self.state = {"version": 4, "terraform_version": "1.15.8", "serial": 1,
                      "lineage": "11111111-2222-3333-4444-555555555555", "outputs": {}, "resources": [], "check_results": None}
        self.raw = (json.dumps(self.state, indent=2) + "\n").encode()
        self.binding = {"name": driver.STATE_NAME, "generation": "1000001", "size": str(len(self.raw)),
                        "lineage": self.state["lineage"], "sha256": hashlib.sha256(self.raw).hexdigest()}
        self.patch = mock.patch.object(driver, "INITIAL_STATE", self.binding)
        self.patch.start(); self.addCleanup(self.patch.stop)
        self.obj = {k: self.binding[k] for k in ("name", "generation", "size")}
        self.obj.update(timeCreated="2026-11-13T19:50:21Z", updated="2026-11-13T19:50:21Z")
        self.old_lock = {"name": driver.LOCK_NAME, "generation": "999999", "size": "240",
                         "timeCreated": "2026-11-13T19:50:20Z", "timeDeleted": "2026-11-13T19:50:22Z"}
        self.inventory = {"live": [self.obj], "versions": [self.old_lock, self.obj], "soft_deleted": []}
        self.bucket = {"name": c.BUCKET, "projectNumber": c.NUMBER, "versioning": {"enabled": True},
                       "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"}}

    def test_uninitialized_backend_is_distinct_from_recognized_initial_state(self):
        empty = {"live": [], "versions": [], "soft_deleted": []}
        self.assertEqual(driver.classify_backend(empty)["classification"], "uninitialized")
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "initial_state_pending_private_verification")
        driver.verify_initial_state(self.raw)

    def test_current_lock_blocks_even_if_old_and_never_assumes_orphanhood(self):
        self.inventory["live"].append(self.old_lock)
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "blocked_current_lock")

    def test_historical_and_soft_deleted_locks_are_not_active_locks(self):
        self.inventory["soft_deleted"].append({**self.old_lock, "generation": "999998", "softDeleteTime": "2026-11-13T19:51:00Z"})
        result = driver.classify_backend(self.inventory)
        self.assertEqual(result["classification"], "initial_state_pending_private_verification")
        self.assertEqual(result["historical"], [self.old_lock])
        only_old_locks = {"live": [], "versions": [self.old_lock], "soft_deleted": []}
        self.assertEqual(driver.classify_backend(only_old_locks)["classification"], "uninitialized")

    def test_historical_state_without_current_state_never_creates_a_replacement(self):
        self.inventory["live"] = []
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "blocked_state_provenance_unconfirmed")

    def test_unknown_generation_history_workspace_and_nearby_prefix(self):
        old_state = {**self.obj, "generation": "999997"}
        self.inventory["versions"].append(old_state)
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "blocked_state_provenance_unconfirmed")
        self.inventory["versions"].remove(old_state)
        other = {**self.obj, "name": c.PREFIX + "/other.tfstate"}
        self.inventory["live"].append(other)
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "blocked_unknown_object_or_workspace")
        self.inventory["live"].remove(other)
        nearby = {**other, "name": c.PREFIX + "-nearby/default.tfstate"}
        self.inventory["live"].append(nearby)
        self.assertEqual(driver.classify_backend(self.inventory)["classification"], "initial_state_pending_private_verification")

    def test_unknown_or_managed_state_never_passes_private_verification(self):
        for field, value in [("lineage", "66666666-2222-3333-4444-555555555555"), ("serial", 2),
                             ("outputs", {"sensitive": {"value": "authored-private-sentinel"}}),
                             ("resources", [{"mode": "managed", "instances": [{"attributes": {"private": "authored-private-sentinel"}}]}])]:
            altered = {**self.state, field: value}
            raw = (json.dumps(altered, indent=2) + "\n").encode()
            with self.subTest(field=field), self.assertRaises(ValueError) as error:
                driver.verify_initial_state(raw)
            self.assertNotIn("authored-private-sentinel", str(error.exception))
        # Even a newly supplied matching digest cannot bypass the empty-state schema.
        bad = {**self.state, "resources": [{"mode": "managed"}]}
        raw = json.dumps(bad).encode()
        with mock.patch.dict(self.binding, size=str(len(raw)), sha256=hashlib.sha256(raw).hexdigest()):
            with self.assertRaises(ValueError): driver.verify_initial_state(raw)

    def test_inventory_paginates_without_combining_live_and_history(self):
        responses = [{"items": [self.obj], "nextPageToken": "authored-page"}, {},
                     {"items": [self.old_lock, self.obj]}]
        with mock.patch.object(driver, "metadata", side_effect=responses) as query:
            inventory = driver.backend_inventory(self.bucket)
        self.assertEqual(inventory["live"], [self.obj])
        self.assertEqual(inventory["versions"], [self.old_lock, self.obj])
        self.assertEqual(query.call_args_list[1].args[1]["pageToken"], "authored-page")
        self.assertTrue(all(call.args[1]["prefix"] == "terraform/int/" for call in query.call_args_list))
        with mock.patch.object(driver, "metadata", return_value={"nextPageToken": "authored-loop"}), self.assertRaises(ValueError):
            driver.backend_inventory(self.bucket)

    def test_private_read_is_generation_pinned_and_deletes_only_its_temporary_file(self):
        opener = mock.Mock()
        with tempfile.TemporaryDirectory(prefix="clipforge-authored-state-") as temporary:
            work = Path(temporary)
            opener.open.return_value = io.BytesIO(self.raw)
            with mock.patch.dict(os.environ, {"GCP_ACCESS_TOKEN": "authored"}), mock.patch.object(driver, "build_opener", return_value=opener):
                driver.read_initial_state(work)
            self.assertFalse((work / "initial-state-private.json").exists())
            request = opener.open.call_args.args[0]
            query = parse_qs(urlsplit(request.full_url).query)
            self.assertEqual(query["generation"], [self.binding["generation"]])
            self.assertEqual(query["ifGenerationMatch"], [self.binding["generation"]])
            self.assertIn("default.tfstate", request.full_url)
            target = work / "initial-state-private.json"; target.write_text("authored prior file")
            opener.open.return_value = io.BytesIO(self.raw)
            with mock.patch.dict(os.environ, {"GCP_ACCESS_TOKEN": "authored"}), mock.patch.object(driver, "build_opener", return_value=opener):
                with self.assertRaises(FileExistsError): driver.read_initial_state(work)
            self.assertEqual(target.read_text(), "authored prior file")

    def test_race_with_new_live_lock_stops_before_terraform(self):
        after = copy.deepcopy(self.inventory); after["live"].append(self.old_lock)
        receipt = {"status": "started", "checks": {}}
        with mock.patch.object(driver, "backend_inventory", side_effect=[self.inventory, after]), mock.patch.object(driver, "read_initial_state"), mock.patch.object(driver, "save_summary"):
            with self.assertRaises(ValueError): driver.inspect_backend(self.bucket, Path("unused"), Path("unused"), receipt)

    def test_second_execution_after_native_init_and_failed_plan_reaches_plan_with_locking(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-authored-rerun-") as temporary:
            work = Path(temporary); module = work / "module"; module.mkdir()
            (module / "backend-int.hcl").write_text('bucket = "' + c.BUCKET + '"\nprefix = "' + c.PREFIX + '"\n')
            adc = work / "gha-creds-authored.json"; adc.write_text("authored fixture, no credentials")
            env = {"GOOGLE_APPLICATION_CREDENTIALS": str(adc), "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
                   "GITHUB_REF": "refs/heads/ci/bootstrap-sec03", "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted",
                   "RUNTIME_IMAGE": IMAGE, "SECRET_VERSIONS_JSON": "null", "INT_STAGE": "foundation"}
            runs = []
            def execute(command, operation, *args, **kwargs):
                runs.append((operation, command))
                return (1 if operation == "plan" else 0), b""
            # First init has left exactly this initial snapshot; the plan failed.
            # Subsequent runs retain it and ignore only non-current lock generations.
            for attempt in (1, 2):
                receipt = {"status": "started", "checks": {}}
                with mock.patch.dict(os.environ, env, clear=True), mock.patch.object(c, "validate_variables"), mock.patch.object(driver, "metadata", return_value=self.bucket), mock.patch.object(driver, "backend_inventory", return_value=self.inventory), mock.patch.object(driver, "read_initial_state", side_effect=lambda _: driver.verify_initial_state(self.raw)), mock.patch.object(driver, "terraform_binary", return_value="authored-terraform"), mock.patch.object(driver, "save_summary"), mock.patch.object(driver, "run", side_effect=execute):
                    with self.assertRaisesRegex(ValueError, "Plan returned exit code 1"):
                        driver.real_plan(work, work, receipt)
                self.assertEqual(receipt["backend"]["classification"], "recognized_initial_state")
                self.assertEqual(self.inventory["live"], [self.obj])
            self.assertEqual([op for op, _ in runs], ["init", "validate_backend", "plan"] * 2)
            plans = [command for op, command in runs if op == "plan"]
            self.assertTrue(all("-lock=true" in command and "-lock=false" not in command for command in plans))
            self.assertFalse(any(word in {"apply", "destroy", "import", "force-unlock", "push"} for _, command in runs for word in command))


if __name__ == "__main__":
    unittest.main()
