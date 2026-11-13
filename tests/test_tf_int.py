"""Synthetic TF-INT-01 contracts; no cloud, local state or credential access."""
from __future__ import annotations

import copy
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import check_tf_int as c, tf_int_plan as driver


def fixture():
    rows = []
    for address in sorted(c.ADDRESSES):
        kind, name = address.split(".", 1)
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
        rows.append({"address": address, "mode": "managed", "type": kind, "name": name,
                     "change": {"actions": ["create"], "before": None, "after": values}})
    return {"variables": {v: {"value": "authored input"} for v in c.VARIABLES},
            "output_changes": {"reviewed_boundary": {}}, "resource_changes": rows}


class TFIntContracts(unittest.TestCase):
    def setUp(self):
        self.plan = fixture()

    def row(self, kind):
        return next(r for r in self.plan["resource_changes"] if r["address"] == kind)

    def check(self):
        return c.plan_contract(self.plan, "# authored startup fixture")

    def test_complete_safe_plan_produces_only_explicit_addresses_and_counts(self):
        summary = self.check()
        self.assertEqual(summary["counts"], {"create": 16})
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

    def test_backend_requires_matching_private_versioned_bucket_and_unused_prefix(self):
        bucket = {"name": c.BUCKET, "projectNumber": c.NUMBER, "versioning": {"enabled": True},
                  "iamConfiguration": {"uniformBucketLevelAccess": {"enabled": True}, "publicAccessPrevention": "enforced"}}
        c.backend_contract(bucket, {})
        for listing in [{"items": [{"name": "authored-existing-version"}]}, {"nextPageToken": "authored"}]:
            with self.assertRaises(ValueError): c.backend_contract(bucket, listing)
        for field in ["name", "projectNumber", "versioning", "iamConfiguration"]:
            bad = copy.deepcopy(bucket); bad.pop(field)
            with self.subTest(field=field), self.assertRaises(ValueError): c.backend_contract(bad, {})

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


if __name__ == "__main__":
    unittest.main()
