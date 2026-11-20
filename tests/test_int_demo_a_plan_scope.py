"""Synthetic plan-shape tests. No cloud contacts or real secret version numbers."""
from copy import deepcopy
from hashlib import sha256
import unittest

from scripts import int_demo_a_plan_scope as gate


def account(name):
    return f"clipforge-{name}-int@clipforgebeta2.iam.gserviceaccount.com"


def template(admin, versions):
    user = "clipforge_migrator" if admin else "clipforge_app"
    env = {**gate.RUNTIME_ENV, "CLIPFORGE_DATABASE_USER": user}
    mounts = {"database": "migrator_password" if admin else "app_password", "postgres-ca": "postgres_ca"}
    if admin:
        env["CLIPFORGE_BOOTSTRAP_ADMIN_FILE"] = "/secrets/admin/value"
        mounts["admin"] = "bootstrap_admin"
    return {"service_account": account("migrate" if admin else "api"), "execution_environment": "EXECUTION_ENVIRONMENT_GEN2",
            "vpc_access": [{"egress": "PRIVATE_RANGES_ONLY", "network_interfaces": [
                {"network": "clipforge-int-base", "subnetwork": "clipforge-int-base-run"}]}],
            "containers": [{"image": gate.IMAGE, "command": ["python"], "args": (gate.ADMIN_ARGS if admin else gate.API_ARGS)[:],
                            "env": [{"name": key, "value": value} for key, value in env.items()],
                            "volume_mounts": [{"name": name, "mount_path": "/secrets/" + name} for name in mounts]}],
            "volumes": [{"name": name, "secret": [{"secret": gate.SECRET_NAMES[slot],
                         "items": [{"version": versions[slot], "path": "value"}]}]} for name, slot in mounts.items()]}


def modules(values):
    return {"root_module": {"resources": [{"mode": "managed", "address": path, "values": fields} for path, fields in values.items()]}}


def initial_plan(versions):
    old = dict.fromkeys(gate.baseline(), {})
    old["google_compute_disk.noble_boot[0]"] = {"disk_id": "8897353356069952044"}
    old["google_compute_disk.noble_data[0]"] = {"disk_id": "7382984635240536620"}
    old["google_compute_instance.postgres"] = {"instance_id": "1670495097211408131"}
    old["google_compute_disk.postgres"] = {"disk_id": "6427691858848206684"}
    old["google_compute_instance.noble[0]"] = {"instance_id": "7365414160255801909", "name": "clipforge-int-db01-noble",
        "deletion_protection": True, "network_interface": [{"network_ip": "10.80.1.3"}],
        "boot_disk": [{"auto_delete": False, "source": "zones/us-central1-a/disks/clipforge-int-db01-noble-boot"}],
        "attached_disk": [{"mode": "READ_WRITE", "device_name": "clipforge-noble-pg-data",
                           "source": "zones/us-central1-a/disks/clipforge-int-db01-noble-data"}]}
    regional = {"project": gate.PROJECT, "location": gate.REGION}
    job = {**template(True, versions), "max_retries": 0, "timeout": "600s"}
    new = {gate.SERVICE: {**regional, "name": "clipforge-int-api", "deletion_protection": True,
                           "iap_enabled": True, "ingress": "INGRESS_TRAFFIC_ALL", "template": [template(False, versions)]},
           gate.BOOTSTRAP: {**regional, "name": "clipforge-int-bootstrap", "deletion_protection": True,
                            "template": [{"task_count": 1, "parallelism": 1, "template": [job]}]},
           gate.FIREWALL: {"project": gate.PROJECT, "name": "clipforge-int-db01-noble-postgres-from-run", "network": "clipforge-int-base",
                           "direction": "INGRESS", "priority": 1000, "source_ranges": ["10.80.0.0/26"],
                           "target_service_accounts": [account("db01-noble")], "allow": [{"ports": ["5432"], "protocol": "tcp"}],
                           "log_config": [{"metadata": "EXCLUDE_ALL_METADATA"}]},
           gate.INVOKER: {**regional, "name": "clipforge-int-api", "role": "roles/run.invoker",
                          "member": "serviceAccount:service-816643438938@gcp-sa-iap.iam.gserviceaccount.com"},
           gate.HUMAN: {**regional, "cloud_run_service_name": "clipforge-int-api", "role": "roles/iap.httpsResourceAccessor",
                        "member": "user:admin@ixbalam.studio"},
           gate.JOB_OPERATOR: {**regional, "name": "clipforge-int-bootstrap", "role": "roles/run.invoker", "member": "serviceAccount:" + account("deploy")}}
    all_values = old | new
    return {"terraform_version": "1.15.8", "format_version": "1.2", "complete": True, "applyable": True, "errored": False,
            "variables": {key: {"value": value} for key, value in gate.planned_variables(versions).items()},
            "prior_state": {"values": modules(deepcopy(old))}, "planned_values": modules(deepcopy(all_values)),
            "resource_changes": [{"mode": "managed", "address": key, "change": {"actions": ["no-op"] if key in old else ["create"],
                "before": deepcopy(old.get(key)), "after": deepcopy(fields)}} for key, fields in all_values.items()]}


class NativeScopeTest(unittest.TestCase):
    def setUp(self):
        self.receipts = {key: {"secret": secret, "version": str(90000 + index)}
                         for index, (key, secret) in enumerate(gate.SECRET_NAMES.items())}
        self.numbers = gate.versions(self.receipts)
        self.plan = initial_plan(self.numbers)

    def change(self, path):
        return next(row["change"] for row in self.plan["resource_changes"] if row["address"] == path)

    def planned(self, path):
        return next(row["values"] for row in self.plan["planned_values"]["root_module"]["resources"] if row["address"] == path)

    def test_exact_mock_scope_passes_offline(self):
        result = gate.verify_diff(self.plan, self.numbers)
        self.assertEqual((result["managed_noop"], len(result["managed_create"]), result["managed_total"]), (53, 6, 59))

    def test_delete_or_replace_disk_is_blocked(self):
        self.change("google_compute_disk.noble_data[0]")["actions"] = ["delete", "create"]
        with self.assertRaisesRegex(ValueError, "existing_resource_not_exact_noop"):
            gate.verify_diff(self.plan, self.numbers)

    def test_native_drift_is_blocked_even_when_action_is_noop(self):
        self.plan["resource_drift"] = [{"address": "google_compute_disk.noble_data[0]"}]
        with self.assertRaisesRegex(ValueError, "native_drift_deferred_or_action_invocation"):
            gate.verify_diff(self.plan, self.numbers)

    def test_multimedia_entrypoint_is_blocked(self):
        for value in (self.planned(gate.SERVICE), self.change(gate.SERVICE)["after"]):
            value["template"][0]["containers"][0]["args"][2] = "app.main:app"
        with self.assertRaisesRegex(ValueError, "exact_runtime_image_and_commands"):
            gate.verify_diff(self.plan, self.numbers)

    def test_unpinned_mounted_version_is_blocked(self):
        for value in (self.planned(gate.SERVICE), self.change(gate.SERVICE)["after"]):
            value["template"][0]["volumes"][0]["secret"][0]["items"][0]["version"] = "latest"
        with self.assertRaisesRegex(ValueError, "runtime_receipt_version_mount"):
            gate.verify_diff(self.plan, self.numbers)

    def test_missing_or_foreign_version_receipts_are_blocked(self):
        self.receipts["bootstrap_admin"]["secret"] = self.receipts["postgres_ca"]["secret"]
        with self.assertRaisesRegex(ValueError, "version_receipt_target_or_number"):
            gate.versions(self.receipts)

    def test_additional_gateway_step_and_different_binary_are_blocked(self):
        fake, binary, receipts = b"fixture-json", b"fixture-tfplan", b"fixture-secret-numbers"
        commit = "a" * 40
        proof = {"controls_commit": commit, "iac_patch_sha256": gate.IAC_PATCH_SHA, "environment": "int",
            "identity": account("terraform"), "operation": "plan-native-demo-a", "completed_steps": gate.GATEWAY[:],
            "run_id": "1", "run_attempt": "2",
            "backend_bucket": gate.BUCKET, "workspace": "default", "backend_pre": gate.STATE, "backend_after_init": gate.STATE,
            "backend_post": gate.STATE, "lock": True, "native_plan_exit": 2, "plan_attempted": 1,
            "secret_receipt_sha256": sha256(receipts).hexdigest(), "plan_binary_sha256": sha256(binary).hexdigest(),
            "native_json_sha256": sha256(fake).hexdigest()}
        gate.verify_production_receipt(proof, fake, binary, commit, receipts)
        with self.assertRaisesRegex(ValueError, "native_plan_files_differ"):
            gate.verify_production_receipt(proof, fake, binary + b"altered", commit, receipts)
        proof["completed_steps"].append("terraform_apply")
        with self.assertRaisesRegex(ValueError, "gateway_commands_missing_or_out_of_order"):
            gate.verify_production_receipt(proof, fake, binary, commit, receipts)

    def test_custody_rejects_another_run_prefix(self):
        run = {"controls_commit": "a" * 40, "run_id": "1", "run_attempt": "2"}
        payloads = {"int.tfplan": b"plan", "int.json": b"json", "manifest.json": b"manifest"}
        terminal = {"bucket": gate.BUCKET, "completed_steps": gate.GATEWAY_COMPLETE[:], "objects": {
            path: {"name": "private-plans/int/" + "a" * 40 + "/1-2/" + path, "generation": "1", "size": len(raw),
                   "sha256": sha256(raw).hexdigest()} for path, raw in payloads.items()}}
        args = [payloads[path] for path in ("int.json", "int.tfplan", "manifest.json")]
        gate.verify_custody(terminal, run, *args)
        terminal["objects"]["int.json"]["name"] = terminal["objects"]["int.json"]["name"].replace("1-2", "1-3")
        with self.assertRaisesRegex(ValueError, "immutable_custody_reference"):
            gate.verify_custody(terminal, run, *args)


if __name__ == "__main__":
    unittest.main()
