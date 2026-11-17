"""Synthetic regression contracts; no cloud calls or owner plans in unit discovery."""
from copy import deepcopy
from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import compare_int_foundation_plans as comparison


def documents():
    variables = {"project_id": "clipforgebeta2", "machine_type": "e2-micro", "run_subnet_cidr": "10.80.0.0/26",
                 "postgres_subnet_cidr": "10.80.1.0/28", "data_disk_gb": 20, "runtime_image":
                 "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "a" * 64,
                 "secret_versions": None, "stage": "foundation"}
    resources = [{"address": address, "mode": "managed", "type": address.split(".")[0],
                  "provider_name": "registry.terraform.io/hashicorp/google", "change":
                  {"actions": ["create"], "before": None, "after": {}, "after_unknown": {},
                   "after_sensitive": {}, "before_sensitive": {}, "after_identity": None}}
                 for address in sorted(comparison.FOUNDATION_ADDRESSES)]
    plan = {"format_version": "1.2", "terraform_version": "1.15.8", "variables":
            {key: {"value": value} for key, value in variables.items()}, "resource_changes": resources,
            "configuration": {"provider_config": {"google": {"version_constraint": "8.11.0"}}},
            "planned_values": {"root_module": {"resources": [
                {"address": r["address"], "mode": "managed", "type": r["type"], "values": {}, "sensitive_values": {}}
                for r in resources]}}, "prior_state": {"values": {"root_module": {"resources": []}}},
            "timestamp": "2026-11-13T23:39:17Z", "complete": True, "applyable": True, "errored": False,
            "output_changes": {}, "checks": []}
    manifest = {"schema": "clipforge-int-e2e-private-plan-1", "terraform_version": "1.15.8",
                "repository": "AldemaroCruz/ClipForge", "branch": "ci/bootstrap-sec03", "commit": "a" * 40,
                "run_id": "43528573812", "run_attempt": "1", "created_utc": plan["timestamp"],
                "inputs": {key: variables[key] for key in ("stage", "machine_type", "runtime_image", "secret_versions")},
                "configuration_sha256": "b" * 64, "provider_lock_sha256": "c" * 64,
                "backend": {"bucket": "clipforgebeta2-tfstate-int", "prefix": "terraform/int/tf-int-01", "workspace": "default",
                            "lineage": "synthetic-initial", "serial": 1, "state_generation": "1", "state_sha256": "d" * 64},
                "approval": "pending_new_manual_int_approval", "runtime_published": False}
    bind(plan, manifest)
    return plan, manifest


def bind(plan, manifest):
    prefix = "private-plans/int/" + manifest["commit"] + "/" + manifest["run_id"] + "-" + manifest["run_attempt"]
    raw = json.dumps(plan, sort_keys=True).encode()
    manifest["json"] = {"name": prefix + "/int.json", "generation": "2", "sha256": hashlib.sha256(raw).hexdigest(), "size": len(raw)}
    manifest["binary"] = {"name": prefix + "/int.tfplan", "generation": "3", "sha256": "e" * 64, "size": 100}
    return raw


def resource(plan, address):
    return next(r for r in plan["resource_changes"] if r["address"] == address)


class FoundationComparison(unittest.TestCase):
    def setUp(self):
        self.old, self.manifest = documents()
        self.new, self.new_manifest = deepcopy(self.old), deepcopy(self.manifest)

    def report(self):
        return comparison.compare(self.old, self.new, self.manifest, self.new_manifest)

    def blocked(self):
        result = self.report()
        self.assertEqual(result["status"], "blocked_input_change")
        self.assertFalse(result["apply_authorized"])
        return result

    def test_equal_is_not_apply_authorization(self):
        before = deepcopy((self.old, self.new, self.manifest, self.new_manifest))
        result = self.report()
        self.assertEqual(result["status"], "equivalent_operational_plan")
        self.assertEqual(result["managed_count"], {"old": 42, "new": 42})
        self.assertEqual(result["differences"], [])
        self.assertFalse(result["apply_authorized"])
        self.assertEqual(before, (self.old, self.new, self.manifest, self.new_manifest))

    def test_only_root_timestamp_and_new_custody_are_allowed(self):
        self.new["timestamp"] = "2026-11-17T20:00:00Z"
        self.new_manifest.update(commit="f" * 40, run_id="44161869072", run_attempt="2", created_utc=self.new["timestamp"])
        bind(self.new, self.new_manifest)
        result = self.report()
        self.assertEqual(result["status"], "equivalent_operational_plan")
        self.assertTrue(result["custody_changes"])

    def test_nested_timestamp_is_never_ignored(self):
        resource(self.old, "google_compute_instance.postgres")["change"]["after"]["metadata"] = {"timestamp": "old"}
        resource(self.new, "google_compute_instance.postgres")["change"]["after"]["metadata"] = {"timestamp": "new"}
        self.assertTrue(self.blocked()["differences"])

    def test_same_42_count_cannot_hide_operational_changes(self):
        cases = (
            ("google_project_iam_member.bootstrap_reader", "role", "roles/viewer", "roles/owner"),
            ("google_compute_firewall.postgres", "allow", [{"ports": ["5432"]}], [{"ports": ["22"]}]),
            ("google_compute_instance.postgres", "boot_disk", [{"initialize_params": {"image": "debian-cloud/global/images/debian-13-old"}}],
             [{"initialize_params": {"image": "debian-cloud/global/images/debian-13-new"}}]),
            ("google_compute_instance.postgres", "metadata_startup_script", "reviewed startup", "changed startup"),
            ("google_compute_disk.postgres", "size", 20, 30),
            ("google_logging_project_bucket_config.access", "retention_days", 30, 7),
            ('google_secret_manager_secret_iam_member.runtime["api_password"]', "role", "roles/secretmanager.secretAccessor", "roles/owner"),
        )
        for address, key, before, after in cases:
            with self.subTest(address=address, key=key):
                self.old, self.manifest = documents()
                self.new, self.new_manifest = deepcopy(self.old), deepcopy(self.manifest)
                resource(self.old, address)["change"]["after"][key] = before
                resource(self.new, address)["change"]["after"][key] = after
                result = self.blocked()
                self.assertEqual(result["managed_count"], {"old": 42, "new": 42})
                self.assertTrue(result["differences"])
                if key == "metadata_startup_script":
                    encoded = json.dumps(result)
                    self.assertNotIn(before, encoded)
                    self.assertNotIn(after, encoded)
                    self.assertIn(hashlib.sha256(after.encode()).hexdigest(), encoded)

    def test_actions_before_unknown_sensitive_type_and_provider_changes(self):
        cases = (("actions", ["delete", "create"]), ("before", {"existing": True}),
                 ("after_unknown", {"network_ip": True}), ("after_sensitive", {"metadata": True}))
        for key, value in cases:
            with self.subTest(key=key):
                self.new = deepcopy(self.old)
                resource(self.new, "google_compute_instance.postgres")["change"][key] = value
                self.assertTrue(self.blocked()["differences"])
        for key in ("type", "provider_name"):
            self.new = deepcopy(self.old)
            resource(self.new, "google_compute_instance.postgres")[key] = "synthetic-other"
            self.assertTrue(self.blocked()["differences"])

    def test_disks_and_interfaces_keep_order(self):
        left = resource(self.old, "google_compute_instance.postgres")["change"]["after"]
        right = resource(self.new, "google_compute_instance.postgres")["change"]["after"]
        left["network_interface"], right["network_interface"] = [{"network_ip": "10.0.0.1"}, {"network_ip": "10.0.0.2"}], [{"network_ip": "10.0.0.2"}, {"network_ip": "10.0.0.1"}]
        self.assertTrue(self.blocked()["differences"])

    def test_resource_collection_order_is_not_an_input(self):
        self.new["resource_changes"].reverse()
        self.new["planned_values"]["root_module"]["resources"].reverse()
        self.assertEqual(self.report()["status"], "equivalent_operational_plan")

    def test_private_values_outputs_arbitrary_keys_and_sensitive_public_field_never_leak(self):
        sentinel = "SYNTHETIC_PRIVATE_SENTINEL_73ee"
        self.new["output_changes"][sentinel] = {"after": sentinel, "after_sensitive": True}
        row = resource(self.new, "google_project_iam_member.bootstrap_reader")["change"]
        row["after"]["member"] = sentinel
        row["after_sensitive"]["member"] = True
        self.new["planned_values"]["root_module"]["resources"][0]["values"][sentinel] = sentinel
        self.assertNotIn(sentinel, json.dumps(self.blocked()))

    def test_sensitive_iam_member_is_not_disclosed_even_when_format_is_public(self):
        value = "user:admin@ixbalam.studio"
        for plan in (self.old, self.new):
            row = resource(plan, "google_project_iam_member.bootstrap_reader")["change"]
            row["after_sensitive"]["member"] = True
        resource(self.new, "google_project_iam_member.bootstrap_reader")["change"]["after"]["member"] = value
        planned = self.new["planned_values"]["root_module"]["resources"][0]
        planned["values"]["member"], planned["sensitive_values"]["member"] = value, True
        self.assertNotIn(value, json.dumps(self.blocked()))

    def test_public_formats_in_vm_metadata_are_not_public_image_or_iam_fields(self):
        metadata = {"image": "debian-cloud/global/images/debian-13-synthetic-private",
                    "member": "user:admin@ixbalam.studio", "role": "roles/owner"}
        resource(self.new, "google_compute_instance.postgres")["change"]["after"]["metadata"] = metadata
        output = json.dumps(self.blocked())
        for value in metadata.values():
            self.assertNotIn(value, output)

    def test_scope_duplicate_addresses_and_prior_managed_state_fail_closed(self):
        for mutation in ("missing", "extra", "duplicate", "substitution", "prior", "planned"):
            with self.subTest(mutation=mutation):
                self.new = deepcopy(self.old)
                if mutation == "missing":
                    self.new["resource_changes"].pop()
                elif mutation == "extra":
                    self.new["resource_changes"].append(deepcopy(self.new["resource_changes"][0]))
                elif mutation == "duplicate":
                    self.new["resource_changes"][1] = deepcopy(self.new["resource_changes"][0])
                elif mutation == "substitution":
                    self.new["resource_changes"][0]["address"] = "google_secret_manager_secret_version.unapproved"
                elif mutation == "prior":
                    self.new["prior_state"]["values"]["root_module"]["resources"] = [{"mode": "managed"}]
                else:
                    self.new["planned_values"]["root_module"]["resources"].pop()
                self.assertTrue(self.blocked()["guards"])

    def test_secrets_payloads_versions_and_unknown_payload_are_guarded(self):
        for value in ("SYNTHETIC_PRIVATE_SECRET", True, {"unknown": True}):
            self.new = deepcopy(self.old)
            resource(self.new, "google_compute_instance.postgres")["change"]["after_unknown"]["private_key"] = value
            result = self.blocked()
            self.assertIn("secret_payload_or_unknown_secret", [x["category"] for x in result["guards"]])
            self.assertNotIn("SYNTHETIC_PRIVATE_SECRET", json.dumps(result))
        self.new = deepcopy(self.old)
        self.new["variables"]["secret_versions"] = {"value": {"app_password": "1"}}
        self.assertTrue(self.blocked()["guards"])

    def test_optional_null_encryption_keys_are_not_secret_payloads(self):
        for plan in (self.old, self.new):
            change = resource(plan, "google_compute_instance.postgres")["change"]
            change["after"]["boot_disk"] = [{"disk_encryption_key_raw": None}]
            change["after_sensitive"]["boot_disk"] = [{"disk_encryption_key_raw": True}]
        self.assertEqual(self.report()["status"], "equivalent_operational_plan")

    def test_unrecognized_sensitive_payload_blocks_even_when_unchanged(self):
        for plan in (self.old, self.new):
            change = resource(plan, "google_compute_instance.postgres")["change"]
            change["after"]["unexpected_sensitive"] = "SYNTHETIC_PRIVATE"
            change["after_sensitive"]["unexpected_sensitive"] = True
        result = self.blocked()
        self.assertTrue(result["guards"])
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_effective_variables_configuration_backend_and_hashes_are_compared(self):
        for key in ("configuration_sha256", "provider_lock_sha256", "runtime_published", "approval"):
            self.new_manifest = deepcopy(self.manifest)
            self.new_manifest[key] = "f" * 64 if key.endswith("sha256") else "changed"
            self.assertTrue(self.blocked()["differences"])
        self.new_manifest = deepcopy(self.manifest)
        self.new_manifest["backend"]["state_generation"] = "99"
        self.assertTrue(self.blocked()["differences"])
        self.new_manifest = deepcopy(self.manifest)
        self.new["variables"]["data_disk_gb"]["value"] = 30
        self.assertTrue(self.blocked()["differences"])
        self.new = deepcopy(self.old)
        self.new["configuration"]["provider_config"]["google"]["version_constraint"] = "8.12.0"
        self.assertTrue(self.blocked()["differences"])

    def test_reviewed_candidate_image_and_configuration_delta_are_reported_not_ignored(self):
        old_image = "https://www.googleapis.com/compute/v1/projects/debian-cloud/global/images/debian-13-trixie-v20261109"
        new_image = old_image.replace("20261109", "20261116")
        for plan, image in ((self.old, old_image), (self.new, new_image)):
            resource(plan, "google_compute_instance.postgres")["change"]["after"]["boot_disk"] = [
                {"initialize_params": [{"image": image}]}]
        self.new["configuration"]["root_module"] = {"resources": [
            {"address": "data.google_compute_image.debian", "expressions": {"name": {"constant_value": "debian-13-trixie-v20261116"}}}]}
        self.new_manifest["configuration_sha256"] = "f" * 64
        result = self.blocked()
        output = json.dumps(result)
        self.assertIn(old_image, output)
        self.assertIn(new_image, output)
        self.assertTrue(any(row["path"] == "/manifest/configuration_sha256" for row in result["differences"]))
        self.assertTrue(any("configuration" in row["path"] for row in result["differences"]))
        self.assertEqual(result["managed_count"], {"old": 42, "new": 42})

    def test_manifest_inputs_must_match_effective_variables(self):
        self.new_manifest["inputs"]["machine_type"] = "e2-small"
        self.assertIn("manifest_input_binding", [r["category"] for r in self.blocked()["guards"]])

    def test_custody_does_not_hide_an_operational_subtree_or_invalid_identity(self):
        self.new["timestamp"] = {"startup": "SYNTHETIC_PRIVATE"}
        self.new_manifest["binary"]["unexpected"] = "SYNTHETIC_PRIVATE"
        result = self.blocked()
        self.assertTrue(result["guards"])
        self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_malformed_and_nonfinite_inputs_are_safe(self):
        for plan in (None, [], {"resource_changes": "SYNTHETIC_PRIVATE"}, {"nonfinite": float("nan")}):
            result = comparison.compare(plan, self.new, self.manifest, self.new_manifest)
            self.assertEqual(result["status"], "blocked_input_change")
            self.assertNotIn("SYNTHETIC_PRIVATE", json.dumps(result))

    def test_cli_binds_raw_json_and_rejects_tampering(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-foundation-compare-") as temporary:
            base = Path(temporary)
            raw = bind(self.old, self.manifest)
            for name, data in (("old", raw), ("new", raw), ("old-manifest", json.dumps(self.manifest).encode()),
                               ("new-manifest", json.dumps(self.manifest).encode())):
                (base / (name + ".json")).write_bytes(data)
            args = ["--old-plan", str(base / "old.json"), "--new-plan", str(base / "new.json"),
                    "--old-manifest", str(base / "old-manifest.json"), "--new-manifest", str(base / "new-manifest.json")]
            output = io.StringIO()
            with redirect_stdout(output):
                self.assertEqual(comparison.main(args), 0)
            self.assertEqual(json.loads(output.getvalue())["raw_json_binding"], "verified")
            (base / "new.json").write_bytes(raw + b"\n")
            with redirect_stdout(io.StringIO()):
                self.assertEqual(comparison.main(args), 2)

    def test_reader_rejects_checkout_duplicate_keys_and_oversized_inputs(self):
        with self.assertRaises(ValueError):
            comparison._read_private(Path(comparison.__file__))
        with tempfile.TemporaryDirectory(prefix="clipforge-foundation-reader-") as temporary:
            target = Path(temporary) / "synthetic.json"
            for raw in (b'{"x":1,"x":2}', b'{"x":NaN}'):
                target.write_bytes(raw)
                with self.assertRaises(ValueError):
                    comparison._read_private(target)
            target.write_bytes(b"{}")
            with mock.patch.object(comparison, "MAX_BYTES", 1):
                with self.assertRaises(ValueError):
                    comparison._read_private(target)


if __name__ == "__main__":
    unittest.main()
