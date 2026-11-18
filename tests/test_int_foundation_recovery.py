"""Authored partial-state/import fixtures: no real state, checkout or cloud reads.

Management confirmation below is a synthetic test input, never owner consent.
The exact partial-state hash is computed from these fixture bytes; no test
pretends to possess a preimage of the production state or source fingerprints.
"""
from copy import deepcopy
from contextlib import redirect_stderr
from datetime import datetime, timedelta, timezone
import hashlib
import io
import json
import re
import sys
import tempfile
from pathlib import Path
import types
import unittest
from unittest import mock
from urllib.parse import parse_qs, quote, urlsplit

from scripts import check_tf_int as c, int_foundation_recovery as recovery, int_release as custody
from scripts import check_int_foundation as foundation
from tests.test_tf_int import fixture as target_plan_fixture


PRIVATE_SENTINEL = "synthetic-private-recovery-attributes-never-publish"


def authored_imports():
    entries = (
        ('google_secret_manager_secret_iam_member.runtime["api_password"]', "clipforge-int-pg-app-password", "secretAccessor", "api"),
        ('google_secret_manager_secret_iam_member.runtime["worker_password"]', "clipforge-int-pg-app-password", "secretAccessor", "worker"),
        ('google_secret_manager_secret_iam_member.runtime["migrate_password"]', "clipforge-int-pg-migrator-password", "secretAccessor", "migrate"),
        ('google_secret_manager_secret_iam_member.version_publisher["app_password"]', "clipforge-int-pg-app-password", "secretVersionAdder", "deploy"),
        ('google_secret_manager_secret_iam_member.version_publisher["migrator_password"]', "clipforge-int-pg-migrator-password", "secretVersionAdder", "deploy"),
    )
    rows = []
    for address, secret, role_name, account in entries:
        role = "roles/secretmanager." + role_name
        member = "serviceAccount:clipforge-" + account + "-int@clipforgebeta2.iam.gserviceaccount.com"
        rows.append({"address": address, "id": "projects/clipforgebeta2/secrets/" + secret + " " + role + " " + member,
                     "secret_id": secret, "role": role, "member": member, "condition": None})
    return rows


def authored_partial(*, serial6=False):
    imports = authored_imports()
    imported = {row["address"] for row in imports}
    current = sorted(c.FOUNDATION_ADDRESSES - {recovery.PENDING_IAP}) if serial6 else sorted(c.FOUNDATION_ADDRESSES - imported)[:20]
    groups = {}
    for address in current:
        kind, rest = address.split(".", 1)
        match = re.fullmatch(r'([^\[]+)(?:\["([^"\]]+)"\])?', rest)
        name, index = match.groups()
        provider = "terraform.io/builtin/terraform" if kind == "terraform_data" else "registry.terraform.io/hashicorp/google"
        group = groups.setdefault((kind, name), {"mode": "managed", "type": kind, "name": name,
                    "provider": 'provider["' + provider + '"]', "instances": []})
        instance = {"schema_version": 0, "attributes": {"id": "synthetic-id", "private_attribute": PRIVATE_SENTINEL}, "sensitive_attributes": []}
        if index is not None:
            instance["index_key"] = index
        group["instances"].append(instance)
    state = {"version": 4, "terraform_version": "1.15.8", "serial": 6 if serial6 else 5,
             "lineage": "813c84a2-2ef1-ceb3-177e-3a2c3b815066", "resources": list(groups.values()),
             "outputs": {"reviewed_boundary": {"sensitive": True, "value": PRIVATE_SENTINEL, "type": "string"}}}
    raw = json.dumps(state, sort_keys=True, separators=(",", ":")).encode()
    backend = {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "name": c.PREFIX + "/default.tfstate",
               "generation": "1794975925421249" if serial6 else "1794961942265923", "size": len(raw), "sha256": hashlib.sha256(raw).hexdigest(),
               "lineage": state["lineage"], "serial": state["serial"], "terraform_version": "1.15.8", "version": 4, "managed_addresses": current}
    previous = "private-plans/int/" + "b" * 40 + "/44194990499-1/"
    reference = lambda name, generation, digest: {"name": previous + name, "generation": generation, "sha256": digest, "size": 100}
    contract = {"schema": "clipforge-int-foundation-recovery-1", "mode": "plan_only_no_apply", "repository": "AldemaroCruz/ClipForge",
                "branch": "ci/bootstrap-sec03", "environment": "int", "backend": backend, "target_addresses": sorted(c.FOUNDATION_ADDRESSES),
                "inputs": {"stage": "foundation", "machine_type": "e2-micro", "secret_versions": None,
                           "runtime_image": "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "a" * 64},
                "imports": imports, "management_owner_confirmed": True, "apply_authorized": False, "plan_ttl_seconds": 86400,
                "management": {"import_apply_authorized": False, "import_plan_is_not_effective_import": True},
                "original_plan_forbidden": {"run_id": "44194990499", "binary": reference("int.tfplan", "901", "a" * 64),
                                            "manifest": reference("manifest.json", "902", "b" * 64)},
                "risk_acceptance": {"new_plan_approved": False, "maximum_expiry_utc": "2026-11-28T05:59:59+00:00"}}
    if serial6:
        contract.update(recovery_phase=recovery.SERIAL6_PHASE, imports=[], completed_imports=imports,
                        pending_addresses=[recovery.PENDING_IAP], expected_plan={"no-op": 41, "create": 1},
                        source_bindings={}, additional_retired_plans=[deepcopy(recovery.SERIAL5_RETIRED)])
    live = {"name": backend["name"], "generation": backend["generation"], "size": str(len(raw)), "timeCreated": "2026-11-18T00:00:00Z"}
    inventory = {"live": [live], "versions": [deepcopy(live)], "soft_deleted": []}
    return raw, inventory, contract


def authored_observations(contract):
    result = {}
    for row in contract["imports"]:
        bindings = result.setdefault(row["secret_id"], {"http": 200, "policy": {"bindings": []}})["policy"]["bindings"]
        binding = next((item for item in bindings if item["role"] == row["role"]), None)
        if binding is None:
            binding = {"role": row["role"], "members": []}
            bindings.append(binding)
        binding["members"].append(row["member"])
    return result


def authored_plan(contract, with_imports=False):
    plan = target_plan_fixture()
    plan["resource_changes"] = [row for row in plan["resource_changes"] if row["address"] in c.FOUNDATION_ADDRESSES]
    plan["variables"].update({key: {"value": value} for key, value in contract["inputs"].items()})
    plan["variables"].update(project_id={"value": "clipforgebeta2"}, data_disk_gb={"value": 20},
                             run_subnet_cidr={"value": "10.80.0.0/26"}, postgres_subnet_cidr={"value": "10.80.1.0/28"})
    approved = {row["address"]: row["id"] for row in contract["imports"]} if with_imports else {}
    for row in plan["resource_changes"]:
        if row["address"] == recovery.PENDING_IAP and recovery.iap_patch_mode(contract):
            row["change"]["after"].update(project="816643438938", instance="1670495097211408131", zone="us-central1-a")
        existing = row["address"] in contract["backend"]["managed_addresses"] or row["address"] in approved
        row["change"]["actions"] = ["no-op"] if existing else ["create"]
        row["change"]["before"] = deepcopy(row["change"]["after"]) if existing else None
        row["change"].update(after_unknown={}, before_sensitive={}, after_sensitive={})
        if row["address"] in approved:
            row["change"]["importing"] = {"id": approved[row["address"]]}
    plan["planned_values"] = {"root_module": {"resources": [{"address": row["address"], "mode": "managed", "type": row["type"],
        "name": row["name"], "values": deepcopy(row["change"]["after"]), "sensitive_values": {}} for row in plan["resource_changes"]]}}
    plan.update(format_version="1.2", terraform_version="1.15.8", complete=True, applyable=True, errored=False)
    return plan


def authored_manifest(contract):
    now = datetime(2026, 11, 19, 0, 0, tzinfo=timezone.utc)
    files = {name: hashlib.sha256(("synthetic source bytes " + name).encode()).hexdigest() for name in c.FILES}
    base = custody.sha256(custody.canonical(files))
    serial6 = recovery.serial6_mode(contract)
    if not serial6:
        files["recovery-imports.tf"] = hashlib.sha256(b"synthetic exact import source").hexdigest()
    contract["source_bindings"] = {"base_configuration_sha256": base, "provider_lock_sha256": files[".terraform.lock.hcl"],
                                   **({} if serial6 else {"imports_sha256": files["recovery-imports.tf"]})}
    contract["baseline"] = {"configuration_commit": "b" * 40}
    prefix = "private-plans/int/" + "c" * 40 + "/50000000000-1/"
    manifest = {"schema": "clipforge-int-foundation-recovery-private-plan-1", "configuration_commit": "c" * 40,
                "controls_commit": "c" * 40, "baseline_configuration_commit": "b" * 40,
                "configuration_files": files, "configuration_sha256": custody.sha256(custody.canonical(files)),
                "base_configuration_sha256": base, "provider_lock_sha256": files[".terraform.lock.hcl"],
                "terraform_version": "1.15.8", "provider_version": "8.11.0", "control_sources_sha256": "f" * 64,
                "backend": {key: contract["backend"][key] for key in ("bucket", "prefix", "workspace", "name", "generation", "size", "sha256", "lineage", "serial", "terraform_version")},
                "imports": deepcopy(contract["imports"]), "inputs": deepcopy(contract["inputs"]),
                "risk_acceptance": deepcopy(contract["risk_acceptance"]), "apply_authorized": False,
                "created_utc": now.isoformat(), "expires_utc": (now + timedelta(hours=24)).isoformat(),
                "run_id": "50000000000", "run_attempt": "1",
                "binary": {"name": prefix + "int.tfplan", "generation": "1001", "sha256": "d" * 64, "size": 100},
                "json": {"name": prefix + "int.json", "generation": "1002", "sha256": "e" * 64, "size": 200}}
    if serial6:
        manifest.update(recovery_phase=recovery.SERIAL6_PHASE, completed_imports=deepcopy(contract["completed_imports"]),
                        import_policies_sha256=None)
    return manifest, now


def authored_computed_role_plan(contract):
    plan = authored_plan(contract, with_imports=True)
    member = next(row for row in plan["resource_changes"] if row["address"] == "google_project_iam_member.bootstrap_reader")
    member["change"]["after"]["role"] = None
    member["change"]["after_unknown"]["role"] = True
    role = next(row for row in plan["resource_changes"] if row["address"] == "google_project_iam_custom_role.bootstrap_reader")
    role["change"]["after"].update(project="clipforgebeta2", role_id="clipforgeIntBootstrapReader", permissions=[
        "compute.disks.get", "compute.instances.get", "compute.projects.get", "run.operations.get"])
    plan["configuration"] = {"root_module": {"resources": [{"address": member["address"], "expressions": {"role": {"references": [
        "google_project_iam_custom_role.bootstrap_reader.name", "google_project_iam_custom_role.bootstrap_reader"]}}}]}}
    return plan


class FoundationRecovery(unittest.TestCase):
    def setUp(self):
        self.raw, self.inventory, self.contract = authored_partial()

    def test_exact_partial_identity_is_recognized_without_disclosing_state_or_mutation(self):
        before = deepcopy((self.inventory, self.contract))
        proof = recovery.verify_partial_bytes(self.raw, self.inventory, self.contract)
        self.assertEqual(proof["classification"], "recognized_partial_foundation_state")
        for key in ("name", "generation", "size", "sha256", "lineage", "serial"):
            self.assertEqual(proof["state"][key], self.contract["backend"][key])
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(proof))
        self.assertEqual((self.inventory, self.contract), before)

    def test_current_generation_size_state_hash_serial_lineage_and_versions_are_exact(self):
        for field, value in (("generation", "999"), ("size", 1), ("sha256", "0" * 64), ("lineage", "another-lineage"),
                             ("serial", 6), ("terraform_version", "1.16.0"), ("version", 3), ("workspace", "other"),
                             ("name", c.PREFIX + "/other.tfstate"), ("managed_addresses", self.contract["backend"]["managed_addresses"][:-1])):
            changed = deepcopy(self.contract)
            changed["backend"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                recovery.verify_partial_bytes(self.raw, self.inventory, changed)
        for changed in (self.raw + b" ", self.raw[:-1], b'{"version":4,"version":4}'):
            with self.subTest(bytes=len(changed)), self.assertRaises(ValueError):
                recovery.verify_partial_bytes(changed, self.inventory, self.contract)

    def test_same_count_cannot_hide_partial_managed_address_change(self):
        changed = deepcopy(self.contract)
        absent = next(name for name in c.FOUNDATION_ADDRESSES if name not in changed["backend"]["managed_addresses"])
        changed["backend"]["managed_addresses"] = sorted(changed["backend"]["managed_addresses"][1:] + [absent])
        self.assertEqual(len(changed["backend"]["managed_addresses"]), 20)
        with self.assertRaises(ValueError): recovery.verify_partial_bytes(self.raw, self.inventory, changed)

    def test_current_lock_blocks_without_assuming_it_is_orphaned(self):
        inventory = deepcopy(self.inventory)
        inventory["live"].append({"name": c.PREFIX + "/default.tflock", "generation": "1", "size": "1", "timeCreated": "2000-01-01T00:00:00Z"})
        with self.assertRaises(ValueError): recovery.verify_partial_bytes(self.raw, inventory, self.contract)

    def test_historical_and_soft_deleted_locks_are_not_current_locks(self):
        inventory = deepcopy(self.inventory)
        lock = {"name": c.PREFIX + "/default.tflock", "generation": "1", "size": "100"}
        inventory["versions"].append(lock)
        inventory["soft_deleted"].append({**lock, "generation": "2"})
        inventory["versions"].append({"name": c.PREFIX + "/default.tfstate", "generation": "3", "size": "10"})
        self.assertEqual(recovery.verify_partial_bytes(self.raw, inventory, self.contract)["classification"], "recognized_partial_foundation_state")

    def test_missing_current_or_additional_workspace_is_never_adopted(self):
        for mutation in ("missing", "different-workspace", "duplicate"):
            inventory = deepcopy(self.inventory)
            if mutation == "missing": inventory["live"] = []
            elif mutation == "different-workspace": inventory["live"].append({"name": c.PREFIX + "/other.tfstate", "generation": "4", "size": "10"})
            else: inventory["live"].append(deepcopy(inventory["live"][0]))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_partial_bytes(self.raw, inventory, self.contract)

    def test_new_current_after_a_valid_proof_requires_fresh_review(self):
        proof = recovery.verify_partial_bytes(self.raw, self.inventory, self.contract)
        changed = deepcopy(self.inventory)
        changed["live"][0]["generation"] = "1794961942265924"
        with self.assertRaises(ValueError): recovery.verify_partial_bytes(self.raw, changed, self.contract)
        self.assertEqual(proof["state"]["generation"], "1794961942265923")

    def test_exact_observed_bindings_and_explicit_management_confirmation_allow_only_five_ids(self):
        observations = authored_observations(self.contract)
        result = recovery.verify_import_observations(observations, self.contract)
        self.assertEqual(result, self.contract["imports"])
        self.assertEqual(len(result), 5)
        self.assertNotIn("origin", json.dumps(result))
        for value in (False, None):
            changed = {**self.contract, "management_owner_confirmed": value}
            with self.subTest(confirmation=value), self.assertRaises(ValueError):
                recovery.verify_import_observations(observations, changed)

    def test_binding_reads_denied_absent_conditional_or_duplicated_stop_imports(self):
        sid = self.contract["imports"][0]["secret_id"]
        for mutation in ("403", "404", "missing", "member", "role", "condition", "duplicate"):
            observations = authored_observations(self.contract)
            row = observations[sid]
            if mutation in {"403", "404"}: row["http"] = int(mutation)
            elif mutation == "missing": del observations[sid]
            elif mutation == "member": row["policy"]["bindings"][0]["members"] = []
            elif mutation == "role": row["policy"]["bindings"][0]["role"] = "roles/owner"
            elif mutation == "condition": row["policy"]["bindings"][0]["condition"] = {"title": "synthetic", "expression": "true"}
            else: row["policy"]["bindings"].append(deepcopy(row["policy"]["bindings"][0]))
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_import_observations(observations, self.contract)

    def test_no_extra_or_substituted_import_id_is_accepted(self):
        observations = authored_observations(self.contract)
        for mutation in ("extra", "missing", "address", "id", "role", "member", "condition"):
            contract = deepcopy(self.contract)
            if mutation == "extra": contract["imports"].append(deepcopy(contract["imports"][0]))
            elif mutation == "missing": contract["imports"].pop()
            else: contract["imports"][0][mutation] = {"title": "unexpected"} if mutation == "condition" else "unreviewed"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_import_observations(observations, contract)

    def test_plan_without_explicit_imports_cannot_recreate_existing_manual_bindings(self):
        plan = authored_plan(self.contract)
        before = deepcopy(plan)
        with self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)
        self.assertEqual(plan, before)

    def test_importing_noops_are_exact_and_never_effective_import_authorization(self):
        result = recovery.verify_recovery_plan(authored_plan(self.contract, with_imports=True), self.contract)
        self.assertEqual(result["counts"].get("no-op"), 20 + len(self.contract["imports"]))
        self.assertEqual(result["counts"].get("create"), len(c.FOUNDATION_ADDRESSES) - 20 - len(self.contract["imports"]))
        self.assertEqual(len(result["imports"]), 5)
        self.assertEqual(set(result["addresses"]), c.FOUNDATION_ADDRESSES)
        self.assertFalse(result["apply_authorized"])

    def test_only_exact_custom_role_reference_preserves_native_unknown_without_inventing_a_value(self):
        plan = authored_computed_role_plan(self.contract)
        before = deepcopy(plan)
        result = recovery.verify_recovery_plan(plan, self.contract)
        self.assertEqual(result["computed_iam_roles"], [{"address": "google_project_iam_member.bootstrap_reader",
            "native_value": "unknown_until_create",
            "expected_role_from_exact_configuration": "projects/clipforgebeta2/roles/clipforgeIntBootstrapReader"}])
        self.assertEqual(plan, before)
        self.assertFalse(result["apply_authorized"])

    def test_computed_role_exception_does_not_expand_to_other_iam_or_weakened_configuration(self):
        for mutation in ("other-iam", "weak-reference", "extra-permission", "wrong-role-id", "wrong-project", "wrong-member", "not-unknown"):
            plan = authored_computed_role_plan(self.contract)
            member = next(row for row in plan["resource_changes"] if row["address"] == "google_project_iam_member.bootstrap_reader")
            role = next(row for row in plan["resource_changes"] if row["address"] == "google_project_iam_custom_role.bootstrap_reader")
            if mutation == "other-iam":
                other = next(row for row in plan["resource_changes"] if row["address"] == 'google_storage_bucket_iam_member.media["api"]')
                other["change"]["after"]["role"] = None
                other["change"]["after_unknown"]["role"] = True
            elif mutation == "weak-reference": plan["configuration"]["root_module"]["resources"][0]["expressions"]["role"]["references"].pop()
            elif mutation == "extra-permission": role["change"]["after"]["permissions"].append("compute.instances.create")
            elif mutation == "wrong-role-id": role["change"]["after"]["role_id"] = "anotherRole"
            elif mutation == "wrong-project": role["change"]["after"]["project"] = "another-project"
            elif mutation == "wrong-member": member["change"]["after"]["member"] = "allUsers"
            else: member["change"]["after_unknown"]["role"] = False
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)

    def test_private_endpoint_rejection_precedes_token_access_and_network(self):
        good = "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/clipforge-int-pg-app-password:getIamPolicy"
        urls = (good.replace("https:", "http:"), good.replace("secretmanager.googleapis.com", "example.invalid"),
                good.replace("secretmanager.googleapis.com", "secretmanager.googleapis.com.example.invalid"),
                good.replace("https://", "https://synthetic-user:synthetic-password@"),
                good.replace(".com/", ".com:80/"), good.replace(".com/", ".com:invalid/"), good + "#fragment",
                good + "?unreviewed=value", good.replace("clipforgebeta2", "another-project"),
                good.replace(":getIamPolicy", "/versions/latest:access"),
                "https://storage.googleapis.com/storage/v1/b/another-bucket/o/object?alt=media")
        class NoTokenReads(dict):
            def __getitem__(self, key):
                raise AssertionError("Rejected endpoint attempted credential lookup")
        for url in urls:
            with mock.patch.object(recovery.os, "environ", NoTokenReads()), \
                    mock.patch.object(recovery, "build_opener") as network, self.subTest(url=url), self.assertRaises(ValueError):
                recovery.read_private(url, "synthetic read", "synthetic resource")
            network.assert_not_called()

    def test_private_reader_allows_only_fixed_policy_and_pinned_state_gets_with_mock_transport(self):
        state = "https://storage.googleapis.com/storage/v1/b/" + c.BUCKET + "/o/" + quote(c.PREFIX + "/default.tfstate", safe="")
        urls = (state + "?alt=media&generation=123&ifGenerationMatch=123",
                "https://secretmanager.googleapis.com:443/v1/projects/clipforgebeta2/secrets/clipforge-int-pg-app-password:getIamPolicy")
        for url in urls:
            opener, response = mock.Mock(), mock.MagicMock()
            response.__enter__.return_value.read.return_value = b"synthetic private response"
            opener.open.return_value = response
            with mock.patch.dict(recovery.os.environ, {"GCP_ACCESS_TOKEN": "synthetic-no-credentials"}, clear=True), \
                    mock.patch.object(recovery, "build_opener", return_value=opener), self.subTest(url=url):
                self.assertEqual(recovery.read_private(url, "synthetic read", "synthetic resource"), b"synthetic private response")
            request = opener.open.call_args.args[0]
            self.assertEqual(request.get_method(), "GET")
            self.assertIsNone(request.data)
            self.assertEqual(request.full_url, url)

    def test_native_diagnostics_keep_later_logging_iap_errors_and_filter_private_bearer_headers(self):
        lines = ["Error: googleapi: Error 403: Permission 'compute.instances.get' denied on resource projects/clipforgebeta2/zones/us-central1-a/instances/synthetic-" + str(index)
                 for index in range(15)]
        lines += ["Error: googleapi: Error 403: Permission 'logging.buckets.create' denied on resource projects/clipforgebeta2/locations/us-central1/buckets/synthetic",
                  "Error: googleapi: Error 403: Permission 'iap.tunnelInstances.getIamPolicy' denied on resource projects/clipforgebeta2/iap_tunnel/synthetic",
                  "Error: 403 Bearer " + PRIVATE_SENTINEL,
                  json.dumps({"private_attribute": PRIVATE_SENTINEL})]
        raw = "\n".join(lines).encode()
        report = recovery.sanitized_native_errors(raw)
        self.assertEqual(len(report["messages"]), 17)
        self.assertIn("logging.buckets.create", report["permissions"])
        self.assertIn("iap.tunnelInstances.getIamPolicy", report["permissions"])
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(report))
        self.assertEqual(report["original_private_log_sha256"], hashlib.sha256(raw).hexdigest())
        self.assertEqual(report["original_private_log_bytes"], len(raw))
        self.assertFalse(report["raw_log_published"])
        self.assertFalse(report["message_limit_reached"])

    def test_updates_deletes_replacements_and_recreating_current_objects_fail(self):
        for actions in (["update"], ["delete"], ["delete", "create"], ["create", "delete"], ["create"]):
            plan = authored_plan(self.contract, with_imports=True)
            current = next(row for row in plan["resource_changes"] if row["address"] in self.contract["backend"]["managed_addresses"])
            current["change"]["actions"] = actions
            with self.subTest(actions=actions), self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)
        plan = authored_plan(self.contract, with_imports=True)
        untracked = next(row for row in plan["resource_changes"] if row["address"] not in self.contract["backend"]["managed_addresses"]
                         and "importing" not in row["change"])
        untracked["change"].update(actions=["no-op"], before=deepcopy(untracked["change"]["after"]))
        with self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)

    def test_missing_unknown_duplicate_or_payload_resources_and_unsupported_data_fail(self):
        for mutation in ("missing", "duplicate", "foreign", "secret-version", "runtime", "sensitive-data",
                         "mismatched-type", "unknown-mode", "planned-duplicate"):
            plan = authored_plan(self.contract, with_imports=True)
            if mutation == "missing": plan["resource_changes"].pop()
            elif mutation == "duplicate": plan["resource_changes"][0] = deepcopy(plan["resource_changes"][1])
            elif mutation == "foreign": plan["resource_changes"][0]["address"] = "google_compute_instance.unreviewed"
            elif mutation == "secret-version": plan["resource_changes"][0].update(address="google_secret_manager_secret_version.unapproved", type="google_secret_manager_secret_version")
            elif mutation == "runtime": plan["resource_changes"][0].update(address="google_cloud_run_v2_service.api[0]", type="google_cloud_run_v2_service")
            elif mutation == "mismatched-type": plan["resource_changes"][0]["type"] = "google_secret_manager_secret_version"
            elif mutation == "unknown-mode": plan["resource_changes"][0]["mode"] = "unreviewed"
            elif mutation == "planned-duplicate": plan["planned_values"]["root_module"]["resources"].append(deepcopy(plan["planned_values"]["root_module"]["resources"][0]))
            else: plan["planned_values"]["root_module"]["resources"].append({"address": "data.google_secret_manager_secret_version.payload", "mode": "data", "type": "google_secret_manager_secret_version", "values": {"secret_data": PRIVATE_SENTINEL}})
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)

    def test_pinned_plan_import_ids_and_actions_cannot_be_changed(self):
        for mutation in ("id", "create", "unapproved-address"):
            plan = authored_plan(self.contract, with_imports=True)
            if mutation == "unapproved-address":
                row = next(row for row in plan["resource_changes"] if row["address"] not in self.contract["backend"]["managed_addresses"] and "importing" not in row["change"])
                row["change"].update(actions=["no-op"], importing={"id": self.contract["imports"][0]["id"]})
            else:
                row = next(row for row in plan["resource_changes"] if "importing" in row["change"])
                if mutation == "id": row["change"]["importing"]["id"] += " unexpected"
                else: row["change"]["actions"] = ["create"]
            with self.subTest(mutation=mutation), self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)

    def test_reviewed_eight_variables_reject_payload_and_project_disk_or_network_drift(self):
        for key, value in (("project_id", "another-project"), ("data_disk_gb", 21), ("run_subnet_cidr", "0.0.0.0/0"),
                           ("postgres_subnet_cidr", "10.80.0.0/28"), ("machine_type", "e2-small"),
                           ("secret_versions", {"secret_payload": PRIVATE_SENTINEL}), ("stage", "runtime"),
                           ("unreviewed_secret", PRIVATE_SENTINEL)):
            plan = authored_plan(self.contract, with_imports=True)
            plan["variables"][key] = {"value": value}
            with self.subTest(variable=key), self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)
        plan = authored_plan(self.contract, with_imports=True)
        del plan["variables"]["project_id"]
        with self.assertRaises(ValueError): recovery.verify_recovery_plan(plan, self.contract)

    def test_old_plan_name_hash_or_generation_can_never_be_reused(self):
        forbidden = self.contract["original_plan_forbidden"]
        for key in ("binary", "manifest"):
            ref = forbidden[key]
            for field in ("exact", "name", "sha256", "generation"):
                changed = {"name": "private-plans/int/" + "e" * 40 + "/50000000000-1/int.tfplan", "generation": "999", "sha256": "f" * 64, "size": 100}
                if field == "exact": changed = deepcopy(ref)
                else: changed[field] = ref[field]
                with self.subTest(reference=key, field=field), self.assertRaises(ValueError): recovery.reject_original_plan(changed, self.contract)

    def test_new_private_manifest_binds_partial_backend_sources_and_original_twenty_four_hours(self):
        manifest, now = authored_manifest(self.contract)
        before = deepcopy((manifest, self.contract))
        recovery.verify_new_manifest(manifest, self.contract, now=now)
        self.assertEqual((manifest, self.contract), before)
        for instant in (now - timedelta(seconds=1), now + timedelta(hours=24)):
            with self.subTest(time=instant), self.assertRaises(ValueError): recovery.verify_new_manifest(manifest, self.contract, now=instant)
        for field, value in (("expires_utc", (now + timedelta(hours=24, seconds=1)).isoformat()),
                             ("created_utc", now.replace(tzinfo=None).isoformat()), ("apply_authorized", True),
                             ("controls_commit", "a" * 40), ("baseline_configuration_commit", "e" * 40),
                             ("run_id", "44194990499"), ("provider_version", "8.12.0"), ("terraform_version", "1.16.0"),
                             ("base_configuration_sha256", "0" * 64), ("configuration_sha256", "0" * 64),
                             ("control_sources_sha256", ""), ("provider_lock_sha256", "0" * 64),
                             ("risk_acceptance", {"new_plan_approved": True})):
            changed = deepcopy(manifest)
            changed[field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): recovery.verify_new_manifest(changed, self.contract, now=now)
        for field in ("generation", "sha256", "lineage", "serial", "bucket", "prefix", "workspace"):
            changed = deepcopy(manifest)
            changed["backend"][field] = 6 if field == "serial" else "different"
            with self.subTest(backend=field), self.assertRaises(ValueError): recovery.verify_new_manifest(changed, self.contract, now=now)
        for field in ("main.tf", ".terraform.lock.hcl", "recovery-imports.tf", "unexpected.tf"):
            changed = deepcopy(manifest)
            changed["configuration_files"][field] = "0" * 64
            with self.subTest(source=field), self.assertRaises(ValueError): recovery.verify_new_manifest(changed, self.contract, now=now)
        for key, field, value in (("binary", "name", "another-object"), ("json", "generation", "0"),
                                  ("binary", "sha256", self.contract["original_plan_forbidden"]["binary"]["sha256"]),
                                  ("json", "size", 0), ("binary", "size", True)):
            changed = deepcopy(manifest)
            changed[key][field] = value
            with self.subTest(reference=key, field=field), self.assertRaises(ValueError): recovery.verify_new_manifest(changed, self.contract, now=now)

    def trace_recovery(self, root, *, race=None, native_exit=2, reviewed_controls="c" * 40, material_update=False,
                       serial6=False, material_drift=False, numeric_iap=False, expire_at=None):
        """Real validation, simulated HTTP/source preconditions/native execution."""
        raw_state, initial_inventory, initial_contract = authored_partial(serial6=True) if serial6 else (self.raw, self.inventory, self.contract)
        work, reports = root / "work", root / "reports"
        module = work / "module"
        module.mkdir(parents=True)
        reports.mkdir()
        for name in c.FILES:
            target = module / name
            target.parent.mkdir(parents=True, exist_ok=True)
            if numeric_iap:
                target.write_bytes((recovery.ROOT / "infra/gcp/int-base" / name).read_bytes())
            else:
                target.write_text("synthetic prepared module " + name)
        adc = root / "gha-creds-recovery-synthetic.json"
        adc.write_text("Synthetic filename fixture; no credentials.")
        env = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
               "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted", "GITHUB_SHA": "c" * 40,
               "GITHUB_RUN_ID": "50000000000", "GITHUB_RUN_ATTEMPT": "1", "GCP_ACCESS_TOKEN": "synthetic-not-credentials",
               "INT_REVIEWED_CONTROLS_COMMIT": reviewed_controls,
               "GCP_PROJECT_ID": "clipforgebeta2", "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1",
               "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
               "GCP_WIF_PROVIDER": "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
               "TF_STATE_BUCKET": c.BUCKET, "TF_STATE_PREFIX": "terraform/int", "TF_WORKSPACE": "default", "INT_STAGE": "foundation",
               "RUNTIME_IMAGE": self.contract["inputs"]["runtime_image"], "MACHINE_TYPE": "e2-micro", "SECRET_VERSIONS_JSON": "null",
               "GOOGLE_APPLICATION_CREDENTIALS": str(adc)}
        if reviewed_controls is None:
            del env["INT_REVIEWED_CONTROLS_COMMIT"]
        binding = custody.source_binding(module, env)
        contract = deepcopy(initial_contract)
        contract["baseline"] = {"configuration_commit": "b" * 40}
        contract["source_bindings"] = {"base_configuration_sha256": binding["configuration_sha256"],
                                       "provider_lock_sha256": binding["provider_lock_sha256"],
                                       **({} if serial6 else {"imports_sha256": custody.sha256(recovery.import_source(contract))})}
        if numeric_iap:
            contract.update(iap_identity_patch=deepcopy(recovery.IAP_PATCH), read_window=deepcopy(recovery.READ_WINDOW))
            contract["baseline"]["historical_recovery_contract"] = {"path": "config/int-foundation-history/5800b4c-recovery-contract.json",
                "sha256": "97ffe48de5db6ac342acc42b7bb17c1087430c080c6e66b0a431b16d0f115832"}
            env.update(INT_READ_WINDOW_MANIFEST_SHA256="d" * 64, INT_ADMIN_READ_RECEIPTS_SHA256="e" * 64)
        (root / "config").mkdir()
        (root / "config/int-foundation-recovery.json").write_bytes(custody.canonical(contract))
        (root / "config/int-iap-diagnostic.json").write_bytes(custody.canonical({"read_window": {
            **recovery.READ_WINDOW, "manifest_sha256": "d" * 64}}))
        clock = {"now": datetime(2026, 11, 18, 17, 10, tzinfo=timezone.utc)}
        class FixtureClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock["now"]
        observations, calls, uploads = authored_observations(contract), [], []
        def current(_bucket):
            inventory = deepcopy(initial_inventory)
            operations = [operation for _, operation in calls]
            if race == "after-init" and "recovery_init" in operations:
                inventory["live"][0]["generation"] = "1794961942265924"
            return inventory
        def read(url, _operation, resource):
            if resource == contract["backend"]["name"]:
                query = parse_qs(urlsplit(url).query)
                self.assertEqual(query["generation"], [contract["backend"]["generation"]])
                self.assertEqual(query["ifGenerationMatch"], query["generation"])
                return raw_state
            self.assertIn(resource, observations)
            self.assertTrue(url.endswith(":getIamPolicy"))
            return custody.canonical(observations[resource]["policy"])
        def native(argv, operation, _work, **_kwargs):
            calls.append((argv, operation))
            if ((expire_at == "before-plan" and operation == "recovery_validate")
                    or (expire_at == "after-plan" and operation == "recovery_plan")):
                clock["now"] = datetime(2026, 11, 18, 18, tzinfo=timezone.utc)
            if operation == "recovery_plan":
                (work / "int.tfplan").write_bytes(b"synthetic recovery binary")
                return native_exit, b""
            if operation == "recovery_private_plan_json":
                plan = authored_plan(contract, with_imports=True)
                if material_update:
                    row = next(row for row in plan["resource_changes"] if row["address"] in contract["backend"]["managed_addresses"])
                    row["change"]["actions"] = ["update"]
                    row["change"]["after"]["synthetic_private_attribute"] = PRIVATE_SENTINEL
                if material_drift:
                    plan["resource_drift"] = [{"address": "google_compute_instance.postgres", "type": "google_compute_instance",
                                               "change": {"actions": ["update"], "before": {"etag": PRIVATE_SENTINEL + "-old"},
                                                          "after": {"etag": PRIVATE_SENTINEL + "-new"}}}]
                return 0, custody.canonical(plan)
            return 0, b""
        def upload(name, raw):
            uploads.append((name, raw))
            if ((expire_at == "during-upload" and name.endswith("int.json"))
                    or (expire_at == "after-manifest" and name.endswith("manifest.json"))):
                clock["now"] = datetime(2026, 11, 18, 18, tzinfo=timezone.utc)
            return {"name": name, "generation": str(1000 + len(uploads)), "sha256": custody.sha256(raw), "size": len(raw)}
        image_module = types.ModuleType("scripts.review_int_foundation_plan")
        image_module.image_metadata = mock.Mock(return_value={"project": "debian-cloud", "name": "debian-13-trixie-v20261116",
                                                               "id": "5913446147369107523", "status": "READY"})
        with mock.patch.object(recovery, "ROOT", root), mock.patch.object(recovery, "load_contract", return_value=contract), \
                mock.patch.object(recovery, "datetime", FixtureClock), \
                mock.patch.object(recovery, "static_contract"), mock.patch.object(recovery, "read_private", side_effect=read), \
                mock.patch.object(recovery.driver, "metadata", return_value={}), mock.patch.object(recovery.driver, "backend_inventory", side_effect=current), \
                mock.patch.object(recovery.driver, "terraform_binary", return_value="synthetic-terraform"), \
                mock.patch.object(recovery.driver, "run", side_effect=native), mock.patch.object(custody, "upload", side_effect=upload), \
                mock.patch.object(foundation, "fingerprint", return_value=("f" * 64, {})), mock.patch.object(foundation, "load_contract", return_value={}), \
                mock.patch.dict(sys.modules, {image_module.__name__: image_module}), \
                mock.patch.object(sys.modules["scripts"], "review_int_foundation_plan", image_module, create=True), \
                mock.patch.dict(recovery.os.environ, {}, clear=True):
            try:
                summary = recovery.plan_recovery(work, reports, env)
            except ValueError:
                return None, calls, uploads
        return summary, calls, uploads

    def test_native_trace_retains_only_a_new_private_plan_and_never_runs_effective_import_or_apply(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-recovery-native-fixture-") as temporary:
            summary, calls, uploads = self.trace_recovery(Path(temporary))
            self.assertIsNotNone(summary)
            self.assertEqual([operation for _, operation in calls], ["recovery_init", "recovery_validate", "recovery_plan", "recovery_private_plan_json"])
            plan_argv = calls[2][0]
            self.assertIn("-lock=true", plan_argv)
            self.assertIn("-lock-timeout=120s", plan_argv)
            self.assertNotIn("-refresh=false", plan_argv)
            self.assertNotIn("-lock=false", plan_argv)
            self.assertEqual([Path(name).name for name, _ in uploads], ["int.tfplan", "int.json", "manifest.json"])
            self.assertFalse(summary["apply_authorized"])
            self.assertNotIn(PRIVATE_SENTINEL, json.dumps(summary))
            manifest = json.loads(uploads[-1][1])
            self.assertEqual(manifest["baseline_configuration_commit"], "b" * 40)
            self.assertEqual(manifest["controls_commit"], "c" * 40)
            self.assertEqual(manifest["expires_utc"], (datetime.fromisoformat(manifest["created_utc"]) + timedelta(hours=24)).isoformat())
            self.assertFalse(manifest["risk_acceptance"]["new_plan_approved"])
            self.assertEqual(manifest["risk_acceptance"]["maximum_expiry_utc"], self.contract["risk_acceptance"]["maximum_expiry_utc"])

    def test_native_trace_stops_before_plan_if_current_backend_changes_after_init(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-recovery-race-fixture-") as temporary:
            summary, calls, uploads = self.trace_recovery(Path(temporary), race="after-init")
        self.assertIsNone(summary)
        self.assertEqual([operation for _, operation in calls], ["recovery_init", "recovery_validate"])
        self.assertEqual(uploads, [])

    def test_native_plan_failure_is_not_retried_or_published(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-recovery-failure-fixture-") as temporary:
            summary, calls, uploads = self.trace_recovery(Path(temporary), native_exit=1)
        self.assertIsNone(summary)
        self.assertEqual([operation for _, operation in calls], ["recovery_init", "recovery_validate", "recovery_plan"])
        self.assertEqual(uploads, [])

    def test_material_plan_is_retained_privately_once_while_public_review_stays_blocked(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-recovery-material-fixture-") as temporary:
            summary, calls, uploads = self.trace_recovery(Path(temporary), material_update=True)
        self.assertEqual([operation for _, operation in calls], ["recovery_init", "recovery_validate", "recovery_plan", "recovery_private_plan_json"])
        self.assertEqual(summary["status"], "blocked_recovery_plan_material_difference")
        self.assertFalse(summary["apply_authorized"])
        self.assertEqual(len(uploads), 3)
        self.assertIn(PRIVATE_SENTINEL, uploads[1][1].decode())
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(summary))
        self.assertNotIn("counts", summary["review"])
        self.assertTrue(any(row["actions"] == ["update"] for row in summary["review"]["changes"]))
        self.assertTrue(all(set(row) == {"address", "type", "actions", "importing"} for row in summary["review"]["changes"]))
        self.assertEqual(json.loads(uploads[2][1])["plan_review_status"], "blocked_recovery_plan_material_difference")
        with mock.patch.object(sys, "argv", ["int_foundation_recovery", "plan"]), mock.patch.object(recovery.os, "umask"), \
                mock.patch.object(recovery.driver, "private_paths", return_value=(Path("synthetic-work"), Path("synthetic-reports"))), \
                mock.patch.object(recovery, "plan_recovery", return_value=summary):
            self.assertEqual(recovery.main(), 1)

    def test_recovery_requires_the_exact_explicitly_reviewed_dispatch_sha(self):
        for reviewed in (None, "a" * 40):
            with tempfile.TemporaryDirectory(prefix="clipforge-recovery-dispatch-fixture-") as temporary:
                summary, calls, uploads = self.trace_recovery(Path(temporary), reviewed_controls=reviewed)
            with self.subTest(reviewed=reviewed):
                self.assertIsNone(summary)
                self.assertEqual(calls, [])
                self.assertEqual(uploads, [])

    def test_retired_original_apply_contract_rejects_all_real_activation_entry_points(self):
        record = {"schema": "clipforge-int-foundation-owner-risk-acceptance-2", "owner": "AldemaroCruz",
                  "effective_apply_contract_activated": True}
        retired = {"mode": "recovery_preparation_only", "owner_risk_acceptance": record,
                   "owner_risk_acceptance_sha256": custody.sha256(custody.canonical(record))}
        calls = ((foundation.verify_activation, (retired,)),
                 (foundation.verify_owner_decision, ({"apply_decision": "approve_exact_foundation_binary_once"}, "", {}, retired)),
                 (foundation.verify_plan_bridge, ({}, Path("synthetic-unread-module"), {}, {}, retired)))
        for entry, args in calls:
            with self.subTest(entry=entry.__name__), self.assertRaises(ValueError) as error:
                entry(*args)
            self.assertRegex(str(error.exception).lower(), "retir|recovery")

    def test_cli_never_offers_apply_or_effective_import(self):
        for operation in ("apply", "import", "destroy", "force-unlock", "state"):
            with mock.patch.object(sys, "argv", ["int_foundation_recovery", operation]), redirect_stderr(io.StringIO()), self.subTest(operation=operation):
                with self.assertRaises(SystemExit) as result: recovery.main()
            self.assertEqual(result.exception.code, 2)


class FoundationRecoverySerial6(unittest.TestCase):
    def setUp(self):
        self.raw, self.inventory, self.contract = authored_partial(serial6=True)

    def test_authored_serial6_has_41_addresses_without_claiming_real_state_preimage(self):
        proof = recovery.verify_partial_bytes(self.raw, self.inventory, self.contract)
        self.assertEqual(proof["classification"], "recognized_serial6_foundation_state")
        self.assertEqual(len(proof["managed_addresses"]), 41)
        self.assertNotIn(recovery.PENDING_IAP, proof["managed_addresses"])
        self.assertNotEqual(proof["state"]["sha256"], recovery.SERIAL6_PIN["sha256"])
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(proof))

    def test_historical_contract_copy_remains_exact_without_becoming_active(self):
        path = recovery.ROOT / "config/int-foundation-history/79ecadb-recovery-contract.json"
        raw = path.read_bytes()
        self.assertEqual(custody.sha256(raw), "b9be41bc3608e8ea4704cb99379dc337d3775382c32af942155a78c7f84f4a8d")
        historical = json.loads(raw)
        self.assertEqual(historical["backend"]["serial"], 5)
        self.assertEqual(len(historical["imports"]), 5)
        self.assertNotIn("recovery_phase", historical)

    def test_current_contract_is_exact_confirmed_serial6_with_completed_imports_and_no_apply(self):
        contract = recovery.load_contract()
        self.assertTrue(recovery.serial6_mode(contract))
        self.assertEqual({key: contract["backend"][key] for key in recovery.SERIAL6_PIN}, recovery.SERIAL6_PIN)
        self.assertEqual(contract["state_confirmation"]["observed_utc"], "2026-11-18T12:56:44Z")
        self.assertFalse(contract["state_confirmation"]["current_lock_present"])
        self.assertEqual(contract["baseline"]["configuration_commit"], "264d1cfad6500e1abd60d3e7f966a3614a3a5831")
        self.assertEqual(contract["baseline"]["controls_reference"], "5800b4c")
        self.assertEqual(contract["imports"], [])
        self.assertEqual(len(contract["completed_imports"]), 5)
        self.assertFalse(contract["apply_authorized"])
        self.assertFalse(contract["risk_acceptance"]["new_plan_approved"])
        self.assertTrue(contract["risk_acceptance"]["historical_reference_only"])

    def test_serial6_static_pin_checks_original_ten_sources_without_reading_import_file(self):
        historical = json.loads((recovery.ROOT / "config/int-foundation-history/79ecadb-recovery-contract.json").read_bytes())
        contract = deepcopy(historical)
        contract.update(recovery_phase=recovery.SERIAL6_PHASE, completed_imports=deepcopy(historical["imports"]),
                        imports=[], pending_addresses=[recovery.PENDING_IAP], expected_plan={"no-op": 41, "create": 1},
                        additional_retired_plans=[deepcopy(recovery.SERIAL5_RETIRED)])
        contract["backend"].update(recovery.SERIAL6_PIN)
        contract["backend"]["managed_addresses"] = sorted(c.FOUNDATION_ADDRESSES - {recovery.PENDING_IAP})
        del contract["source_bindings"]["imports_source"]
        del contract["source_bindings"]["imports_sha256"]
        native_read = Path.read_bytes
        def read(path):
            self.assertNotIn(path.name, {"int-foundation-recovery-imports.tf", "recovery-imports.tf"})
            return native_read(path)
        with tempfile.TemporaryDirectory(prefix="clipforge-original-source-fixture-") as temporary:
            original = Path(temporary)
            module = original / "infra/gcp/int-base"
            module.mkdir(parents=True)
            for name in c.FILES:
                raw = (recovery.ROOT / "infra/gcp/int-base" / name).read_bytes()
                if name == "runtime.tf": raw = raw.replace(recovery.IAP_NEW, recovery.IAP_OLD)
                (module / name).parent.mkdir(parents=True, exist_ok=True)
                (module / name).write_bytes(raw)
            (original / "scripts").mkdir()
            (original / "scripts/tf_int_plan.py").write_bytes((recovery.ROOT / "scripts/tf_int_plan.py").read_bytes())
            with mock.patch.object(Path, "read_bytes", read):
                binding = recovery.static_contract(original, contract)
            for key, value in (("serial", 5), ("generation", "1794975925421250"), ("sha256", "0" * 64), ("size", 109543)):
                changed = deepcopy(contract)
                changed["backend"][key] = value
                with self.subTest(key=key), self.assertRaises(ValueError):
                    recovery.static_contract(original, changed)
        self.assertEqual(binding["configuration_sha256"], "1cf09b8ebd357761a217b7cae3d46e37397eadff39deeaa79500aac5276a7a7c")

    def test_serial1_and_serial5_state_or_incomplete_41_set_are_rejected(self):
        for mutation in ("serial1", "serial5", "missing", "substituted", "imports", "preview-source", "phase"):
            contract = deepcopy(self.contract)
            if mutation.startswith("serial"):
                contract["backend"]["serial"] = int(mutation[-1])
            elif mutation == "missing":
                contract["backend"]["managed_addresses"].pop()
            elif mutation == "substituted":
                contract["backend"]["managed_addresses"] = sorted(contract["backend"]["managed_addresses"][1:] + [recovery.PENDING_IAP])
            elif mutation == "imports":
                contract["imports"] = authored_imports()
            elif mutation == "preview-source":
                contract["source_bindings"]["imports_source"] = "config/int-foundation-recovery-imports.tf"
            else:
                contract["recovery_phase"] = "unreviewed"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_partial_bytes(self.raw, self.inventory, contract)

    def test_serial6_only_accepts_actual_41_noops_one_iap_create_and_no_imports(self):
        plan = authored_plan(self.contract)
        before = deepcopy(plan)
        result = recovery.verify_recovery_plan(plan, self.contract)
        self.assertEqual(result["counts"], {"no-op": 41, "create": 1})
        self.assertEqual(result["imports"], [])
        self.assertFalse(result["apply_authorized"])
        self.assertEqual(plan, before)
        self.assertEqual([row["address"] for row in plan["resource_changes"] if row["change"]["actions"] == ["create"]], [recovery.PENDING_IAP])

    def test_serial6_drift_replacement_incomplete_and_hidden_noop_change_block(self):
        for mutation in ("update", "replacement", "drift", "deferred", "incomplete", "hidden-noop", "import", "iap-noop", "member", "role"):
            plan = authored_plan(self.contract)
            prior = next(row for row in plan["resource_changes"] if row["address"] in self.contract["backend"]["managed_addresses"])
            iap = next(row for row in plan["resource_changes"] if row["address"] == recovery.PENDING_IAP)
            if mutation == "update": prior["change"]["actions"] = ["update"]
            elif mutation == "replacement": prior["change"]["actions"] = ["delete", "create"]
            elif mutation == "drift": plan["resource_drift"] = [{"address": prior["address"], "change": {"actions": ["update"]}}]
            elif mutation == "deferred": plan["deferred_changes"] = [{"reason": "synthetic"}]
            elif mutation == "incomplete": plan["complete"] = False
            elif mutation == "hidden-noop": prior["change"]["after"]["private_change"] = PRIVATE_SENTINEL
            elif mutation == "import": prior["change"]["importing"] = {"id": "synthetic-new-import"}
            elif mutation == "iap-noop": iap["change"]["actions"] = ["no-op"]
            elif mutation == "member": iap["change"]["after"]["member"] = "serviceAccount:other@example.invalid"
            else: iap["change"]["after"]["role"] = "roles/owner"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_recovery_plan(plan, self.contract)

    def test_serial6_manifest_has_only_ten_original_files_and_rejects_retired_backend(self):
        manifest, now = authored_manifest(self.contract)
        recovery.verify_new_manifest(manifest, self.contract, now)
        self.assertEqual(set(manifest["configuration_files"]), set(c.FILES))
        for mutation in ("import-file", "import-preview", "backend1", "backend5", "phase", "completed-imports", "old-binary"):
            changed = deepcopy(manifest)
            if mutation == "import-file": changed["configuration_files"]["recovery-imports.tf"] = "a" * 64
            elif mutation == "import-preview": changed["imports"] = authored_imports()
            elif mutation.startswith("backend"): changed["backend"]["serial"] = int(mutation[-1])
            elif mutation == "phase": changed["recovery_phase"] = None
            elif mutation == "completed-imports": changed["completed_imports"] = []
            else: changed["binary"]["sha256"] = "c75860660cee6f3ac1c929963bac70f660e08d40767610e1895cd115f2462469"
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                recovery.verify_new_manifest(changed, self.contract, now)

    def test_retired_serial5_binary_manifest_and_run_are_rejected_even_if_renamed(self):
        for key in ("binary", "manifest"):
            retired = recovery.SERIAL5_RETIRED[key]
            for field in ("generation", "sha256"):
                reference = {"name": "private-plans/int/" + "c" * 40 + "/50000000000-1/int.tfplan",
                             "generation": "999999", "sha256": "f" * 64}
                reference[field] = retired[field]
                with self.subTest(key=key, field=field), self.assertRaises(ValueError):
                    recovery.reject_original_plan(reference, self.contract)
        with self.assertRaises(ValueError):
            recovery.reject_original_plan({"name": "private-plans/int/" + "c" * 40 + "/44219757502-1/int.tfplan"}, self.contract)

    def test_serial6_never_generates_import_source_or_observes_import_policies(self):
        with self.assertRaises(ValueError): recovery.import_source(self.contract)
        with mock.patch.object(recovery, "read_private", side_effect=AssertionError("no IAM observation")):
            with self.assertRaises(ValueError): recovery.inspect_imports(self.contract)

    def test_serial6_trace_uses_no_import_file_or_policy_reads_and_keeps_native_locking(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-serial6-fixture-") as temporary:
            root = Path(temporary)
            summary, calls, uploads = FoundationRecovery.trace_recovery(self, root, serial6=True)
            self.assertIsNotNone(summary)
            self.assertFalse((root / "work/module/recovery-imports.tf").exists())
            self.assertEqual(summary["review"]["counts"], {"no-op": 41, "create": 1})
            self.assertEqual(summary["review"]["imports"], [])
            manifest = json.loads(uploads[-1][1])
            self.assertEqual(set(manifest["configuration_files"]), set(c.FILES))
            self.assertIsNone(manifest["import_policies_sha256"])
            self.assertIn("-lock=true", calls[2][0])
            self.assertNotIn("-refresh=false", calls[2][0])

    def test_serial6_real_drift_fixture_is_preserved_privately_and_public_summary_blocks(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-serial6-drift-fixture-") as temporary:
            summary, calls, uploads = FoundationRecovery.trace_recovery(self, Path(temporary), serial6=True, material_drift=True)
            self.assertEqual(summary["status"], "blocked_recovery_plan_material_difference")
            self.assertFalse(summary["apply_authorized"])
            self.assertEqual(summary["review"]["drift"][0]["address"], "google_compute_instance.postgres")
            self.assertEqual(summary["review"]["observed_drift"], [{"address": "google_compute_instance.postgres",
                "type": "google_compute_instance", "actions": ["update"], "changed_attribute_keys": ["etag"]}])
            private_plan = json.loads(uploads[1][1])
            self.assertEqual(sum(row["change"]["actions"] == ["no-op"] for row in private_plan["resource_changes"]), 41)
            self.assertEqual(sum(row["change"]["actions"] == ["create"] for row in private_plan["resource_changes"]), 1)
            self.assertNotIn(PRIVATE_SENTINEL, json.dumps(summary))
            self.assertIn(PRIVATE_SENTINEL, uploads[1][1].decode())
            self.assertEqual(len(uploads), 3)
            self.assertEqual(sum(operation == "recovery_plan" for _, operation in calls), 1)


class FoundationRecoveryNumericIap(unittest.TestCase):
    def setUp(self):
        self.raw, self.inventory, self.contract = authored_partial(serial6=True)
        self.contract.update(iap_identity_patch=deepcopy(recovery.IAP_PATCH), read_window=deepcopy(recovery.READ_WINDOW))

    def test_previous_head_contract_is_preserved_byte_exact_with_serial6_and_no_new_imports(self):
        raw = (recovery.ROOT / "config/int-foundation-history/5800b4c-recovery-contract.json").read_bytes()
        self.assertEqual(custody.sha256(raw), "97ffe48de5db6ac342acc42b7bb17c1087430c080c6e66b0a431b16d0f115832")
        history = json.loads(raw)
        self.assertTrue(recovery.serial6_mode(history))
        self.assertFalse(recovery.iap_patch_mode(history))
        self.assertNotIn("read_window", history)
        self.assertEqual(history["baseline"]["configuration_commit"], "264d1cfad6500e1abd60d3e7f966a3614a3a5831")

    def test_current_source_is_exact_two_expression_patch_and_preserves_original_baseline(self):
        contract = recovery.load_contract()
        self.assertTrue(recovery.iap_patch_mode(contract))
        binding = recovery.static_contract(recovery.ROOT, contract)
        self.assertEqual(binding["configuration_sha256"], recovery.IAP_PATCH["configuration_sha256"])
        self.assertEqual(contract["source_bindings"]["original_base_configuration_sha256"],
                         recovery.IAP_PATCH["original_configuration_sha256"])
        self.assertEqual(contract["baseline"]["previous_controls_commit"], "5800b4c5c7a58ccd9ee738cc7d72cc59cb6c007f")

    def test_source_guard_rejects_old_half_patch_additional_runtime_or_other_file_changes(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-iap-source-fixture-") as temporary:
            source = Path(temporary)
            originals = {name: (recovery.ROOT / "infra/gcp/int-base" / name).read_bytes() for name in c.FILES}
            for mutation in ("old", "half", "runtime", "other"):
                changed = dict(originals)
                if mutation == "old": changed["runtime.tf"] = changed["runtime.tf"].replace(recovery.IAP_NEW, recovery.IAP_OLD)
                elif mutation == "half": changed["runtime.tf"] = changed["runtime.tf"].replace(b"postgres.instance_id", b"postgres.name")
                elif mutation == "runtime": changed["runtime.tf"] += b"\n# unauthorized\n"
                else: changed["main.tf"] += b"\n# unauthorized\n"
                for name, raw in changed.items():
                    (source / name).parent.mkdir(parents=True, exist_ok=True)
                    (source / name).write_bytes(raw)
                with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                    recovery.verify_iap_sources(source, self.contract)

    def test_numeric_iap_plan_requires_exact_project_instance_and_zone(self):
        plan = authored_plan(self.contract)
        self.assertEqual(recovery.verify_recovery_plan(plan, self.contract)["counts"], {"no-op": 41, "create": 1})
        for key, value in (("project", "clipforgebeta2"), ("project", "816643438939"),
                           ("instance", "clipforge-int-base-postgres"), ("instance", "1670495097211408132"),
                           ("zone", "us-central1-b"), ("instance", None)):
            changed = deepcopy(plan)
            row = next(row for row in changed["resource_changes"] if row["address"] == recovery.PENDING_IAP)
            row["change"]["after"][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                recovery.verify_recovery_plan(changed, self.contract)

    def test_read_window_has_half_open_utc_bounds_and_reference_only_receipts(self):
        env = {"INT_READ_WINDOW_MANIFEST_SHA256": "d" * 64, "INT_ADMIN_READ_RECEIPTS_SHA256": "e" * 64}
        with tempfile.TemporaryDirectory(prefix="clipforge-iap-window-fixture-") as temporary:
            root = Path(temporary)
            (root / "config").mkdir()
            path = root / "config/int-iap-diagnostic.json"
            path.write_bytes(custody.canonical({"read_window": {**recovery.READ_WINDOW, "manifest_sha256": "d" * 64}}))
            with mock.patch.object(recovery, "ROOT", root):
                result = recovery.read_window_reference(self.contract, env, datetime(2026, 11, 18, 17, tzinfo=timezone.utc))
                self.assertFalse(result["external_evidence_bytes_ingested"])
                self.assertEqual(result["admin_read_receipts_sha256"], "e" * 64)
                for hour, minute in ((16, 59), (18, 0)):
                    with self.subTest(hour=hour), self.assertRaises(ValueError):
                        recovery.read_window_reference(self.contract, env, datetime(2026, 11, 18, hour, minute, tzinfo=timezone.utc))
                for key in env:
                    changed = dict(env, **{key: "invalid"})
                    with self.subTest(key=key), self.assertRaises(ValueError):
                        recovery.read_window_reference(self.contract, changed, datetime(2026, 11, 18, 17, tzinfo=timezone.utc))
                changed = dict(env, INT_READ_WINDOW_MANIFEST_SHA256="a" * 64)
                with self.assertRaises(ValueError):
                    recovery.read_window_reference(self.contract, changed, datetime(2026, 11, 18, 17, tzinfo=timezone.utc))

    def test_new_plan_manifest_uses_new_github_sha_and_original_producer_and_keeps_private_ttl(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-numeric-iap-fixture-") as temporary:
            summary, calls, uploads = FoundationRecovery.trace_recovery(self, Path(temporary), serial6=True, numeric_iap=True)
        self.assertEqual(summary["status"], "recovery_plan_requires_new_review")
        manifest = json.loads(uploads[-1][1])
        self.assertEqual(manifest["configuration_commit"], "c" * 40)
        self.assertEqual(manifest["controls_commit"], "c" * 40)
        self.assertEqual(manifest["baseline_configuration_commit"], "b" * 40)
        self.assertEqual(manifest["iap_identity_patch"], recovery.IAP_PATCH)
        self.assertEqual(manifest["configuration_sha256"], recovery.IAP_PATCH["configuration_sha256"])
        self.assertEqual(manifest["expires_utc"], (datetime.fromisoformat(manifest["created_utc"]) + timedelta(hours=24)).isoformat())
        self.assertFalse(manifest["read_window"]["external_evidence_bytes_ingested"])
        self.assertFalse(summary["apply_authorized"])
        self.assertIn("-lock=true", calls[2][0])
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(summary))

    def test_expiry_before_plan_blocks_without_planning_or_uploading(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-numeric-iap-preexpiry-fixture-") as temporary:
            summary, calls, uploads = FoundationRecovery.trace_recovery(self, Path(temporary), serial6=True,
                                                                       numeric_iap=True, expire_at="before-plan")
        self.assertIsNone(summary)
        self.assertEqual([operation for _, operation in calls], ["recovery_init", "recovery_validate"])
        self.assertEqual(uploads, [])

    def test_expiry_after_plan_or_during_custody_preserves_private_evidence_but_blocks(self):
        for stage in ("after-plan", "during-upload", "after-manifest"):
            with tempfile.TemporaryDirectory(prefix="clipforge-numeric-iap-expiry-fixture-") as temporary:
                summary, calls, uploads = FoundationRecovery.trace_recovery(self, Path(temporary), serial6=True,
                                                                           numeric_iap=True, expire_at=stage)
            with self.subTest(stage=stage):
                self.assertEqual(summary["status"], "blocked_recovery_plan_read_window_expired")
                self.assertTrue(summary["review"]["read_window_expired"])
                self.assertEqual(len(uploads), 3)
                self.assertFalse(summary["apply_authorized"])
                self.assertEqual(sum(operation == "recovery_plan" for _, operation in calls), 1)
                if stage != "after-manifest":
                    self.assertEqual(json.loads(uploads[-1][1])["plan_review_status"], summary["status"])

    def test_numeric_plan_drift_is_not_hidden_by_identity_fix(self):
        with tempfile.TemporaryDirectory(prefix="clipforge-numeric-iap-drift-fixture-") as temporary:
            summary, _, uploads = FoundationRecovery.trace_recovery(self, Path(temporary), serial6=True,
                                                                    numeric_iap=True, material_drift=True)
        self.assertEqual(summary["status"], "blocked_recovery_plan_material_difference")
        self.assertEqual(summary["review"]["observed_drift"][0]["changed_attribute_keys"], ["etag"])
        self.assertEqual(len(uploads), 3)
        self.assertNotIn(PRIVATE_SENTINEL, json.dumps(summary))


if __name__ == "__main__":
    unittest.main()
