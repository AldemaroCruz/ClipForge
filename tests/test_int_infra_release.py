"""Authored contracts for private custody/approval. No cloud acceptance is claimed."""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import tarfile
import io
import unittest
from unittest import mock
from urllib.parse import parse_qs, urlsplit

from scripts import check_tf_int as c, int_release as r, int_secrets as secrets
from scripts import int_bootstrap_vm as vm, int_bootstrap_db as db, int_release_image as image_release
from scripts import int_release_state as provenance
from tests.test_tf_int import fixture, IMAGE, VERSIONS


class Custody(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="clipforge-int-release-test-")
        self.addCleanup(self.temp.cleanup)
        self.work = Path(self.temp.name)
        self.module = self.work / "module"
        self.module.mkdir()
        for name in c.FILES:
            target = self.module / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text("authored source fixture " + name)
        self.env = {"GITHUB_SHA": "b" * 40, "RUNTIME_IMAGE": IMAGE, "SECRET_VERSIONS_JSON": json.dumps(VERSIONS),
                    "MACHINE_TYPE": "e2-micro", "INT_STAGE": "foundation", "GITHUB_RUN_ID": "123", "GITHUB_RUN_ATTEMPT": "1",
                    "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
                    "GITHUB_EVENT_NAME": "workflow_dispatch", "RUNNER_ENVIRONMENT": "github-hosted", "GCP_ACCESS_TOKEN": "synthetic-redacted"}
        self.backend = {"classification": "recognized_initial_state", "initial_lineage": "authored-lineage",
                        "initial_state_sha256": "c" * 64, "live": [{"name": c.PREFIX + "/default.tfstate", "generation": "11"}]}
        self.base = r.PREFIX + "b" * 40 + "/123-1/"
        self.manifest = {"schema": r.SCHEMA, **r.source_binding(self.module, self.env),
                         "backend": {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "lineage": "authored-lineage",
                                     "serial": 1, "state_generation": "11", "state_sha256": "c" * 64},
                         "created_utc": datetime.now(timezone.utc).isoformat(), "run_id": "123", "run_attempt": "1",
                         "binary": {"name": self.base + "int.tfplan"}, "json": {"name": self.base + "int.json"}}

    def test_manifest_rejects_other_commit_inputs_config_provider_state_and_expiry(self):
        r.verify_manifest(self.manifest, self.module, self.env, self.backend)
        for key in ("commit", "inputs", "configuration_sha256", "provider_lock_sha256", "terraform_version", "backend"):
            value = copy.deepcopy(self.manifest)
            value[key] = "different reviewed binding"
            with self.subTest(key=key), self.assertRaises(ValueError):
                r.verify_manifest(value, self.module, self.env, self.backend)
        old = {**self.manifest, "created_utc": (datetime.now(timezone.utc) - timedelta(hours=25)).isoformat()}
        with self.assertRaises(ValueError): r.verify_manifest(old, self.module, self.env, self.backend)
        changed = copy.deepcopy(self.backend); changed["live"][0]["generation"] = "12"
        with self.assertRaises(ValueError): r.verify_manifest(self.manifest, self.module, self.env, changed)

    def test_custody_only_creates_immutable_objects_outside_backend(self):
        opener = mock.Mock()
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"name":"safe"}'
        opener.open.return_value = response
        with mock.patch.dict(os.environ, self.env, clear=True), mock.patch.object(r, "build_opener", return_value=opener):
            r.request("POST", self.base + "int.tfplan", payload=b"authored binary")
        req = opener.open.call_args.args[0]
        query = parse_qs(urlsplit(req.full_url).query)
        self.assertEqual(query["ifGenerationMatch"], ["0"])
        self.assertTrue(query["name"][0].startswith("private-plans/int/"))
        for method in ("DELETE", "PUT", "PATCH"):
            with self.subTest(method=method), self.assertRaises(ValueError): r.request(method, self.base + "int.tfplan")
        for name in (c.PREFIX + "/default.tfstate", "private-plans/int/../int.tfplan", self.base + "gha-creds.json"):
            with self.subTest(name=name), self.assertRaises(ValueError): r.object_name(name)

    def test_generation_sha_and_size_are_all_verified(self):
        raw = b"authored binary"
        reference = {"name": self.base + "int.tfplan", "generation": "123", "sha256": r.sha256(raw), "size": len(raw)}
        with mock.patch.object(r, "request", return_value=raw):
            self.assertEqual(r.fetch_verified(reference), raw)
            for field, value in (("sha256", "d" * 64), ("size", 100)):
                with self.subTest(field=field), self.assertRaises(ValueError): r.fetch_verified({**reference, field: value})

    def test_retention_writes_only_private_binary_json_manifest_and_safe_references(self):
        (self.work / "int.tfplan").write_bytes(b"private-authored-plan")
        (self.work / "private-plan.json").write_bytes(b'{"synthetic":"private-state-sentinel"}')
        names = []
        def upload(name, raw):
            names.append(name)
            return {"name": name, "generation": "123", "sha256": r.sha256(raw), "size": len(raw)}
        with mock.patch.object(r, "upload", side_effect=upload):
            report = r.retain_plan(self.work, self.backend, self.env)
        self.assertEqual(names, [self.base + "int.tfplan", self.base + "int.json", self.base + "manifest.json"])
        self.assertNotIn("private-state-sentinel", json.dumps(report))

    def test_no_apply_when_application_ci_blocked(self):
        env = {**self.env, "INT_APPROVED_COMMIT": self.env["GITHUB_SHA"]}
        with mock.patch.object(r, "require_application_ci", side_effect=ValueError("Existing application CI blocks INT mutation")), \
                mock.patch.object(r, "fetch_verified") as fetch:
            with self.assertRaises(ValueError): r.apply_saved(self.work, self.work, {}, env)
        fetch.assert_not_called()

    def test_runtime_image_and_secret_versions_reject_tags_latest_or_payloads(self):
        for image, versions in ((IMAGE.replace("@sha256:", ":"), VERSIONS),
                                (IMAGE, {**VERSIONS, "app_password": "latest"}), (IMAGE, {"password": "private-sentinel"})):
            with self.subTest(image=image), self.assertRaises(ValueError) as failure: c.runtime_inputs(image, versions)
            self.assertNotIn("private-sentinel", str(failure.exception))


class RuntimeSafety(unittest.TestCase):
    def test_blank_disk_requires_explicit_identity_and_refuses_existing_signatures_partitions_mounts(self):
        blank = {"blockdevices": [{"type": "disk", "fstype": None, "mountpoints": [None]}]}
        vm.blank_disk_contract("123", "INITIALIZE_NEW_DISK_123", [], blank)
        for confirmation, signatures, info in (("INITIALIZE_NEW_DISK_124", [], blank),
                ("INITIALIZE_NEW_DISK_123", [{"type": "ext4"}], blank),
                ("INITIALIZE_NEW_DISK_123", [], {"blockdevices": [{"type": "disk", "children": [{}]}]}),
                ("INITIALIZE_NEW_DISK_123", [], {"blockdevices": [{"type": "disk", "mountpoints": ["/existing"]}]})):
            with self.subTest(confirmation=confirmation), self.assertRaises(ValueError): vm.blank_disk_contract("123", confirmation, signatures, info)

    def test_archive_identity_is_manifest_bytes_never_docker_image_config_id(self):
        manifest = r.canonical({"mediaType": "application/vnd.oci.image.manifest.v1+json", "config": {"digest": "sha256:" + "b" * 64}})
        digest = r.sha256(manifest)
        index = r.canonical({"manifests": [{"digest": "sha256:" + digest}]})
        with tempfile.TemporaryDirectory(prefix="clipforge-oci-test-") as temporary:
            path = Path(temporary) / "runtime.oci.tar"
            with tarfile.open(path, "w") as archive:
                for name, raw in (("index.json", index), ("blobs/sha256/" + digest, manifest)):
                    member = tarfile.TarInfo(name); member.size = len(raw); archive.addfile(member, io.BytesIO(raw))
            self.assertEqual(image_release.archive_digest(path), "sha256:" + digest)
            self.assertNotEqual(image_release.archive_digest(path), "sha256:" + "b" * 64)

    def test_foundation_and_runtime_have_explicit_complete_different_counts(self):
        plan = fixture()
        self.assertEqual(len(c.ADDRESSES), 52)
        self.assertEqual(len(c.FOUNDATION_ADDRESSES), 42)
        plan["variables"]["stage"]["value"] = "foundation"
        plan["resource_changes"] = [x for x in plan["resource_changes"] if x["address"] in c.FOUNDATION_ADDRESSES]
        self.assertEqual(c.plan_contract(plan, "# authored startup fixture")["counts"], {"create": 42})
        plan["resource_changes"].pop()
        with self.assertRaises(ValueError): c.plan_contract(plan, "# authored startup fixture")

    def test_iap_audit_retention_and_single_task_guards(self):
        cases = [("google_cloud_run_v2_service.api[0]", "iap_enabled", False),
                 ("google_logging_project_bucket_config.access", "retention_days", 0)]
        for address, key, value in cases:
            plan = fixture()
            next(x for x in plan["resource_changes"] if x["address"] == address)["change"]["after"][key] = value
            with self.subTest(address=address), self.assertRaises(ValueError): c.plan_contract(plan, "# authored startup fixture")
        plan = fixture()
        audit = next(x for x in plan["resource_changes"] if x["address"] == "google_project_iam_audit_config.storage_access")
        audit["change"]["after"]["audit_log_config"][0]["exempted_members"] = ["allUsers"]
        with self.assertRaises(ValueError): c.plan_contract(plan, "# authored startup fixture")

    def test_proposed_iam_rejects_other_principals_roles_and_custom_role_expansion(self):
        for field, value in (("member", "user:unapproved@example.org"), ("role", "roles/owner")):
            plan = fixture()
            row = next(x for x in plan["resource_changes"] if x["address"] == 'google_secret_manager_secret_iam_member.version_publisher["app_password"]')
            row["change"]["after"][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError): c.plan_contract(plan, "# authored startup fixture")
        plan = fixture()
        row = next(x for x in plan["resource_changes"] if x["address"] == "google_project_iam_custom_role.bootstrap_reader")
        row["change"]["after"]["permissions"].append("compute.instances.create")
        with self.assertRaises(ValueError): c.plan_contract(plan, "# authored startup fixture")

    def test_protected_payloads_have_no_defaults_and_never_return_secret_values(self):
        for target, raw in (("app_password", b""), ("app_password", b"weak"), ("bootstrap_admin", b'{}'),
                            ("postgres_ca", b"-----BEGIN PRIVATE KEY-----\nsynthetic")):
            with self.subTest(target=target), self.assertRaises(ValueError) as failure: secrets.validate_payload(target, raw)
            self.assertNotIn("synthetic", str(failure.exception))
        secrets.validate_payload("app_password", b"x" * 32)
        secrets.validate_payload("bootstrap_admin", b'{"username":"pilot.admin","password":"authored-test-password"}')


class FoundationProvenance(unittest.TestCase):
    setUp = Custody.setUp
    def state(self):
        resources = []
        for address in sorted(c.FOUNDATION_ADDRESSES):
            base, _, index = address.partition("[")
            kind, name = base.split(".", 1)
            instance = {"attributes": {"private_sentinel": "never-publish-state-attributes"}}
            if index:
                instance["index_key"] = json.loads(index[:-1])
            resources.append({"mode": "managed", "type": kind, "name": name, "instances": [instance]})
        return {"version": 4, "terraform_version": "1.15.8", "lineage": provenance.driver.INITIAL_STATE["lineage"],
                "serial": 2, "outputs": {}, "resources": resources}

    def receipt(self):
        raw = r.canonical(self.state())
        reference = {"name": self.base + "foundation-state.json", "generation": "15", "size": 100, "sha256": "e" * 64}
        env = {**self.env, "INT_STAGE": "runtime", "FOUNDATION_RECEIPT_JSON": json.dumps(reference)}
        parent = {**self.manifest, "backend": {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default",
                 "lineage": provenance.driver.INITIAL_STATE["lineage"], "serial": 1,
                 "state_generation": provenance.driver.INITIAL_STATE["generation"], "state_sha256": provenance.driver.INITIAL_STATE["sha256"]},
                 "binary": {"sha256": "f" * 64}}
        receipt = {"schema": provenance.SCHEMA, "foundation_commit": self.env["GITHUB_SHA"],
                   "source_plan_sha256": "f" * 64, "managed_addresses": sorted(c.FOUNDATION_ADDRESSES),
                   "foundation_plan_manifest": {"name": self.base + "manifest.json"},
                   "issuer": {"repository": "AldemaroCruz/ClipForge", "workflow": ".github/workflows/int-e2e-apply.yml",
                              "commit": self.env["GITHUB_SHA"], "run_id": "123"},
                   "state": {"name": provenance.driver.STATE_NAME, "generation": "22", "size": len(raw),
                             "sha256": r.sha256(raw), "lineage": provenance.driver.INITIAL_STATE["lineage"], "serial": 2}}
        return raw, env, parent, receipt

    def test_owned_foundation_is_accepted_only_with_explicit_reviewed_receipt_and_current_bytes(self):
        raw, env, parent, receipt = self.receipt()
        safe = {"bucket": c.BUCKET, "prefix": c.PREFIX, "workspace": "default", "live": [{"name": provenance.driver.STATE_NAME, "generation": "22"}],
                "historical": [], "soft_deleted": []}
        with mock.patch.object(r, "fetch_verified", side_effect=[r.canonical(receipt), r.canonical(parent)]), \
                mock.patch.object(provenance, "verify_apply_run"), \
                mock.patch.object(provenance, "private_current_state", return_value=(raw, {"generation": "22"}, safe)):
            result = provenance.inspect_approved_foundation({}, self.module, env)
        self.assertEqual(result["classification"], "recognized_approved_foundation_state")
        self.assertNotIn("never-publish-state-attributes", json.dumps(result))
        with self.assertRaises(ValueError): r.inputs({**env, "FOUNDATION_RECEIPT_JSON": "null"})

    def test_unknown_resources_and_current_generation_change_stop_runtime(self):
        value = self.state()
        value["resources"].append({"mode": "managed", "type": "google_compute_instance", "name": "unknown", "instances": [{}]})
        with self.assertRaises(ValueError): provenance.state_contract(r.canonical(value), lineage=provenance.driver.INITIAL_STATE["lineage"])
        raw, env, parent, receipt = self.receipt()
        with mock.patch.object(r, "fetch_verified", side_effect=[r.canonical(receipt), r.canonical(parent)]), \
                mock.patch.object(provenance, "verify_apply_run"), \
                mock.patch.object(provenance, "private_current_state", return_value=(raw, {"generation": "23"}, {})):
            with self.assertRaises(ValueError): provenance.inspect_approved_foundation({}, self.module, env)

    def test_forged_or_wrong_parent_plan_cannot_authorize_managed_state(self):
        _, env, parent, receipt = self.receipt()
        provenance.verify_parent(receipt, parent, self.module, env)
        for key, value in (("foundation_commit", "d" * 40), ("source_plan_sha256", "c" * 64), ("schema", "untrusted")):
            forged = {**receipt, key: value}
            with self.subTest(key=key), self.assertRaises(ValueError): provenance.verify_parent(forged, parent, self.module, env)
        wrong = copy.deepcopy(parent); wrong["inputs"]["stage"] = "runtime"
        with self.assertRaises(ValueError): provenance.verify_parent(receipt, wrong, self.module, env)


if __name__ == "__main__":
    unittest.main()
