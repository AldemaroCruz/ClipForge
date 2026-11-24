from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from scripts import int_hito_a_delivery as delivery
from scripts import int_release


COMMIT = "a" * 40
DIGEST = "sha256:" + "b" * 64
IMAGE = delivery.IMAGE_PREFIX + "b" * 64


def environment(root):
    private = Path(root) / "clipforge-int-hito-a.fixture"
    private.mkdir()
    archive = private / "runtime.oci.tar"
    archive.write_bytes(b"exact-archive")
    return {
        "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
        "GITHUB_REF": "refs/heads/ci/bootstrap-sec03",
        "GITHUB_EVENT_NAME": "workflow_dispatch",
        "GITHUB_WORKFLOW_REF": "AldemaroCruz/ClipForge/.github/workflows/int-hito-a.yml@refs/heads/ci/bootstrap-sec03",
        "RUNNER_ENVIRONMENT": "github-hosted",
        "GITHUB_JOB": "deploy",
        "GITHUB_SHA": COMMIT,
        "INT_APPROVED_COMMIT": COMMIT,
        "GITHUB_RUN_ID": "123",
        "GITHUB_RUN_ATTEMPT": "1",
        "GCP_PROJECT_ID": delivery.PROJECT,
        "GCP_PROJECT_NUMBER": delivery.PROJECT_NUMBER,
        "GCP_REGION": delivery.REGION,
        "GCP_WIF_PROVIDER":
            "projects/816643438938/locations/global/workloadIdentityPools/clipforge-gh-int/providers/github",
        "GCP_TERRAFORM_SA": "clipforge-terraform-int@clipforgebeta2.iam.gserviceaccount.com",
        "GCP_DEPLOY_SA": "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com",
        "ARTIFACT_REGISTRY_REPOSITORY": "clipforge-int",
        "CLOUD_RUN_SERVICE": delivery.SERVICE,
        "INT_MIGRATION_JOB": delivery.MIGRATION_JOB,
        "INT_BOOTSTRAP_JOB": delivery.BOOTSTRAP_JOB,
        "TF_STATE_BUCKET": "clipforgebeta2-tfstate-int",
        "TF_STATE_PREFIX": "terraform/int",
        "RUNNER_TEMP": str(Path(root).resolve()),
        "INT_HITO_A_SCRATCH": str(private.resolve()),
        "INT_RUNTIME_ARCHIVE": str(archive.resolve()),
        "EXPECTED_ARCHIVE_SHA256": hashlib.sha256(b"exact-archive").hexdigest(),
        "EXPECTED_ARCHIVE_SIZE": str(len(b"exact-archive")),
        "RUNTIME_IMAGE": IMAGE,
        "INT_HITO_A_API_RESULT": "success",
        "INT_HITO_A_SCANS_PASSED": "true",
    }


def runtime_plan(state, nonce, *, action="create"):
    common_env = {
        "CLIPFORGE_DATABASE_HOST": delivery.PRIVATE_IP,
        "CLIPFORGE_DATABASE_SSL_MODE": "verify-full",
        "CLIPFORGE_RUNTIME_PROFILE": "int-demo-a",
        "CLIPFORGE_REVISION": state["commit"],
        "CLIPFORGE_ACCEPTANCE_NONCE": nonce,
        "CLIPFORGE_AUTH_PROFILE": "https",
        "CLIPFORGE_ALLOW_INSECURE_HTTP": "0",
    }
    service = {
        "name": delivery.SERVICE, "project": delivery.PROJECT, "location": delivery.REGION,
        "deletion_protection": True, "iap_enabled": True, "invoker_iam_disabled": False,
        "template": [{
            "service_account": "clipforge-api-int@clipforgebeta2.iam.gserviceaccount.com",
            "scaling": [{"max_instance_count": 1, "min_instance_count": 0}],
            "containers": [{"image": state["image"], "command": ["python"],
                            "args": ["-m", "uvicorn", "app.int_demo:app"],
                            "env": [{"name": key, "value": value} for key, value in common_env.items()]}],
        }],
    }

    def job(name, args):
        return {"name": "clipforge-int-" + name, "deletion_protection": True,
                "template": [{"task_count": 1, "parallelism": 1, "template": [{
                    "max_retries": 0,
                    "service_account": "clipforge-migrate-int@clipforgebeta2.iam.gserviceaccount.com",
                    "containers": [{"image": state["image"], "command": ["python"], "args": args}],
                }]}]}

    values = {
        "google_cloud_run_v2_service.api[0]": service,
        'google_cloud_run_v2_job.task["migrate"]': job("migrate", ["-m", "app.cloud.migrate"]),
        'google_cloud_run_v2_job.task["bootstrap"]': job("bootstrap", ["-m", "app.cloud.bootstrap_admin"]),
        "google_iap_web_cloud_run_service_iam_member.pilot_admin[0]": {
            "member": "user:admin@ixbalam.studio", "role": "roles/iap.httpsResourceAccessor"},
        "google_iap_web_cloud_run_service_iam_member.deploy_acceptance[0]": {
            "member": "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com",
            "role": "roles/iap.httpsResourceAccessor"},
        "google_secret_manager_secret_iam_member.bootstrap_admin_human[0]": {
            "secret_id": "clipforge-int-bootstrap-admin",
            "member": "user:admin@ixbalam.studio",
            "role": "roles/secretmanager.secretAccessor"},
    }
    for address in delivery.REQUIRED_RUNTIME:
        values.setdefault(address, {})
    resources = [{"mode": "managed", "address": address, "values": value}
                 for address, value in values.items()]
    changes = [{"mode": "managed", "address": address,
                "change": {"actions": [action if address == "google_cloud_run_v2_service.api[0]" else "create"]}}
               for address in values]
    return {"terraform_version": delivery.TERRAFORM_VERSION, "format_version": "1.2",
            "complete": True, "applyable": True, "errored": False,
            "resource_changes": changes, "planned_values": {"root_module": {"resources": resources}}}


def prepare_acceptance_result(state):
    revision = "clipforge-int-api-00001"
    return {
        "schema": "clipforge-int-demo-a-acceptance-1",
        "operation": "prepare",
        "status": "prepared_for_revision_replacement",
        "stage": "complete",
        "controls_commit": state["commit"],
        "steps": [{"id": step, "status": "passed"} for step in (
            "cloud_ready_revision_digest_traffic", "https_iap_unauthorized_rejection",
            "frontend_health_environment_admin_login", "admin_create_list_and_secret_free_audit",
            "ordinary_rejections_and_logout",
        )],
        "service": {
            "uri": "https://clipforge-int-api-816643438938.us-central1.run.app",
            "revision": revision,
            "image": state["image"],
            "digest": state["manifest_digest"].removeprefix("sha256:"),
            "traffic": [{"revision": revision, "percent": 100}],
            "iap_enabled": True,
            "owner_member": "user:admin@ixbalam.studio",
        },
        "application": {"environment": "INT", "commit": state["commit"],
                        "health": "ok", "profile": "int-demo-a"},
        "iap": {"protected": True, "owner_member_verified": True},
        "audit_receipt": {"credentials_present": False},
        "persistence": {"prepared": True, "revision_replaced": False, "verified": False},
    }


def verify_acceptance_result(state):
    before = "clipforge-int-api-00001"
    revision = "clipforge-int-api-00002"
    value = prepare_acceptance_result(state)
    value.update({
        "operation": "verify",
        "status": "passed",
        "steps": [{"id": step, "status": "passed"} for step in (
            "replacement_revision_ready_digest_traffic", "https_iap_unauthorized_rejection",
            "persistent_account_login_and_rejections", "persistent_admin_list_and_secret_free_audit",
            "post_replacement_logout",
        )],
        "service": {**value["service"], "revision": revision,
                    "traffic": [{"revision": revision, "percent": 100}]},
        "account": {"id": "c" * 32, "created": True, "listed": True, "persisted": True},
        "persistence": {"prepared": True, "revision_replaced": True, "verified": True,
                        "before_revision": before, "after_revision": revision},
    })
    return value


def browser_acceptance_result(state, revision):
    return {
        "schema": "clipforge-int-hito-a-browser-acceptance-1",
        "operation": "post_replacement_browser",
        "status": "passed",
        "stage": "complete",
        "controls_commit": state["commit"],
        "origin": "https://clipforge-int-api-816643438938.us-central1.run.app",
        "revision": revision,
        "digest": state["manifest_digest"].removeprefix("sha256:"),
        "checks": [{"id": check, "status": "passed"} for check in (
            "private_persistence_state_bound", "pinned_playwright_preinstalled_browser",
            "iap_scoped_css_javascript_loaded", "admin_ui_login_users_audit_logout",
            "persistent_account_ui_login_logout", "zero_page_console_request_errors",
        )],
        "toolchain": {"playwright_version": "1.64.1", "browser_family": "chromium",
                      "preinstalled_browser": True},
        "assets": {"css": ["/static/account.css"],
                   "javascript": ["/static/account.js", "/static/auth.js"],
                   "contexts_verified": 2},
        "errors": {"page": 0, "console": 0, "request": 0, "observer": 0},
        "iap": {"bearer_scoped_to_origin": True, "external_requests": 0},
        "admin_ui": {"login": True, "users": True, "audit": True, "logout": True},
        "persistent_account_ui": {"login": True, "admin_panels_hidden": True, "logout": True},
        "persistence": {"revision_replaced": True, "account_verified": True},
        "credentials_present": False,
    }


class DeliveryContractTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="clipforge-hito-a-delivery-")
        self.env = environment(self.temporary.name)

    def tearDown(self):
        self.temporary.cleanup()

    def test_artifact_state_binds_api_gate_commit_archive_and_manifest(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            value = delivery.verify_artifact(self.env)
        self.assertEqual(value["phase"], "artifact_verified")
        self.assertEqual(value["manifest_digest"], DIGEST)
        state = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) / "delivery-state.json").read_text())
        self.assertTrue(state["runtime_scans_passed"])
        for changed in ("INT_HITO_A_API_RESULT", "INT_HITO_A_SCANS_PASSED", "EXPECTED_ARCHIVE_SHA256"):
            altered = dict(self.env)
            altered[changed] = "blocked"
            with self.subTest(changed=changed), self.assertRaises(delivery.DeliveryBlocked):
                with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
                    delivery.verify_artifact(altered)

    def test_artifact_gate_binds_all_oidc_and_cloud_targets_before_wif(self):
        for changed in ("GCP_WIF_PROVIDER", "GCP_TERRAFORM_SA", "GCP_DEPLOY_SA",
                        "ARTIFACT_REGISTRY_REPOSITORY", "CLOUD_RUN_SERVICE",
                        "INT_MIGRATION_JOB", "INT_BOOTSTRAP_JOB", "TF_STATE_BUCKET",
                        "TF_STATE_PREFIX"):
            altered = dict(self.env)
            altered[changed] = "unreviewed"
            with self.subTest(changed=changed), self.assertRaisesRegex(
                    delivery.DeliveryBlocked, "protected_deploy_context"):
                delivery.verify_artifact(altered)

    def test_hito_a_mutation_gate_uses_only_its_exact_api_job_result(self):
        exact = dict(self.env)
        exact.update({
            "GITHUB_WORKFLOW_REF":
                "AldemaroCruz/ClipForge/.github/workflows/int-hito-a.yml@refs/heads/ci/bootstrap-sec03",
            "GITHUB_JOB": "deploy",
        })
        int_release.require_application_ci(exact, delivery="int-hito-a")
        for key, bad in (("GITHUB_JOB", "api"),
                         ("INT_HITO_A_API_RESULT", "failure"),
                         ("INT_HITO_A_SCANS_PASSED", "false")):
            changed = dict(exact)
            changed[key] = bad
            with self.subTest(key=key), self.assertRaises(ValueError):
                int_release.require_application_ci(changed, delivery="int-hito-a")

    def test_cloud_preflight_precedes_every_mutation(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            delivery.verify_artifact(self.env)
        with mock.patch.object(delivery, "_require_delivery_iam_permissions") as check:
            state = delivery.preflight(self.env)
        check.assert_called_once_with(self.env)
        self.assertEqual(state["phase"], "cloud_preflighted")
        self.assertTrue(state["bootstrap_access_grant_permission"])
        self.assertTrue(state["iap_policy_permissions"])

    def test_cloud_preflight_reports_all_missing_policy_authority_at_once(self):
        with mock.patch.object(delivery, "_require_bootstrap_access_grant_permission",
                               side_effect=delivery.DeliveryBlocked("secret")), \
                mock.patch.object(delivery, "_require_iap_policy_permissions",
                                  side_effect=delivery.DeliveryBlocked("iap")), \
                self.assertRaisesRegex(delivery.DeliveryBlocked,
                                       "terraform_delivery_iam_permissions_missing"):
            delivery._require_delivery_iam_permissions(self.env)

    def test_cloud_preflight_reports_each_missing_policy_authority(self):
        cases = (
            ("_require_bootstrap_access_grant_permission",
             "terraform_cannot_grant_bootstrap_credential_access"),
            ("_require_iap_policy_permissions", "terraform_cannot_manage_iap_policy"),
        )
        for blocked, code in cases:
            allowed = ("_require_iap_policy_permissions"
                       if blocked == "_require_bootstrap_access_grant_permission"
                       else "_require_bootstrap_access_grant_permission")
            with self.subTest(blocked=blocked), \
                    mock.patch.object(delivery, blocked,
                                      side_effect=delivery.DeliveryBlocked("denied")), \
                    mock.patch.object(delivery, allowed), \
                    self.assertRaisesRegex(delivery.DeliveryBlocked, code):
                delivery._require_delivery_iam_permissions(self.env)

    def test_noble_host_pin_is_rebuilt_from_the_exact_serial_record(self):
        record = {"public_key": "ssh-ed25519 fixture-public-key",
                  "guest_boot_id": "e1a4fb53-1970-490b-af37-5cccbbc99f32"}
        with mock.patch.object(delivery, "_gcloud_json", return_value={"start": "0", "next": "1"}), \
                mock.patch.object(delivery.noble_hostkey, "serial_record", return_value=record) as parser:
            path, actual = delivery._noble_host_pin(self.env)
        self.assertEqual(actual, record)
        self.assertEqual(path.read_text(encoding="ascii"),
                         delivery.INSTANCE + "." + delivery.INSTANCE_ID + " " +
                         record["public_key"] + "\n")
        parser.assert_called_once_with(
            {"start": "0", "next": "1"}, instance_id=delivery.INSTANCE_ID,
            nonce=delivery.NOBLE_HOST_RECORD_NONCE,
            publisher_sha256=delivery.NOBLE_HOST_RECORD_PUBLISHER_SHA256,
        )

    def test_noble_ssh_requires_the_published_ed25519_pin_and_private_key(self):
        known = Path(self.env["INT_HITO_A_SCRATCH"]) / "known-hosts.fixture"
        known.write_text("fixture\n", encoding="ascii")
        record = {"guest_boot_id": "e1a4fb53-1970-490b-af37-5cccbbc99f32"}
        captured = {}

        def invoke(command, **kwargs):
            captured.update(command=command, kwargs=kwargs)
            return b'{"schema":"fixture"}\n'

        with mock.patch.object(delivery, "_noble_host_pin", return_value=(known, record)), \
                mock.patch.object(delivery, "_gcloud_binary", return_value="/usr/bin/gcloud"), \
                mock.patch.object(delivery, "_run", side_effect=invoke):
            receipt, actual_record = delivery._ssh_public(b"print('fixture')\n", self.env)
        self.assertEqual(receipt, {"schema": "fixture"})
        self.assertEqual(actual_record, record)
        command = captured["command"]
        for option in (
            "--tunnel-through-iap", "--ssh-key-expire-after=10m",
            "--ssh-flag=-o=StrictHostKeyChecking=yes",
            "--ssh-flag=-o=GlobalKnownHostsFile=/dev/null",
            "--ssh-flag=-o=HostKeyAlgorithms=ssh-ed25519",
            "--ssh-flag=-o=UpdateHostKeys=no", "--ssh-flag=-o=BatchMode=yes",
            "--ssh-flag=-o=PasswordAuthentication=no",
        ):
            self.assertIn(option, command)
        self.assertIn("--ssh-flag=-o=UserKnownHostsFile=" + str(known), command)
        self.assertIn("--ssh-flag=-o=HostKeyAlias=" + delivery.INSTANCE + "." +
                      delivery.INSTANCE_ID, command)
        self.assertTrue(any(item.startswith("--ssh-key-file=") for item in command))

    def test_plan_allows_only_one_service_two_jobs_and_safe_revision_update(self):
        state = {"commit": COMMIT, "image": IMAGE}
        nonce = "prepare-123-1"
        created = runtime_plan(state, nonce)
        summary = delivery._verify_plan(created, state, nonce)
        self.assertEqual(set(summary["actions"]), delivery.ALLOWED_CREATES)
        replacement = runtime_plan(state, "verify-123-1", action="update")
        for row in replacement["resource_changes"]:
            if row["address"] != "google_cloud_run_v2_service.api[0]":
                row["change"]["actions"] = ["no-op"]
        summary = delivery._verify_plan(replacement, state, "verify-123-1")
        self.assertEqual(summary["actions"], {"google_cloud_run_v2_service.api[0]": "update"})
        destructive = deepcopy(replacement)
        destructive["resource_changes"][0]["change"]["actions"] = ["delete", "create"]
        with self.assertRaises(delivery.DeliveryBlocked):
            delivery._verify_plan(destructive, state, "verify-123-1")

    def test_acceptance_private_state_is_not_copied_to_public_receipt(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            state = delivery.verify_artifact(self.env)
        state.update(phase="migrated", secret_versions={"app_password": "1", "migrator_password": "2",
                     "postgres_ca": "3", "bootstrap_admin": "4"})
        delivery.save_state(self.env, state)
        self.env.update(INT_HITO_A_ACCEPTANCE_PHASE="prepare", GCP_ACCESS_TOKEN="g" * 40,
                        INT_IAP_ACCESS_TOKEN="i" * 40,
                        INT_BOOTSTRAP_ADMIN='{"username":"admin","password":"authored-test-password"}')
        result = prepare_acceptance_result(state)
        with mock.patch("scripts.int_hito_a_acceptance.run", return_value=result):
            accepted = delivery.accept(self.env)
        self.assertEqual(accepted["phase"], "acceptance_prepared")
        receipt = (Path(self.env["INT_HITO_A_SCRATCH"]) / "delivery-receipt.json").read_text()
        self.assertNotIn("authored-test-password", receipt)
        self.assertNotIn("acceptance-private.json", receipt)

    def test_incomplete_acceptance_is_blocked_but_its_sanitized_report_is_retained(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            state = delivery.verify_artifact(self.env)
        state.update(phase="migrated")
        delivery.save_state(self.env, state)
        self.env.update(INT_HITO_A_ACCEPTANCE_PHASE="prepare", GCP_ACCESS_TOKEN="g" * 40,
                        INT_IAP_ACCESS_TOKEN="i" * 40,
                        INT_BOOTSTRAP_ADMIN='{"username":"admin","password":"authored-test-password"}')
        result = {"schema": "clipforge-int-demo-a-acceptance-1", "operation": "prepare",
                  "status": "blocked", "stage": "cloud_identity", "controls_commit": COMMIT}
        with mock.patch("scripts.int_hito_a_acceptance.run", return_value=result), \
                self.assertRaises(delivery.DeliveryBlocked):
            delivery.accept(self.env)
        retained = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) / "api-demo-prepare.json").read_text())
        self.assertEqual(retained, result)

    def test_verify_requires_real_browser_receipt_and_binds_it_to_public_delivery_receipt(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            state = delivery.verify_artifact(self.env)
        state.update(phase="replaced")
        delivery.save_state(self.env, state)
        self.env.update(INT_HITO_A_ACCEPTANCE_PHASE="verify", GCP_ACCESS_TOKEN="g" * 40,
                        INT_IAP_ACCESS_TOKEN="i" * 40,
                        INT_BOOTSTRAP_ADMIN='{"username":"admin","password":"authored-test-password"}')
        api = verify_acceptance_result(state)
        browser = browser_acceptance_result(state, api["service"]["revision"])
        with mock.patch("scripts.int_hito_a_acceptance.run", return_value=api), \
                mock.patch("scripts.int_hito_a_browser.run", return_value=browser) as browser_run:
            accepted = delivery.accept(self.env)
        self.assertEqual(accepted["phase"], "accepted")
        self.assertEqual(accepted["browser_acceptance"], browser)
        browser_run.assert_called_once()
        receipt = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) / "delivery-receipt.json").read_text())
        self.assertEqual(receipt["browser_acceptance"], browser)

    def test_blocked_browser_receipt_is_retained_and_prevents_acceptance(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            state = delivery.verify_artifact(self.env)
        state.update(phase="replaced")
        delivery.save_state(self.env, state)
        self.env.update(INT_HITO_A_ACCEPTANCE_PHASE="verify", GCP_ACCESS_TOKEN="g" * 40,
                        INT_IAP_ACCESS_TOKEN="i" * 40,
                        INT_BOOTSTRAP_ADMIN='{"username":"admin","password":"authored-test-password"}')
        api = verify_acceptance_result(state)
        blocked = {"schema": "clipforge-int-hito-a-browser-acceptance-1",
                   "operation": "post_replacement_browser", "status": "blocked",
                   "stage": "browser_acceptance", "controls_commit": COMMIT}
        with mock.patch("scripts.int_hito_a_acceptance.run", return_value=api), \
                mock.patch("scripts.int_hito_a_browser.run", return_value=blocked), \
                self.assertRaises(delivery.DeliveryBlocked):
            delivery.accept(self.env)
        retained = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) / "api-demo-browser.json").read_text())
        self.assertEqual(retained, blocked)
        state_after = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) / "delivery-state.json").read_text())
        self.assertEqual(state_after["phase"], "replaced")

    def test_rollback_before_replacement_apply_is_an_explicit_noop(self):
        with mock.patch.object(delivery.int_release_image, "archive_digest", return_value=DIGEST):
            state = delivery.verify_artifact(self.env)
        state.update(phase="acceptance_prepared", acceptance_prepare=prepare_acceptance_result(state))
        delivery.save_state(self.env, state)
        with mock.patch.object(delivery, "_run") as command:
            rolled_back = delivery.rollback(self.env)
        command.assert_not_called()
        self.assertEqual(rolled_back["phase"], "rolled_back")
        self.assertEqual(rolled_back["rollback"], {
            "status": "not_required", "revision": "clipforge-int-api-00001", "traffic_percent": 100,
        })

    def test_entrypoint_retains_a_fixed_secret_free_failure_code(self):
        with mock.patch.dict(os.environ, self.env, clear=True), \
                mock.patch.object(delivery, "preflight",
                                  side_effect=delivery.DeliveryBlocked(
                                      "terraform_cannot_grant_bootstrap_credential_access")):
            self.assertEqual(delivery.main(["preflight"]), 1)
        failure = json.loads((Path(self.env["INT_HITO_A_SCRATCH"]) /
                              "delivery-failure-preflight.json").read_text())
        self.assertEqual(failure, {
            "schema": "clipforge-int-hito-a-delivery-failure-1",
            "status": "blocked",
            "operation": "preflight",
            "failed_check": "terraform_cannot_grant_bootstrap_credential_access",
            "commit": COMMIT,
            "image": IMAGE,
        })


if __name__ == "__main__":
    unittest.main()
