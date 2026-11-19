import copy
import json
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import patch

from scripts import db01_noble_plan as plan


def candidate_image():
    name = "ubuntu-2404-noble-amd64-v20261114"
    return {"name": name, "id": "123", "status": "READY", "architecture": "X86_64", "family": plan.FAMILY,
            "selfLink": plan.API + plan.IMAGE_ROOT + "/images/" + name,
            "creationTimestamp": "2026-11-14T10:00:00Z", "diskSizeGb": "10",
            "licenses": [plan.API + plan.IMAGE_ROOT + "/licenses/ubuntu-2404-lts"]}


def actions():
    return {"complete": True, "applyable": True, "errored": False, "resource_changes": [
        {"address": address, "mode": "managed", "change": {"actions": [effect]}}
        for addresses, effect in ((plan.EXISTING, "no-op"), (plan.CREATES, "create"))
        for address in sorted(addresses)
    ]}


def network_responses():
    subnet = {"name": "clipforge-int-base-postgres", "ipCidrRange": "10.80.1.0/28",
              "network": plan.API + plan.PROJECT_ROOT + plan.NETWORK, "privateIpGoogleAccess": True,
              "stackType": "IPV4_ONLY"}
    router = {"network": subnet["network"], "nats": [
        {"name": "clipforge-int-base-maintenance", "natIpAllocateOption": "AUTO_ONLY",
         "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS",
         "subnetworks": [{"name": plan.API + plan.PROJECT_ROOT + plan.SUBNET,
                         "sourceIpRangesToNat": ["PRIMARY_IP_RANGE"]}]}]}
    return subnet, router


LOG_BUCKET = "projects/clipforgebeta2/locations/us-central1/buckets/clipforge-int-access"
POSTGRES_CA = "projects/clipforgebeta2/secrets/clipforge-int-postgres-ca"
BOOTSTRAP_ADMIN = "projects/clipforgebeta2/secrets/clipforge-int-bootstrap-admin"
IAP_INSTANCE = "projects/816643438938/iap_tunnel/zones/us-central1-a/instances/1670495097211408131"
NATIVE_REFRESH = "\n".join((
    "terraform_data.boundary: Refreshing state... [id=00000001-1111-b403-2222-333333333333]",
    "hash prefix aaa403aaa, storage.googleapis.com, roles/storage.objectUser",
    "google_project_iam_custom_role.bootstrap_reader: Refreshing state... [id=iam.roles.get]",
    "google_service_account_iam_member.protected_bootstrap: Refreshing state... [id=iam.serviceAccounts.getIamPolicy]",
    f"│ Error: Error when reading or editing Logging Bucket Config {LOG_BUCKET}: googleapi: Error 403: "
    f"Permission 'logging.buckets.get' denied on resource '//logging.googleapis.com/{LOG_BUCKET}' (or it may not exist).",
    '  "reason": "IAM_PERMISSION_DENIED"',
    f'Error: Error when reading or editing SecretManagerSecret "{POSTGRES_CA}": googleapi: Error 403: '
    "Permission 'secretmanager.secrets.get' denied on resource (or it may not exist). "
    "Troubleshooter URL https://console.cloud.google.com/iam-admin/troubleshooter/summary;errorId=SYNTHETIC_ID",
    '  "reason": "IAM_PERMISSION_DENIED"',
    f'Error: Error when reading or editing SecretManagerSecret "{BOOTSTRAP_ADMIN}": googleapi: Error 403: '
    "Permission 'secretmanager.secrets.get' denied on resource (or it may not exist).",
    f'Error: Error when reading or editing Resource "iap tunnelinstance \\"{IAP_INSTANCE}\\"" '
    f'with IAM Member: Role "roles/iap.tunnelResourceAccessor": Error retrieving IAM policy for iap tunnelinstance "{IAP_INSTANCE}": '
    "googleapi: Error 403: Permission 'iap.tunnelInstances.getIamPolicy' denied on resource "
    "'//iap.googleapis.com/projects/816643438938/iap_tunnel/zones/us-central1-a/insta",
))


def network_instance(*, address="10.80.1.2", alias=None):
    interface = {"networkIP": address}
    if alias is not None:
        interface["aliasIpRanges"] = [{"ipCidrRange": alias}]
    return {"networkInterfaces": [interface]}


def report_fixture(status):
    return {"schema": "clipforge-db01-noble-plan-summary-1", "status": status, "apply_authorized": False,
            "checks": {key: "passed" for key in ("fmt", "validate_init", "validate", "noble_native_mock", "noble_iac_security")}}


def backend_fixture():
    return {**plan.foundation.STATE_PIN, "managed_addresses": sorted(plan.EXISTING), "current_lock_absent": True}


def planned_report():
    prefix = plan.custody.PREFIX + "1" * 40 + "/12345-1/"
    references = {
        kind: {"name": prefix + filename, "generation": str(index), "sha256": str(index) * 64, "size": 64}
        for index, (kind, filename) in enumerate(
            (("binary", "int.tfplan"), ("json", "int.json"), ("manifest", "manifest.json")), start=1
        )
    }
    report = report_fixture("planned")
    report.update(image=candidate_image(), backend=backend_fixture(),
                  network={"subnet": plan.SUBNET, "nat": "clipforge-int-base-maintenance",
                           "private_ip": plan.ADDRESS, "observed_available": True},
                  actions=plan.action_summary(actions()), plan_exit_code=2,
                  private_plan={"bucket": plan.contract.BUCKET, **references, "expires_utc": "2026-11-20T18:00:00+00:00"})
    return report


class NoblePlanTests(unittest.TestCase):
    def test_receipt_binds_exact_public_standard_image(self):
        image = candidate_image()
        with patch.object(plan, "compute_get", side_effect=[image, image]) as get:
            self.assertEqual(plan.resolve_image(), image)
            self.assertEqual(get.call_args_list[0].args[0], plan.IMAGE_ROOT + "/images/family/" + plan.FAMILY)
            self.assertEqual(get.call_args_list[1].args[0], plan.IMAGE_ROOT + "/images/" + image["name"])
        for changed in (dict(architecture="ARM64"), dict(status="PENDING"), dict(id="0"),
                        dict(deprecated={"state": "DEPRECATED"}), dict(diskSizeGb="20"),
                        dict(licenses=[plan.API + plan.IMAGE_ROOT + "/licenses/ubuntu-2404-pro"])):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                plan.image_identity({**image, **changed})
        with patch.object(plan, "compute_get", side_effect=[image, {**image, "id": "124"}]), self.assertRaises(ValueError):
            plan.resolve_image()

    def test_only_expected_managed_actions(self):
        native = actions()
        receipt = plan.action_summary(native)
        self.assertEqual(receipt["counts"], {"no-op": 42, "create": 11})
        self.assertEqual(receipt["deviations"], {})
        modified = next(row for row in native["resource_changes"] if row["address"] == "google_compute_instance.postgres")
        modified["change"]["actions"] = ["delete", "create"]
        receipt = plan.action_summary(native)
        self.assertEqual(receipt["deviations"], {"google_compute_instance.postgres": ["delete", "create"]})

    def test_blocks_unknown_moves_imports_deferred_and_duplicates(self):
        clean = actions()
        for changed in (dict(deferred_changes=[{}]), dict(errored=True), dict(complete=False)):
            with self.subTest(changed=changed), self.assertRaises(ValueError):
                plan.action_summary({**clean, **changed})
        for field in ("importing", "deposed", "previous_address"):
            native = copy.deepcopy(clean)
            native["resource_changes"][0][field] = "unexpected"
            with self.subTest(field=field), self.assertRaises(ValueError):
                plan.action_summary(native)
        native = copy.deepcopy(clean)
        native["resource_changes"].append(native["resource_changes"][0].copy())
        with self.assertRaises(ValueError):
            plan.action_summary(native)

    def test_network_reads_all_instance_pages_with_supported_query(self):
        subnet, router = network_responses()
        first = {"nextPageToken": "second-page", "items": {"zones/us-central1-a": {"instances": [network_instance()]}}}
        second = {"items": {"zones/us-central1-b": {"warning": {"code": "NO_RESULTS_ON_PAGE"}}}}
        with patch.object(plan, "compute_get", side_effect=[subnet, router, {}, first, second]) as get:
            result = plan.preflight_network()
        self.assertTrue(result["observed_available"])
        self.assertEqual(result["private_ip"], plan.ADDRESS)
        reads = [call for call in get.call_args_list if call.args[0] == plan.PROJECT_ROOT + "aggregated/instances"]
        self.assertEqual(len(reads), 2)
        self.assertNotIn("filter", reads[0].kwargs)
        self.assertNotIn("filter", reads[1].kwargs)
        self.assertNotIn("pageToken", reads[0].kwargs)
        self.assertEqual(reads[1].kwargs["pageToken"], "second-page")

    def test_network_blocks_an_address_found_on_a_later_instance_page(self):
        subnet, router = network_responses()
        first = {"nextPageToken": "occupied-page", "items": {"zones/us-central1-a": {"instances": [network_instance()]}}}
        for conflict in (network_instance(address=plan.ADDRESS), network_instance(alias=f"{plan.ADDRESS}/32")):
            second = {"items": {"zones/us-central1-b": {"instances": [conflict]}}}
            with self.subTest(conflict=conflict), patch.object(plan, "compute_get", side_effect=[subnet, router, {}, first, second]), self.assertRaises(ValueError):
                plan.preflight_network()

    def test_network_rejects_reserved_address_or_incomplete_instance_list(self):
        subnet, router = network_responses()
        zone = {"zones/us-central1-a": {"instances": [network_instance()]}}
        cases = {
            "reserved": [{"items": [{"address": plan.ADDRESS}]}, {"items": zone}],
            "unreachable": [{}, {"unreachables": ["zones/us-central1-a"], "items": zone}],
            "malformed_unreachables": [{}, {"unreachables": None, "items": zone}],
            "partial_warning": [{}, {"items": {"zones/us-central1-a": {"warning": {"code": "UNREACHABLE"}}}}],
            "missing_interfaces": [{}, {"items": {"zones/us-central1-a": {"instances": [{"name": "unknown"}]}}}],
            "no_instance_coverage": [{}, {}],
            "malformed_page": [{}, []],
            "malformed_cursor": [{}, {"nextPageToken": [], "items": zone}],
            "repeated_page": [{}, {"nextPageToken": "repeat", "items": zone}, {"nextPageToken": "repeat", "items": zone}],
        }
        for name, remaining in cases.items():
            with self.subTest(name=name), patch.object(plan, "compute_get", side_effect=[subnet, router, *remaining]), self.assertRaises(ValueError):
                plan.preflight_network()

    def test_network_pagination_hard_bound_blocks_without_partial_success(self):
        subnet, router = network_responses()
        zone = {"zones/us-central1-a": {"instances": [network_instance()]}}
        pages = [{"nextPageToken": f"next-{index}", "items": zone} for index in range(10)]
        with patch.object(plan, "compute_get", side_effect=[subnet, router, {}, *pages]) as get:
            with self.assertRaisesRegex(plan.Blocked, "candidate_ip_pagination_bound"):
                plan.preflight_network()
        self.assertEqual(get.call_count, 13)


class NobleNativeDiagnosticTests(unittest.TestCase):
    def test_native_refresh_receipt_binds_the_four_observed_denials(self):
        output = NATIVE_REFRESH + "\n" + NATIVE_REFRESH.splitlines()[6]
        receipt = plan.native_diagnostic.classify_native_errors(output)
        self.assertEqual(receipt["denials"], [
            {"permission": permission, "resource": resource, "http_status": 403}
            for permission, resource in (
                ("iap.tunnelInstances.getIamPolicy", IAP_INSTANCE),
                ("logging.buckets.get", LOG_BUCKET),
                ("secretmanager.secrets.get", BOOTSTRAP_ADMIN),
                ("secretmanager.secrets.get", POSTGRES_CA),
            )
        ])
        self.assertEqual(receipt["role_references"], ["roles/iap.tunnelResourceAccessor"])
        self.assertEqual(receipt["domain_references"], ["iap.googleapis.com", "logging.googleapis.com"])
        self.assertEqual(receipt["unbound_permissions"], [])
        self.assertEqual(receipt["unclassified_http_403_errors"], 0)
        encoded = json.dumps(receipt)
        for unrelated in ("iam.roles.get", "iam.serviceAccounts.getIamPolicy", "SYNTHETIC_ID",
                          "storage.objectUser", "aaa403aaa", "00000001-1111-b403"):
            self.assertNotIn(unrelated, encoded)

    def test_permission_and_target_must_belong_to_the_same_error(self):
        confirmed = "projects/clipforgebeta2/roles/clipforgeIntBootstrapReader"
        receipt = plan.native_diagnostic.classify_native_errors("\n".join((
            f'Error: Cloud error for "{LOG_BUCKET}": googleapi: Error 403: forbidden.',
            f"Error: googleapi: Error 403: Required 'iam.roles.get' permission for '{confirmed}'.",
            f"Error: Cloud error for '{POSTGRES_CA}': googleapi: Error 403: "
            "Permission 'secretmanager.secrets.get' denied on resource 'projects/foreign/secrets/foreign'.",
            "Error: can't refresh due to hash a403b; another error mentions iam.serviceAccounts.getIamPolicy.",
        )))
        self.assertEqual(receipt["denials"], [
            {"permission": "iam.roles.get", "resource": confirmed, "http_status": 403},
        ])
        self.assertEqual(receipt["unbound_permissions"], ["secretmanager.secrets.get"])
        self.assertEqual(receipt["unclassified_http_403_errors"], 1)

    def test_native_byte_and_result_bounds_are_reported(self):
        operation = "noble_native_plan"
        with TemporaryDirectory() as temporary:
            scratch = Path(temporary)
            payload = NATIVE_REFRESH.encode()
            (scratch / (operation + ".log")).write_bytes(b"!" * 1024 + b"\n" + payload)
            with (
                patch.object(plan.native_diagnostic, "MAX_NATIVE_BYTES", len(payload) + 128),
                patch.object(plan.native_diagnostic, "MAX_RECEIPT_ROWS", 1),
            ):
                receipt = plan.native_diagnostic.operation_receipt(scratch, {"operation": operation, "status": 1})
        self.assertTrue(receipt["limits"]["native_tail_truncated"])
        self.assertEqual(receipt["limits"]["native_tail_bytes"], len(payload) + 128)
        self.assertEqual(receipt["limits"]["truncated_lists"], ["denials", "domain_references"])
        self.assertEqual(len(receipt["denials"]), 1)
        self.assertEqual(receipt["operation"], operation)
        self.assertEqual(receipt["status"], 1)

    def test_primary_operation_is_preserved_if_native_log_is_unavailable(self):
        operation = "noble_native_plan"
        with TemporaryDirectory() as temporary:
            receipt = plan.native_diagnostic.operation_receipt(Path(temporary), {
                "operation": operation, "status": 1, "permissions": ["iam.roles.get"], "messages": ["raw"],
            })
        self.assertEqual(receipt, {"operation": operation, "status": 1,
                                   "extraction_error": {"error_type": "FileNotFoundError"}})


class NobleSummaryTests(unittest.TestCase):
    def setUp(self):
        temporary = TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.reports = Path(temporary.name)
        self.step_summary = self.reports / "step-summary.md"
        environment = patch.dict(os.environ, {"GITHUB_STEP_SUMMARY": str(self.step_summary)})
        environment.start()
        self.addCleanup(environment.stop)

    def saved_json(self):
        return json.loads((self.reports / "summary.json").read_text(encoding="utf-8"))

    def saved_markdown(self):
        return (self.reports / "summary.md").read_text(encoding="utf-8")

    def test_checks_passed_preserves_both_reports_without_backend(self):
        report = report_fixture("checks_passed")
        self.assertEqual(plan.save_summary(self.reports, report), 0)

        self.assertEqual(self.saved_json(), report)
        self.assertIn("checks_passed", self.saved_markdown())
        self.assertIn("noble_native_mock", self.saved_markdown())
        self.assertIn("checks_passed", self.step_summary.read_text(encoding="utf-8"))

    def test_blocked_http_result_keeps_backend_receipt_and_original_diagnostic(self):
        report = report_fixture("blocked")
        report.update(image=candidate_image(), backend=backend_fixture(),
                      diagnostic={"operation": "check_candidate_ip_in_use", "http_status": 400})
        expected = copy.deepcopy(report)

        self.assertEqual(plan.save_summary(self.reports, report), 1)

        self.assertEqual(self.saved_json(), expected)
        markdown = self.saved_markdown()
        self.assertIn("blocked", markdown)
        self.assertIn(expected["backend"]["name"], markdown)
        self.assertIn(expected["diagnostic"]["operation"], markdown)
        self.assertIn("400", markdown)
        self.assertNotIn('"bucket":', markdown.lower())
        self.assertNotIn("jobs", markdown.lower())

    def test_complete_native_plan_reports_exact_actions_and_custody_references(self):
        report = planned_report()
        self.assertEqual(plan.save_summary(self.reports, report), 0)
        result = self.saved_json()
        self.assertEqual(result, report)
        self.assertFalse(result["apply_authorized"])
        self.assertEqual(result["plan_exit_code"], 2)
        self.assertEqual(result["actions"]["counts"], {"no-op": 42, "create": 11})
        markdown = self.saved_markdown()
        self.assertIn("planned", markdown)
        self.assertIn("no-op", markdown)
        for kind in ("binary", "json", "manifest"):
            self.assertIn(report["private_plan"][kind]["name"], markdown)

    def test_incomplete_plan_cannot_report_planning_success(self):
        for changed in ("bad_exit", "missing_actions", "wrong_addresses", "drift", "missing_custody", "incomplete_reference"):
            report = planned_report()
            if changed == "bad_exit":
                report["plan_exit_code"] = 0
            elif changed == "missing_actions":
                del report["actions"]
            elif changed == "wrong_addresses":
                report["actions"]["preserved_addresses"][0] = "google_compute_instance.unreviewed"
            elif changed == "drift":
                report["actions"]["refresh_drift"] = {"google_compute_instance.postgres": ["update"]}
            elif changed == "missing_custody":
                del report["private_plan"]["manifest"]
            else:
                del report["private_plan"]["binary"]["sha256"]
            with self.subTest(changed=changed):
                self.assertEqual(plan.save_summary(self.reports, report), 1)
                self.assertEqual(self.saved_json()["status"], "blocked")
                self.assertNotIn("Status: planned", self.saved_markdown())

    def test_rendering_error_is_secondary_and_original_json_is_kept(self):
        report = report_fixture("blocked")
        report["diagnostic"] = {"operation": "check_candidate_ip_in_use", "http_status": 400}
        expected_diagnostic = dict(report["diagnostic"])
        with patch.object(plan, "render_summary", side_effect=KeyError("PRIVATE-EXCEPTION-TEXT")):
            self.assertEqual(plan.save_summary(self.reports, report), 1)
        saved = self.saved_json()
        self.assertEqual(saved["status"], "blocked")
        self.assertEqual(saved["diagnostic"], expected_diagnostic)
        self.assertEqual(saved["summary_error"], {"operation": "render_summary", "error_type": "KeyError"})
        self.assertNotIn("PRIVATE-EXCEPTION-TEXT", json.dumps(saved))

    def test_partial_and_incompatible_backends_remain_blocked(self):
        diagnostic = {"operation": "read_backend", "http_status": 503}
        partial = {"generation": "1795030868572779"}
        report = report_fixture("blocked")
        report.update(backend=partial, diagnostic=diagnostic)
        self.assertEqual(plan.save_summary(self.reports, report), 1)
        self.assertEqual(self.saved_json()["backend"], partial)
        self.assertIn(partial["generation"], self.saved_markdown())
        self.assertNotIn('"serial":', self.saved_markdown())
        self.assertNotIn("Status: planned", self.saved_markdown())

        report["backend"] = {"classification": "legacy"}
        self.assertEqual(plan.save_summary(self.reports, report), 1)
        self.assertEqual(self.saved_json()["diagnostic"], diagnostic)
        self.assertEqual(self.saved_json()["summary_error"]["operation"], "render_summary")
        self.assertNotIn("legacy", self.saved_markdown())
        self.assertNotIn("Status: planned", self.saved_markdown())

    def test_native_diagnostic_survives_a_summary_format_error(self):
        operation = "noble_native_plan"
        path = self.reports / "summary.json"
        path.write_text(json.dumps(report_fixture("checks_passed")), encoding="utf-8")
        (self.reports / (operation + ".log")).write_text(NATIVE_REFRESH, encoding="utf-8")
        commit = "1" * 40
        old_failure = plan.driver.FailedOperation(operation, NATIVE_REFRESH, 1)
        with (
            patch.dict(os.environ, {"GITHUB_SHA": commit, "DB01_NOBLE_APPROVED_COMMIT": commit}),
            patch.object(plan.driver, "private_paths", return_value=(self.reports, self.reports)),
            patch.object(plan.os, "umask"),
            patch.object(plan.contract, "validate_variables"),
            patch.object(plan, "real_plan", side_effect=old_failure),
            patch.object(plan, "render_summary", side_effect=ValueError("private formatter message")),
        ):
            self.assertEqual(plan.main(["plan"]), 1)
        report = self.saved_json()
        self.assertEqual(report["diagnostic"]["operation"], operation)
        self.assertEqual(report["diagnostic"]["status"], 1)
        self.assertEqual(len(report["diagnostic"]["denials"]), 4)
        self.assertEqual(report["summary_error"]["operation"], "render_summary")
        self.assertIn("iap.tunnelInstances.getIamPolicy", self.saved_markdown())
        self.assertNotIn("SYNTHETIC_ID", self.saved_markdown())

    def test_main_saves_blocked_summary_before_backend_access(self):
        path = self.reports / "summary.json"
        incompatible = {**report_fixture("checks_passed"), "schema": "old-frozen-summary"}
        for content, error_type in ((None, "FileNotFoundError"), ("{", "JSONDecodeError"), (json.dumps(incompatible), "ValueError")):
            path.unlink(missing_ok=True)
            if content is not None:
                path.write_text(content, encoding="utf-8")
            with (
                self.subTest(error_type=error_type),
                patch.object(plan.driver, "private_paths", return_value=(self.reports, self.reports)),
                patch.object(plan.os, "umask"),
                patch.object(plan, "real_plan") as native,
            ):
                self.assertEqual(plan.main(["plan"]), 1)
                native.assert_not_called()
                self.assertEqual(self.saved_json()["diagnostic"], {"operation": "plan", "error_type": error_type})
                self.assertEqual(self.saved_json()["status"], "blocked")
                self.assertNotIn("backend", self.saved_json())
                self.assertIn(error_type, self.saved_markdown())
