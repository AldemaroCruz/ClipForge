import copy
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

    def test_network_uses_existing_subnet_and_nat_and_rejects_occupied_or_partial(self):
        subnet = {"name": "clipforge-int-base-postgres", "ipCidrRange": "10.80.1.0/28",
                  "network": plan.API + plan.PROJECT_ROOT + plan.NETWORK, "privateIpGoogleAccess": True,
                  "stackType": "IPV4_ONLY"}
        router = {"network": subnet["network"], "nats": [
            {"name": "clipforge-int-base-maintenance", "natIpAllocateOption": "AUTO_ONLY",
             "sourceSubnetworkIpRangesToNat": "LIST_OF_SUBNETWORKS",
             "subnetworks": [{"name": plan.API + plan.PROJECT_ROOT + plan.SUBNET,
                             "sourceIpRangesToNat": ["PRIMARY_IP_RANGE"]}]}]}
        with patch.object(plan, "compute_get", side_effect=[subnet, router, {}, {}]):
            self.assertTrue(plan.preflight_network()["observed_available"])
        for reservation, instances in (({"items": [{"address": plan.ADDRESS}]}, {}),
                                       ({}, {"nextPageToken": "more"}),
                                       ({}, {"items": {"zones/x": {"instances": [{"name": "in-use"}]}}})):
            with patch.object(plan, "compute_get", side_effect=[subnet, router, reservation, instances]), self.assertRaises(ValueError):
                plan.preflight_network()
