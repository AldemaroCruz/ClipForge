"""Validate the three exact reviewed Noble IAM policy transitions and live policies."""

import re

from scripts import int_db01_noble_read_iam as iam
from scripts import int_guest_inventory as transport
from scripts import int_noble_apply as previous


CONFIG = "config/int-demo-a-noble-policy.json"
ACCOUNT = "projects/clipforgebeta2/serviceAccounts/clipforge-db01-noble-int@clipforgebeta2.iam.gserviceaccount.com"
PRINCIPAL = "serviceAccount:clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com"
ROLES = {
    "account": ("clipforgeIntReadPostgresPolicy_20261118T180000Z", "reuse", "iam.serviceAccounts.getIamPolicy"),
    "instance": ("clipforgeIntDemoANobleInstancePolicyRead", "create", "compute.instances.getIamPolicy"),
    "tunnel": ("clipforgeIntNobleIapPolicyRead", "reuse", "iap.tunnelInstances.getIamPolicy"),
}
ROUTES = {
    "instance": ("GET", "https://compute.googleapis.com/compute/v1/projects/clipforgebeta2/zones/us-central1-a/"
                 "instances/clipforge-int-db01-noble/getIamPolicy?optionsRequestedPolicyVersion=3", None),
    "account": ("POST", f"https://iam.googleapis.com/v1/{ACCOUNT}:getIamPolicy?options.requestedPolicyVersion=3", None),
    "tunnel": ("POST", "https://iap.googleapis.com/v1/projects/816643438938/iap_tunnel/zones/us-central1-a/"
               "instances/7365414160255801909:getIamPolicy", {"options": {"requestedPolicyVersion": 3}}),
}
require = transport.require
canonical = previous.canonical_direct_policy


def expected_policy(config, transition):
    """Accept only an approved complete before/after with one added read binding per target."""
    require(set(config) == {"schema", "project", "principal", "read_roles", "prior", "ownership", "authorized"}
            and config["schema"] == "clipforge-int-demo-a-noble-policy-1" and config["project"] == "clipforgebeta2"
            and config["principal"] == PRINCIPAL and set(config["read_roles"]) == set(ROLES)
            and config["ownership"] == "external_additive_binding" and config["authorized"] is False
            and set(config["prior"]) == set(ROUTES), "noble_read_policy_scope")
    require(set(transition) == {"schema", "status", "approval_sha256", "policies"}
            and transition["schema"] == "clipforge-int-demo-a-noble-policy-receipt-2"
            and transition["status"] == "applied_and_verified" and set(transition["policies"]) == set(ROUTES)
            and isinstance(transition["approval_sha256"], str) and re.fullmatch(r"[a-f0-9]{64}", transition["approval_sha256"]),
            "noble_read_policy_receipt")
    expected = {}
    for target, (name, mode, permission) in ROLES.items():
        role = f"projects/clipforgebeta2/roles/{name}"
        source = config["read_roles"][target]
        definition = source["definition"]
        require(set(source) == {"name", "mode", "definition"} and source["name"] == role and source["mode"] == mode
                and set(definition) == {"title", "description", "stage", "includedPermissions"} and definition["stage"] == "GA"
                and definition["includedPermissions"] == [permission], "noble_read_policy_role_scope")
        receipt = transition["policies"][target]
        require(set(receipt) == {"before", "after", "role", "role_definition"} and receipt["role"] == role
                and receipt["role_definition"] == definition, "noble_read_policy_receipt")
        before, after = canonical(receipt["before"]), canonical(receipt["after"])
        require(before == canonical(config["prior"][target]), "noble_read_policy_baseline")
        iam.check_policy_delta(before, after, [{"role": role, "members": [PRINCIPAL]}])
        expected[target] = after
    return expected


def verify_live(expected, token, *, reader=None):
    reader = reader or iam.request_json
    blocked = []
    for name, (method, url, body) in ROUTES.items():
        try:
            observed = canonical(reader(url, token, method, body))
            if observed != expected[name]:
                blocked.append({"operation": "getIamPolicy", "resource": name, "reason": "full_policy_or_etag_drift"})
        except iam.CloudError as error:
            blocked.append({"operation": "getIamPolicy", "resource": name, "http_status": error.status})
    return blocked
