"""Protected future secret-version publication; values never enter CLI arguments.

Containers must already have been created by the reviewed foundation plan.
This helper cannot create containers, IAM, keys, or change enabled versions.
"""
import argparse
import base64
import json
import os
import re
from urllib.request import Request, build_opener, ProxyHandler

from scripts import int_release
from scripts.check_tf_int import require
from scripts.tf_int_plan import NoRedirect

TARGETS = {"app_password": "clipforge-int-pg-app-password",
           "migrator_password": "clipforge-int-pg-migrator-password",
           "postgres_ca": "clipforge-int-postgres-ca", "bootstrap_admin": "clipforge-int-bootstrap-admin"}


def validate_payload(target, raw):
    require(target in TARGETS and isinstance(raw, bytes) and 1 <= len(raw) <= 16384, "Missing or oversized protected input")
    text = raw.decode("utf-8")
    if target in {"app_password", "migrator_password"}:
        require(32 <= len(text) <= 4096 and text.isascii() and all(33 <= ord(ch) <= 126 for ch in text),
                "Database password does not meet the protected-input ASCII contract")
    elif target == "bootstrap_admin":
        value = json.loads(text)
        require(isinstance(value, dict) and set(value) == {"username", "password"}
                and isinstance(value["username"], str) and bool(re.fullmatch(r"[A-Za-z0-9_.@+-]{3,64}", value["username"]))
                and isinstance(value["password"], str) and 12 <= len(value["password"]) <= 128,
                "Initial administrator must be explicit protected JSON; no defaults")
    else:
        require(text.startswith("-----BEGIN CERTIFICATE-----\n") and text.rstrip().endswith("-----END CERTIFICATE-----")
                and "PRIVATE KEY" not in text, "Only the PostgreSQL CA certificate may be published")


def add_version(target, raw, environ):
    int_release.hosted_context(environ)
    int_release.require_application_ci(environ)
    require(environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"), "Exact owner-confirmed commit required")
    validate_payload(target, raw)
    url = "https://secretmanager.googleapis.com/v1/projects/clipforgebeta2/secrets/" + TARGETS[target] + ":addVersion"
    payload = json.dumps({"payload": {"data": base64.b64encode(raw).decode("ascii")}}).encode()
    request = Request(url, data=payload, method="POST", headers={"Authorization": "Bearer " + environ["GCP_ACCESS_TOKEN"], "Content-Type": "application/json"})
    with build_opener(ProxyHandler({}), NoRedirect()).open(request, timeout=60) as response:
        result = json.loads(response.read(32769))
    name = result.get("name", "")
    require(bool(re.fullmatch(r"projects/(?:clipforgebeta2|816643438938)/secrets/" + TARGETS[target] + r"/versions/[1-9][0-9]*", name)),
            "Secret version response differs from protected target")
    # Version metadata only. No response body or hash of a password is printed.
    return {"secret": TARGETS[target], "version": name.rsplit("/", 1)[1]}


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("target", choices=sorted(TARGETS))
    args = parser.parse_args(argv)
    raw = os.environ.pop("INT_SECRET_PAYLOAD", "").encode("utf-8")
    try:
        print(json.dumps(add_version(args.target, raw, os.environ)))
        return 0
    except Exception:
        print("Protected secret publication stopped; no values or server response were logged.")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
