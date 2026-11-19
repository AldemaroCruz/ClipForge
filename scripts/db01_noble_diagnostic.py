"""Bounded IAM evidence from explicit DB-01 Noble Terraform provider errors."""

import re


MAX_NATIVE_BYTES = 2 * 1024 * 1024
MAX_RECEIPT_ROWS = 64
NATIVE_LOG_OPERATIONS = {
    "fmt", "validate_init", "validate", "noble_native_mock", "noble_iac_security",
    "noble_backend_init", "noble_native_plan", "noble_private_show",
}
HTTP_403 = re.compile(r"\bgoogleapi: Error 403:\s*")
PERMISSION_NAME = (
    r"((?:artifactregistry|compute|iam|iap|logging|resourcemanager|secretmanager|serviceusage|storage)"
    r"(?:\.[a-zA-Z][a-zA-Z0-9]{0,63}){2,3})"
)
DENIED = re.compile(r"^Permission ['\"]" + PERMISSION_NAME + r"['\"] denied\b")
REQUIRED = re.compile(r"^Required ['\"]" + PERMISSION_NAME + r"['\"] permission\b")
RESOURCE_PATH = (
    r"projects/(?:clipforgebeta2|816643438938|-)"
    r"(?:/[A-Za-z0-9_-][A-Za-z0-9_.@-]{0,128}){0,12}"
)
GOOGLE_API_HOST = r"(?:[a-z][a-z0-9-]{0,62}\.)?googleapis\.com"
DIRECT_TARGET = re.compile(r"^\s*(?:on|for)\s+(?:resource\s+)?(['\"])([^'\"]{1,2048})\1")
CANONICAL_TARGET = re.compile(r"(?://" + GOOGLE_API_HOST + r"/)?(" + RESOURCE_PATH + ")")
CONTEXT_TARGET = re.compile(r"(?<![\w/-])(" + RESOURCE_PATH + r")(?![\w./@-])")
ROLE = re.compile(r"\broles/[A-Za-z][A-Za-z0-9_.]{0,127}\b")
DOMAIN = re.compile(r"\b(?:" + GOOGLE_API_HOST + r"|iam\.gserviceaccount\.com)\b")
ANSI_COLOR = re.compile(r"\x1b\[[0-9;]*m")


def denied_target(detail, context):
    explicit = DIRECT_TARGET.match(detail)
    if explicit:
        canonical = CANONICAL_TARGET.fullmatch(explicit[2])
        return canonical[1] if canonical else None
    # Secret Manager can redact the target, and the old receipt cropped the IAP
    # target. Its own Terraform provider error identifies the requested resource.
    candidates = set(CONTEXT_TARGET.findall(context))
    return next(iter(candidates)) if len(candidates) == 1 else None


def classify_native_errors(text, *, native_tail_truncated=False):
    denials = set()
    unbound = set()
    roles = set()
    domains = set()
    other_403_errors = 0
    for line in text.splitlines():
        header = ANSI_COLOR.sub("", line).lstrip(" \t│")
        if not header.startswith("Error:"):
            continue
        match = HTTP_403.search(header)
        if not match:
            continue
        context, detail = header[:match.start()], header[match.end():]
        roles.update(ROLE.findall(context))
        domains.update(DOMAIN.findall(header))
        permission = DENIED.match(detail) or REQUIRED.match(detail)
        if not permission:
            other_403_errors += 1
            continue
        target = denied_target(detail[permission.end():], context)
        if target is None:
            unbound.add(permission[1])
        else:
            denials.add((permission[1], target))

    observed = {
        "denials": [{"permission": permission, "resource": resource, "http_status": 403}
                    for permission, resource in sorted(denials)],
        "unbound_permissions": sorted(unbound),
        "role_references": sorted(roles),
        "domain_references": sorted(domains),
    }
    return {
        **{key: rows[:MAX_RECEIPT_ROWS] for key, rows in observed.items()},
        "unclassified_http_403_errors": other_403_errors,
        "limits": {
            "native_tail_bytes": MAX_NATIVE_BYTES,
            "native_tail_truncated": native_tail_truncated,
            "max_entries_per_list": MAX_RECEIPT_ROWS,
            "truncated_lists": sorted(key for key, rows in observed.items() if len(rows) > MAX_RECEIPT_ROWS),
        },
    }


def operation_receipt(work, legacy_receipt):
    operation = legacy_receipt["operation"]
    receipt = {"operation": operation, "status": legacy_receipt["status"]}
    if operation not in NATIVE_LOG_OPERATIONS:
        return receipt
    try:
        with (work / (operation + ".log")).open("rb") as stream:
            size = stream.seek(0, 2)
            truncated = size > MAX_NATIVE_BYTES
            stream.seek(max(0, size - MAX_NATIVE_BYTES))
            tail = stream.read(MAX_NATIVE_BYTES)
        if truncated:
            # The first line may begin mid-output and cannot identify a complete error.
            tail = tail.partition(b"\n")[2]
        receipt.update(classify_native_errors(tail.decode("utf-8", errors="replace"), native_tail_truncated=truncated))
    except Exception as error:
        receipt["extraction_error"] = {"error_type": type(error).__name__}
    return receipt
