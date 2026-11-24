"""Fingerprint only tools used by an approved INT database job."""

import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys
import uuid

from scripts import int_demo_a_publication_host as common
from scripts import int_runner_risk as runner_risk


SCHEMA = "clipforge-int-db-runner-1"
OPERATIONS = {
    "bootstrap": ("int-db01-noble-bootstrap.yml", "protected-bootstrap"),
    "guest_intervention": ("int-db01-noble-intervention.yml", "intervene"),
    "apt_preflight": ("int-db01-noble-intervention.yml", "intervene"),
    "personal_sql_intervention": ("int-db01-noble-intervention.yml", "intervene"),
    "secret_versions": ("int-demo-a-secrets.yml", "protected-operation"),
}
ACTIONS = {
    "checkout": ("actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1", ("dist/index.js",)),
    "download_artifact": ("actions/download-artifact@9000827ccba6bdab643e8b6fd33ac0654aef8333", ("dist/index.js",)),
    "google_auth": ("google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
                    ("dist/main/index.js", "dist/post/index.js")),
    "setup_gcloud": ("google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db", ("dist/index.js",)),
    "upload_artifact": ("actions/upload-artifact@cf430e030ddbb5b0abf93d22962f4752f3646cd9", ("dist/upload/index.js",)),
}
COMMON = {"bash", "git", "python", "system_ca", "runner_worker", "node24", "libssl", "libcrypto", "libc"}
SSH = {"ssh", "ssh_keygen", "gcloud", "gcloud_entry", "gcloud_version"}
HEX = re.compile(r"[a-f0-9]{64}")


def require(value, code):
    if not value:
        raise ValueError(code)


def tool_names(operation):
    names = ACTIONS if operation != "secret_versions" else ("checkout", "download_artifact", "google_auth")
    return COMMON | (SSH if operation != "secret_versions" else set()) | {f"action_{name}" for name in names}


def executable(name):
    path = shutil.which(name)
    require(path and Path(path).is_absolute(), "db_runner_missing_" + name)
    return Path(path)


def kernel_review(kernel):
    require(isinstance(kernel, dict) and set(kernel) == {"release", "family", "signature", "packages"},
            "db_runner_kernel_fields")
    release, family = kernel["release"], kernel["family"]
    abi = re.fullmatch(r"([0-9]+\.[0-9]+\.[0-9]+-[0-9]+)-(aws|azure)", release)
    require(abi and abi[2] == family, "db_runner_kernel_family")
    packages = dict((row[0], row[1:]) for row in kernel["packages"])
    require(len(packages) == len(kernel["packages"]) and all(
        len(row) == 4 and all(isinstance(value, str) and 0 < len(value) <= 160 for value in row)
        for row in kernel["packages"]), "db_runner_kernel_package_rows")
    image = packages.get("linux-image-" + release)
    modules = packages.get("linux-modules-" + release)
    require(image and modules and set(packages) <= {
        "linux-image-" + release, "linux-modules-" + release, "linux-modules-extra-" + release
    } and all(row[0] == image[0] for row in packages.values()) and image[0].startswith(abi[1] + "."),
            "db_runner_kernel_package_match")
    require(re.fullmatch(r"Ubuntu " + re.escape(image[0] + "-" + family) +
                        r" [0-9]+\.[0-9]+\.[0-9]+(?:[.0-9+~-]+)?", kernel["signature"]),
            "db_runner_kernel_signature_match")


def checked(facts, operation):
    require(isinstance(facts, dict) and set(facts) == {
        "schema", "image", "os", "architecture", "kernel", "tools"
    } and facts["schema"] == SCHEMA and facts["os"] == "ubuntu24" and facts["architecture"] == "x86_64"
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", facts["image"]), "db_runner_projection")
    kernel_review(facts["kernel"])
    tools = facts["tools"]
    require(set(tools) == tool_names(operation) and all(HEX.fullmatch(digest or "") for digest in tools.values()),
            "db_runner_exact_tool_scope")
    return facts


def runner_component_paths(operation, runner_temp):
    worker = common.runner_executables()
    paths = {"runner_worker": worker["runner_worker"], "node24": worker["node24"],
             "bash": Path("/usr/bin/bash"), "git": executable("git"), "python": Path(sys.executable),
             "system_ca": Path("/etc/ssl/certs/ca-certificates.crt"), **common.ssl_dependencies()}
    if operation != "secret_versions":
        sdk = executable("gcloud").resolve(strict=True)
        root = sdk.parent.parent
        version = root / "VERSION"
        require(sdk.parent.name == "bin" and sdk.name == "gcloud" and version.stat().st_size <= 64
                and version.read_text(encoding="ascii").strip() == "582.0.0", "db_runner_gcloud_release")
        paths.update(ssh=Path("/usr/bin/ssh"), ssh_keygen=Path("/usr/bin/ssh-keygen"),
                     gcloud=sdk, gcloud_entry=root / "lib/gcloud.py", gcloud_version=version)
    components = {name: {"file": path} for name, path in paths.items()}
    actions_root = runner_temp.parent / "_actions"
    for action in sorted(name.removeprefix("action_") for name in tool_names(operation) if name.startswith("action_")):
        pin, entries = ACTIONS[action]
        repository, commit = pin.split("@", 1)
        root = actions_root / repository / commit
        components[f"action_{action}"] = {leaf: root / leaf for leaf in ("action.yml", *entries)}
    return components


def component_hashes(components):
    files = {}
    for name, entries in components.items():
        identities = {leaf: common.file_identity(path) for leaf, path in entries.items()}
        files[name] = common.digest(identities) if name.startswith("action_") else identities["file"]["sha256"]
    return files


def runner_tools(operation, runner_temp):
    return component_hashes(runner_component_paths(operation, runner_temp))


def live_facts(operation, env, runner_temp, *, inventory=None):
    machine = os.uname()
    with Path("/proc/version_signature").open(encoding="ascii") as stream:
        signature = stream.read(256).strip()
    require(len(signature) < 255, "db_runner_kernel_signature_bound")
    package_names = {prefix + machine.release for prefix in ("linux-image-", "linux-modules-", "linux-modules-extra-")}
    packages = []
    for row in common.package_inventory() if inventory is None else inventory:
        name = row[0].removesuffix(":amd64")
        if name in package_names:
            packages.append([name, *row[1:]])
    kernel = {"release": machine.release, "family": machine.release.rsplit("-", 1)[-1],
              "signature": signature, "packages": sorted(packages)}
    facts = checked({"schema": SCHEMA, "image": env["ImageVersion"], "os": env["ImageOS"],
                     "architecture": machine.machine, "kernel": kernel, "tools": runner_tools(operation, runner_temp)}, operation)
    boot = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()))
    return facts, boot


def observe(operation, env, binding):
    workflow, job = OPERATIONS[operation]
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24",
                "GITHUB_JOB": job, "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": binding["source_commit"],
                "GITHUB_WORKFLOW_REF": f"{binding['repository']}/.github/workflows/{workflow}@refs/heads/{binding['branch']}"}
    require(all(env.get(key) == value for key, value in expected.items())
            and re.fullmatch(r"[1-9][0-9]*", env.get("GITHUB_RUN_ID", ""))
            and os.getuid() == os.geteuid() > 0, "db_runner_protected_job_identity")
    runner_temp = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    require(runner_temp.is_dir() and runner_temp.stat().st_uid == os.getuid(), "db_runner_private_checkpoint_parent")
    facts, boot = live_facts(operation, env, runner_temp)
    return runner_temp, {"facts": facts, "boot_id": boot, "run": env["GITHUB_RUN_ID"],
                         "attempt": env["GITHUB_RUN_ATTEMPT"], "job": job, "operation": operation,
                         "commit": env["GITHUB_SHA"]}


def admission_inputs_present(env):
    return any(env.get(name) for name in (
        "GCP_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH",
        "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "INT_PG_APP_PASSWORD", "INT_PG_MIGRATOR_PASSWORD",
        "INT_PG_CA_CERT", "INT_PG_SERVER_CERT", "INT_PG_SERVER_KEY", "INT_BOOTSTRAP_ADMIN",
        "INT_NOBLE_PERSONAL_SQL_PASSWORD",
    ))


def require_secretless_admission(env):
    require(not admission_inputs_present(env), "db_runner_admission_requires_no_secret_inputs")


def verify(expected, operation, env, binding):
    """Validate each hosted runner independently, then pin only this job across WIF."""
    checked(expected, operation)
    runner_temp, actual = observe(operation, env, binding)
    checked(actual["facts"], operation)
    require(not runner_risk.cross_job_identity_required()
            and runner_risk.POLICY["same_job_continuity_required"] is True,
            "db_runner_risk_acceptance_scope")
    checkpoint = runner_temp / f".int-db-host.{actual['run']}.{actual['job']}.json"
    raw = json.dumps(actual, sort_keys=True, separators=(",", ":")).encode("ascii")
    try:
        with os.fdopen(os.open(checkpoint, os.O_RDONLY | os.O_NOFOLLOW), "rb") as stream:
            info = os.fstat(stream.fileno())
            require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and info.st_uid == os.getuid()
                    and info.st_mode & 0o077 == 0, "db_runner_private_checkpoint")
            require(stream.read(len(raw) + 1) == raw, "db_runner_continuity_changed")
    except FileNotFoundError:
        require(not admission_inputs_present(env) and env.get("INT_DB_RUNNER_REQUIRE_EXISTING") != "1",
                "db_runner_missing_preauth_checkpoint")
        with os.fdopen(os.open(checkpoint, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600), "wb") as stream:
            stream.write(raw)
