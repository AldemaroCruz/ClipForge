"""Collect review-only host and native scan evidence for APT on a standard runner."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys

from scripts import int_demo_a_db_runner as db
from scripts import int_demo_a_publication_host as common


REPOSITORY = "AldemaroCruz/ClipForge"
BRANCH = "ci/bootstrap-sec03"
WORKFLOW = ".github/workflows/int-db01-noble-apt-runner-observe.yml"
JOB = "observe-apt-runner"
OPERATION = "guest_intervention"
SCHEMA = "clipforge-int-noble-apt-runner-observation-1"
SCANNER = "ghcr.io/aquasecurity/trivy:0.76.2@sha256:6fa071ef8daa2e58b90cbf1710bedca91adbb3bf98693533226f442035b836a6"
SYSTEM_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
AMBIENT = ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN", "GCP_READ_ACCESS_TOKEN",
           "GOOGLE_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN", "GOOGLE_CREDENTIALS", "CLOUDSDK_AUTH_ACCESS_TOKEN",
           "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE", "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT")
ELF_ROLES = {"bash", "git", "python", "runner_worker", "node24", "ssh", "ssh_keygen"}
METADATA_NAMES = {"package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml",
                  "Pipfile.lock", "poetry.lock", "requirements.txt", "METADATA", "PKG-INFO"}
MAX_REPORT = 32 * 1024 * 1024
MAX_DATABASE = 3 * 1024 * 1024 * 1024


def verify_context(env, work):
    db.require_secretless_admission(env)
    db.require(not any(env.get(name) for name in AMBIENT), "apt_observation_has_credentials")
    expected = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24",
                "GITHUB_REPOSITORY": REPOSITORY, "GITHUB_REF": "refs/heads/" + BRANCH,
                "GITHUB_WORKFLOW_REF": f"{REPOSITORY}/{WORKFLOW}@refs/heads/{BRANCH}",
                "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_JOB": JOB}
    db.require(all(env.get(key) == value for key, value in expected.items())
               and re.fullmatch(r"[1-9][0-9]{0,18}", env.get("GITHUB_RUN_ID", ""))
               and re.fullmatch(r"[a-f0-9]{40}", env.get("GITHUB_SHA", ""))
               and env["GITHUB_SHA"] == env.get("INT_APPROVED_COMMIT")
               and os.getuid() == os.geteuid() > 0, "apt_observation_hosted_identity")
    runner_temp = Path(env["RUNNER_TEMP"]).resolve(strict=True)
    db.require(work == work.resolve(strict=True) and work.parent == runner_temp
               and work.name.startswith("clipforge-apt-runner.") and work.stat().st_uid == os.getuid(), "apt_observation_scratch")
    return runner_temp


def write_json(path, value):
    raw = common.encoded_report(value)
    db.require(len(raw) <= MAX_REPORT, "apt_observation_report_bound")
    with path.open("xb") as stream:
        stream.write(raw)


def read_json(path):
    with path.open("rb") as stream:
        raw = stream.read(MAX_REPORT + 1)
    db.require(0 < len(raw) <= MAX_REPORT, "apt_observation_report_bound")
    return json.loads(raw)


def local_command(args):
    proc = subprocess.run(args, env=SYSTEM_ENV, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, timeout=6, check=False)
    db.require(len(proc.stdout) <= 65536, "apt_observation_dependency_output_bound")
    return proc.returncode, proc.stdout.decode("utf-8", errors="strict")


def package_owner(path, inventory):
    text = str(path)
    aliases = [text]
    if text.startswith(("/usr/bin/", "/usr/sbin/", "/usr/lib/")):
        aliases.append(text[4:])
    owners = set()
    for alias in aliases:
        _, output = local_command(["/usr/bin/dpkg-query", "-S", "--", alias])
        for line in output.splitlines():
            name, _, reported = line.rpartition(": ")
            if reported == alias and name in inventory:
                owners.add(name)
            elif reported == alias and name + ":amd64" in inventory:
                owners.add(name + ":amd64")
    return sorted(owners)


def linked_libraries(path):
    resolved = path.resolve(strict=True)
    with resolved.open("rb") as stream:
        if stream.read(4) != b"\x7fELF":
            return [], []
    status, output = local_command(["/usr/bin/ldd", str(resolved)])
    db.require(status == 0 or output.strip() in {"statically linked", "not a dynamic executable"}, "apt_observation_ldd_failed")
    linked, missing = set(), set()
    for line in output.splitlines():
        match = re.fullmatch(r"\s*(?:[^\s]+ => )?(/[^\s]+) \(0x[0-9a-fA-F]+\)\s*", line)
        if match:
            linked.add(Path(match[1]).resolve(strict=True))
        elif absent := re.fullmatch(r"\s*([A-Za-z0-9._+-]+) => not found\s*", line):
            missing.add(absent[1])
    return sorted(linked), sorted(missing)


def stage_metadata(source, dest):
    """Stage public dependency metadata, keeping the native analyzer's coverage distinct from use."""
    selected = {}
    total = 0
    source = source.resolve(strict=True)
    for folder, dirs, names in os.walk(source, followlinks=False):
        root = Path(folder)
        dirs[:] = sorted(name for name in dirs if name not in {".git", "__pycache__"}
                         and not (root / name).is_symlink())
        for name in sorted(names):
            if name not in METADATA_NAMES and not name.endswith((".deps.json", ".runtimeconfig.json")):
                continue
            path = root / name
            if path.is_symlink():
                continue
            relative = path.relative_to(source)
            info = path.stat()
            size = info.st_size
            db.require(stat.S_ISREG(info.st_mode) and len(selected) < 1000 and 0 <= size <= 8 * 1024 * 1024
                       and total + size <= 48 * 1024 * 1024, "apt_observation_metadata_bound")
            value = path.read_bytes()
            db.require(len(value) == size, "apt_observation_metadata_changed")
            target = dest / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(value)
            selected[relative.as_posix()] = sha256(value).hexdigest()
            total += size
    return selected


def stage_dpkg(root, package_names):
    with Path("/var/lib/dpkg/status").open(encoding="utf-8") as stream:
        content = stream.read(16 * 1024 * 1024 + 1)
    db.require(len(content) <= 16 * 1024 * 1024, "apt_observation_dpkg_input_bound")
    raw, found = [], set()
    for paragraph in content.strip().split("\n\n"):
        name = re.search(r"(?m)^Package: ([^ ]+)$", paragraph)
        arch = re.search(r"(?m)^Architecture: ([a-z0-9-]+)$", paragraph)
        if name is None or arch is None or "\nStatus: install ok installed\n" not in "\n" + paragraph + "\n":
            continue
        names = {name[1], f"{name[1]}:{arch[1]}"} & package_names
        if names:
            found.update(names)
            raw.append(paragraph)
    db.require(found == package_names, "apt_observation_dpkg_input_incomplete")
    status = root / "var/lib/dpkg/status"
    status.parent.mkdir(parents=True)
    status.write_text("\n\n".join(raw) + "\n\n", encoding="utf-8")
    release = root / "etc/os-release"
    release.parent.mkdir()
    release.write_text(common.bounded_text("/etc/os-release", 16384), encoding="ascii")


def database_receipt(work, image):
    db.require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "apt_observation_scanner_image_id")
    cache = work / "cache/db"
    metadata = read_json(cache / "metadata.json")
    expires = datetime.fromisoformat(metadata["NextUpdate"].replace("Z", "+00:00"))
    db.require(metadata["Version"] == 2 and expires > datetime.now(timezone.utc), "apt_observation_scanner_db_expired")
    path = cache / "trivy.db"
    before = path.lstat()
    db.require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= MAX_DATABASE, "apt_observation_scanner_db_bound")
    hashed = sha256()
    count = 0
    with path.open("rb") as stream:
        while block := stream.read(4 * 1024 * 1024):
            count += len(block)
            db.require(count <= before.st_size, "apt_observation_scanner_db_changed")
            hashed.update(block)
    after = path.lstat()
    db.require(count == before.st_size and (before.st_ino, before.st_size, before.st_mtime_ns)
               == (after.st_ino, after.st_size, after.st_mtime_ns), "apt_observation_scanner_db_changed")
    write_json(work / "reports/trivy-db-receipt.json", {"scanner_image": SCANNER, "local_image_id": image,
               "database": {"sha256": hashed.hexdigest(), "bytes": count}, "metadata": metadata,
               "metadata_file": common.file_identity(cache / "metadata.json")})


def collect(env, work):
    runner_temp = verify_context(env, work)
    inventory_rows = common.package_inventory()
    inventory = {row[0]: row for row in inventory_rows}
    facts, boot_id = db.live_facts(OPERATION, env, runner_temp, inventory=inventory_rows)
    measured = {"schema": SCHEMA, "facts": facts, "boot_id": boot_id, "run": env["GITHUB_RUN_ID"], "attempt": 1,
                "job": JOB, "commit": env["GITHUB_SHA"], "operation": "apt_upgrade",
                "observed_at": datetime.now(timezone.utc).isoformat(), "activation_authorized": False}
    write_json(work / "reports/host-facts.json", measured)
    paths = db.runner_component_paths(OPERATION, runner_temp)
    identities = {role: {key: common.file_identity(path) for key, path in files.items()} for role, files in paths.items()}
    projected = {role: (files["file"]["sha256"] if "file" in files else common.digest(files))
                 for role, files in identities.items()}
    db.require(projected == facts["tools"], "apt_observation_tool_projection_changed")
    app_roots = {role: files["action.yml"].parent for role, files in paths.items() if role.startswith("action_")}
    sdk = paths["gcloud_entry"]["file"].parent.parent
    app_roots.update({"gcloud": sdk, "runner_worker": paths["runner_worker"]["file"].parent})
    bundled_python = sdk / "platform/bundledpythonunix/bin/python3"
    interpreters = {"gcloud_bundled_python": bundled_python} if bundled_python.is_file() else {}
    for role in ELF_ROLES:
        interpreters[role] = paths[role]["file"]
    linked = {role: linked_libraries(path) for role, path in sorted(interpreters.items())}
    owned_paths = {path.resolve(strict=True) for files in paths.values() for path in files.values()}
    owned_paths.update(path for files, _ in linked.values() for path in files)
    # Tool files under the SDK/actions/runner need independent distro-external evidence.
    owners = {str(path): package_owner(path, inventory) for path in sorted(owned_paths)
              if str(path).startswith(("/usr/", "/lib/", "/etc/"))}
    selected = {package for row in owners.values() for package in row}
    for name, _, _, _ in facts["kernel"]["packages"]:
        selected.add(name if name in inventory else name + ":amd64")
    if "ca-certificates" in inventory:
        selected.add("ca-certificates")
    roles = {role: {"files": {key: {**identities[role][key], "path": str(path.resolve(strict=True)),
                                  "dpkg_owners": owners.get(str(path.resolve(strict=True)), [])}
                              for key, path in files.items()},
                    "usage": "downloaded_not_executed" if role in {"action_download_artifact", "action_google_auth"}
                    else "observer_workflow" if role in {"action_checkout", "action_setup_gcloud", "action_upload_artifact"}
                    else "measured_on_assigned_runner"}
             for role, files in paths.items()}
    if bundled_python.is_file():
        roles["gcloud"]["bundled_python"] = common.file_identity(bundled_python)
    version_status, node = local_command([str(paths["node24"]["file"]), "--print", "JSON.stringify(process.versions)"])
    db.require(version_status == 0, "apt_observation_node_runtime_print_failed")
    observed = {**measured, "status": "measurement_recorded_review_required",
                "inventory": inventory_rows, "inventory_sha256": common.digest(inventory_rows),
                "component_files": roles, "node_versions": json.loads(node), "python_version": sys.version.split()[0],
                "runtime_libraries": {name: {"files": {str(path): {**common.file_identity(path), "dpkg_owners": owners.get(str(path), [])}
                                                      for path in files}, "missing": missing}
                                      for name, (files, missing) in linked.items()},
                "os_scan_packages": [inventory[name] for name in sorted(selected)]}
    write_json(work / "reports/host-observed.json", observed)
    stage_dpkg(work / "scan/runner-os", selected)
    metadata = {role: stage_metadata(path, work / "scan/app-metadata" / role) for role, path in app_roots.items()}
    write_json(work / "reports/scan-inputs.json", {"native_os_input": "runner-os", "native_app_input": "app-metadata",
                                                  "app_dependency_metadata": metadata,
                                                  "app_metadata_proves_effective_use": False})


def summarize(env, work, native_stage):
    verify_context(env, work)
    reports = work / "reports"
    if not (reports / "host-observed.json").is_file():
        if not (reports / "host-result.json").exists():
            reason = "dependency_measurement_missing" if (reports / "host-facts.json").is_file() else "measurement_missing"
            write_json(reports / "host-result.json", {"status": "host_observation_blocked", "reason": reason,
                                                       "activation_authorized": False})
        return 1
    observed = read_json(reports / "host-observed.json")
    receipt = {"status": "host_observed_review_required", "activation_authorized": False, "operation": "apt_upgrade",
               "run": observed["run"], "commit": observed["commit"], "boot_id": observed["boot_id"], "scanner": SCANNER,
               "measurement_sha256": common.file_identity(reports / "host-observed.json")["sha256"], "native_reports": {},
               "known_scope_gaps": ["owner_dispositions", "effective_use_of_bundled_and_language_metadata",
                                    "independent_binding_and_protected_host_continuity"]}
    if any(value["missing"] for value in observed.get("runtime_libraries", {}).values()):
        receipt.update(status="host_rejected", reason="apt_observation_runtime_library_missing")
    expected = {(package.split(":", 1)[0], version) for package, version, _, _ in observed["os_scan_packages"]}
    kernel_packages = {package for package, _, _, _ in observed["facts"]["kernel"]["packages"]}
    for name in ("trivy-os.json", "trivy-app-metadata.json"):
        path = reports / name
        if not path.is_file():
            receipt["known_scope_gaps"].append(name)
            continue
        raw = read_json(path)
        db.require(raw.get("SchemaVersion") == 2, "apt_observation_native_trivy_schema")
        targets = raw.get("Results", [])
        if not targets or any(not item.get("Packages") for item in targets):
            receipt["known_scope_gaps"].append(name + ":package_coverage_missing")
        blockers = [row for target in targets for row in target.get("Vulnerabilities", [])
                    if row.get("Severity") in {"HIGH", "CRITICAL", "UNKNOWN"}]
        receipt["native_reports"][name] = {**common.file_identity(path), "targets": [item["Target"] for item in targets],
                                           "threshold_rows": len(blockers)}
        if name == "trivy-os.json":
            actual = {(row["Name"], row["Version"]) for target in targets for row in target.get("Packages", [])}
            if actual != expected:
                receipt["known_scope_gaps"].append("native_os_package_set_mismatch")
            attributed = [row for row in blockers if (row["PkgName"], row["InstalledVersion"]) in expected]
            if attributed:
                first = next((row for row in attributed if row["PkgName"] in kernel_packages), attributed[0])
                receipt.update(status="host_rejected", reason="native_image_threshold:credential_toolchain",
                               first_os_blocker={key: first.get(key) for key in (
                                   "VulnerabilityID", "PkgName", "InstalledVersion", "FixedVersion", "Severity", "PkgIdentifier")})
    if native_stage != "success" or not (reports / "trivy-db-receipt.json").is_file():
        receipt["known_scope_gaps"].append("native_scan_incomplete")
        if receipt["status"] != "host_rejected":
            receipt.update(status="host_observation_blocked", reason="native_scan_incomplete")
    write_json(reports / "host-result.json", receipt)
    print(json.dumps({key: receipt.get(key) for key in ("status", "reason", "activation_authorized")}))
    return int(receipt["status"] != "host_observed_review_required")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=("collect", "database", "summarize"))
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--native-stage", choices=("success", "failure", "skipped", "cancelled"), default="skipped")
    args = parser.parse_args(argv)
    try:
        if args.phase == "collect":
            collect(os.environ, args.work)
            return 0
        if args.phase == "database":
            verify_context(os.environ, args.work)
            database_receipt(args.work, os.environ["TRIVY_LOCAL_ID"])
            return 0
        return summarize(os.environ, args.work, args.native_stage)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        text = str(error)
        report = {"status": "host_observation_blocked", "activation_authorized": False, "phase": args.phase,
                  "reason": text if re.fullmatch(r"[a-z_]{1,120}", text) else type(error).__name__}
        try:
            verify_context(os.environ, args.work)
            write_json(args.work / f"reports/{args.phase}-failure.json", report)
        except (OSError, ValueError, KeyError):
            pass
        print(json.dumps(report))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
