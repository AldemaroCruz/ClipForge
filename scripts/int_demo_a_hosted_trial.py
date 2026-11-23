"""Verify the one nominated GitHub-hosted Noble image before Docker preparation."""

import argparse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from hashlib import sha256
import json
import lzma
import os
from pathlib import Path
import re
import subprocess
from tempfile import TemporaryDirectory
import time
from urllib.error import HTTPError
from urllib.request import ProxyHandler, build_opener

from scripts import int_demo_a_docker as docker
from scripts import int_demo_a_docker_prepare as preparation


IMAGE = "20261122.23.1"
SCHEMA = "clipforge-int-demo-a-hosted-trial-1"
REPORT = "int-demo-a-hosted-trial.json"
RELEASE_URL = "https://github.com/actions/runner-images/releases/tag/ubuntu24%2F20261122.23"
SIGNER = "F6ECB3762474EDA9D21B7022871920D1991BC93C"
KEYRING = Path("/usr/share/keyrings/ubuntu-archive-keyring.gpg")
POCKETS = (
    ("noble-updates", "https://archive.ubuntu.com/ubuntu"),
    ("noble-security", "https://security.ubuntu.com/ubuntu"),
)
INDEX_PATH = "main/binary-amd64/Packages.xz"
INDEX_MAX = 24 * 1024 * 1024
INDEX_RAW_MAX = 96 * 1024 * 1024
KERNELS = {
    "7.0.0-1018-aws": ("aws", "7.0.0-1018.19~24.04.1", "USN-9020-1", "7.0.0-1017.18~24.04.1"),
    "7.0.0-1020-azure": ("azure", "7.0.0-1020.21~24.04.2", "USN-9160-1", "7.0.0-1020.21~24.04.2"),
}
require = docker.require


def read_https(opener, url, maximum):
    deadline = time.monotonic() + 75
    with opener.open(url, timeout=20) as stream:
        data = bytearray()
        while block := stream.read(min(64 * 1024, maximum + 1 - len(data))):
            data.extend(block)
            require(len(data) <= maximum and time.monotonic() < deadline, "hosted_trial_archive_read_bound")
    require(data, "hosted_trial_archive_empty")
    return bytes(data)


def signed_index_entry(release, pocket, now):
    headers = dict(row.split(": ", 1) for row in release.splitlines() if ": " in row and not row.startswith(" "))
    require(headers.get("Origin") == "Ubuntu" and headers.get("Suite") == pocket and headers.get("Codename") == "noble",
            "hosted_trial_archive_suite")
    date = parsedate_to_datetime(headers.get("Date", ""))
    require(now - timedelta(days=14) <= date <= now + timedelta(minutes=5), "hosted_trial_archive_release_age")
    if "Valid-Until" in headers:
        require(now <= parsedate_to_datetime(headers["Valid-Until"]), "hosted_trial_archive_release_expired")
    hashes = re.search(r"^SHA256:\n((?: [^\n]+\n)+)", release, re.M)
    require(hashes is not None, "hosted_trial_archive_missing_sha256")
    selected = [row.split() for row in hashes[1].splitlines() if row.split()[-1] == INDEX_PATH]
    require(len(selected) == 1 and len(selected[0]) == 3, "hosted_trial_archive_index_selection")
    digest, size, _ = selected[0]
    require(re.fullmatch(r"[a-f0-9]{64}", digest) and 0 < int(size) <= INDEX_MAX, "hosted_trial_archive_index_identity")
    return {"sha256": digest, "size": int(size), "date": date.isoformat()}


def matching_packages(compressed, installed, family):
    unpacker = lzma.LZMADecompressor(format=lzma.FORMAT_XZ, memlimit=128 * 1024 * 1024)
    index = unpacker.decompress(compressed, max_length=INDEX_RAW_MAX + 1)
    require(unpacker.eof and not unpacker.unused_data and len(index) <= INDEX_RAW_MAX, "hosted_trial_archive_index_bound")
    records = {}
    for paragraph in index.split(b"\n\n"):
        line = paragraph.partition(b"\n")[0]
        if not line.startswith(b"Package: ") or line[9:].decode("ascii") not in installed:
            continue
        fields = {key: value for row in paragraph.decode().splitlines() if not row.startswith(" ")
                  for key, marker, value in [row.partition(": ")] if marker}
        package = fields["Package"]
        if fields.get("Version") != installed[package] or fields.get("Architecture") != "amd64":
            continue
        source = fields.get("Source", "").split(" ", 1)[0]
        expected_source = ("linux-signed-" if package.startswith("linux-image-") else "linux-") + family + "-7.0"
        expected_file = f"pool/main/l/{expected_source}/{package}_{installed[package]}_amd64.deb"
        require(package not in records and source == expected_source and fields.get("Filename") == expected_file
                and re.fullmatch(r"[a-f0-9]{64}", fields.get("SHA256", "")) and 0 < int(fields.get("Size", "")) <= 512 * 1024 * 1024,
                "hosted_trial_archive_package_identity")
        records[package] = {"source_package": source, "version": installed[package], "architecture": "amd64",
                            "filename": expected_file, "size": int(fields["Size"]), "sha256": fields["SHA256"]}
    return records


def archive_provenance(work, installed, family, *, now):
    opener = build_opener(ProxyHandler({}), preparation.NoRedirect())
    result, packages = {}, {}
    for pocket, archive in POCKETS:
        location = f"{archive}/dists/{pocket}"
        signed = read_https(opener, location + "/InRelease", 512 * 1024)
        inrelease, release = work / (pocket + ".InRelease"), work / (pocket + ".Release")
        inrelease.write_bytes(signed)
        status = docker.run(["/usr/bin/gpgv", "--status-fd", "1", "--keyring", str(KEYRING),
                             "--output", str(release), str(inrelease)], work, timeout=25)
        signers = [line.split()[2:] for line in status.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
        require(len(signers) == 1 and signers[0][-1] == SIGNER, "hosted_trial_archive_signer")
        index = signed_index_entry(docker.bounded_text(release, 512 * 1024), pocket, now)
        compressed = read_https(opener, f"{location}/main/binary-amd64/by-hash/SHA256/{index['sha256']}", index["size"])
        require(len(compressed) == index["size"] and sha256(compressed).hexdigest() == index["sha256"],
                "hosted_trial_archive_index_hash")
        selected = matching_packages(compressed, installed, family)
        require(all(package not in packages or packages[package] == item for package, item in selected.items()),
                "hosted_trial_archive_conflicting_packages")
        packages.update(selected)
        result[pocket] = {"origin": archive, "inrelease_sha256": sha256(signed).hexdigest(),
                          "signing_key_fingerprint": signers[0][0], "archive_key_fingerprint": SIGNER,
                          "index": index, "packages": selected}
        if packages.keys() == installed.keys():
            break
    require(packages.keys() == installed.keys(), "hosted_trial_archive_missing_exact_packages")
    return result


def native_packages(release, version, work):
    expected = {"linux-image-" + release, "linux-modules-" + release}
    optional = "linux-modules-extra-" + release
    raw = docker.run(["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status}\t${Package}\t${Version}\t${Architecture}\n",
                      "linux-image-" + release, "linux-modules*-" + release], work)
    installed = {}
    for row in raw.splitlines():
        state, package, revision, arch = row.split("\t")
        if state != "installed":
            continue
        require(package in expected | {optional} and package not in installed and revision == version and arch == "amd64",
                "hosted_trial_installed_kernel_package")
        installed[package] = revision
    require(expected <= installed.keys(), "hosted_trial_missing_installed_kernel_package")
    return installed


def running_signature():
    value = docker.bounded_text("/proc/version_signature", 1024).strip()
    require(re.fullmatch(r"Ubuntu [A-Za-z0-9.~-]{1,120} [0-9.]{1,32}", value), "hosted_trial_version_signature_scope")
    return value


def record_other_host(work, report):
    """Retain bounded native evidence without reading an archive or installing."""
    release = report["boot"]["release"]
    evidence_errors = {}
    try:
        report["running_version_signature"] = running_signature()
    except (OSError, ValueError, UnicodeError) as error:
        evidence_errors["version_signature"] = type(error).__name__
    if re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-[a-z0-9-]{1,32}", release):
        report["installed_packages"] = {}
        for package in ("linux-image-" + release, "linux-modules-" + release):
            try:
                report["installed_packages"][package] = docker.package_identity(package, work)
            except (OSError, ValueError, subprocess.SubprocessError) as error:
                evidence_errors[package] = type(error).__name__
    if evidence_errors:
        report["observation_errors"] = evidence_errors


def evaluate(env, commit, work, report):
    preparation.hosted(env, "evaluate", commit)
    require(env.get("GITHUB_JOB") == "docker-preparation-without-federation", "hosted_trial_job_scope")
    report["scope_verified"] = True
    report["context"] = {"run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "commit": commit,
                         "job": env["GITHUB_JOB"], "cloud_credentials_used": False, "oidc_job_capability": False}
    boot = preparation.boot_identity()
    report["boot"] = boot
    release = boot["release"]
    if env.get("ImageVersion") != IMAGE or release not in KERNELS:
        record_other_host(work, report)
    require(env.get("ImageVersion") == IMAGE, "hosted_trial_image_not_nominated")
    require(release in KERNELS, "hosted_trial_kernel_not_nominated")
    family, version, notice, floor = KERNELS[release]
    package_version = running_signature()
    report["running_version_signature"] = package_version
    require(re.fullmatch(r"Ubuntu " + re.escape(version + "-" + family) + r" [0-9]+\.[0-9]+(?:\.[0-9]+)?", package_version),
            "hosted_trial_boot_package_version")
    report["installed_packages"] = native_packages(release, version, work)
    report["check_stage"] = "signed_kernel_package_provenance"
    report["signed_package_index"] = archive_provenance(work, report["installed_packages"], family, now=datetime.now(timezone.utc))
    require(preparation.boot_identity() == boot, "hosted_trial_boot_changed")
    report["advisory"] = {"url": f"https://ubuntu.com/security/notices/{notice}", "family": family, "fixed_package_version": floor,
                          "observed_package_version": version, "scope": "listed_noble_branch_only"}
    report["package_evidence_scope"] = "running Ubuntu version signature and installed amd64 package versions matched to signed archive metadata"
    require(family == "aws", "hosted_trial_azure_requires_admission")
    report["status"] = "eligible_for_credential_free_docker_evaluation"


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--approved-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    args = parser.parse_args(argv)
    try:
        root = Path(env["RUNNER_TEMP"]).resolve(strict=True)
        require(args.report == root / REPORT, "hosted_trial_report_scope")
        image = env.get("ImageVersion", "")
        report = {"schema": SCHEMA, "status": "blocked", "image_expected": IMAGE, "release_notice": RELEASE_URL,
                  "image_observed": image if re.fullmatch(r"[0-9]{8}\.[0-9]{1,9}\.[0-9]{1,9}", image) else None,
                  "publication_authorized": False}
        with args.report.open("x", encoding="utf-8", newline="\n") as output:
            try:
                with TemporaryDirectory(prefix="clipforge-hosted-trial.", dir=root) as work:
                    evaluate(env, args.approved_commit, Path(work), report)
            except (OSError, ValueError, TypeError, KeyError, lzma.LZMAError, subprocess.SubprocessError) as error:
                report["error_code"] = str(error) if isinstance(error, docker.ToolchainBlocked) else type(error).__name__
                if isinstance(error, HTTPError):
                    report["http_status"] = error.code
            finally:
                output.write(json.dumps(report, sort_keys=True, separators=(",", ":")) + "\n")
        print(json.dumps({key: report[key] for key in ("status", "error_code") if key in report}))
        return int(report["status"] == "blocked")
    except (OSError, ValueError, KeyError) as error:
        print(json.dumps({"status": "blocked", "error_code": str(error) if isinstance(error, docker.ToolchainBlocked) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
