"""Offline Debian13 source/backport applicability experiment, never a VM install.

Only pinned public inputs are unpacked in a new external directory. A cached,
test-owned Debian13 CI image runs the signed-archive GNU patch binary with no
network. Applying an upstream diff is not proof of ABI safety or CVE resolution.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import uuid

ROOT = Path(__file__).resolve().parents[1]
CI_IMAGE = "sha256:f77e007bc94b1fb184f80886c7afb65ab98adfc01401e7609096b98850ca2372"
SOURCE_VERSION = "2.12.7+dfsg+really2.9.14-2.1+deb13u3"
PATCH_CANDIDATES = {
    "upstream": {"name": "libxml-upstream-fix.patch", "sha256": "1d0dd8a82e734830e2610f8bd7ccd21b02507206dcf9f9ed5ede28abe48b686d",
                 "origin": "GNOME upstream commit 463bbeeca1805b5c4828f50d0fefc4eebaf620df"},
    "reference_2_9_14": {"name": "CVE-2026-6653-reference.patch", "sha256": "6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54",
                         "origin": "Canonical source-only adaptation for libxml2 2.9.14; not a Debian binary or verified Debian fix"},
}
INPUTS = {
    "libxml2_2.12.7+dfsg+really2.9.14.orig.tar.xz": "4fe913dec8b1ab89d13b489b419a8203176ea39e931eaa0d25b17eafb9c279e9",
    "libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.debian.tar.xz": "3b6d265f482d6a8fbe3c056d2006fb3b563b4a838f7258b388ac5f0b29206921",
    "patch_2.8-2_amd64.deb": "80c46a0085b33acc74bf451fddb6a70cb43d4ebcc4a873aec04d8d0a63ffc630",
    "libxml-upstream-fix.patch": "1d0dd8a82e734830e2610f8bd7ccd21b02507206dcf9f9ed5ede28abe48b686d",
}


def require(ok, code):
    if not ok:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def safe_member(name):
    path = PurePosixPath(name)
    require(name and not path.is_absolute() and ".." not in path.parts and "\\" not in name and ":" not in name, "archive_path_unsafe")
    return path


def extract_archive(archive, destination, prefix):
    """Only directories/regular files, checked completely before first write."""
    with tarfile.open(archive, "r:xz") as stream:
        members = stream.getmembers(); require(0 < len(members) <= 12000, "archive_count")
        seen, total = set(), 0
        for item in members:
            path = safe_member(item.name)
            require(path.parts[0] == prefix and item.name not in seen and (item.isdir() or item.isfile()), "archive_type_or_prefix")
            require(0 <= item.size <= 16 * 1024 * 1024, "archive_file_size")
            seen.add(item.name); total += item.size
        require(total <= 128 * 1024 * 1024, "archive_total_size")
        for item in members:
            target = destination.joinpath(*PurePosixPath(item.name).parts)
            require(not target.is_symlink(), "archive_output_symlink")
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output, 65536)


def series_paths(source):
    rows = []
    for line in (source / "debian/patches/series").read_text().splitlines():
        name = line.split("#", 1)[0].strip()
        if not name:
            continue
        path = safe_member(name)
        require(re.fullmatch(r"[A-Za-z0-9_./+-]+", name) and path.parts[0] != "." and name not in rows, "unreviewed_series_options_or_duplicate")
        target = source / "debian/patches" / name
        require(target.is_file() and not target.is_symlink(), "series_regular_patch_required")
        rows.append(name)
    require(0 < len(rows) <= 100, "series_count")
    return rows


def apply_trial(work, candidate="upstream"):
    """Runs inside the dedicated network-none container, never at import time."""
    require(sys.platform.startswith("linux") and work == Path("/trial") and candidate in PATCH_CANDIDATES, "fixed_container_work_required")
    selection = PATCH_CANDIDATES[candidate]
    selected_patch = work / selection["name"]
    require(selected_patch.is_file() and not selected_patch.is_symlink() and selected_patch.stat().st_size <= 200000
            and sha(selected_patch.read_bytes()) == selection["sha256"], "pinned_candidate_patch_required")
    source, tool = work / "source/libxml2-2.9.14", work / "tools/usr/bin/patch"
    require(tool.is_file() and not tool.is_symlink() and source.is_dir(), "prepared_trial_inputs_required")
    # Native source work stays on Linux tmpfs, independent of Desktop bind utime.
    local = Path(tempfile.mkdtemp(prefix="db01-source-", dir="/work"))
    shutil.copytree(source, local / "source")
    shutil.copyfile(tool, local / "patch"); (local / "patch").chmod(0o755)
    source, tool = local / "source", local / "patch"
    import resource
    resource.setrlimit(resource.RLIMIT_FSIZE, (2 * 1024 * 1024, 2 * 1024 * 1024))
    report = {"schema": "clipforge-db01-libxml-source-trial-1", "source_version": SOURCE_VERSION,
        "status": "blocked", "package_built": False, "ABI_compatibility_proven": False, "CVE_resolution_proven": False,
        "install_on_VM_authorized": False, "network": "none", "source_work_filesystem": "private Linux tmpfs", "debian_patches": [],
        "patch_candidate": candidate, "candidate_patch_sha256": selection["sha256"], "candidate_patch_origin": selection["origin"]}
    for index, name in enumerate([*series_paths(source), "UPSTREAM"]):
        patch = selected_patch if name == "UPSTREAM" else source / "debian/patches" / name
        label = "upstream" if name == "UPSTREAM" else "debian-" + str(index + 1).zfill(3)
        args = [str(tool), "--batch", "--forward", "--fuzz=0", "-p1", "--directory", str(source), "--input", str(patch)]
        with (work / (label + ".stdout.log")).open("xb") as stdout, (work / (label + ".stderr.log")).open("xb") as stderr:
            try:
                result = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=60, check=False)
                exit_code = result.returncode
            except subprocess.TimeoutExpired:
                exit_code = None
            except OSError:
                exit_code = None
        raw = (work / (label + ".stdout.log")).read_bytes() + (work / (label + ".stderr.log")).read_bytes()
        require(len(raw) <= 2 * 1024 * 1024, "patch_diagnostic_limit")
        item = {"patch": name, "exit_code": exit_code, "timed_out": exit_code is None, "diagnostic_sha256": sha(raw),
            "failed_hunks": len(re.findall(rb"Hunk #[0-9]+ FAILED", raw)), "fuzz_allowed": False}
        if name == "UPSTREAM":
            report["upstream" if candidate == "upstream" else "reference_adaptation"] = item
            report["status"] = (("upstream_diff_applies_source_only_not_a_validated_package" if candidate == "upstream"
                else "reference_diff_applies_source_only_not_a_validated_package") if exit_code == 0
                else "blocked_native_patch_execution" if exit_code is None else "blocked_candidate_diff_requires_manual_backport")
        else:
            report["debian_patches"].append(item)
        if exit_code != 0:
            break
    with (work / "trial-summary.json").open("x") as stream:
        json.dump(report, stream, indent=2); stream.write("\n")
    return report


def run(inputs, output, candidate="upstream"):
    require(os.name == "nt" and inputs.is_absolute() and output.is_absolute() and not output.exists()
            and ROOT not in output.parents and output != ROOT, "new_external_windows_trial_directory_required")
    require(candidate in PATCH_CANDIDATES, "reviewed_patch_candidate_required")
    selected = PATCH_CANDIDATES[candidate]
    required_inputs = {**INPUTS, selected["name"]: selected["sha256"]}
    for name, expected in required_inputs.items():
        path = inputs / name
        require(path.is_file() and not path.is_symlink() and path.stat().st_size <= 32 * 1024 * 1024 and sha(path.read_bytes()) == expected, "pinned_public_input_mismatch")
    output.mkdir(); (output / "source").mkdir(); (output / "docker-config").mkdir()
    extract_archive(inputs / next(name for name in INPUTS if name.endswith("orig.tar.xz")), output / "source", "libxml2-2.9.14")
    extract_archive(inputs / next(name for name in INPUTS if name.endswith("debian.tar.xz")), output / "source/libxml2-2.9.14", "debian")
    shutil.copyfile(inputs / "libxml-upstream-fix.patch", output / "libxml-upstream-fix.patch")
    if candidate != "upstream":
        shutil.copyfile(inputs / selected["name"], output / selected["name"])
    shutil.copyfile(Path(__file__), output / "executor.py")
    nonce = uuid.uuid4().hex
    common = ["docker", "--config", str(output / "docker-config"), "--host", "npipe:////./pipe/dockerDesktopLinuxEngine",
        "run", "--rm", "--pull", "never", "--network", "none", "--user", "10001:10001", "--read-only", "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges", "--cpus", "1", "--memory", "1g", "--pids-limit", "64",
        "--label", "clipforge.db01.remediation=" + nonce, "--tmpfs", "/tmp:rw,nosuid,nodev,size=128m",
        "--tmpfs", "/work:rw,exec,nosuid,nodev,uid=10001,gid=10001,mode=0700,size=128m",
        "--mount", f"type=bind,src={inputs},dst=/inputs,readonly", "--mount", f"type=bind,src={output},dst=/trial"]
    commands = [common + ["--name", "clipforge-db01-patch-tool-" + nonce[:12], "--entrypoint", "/usr/bin/dpkg-deb", CI_IMAGE,
                         "-x", "/inputs/patch_2.8-2_amd64.deb", "/trial/tools"],
                common + ["--name", "clipforge-db01-libxml-trial-" + nonce[:12], "--entrypoint", "/usr/local/bin/python", CI_IMAGE,
                          "/trial/executor.py", "apply", "--output", "/trial", "--candidate", candidate]]
    for index, args in enumerate(commands):
        with (output / ("container-" + str(index) + ".stdout.log")).open("xb") as stdout, (output / ("container-" + str(index) + ".stderr.log")).open("xb") as stderr:
            result = subprocess.run(args, stdout=stdout, stderr=stderr, timeout=180, check=False)
        require(result.returncode == 0, "isolated_trial_container_failed")
    return json.loads((output / "trial-summary.json").read_bytes())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "apply"))
    parser.add_argument("--inputs", type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--candidate", choices=tuple(PATCH_CANDIDATES), default="upstream")
    args = parser.parse_args()
    report = apply_trial(args.output, args.candidate) if args.operation == "apply" else run(args.inputs, args.output, args.candidate)
    print(json.dumps({"status": report["status"], "package_built": report["package_built"], "CVE_resolution_proven": False}))


if __name__ == "__main__":
    main()
