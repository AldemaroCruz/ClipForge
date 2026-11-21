"""Build and execute the exact, one-shot Noble linux-tools-common intervention."""

import argparse
import base64
from contextlib import contextmanager
from hashlib import sha256
import http.client
import json
import os
from pathlib import Path
import re
import sys
import tempfile
import time

if "apt_checks" not in globals():
    from scripts import int_noble_demo_preflight_guest as apt_checks


DEB = "linux-tools-common_6.8.0-151.151_all.deb"
SIZE = 551716
DIGEST = "953d51879d4690a59138d9f2ec933bd703c928d75c4448681a7880d323bc7579"
SIGNED_INDEX = "c804e534950988a2af91a14e2d74a0f530b5458ba0354a8cbb61c68aeab3797e"
ORIGIN = "archive.ubuntu.com"
RELEASE = "7.0.0-1017-gcp"
GUEST_BOOT = "e1a4fb53-1970-490b-af37-5cccbbc99f32"
INSTANCE = "7365414160255801909"
BOOT_DISK = "8897353356069952044"
DATA_DISK = "7382984635240536620"
READINESS = "63406f8a35d85e89ae83dacc437e76e922dd19b58eb820716ae5251df930000f"
ROOT = Path("/root")
INTENT = ROOT / "clipforge-noble-apt-6.8.0-151.151.intent.json"
RECEIPT = ROOT / "clipforge-noble-apt-6.8.0-151.151.receipt.json"
INPUT = "clipforge-int-noble-apt-input-1"
APT_COMMAND = ["/usr/bin/apt-get", *apt_checks.APT_NO_CACHE, "--no-download",
               "--no-install-recommends", "--no-remove", "--only-upgrade"]
INSTALL_ERRORS = {
    "dpkg_lock_unavailable": r"^dpkg: error: .*(?:lock|another process).*$",
    "dpkg_dependency_rejected": r"^dpkg: dependency problems prevent configuration of linux-tools-common:$",
    "dpkg_install_error": r"^dpkg: error processing archive .+$",
}
METADATA = {
    "project/project-id": "clipforgebeta2",
    "project/numeric-project-id": "816643438938",
    "instance/id": INSTANCE,
    "instance/name": "clipforge-int-db01-noble",
    "instance/zone": "projects/816643438938/zones/us-central1-a",
}


class Blocked(ValueError):
    """A closed diagnostic code safe for the operation receipt."""


def require(condition, code):
    if not condition:
        raise Blocked(code)


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":")).encode("ascii")


def request(raw, operator_sha256):
    require(0 < len(raw) <= 4096, "apt_input_size")
    value = json.loads(raw.decode("ascii"))
    expected = {"schema": INPUT, "operation": "upgrade_reviewed_linux_tools_common_once", "instance_id": INSTANCE,
                "boot_disk_id": BOOT_DISK, "data_disk_id": DATA_DISK, "boot_id": GUEST_BOOT,
                "readiness_sha256": READINESS, "operator_sha256": operator_sha256,
                "signed_index_sha256": SIGNED_INDEX, "package_sha256": DIGEST}
    require(re.fullmatch(r"[a-f0-9]{64}", operator_sha256) and isinstance(value, dict)
            and set(value) == set(expected) | {"operation_id", "approved_commit", "owner_decision_sha256"}
            and all(value[key] == field for key, field in expected.items()), "apt_input_scope")
    require(re.fullmatch(r"[a-z][a-z0-9-]{15,63}", value["operation_id"])
            and re.fullmatch(r"[a-f0-9]{40}", value["approved_commit"])
            and re.fullmatch(r"[a-f0-9]{64}", value["owner_decision_sha256"])
            and canonical(value) in {raw, raw.rstrip(b"\n")}, "apt_input_approval_or_canonical_form")
    return value


def guest_identity(expected_boot=GUEST_BOOT):
    current_boot, release = apt_checks.kernel.identity()
    require(os.geteuid() == 0 and release == RELEASE and (expected_boot is None or current_boot == expected_boot), "apt_guest_boot_or_actor")
    connection = http.client.HTTPConnection("169.254.169.254", timeout=3)
    try:
        for path, expected in METADATA.items():
            connection.request("GET", "/computeMetadata/v1/" + path, headers={"Metadata-Flavor": "Google"})
            response = connection.getresponse()
            require(response.status == 200 and response.getheader("Metadata-Flavor") == "Google"
                    and response.read(256).decode("ascii").strip() == expected, "apt_guest_metadata_identity")
    finally:
        connection.close()
    return current_boot


def package_bytes():
    connection = http.client.HTTPSConnection(ORIGIN, timeout=8)
    end = time.monotonic() + 12
    try:
        connection.request("GET", "/ubuntu/pool/main/l/linux/" + DEB)
        response = connection.getresponse()
        require(response.status == 200, "apt_archive_http_" + str(response.status))
        data = bytearray()
        while len(data) <= SIZE and time.monotonic() < end:
            chunk = response.read1(min(65536, SIZE + 1 - len(data)))
            if not chunk:
                require(len(data) == SIZE and sha256(data).hexdigest() == DIGEST, "apt_package_identity")
                return data
            data.extend(chunk)
        raise Blocked("apt_package_size_or_time_limit")
    finally:
        connection.close()


@contextmanager
def apt_scratch(package):
    mountinfo = apt_checks.kernel.read("/proc/self/mountinfo", 262144).splitlines()
    scratch = Path("/dev/shm")
    mounts = [line for line in mountinfo if line.split()[4] == str(scratch)]
    require(len(mounts) == 1 and mounts[0].split(" - ", 1)[1].split()[0] == "tmpfs"
            and scratch.is_dir() and not scratch.is_symlink() and scratch.stat().st_uid == 0, "apt_tmpfs_required")
    require(len(package) == SIZE and sha256(package).hexdigest() == DIGEST, "apt_package_identity")
    with tempfile.TemporaryDirectory(prefix="clipforge-noble-apt-", dir=scratch) as directory:
        top = Path(directory)
        conf = top / "apt.conf"
        for name in ("lists", "parts", "sourceparts", "preferencesparts", "archives/partial"):
            (top / name).mkdir(parents=True)
        for name in ("main.conf", "sources.list", "preferences"):
            (top / name).touch()
        conf.write_text(f'''Dir::Etc::Parts "{top / 'parts'}";
Dir::Etc::Main "{top / 'main.conf'}";
Dir::Etc::sourcelist "{top / 'sources.list'}";
Dir::Etc::sourceparts "{top / 'sourceparts'}";
Dir::Etc::preferences "{top / 'preferences'}";
Dir::Etc::preferencesparts "{top / 'preferencesparts'}";
Dir::State::Lists "{top / 'lists'}";
Dir::State::status "/var/lib/dpkg/status";
Dir::Cache::archives "{top / 'archives'}";
''', encoding="ascii")
        deb = top / DEB
        deb.write_bytes(package)
        yield deb, {**apt_checks.kernel.ENVIRONMENT, "APT_CONFIG": str(conf), "TMPDIR": str(top),
                    "DEBIAN_FRONTEND": "noninteractive"}


def observed_packages():
    audit = apt_checks.run_diagnostic(["/usr/bin/dpkg", "--audit"], budget=8, limit=32768)
    require(audit == ("exited", 0, "", ""), "apt_dpkg_audit_not_clean")
    result = apt_checks.run_diagnostic(["/usr/bin/dpkg-query", "-W", "-f=${binary:Package}\\t${Version}\\t${db:Status-Status}\\n"],
                                       budget=10, limit=262144)
    require(result[0] == "exited" and result[1] == 0 and not result[3], "apt_dpkg_inventory")
    rows = {}
    for line in result[2].splitlines():
        parts = line.split("\t")
        require(len(parts) == 3 and parts[0] not in rows, "apt_dpkg_inventory_row")
        rows[parts[0]] = tuple(parts[1:])
    target = rows.pop(apt_checks.PACKAGE, ())
    require(target in {(apt_checks.CURRENT, "installed"), (apt_checks.TARGET, "installed")}, "apt_target_state")
    require(all(rows.get(name, (None, None))[1] == "installed" for name in ("lsb-release", "hwdata")), "apt_dependency_state")
    return target[0], sha256(canonical(rows)).hexdigest()


def save_record(path, value):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(canonical(value) + b"\n")
        stream.flush()
        os.fsync(stream.fileno())
    disk = os.open(ROOT, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(disk)
    finally:
        os.close(disk)


def save_intent(value):
    save_record(INTENT, value)


def execute(value):
    receipt = {"schema": "clipforge-int-noble-apt-receipt-1", "status": "blocked_before_install", "launch_intent": False,
               "operation_id": value["operation_id"], "approved_commit": value["approved_commit"],
               "owner_decision_sha256": value["owner_decision_sha256"], "request_sha256": sha256(canonical(value)).hexdigest(),
               "instance_id": INSTANCE, "boot_disk_id": BOOT_DISK, "data_disk_id": DATA_DISK, "boot_id": GUEST_BOOT,
               "kernel": RELEASE, "package": apt_checks.PACKAGE, "package_sha256": DIGEST, "signed_index_sha256": SIGNED_INDEX,
               "download_verified": False, "simulation": None, "install": None, "postcheck": None, "temp_released": None}
    result = None
    try:
        guest_identity()
        require(not os.path.lexists(INTENT) and not os.path.lexists(RECEIPT), "apt_intent_exists_reconcile")
        version, rest = observed_packages()
        require(version == apt_checks.CURRENT, "apt_not_at_reviewed_installed_version")
        with apt_scratch(package_bytes()) as (deb, env):
            receipt["download_verified"] = True
            receipt["temp_released"] = False
            result = apt_checks.run_diagnostic([*APT_COMMAND, "-s", "install", str(deb)], budget=20, environment=env)
            receipt["simulation"] = apt_checks.upgrade(result, version)
            require(receipt["simulation"]["exact_upgrade"], "apt_scope_not_exact")
            require(observed_packages() == (version, rest) and sha256(deb.read_bytes()).hexdigest() == DIGEST, "apt_drift_after_simulation")
            intent = {"schema": "clipforge-int-noble-apt-intent-1", "request_sha256": receipt["request_sha256"],
                      "approved_commit": value["approved_commit"], "owner_decision_sha256": value["owner_decision_sha256"],
                      "simulation": receipt["simulation"], "operation_id": value["operation_id"], "package_sha256": DIGEST,
                      "boot_id": GUEST_BOOT, "other_package_states_sha256": rest}
            save_intent(intent)
            receipt["launch_intent"] = True
            receipt["status"] = "install_outcome_unknown_reconcile"
            receipt["intent_sha256"] = sha256(canonical(intent) + b"\n").hexdigest()
            # APT validates the delta. dpkg's native lock then protects installation of only this local archive.
            result = apt_checks.run_diagnostic(["/usr/bin/dpkg", "--install", str(deb)], budget=120, environment=env)
            receipt["install"] = {"tool": "dpkg", **apt_checks.sanitized(result, INSTALL_ERRORS)}
            require(result[1] == 0, "apt_install_exit_requires_reconciliation")
            later, rest_after = observed_packages()
            guest_identity()
            receipt["postcheck"] = {"installed": later, "other_package_states_equal": rest == rest_after,
                                    "other_package_states_sha256": rest_after, "dpkg_clean": True, "same_boot_and_kernel": True}
            require(later == apt_checks.TARGET and rest == rest_after, "apt_postcheck_scope_mismatch")
        receipt["temp_released"] = not deb.parent.exists()
        require(receipt["temp_released"], "apt_tmpfs_cleanup_unconfirmed")
        verified = {**receipt, "status": "updated_exact_package"}
        save_record(RECEIPT, verified)
        return verified
    except (OSError, UnicodeError, http.client.HTTPException, ValueError) as error:
        receipt["error"] = str(error) if isinstance(error, Blocked) else type(error).__name__
        if receipt["temp_released"] is False and 'deb' in locals():
            receipt["temp_released"] = not deb.parent.exists()
    return receipt


def build_payload(root):
    sources = {name: (root / name).read_bytes().replace(b"\r\n", b"\n") for name in (
        "int_noble_kernel_guest.py", "int_noble_demo_preflight_guest.py", "int_noble_guest_apt.py")}
    kernel, preflight, operator = (base64.b64encode(value) for value in sources.values())
    return ("import base64, sys, types\n"
            "_noble_kernel_reads = types.ModuleType('_clipforge_noble_kernel_reads')\n"
            "sys.modules[_noble_kernel_reads.__name__] = _noble_kernel_reads\n"
            f"exec(compile(base64.b64decode({kernel!r}), '<noble-kernel>', 'exec'), _noble_kernel_reads.__dict__)\n"
            "apt_checks = types.ModuleType('_clipforge_noble_apt_checks')\n"
            "apt_checks._noble_kernel_reads = _noble_kernel_reads\n"
            f"exec(compile(base64.b64decode({preflight!r}), '<noble-apt-checks>', 'exec'), apt_checks.__dict__)\n"
            f"exec(compile(base64.b64decode({operator!r}), '<noble-apt-operation>', 'exec'), globals())\n").encode("ascii")


def guest_entry():
    try:
        value = request(sys.stdin.buffer.read(4097), DB01_OPERATOR_SHA256)
        receipt = execute(value)
    except (ValueError, KeyError, TypeError, OSError) as error:
        receipt = {"status": "blocked_before_install", "error": str(error) if isinstance(error, Blocked) else type(error).__name__}
    print(canonical(receipt).decode("ascii"), flush=True)
    return 0 if receipt["status"] == "updated_exact_package" else 1


if __name__ == "__main__":
    if "DB01_OPERATOR_SHA256" in globals():
        raise SystemExit(guest_entry())
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--render-payload", type=Path, required=True)
    arguments = parser.parse_args()
    raw = build_payload(Path(__file__).resolve().parent)
    with arguments.render_payload.open("xb") as output:
        output.write(raw)
    print(sha256(raw).hexdigest())
