"""Measure and compare the exact Ubuntu runner used for native OCI publication."""

from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import re
import ssl
import stat
import subprocess
import sys
import uuid


SCHEMA = "clipforge-int-demo-a-native-publication-host-1"
HEX = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
ABI = re.compile(r"7\.0\.0-([0-9]{4})-azure")
REVISION = re.compile(r"7\.0\.0-([0-9]{4})\.([0-9]+)~24\.04\.([0-9]+)")
# Lower bound from USN-9160-1. Each live release still needs an exact review.
MINIMUM_AZURE_REVISION = (1020, 21, 2)
SYSTEM_FILES = {
    "bash": "/usr/bin/bash",
    "dpkg_query": "/usr/bin/dpkg-query",
    "git": "/usr/bin/git",
    "python": "/usr/bin/python3",
    "setpriv": "/usr/bin/setpriv",
    "system_ca": "/etc/ssl/certs/ca-certificates.crt",
}
LIVE_COMPONENTS = set(SYSTEM_FILES) | {"runner_worker", "libssl", "libcrypto", "libc"}


class HostBlocked(ValueError):
    pass


def require(condition, code):
    if not condition:
        raise HostBlocked(code)


def digest(value):
    return sha256((json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")).hexdigest()


def kernel(release, signature, version):
    abi = ABI.fullmatch(release)
    revision = REVISION.fullmatch(version)
    require(abi and revision and abi[1] == revision[1]
            and tuple(map(int, revision.groups())) >= MINIMUM_AZURE_REVISION,
            "native_publication_kernel_below_reviewable_floor")
    require(re.fullmatch(r"Ubuntu " + re.escape(version) + r"-azure [0-9]+\.[0-9]+\.[0-9]+(?:[.0-9+~-]+)?", signature),
            "native_publication_running_kernel_revision_mismatch")
    return {"release": release, "signature": signature, "package": "linux-image-" + release, "version": version}


def checked(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "image_version", "os", "architecture", "kernel", "tools", "inventory", "socket", "uid", "groups"
    } and value["schema"] == SCHEMA and value["os"] == "ubuntu24" and value["architecture"] == "x86_64"
            and IMAGE.fullmatch(value["image_version"]) and type(value["uid"]) is int and value["uid"] > 0
            and isinstance(value["groups"], list) and value["groups"] == sorted(set(value["groups"]))
            and all(type(group) is int and group >= 0 for group in value["groups"]),
            "native_publication_host_projection")
    boot = value["kernel"]
    require(boot == kernel(boot["release"], boot["signature"], boot["version"]), "native_publication_kernel_fields")
    tools = value["tools"]
    nodes = set(tools) - LIVE_COMPONENTS
    require(LIVE_COMPONENTS <= set(tools) and nodes and all(re.fullmatch("node[0-9]{2}", name) for name in nodes)
            and all(isinstance(item, dict) and set(item) == {"sha256", "bytes"} and HEX.fullmatch(item["sha256"])
                    and type(item["bytes"]) is int and 0 < item["bytes"] <= 256 * 1024 * 1024
                    for item in tools.values()), "native_publication_host_tools")
    inventory = value["inventory"]
    require(set(inventory) == {"sha256", "packages"} and HEX.fullmatch(inventory["sha256"]) and
            type(inventory["packages"]) is int and 0 < inventory["packages"] <= 20000, "native_publication_host_inventory")
    socket = value["socket"]
    require(socket is None or set(socket) == {"mode", "uid", "gid"} and
            all(type(socket[key]) is int and socket[key] >= 0 for key in socket), "native_publication_socket_projection")
    return value


def file_identity(path):
    path = path.resolve(strict=True)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 256 * 1024 * 1024, "native_publication_tool_file")
    hashed = sha256()
    count = 0
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            count += len(block)
            require(count <= before.st_size, "native_publication_tool_size_changed")
            hashed.update(block)
    after = path.stat()
    require(count == before.st_size and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns), "native_publication_tool_changed")
    return {"sha256": hashed.hexdigest(), "bytes": count}


def package_inventory(release):
    query = r"${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n"
    result = subprocess.run(["/usr/bin/dpkg-query", "-W", "-f=" + query],
                            env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, check=True,
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=15)
    require(0 < len(result.stdout) <= 10 * 1024 * 1024, "native_publication_dpkg_bound")
    rows = [line.split("\t") for line in result.stdout.decode("ascii").splitlines()]
    require(all(len(row) == 5 for row in rows), "native_publication_dpkg_shape")
    active = sorted(row[:4] for row in rows if row[4] == "installed")
    require(len({row[0] for row in active}) == len(active), "native_publication_dpkg_duplicate")
    package = "linux-image-" + release
    version, = [row[1] for row in active if row[0] in {package, package + ":amd64"}]
    return version, active


def runner_executables():
    pid = os.getppid()
    for _ in range(12):
        proc = Path("/proc") / str(pid)
        path = Path(os.readlink(proc / "exe"))
        if path.name == "Runner.Worker" and path.parent.name == "bin":
            paths = sorted((path.parent.parent / "externals").glob("node[0-9][0-9]/bin/node"))
            require(0 < len(paths) <= 8, "native_publication_runner_node_missing")
            return {"runner_worker": path, **{item.parent.parent.name: item for item in paths}}
        pid = int((proc / "stat").read_text(encoding="ascii").rsplit(")", 1)[1].split()[1])
        if pid <= 1:
            break
    raise HostBlocked("native_publication_runner_worker_missing")


def ssl_dependencies():
    libraries = {}
    # The same Python process performs TLS readbacks and drives the credentialed operator.
    ssl.create_default_context()
    for line in Path("/proc/self/maps").read_text(encoding="ascii").splitlines():
        file_path = line.split(maxsplit=5)[-1]
        if not file_path.startswith("/"):
            continue
        match = re.match(r"(libssl|libcrypto|libc)\.so\.", Path(file_path).name)
        if match:
            name = match[1]
            require(name not in libraries or libraries[name] == Path(file_path), "native_publication_tls_library_ambiguous")
            libraries[name] = Path(file_path)
    require(set(libraries) == {"libssl", "libcrypto", "libc"}, "native_publication_tls_libraries_missing")
    return libraries


def docker_socket():
    try:
        info = Path("/run/docker.sock").lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISSOCK(info.st_mode), "native_publication_docker_socket_shape")
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def snapshot(env, job):
    require(env.get("ImageOS") == "ubuntu24" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_JOB") == job and env.get("GITHUB_RUN_ATTEMPT") == "1",
            "native_publication_hosted_runner_scope")
    require(Path(sys.executable).resolve(strict=True) == Path(SYSTEM_FILES["python"]).resolve(strict=True)
            and os.getuid() == os.geteuid() and os.getuid() > 0, "native_publication_runner_user")
    machine = os.uname()
    release = machine.release
    require(ABI.fullmatch(release), "native_publication_azure_kernel_family")
    version, inventory = package_inventory(release)
    signature = Path("/proc/version_signature").read_text(encoding="ascii").strip()
    paths = {name: Path(path) for name, path in SYSTEM_FILES.items()}
    paths.update(runner_executables())
    paths.update(ssl_dependencies())
    tools = {name: file_identity(path) for name, path in paths.items()}
    portable = {"schema": SCHEMA, "image_version": env["ImageVersion"], "os": env["ImageOS"],
                "architecture": machine.machine, "kernel": {"release": release, "signature": signature,
                                                            "package": "linux-image-" + release, "version": version},
                "tools": tools, "inventory": {"sha256": digest(inventory), "packages": len(inventory)},
                "socket": docker_socket(), "uid": os.getuid(), "groups": sorted(set([os.getgid(), *os.getgroups()]))}
    boot_id = str(uuid.UUID(Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()))
    return {"host": portable, "boot_id": boot_id, "run": env["GITHUB_RUN_ID"], "job": env["GITHUB_JOB"],
            "attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"]}, inventory


def verify(env, expected, previous=None):
    live, _ = snapshot(env, "protected-operation")
    checked(live["host"])
    require(live["host"] == expected, "native_publication_host_unreviewed_or_changed")
    require(previous is None or live == previous, "native_publication_boot_or_context_changed")
    return live


def observe(env, path):
    require(not any(env.get(key) for key in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                                            "GCP_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS")),
            "native_publication_observation_credentialed")
    try:
        live, inventory = snapshot(env, "observe-host")
    except HostBlocked as error:
        if str(error) != "native_publication_azure_kernel_family":
            raise
        result = {"status": "host_observation_blocked", "reason": str(error)}
        evidence = rejected_kernel_facts(env)
    else:
        try:
            checked(live["host"])
            result = {"status": "host_observed_review_required"}
        except HostBlocked as error:
            result = {"status": "host_rejected", "reason": str(error)}
        evidence = {**live, "binary_source_packages": inventory}
    raw = (json.dumps({**result, **evidence, "activation_authorized": False},
                      sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")
    require(len(raw) <= 10 * 1024 * 1024, "native_publication_observation_bound")
    with path.open("xb") as output:
        output.write(raw)
    print(json.dumps(result))
    return int(result["status"] != "host_observed_review_required")


def rejected_kernel_facts(env):
    machine = os.uname()
    require(re.fullmatch(r"[A-Za-z0-9_.+-]{1,96}", machine.release) and re.fullmatch(r"[A-Za-z0-9_]{1,24}", machine.machine),
            "native_publication_rejected_kernel_facts_shape")
    signature = None
    try:
        with Path("/proc/version_signature").open(encoding="ascii") as stream:
            candidate = stream.read(257).strip()
        if re.fullmatch(r"[A-Za-z0-9 ._+~()-]{1,255}", candidate):
            signature = candidate
    except (OSError, UnicodeError):
        pass
    image = env.get("ImageVersion", "")
    return {"schema": SCHEMA, "image_version": image if IMAGE.fullmatch(image) else None,
            "kernel_release": machine.release, "kernel_signature": signature, "architecture": machine.machine,
            "run": env["GITHUB_RUN_ID"], "attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"]}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observe", type=Path, required=True)
    args = parser.parse_args()
    try:
        return observe(os.environ, args.observe)
    except (OSError, ValueError, TypeError, KeyError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "host_observation_blocked",
                          "reason": str(error) if isinstance(error, HostBlocked) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
