"""Measure and compare the exact Ubuntu runner used for native OCI publication."""

from hashlib import sha256
import argparse
import json
import os
from pathlib import Path
import re
import selectors
import ssl
import stat
import subprocess
import sys
import time
import uuid


SCHEMA = "clipforge-int-demo-a-native-publication-host-2"
HEX = re.compile(r"[0-9a-f]{64}")
IMAGE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+")
RELEASE = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)-([0-9]{1,6})-([a-z0-9-]+)")
REVISION = re.compile(r"7\.0\.0-([0-9]{4})\.([0-9]+)~24\.04\.([0-9]+)")
# USN-9020-1 (AWS) and USN-9160-1 (Azure), for Noble amd64.
# Each exact live release and applicable finding still requires review.
REVIEWABLE_REVISION = {"aws": (1017, 18, 1), "azure": (1020, 21, 2)}
MODULES = {"siw": "CONFIG_RDMA_SIW", "ib_core": "CONFIG_INFINIBAND", "ib_uverbs": "CONFIG_INFINIBAND_USER_ACCESS",
           "rdma_cm": "CONFIG_INFINIBAND_ADDR_TRANS"}
KERNEL_CONFIG = set(MODULES.values()) | {"CONFIG_INET", "CONFIG_IO_URING", "CONFIG_BPF_SYSCALL", "CONFIG_USER_NS"}
CONTROL_PATHS = {
    "modules_disabled": "/proc/sys/kernel/modules_disabled",
    "unprivileged_bpf_disabled": "/proc/sys/kernel/unprivileged_bpf_disabled",
    "unprivileged_userns_clone": "/proc/sys/kernel/unprivileged_userns_clone",
}
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


def parsed_release(release):
    match = RELEASE.fullmatch(release) if isinstance(release, str) else None
    return (match[1], match[2], match[3]) if match else (None, None, None)


def kernel_family(release):
    _, _, flavor = parsed_release(release)
    if flavor is None:
        return None if release is None else "unknown"
    return flavor.split("-")[0] if flavor.split("-")[0] in REVIEWABLE_REVISION else "unknown"


def kernel(release, signature, version):
    base, abi, flavor = parsed_release(release)
    family = kernel_family(release)
    require(family in REVIEWABLE_REVISION, "native_publication_kernel_family_unsupported")
    require(base == "7.0.0" and flavor == family, "native_publication_kernel_abi_unsupported")
    revision = REVISION.fullmatch(version) if isinstance(version, str) else None
    require(revision and abi == revision[1] and tuple(map(int, revision.groups())) >= REVIEWABLE_REVISION[family],
            "native_publication_kernel_below_reviewable_floor")
    require(isinstance(signature, str) and re.fullmatch(
            r"Ubuntu " + re.escape(version) + "-" + family + r" [0-9]+\.[0-9]+\.[0-9]+(?:[.0-9+~-]+)?", signature),
            "native_publication_running_kernel_revision_mismatch")
    return {"release": release, "signature": signature, "package": "linux-image-" + release, "version": version}


def checked_kernel_packages(boot, family):
    release, version = boot["release"], boot["version"]
    package_sources = {boot["package"]: f"linux-signed-{family}-7.0",
                       "linux-modules-" + release: f"linux-{family}-7.0",
                       "linux-modules-extra-" + release: f"linux-{family}-7.0"}
    rows = boot["packages"]
    require(isinstance(rows, list) and 2 <= len(rows) <= 3 and all(
            isinstance(row, list) and len(row) == 4 and isinstance(row[0], str)
            and row[0].removesuffix(":amd64") in package_sources
            and row[1:] == [version, package_sources[row[0].removesuffix(":amd64")], version] for row in rows),
            "native_publication_running_kernel_packages_mismatch")
    names = {row[0].removesuffix(":amd64") for row in rows}
    require(len(names) == len(rows) and {boot["package"], "linux-modules-" + release} <= names,
            "native_publication_running_kernel_packages_incomplete")


def checked(value):
    require(isinstance(value, dict) and set(value) == {
        "schema", "complete", "image_version", "os", "architecture", "family", "kernel", "module_evidence", "tools",
        "inventory", "socket", "uid", "groups"
    } and value["schema"] == SCHEMA and value["complete"] is True and value["os"] == "ubuntu24"
            and value["architecture"] == "x86_64" and isinstance(value["image_version"], str)
            and IMAGE.fullmatch(value["image_version"]) and type(value["uid"]) is int and value["uid"] > 0
            and isinstance(value["groups"], list) and value["groups"] == sorted(set(value["groups"]))
            and all(type(group) is int and group >= 0 for group in value["groups"]),
            "native_publication_host_projection")
    boot = value["kernel"]
    require(isinstance(boot, dict) and set(boot) == {"release", "abi", "signature", "package", "version", "packages"},
            "native_publication_kernel_fields")
    expected = kernel(boot["release"], boot["signature"], boot["version"])
    require(all(boot[key] == expected[key] for key in expected) and boot["abi"] == parsed_release(boot["release"])[1]
            and value["family"] == kernel_family(boot["release"]), "native_publication_kernel_fields")
    checked_kernel_packages(boot, value["family"])
    checked_module_evidence(value["module_evidence"])
    tools = value["tools"]
    require(isinstance(tools, dict), "native_publication_host_tools")
    nodes = set(tools) - LIVE_COMPONENTS
    require(LIVE_COMPONENTS <= set(tools) and nodes and all(re.fullmatch("node[0-9]{2}", name) for name in nodes)
            and all(isinstance(item, dict) and set(item) == {"sha256", "bytes"} and HEX.fullmatch(item["sha256"])
                    and type(item["bytes"]) is int and 0 < item["bytes"] <= 256 * 1024 * 1024
                    for item in tools.values()), "native_publication_host_tools")
    inventory = value["inventory"]
    require(isinstance(inventory, dict) and set(inventory) == {"sha256", "packages"} and HEX.fullmatch(inventory["sha256"]) and
            type(inventory["packages"]) is int and 0 < inventory["packages"] <= 20000, "native_publication_host_inventory")
    socket = value["socket"]
    require(socket is None or isinstance(socket, dict) and set(socket) == {"mode", "uid", "gid"} and
            all(type(socket[key]) is int and socket[key] >= 0 for key in socket), "native_publication_socket_projection")
    return value


def file_identity(path):
    path = path.resolve(strict=True)
    before = path.stat()
    require(stat.S_ISREG(before.st_mode) and 0 < before.st_size <= 256 * 1024 * 1024, "native_publication_tool_file")
    hashed = sha256()
    count = 0
    expires = time.monotonic() + 8
    with path.open("rb") as stream:
        while block := stream.read(1024 * 1024):
            count += len(block)
            require(count <= before.st_size, "native_publication_tool_size_changed")
            require(time.monotonic() < expires, "native_publication_tool_deadline")
            hashed.update(block)
    after = path.stat()
    require(count == before.st_size and (before.st_dev, before.st_ino, before.st_mtime_ns, before.st_ctime_ns)
            == (after.st_dev, after.st_ino, after.st_mtime_ns, after.st_ctime_ns), "native_publication_tool_changed")
    return {"sha256": hashed.hexdigest(), "bytes": count}


def package_inventory():
    query = r"${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\t${db:Status-Status}\n"
    raw = bytearray()
    limit = 2 * 1024 * 1024
    expires = time.monotonic() + 15
    with subprocess.Popen(["/usr/bin/dpkg-query", "-W", "-f=" + query],
                          env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
                          stdout=subprocess.PIPE, stderr=subprocess.DEVNULL) as proc:
        try:
            with selectors.DefaultSelector() as reader:
                reader.register(proc.stdout, selectors.EVENT_READ)
                while True:
                    remaining = expires - time.monotonic()
                    require(remaining > 0 and reader.select(remaining), "native_publication_dpkg_deadline")
                    block = os.read(proc.stdout.fileno(), min(65536, limit - len(raw) + 1))
                    if not block:
                        break
                    raw.extend(block)
                    require(len(raw) <= limit, "native_publication_dpkg_bound")
            require(proc.wait(timeout=max(0.01, expires - time.monotonic())) == 0, "native_publication_dpkg_exit")
        finally:
            if proc.poll() is None:
                proc.kill()
    require(raw, "native_publication_dpkg_empty")
    rows = [line.split("\t") for line in raw.decode("ascii").splitlines()]
    require(all(len(row) == 5 for row in rows), "native_publication_dpkg_shape")
    active = sorted(row[:4] for row in rows if row[4] == "installed")
    require(len({row[0] for row in active}) == len(active), "native_publication_dpkg_duplicate")
    return active


def bounded_text(path, limit):
    with Path(path).open(encoding="ascii") as stream:
        raw = stream.read(limit + 1)
    require(len(raw) <= limit, "native_publication_read_bound")
    return raw


def runner_executables():
    pid = os.getppid()
    for _ in range(12):
        proc = Path("/proc") / str(pid)
        try:
            path = Path(os.readlink(proc / "exe"))
        except OSError:
            path = None
        if path and path.name == "Runner.Worker" and path.parent.name == "bin":
            paths = sorted((path.parent.parent / "externals").glob("node[0-9][0-9]/bin/node"))
            require(len(paths) <= 8, "native_publication_runner_node_bound")
            return {"runner_worker": path, **{item.parent.parent.name: item for item in paths}}
        pid = int(bounded_text(proc / "stat", 8192).rsplit(")", 1)[1].split()[1])
        if pid <= 1:
            break
    raise HostBlocked("native_publication_runner_worker_missing")


def ssl_dependencies():
    libraries = {}
    # The same Python process performs TLS readbacks and drives the credentialed operator.
    ssl.create_default_context()
    for line in bounded_text("/proc/self/maps", 262144).splitlines():
        fields = line.split(maxsplit=5)
        file_path = fields[5] if len(fields) == 6 else ""
        if not file_path.startswith("/"):
            continue
        match = re.match(r"(libssl|libcrypto|libc)\.so\.", Path(file_path).name)
        if match:
            name = match[1]
            require(name not in libraries or libraries[name] == Path(file_path), "native_publication_tls_library_ambiguous")
            libraries[name] = Path(file_path)
    return libraries


def capture(errors, field, reader):
    try:
        return reader()
    except HostBlocked as error:
        errors[field] = str(error)
    except (OSError, ValueError, TypeError, LookupError, subprocess.SubprocessError) as error:
        errors[field] = type(error).__name__
    return None


def token(value, pattern):
    require(isinstance(value, str) and re.fullmatch(pattern, value), "native_publication_fact_shape")
    return value


def config_items(release):
    raw = bounded_text(f"/boot/config-{release}", 1024 * 1024)
    found = {}
    for line in raw.splitlines():
        enabled = re.fullmatch(r"(CONFIG_[A-Z0-9_]+)=([ymn])", line)
        disabled = re.fullmatch(r"# (CONFIG_[A-Z0-9_]+) is not set", line)
        if enabled and enabled[1] in KERNEL_CONFIG:
            found[enabled[1]] = enabled[2]
        if disabled and disabled[1] in KERNEL_CONFIG:
            found[disabled[1]] = "n"
    return {"sha256": sha256(raw.encode("ascii")).hexdigest(),
            "values": {name: found.get(name) for name in sorted(KERNEL_CONFIG)}}


def named_modules(raw):
    matches = set()
    for line in raw.splitlines():
        path = line.split(":", 1)[0].rsplit("/", 1)[-1]
        module = path.split(".ko", 1)[0].replace("-", "_")
        if module in MODULES:
            matches.add(module)
    return sorted(matches)


def loaded_modules():
    lines = bounded_text("/proc/modules", 524288).splitlines()
    names = {line.split(" ", 1)[0] for line in lines}
    return sorted(names & MODULES.keys())


def rdma_devices(path):
    try:
        directory = os.scandir(path)
    except FileNotFoundError:
        return {"present": False, "count": 0}
    count = 0
    with directory:
        for count, _ in enumerate(directory, start=1):
            require(count <= 128, "native_publication_rdma_device_bound")
    return {"present": True, "count": count}


def process_capabilities():
    raw = bounded_text("/proc/self/status", 65536)
    values = dict(line.split(":", 1) for line in raw.splitlines() if ":" in line)
    names = ("CapEff", "CapBnd", "NoNewPrivs")
    return {name: token(values[name].strip(), r"[01]" if name == "NoNewPrivs" else r"[0-9a-f]{16}") for name in names}


def collect_modules(errors, release):
    return {
        "profile_configs": capture(errors, "kernel_config", lambda: config_items(release)) if release else None,
        "loaded": capture(errors, "modules_loaded", loaded_modules),
        "builtin": capture(errors, "modules_builtin", lambda: named_modules(
            bounded_text(f"/lib/modules/{release}/modules.builtin", 2 * 1024 * 1024))) if release else None,
        "packaged": capture(errors, "modules_packaged", lambda: named_modules(
            bounded_text(f"/lib/modules/{release}/modules.dep", 4 * 1024 * 1024))) if release else None,
        "rdma": {name: capture(errors, "device_" + name, lambda: rdma_devices(path)) for name, path in {
            "interfaces": "/sys/class/infiniband", "userspace": "/dev/infiniband"}.items()},
        "kernel_controls": {name: capture(errors, "control_" + name, lambda: token(bounded_text(path, 16).strip(), r"[0-2]"))
                            for name, path in CONTROL_PATHS.items()},
        "process_capabilities": capture(errors, "process_capabilities", process_capabilities),
    }


def checked_module_evidence(value):
    code = "native_publication_module_evidence"
    require(isinstance(value, dict) and set(value) == {
        "profile_configs", "loaded", "builtin", "packaged", "rdma", "kernel_controls", "process_capabilities"}, code)
    config = value["profile_configs"]
    require(isinstance(config, dict) and set(config) == {"sha256", "values"} and HEX.fullmatch(config["sha256"])
            and set(config["values"]) == KERNEL_CONFIG
            and all(item in {"y", "m", "n", None} for item in config["values"].values()), code)
    for name in ("loaded", "builtin", "packaged"):
        modules = value[name]
        require(isinstance(modules, list) and sorted(set(modules)) == modules and set(modules) <= MODULES.keys(), code)
    controls = value["kernel_controls"]
    require(isinstance(controls, dict) and set(controls) == CONTROL_PATHS.keys()
            and all(item in {"0", "1", "2"} for item in controls.values()), code)
    caps = value["process_capabilities"]
    require(isinstance(caps, dict) and set(caps) == {"CapEff", "CapBnd", "NoNewPrivs"} and caps["NoNewPrivs"] in {"0", "1"}
            and all(re.fullmatch(r"[0-9a-f]{16}", caps[name]) for name in ("CapEff", "CapBnd")), code)
    require(isinstance(value["rdma"], dict) and set(value["rdma"]) == {"interfaces", "userspace"} and all(
        isinstance(result, dict) and set(result) == {"present", "count"} and type(result["present"]) is bool
        and type(result["count"]) is int and 0 <= result["count"] <= 128
        and (result["present"] or result["count"] == 0) for result in value["rdma"].values()), code)


def docker_socket():
    try:
        info = Path("/run/docker.sock").lstat()
    except FileNotFoundError:
        return None
    require(stat.S_ISSOCK(info.st_mode), "native_publication_docker_socket_shape")
    return {"mode": stat.S_IMODE(info.st_mode), "uid": info.st_uid, "gid": info.st_gid}


def snapshot(env, job):
    errors = {}
    if not (env.get("ImageOS") == "ubuntu24" and env.get("RUNNER_ENVIRONMENT") == "github-hosted"
            and env.get("GITHUB_JOB") == job and env.get("GITHUB_RUN_ATTEMPT") == "1"):
        errors["runner_scope"] = "native_publication_hosted_runner_scope"
    identifiers = {name: capture(errors, name, lambda: token(env.get(key), pattern)) for name, key, pattern in (
        ("run", "GITHUB_RUN_ID", r"[0-9]{1,20}"), ("attempt", "GITHUB_RUN_ATTEMPT", r"[0-9]{1,8}"),
        ("job", "GITHUB_JOB", r"[A-Za-z0-9_-]{1,80}"), ("commit", "GITHUB_SHA", r"[0-9a-f]{40}"))}
    image = capture(errors, "image_version", lambda: token(env.get("ImageVersion"), r"[0-9.]{5,40}"))
    observed_os = capture(errors, "image_os", lambda: token(env.get("ImageOS"), r"[A-Za-z0-9_.-]{1,40}"))
    uid = capture(errors, "uid", os.getuid)
    groups = capture(errors, "groups", lambda: sorted(set([os.getgid(), *os.getgroups()])))
    identity = capture(errors, "python_path", lambda: Path(sys.executable).resolve(strict=True)
                       == Path(SYSTEM_FILES["python"]).resolve(strict=True))
    effective_uid = capture(errors, "euid", os.geteuid)
    if identity is not True or not uid or uid != effective_uid:
        errors["runner_user"] = "native_publication_runner_user"

    machine = capture(errors, "uname", os.uname)
    release = capture(errors, "kernel_release", lambda: token(machine.release, r"[A-Za-z0-9_.+-]{1,96}")) if machine else None
    arch = capture(errors, "architecture", lambda: token(machine.machine, r"[A-Za-z0-9_]{1,24}")) if machine else None
    signature = capture(errors, "kernel_signature", lambda: token(
        bounded_text("/proc/version_signature", 256).strip(), r"[A-Za-z0-9 ._+~()-]{1,255}"))
    boot_id = capture(errors, "boot_id", lambda: str(uuid.UUID(
        bounded_text("/proc/sys/kernel/random/boot_id", 128).strip())))
    inventory = capture(errors, "dpkg_inventory", package_inventory)
    image_package = "linux-image-" + release if release else None
    packages, version = None, None
    if release and inventory is not None:
        names = {image_package, "linux-image-unsigned-" + release, "linux-modules-" + release,
                 "linux-modules-extra-" + release}
        packages = [row for row in inventory if row[0].removesuffix(":amd64") in names]
        image_rows = [row for row in packages if row[0].removesuffix(":amd64") == image_package]
        if len(image_rows) == 1:
            version = image_rows[0][1]
        else:
            errors["kernel_package"] = "native_publication_running_image_package_missing_or_ambiguous"
    module_evidence = collect_modules(errors, release)
    paths = {name: Path(path) for name, path in SYSTEM_FILES.items()}
    runner = capture(errors, "runner_executables", runner_executables) or {}
    if runner and len(runner) == 1:
        errors["runner_nodes"] = "native_publication_runner_node_missing"
    paths.update(runner)
    libraries = capture(errors, "tls_dependencies", ssl_dependencies) or {}
    for missing in sorted({"libssl", "libcrypto", "libc"} - libraries.keys()):
        errors[missing] = "native_publication_tls_library_missing"
    paths.update(libraries)
    tools = {name: capture(errors, "tool_" + name, lambda: file_identity(path)) for name, path in paths.items()}
    socket = capture(errors, "docker_socket", docker_socket)
    portable = {"schema": SCHEMA, "complete": not errors, "image_version": image, "os": observed_os,
                "architecture": arch, "family": kernel_family(release),
                "kernel": {"release": release, "abi": parsed_release(release)[1], "signature": signature,
                           "package": image_package, "version": version, "packages": packages},
                "module_evidence": module_evidence, "tools": tools,
                "inventory": {"sha256": digest(inventory), "packages": len(inventory)} if inventory is not None else None,
                "socket": socket, "uid": uid, "groups": groups}
    return {"host": portable, "boot_id": boot_id, **identifiers, "errors": errors}, inventory


def verify(env, expected, previous=None):
    live, _ = snapshot(env, "protected-operation")
    checked(live["host"])
    require(live["host"] == expected, "native_publication_host_unreviewed_or_changed")
    require(previous is None or live == previous, "native_publication_boot_or_context_changed")
    return live


def observe(env, path):
    credentialed = any(env.get(key) for key in ("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "ACTIONS_ID_TOKEN_REQUEST_URL",
                      "GCP_ACCESS_TOKEN", "GCP_READ_ACCESS_TOKEN", "GOOGLE_APPLICATION_CREDENTIALS",
                      "GOOGLE_GHA_CREDS_PATH", "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE"))
    errors = {}
    sample = None
    if credentialed:
        errors["scope"] = "native_publication_observation_credentialed"
    else:
        sample = capture(errors, "snapshot", lambda: snapshot(env, "observe-host"))
    live, inventory = sample if sample else ({"host": None, "errors": errors}, None)
    boot = live["host"]["kernel"] if live["host"] else {}
    profile_errors = {}
    capture(profile_errors, "kernel", lambda: kernel(boot.get("release"), boot.get("signature"), boot.get("version")))
    profile = {"status": "blocked" if profile_errors else "review_required", "errors": profile_errors}
    reason = next(iter(live["errors"].values()), None)
    try:
        require(not live["errors"], "native_publication_observation_read_failed")
        checked(live["host"])
    except HostBlocked as error:
        result = {"status": "host_rejected", "reason": reason or str(error)}
    else:
        result = {"status": "host_observed_review_required"}
    evidence = {**result, **live, "kernel_profile": profile, "binary_source_packages": inventory,
                "activation_authorized": False}
    raw = encoded_report(evidence)
    if len(raw) > 10 * 1024 * 1024:
        evidence["errors"]["observation"] = "native_publication_observation_bound"
        if evidence["host"]:
            evidence["host"]["complete"] = False
        evidence["binary_source_packages"] = None
        result = {"status": "host_rejected", "reason": "native_publication_observation_bound"}
        raw = encoded_report({**evidence, **result})
    with path.open("xb") as output:
        output.write(raw)
    print(json.dumps(result))
    return int(result["status"] != "host_observed_review_required")


def encoded_report(evidence):
    return (json.dumps(evidence, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


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
