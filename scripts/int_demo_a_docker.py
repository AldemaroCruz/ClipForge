"""Identify the root-owned Docker toolchain used by INT Demo A without a cloud token."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import subprocess
from tempfile import TemporaryDirectory


DOCKER = "/usr/bin/docker"
SOCKET = "/run/docker.sock"
PACKAGE_VERSIONS = {"docker-ce": "5:29.10.0-1~ubuntu.24.04~noble", "docker-ce-cli": "5:29.10.0-1~ubuntu.24.04~noble",
                    "containerd.io": "2.4.2-4~ubuntu.24.04~noble"}
BINARY_PACKAGES = {DOCKER: "docker-ce-cli", "/usr/bin/dockerd": "docker-ce", "/usr/bin/containerd": "containerd.io",
                   "/usr/bin/containerd-shim-runc-v2": "containerd.io", "/usr/bin/runc": "containerd.io"}
BINARIES = tuple(BINARY_PACKAGES)
SERVICE_BINARIES = {"docker.service": "/usr/bin/dockerd", "containerd.service": "/usr/bin/containerd"}
SCHEMA = "clipforge-int-demo-a-docker-toolchain-3"
STABLE_FIELDS = ("schema", "runner_image", "image_os", "platform", "context", "packages", "socket", "socket_security", "files",
                 "services", "native", "components", "engine_settings", "kernel")
OBSERVATION_FIELDS = {"repository", "source_commit", "run", "attempt", "job", "boot_id", "observed_utc", "files", "socket", "processes"}
FILE_METADATA = {"device": "st_dev", "inode": "st_ino", "mode": "st_mode", "uid": "st_uid", "gid": "st_gid", "bytes": "st_size",
                 "mtime_ns": "st_mtime_ns", "ctime_ns": "st_ctime_ns"}
LIVE_FIELDS = ("device", "inode", "mode", "uid", "gid", "bytes", "mtime", "ctime")
SHA256 = re.compile(r"[a-f0-9]{64}")
BOOT_ID = re.compile(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}")
DECIMAL = re.compile(r"[1-9][0-9]{0,19}")
SEMVER = re.compile(r"v?([0-9]+)\.([0-9]+)\.([0-9]+)")
AWS_NOBLE_KERNEL = re.compile(r"7\.0\.0-([0-9]+)\.([0-9]+)~24\.04\.([0-9]+)")


class ToolchainBlocked(ValueError):
    """A fixed diagnostic code for the staged publisher."""


def require(condition, error):
    if not condition:
        raise ToolchainBlocked(error)


def run(args, home, *, timeout=12):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C"}
    result = subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, "docker_toolchain_command_failed")
    return result.stdout.decode().strip()


def metadata(info):
    return {key: getattr(info, field) for key, field in FILE_METADATA.items()}


def identify_file(name):
    path = Path(name)
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    require(resolved.is_relative_to("/usr/bin") and stat.S_ISREG(before.st_mode) and before.st_uid == before.st_gid == 0
            and before.st_mode & 0o022 == 0 and before.st_mode & 0o111 != 0
            and 0 < before.st_size <= 256 * 1024 * 1024, "docker_toolchain_file_boundary")
    with resolved.open("rb") as data:
        digest = sha256()
        while block := data.read(1024 * 1024):
            digest.update(block)
        after = os.fstat(data.fileno())
        require(metadata(before) == metadata(after), "docker_toolchain_file_changed")
    identity = {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size,
                "mode": before.st_mode, "uid": before.st_uid, "gid": before.st_gid, "package": BINARY_PACKAGES[name]}
    return identity, metadata(after)


def endpoint(config):
    return [DOCKER, "--config", str(config), "--host", "unix://" + SOCKET]


def bounded_text(path, limit):
    with Path(path).open("rb") as stream:
        raw = stream.read(limit + 1)
    require(0 < len(raw) <= limit, "docker_toolchain_observation_bound")
    return raw.decode("utf-8")


def platform_identity(release):
    content = bounded_text("/etc/os-release", 8192).splitlines()
    os_rows = [line.split("=", 1) for line in content if line.startswith(("ID=", "VERSION_ID="))]
    require(len(os_rows) == 2 and {key: value.strip('"') for key, value in os_rows} == {"ID": "ubuntu", "VERSION_ID": "24.04"}
            and os.uname().machine == "x86_64", "docker_observed_platform")
    match = re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([a-z0-9-]{1,32})", release)
    require(match is not None, "docker_kernel_family_unidentified")
    return {"distribution": "ubuntu", "version": "24.04", "architecture": "amd64", "kernel_family": match[1]}


def package_identity(package, work):
    values = run(["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status} ${Version} ${Architecture}", package], work).split()
    require(len(values) == 3 and values[0] == "installed" and values[2] == "amd64"
            and re.fullmatch(r"[A-Za-z0-9:._+~-]{1,120}", values[1]), "docker_installed_package_identity")
    return values[1]


def process_start(raw, pid):
    first, marker, rest = raw.rpartition(") ")
    fields = rest.split()
    require(marker and first.startswith(f"{pid} (") and len(fields) > 19 and DECIMAL.fullmatch(fields[19]),
            "docker_live_pid_start_unavailable")
    return fields[19]


def live_metadata(raw):
    parts = raw.split()
    require(len(parts) == len(LIVE_FIELDS) and all(re.fullmatch(r"[0-9]+", value) for i, value in enumerate(parts) if i != 2)
            and re.fullmatch(r"[0-9a-f]+", parts[2]), "docker_live_executable_metadata")
    return {key: int(value, 16 if key == "mode" else 10) for key, value in zip(LIVE_FIELDS, parts)}


def live_from_file(file):
    return {**{key: file[key] for key in LIVE_FIELDS[:-2]}, "mtime": file["mtime_ns"] // 10**9, "ctime": file["ctime_ns"] // 10**9}


def live_service(unit, file, observed_file, work):
    service = ["/usr/bin/systemctl", "show", "--property=MainPID", "--value", unit]
    pid = run(service, work)
    require(DECIMAL.fullmatch(pid) and int(pid) <= 2**31 - 1, "docker_running_service_required")
    proc = f"/proc/{pid}"
    start = process_start(bounded_text(proc + "/stat", 8192), pid)
    executable = proc + "/exe"
    sudo = ["/usr/bin/sudo", "-n"]
    stat_command = [*sudo, "/usr/bin/stat", "-L", "--printf=%d %i %f %u %g %s %Y %Z", "--", executable]
    before = live_metadata(run(stat_command, work))
    path = run([*sudo, "/usr/bin/readlink", "--", executable], work)
    require(path == file["path"] and before == live_from_file(observed_file), "docker_running_executable_changed")
    checksum = run([*sudo, "/usr/bin/sha256sum", "--", executable], work).split()
    require(checksum == [file["sha256"], executable], "docker_running_executable_digest_changed")
    require(live_metadata(run(stat_command, work)) == before and run(service, work) == pid
            and process_start(bounded_text(proc + "/stat", 8192), pid) == start, "docker_running_service_changed_during_observation")
    return {**file, "path": path, "sha256": checksum[0]}, {"pid": pid, "start_ticks": start, "executable": before}


def inventory(env=os.environ):
    import grp

    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("ImageOS") == "ubuntu24"
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", env.get("ImageVersion", "")), "docker_exact_hosted_image")
    socket = Path(SOCKET).lstat()
    require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_mode & 0o007 == 0, "docker_local_root_socket")
    socket_security = {"mode": socket.st_mode, "uid": socket.st_uid, "group": grp.getgrgid(socket.st_gid).gr_name}
    hashes = {path: identify_file(path) for path in BINARIES}
    files = {path: identity for path, (identity, _) in hashes.items()}
    file_metadata = {path: record for path, (_, record) in hashes.items()}
    boot_path = "/proc/sys/kernel/random/boot_id"
    boot_id = bounded_text(boot_path, 64).strip()
    kernel = os.uname().release
    platform = platform_identity(kernel)
    package = "linux-image-" + kernel
    with TemporaryDirectory(prefix="docker-int-a-identity.") as work:
        cli = endpoint(work)
        context = {"name": run(cli + ["context", "show"], work), "endpoint": "unix://" + SOCKET}
        reported = json.loads(run(cli + ["version", "--format", "{{json .}}"], work))
        info_format = ('{"driver":{{json .Driver}},"driver_status":{{json .DriverStatus}},'
                       '"security":{{json .SecurityOptions}},"default_runtime":{{json .DefaultRuntime}},'
                       '"cgroup_version":{{json .CgroupVersion}}}')
        settings = json.loads(run(cli + ["info", "--format", info_format], work))
        measured = {unit: live_service(unit, files[path], file_metadata[path], work) for unit, path in SERVICE_BINARIES.items()}
        packages = {name: package_identity(name, work) for name in PACKAGE_VERSIONS}
        for path, identity in files.items():
            owner = run(["/usr/bin/dpkg-query", "-S", path], work)
            require(owner == f"{identity['package']}: {path}", "docker_executable_package_identity")
        kernel_version = package_identity(package, work)
    require(bounded_text(boot_path, 64).strip() == boot_id and metadata(Path(SOCKET).lstat()) == metadata(socket)
            and all(metadata(Path(path).stat()) == item for path, item in file_metadata.items()), "docker_host_changed_during_observation")
    versions, components = native_versions(reported)
    observation = {"repository": env.get("GITHUB_REPOSITORY"), "source_commit": env.get("GITHUB_SHA"), "run": env.get("GITHUB_RUN_ID"),
                   "attempt": env.get("GITHUB_RUN_ATTEMPT"), "job": env.get("GITHUB_JOB"), "boot_id": boot_id,
                   "observed_utc": datetime.now(timezone.utc).isoformat(), "files": file_metadata, "socket": metadata(socket),
                   "processes": {unit: state for unit, (_, state) in measured.items()}}
    result = {"schema": SCHEMA, "runner_image": env["ImageVersion"], "image_os": "ubuntu24", "platform": platform, "context": context,
              "packages": packages, "socket": SOCKET, "socket_security": socket_security, "files": files,
              "services": {unit: identity for unit, (identity, _) in measured.items()}, "native": versions, "components": components,
              "engine_settings": engine_settings(settings), "kernel": {"release": kernel, "package": package, "version": kernel_version},
              "observation": observation}
    stable_projection(result)
    return result


def engine_settings(value):
    require(set(value) == {"driver", "driver_status", "security", "default_runtime", "cgroup_version"}
            and value["default_runtime"] == "runc" and value["cgroup_version"] in {"1", "2"}
            and isinstance(value["driver"], str) and re.fullmatch(r"[a-z0-9_-]{1,32}", value["driver"])
            and isinstance(value["security"], list) and 0 < len(value["security"]) <= 20
            and all(isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9 ,._:=/-]{1,120}", item) for item in value["security"]),
            "docker_engine_security_settings")
    status = value["driver_status"] or []
    require(isinstance(status, list) and all(isinstance(item, list) and len(item) == 2 for item in status), "docker_engine_driver_status")
    backend = [item[1] for item in status if item[0] == "driver-type"]
    require(len(backend) <= 1 and all(isinstance(item, str) and re.fullmatch(r"[a-z0-9._-]{1,80}", item) for item in backend),
            "docker_engine_snapshotter")
    return {"driver": value["driver"], "snapshotter": backend[0] if backend else None,
            "security": sorted(value["security"]), "default_runtime": value["default_runtime"], "cgroup_version": value["cgroup_version"]}


def native_versions(reported):
    try:
        client, server = reported["Client"], reported["Server"]
        fields = ("version", "apiversion", "gitcommit", "os", "arch")
        versions = {}
        for key, source in (("client", client), ("server", server)):
            normalized = {field.casefold(): value for field, value in source.items()}
            require(len(normalized) == len(source), "docker_native_ambiguous_version")
            versions[key] = {field: normalized[field] for field in fields}
        for item in versions.values():
            require(item["os"] == "linux" and item["arch"] == "amd64" and all(
                isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._+-]{1,80}", value) for value in item.values()), "docker_native_versions")
        components = {item["Name"]: {key: item[key] for key in ("Version", "Name")} for item in server["Components"]}
        require({"Engine", "containerd", "runc"} <= set(components) and all(re.fullmatch(r"[A-Za-z0-9._+ -]{1,80}", item[field])
                for item in components.values() for field in ("Name", "Version")), "docker_native_components")
    except (AttributeError, KeyError, TypeError) as error:
        raise ValueError("docker_version_schema") from error
    return versions, components


def closed(value, fields):
    return isinstance(value, dict) and set(value) == set(fields)


def valid_metadata(value):
    return closed(value, FILE_METADATA) and all(type(item) is int and item >= 0 for item in value.values()) and value["inode"] > 0


def review_observation(value):
    observation = value["observation"]
    require(closed(observation, OBSERVATION_FIELDS) and observation["repository"] == "AldemaroCruz/ClipForge"
            and re.fullmatch(r"[0-9a-f]{40}", observation["source_commit"]) and BOOT_ID.fullmatch(observation["boot_id"])
            and DECIMAL.fullmatch(observation["run"]) and DECIMAL.fullmatch(observation["attempt"])
            and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_-]{0,127}", observation["job"]), "docker_host_observation_fields")
    observed = datetime.fromisoformat(observation["observed_utc"])
    require(observed.utcoffset() == timezone.utc.utcoffset(None), "docker_observation_utc_required")
    require(closed(observation["files"], BINARIES) and closed(observation["processes"], SERVICE_BINARIES)
            and valid_metadata(observation["socket"]), "docker_host_observation_incomplete")
    socket = value["socket_security"]
    require(closed(socket, {"mode", "uid", "group"}) and socket["group"] in {"docker", "root"}
            and socket["uid"] == observation["socket"]["uid"] == 0 and socket["mode"] == observation["socket"]["mode"]
            and stat.S_ISSOCK(socket["mode"]) and not socket["mode"] & 0o007, "docker_local_root_socket")
    for name, file in value["files"].items():
        info = observation["files"][name]
        require(closed(file, {"path", "sha256", "bytes", "uid", "gid", "mode", "package"}) and valid_metadata(info)
                and file["package"] == BINARY_PACKAGES[name] and SHA256.fullmatch(file["sha256"])
                and re.fullmatch(r"/usr/bin/[A-Za-z0-9._+-]+", file["path"])
                and all(file[key] == info[key] for key in ("bytes", "mode", "uid", "gid"))
                and file["uid"] == file["gid"] == 0 and 0 < file["bytes"] <= 256 * 1024 * 1024
                and stat.S_ISREG(file["mode"]) and not file["mode"] & 0o022 and file["mode"] & 0o111, "docker_toolchain_file_boundary")
    pids = set()
    for unit, path in SERVICE_BINARIES.items():
        live = observation["processes"][unit]
        require(closed(live, {"pid", "start_ticks", "executable"}) and DECIMAL.fullmatch(live["pid"]) and DECIMAL.fullmatch(live["start_ticks"])
                and live["pid"] not in pids and int(live["pid"]) <= 2**31 - 1
                and live["executable"] == live_from_file(observation["files"][path]) and value["services"][unit] == value["files"][path],
                "docker_live_services_unbound")
        pids.add(live["pid"])
    return observed


def stable_projection(value):
    """Validate a complete receipt and select the facts reproducible on a fresh host."""
    require(closed(value, {*STABLE_FIELDS, "observation"}) and value["schema"] == SCHEMA and value["image_os"] == "ubuntu24"
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", value["runner_image"]), "docker_receipt_fields")
    require(value["socket"] == SOCKET and value["context"] == {"name": "default", "endpoint": "unix://" + SOCKET}, "docker_context_changed")
    require(closed(value["packages"], PACKAGE_VERSIONS)
            and all(re.fullmatch(r"[A-Za-z0-9:._+~-]{1,120}", version) for version in value["packages"].values()), "docker_receipt_package_inventory")
    require(closed(value["files"], BINARIES) and closed(value["services"], SERVICE_BINARIES), "docker_receipt_executable_inventory")
    kernel, platform = value["kernel"], value["platform"]
    require(closed(kernel, {"release", "package", "version"}) and isinstance(kernel["release"], str), "docker_receipt_kernel")
    family = re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+-[0-9]+-([a-z0-9-]{1,32})", kernel["release"])
    require(family and kernel["package"] == "linux-image-" + kernel["release"] and re.fullmatch(r"[A-Za-z0-9:._+~-]{1,120}", kernel["version"])
            and platform == {"distribution": "ubuntu", "version": "24.04", "architecture": "amd64", "kernel_family": family[1]},
            "docker_receipt_kernel")
    versions = value["native"]
    version_fields = {"version", "apiversion", "gitcommit", "os", "arch"}
    require(closed(versions, {"client", "server"}) and all(closed(item, version_fields) and item["os"] == "linux" and item["arch"] == "amd64"
                and all(re.fullmatch(r"[A-Za-z0-9._+-]{1,80}", part) for part in item.values()) for item in versions.values()), "docker_native_versions")
    components = value["components"]
    require(isinstance(components, dict) and {"Engine", "containerd", "runc"} <= set(components)
            and all(closed(item, {"Name", "Version"}) and item["Name"] == name
                    and all(re.fullmatch(r"[A-Za-z0-9._+ -]{1,80}", part) for part in item.values()) for name, item in components.items()),
            "docker_native_components")
    engine = value["engine_settings"]
    require(closed(engine, {"driver", "snapshotter", "security", "default_runtime", "cgroup_version"}), "docker_engine_security_settings")
    settings = {key: engine[key] for key in ("driver", "security", "default_runtime", "cgroup_version")}
    settings["driver_status"] = [] if engine["snapshotter"] is None else [["driver-type", engine["snapshotter"]]]
    require(engine_settings(settings) == engine, "docker_engine_security_settings")
    review_observation(value)
    return {key: value[key] for key in STABLE_FIELDS}


def projection_sha256(value):
    return sha256(json.dumps(stable_projection(value), sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def verify(expected, *, inspect=None):
    reviewed = stable_projection(expected)
    inspect = inspect or inventory
    current = inspect()
    require(stable_projection(current) == reviewed, "docker_credentialed_toolchain_differs")
    return current


def verify_same_host(staged, current):
    require(stable_projection(staged) == stable_projection(current), "docker_credentialed_toolchain_differs")
    identity = OBSERVATION_FIELDS - {"observed_utc"}
    require(all(staged["observation"][key] == current["observation"][key] for key in identity)
            and datetime.fromisoformat(staged["observation"]["observed_utc"]) <= datetime.fromisoformat(current["observation"]["observed_utc"]),
            "docker_credentialed_host_observation_changed")


def verify_maintained(expected):
    """Restrict publication to the reviewed maintained Noble AWS and Docker lines."""
    stable_projection(expected)
    native = expected["native"]
    engine = native["server"]["version"]
    components = expected["components"]
    require(native["client"]["version"] == engine == components["Engine"]["Version"],
            "docker_client_server_engine_version_mismatch")
    # Docker 28 is out of maintenance. The exact reviewed alternative starts at 29.10.0.
    engine_version = SEMVER.fullmatch(engine)
    require(engine_version and int(engine_version[1]) == 29 and int(engine_version[2]) >= 10,
            "docker_engine_publication_maintenance_floor")
    for component, required in (("containerd", (2, 4, 2)), ("runc", (1, 5, 3))):
        version = SEMVER.fullmatch(components[component]["Version"])
        numbers = tuple(map(int, version.groups())) if version else ()
        require(numbers[:2] == required[:2] and numbers >= required, "docker_component_publication_maintenance_floor")
    require(expected["packages"] == PACKAGE_VERSIONS, "docker_publication_packages_not_exact")
    kernel = expected["kernel"]
    version = AWS_NOBLE_KERNEL.fullmatch(kernel["version"])
    # This floor is for Noble AWS 7.0 only. Other variants require their own reviewed policy.
    require(expected["platform"]["kernel_family"] == "aws" and version
            and kernel["release"] == f"7.0.0-{version[1]}-aws" and kernel["package"] == "linux-image-" + kernel["release"]
            and tuple(map(int, version.groups())) >= (1017, 18, 1), "docker_noble_aws_kernel_security_floor")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__ + " The receipt is read-only evidence and confers no publication authority.")
    parser.add_argument("--output", type=Path, required=True)
    options = parser.parse_args(argv)
    output = options.output
    require(output.resolve().parent == Path(os.environ["RUNNER_TEMP"]).resolve()
            and output.name == "int-demo-a-docker-toolchain.json", "docker_receipt_owned_output")
    os.umask(0o077)
    with output.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(inventory(), stream, indent=2, sort_keys=True)
        stream.write("\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
