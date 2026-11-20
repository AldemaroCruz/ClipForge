"""Identify the root-owned Docker toolchain used by INT Demo A without a cloud token."""

import argparse
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
BINARIES = (DOCKER, "/usr/bin/dockerd", "/usr/bin/containerd", "/usr/bin/containerd-shim-runc-v2", "/usr/bin/runc")
SCHEMA = "clipforge-int-demo-a-docker-toolchain-2"


def require(condition, error):
    if not condition:
        raise ValueError(error)


def run(args, home, *, timeout=12):
    env = {"PATH": "/usr/bin:/bin", "HOME": str(home), "LC_ALL": "C"}
    result = subprocess.run(args, env=env, capture_output=True, timeout=timeout, check=False)
    require(result.returncode == 0 and 0 < len(result.stdout) <= 65536, "docker_toolchain_command_failed")
    return result.stdout.decode().strip()


def identify_file(name):
    path = Path(name)
    resolved = path.resolve(strict=True)
    before = resolved.stat()
    require(resolved.is_relative_to("/usr/bin") and stat.S_ISREG(before.st_mode) and before.st_uid == 0
            and before.st_mode & 0o022 == 0 and before.st_mode & 0o111 != 0
            and 0 < before.st_size <= 256 * 1024 * 1024, "docker_toolchain_file_boundary")
    with resolved.open("rb") as data:
        digest = sha256()
        while block := data.read(1024 * 1024):
            digest.update(block)
        after = os.fstat(data.fileno())
        identity = ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns")
        require(all(getattr(before, field) == getattr(after, field) for field in identity), "docker_toolchain_file_changed")
    return {"path": str(resolved), "sha256": digest.hexdigest(), "bytes": before.st_size}


def endpoint(config):
    return [DOCKER, "--config", str(config), "--host", "unix://" + SOCKET]


def inventory(env=os.environ):
    require(env.get("RUNNER_ENVIRONMENT") == "github-hosted" and env.get("ImageOS") == "ubuntu24"
            and re.fullmatch(r"[0-9]+\.[0-9]+\.[0-9]+", env.get("ImageVersion", "")), "docker_exact_hosted_image")
    socket = Path(SOCKET).lstat()
    require(stat.S_ISSOCK(socket.st_mode) and socket.st_uid == 0 and socket.st_mode & 0o007 == 0, "docker_local_root_socket")
    files = {path: identify_file(path) for path in BINARIES}
    with TemporaryDirectory(prefix="docker-int-a-identity.") as work:
        cli = endpoint(work)
        reported = json.loads(run(cli + ["version", "--format", "{{json .}}"], work))
        info_format = ('{"driver":{{json .Driver}},"driver_status":{{json .DriverStatus}},'
                       '"security":{{json .SecurityOptions}},"default_runtime":{{json .DefaultRuntime}},'
                       '"cgroup_version":{{json .CgroupVersion}}}')
        settings = json.loads(run(cli + ["info", "--format", info_format], work))
        pid = run(["/usr/bin/systemctl", "show", "--property=MainPID", "--value", "docker.service"], work)
        require(re.fullmatch(r"[1-9][0-9]*", pid), "docker_running_service_required")
        exe = run(["/usr/bin/sudo", "-n", "/usr/bin/readlink", f"/proc/{pid}/exe"], work)
        require(exe == files["/usr/bin/dockerd"]["path"], "docker_running_executable_changed")
        kernel = os.uname().release
        require(re.fullmatch(r"[0-9][A-Za-z0-9._+-]{2,95}", kernel), "docker_kernel_identity")
        package = "linux-image-" + kernel
        installed = run(["/usr/bin/dpkg-query", "-W", "-f=${db:Status-Status} ${Version}", package], work).split()
        require(len(installed) == 2 and installed[0] == "installed" and re.fullmatch(r"[A-Za-z0-9:._+~-]{1,120}", installed[1]),
                "docker_running_kernel_package_identity")
    versions, components = native_versions(reported)
    return {"schema": SCHEMA, "runner_image": env["ImageVersion"], "image_os": "ubuntu24", "socket": SOCKET,
            "files": files, "native": versions, "components": components, "engine_settings": engine_settings(settings),
            "kernel": {"release": kernel, "package": package, "version": installed[1]}}


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


def verify(expected, *, inspect=None):
    inspect = inspect or inventory
    require(inspect() == expected, "docker_credentialed_toolchain_differs")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
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
