"""Measure the default AppArmor profile on an owned, digest-pinned Linux process."""

import json
import re
from secrets import token_hex

from scripts import int_demo_a_docker as docker


PROBE_IMAGE = "python:3.12-slim-bookworm@sha256:935c3c5b12357a7e10caa9c1e6ca5692344d97cf229832ef584be2cec9fc03df"
OLD = "name=apparmor"
NEW = "name=apparmor,profile=default"
PROFILE = "docker-default"
ENFORCED = PROFILE + " (enforce)"
SUDO = ["/usr/bin/sudo", "-n", "--"]


def enforce_options(before, after, native):
    old, new = set(before), set(after)
    docker.require("name=seccomp,profile=builtin" in new and "name=cgroupns" in new,
                   "docker_prepare_effective_protections_regressed")
    old_apparmor = {item for item in before if item.startswith("name=apparmor")}
    new_apparmor = {item for item in after if item.startswith("name=apparmor")}
    known = ({OLD}, {NEW})
    docker.require(old_apparmor in known and new_apparmor in known and (old_apparmor == new_apparmor or (old_apparmor, new_apparmor) == known)
                   and old - old_apparmor <= new - new_apparmor, "docker_prepare_effective_protections_regressed")
    docker.require(all(native.get(stage, {}).get("kernel_label") == ENFORCED and native[stage].get("loaded") is True
                       and native[stage].get("seccomp_mode") == 2 and native[stage].get("no_new_privileges") is True
                       for stage in ("before", "after")), "docker_prepare_apparmor_enforcement_unverified")


def confinement(commands, image_config, stage):
    cli = docker.endpoint(commands.home / "empty-docker-config")
    name = "clipforge-hosted-aa-" + token_hex(12)
    primary = None
    active = None
    try:
        _, active = commands.run(f"apparmor_{stage}_container_start", cli + ["run", "--detach", "--pull=never", "--network=none",
            "--name", name, "--cap-drop=ALL", "--security-opt=no-new-privileges", "--read-only", "--entrypoint=/bin/sleep",
            PROBE_IMAGE, "70"], budget=30)
        docker.require(re.fullmatch(r"[0-9a-f]{64}", active), "docker_prepare_apparmor_container_identity")

        def inspect():
            _, raw = commands.run(f"apparmor_{stage}_container_inspect", cli + ["inspect", "--format",
                "{{json .Id}}\n{{json .Image}}\n{{json .State.Pid}}\n{{json .AppArmorProfile}}", active])
            identifier, image, pid, profile = (json.loads(row) for row in raw.splitlines())
            docker.require(identifier == active and image == image_config and type(pid) is int and 1 < pid <= 4194304 and profile == PROFILE,
                           "docker_prepare_apparmor_container_identity")
            return pid, profile

        pid, profile = inspect()
        _, label = commands.run(f"apparmor_{stage}_kernel_label", SUDO + ["/usr/bin/cat", f"/proc/{pid}/attr/apparmor/current"], limit=512)
        _, status = commands.run(f"apparmor_{stage}_proc_status", SUDO + ["/usr/bin/cat", f"/proc/{pid}/status"], limit=16384)
        _, profiles = commands.run(f"apparmor_{stage}_loaded_profiles", SUDO + ["/usr/bin/cat", "/sys/kernel/security/apparmor/profiles"], limit=262144)
        docker.require(label == ENFORCED and ENFORCED in profiles.splitlines() and re.search(r"(?m)^NoNewPrivs:\s+1$", status)
                       and re.search(r"(?m)^Seccomp:\s+2$", status) and inspect() == (pid, profile),
                       "docker_prepare_apparmor_enforcement_unverified")
        return {"image": PROBE_IMAGE, "image_config": image_config, "container": active, "pid": pid,
                "kernel_label": label, "loaded": True, "seccomp_mode": 2, "no_new_privileges": True}
    except Exception as error:
        primary = error
        raise
    finally:
        try:
            commands.run(f"apparmor_{stage}_cleanup", cli + ["rm", "--force", "--", name], budget=15)
        except Exception:
            if primary is None:
                raise


def prepare_image(commands):
    cli = docker.endpoint(commands.home / "empty-docker-config")
    commands.run("apparmor_pull_pinned_probe", cli + ["pull", "--platform=linux/amd64", PROBE_IMAGE], budget=105)
    _, image = commands.run("apparmor_probe_image_config", cli + ["image", "inspect", "--format", "{{.Id}}", PROBE_IMAGE])
    docker.require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "docker_prepare_apparmor_image_identity")
    return image
