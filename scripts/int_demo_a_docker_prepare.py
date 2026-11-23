"""Prepare only the reviewed Docker packages on the ephemeral Noble runner."""

import argparse
from dataclasses import dataclass
from hashlib import sha256
import json
import os
from pathlib import Path
import re
import stat
import sys
from tempfile import TemporaryDirectory
import time
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from scripts import int_demo_a_docker as docker
from scripts import int_demo_a_docker_apparmor as apparmor
from scripts.int_noble_demo_preflight_guest import run_diagnostic


SCHEMA = "clipforge-int-demo-a-docker-prepare-1"
REPO = "AldemaroCruz/ClipForge"
BRANCH = "refs/heads/ci/bootstrap-sec03"
WORKFLOWS = {"evaluate": "int-demo-a-wif-read.yml", "protected": "int-demo-a-publish.yml"}
REPORT_NAME = "int-demo-a-docker-prepare.json"
ORIGIN = "https://download.docker.com/linux/ubuntu/dists/noble/pool/stable/amd64/"
METADATA = {"signed_metadata_sha256": "d680a67beb302d59b1bed4e5edef26612924ac3ec65f0ac792f4da69c52ececc",
            "deb_evidence_sha256": "4b6d0554c60e7306f37a66340c88e917a5cdcaebabd7be162eca156ec340f921",
            "inrelease_sha256": "35ae17adf844d1bfeaa74578f4bdd0a5f12530f63129aba9f582651cd8b52885",
            "packages_gz_sha256": "fadc47d42267b9922cba6292c1874755a0a829de4651929a55e647e3868e70d5",
            "primary_fingerprint": "9DC858229FC7DD38854AE2D88D81803C0EBFCD88",
            "signer_fingerprint": "D3306A018370199E527AE7997EA0A9C3F273FCD8"}
VERSION = r"[0-9][A-Za-z0-9:._+~\-]{0,119}"
NAME = r"[a-z0-9][a-z0-9+.-]{1,127}"
SHA = r"[a-f0-9]{64}"
RUN = r"[1-9][0-9]*"
SUDO = ["/usr/bin/sudo", "-n", "--"]
SYSTEMCTL = "/usr/bin/systemctl"
DPKG = "/usr/bin/dpkg"
SERVICES = {"docker.service": "/usr/bin/dockerd", "containerd.service": "/usr/bin/containerd"}
FORBIDDEN_ENV = {"GOOGLE_APPLICATION_CREDENTIALS", "GOOGLE_GHA_CREDS_PATH", "GCP_ACCESS_TOKEN", "GOOGLE_OAUTH_ACCESS_TOKEN",
                 "CLOUDSDK_AUTH_CREDENTIAL_FILE_OVERRIDE", "CLOUDSDK_AUTH_ACCESS_TOKEN", "CLOUDSDK_AUTH_ACCESS_TOKEN_FILE",
                 "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT", "DOCKER_AUTH_CONFIG", "REGISTRY_AUTH_FILE", "GOOGLE_CREDENTIALS",
                 "GOOGLE_CLOUD_KEYFILE_JSON", "GOOGLE_IMPERSONATE_SERVICE_ACCOUNT"}
MAX_RECEIPT = 2 * 1024 * 1024
require = docker.require


@dataclass(frozen=True)
class Package:
    name: str
    version: str
    size: int
    digest: str
    depends: str = ""
    pre_depends: str = ""
    provides: str = ""

    @property
    def filename(self):
        return f"{self.name}_{self.version.split(':')[-1]}_amd64.deb"


REVIEWED = (
    Package("containerd.io", "2.4.2-4~ubuntu.24.04~noble", 23265116, "15cc3d6c64422ed278f60cb3c9a5df760a3de38055affc335c6ee40c12411b75",
            "libc6 (>= 2.38), libseccomp2 (>= 2.5.0)", provides="containerd, runc"),
    Package("docker-ce-cli", "5:29.10.0-1~ubuntu.24.04~noble", 8618748, "a9d3801c3efd3c78786948e8dd1c023796c9145aca8c882818664e79402578f1",
            "libc6 (>= 2.34)"),
    Package("docker-ce", "5:29.10.0-1~ubuntu.24.04~noble", 24965580, "85abe031338e48e9cb157238732b2c40aeb4f1741d399f64042abcca2950c951",
            "containerd.io (>= 2.1.5), docker-ce-cli, iptables, nftables, libc6 (>= 2.34), libsystemd0", "init-system-helpers (>= 1.54~)"),
)
TARGETS = {package.name: package for package in REVIEWED}
BINARIES = {"/usr/bin/docker": (37920486, "feae2898f107d430c4cc8cca0f0155876c0cf95f63ba6efeed203b4a9b304caa"),
            "/usr/bin/dockerd": (111527360, "961d4c7074f01b3bdd3eaf714298a24cff642e675490737e43865bad916944f6"),
            "/usr/bin/containerd": (44299016, "b772d4cc7f5822b80ac837c4897b39ac310539c08c055a69b5f6559ec4a16e6e"),
            "/usr/bin/containerd-shim-runc-v2": (8483416, "dc2e7f659178401a196fc9431ec70c9e29bc46f22a1969342b21b979cb113228"),
            "/usr/bin/runc": (9723344, "9c1d6487f5139f4d71113e3a3eef1a4c881d7714b39ee47ed22bff9aba856b4d")}


def hosted(env, profile, approved_commit):
    workflow = WORKFLOWS[profile]
    fixed = {"GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted", "ImageOS": "ubuntu24",
             "GITHUB_REPOSITORY": REPO, "GITHUB_REF": BRANCH, "GITHUB_EVENT_NAME": "workflow_dispatch", "GITHUB_RUN_ATTEMPT": "1",
             "GITHUB_WORKFLOW_REF": f"{REPO}/.github/workflows/{workflow}@{BRANCH}", "GITHUB_SHA": approved_commit}
    require(all(env.get(key) == value for key, value in fixed.items()) and re.fullmatch(r"[a-f0-9]{40}", approved_commit)
            and re.fullmatch(RUN, env.get("GITHUB_RUN_ID", "")) and not any(env.get(name) for name in FORBIDDEN_ENV),
            "docker_prepare_hosted_no_credential_boundary")
    if profile == "evaluate":
        require(env.get("INT_DOCKER_PREP_SELECTOR") == "docker_prepare"
                and not any(env.get(name) for name in ("ACTIONS_ID_TOKEN_REQUEST_URL", "ACTIONS_ID_TOKEN_REQUEST_TOKEN")),
                "docker_prepare_evaluation_requires_no_oidc")
    else:
        require(env.get("INT_DOCKER_PREP_ENVIRONMENT") == "int", "docker_prepare_protected_environment")


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def read_expected(path, expected_sha256):
    require(path is not None and re.fullmatch(SHA, expected_sha256 or ""), "docker_prepare_expected_receipt_required")
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_mode & 0o022
            and 0 < info.st_size <= MAX_RECEIPT, "docker_prepare_expected_receipt_unsafe")
    with path.open("rb") as stream:
        raw = stream.read(MAX_RECEIPT + 1)
    require(len(raw) == info.st_size and sha256(raw).hexdigest() == expected_sha256, "docker_prepare_expected_receipt_changed")
    value = json.loads(raw)
    require(raw == canonical(value) + b"\n" and value["schema"] == SCHEMA and value["profile"] == "evaluate"
            and value["status"] == "prepared_verified" and value["publication_eligibility"] == "eligible"
            and set(value["comparison"]) == {"apt", "after"}, "docker_prepare_expected_receipt_scope")
    return value["comparison"]


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def verify_file(path, package):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_size == package.size, "docker_prepare_deb_size")
    digest = sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    require(digest.hexdigest() == package.digest, "docker_prepare_deb_hash")


def download(work, package, opener):
    path = work / package.filename
    end = time.monotonic() + 120
    with opener.open(ORIGIN + package.filename, timeout=12) as response, path.open("xb") as output:
        require(response.status == 200 and response.url == ORIGIN + package.filename, "docker_prepare_deb_origin")
        written = 0
        while block := response.read(min(1024 * 1024, package.size + 1 - written)):
            written += len(block)
            require(written <= package.size and time.monotonic() < end, "docker_prepare_deb_download_bound")
            output.write(block)
    verify_file(path, package)
    return path


class Commands:
    """Fixed-path native requests with bounded output and no inherited credentials."""

    def __init__(self, home, report):
        self.home, self.report = home, report
        self.env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": str(home)}

    def run(self, label, argv, *, budget=25, limit=65536, exits=(0,), record=True, extra=None, trim=True):
        state, code, stdout, stderr = run_diagnostic(argv, budget=budget, limit=limit, environment={**self.env, **(extra or {})})
        if record or code not in exits or state != "exited":
            row = {"stage": label, "process": state, "exit": code, "stdout_sha256": sha256(stdout.encode()).hexdigest(),
                   "stderr_sha256": sha256(stderr.encode()).hexdigest()}
            if code not in exits or state != "exited":
                for field, text in (("stdout_excerpt", stdout), ("stderr_excerpt", stderr)):
                    row[field] = text.replace(str(self.home.parent), "<scratch>")[:4000]
            self.report.setdefault("commands", []).append(row)
        require(state == "exited" and code in exits, "docker_prepare_" + label)
        return code, stdout.strip() if trim else stdout


def dpkg_state(commands):
    fmt = "${binary:Package}\\t${Version}\\t${db:Status-Status}\\t${Architecture}\\t${Depends}\\t${Pre-Depends}\\t${Provides}\\n"
    raw = commands.run("dpkg_inventory", ["/usr/bin/dpkg-query", "-W", "-f=" + fmt], limit=2 * 1024 * 1024, trim=False)[1]
    states = {}
    for row in raw.splitlines():
        fields = row.split("\t")
        require(len(fields) == 7, "docker_prepare_dpkg_inventory_columns")
        binary, version, status, arch, depends, pre_depends, provides = fields
        name = binary.partition(":")[0]
        require(binary not in states and re.fullmatch(NAME, name) and re.fullmatch(r"[a-z0-9-]+", arch)
                and re.fullmatch(VERSION, version) and re.fullmatch(r"[a-z-]+", status), "docker_prepare_dpkg_inventory_row")
        states[binary] = {"name": name, "version": version, "status": status, "architecture": arch,
                          "depends": depends, "pre_depends": pre_depends, "provides": provides}
    require(states, "docker_prepare_empty_dpkg_inventory")
    return states


def compare(commands, installed, operator, wanted):
    native = {"=": "eq", "<<": "lt", "<=": "le", ">=": "ge", ">>": "gt"}
    return commands.run("dpkg_compare_versions", [DPKG, "--compare-versions", installed, native[operator], wanted],
                        exits=(0, 1), record=False)[0] == 0


def dep_atom(value):
    found = re.fullmatch(rf"({NAME})(?::(any|native|amd64))?(?:\s*\((<<|<=|=|>=|>>)\s*({VERSION})\))?", value.strip())
    require(found is not None, "docker_prepare_unreviewed_dependency_syntax")
    return found.groups()


def dependency_closure(projected, commands):
    installed = {binary: info for binary, info in projected.items()
                 if info["status"] == "installed" and info["architecture"] in {"amd64", "all"}}
    providers = {}
    for binary, row in installed.items():
        providers.setdefault(row["name"], []).append((binary, row["version"]))
        for declaration in row["provides"].split(","):
            if declaration and re.match(rf"^\s*{NAME}(?::(?:any|native|amd64))?(?:\s*\(=\s*{VERSION}\))?\s*$", declaration):
                name, _, _, version = dep_atom(declaration)
                providers.setdefault(name, []).append((binary, version))
    stack, closure = list(TARGETS), {}
    while stack:
        binary = stack.pop()
        if binary in closure:
            continue
        row = installed[binary]
        requirements = {}
        for group in (row["pre_depends"] + "," + row["depends"]).split(","):
            if not group.strip():
                continue
            candidates = set()
            for alternative in group.split("|"):
                name, _, operator, version = dep_atom(alternative)
                for provider, provided_version in providers.get(name, ()):
                    if operator is None or provided_version and compare(commands, provided_version, operator, version):
                        candidates.add(provider)
            require(candidates, "docker_prepare_dependency_not_installed_or_reviewed")
            requirements[group.strip()] = sorted(candidates)
            stack.extend(sorted(candidates))
        require(len(closure) < 256, "docker_prepare_dependency_closure_bound")
        closure[binary] = {"version": row["version"], "architecture": row["architecture"], "requirements": requirements}
    return dict(sorted(closure.items()))


def apt_config(work):
    for name in ("lists", "sources", "etc", "archives", "apt-cache"):
        (work / name).mkdir()
    lines = {"Dir::Etc::Parts": "etc", "Dir::Etc::SourceParts": "sources", "Dir::State::lists": "lists",
             "Dir::Cache::archives": "archives", "Dir::Cache::pkgcache": "apt-cache/pkgcache.bin",
             "Dir::Cache::srcpkgcache": "apt-cache/srcpkgcache.bin"}
    config = work / "apt.conf"
    config.write_text("\n".join(f'{key} "{work / value}";' for key, value in lines.items()) +
                      '\nDir::Etc::Main "/dev/null";\nDir::Etc::SourceList "/dev/null";\nDir::State::Status "/var/lib/dpkg/status";\n', encoding="ascii")
    return config


def requested_changes(before):
    changes = {}
    for package in REVIEWED:
        current = before.get(package.name)
        require(current is not None and current["architecture"] == "amd64" and current["status"] == "installed",
                "docker_prepare_requires_existing_reviewed_dpkg_names")
        if current["version"] != package.version:
            changes[package.name] = {"before": current["version"], "after": package.version}
    return changes


def check_simulation(raw, expected):
    plan = {"Inst": {}, "Conf": {}}
    for line in raw.splitlines():
        prefix = line.partition(" ")[0]
        if prefix not in {"Inst", "Conf", "Remv", "Purg"}:
            continue
        require(prefix in plan, "docker_prepare_unapproved_simulated_removal")
        found = re.fullmatch(rf"{prefix} ({NAME})(?::amd64)? (?:\[({VERSION})\] )?\(({VERSION}) (?:local-deb|local-deb:now) \[amd64\]\)", line)
        require(found is not None and found[1] not in plan[prefix], "docker_prepare_simulated_action_shape")
        plan[prefix][found[1]] = (found[2], found[3])
    require(set(plan["Inst"]) == set(plan["Conf"]) == set(expected)
            and all(plan["Inst"][name] == (pair["before"], pair["after"]) and plan["Conf"][name] == (None, pair["after"])
                    for name, pair in expected.items()), "docker_prepare_unapproved_simulated_delta")
    require(re.search(rf"^{len(expected)} upgraded, 0 newly installed, 0 to remove and [0-9]+ not upgraded\.$", raw, re.M),
            "docker_prepare_unapproved_simulation_summary")
    return plan


def boot_identity():
    info = dict(line.split("=", 1) for line in Path("/etc/os-release").read_text(encoding="ascii").splitlines() if "=" in line)
    os_id, version = (info[name].strip('"') for name in ("ID", "VERSION_ID"))
    uname = os.uname()
    boot = Path("/proc/sys/kernel/random/boot_id").read_text(encoding="ascii").strip()
    require((os_id, version, uname.sysname, uname.machine) == ("ubuntu", "24.04", "Linux", "x86_64")
            and re.fullmatch(r"[a-f0-9-]{36}", boot), "docker_prepare_noble_amd64_boot")
    return {"distribution": {"id": os_id, "version": version, "architecture": "amd64"}, "boot_id": boot, "release": uname.release}


def require_idle(commands):
    selected = docker.endpoint(commands.home / "empty-docker-config")
    require(commands.run("active_docker_containers", selected + ["ps", "--quiet"])[1] == "", "docker_prepare_active_docker_workload")
    ctr = SUDO + ["/usr/bin/ctr", "--address", "/run/containerd/containerd.sock"]
    namespaces = commands.run("containerd_namespaces", ctr + ["namespaces", "list", "--quiet"])[1].splitlines()
    require(len(namespaces) <= 32 and all(re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,63}", item) for item in namespaces),
            "docker_prepare_containerd_namespace_scope")
    for name in namespaces:
        require(commands.run("active_containerd_tasks", ctr + ["--namespace", name, "tasks", "list", "--quiet"])[1] == "",
                "docker_prepare_active_containerd_workload")


def snapshot(env, state):
    boot = boot_identity()
    toolchain = docker.inventory(env)
    targets = {name: state[name]["version"] for name in TARGETS}
    require(boot["release"] == toolchain["kernel"]["release"] and boot["boot_id"] == toolchain["observation"]["boot_id"]
            and toolchain["packages"] == targets, "docker_prepare_observation_state_changed")
    return {"boot": boot, "toolchain": toolchain, "target_packages": targets}


def portable(snapshot):
    return {"toolchain": docker.stable_projection(snapshot["toolchain"]), "distribution": snapshot["boot"]["distribution"]}


def install_reviewed(commands, packages):
    commands.run("stop_docker", SUDO + [SYSTEMCTL, "stop", "docker.socket", "docker.service"], budget=45)
    commands.run("stop_containerd", SUDO + [SYSTEMCTL, "stop", "containerd.service"], budget=45)
    commands.run("dpkg_install_reviewed", SUDO + ["/usr/bin/env", "DEBIAN_FRONTEND=noninteractive", "SYSTEMD_OFFLINE=1", "NEEDRESTART_MODE=l",
                                                   DPKG, "--install", *map(str, packages)], budget=240, limit=256 * 1024)
    commands.run("systemd_reload", SUDO + [SYSTEMCTL, "daemon-reload"], budget=45)
    commands.run("restart_containerd", SUDO + [SYSTEMCTL, "restart", "containerd.service"], budget=60)
    commands.run("restart_docker", SUDO + [SYSTEMCTL, "restart", "docker.socket", "docker.service"], budget=60)


def prepare(env, work, journal, report, expected, *, native_apparmor=False):
    home = work / "home"
    home.mkdir()
    (home / "empty-docker-config").mkdir()
    commands = Commands(home, report)
    require(commands.run("architecture", [DPKG, "--print-architecture"])[1] == "amd64", "docker_prepare_dpkg_architecture")
    report["dpkg_audit_before"] = commands.run("dpkg_audit_before", [DPKG, "--audit"])[1][:4000]
    require(report["dpkg_audit_before"] == "", "docker_prepare_dpkg_audit_not_clean")
    installed = dpkg_state(commands)
    changes = requested_changes(installed)
    require(all(compare(commands, row["before"], "<<", row["after"]) for row in changes.values()), "docker_prepare_downgrade_blocked")
    report["before"] = snapshot(env, installed)
    require_idle(commands)
    if native_apparmor:
        probe_image = apparmor.prepare_image(commands)
        report["apparmor_native"] = {"before": apparmor.confinement(commands, probe_image, "before")}
    opener = build_opener(ProxyHandler({}), NoRedirect())
    paths = {package.name: download(work, package, opener) for package in REVIEWED}
    for package in REVIEWED:
        raw = commands.run("deb_control", ["/usr/bin/dpkg-deb", "--field", str(paths[package.name])])[1]
        fields = dict(line.split(": ", 1) for line in raw.splitlines() if re.match(r"[A-Za-z][A-Za-z-]+: ", line))
        expected_fields = {"Package": package.name, "Architecture": "amd64", "Version": package.version, "Depends": package.depends,
                           "Pre-Depends": package.pre_depends, "Provides": package.provides}
        require(all(fields.get(key, "") == value for key, value in expected_fields.items()), "docker_prepare_authenticated_deb_control")
    projected = {**installed, **{package.name: {**installed[package.name], "version": package.version, "depends": package.depends,
                                               "pre_depends": package.pre_depends, "provides": package.provides} for package in REVIEWED}}
    comparison = {"apt": {"metadata": METADATA, "changes": changes, "dependencies": dependency_closure(projected, commands),
                           "authenticated_debs": {package.name: {"version": package.version, "size": package.size, "sha256": package.digest}
                                                  for package in REVIEWED}}}
    report["comparison"] = comparison
    apt = apt_config(work)
    simulation = ["/usr/bin/apt-get", "-s", "--no-download", "--no-remove", "--no-install-recommends", "install", *map(str, paths.values())]
    output = commands.run("apt_simulation", simulation, budget=60, limit=128 * 1024, extra={"APT_CONFIG": str(apt)})[1]
    report["simulation"] = {"actions": [line for line in output.splitlines() if line.startswith(("Inst ", "Conf ", "Remv ", "Purg "))]}
    plan = check_simulation(output, changes)
    comparison["apt"]["simulation"] = {action: {name: list(versions) for name, versions in entries.items()} for action, entries in plan.items()}
    if expected is not None:
        require(comparison["apt"] == expected["apt"], "docker_prepare_expected_apt_closure_changed")
    require(dpkg_state(commands) == installed and boot_identity() == report["before"]["boot"], "docker_prepare_state_drift_before_install")
    for package in REVIEWED:
        verify_file(paths[package.name], package)
    require_idle(commands)
    if changes:
        with journal.open("xb") as intent:
            intent.write(canonical({"action": "install_exact_docker_packages_once", "run": env["GITHUB_RUN_ID"],
                                    "commit": env["GITHUB_SHA"], "boot_id": report["before"]["boot"]["boot_id"], "apt": comparison["apt"]}) + b"\n")
            intent.flush()
            os.fsync(intent.fileno())
        report["status"] = "installation_intended_outcome_unverified"
        install_reviewed(commands, [paths[name] for name in TARGETS if name in changes])
    report["dpkg_audit_after"] = commands.run("dpkg_audit_after", [DPKG, "--audit"])[1][:4000]
    require(report["dpkg_audit_after"] == "", "docker_prepare_dpkg_audit_not_clean")
    final = dpkg_state(commands)
    require(final == projected, "docker_prepare_dpkg_delta_changed")
    report["after"] = snapshot(env, final)
    before, after = report["before"], report["after"]
    toolchain = after["toolchain"]
    require(after["boot"] == before["boot"] and (not changes or all(
            toolchain["observation"]["processes"][name]["pid"] != before["toolchain"]["observation"]["processes"][name]["pid"] for name in SERVICES)),
            "docker_prepare_kernel_or_restart_not_verified")
    require(all(toolchain["files"][name]["bytes"] == size and toolchain["files"][name]["sha256"] == digest for name, (size, digest) in BINARIES.items())
            and toolchain["native"]["client"]["version"] == toolchain["native"]["server"]["version"] == "29.10.0"
            and toolchain["components"]["containerd"]["Version"].removeprefix("v") == "2.4.2"
            and toolchain["components"]["runc"]["Version"].removeprefix("v") == "1.5.3", "docker_prepare_exact_loaded_toolchain")
    security = toolchain["engine_settings"]["security"]
    original_security = before["toolchain"]["engine_settings"]["security"]
    if native_apparmor:
        report["apparmor_native"]["after"] = apparmor.confinement(commands, probe_image, "after")
        apparmor.enforce_options(original_security, security, report["apparmor_native"])
        docker.verify_same_host(toolchain, docker.inventory(env))
    else:
        require(any("seccomp" in item for item in security) and set(original_security) <= set(security),
                "docker_prepare_effective_protections_regressed")
    comparison["after"] = portable(after)
    if expected is not None:
        require(comparison["after"] == expected["after"], "docker_prepare_expected_effective_toolchain_changed")
    try:
        docker.verify_maintained(toolchain)
    except docker.ToolchainBlocked as error:
        report.update(publication_eligibility="blocked", publication_blocker=str(error))
        if expected is not None:
            raise
    else:
        report["publication_eligibility"] = "eligible"
    report["status"] = "prepared_verified"


def main(argv=None, *, env=None):
    env = os.environ if env is None else env
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--profile", required=True, choices=sorted(WORKFLOWS))
    parser.add_argument("--approved-commit", required=True)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--expected", type=Path)
    parser.add_argument("--expected-sha256")
    parser.add_argument("--native-apparmor", action="store_true")
    args = parser.parse_args(argv)
    try:
        hosted(env, args.profile, args.approved_commit)
        require(not args.native_apparmor or args.profile == "evaluate", "docker_prepare_native_apparmor_evaluation_only")
        require(sys.platform == "linux", "docker_prepare_linux_runner_required")
        root = Path(env["RUNNER_TEMP"]).resolve(strict=True)
        require(args.report == root / REPORT_NAME and not args.report.is_symlink(), "docker_prepare_report_scope")
        expected = None
        if args.profile == "protected":
            expected = read_expected(args.expected, args.expected_sha256)
        else:
            require(args.expected is None and args.expected_sha256 is None, "docker_prepare_evaluation_has_no_approval_receipt")
        os.umask(0o077)
        journal = root / "int-demo-a-docker-prepare-intent.json"
        require(not os.path.lexists(journal), "docker_prepare_prior_intent_requires_reconciliation")
        report = {"schema": SCHEMA, "profile": args.profile, "status": "blocked_before_install", "run": env["GITHUB_RUN_ID"],
                  "attempt": env["GITHUB_RUN_ATTEMPT"], "commit": env["GITHUB_SHA"], "cloud_credentials_used": False,
                  "oidc_job_capability": args.profile == "protected"}
        with args.report.open("xb") as output:
            try:
                with TemporaryDirectory(prefix="clipforge-docker-prepare.", dir=root) as scratch:
                    if args.native_apparmor:
                        prepare(env, Path(scratch), journal, report, expected, native_apparmor=True)
                    else:
                        prepare(env, Path(scratch), journal, report, expected)
            except (OSError, ValueError, KeyError, TypeError) as error:
                report["error_code"] = str(error) if isinstance(error, docker.ToolchainBlocked) else type(error).__name__
                response_code = getattr(error, "code", None)
                if type(response_code) is int:
                    report["http_status"] = response_code
            finally:
                output.write(canonical(report) + b"\n")
        print(json.dumps({key: report[key] for key in ("status", "error_code", "publication_eligibility") if key in report}, sort_keys=True))
        return int(report["status"] != "prepared_verified")
    except (OSError, ValueError, KeyError, TypeError) as error:
        print(json.dumps({"status": "blocked", "error_code": str(error) if isinstance(error, docker.ToolchainBlocked) else type(error).__name__}))
        return 1


if __name__ == "__main__":
    sys.exit(main())
