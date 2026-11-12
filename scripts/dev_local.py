"""Run isolated AUTH candidates and persistent DEV/INT Docker environments.

No operational Compose, data, credentials, Docker config or project-root bind is
used. Preparation creates new DB credentials outside the checkout and never
prints their contents. PostgreSQL uses a private internal network. The local
application also uses a frontend bridge for loopback publication and can have
egress; integration tests use a separate internal-only network, not network none.
This is an explicit HTTP-development profile, not a production launcher.
"""
from __future__ import annotations

import argparse
import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import http.client
import json
import os
from pathlib import Path, PurePosixPath
import re
import secrets
import socket
import stat
import subprocess
import sys
import tempfile
import uuid

try:
    from scripts import prepare_ci_context as context
    from scripts import prepare_ci_scan as scan
except ModuleNotFoundError:
    import prepare_ci_context as context
    import prepare_ci_scan as scan


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "clipforge-auth01-development-1"
ENV_SCHEMA = "clipforge-env01-local-1"
OWNER_LABEL = "clipforge.environment.owner"
MANAGER_LABEL = "clipforge.managed-by"
MANAGER = "env01-local"
POSTGRES_IMAGE = "postgres:18.6-trixie@sha256:e3d24f6906d0760bf4da0dae872415391ededefad23fd471c47dc53b0ddf3c42"
HOST_EXECUTABLES = {
    "nt": {"git": "C:/Program Files/Git/cmd/git.exe",
           "docker": "C:/Program Files/Docker/Docker/resources/bin/docker.exe"},
    "posix": {"git": "/usr/bin/git", "docker": "/usr/bin/docker"},
}


class DevelopmentError(ValueError):
    """A local development boundary or required step failed."""


def require(condition, message):
    if not condition:
        raise DevelopmentError(message)


def host_executable(name: str) -> str:
    """Use reviewed host installation locations, never a PATH fallback.

    Program Files and /usr/bin are administrator-managed trust boundaries. This
    does not claim resistance to a compromised host administrator or builder.
    Nonstandard installs require an explicit review of this location map.
    """
    value = HOST_EXECUTABLES.get(os.name, {}).get(name)
    require(value is not None, "Unsupported host/tool installation.")
    path = Path(value)
    require(path.is_absolute(), "Host tools require an absolute reviewed path.")
    context._check_components(path)  # Reject symlinks/reparse points before stat.
    metadata = context._checked_stat(path)
    require(stat.S_ISREG(metadata.st_mode), "The reviewed host executable is not a regular file.")
    if os.name == "posix":
        require(metadata.st_uid == 0 and not (metadata.st_mode & (stat.S_IWGRP | stat.S_IWOTH)),
                "The reviewed host executable must be root-owned and not group/world writable.")
    require(os.access(path, os.X_OK), "The reviewed host tool is not executable.")
    return str(path)


def write_new(path: Path, value: str, *, private: bool = False):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600 if private else 0o644)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def save(path: Path, value):
    write_new(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def private_directory(path: Path, *, parents: bool = False):
    """Create a new private directory; never change an existing directory's ACL.

    Windows ignores POSIX 0700. A protected, inheritable DACL instead grants
    full access only to Owner Rights, SYSTEM and Builtin Administrators. Apply
    it before writing any credentials, account data or backup streams.
    """
    context._check_components(path)
    require(not os.path.lexists(path), "A private directory must be new; existing permissions are never changed.")
    path.mkdir(mode=0o700, parents=parents)
    if os.name != "nt":
        return
    import ctypes
    from ctypes import wintypes

    # Microsoft Learn: SetNamedSecurityInfoW, GetSecurityDescriptorDacl and
    # ConvertStringSecurityDescriptorToSecurityDescriptorW. OW is the Owner
    # Rights SID, not an account name or a locale-dependent principal lookup.
    security = ctypes.WinDLL("advapi32.dll", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32.dll", use_last_error=True)
    pointer = ctypes.c_void_p
    convert = security.ConvertStringSecurityDescriptorToSecurityDescriptorW
    convert.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, ctypes.POINTER(pointer), ctypes.POINTER(wintypes.ULONG)]
    convert.restype = wintypes.BOOL
    get_dacl = security.GetSecurityDescriptorDacl
    get_dacl.argtypes = [pointer, ctypes.POINTER(wintypes.BOOL), ctypes.POINTER(pointer), ctypes.POINTER(wintypes.BOOL)]
    get_dacl.restype = wintypes.BOOL
    set_security = security.SetNamedSecurityInfoW
    set_security.argtypes = [wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD, pointer, pointer, pointer, pointer]
    set_security.restype = wintypes.DWORD
    free = kernel.LocalFree
    free.argtypes = [pointer]
    free.restype = pointer
    descriptor = pointer()
    if not convert("D:P(A;OICI;FA;;;OW)(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", 1, ctypes.byref(descriptor), None):
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        present, defaulted, dacl = wintypes.BOOL(), wintypes.BOOL(), pointer()
        if not get_dacl(descriptor, ctypes.byref(present), ctypes.byref(dacl), ctypes.byref(defaulted)):
            raise ctypes.WinError(ctypes.get_last_error())
        require(bool(present.value) and bool(dacl.value), "Private Windows DACL is unavailable; no secret is written.")
        # SE_FILE_OBJECT; DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION.
        result = set_security(str(path), 1, 0x80000004, None, None, dacl, None)
        if result:
            raise ctypes.WinError(result)
    finally:
        free(descriptor)


def replace(path: Path, value: str):
    """Atomic publication; previous build/state records live in release history."""
    context._check_components(path)
    temporary = path.with_name(path.name + ".new-" + uuid.uuid4().hex[:12])
    write_new(temporary, value, private=True)
    os.replace(temporary, path)


def replace_json(path: Path, value):
    replace(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def default_state(environment: str) -> Path:
    require(environment in {"dev", "int"}, "Select dev or int explicitly.")
    base = os.environ.get("LOCALAPPDATA") if os.name == "nt" else os.environ.get("XDG_DATA_HOME")
    require(bool(base), "An explicit persistent --state or local application-data directory is required.")
    return Path(base) / "ClipForge" / "environments" / environment


def source_revision() -> str:
    revision = subprocess.check_output([host_executable("git"), "rev-parse", "HEAD"], cwd=ROOT, timeout=30).decode().strip()
    require(re.fullmatch(r"[a-f0-9]{40}", revision), "Source revision must be a full Git commit.")
    return revision


def manifest_hash(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def require_committed_sources(manifest: Path):
    """A visible commit must identify all candidate source files, including new ones."""
    names = [item["path"] for item in json.loads(manifest.read_text(encoding="utf-8"))["files"]]
    require_committed_names(names)


def require_committed_names(names: list[str]):
    tracked = subprocess.check_output([host_executable("git"), "ls-files", "-z"], cwd=ROOT, timeout=30).decode("utf-8").rstrip("\0").split("\0")
    scan.validate_paths(tracked)
    require(set(names) <= set(tracked), "Commit every candidate context source before preparing/building an ENV-01 image.")
    committed = subprocess.check_output([host_executable("git"), "ls-tree", "-r", "--name-only", "-z", "HEAD"], cwd=ROOT, timeout=30).decode("utf-8").rstrip("\0").split("\0")
    scan.validate_paths(committed)
    expected = {name for name in committed if name in context.ROOT_FILES or (
        PurePosixPath(name).parent.as_posix() in context.DIRECTORIES
        and PurePosixPath(name).suffix.lower() in context.DIRECTORIES[PurePosixPath(name).parent.as_posix()])}
    require(set(names) == expected, "Candidate context inventory differs from committed sources; review missing or new files before building.")
    changed = subprocess.check_output([host_executable("git"), "diff", "--name-only", "HEAD", "--", *names], cwd=ROOT, timeout=30)
    require(not changed.strip(), "Candidate context sources differ from HEAD; review and commit them before preparing/building.")


def migration_revision(source: Path) -> str:
    tree = ast.parse((source / "app/auth_migrations.py").read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(isinstance(target, ast.Name) and target.id == "REVISION" for target in node.targets):
            value = ast.literal_eval(node.value)
            require(isinstance(value, str) and re.fullmatch(r"auth[0-9]{2}_[0-9]{4}", value), "Invalid migration revision.")
            return value
    raise DevelopmentError("The source migration revision is missing.")


@contextmanager
def operation(state: Path):
    lock = state / "operation.lock"
    context._check_components(lock)
    write_new(lock, str(os.getpid()) + "\n", private=True)
    try:
        yield
    finally:
        context._check_components(lock)
        lock.unlink()


def choose_port(requested: int) -> int:
    require(0 <= requested <= 65535 and requested != 8080, "Use a free loopback port other than 8080.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        try:
            listener.bind(("127.0.0.1", requested))
        except OSError:
            raise DevelopmentError("Loopback port " + str(requested) + " is unavailable; no service was stopped.") from None
        selected = listener.getsockname()[1]
    require(selected != 8080, "The selected port is reserved; prepare a new development state.")
    return selected


def dotenv(value: str) -> str:
    require(not any(character in value for character in "'\r\n\0"), "Development paths cannot contain quotes or control characters.")
    return "'" + value + "'"


def runtime_values(state: Path, value: dict) -> str:
    private = state / "private"
    variables = {
        "CLIPFORGE_DEV_IMAGE": value["image"],
        "CLIPFORGE_DEV_PORT": str(value["port"]),
        "CLIPFORGE_DEV_ORIGIN": value["origin"],
        "CLIPFORGE_DEV_POSTGRES_PASSWORD_FILE": (private / "postgres-password").as_posix(),
        "CLIPFORGE_DEV_DATABASE_PASSWORD_FILE": (private / "database-password").as_posix(),
        "CLIPFORGE_DEV_INIT_SQL": (private / "initialize.sql").as_posix(),
    }
    if value.get("schema") == ENV_SCHEMA:
        variables.update({
            "CLIPFORGE_DEV_OWNER": value["owner"],
            "CLIPFORGE_DEV_ENVIRONMENT": value["environment"].upper(),
            "CLIPFORGE_DEV_COOKIE_NAMESPACE": value["cookie_namespace"],
            "CLIPFORGE_DEV_REVISION": value["revision"],
            "CLIPFORGE_DEV_MANIFEST_SHA256": value["source_manifest_sha256"],
        })
    return "\n".join(key + "=" + dotenv(item) for key, item in variables.items()) + "\n"


def prepare(state: Path | None, port: int, local_http: bool, environment: str | None = None) -> Path:
    require(local_http, "Explicit --local-http is required; this launcher is only for local development.")
    require(environment is None or environment in {"dev", "int", "restore"}, "Unknown local environment.")
    if state is None and environment in {"dev", "int"}:
        state = default_state(environment)
    require(environment != "restore" or state is not None, "A new disposable restore destination is required.")
    if state is not None:
        state = Path(os.path.abspath(state))
        context._check_components(state)
        require(not os.path.lexists(state), "Development state must be a new directory; existing state is never overwritten.")
        require(not context._inside(state, ROOT) and not context._inside(ROOT, state), "Development state must be outside the checkout.")
    tracked = subprocess.check_output([host_executable("git"), "ls-files", "-z"], cwd=ROOT, timeout=30).decode("utf-8").rstrip("\0").split("\0")
    scan.validate_paths(tracked)  # Complete tracked-name validation before copying source.
    if environment:
        require_committed_names([name for name, _ in context._files(ROOT, strict=False)])
    selected_port = choose_port(port)  # Fail a collision before creating state or credentials.
    if state is None:
        state = Path(tempfile.mkdtemp(prefix="clipforge-auth01-dev-"))
        # Legacy disposable candidates also receive a protected child before
        # any secret is written; their temporary parent contains no secrets.
        state = state / "private-state"
        private_directory(state)
    else:
        private_directory(state, parents=True)
    context._check_components(state)
    require(not context._inside(state, ROOT), "Development state must be outside the checkout.")
    suffix = uuid.uuid4().hex[:12]
    project = "clipforge-" + environment if environment in {"dev", "int"} else (
        "clipforge-restore-" + suffix if environment == "restore" else "clipforge-auth01-" + suffix)
    origin = f"http://127.0.0.1:{selected_port}"
    image = project + "-app:local"
    (state / "docker-config").mkdir()
    private = state / "private"
    private.mkdir(mode=0o700)
    admin_password, app_password = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
    write_new(private / "postgres-password", admin_password, private=True)
    write_new(private / "database-password", app_password, private=True)
    # Both strings are generated URL-safe values, never supplied SQL fragments.
    write_new(private / "initialize.sql", "CREATE ROLE clipforge LOGIN PASSWORD '" + app_password
              + "';\nCREATE DATABASE clipforge OWNER clipforge;\n", private=True)
    del admin_password, app_password
    context.prepare_context(ROOT, state / "context", state / "context-manifest.json")
    context.verify_context(state / "context", state / "context-manifest.json")
    value = {
        "schema": SCHEMA, "project": project, "origin": origin, "port": selected_port,
        "image": image, "source": str(ROOT), "profile": "local-http",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Generated credential contents are private and excluded from reports. This state has no relation to the operational service.",
    }
    if environment:
        require_committed_sources(state / "context-manifest.json")
        value.update(schema=ENV_SCHEMA, environment=environment, owner=uuid.uuid4().hex,
                     cookie_namespace=environment if environment != "restore" else "restore-" + suffix,
                     revision=source_revision(), context="context", manifest="context-manifest.json",
                     source_manifest_sha256=manifest_hash(state / "context-manifest.json"))
    write_new(state / "runtime.vars", runtime_values(state, value), private=True)
    save(state / "development.json", value)
    return state


def load_state(path: Path) -> tuple[Path, dict]:
    state = Path(os.path.abspath(path))
    context._check_components(state)
    require(not context._inside(state, ROOT) and not context._inside(ROOT, state), "State must remain outside the checkout.")
    context._check_components(state / "development.json")
    metadata = context._checked_stat(state / "development.json")
    require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1 and metadata.st_size <= 1024 * 1024, "Development metadata must be a bounded regular file.")
    value = json.loads((state / "development.json").read_text(encoding="utf-8"))
    require(value.get("schema") in {SCHEMA, ENV_SCHEMA}, "Not a managed local development state.")
    project = value.get("project", "")
    if value["schema"] == ENV_SCHEMA:
        environment = value.get("environment")
        require(environment in {"dev", "int", "restore"}, "Invalid environment identity.")
        expected = "clipforge-" + environment
        require(project == expected if environment != "restore" else re.fullmatch(r"clipforge-restore-[a-f0-9]{12}", project), "Invalid exclusive environment project.")
        require(re.fullmatch(r"[a-f0-9]{32}", value.get("owner", "")), "Invalid environment owner identity.")
        namespace = environment if environment != "restore" else project.removeprefix("clipforge-")
        require(value.get("cookie_namespace") == namespace, "Cookie namespace differs from environment identity.")
        require(re.fullmatch(r"[a-f0-9]{40}", value.get("revision", "")), "Invalid source commit.")
        require(re.fullmatch(r"[a-f0-9]{64}", value.get("source_manifest_sha256", "")), "Invalid source manifest hash.")
        require(re.fullmatch(r"context|snapshot-[a-f0-9]{12}", value.get("context", "")), "Invalid context identity.")
        expected_manifest = "context-manifest.json" if value["context"] == "context" else value["context"] + "-manifest.json"
        require(value.get("manifest") == expected_manifest, "Invalid manifest identity.")
        require(value.get("image") == project + "-app:local" or re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("image", "")), "Invalid immutable application image.")
    else:
        require(re.fullmatch(r"clipforge-auth01-[a-f0-9]{12}", project), "Invalid exclusive development project.")
        require(value.get("image") == project + "-app:local", "Invalid development image name.")
    require(type(value.get("port")) is int and 1 <= value["port"] <= 65535 and value["port"] != 8080, "Invalid development port.")
    require(value.get("origin") == f"http://127.0.0.1:{value['port']}" and value.get("profile") == "local-http", "Invalid explicit loopback profile.")
    require(value.get("source") == str(ROOT), "This state belongs to a different checkout.")
    context._check_components(state / "runtime.vars")
    require((state / "runtime.vars").read_text(encoding="utf-8") == runtime_values(state, value),
            "Development configuration differs from its generated paths/profile.")
    for name in ["postgres-password", "database-password", "initialize.sql"]:
        context._check_components(state / "private" / name)
    context.verify_context(state / value.get("context", "context"), state / value.get("manifest", "context-manifest.json"))
    if value["schema"] == ENV_SCHEMA:
        require(manifest_hash(state / value["manifest"]) == value["source_manifest_sha256"], "Source manifest identity changed.")
    return state, value


def docker(state: Path) -> list[str]:
    endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
    return [host_executable("docker"), "--config", str(state / "docker-config"), "--host", endpoint]


def compose(state: Path, value: dict) -> list[str]:
    # --env-file and external project-directory prevent ambient .env ingestion.
    return docker(state) + ["compose", "--project-name", value["project"], "--project-directory", str(state),
        "--env-file", str(state / "runtime.vars"), "-f", str(state / value.get("context", "context") / "compose.dev.yaml")]


def attempt(state: Path, action: str) -> Path:
    destination = state / ("run-" + action + "-" + uuid.uuid4().hex[:12])
    destination.mkdir()
    return destination


def run(directory: Path, label: str, argv: list[str], *, timeout: int = 1200, interactive: bool = False) -> str:
    start = datetime.now(timezone.utc).isoformat()
    code, error = None, None
    # Ambient Compose variables must not replace the generated isolated profile.
    environment = {key: value for key, value in os.environ.items()
                   if not key.startswith(("COMPOSE_", "CLIPFORGE_DEV_"))}
    try:
        if interactive:
            # Preserve a real terminal for getpass; never capture credentials.
            code = subprocess.run(argv, timeout=timeout, env=environment).returncode
        else:
            with (directory / (label + ".stdout.log")).open("xb") as stdout, (directory / (label + ".stderr.log")).open("xb") as stderr:
                code = subprocess.run(argv, stdout=stdout, stderr=stderr, timeout=timeout, env=environment).returncode
    except subprocess.TimeoutExpired:
        error = "timeout; inspect this project's containers before retrying"
    save(directory / (label + "-command.json"), {"argv": argv, "exit_code": code, "error": error,
         "started_utc": start, "finished_utc": datetime.now(timezone.utc).isoformat(), "interactive_output_captured": False})
    require(code == 0 and error is None, f"{label} failed; its attempt is retained in {directory}.")
    return "" if interactive else (directory / (label + ".stdout.log")).read_text(encoding="utf-8")


def verify_ownership(state: Path, value: dict, directory: Path):
    """Validate *all* objects selected by Compose before allowing a mutation.

    Names are also queried independently, so unlabelled name collisions cannot
    be adopted. Inspect output is restricted to identity/labels, never Env.
    Legacy candidates retain their frozen Compose context and old behavior.
    """
    if value.get("schema") != ENV_SCHEMA:
        return
    project = value["project"]
    discovered = {}
    for kind, listing, names, name_filter in (
        ("container", ["ps", "-aq"], {project + "-app-1", project + "-postgres-1"}, "^/" + project + "-"),
        ("network", ["network", "ls", "-q"], {project + "_private", project + "_frontend"}, "^" + project + "_"),
        ("volume", ["volume", "ls", "-q"], {project + "_app_data", project + "_postgres_data"}, "^" + project + "_"),
    ):
        identifiers = set()
        for selector, filter_value in (("project", "label=com.docker.compose.project=" + project), ("name", "name=" + name_filter)):
            identifiers.update(run(directory, "owned-list-" + kind + "-" + selector,
                                   docker(state) + listing + ["--filter", filter_value], timeout=30).split())
        records = []
        for index, identifier in enumerate(sorted(identifiers)):
            require(re.fullmatch(r"[a-f0-9]{12,64}", identifier) if kind != "volume" else re.fullmatch(r"[a-zA-Z0-9_.-]+", identifier), "Unexpected Docker object identity.")
            fields = '{"name":{{json .Name}},"labels":{{json .Config.Labels}}}' if kind == "container" else '{"name":{{json .Name}},"labels":{{json .Labels}}}'
            record = json.loads(run(directory, "owned-inspect-" + kind + "-" + str(index), docker(state) + [kind, "inspect", "--format", fields, identifier], timeout=30))
            name = record["name"].lstrip("/")
            labels = record.get("labels") or {}
            require(name in names or (kind == "container" and re.fullmatch(re.escape(project) + r"-app-run-[a-f0-9]+", name)), "Unexpected object in environment project.")
            require(labels.get(OWNER_LABEL) == value["owner"] and labels.get(MANAGER_LABEL) == MANAGER
                    and labels.get("com.docker.compose.project") == project, "A resource does not belong to this environment; operation refused.")
            record["name"] = name
            records.append(record)
        discovered[kind] = records
    save(directory / "ownership.json", {"status": "passed", "project": project, "resources": discovered})


def check_available_port(state: Path, value: dict, directory: Path):
    """An already running owned app may keep its port; any other holder fails."""
    running = run(directory, "port-owner", docker(state) + ["ps", "-q", "--filter", "name=^/" + value["project"] + "-app-1$"], timeout=30).strip()
    if not running:
        try:
            selected = choose_port(value["port"])
        except OSError:
            raise DevelopmentError("The saved loopback port is occupied; no other service was stopped. Resolve the collision before starting this environment.") from None
        require(selected == value["port"], "The saved loopback port is unavailable.")


def publish_state(state: Path, value: dict):
    replace(state / "runtime.vars", runtime_values(state, value))
    replace_json(state / "development.json", value)


def read_build(state: Path) -> dict:
    path = state / "build.json"
    context._check_components(path)
    value = json.loads(path.read_text(encoding="utf-8"))
    require(re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("image_id", "")), "Invalid recorded image ID.")
    return value


def require_image(state: Path, value: dict, directory: Path):
    build = read_build(state)
    actual = run(directory, "image-identity", docker(state) + ["image", "inspect", "--format", "{{.Id}}", value["image"]]).strip()
    require(actual == build["image_id"], "Development tag changed since the recorded build.")
    if value.get("schema") == ENV_SCHEMA:
        require(value["image"] == actual and build.get("revision") == value["revision"]
                and build.get("source_manifest_sha256") == value["source_manifest_sha256"], "Active image and source records differ.")


def verify_active_image(state: Path, value: dict, directory: Path, *, require_running: bool = True):
    """Selected metadata alone does not prove which image an app is executing."""
    if value.get("schema") != ENV_SCHEMA:
        return
    actual = run(directory, "active-application-image", docker(state) + ["container", "inspect", "--format", "{{.Image}}|{{.State.Running}}", value["project"] + "-app-1"], timeout=30).strip().split("|")
    build_record = read_build(state)
    require(len(actual) == 2 and actual[0] == build_record["image_id"] == value["image"],
            "The application container does not use the selected exact ImageID; run this environment's up before validating/promoting/backing up.")
    require(not require_running or actual[1] == "true", "The selected application container is not running.")


def verify_runtime_boundary(state: Path, value: dict, directory: Path):
    verify_active_image(state, value, directory)
    internal = run(directory, "network-isolation", docker(state) + ["network", "inspect", "--format", "{{.Internal}}", value["project"] + "_private"]).strip()
    require(internal == "true", "The database network must be internal.")
    app_name = value["project"] + "-app-1"
    postgres_name = value["project"] + "-postgres-1"
    ports = json.loads(run(directory, "published-ports", docker(state) + ["inspect", "--format", "{{json .NetworkSettings.Ports}}", app_name]))
    require(ports == {"8000/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(value["port"])}]},
            "The application must actually publish only its selected loopback port.")
    database_ports = json.loads(run(directory, "database-ports", docker(state) + ["inspect", "--format", "{{json .HostConfig.PortBindings}}", postgres_name]))
    require(not database_ports, "PostgreSQL must not publish a host port.")
    database_networks = json.loads(run(directory, "database-networks", docker(state) + ["inspect", "--format", "{{json .NetworkSettings.Networks}}", postgres_name]))
    require(set(database_networks) == {value["project"] + "_private"}, "PostgreSQL must remain on its private network only.")
    connection = http.client.HTTPConnection("127.0.0.1", value["port"], timeout=10)
    try:
        connection.request("GET", "/health")
        response = connection.getresponse()
        require(response.status == 200, "The published application health check failed.")
    finally:
        connection.close()
    if value.get("schema") == ENV_SCHEMA:
        connection = http.client.HTTPConnection("127.0.0.1", value["port"], timeout=10)
        try:
            connection.request("GET", "/environment")
            response = connection.getresponse()
            require(response.status == 200, "The published environment identity is unavailable.")
            identity = json.loads(response.read(4096))
            require(identity == {"environment": value["environment"].upper(), "revision": value["revision"]},
                    "The running environment identity differs from its selected source revision.")
        finally:
            connection.close()
    save(directory / "runtime-boundary.json", {"status": "passed", "host_health": 200,
         "published_ports": ports, "postgres_published": False, "postgres_internal_only": True,
         "development_frontend_has_egress": True,
         "integration_test_network": "A separate internal network; never the development frontend."})


def build(state: Path, value: dict, directory: Path, browser: bool):
    persistent = value.get("schema") == ENV_SCHEMA
    require(not persistent or value["environment"] == "dev", "Only DEV builds candidates; INT receives an explicit promotion.")
    require(persistent or not (state / "build.json").exists(), "This state already has a build; prepare a new state for changed sources.")
    candidate = dict(value)
    if persistent and (state / "build.json").exists():
        tracked = subprocess.check_output([host_executable("git"), "ls-files", "-z"], cwd=ROOT, timeout=30).decode("utf-8").rstrip("\0").split("\0")
        scan.validate_paths(tracked)
        candidate["context"] = "snapshot-" + uuid.uuid4().hex[:12]
        candidate["manifest"] = candidate["context"] + "-manifest.json"
        context.prepare_context(ROOT, state / candidate["context"], state / candidate["manifest"])
        candidate["revision"] = source_revision()
        candidate["source_manifest_sha256"] = manifest_hash(state / candidate["manifest"])
    source = state / candidate.get("context", "context")
    manifest = state / candidate.get("manifest", "context-manifest.json")
    context.verify_context(source, manifest)
    if persistent:
        require_committed_sources(manifest)
    run(directory, "postgres-pull", docker(state) + ["pull", "--platform", "linux/amd64", POSTGRES_IMAGE])
    identifier = uuid.uuid4().hex[:12] if persistent else "local"
    ci_image = value["project"] + "-ci:" + identifier
    app_image = value["project"] + "-app:" + identifier if persistent else value["image"]
    common = docker(state) + ["build", "--platform", "linux/amd64", "--pull=false", "--progress", "plain"]
    run(directory, "ci-build", common + ["--file", str(source / "Dockerfile.ci"), "--target", "ci",
        "--tag", ci_image, "--iidfile", str(directory / "ci-image-id.txt"), str(source)])
    ci_id = (directory / "ci-image-id.txt").read_text().strip()
    require(run(directory, "ci-parent-identity", docker(state) + ["image", "inspect", "--format", "{{.Id}}", ci_image]).strip() == ci_id, "CI parent identity changed.")
    run(directory, "app-build", common + ["--file", str(source / "Dockerfile.dev"), "--build-arg", "CI_IMAGE=" + ci_image,
        "--tag", app_image, "--iidfile", str(directory / "app-image-id.txt"), str(source)])
    results = {"image_id": (directory / "app-image-id.txt").read_text().strip(), "ci_image": ci_image,
               "ci_image_id": ci_id, "postgres_image": POSTGRES_IMAGE, "attempt": str(directory)}
    if browser:
        tag = value["project"] + "-browser:" + identifier
        run(directory, "browser-build", common + ["--file", str(source / "Dockerfile.ci"), "--target", "browser",
            "--tag", tag, "--iidfile", str(directory / "browser-image-id.txt"), str(source)])
        results.update(browser_image=tag, browser_image_id=(directory / "browser-image-id.txt").read_text().strip())
    context.verify_context(source, manifest)
    if persistent:
        candidate["image"] = results["image_id"]
        results.update(image_tag=app_image, revision=candidate["revision"],
                       source_manifest_sha256=candidate["source_manifest_sha256"],
                       migration_revision=migration_revision(source), context=candidate["context"],
                       manifest=candidate["manifest"], built_locally=True,
                       github_artifact_identity_verified=False)
        activate(state, candidate, results)
        value.update(candidate)
    else:
        save(state / "build.json", results)


def activate(state: Path, value: dict, build_record: dict):
    """Retain every previous image/context; never prune or downgrade a schema."""
    history = state / "releases"
    history.mkdir(mode=0o700, exist_ok=True)
    context._check_components(history)
    if (state / "build.json").exists():
        previous = read_build(state)
        record = {"state": json.loads((state / "development.json").read_text(encoding="utf-8")), "build": previous}
        save(history / ("release-" + uuid.uuid4().hex[:12] + ".json"), record)
        replace_json(state / "previous.json", record)
    replace_json(state / "build.json", build_record)
    publish_state(state, value)


def schema_revision(state: Path, value: dict, directory: Path, label="schema-revision") -> str:
    output = run(directory, label, compose(state, value) + ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "clipforge", "-Atc",
        "SELECT revision FROM auth_schema_migrations ORDER BY revision"], timeout=30)
    revisions = output.splitlines()
    require(revisions and all(re.fullmatch(r"auth[0-9]{2}_[0-9]{4}", item) for item in revisions), "The database migration history is unavailable or unknown.")
    return revisions[-1]


def record_migration(state: Path, value: dict, directory: Path):
    build_record = read_build(state)
    revision = schema_revision(state, value, directory)
    require(revision == build_record.get("migration_revision", revision), "The database revision differs from this candidate.")
    save(directory / "migration.json", {"status": "passed", "migration_revision": revision, "image_id": build_record["image_id"]})
    replace_json(state / "migration.json", {"revision": revision, "image_id": build_record["image_id"], "attempt": str(directory)})


def promote(state: Path, value: dict, source_state: Path) -> Path:
    require(value.get("schema") == ENV_SCHEMA and value.get("environment") == "int", "Only INT can receive a DEV promotion.")
    source_state, source_value = load_state(source_state)
    require(source_value.get("schema") == ENV_SCHEMA and source_value.get("environment") == "dev" and source_state != state,
            "Promotion requires an independent DEV state.")
    with operation(state), operation(source_state):
        directory = attempt(state, "promote")
        verify_ownership(state, value, directory)
        require_image(source_state, source_value, directory)
        verify_active_image(source_state, source_value, directory)
        source_build = read_build(source_state)
        validation_path = source_state / "validated.json"
        context._check_components(validation_path)
        validation = json.loads(validation_path.read_text(encoding="utf-8"))
        require(validation.get("image_id") == source_build["image_id"] and validation.get("status") == "passed"
                and validation.get("source_manifest_sha256") == source_value["source_manifest_sha256"], "Validate this exact DEV candidate before promotion.")
        candidate = dict(value)
        candidate["context"] = "snapshot-" + uuid.uuid4().hex[:12]
        candidate["manifest"] = candidate["context"] + "-manifest.json"
        context.prepare_context(source_state / source_value["context"], state / candidate["context"], state / candidate["manifest"])
        require(manifest_hash(state / candidate["manifest"]) == source_value["source_manifest_sha256"], "Promotion source copy differs from DEV.")
        candidate.update(image=source_build["image_id"], revision=source_value["revision"], source_manifest_sha256=source_value["source_manifest_sha256"])
        promoted = {**source_build, "context": candidate["context"], "manifest": candidate["manifest"],
                    "promoted_from": str(source_state), "attempt": str(directory), "promotion_rebuilt": False}
        # Promotion records an exact image, but starts/stops no containers.
        activate(state, candidate, promoted)
        value.update(candidate)
        save(directory / "promotion.json", {"status": "passed", "image_id": promoted["image_id"], "rebuilt": False})
        return directory


def validate_candidate(state: Path, value: dict, directory: Path, report: Path):
    require(value.get("schema") == ENV_SCHEMA and value.get("environment") == "dev", "Candidate validation applies only to DEV.")
    require_image(state, value, directory)
    verify_runtime_boundary(state, value, directory)
    report = Path(os.path.abspath(report))
    context._check_components(report)
    result = json.loads(report.read_text(encoding="utf-8"))
    require(result.get("schema") == "clipforge-env01-candidate-validation-1" and result.get("status") == "passed"
            and result.get("image_id") == value["image"] and result.get("source_manifest_sha256") == value["source_manifest_sha256"],
            "A successful acceptance report for this exact DEV image and manifest is required.")
    replace_json(state / "validated.json", {"status": "passed", "image_id": value["image"],
                 "source_manifest_sha256": value["source_manifest_sha256"], "report": str(report)})


def rollback(state: Path, value: dict, directory: Path):
    require(value.get("schema") == ENV_SCHEMA, "Rollback requires an ENV-01 state.")
    context._check_components(state / "previous.json")
    previous = json.loads((state / "previous.json").read_text(encoding="utf-8"))
    candidate, build_record = previous["state"], previous["build"]
    require(candidate.get("owner") == value["owner"] and candidate.get("project") == value["project"], "Previous application belongs to another environment.")
    require(schema_revision(state, value, directory) == build_record.get("migration_revision"), "Rollback blocked: the current schema is not exactly compatible; no DDL downgrade is performed.")
    actual = run(directory, "rollback-image", docker(state) + ["image", "inspect", "--format", "{{.Id}}", build_record["image_id"]]).strip()
    require(actual == candidate["image"], "The retained rollback image is unavailable.")
    context.verify_context(state / candidate["context"], state / candidate["manifest"])
    activate(state, candidate, build_record)
    value.update(candidate)


def execute(action: str, state: Path, value: dict, *, browser: bool = False, username: str | None = None,
            destination: Path | None = None, report: Path | None = None):
    with operation(state):
        return execute_locked(action, state, value, browser=browser, username=username, destination=destination, report=report)


def execute_locked(action: str, state: Path, value: dict, *, browser: bool = False, username: str | None = None,
                   destination: Path | None = None, report: Path | None = None):
    directory = attempt(state, action)
    command = compose(state, value)
    verify_ownership(state, value, directory)
    if action == "build":
        build(state, value, directory, browser)
    elif action == "up":
        require_image(state, value, directory)
        if value.get("schema") == ENV_SCHEMA:
            check_available_port(state, value, directory)
        run(directory, "postgres-up", command + ["up", "-d", "--wait", "--wait-timeout", "90", "postgres"], timeout=120)
        run(directory, "migrate", command + ["run", "--rm", "--no-deps", "app", "python", "scripts/auth_migrate.py"], timeout=120)
        record_migration(state, value, directory)
        run(directory, "app-up", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)
        verify_runtime_boundary(state, value, directory)
    elif action == "admin":
        require(username and re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username), "A valid explicit --username is required.")
        require_image(state, value, directory)
        run(directory, "first-admin", command + ["exec", "app", "python", "scripts/auth_admin.py", "--username", username], interactive=True)
    elif action == "migrate":
        require_image(state, value, directory)
        run(directory, "migrate", command + ["run", "--rm", "--no-deps", "app", "python", "scripts/auth_migrate.py"], timeout=120)
        record_migration(state, value, directory)
    elif action == "restart":
        require_image(state, value, directory)
        run(directory, "restart-app", command + ["restart", "app"], timeout=120)
        run(directory, "wait-app", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)
        verify_runtime_boundary(state, value, directory)
    elif action == "status":
        containers = run(directory, "status", command + ["ps", "--all", "--format", "json"], timeout=60).strip()
        print(json.dumps({"environment": value.get("environment", "candidate"), "origin": value["origin"],
                          "revision": value.get("revision"), "image_id": value["image"],
                          "source_manifest_sha256": value.get("source_manifest_sha256"),
                          "containers": [json.loads(line) for line in containers.splitlines() if line.strip()]}))
    elif action == "down":
        # No --volumes, pruning or filesystem deletion: candidate state persists.
        run(directory, "down", command + ["down", "--timeout", "30"], timeout=90)
    elif action == "validate":
        require(report is not None, "A real candidate acceptance --report is required.")
        validate_candidate(state, value, directory, report)
    elif action == "rollback":
        rollback(state, value, directory)
    elif action == "backup":
        require(destination is not None, "A new private --destination is required.")
        try:
            from scripts import dev_backup
        except ModuleNotFoundError:
            import dev_backup
        dev_backup.backup(state, value, directory, destination)
    else:
        raise DevelopmentError("Unknown development action.")
    return directory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "build", "up", "admin", "migrate", "restart", "status", "down", "validate", "promote", "rollback", "backup", "restore"])
    parser.add_argument("--environment", choices=["dev", "int"])
    parser.add_argument("--state", type=Path)
    parser.add_argument("--local-http", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--username")
    parser.add_argument("--source-state", type=Path)
    parser.add_argument("--destination", type=Path)
    parser.add_argument("--backup", type=Path)
    parser.add_argument("--report", type=Path)
    args = parser.parse_args(argv)
    try:
        if args.action == "prepare":
            state = prepare(args.state, args.port, args.local_http, args.environment)
            value = json.loads((state / "development.json").read_text(encoding="utf-8"))
            print(json.dumps({"status": "prepared", "state": str(state), "origin": value["origin"], "profile": "local-http"}))
        elif args.action == "restore":
            require(args.state is not None and args.backup is not None and args.environment is None, "Restore requires an explicit new disposable --state and --backup; never DEV or INT.")
            try:
                from scripts import dev_backup
            except ModuleNotFoundError:
                import dev_backup
            state, directory = dev_backup.restore(args.backup, args.state, args.port, args.local_http)
            _, value = load_state(state)
            print(json.dumps({"status": "completed", "action": "restore", "attempt": str(directory), "origin": value["origin"], "state": str(state)}))
        else:
            state_arg = args.state or (default_state(args.environment) if args.environment else None)
            require(state_arg is not None, "An explicit --state or --environment from prepare is required.")
            state, value = load_state(state_arg)
            require(args.environment is None or value.get("environment") == args.environment, "The selected state belongs to a different environment.")
            if args.action == "promote":
                require(args.source_state is not None, "Promotion requires an explicit DEV --source-state.")
                directory = promote(state, value, args.source_state)
            else:
                directory = execute(args.action, state, value, browser=args.browser, username=args.username, destination=args.destination, report=args.report)
            print(json.dumps({"status": "completed", "action": args.action, "attempt": str(directory), "origin": value["origin"]}))
        return 0
    except (DevelopmentError, OSError, subprocess.SubprocessError, ValueError) as error:
        # The launcher never includes file contents, connection strings or secrets.
        message = str(error) if isinstance(error, DevelopmentError) else "Development action failed. Check this attempt's own logs; do not alter the operational service."
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "message": message}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
