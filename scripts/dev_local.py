"""Prepare and run AUTH-01 in a separate, loopback-only Docker development project.

No operational Compose, data, credentials, Docker config or project-root bind is
used. Preparation creates new DB credentials outside the checkout and never
prints their contents. PostgreSQL uses a private internal network. The local
application also uses a frontend bridge for loopback publication and can have
egress; integration tests use a separate internal-only network, not network none.
This is an explicit HTTP-development profile, not a production launcher.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import http.client
import json
import os
from pathlib import Path
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


def choose_port(requested: int) -> int:
    require(0 <= requested <= 65535 and requested != 8080, "Use a free loopback port other than 8080.")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind(("127.0.0.1", requested))
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
    return "\n".join(key + "=" + dotenv(item) for key, item in variables.items()) + "\n"


def prepare(state: Path | None, port: int, local_http: bool) -> Path:
    require(local_http, "Explicit --local-http is required; this launcher is only for local development.")
    tracked = subprocess.check_output([host_executable("git"), "ls-files", "-z"], cwd=ROOT, timeout=30).decode("utf-8").rstrip("\0").split("\0")
    scan.validate_paths(tracked)  # Complete tracked-name validation before copying source.
    if state is None:
        state = Path(tempfile.mkdtemp(prefix="clipforge-auth01-dev-"))
    else:
        state = Path(os.path.abspath(state))
        context._check_components(state)
        require(not state.exists(), "Development state must be a new directory; existing state is never overwritten.")
        require(not context._inside(state, ROOT) and not context._inside(ROOT, state), "Development state must be outside the checkout.")
        state.mkdir(mode=0o700, parents=True)
    context._check_components(state)
    require(not context._inside(state, ROOT), "Development state must be outside the checkout.")
    selected_port = choose_port(port)
    project = "clipforge-auth01-" + uuid.uuid4().hex[:12]
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
    write_new(state / "runtime.vars", runtime_values(state, {"image": image, "port": selected_port, "origin": origin}), private=True)
    save(state / "development.json", {
        "schema": SCHEMA, "project": project, "origin": origin, "port": selected_port,
        "image": image, "source": str(ROOT), "profile": "local-http",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "note": "Generated credential contents are private and excluded from reports. This state has no relation to the operational service.",
    })
    return state


def load_state(path: Path) -> tuple[Path, dict]:
    state = Path(os.path.abspath(path))
    context._check_components(state)
    require(not context._inside(state, ROOT) and not context._inside(ROOT, state), "State must remain outside the checkout.")
    context._check_components(state / "development.json")
    value = json.loads((state / "development.json").read_text(encoding="utf-8"))
    require(value.get("schema") == SCHEMA, "Not an AUTH-01 development state.")
    project = value.get("project", "")
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
    context.verify_context(state / "context", state / "context-manifest.json")
    return state, value


def docker(state: Path) -> list[str]:
    endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
    return [host_executable("docker"), "--config", str(state / "docker-config"), "--host", endpoint]


def compose(state: Path, value: dict) -> list[str]:
    # --env-file and external project-directory prevent ambient .env ingestion.
    return docker(state) + ["compose", "--project-name", value["project"], "--project-directory", str(state),
        "--env-file", str(state / "runtime.vars"), "-f", str(state / "context/compose.dev.yaml")]


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


def require_image(state: Path, value: dict, directory: Path):
    build = json.loads((state / "build.json").read_text(encoding="utf-8"))
    actual = run(directory, "image-identity", docker(state) + ["image", "inspect", "--format", "{{.Id}}", value["image"]]).strip()
    require(actual == build["image_id"], "Development tag changed since the recorded build.")


def verify_runtime_boundary(state: Path, value: dict, directory: Path):
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
    save(directory / "runtime-boundary.json", {"status": "passed", "host_health": 200,
         "published_ports": ports, "postgres_published": False, "postgres_internal_only": True,
         "development_frontend_has_egress": True,
         "integration_test_network": "A separate internal network; never the development frontend."})


def build(state: Path, value: dict, directory: Path, browser: bool):
    require(not (state / "build.json").exists(), "This state already has a build; prepare a new state for changed sources.")
    run(directory, "postgres-pull", docker(state) + ["pull", "--platform", "linux/amd64", POSTGRES_IMAGE])
    ci_image = value["project"] + "-ci:local"
    common = docker(state) + ["build", "--platform", "linux/amd64", "--pull=false", "--progress", "plain"]
    run(directory, "ci-build", common + ["--file", str(state / "context/Dockerfile.ci"), "--target", "ci",
        "--tag", ci_image, "--iidfile", str(directory / "ci-image-id.txt"), str(state / "context")])
    ci_id = (directory / "ci-image-id.txt").read_text().strip()
    require(run(directory, "ci-parent-identity", docker(state) + ["image", "inspect", "--format", "{{.Id}}", ci_image]).strip() == ci_id, "CI parent identity changed.")
    run(directory, "app-build", common + ["--file", str(state / "context/Dockerfile.dev"), "--build-arg", "CI_IMAGE=" + ci_image,
        "--tag", value["image"], "--iidfile", str(directory / "app-image-id.txt"), str(state / "context")])
    results = {"image_id": (directory / "app-image-id.txt").read_text().strip(), "ci_image": ci_image,
               "ci_image_id": ci_id, "postgres_image": POSTGRES_IMAGE, "attempt": str(directory)}
    if browser:
        tag = value["project"] + "-browser:local"
        run(directory, "browser-build", common + ["--file", str(state / "context/Dockerfile.ci"), "--target", "browser",
            "--tag", tag, "--iidfile", str(directory / "browser-image-id.txt"), str(state / "context")])
        results.update(browser_image=tag, browser_image_id=(directory / "browser-image-id.txt").read_text().strip())
    context.verify_context(state / "context", state / "context-manifest.json")
    save(state / "build.json", results)


def execute(action: str, state: Path, value: dict, *, browser: bool = False, username: str | None = None):
    directory = attempt(state, action)
    command = compose(state, value)
    if action == "build":
        build(state, value, directory, browser)
    elif action == "up":
        require_image(state, value, directory)
        run(directory, "postgres-up", command + ["up", "-d", "--wait", "--wait-timeout", "90", "postgres"], timeout=120)
        run(directory, "migrate", command + ["run", "--rm", "--no-deps", "app", "python", "scripts/auth_migrate.py"], timeout=120)
        run(directory, "app-up", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)
        verify_runtime_boundary(state, value, directory)
    elif action == "admin":
        require(username and re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username), "A valid explicit --username is required.")
        require_image(state, value, directory)
        run(directory, "first-admin", command + ["exec", "app", "python", "scripts/auth_admin.py", "--username", username], interactive=True)
    elif action == "migrate":
        require_image(state, value, directory)
        run(directory, "migrate", command + ["run", "--rm", "--no-deps", "app", "python", "scripts/auth_migrate.py"], timeout=120)
    elif action == "restart":
        require_image(state, value, directory)
        run(directory, "restart-app", command + ["restart", "app"], timeout=120)
        run(directory, "wait-app", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)
        verify_runtime_boundary(state, value, directory)
    elif action == "status":
        print(run(directory, "status", command + ["ps", "--format", "json"], timeout=60).strip())
    elif action == "down":
        # No --volumes, pruning or filesystem deletion: candidate state persists.
        run(directory, "down", command + ["down", "--timeout", "30"], timeout=90)
    else:
        raise DevelopmentError("Unknown development action.")
    return directory


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["prepare", "build", "up", "admin", "migrate", "restart", "status", "down"])
    parser.add_argument("--state", type=Path)
    parser.add_argument("--local-http", action="store_true")
    parser.add_argument("--port", type=int, default=0)
    parser.add_argument("--browser", action="store_true")
    parser.add_argument("--username")
    args = parser.parse_args(argv)
    try:
        if args.action == "prepare":
            state = prepare(args.state, args.port, args.local_http)
            value = json.loads((state / "development.json").read_text(encoding="utf-8"))
            print(json.dumps({"status": "prepared", "state": str(state), "origin": value["origin"], "profile": "local-http"}))
        else:
            require(args.state is not None, "An explicit --state from prepare is required.")
            state, value = load_state(args.state)
            directory = execute(args.action, state, value, browser=args.browser, username=args.username)
            print(json.dumps({"status": "completed", "action": args.action, "attempt": str(directory), "origin": value["origin"]}))
        return 0
    except (DevelopmentError, OSError, subprocess.SubprocessError, ValueError) as error:
        # The launcher never includes file contents, connection strings or secrets.
        print(json.dumps({"status": "failed", "error_type": type(error).__name__, "message": "Development action failed. Check this attempt's own logs; do not alter the operational service."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
