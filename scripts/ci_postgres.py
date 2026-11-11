"""Disposable PostgreSQL lifecycle for AUTH CI, independent of development data.

prepare downloads the pinned image. start/check/migrate/run use an exclusive
internal Docker network. Credentials live outside CI_REPORTS, never in argv.
The workflow must call cleanup with if: always(); SIGTERM/interrupt and setup
failures also trigger it. Cleanup includes test containers still running.
"""
from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
import stat
import subprocess
import sys
import time
import uuid

try:
    from scripts import dev_local, prepare_ci_context as context
except ModuleNotFoundError:
    import dev_local
    import prepare_ci_context as context


ROOT = Path(__file__).resolve().parents[1]
SCHEMA = "clipforge-ci-postgres-1"
POSTGRES_IMAGE = dev_local.POSTGRES_IMAGE
OWNER_LABEL = "clipforge.ci.auth"
MANAGER_LABEL = "clipforge.managed-by"
MANAGER = "ci-postgres-v1"
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
ROLE = re.compile(r"[a-z][a-z0-9-]{0,23}")
PREFIX = re.compile(r"clipforge-ci-auth-[a-f0-9]{12}-[a-f0-9]{12}")


class LifecycleError(ValueError):
    """Unsafe lifecycle input or failed setup; error text never contains secrets."""


def require(condition, message):
    if not condition:
        raise LifecycleError(message)


def save_new(path: Path, value):
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, indent=2, sort_keys=True)
        stream.write("\n")


def publish_once(path: Path, value):
    """Retain the first successful summary; later attempts have separate logs."""
    if path.exists():
        context._check_components(path)
        previous = json.loads(path.read_text(encoding="utf-8"))
        require(previous.get("schema") == value["schema"] and previous.get("nonce") == value["nonce"],
                "A summary already belongs to a different execution.")
        return
    save_new(path, value)


def private_write(path: Path, value: str):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value)
        stream.flush()
        os.fsync(stream.fileno())


def safe_directory(path: Path):
    context._check_components(path)
    require(stat.S_ISDIR(context._checked_stat(path).st_mode), "Expected a real directory.")


@dataclass(frozen=True)
class Configuration:
    scratch: Path
    reports: Path
    user: str
    run_key: str
    image_id: str | None = None

    @classmethod
    def from_environment(cls, environ=None):
        env = os.environ if environ is None else environ
        for key in ("CI_SCRATCH", "CI_REPORTS", "CI_CONTAINER_USER"):
            require(bool(env.get(key)), "Missing required CI lifecycle configuration.")
        scratch = Path(os.path.abspath(env["CI_SCRATCH"]))
        reports = Path(os.path.abspath(env["CI_REPORTS"]))
        require(not context._inside(scratch, ROOT) and not context._inside(ROOT, scratch), "CI scratch must be outside the checkout.")
        require(context._inside(reports, scratch) and reports != scratch, "CI reports must be a separate directory within scratch.")
        require(not context._inside(reports, scratch / "ci-postgres")
                and not context._inside(scratch / "ci-postgres", reports), "Reports and lifecycle state must not overlap.")
        user = env["CI_CONTAINER_USER"]
        require(re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user), "An explicit non-root runner UID:GID is required.")
        key = env.get("CI_RUN_KEY") or (env.get("GITHUB_RUN_ID", "local") + "-" + env.get("GITHUB_RUN_ATTEMPT", "1"))
        require(re.fullmatch(r"[A-Za-z0-9_.-]{1,100}", key), "Invalid CI run identity.")
        image = env.get("CI_IMAGE_ID") or None
        require(image is None or IMAGE_ID.fullmatch(image), "CI_IMAGE_ID must be an immutable image ID.")
        for path in (scratch, reports):
            safe_directory(path)
        if os.name == "posix":
            require(user == f"{os.getuid()}:{os.getgid()}" and os.getuid() != 0, "Container identity must equal the non-root runner.")
            for path in (scratch, reports):
                info = path.stat()
                require(f"{info.st_uid}:{info.st_gid}" == user and stat.S_IMODE(info.st_mode) == 0o700,
                        "Runner scratch/report ownership and mode must be UID:GID 0700.")
        return cls(scratch, reports, user, key, image)

    @property
    def state_root(self):
        return self.scratch / "ci-postgres"

    @property
    def private(self):
        return self.state_root / "private"

    @property
    def report_root(self):
        return self.reports / "postgres-lifecycle"


def validate_command(command):
    """CI runs versioned Python entrypoints, not inline programs or secret argv."""
    value = list(command)
    if value[:1] == ["--"]:
        value.pop(0)
    require(value and value.pop(0) in {"python", "python3", "/usr/local/bin/python"}, "Only the candidate's Python entrypoints are supported.")
    if value[:1] == ["-B"]:
        value.pop(0)
    require(value and re.fullmatch(r"(?:scripts|tests)/[a-z][a-z0-9_]*\.py", value[0]), "A versioned Python script path is required.")
    require(all(not any(word in argument.lower() for word in ("password", "cookie", "token", "dsn", "://")) for argument in value),
            "Secrets and connection strings must not be command arguments.")
    require(all("\0" not in argument and "\n" not in argument and "\r" not in argument for argument in value), "Invalid command argument.")
    return ["/usr/local/bin/python", "-B", *value]


class Lifecycle:
    def __init__(self, configuration: Configuration, executor=None):
        self.config = configuration
        self.executor = executor or subprocess.run

    def docker(self):
        endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
        return [dev_local.host_executable("docker"), "--config", str(self.config.state_root / "docker-config"), "--host", endpoint]

    def attempt(self, action):
        self.config.report_root.mkdir(mode=0o700, exist_ok=True)
        safe_directory(self.config.report_root)
        path = self.config.report_root / (action + "-" + uuid.uuid4().hex[:12])
        path.mkdir(mode=0o700)
        return path

    def call(self, directory, label, arguments, timeout=120, *, allowed=(0,)):
        argv = self.docker() + arguments
        started = datetime.now(timezone.utc).isoformat()
        code, error = None, None
        try:
            with (directory / (label + ".stdout.log")).open("xb") as stdout, (directory / (label + ".stderr.log")).open("xb") as stderr:
                result = self.executor(argv, stdout=stdout, stderr=stderr, timeout=timeout)
                code = result.returncode
        except subprocess.TimeoutExpired:
            error = "TimeoutExpired"
        except (KeyboardInterrupt, InterruptedError):
            error = "cancelled"
            raise
        finally:
            save_new(directory / (label + "-command.json"), {"argv": argv, "exit_code": code, "error": error,
                "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat()})
        require(code in allowed and error is None, label + " failed; its attempt is retained.")
        return code, (directory / (label + ".stdout.log")).read_text(encoding="utf-8")

    def state(self):
        path = self.config.state_root / "state.json"
        context._check_components(path)
        info = context._checked_stat(path)
        require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Lifecycle state must be a regular file.")
        value = json.loads(path.read_text(encoding="utf-8"))
        require(value.get("schema") == SCHEMA and value.get("run_key") == self.config.run_key, "Lifecycle state belongs to another run.")
        require(value.get("scratch") == str(self.config.scratch) and value.get("reports") == str(self.config.reports)
                and value.get("user") == self.config.user, "Lifecycle state paths/identity changed.")
        require(re.fullmatch(r"[a-f0-9]{32}", value.get("nonce", "")) and PREFIX.fullmatch(value.get("prefix", "")), "Invalid lifecycle resource identity.")
        expected = "clipforge-ci-auth-" + hashlib.sha256(self.config.run_key.encode()).hexdigest()[:12] + "-" + value["nonce"][:12]
        require(value["prefix"] == expected, "Lifecycle resource identity mismatch.")
        return value

    def labels(self, value):
        return ["--label", OWNER_LABEL + "=" + value["nonce"], "--label", MANAGER_LABEL + "=" + MANAGER]

    def network_name(self, value):
        return value["prefix"] + "-network"

    def prepare(self):
        self.config.state_root.mkdir(mode=0o700)
        (self.config.state_root / "docker-config").mkdir(mode=0o700)
        nonce = uuid.uuid4().hex
        value = {"schema": SCHEMA, "run_key": self.config.run_key, "nonce": nonce,
                 "prefix": "clipforge-ci-auth-" + hashlib.sha256(self.config.run_key.encode()).hexdigest()[:12] + "-" + nonce[:12],
                 "scratch": str(self.config.scratch), "reports": str(self.config.reports), "user": self.config.user}
        save_new(self.config.state_root / "state.json", value)
        directory = self.attempt("prepare")
        self.call(directory, "postgres-pull", ["pull", "--platform", "linux/amd64", POSTGRES_IMAGE], timeout=600)
        _, identity = self.call(directory, "postgres-identity", ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", POSTGRES_IMAGE])
        parts = identity.strip().split("|")
        require(len(parts) == 3 and IMAGE_ID.fullmatch(parts[0]) and parts[1:] == ["linux", "amd64"], "Unexpected PostgreSQL image platform.")
        save_new(self.config.state_root / "prepared.json", {"image": POSTGRES_IMAGE, "image_id": parts[0], "report": str(directory)})
        for name, item in (("postgres-image-id.txt", parts[0]), ("postgres-image-ref.txt", POSTGRES_IMAGE)):
            with (self.config.reports / name).open("x", encoding="utf-8", newline="\n") as stream:
                stream.write(item + "\n")
        return {"status": "prepared", "image_id": parts[0], "report": str(directory)}

    def start_arguments(self, value):
        uid, gid = self.config.user.split(":")
        return ["run", "-d", "--pull", "never", "--platform", "linux/amd64", "--name", value["prefix"] + "-postgres",
            *self.labels(value), "--network", self.network_name(value), "--network-alias", "postgres",
            "--user", self.config.user, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", f"/var/lib/postgresql:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=1g",
            "--tmpfs", f"/var/run/postgresql:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=16m",
            "--tmpfs", f"/tmp:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=128m",
            "--shm-size=256m",
            "--mount", f"type=bind,src={self.config.private / 'postgres-password'},dst=/run/secrets/postgres-password,readonly",
            "--mount", f"type=bind,src={self.config.private / 'initialize.sql'},dst=/docker-entrypoint-initdb.d/10-ci-auth.sql,readonly",
            "--env", "POSTGRES_USER=postgres", "--env", "POSTGRES_DB=postgres",
            "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
            "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256",
            "--health-cmd", "pg_isready -U postgres -d postgres", "--health-interval", "2s",
            "--health-timeout", "3s", "--health-retries", "30", POSTGRES_IMAGE]

    def start(self):
        value = self.state()
        require((self.config.state_root / "prepared.json").is_file(), "Image preparation must complete before starting PostgreSQL.")
        self.config.private.mkdir(mode=0o700)
        admin_password, app_password = secrets.token_urlsafe(48), secrets.token_urlsafe(48)
        private_write(self.config.private / "postgres-password", admin_password)
        private_write(self.config.private / "database-password", app_password)
        private_write(self.config.private / "initialize.sql", "CREATE ROLE clipforge_ci LOGIN PASSWORD '" + app_password
                      + "';\nCREATE DATABASE clipforge_ci OWNER clipforge_ci;\n")
        del admin_password, app_password
        directory = self.attempt("start")
        _, network_id = self.call(directory, "network-create", ["network", "create", "--internal", *self.labels(value), self.network_name(value)])
        require(re.fullmatch(r"[a-f0-9]{64}", network_id.strip()), "Unexpected network ID.")
        save_new(self.config.state_root / "network.json", {"id": network_id.strip(), "name": self.network_name(value)})
        _, postgres_id = self.call(directory, "postgres-start", self.start_arguments(value))
        require(re.fullmatch(r"[a-f0-9]{64}", postgres_id.strip()), "Unexpected PostgreSQL container ID.")
        save_new(self.config.state_root / "postgres.json", {"id": postgres_id.strip(), "name": value["prefix"] + "-postgres"})
        deadline = time.monotonic() + 90
        number, healthy = 0, False
        while time.monotonic() < deadline:
            _, response = self.call(directory, "health-" + str(number), ["inspect", "--format", "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{end}}", value["prefix"] + "-postgres"])
            if response.strip() == "running|healthy":
                healthy = True
                break
            require(response.strip().startswith("running|") and "unhealthy" not in response, "PostgreSQL stopped or failed health; no retry.")
            number += 1
            time.sleep(1)
        require(healthy, "PostgreSQL health timed out.")
        save_new(self.config.state_root / "started.json", {"status": "healthy", "report": str(directory)})
        return {"status": "healthy", "report": str(directory)}

    def candidate(self, directory, image_id=None):
        image = image_id or self.config.image_id
        require(image and IMAGE_ID.fullmatch(image), "An immutable CI image ID is required.")
        _, result = self.call(directory, "candidate-identity", ["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", image])
        require(result.strip() == image + "|linux|amd64", "Candidate identity/platform mismatch.")
        return image

    def report_directory(self, subdirectory):
        if not subdirectory:
            return self.config.reports
        require(re.fullmatch(r"[a-z][a-z0-9_-]{0,40}", subdirectory), "Invalid report subdirectory.")
        target = self.config.reports / subdirectory
        target.mkdir(mode=0o700, exist_ok=True)
        safe_directory(target)
        if os.name == "posix":
            metadata = target.stat()
            require(f"{metadata.st_uid}:{metadata.st_gid}" == self.config.user and stat.S_IMODE(metadata.st_mode) == 0o700,
                    "Report subdirectory must retain runner ownership and mode0700.")
        return target

    def runner_arguments(self, value, role, reports, *, browser=False):
        require(ROLE.fullmatch(role), "Invalid test role.")
        schema = "auth01_test_" + value["nonce"][:12] + "_" + role.replace("-", "_")
        arguments = ["run", "--rm", "--pull", "never", "--platform", "linux/amd64",
            "--name", value["prefix"] + "-" + role + "-" + uuid.uuid4().hex[:8], *self.labels(value),
            "--network", self.network_name(value), "--user", self.config.user,
            "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,exec,nosuid,nodev,size=3g",
            "--mount", f"type=bind,src={reports},dst=/ci-results",
            "--mount", f"type=bind,src={self.config.private / 'database-password'},dst=/run/secrets/database-password,readonly"]
        variables = {"CLIPFORGE_DATABASE_HOST": "postgres", "CLIPFORGE_DATABASE_PORT": "5432",
            "CLIPFORGE_DATABASE_NAME": "clipforge_ci", "CLIPFORGE_DATABASE_USER": "clipforge_ci",
            "CLIPFORGE_DATABASE_PASSWORD_FILE": "/run/secrets/database-password", "CLIPFORGE_DATABASE_SCHEMA": schema,
            "CLIPFORGE_AUTH_TEST_DATABASE": "1", "CLIPFORGE_AUTH_PROFILE": "local-http",
            "CLIPFORGE_AUTH_ORIGIN": "http://127.0.0.1:8000", "CLIPFORGE_DATA_DIR": "/tmp/ci-auth-data",
            "CLIPFORGE_AI_PROVIDER": "disabled", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1"}
        for key, item in variables.items():
            arguments += ["--env", key + "=" + item]
        if browser:
            arguments += ["--init", "--shm-size=1g"]
        return arguments

    def check(self):
        value = self.state()
        require((self.config.state_root / "started.json").is_file(), "PostgreSQL must be healthy before checks.")
        directory = self.attempt("check")
        image = self.candidate(directory)
        _, network_output = self.call(directory, "internal-network", ["network", "inspect", "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}},"internal":{{json .Internal}},"ipv6":{{json .EnableIPv6}}}', self.network_name(value)])
        network = json.loads(network_output)
        self.owned(value, network, "network")
        require(network.get("internal") is True and network.get("ipv6") is False, "Integration network must be internal IPv4.")
        _, postgres_output = self.call(directory, "postgres-ports", ["inspect", "--format",
            '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}},"ports":{{json .HostConfig.PortBindings}},"image":{{json .Image}}}', value["prefix"] + "-postgres"])
        postgres = json.loads(postgres_output)
        self.owned(value, postgres, "container")
        prepared = json.loads((self.config.state_root / "prepared.json").read_text(encoding="utf-8"))
        require(not postgres.get("ports") and postgres.get("image") == prepared["image_id"], "PostgreSQL identity/port isolation mismatch.")
        probe = '''import json,os,socket,sys
from pathlib import Path
try:
 import psycopg
 password=Path('/run/secrets/database-password').read_text().strip()
 with psycopg.connect(host='postgres',dbname='clipforge_ci',user='clipforge_ci',password=password,connect_timeout=5) as connection:
  row=connection.execute("SELECT current_user,rolsuper,rolcreatedb FROM pg_roles WHERE rolname=current_user").fetchone()
 del password
 if row != ('clipforge_ci',False,False):raise ValueError('Unexpected database role')
 routes=Path('/proc/net/route').read_text().splitlines()[1:]
 if any(line.split()[1]=='00000000' for line in routes if line.split()):raise ValueError('Default IPv4 route exists')
 outcomes=[]
 for endpoint in [('1.1.1.1',443),('8.8.8.8',53)]:
  try:
   with socket.create_connection(endpoint,timeout=2):pass
  except OSError:outcomes.append({'endpoint':list(endpoint),'connection':'blocked'})
  else:raise ValueError('External TCP reachable')
 status=Path('/proc/self/status').read_text().splitlines()
 fields={line.split(':',1)[0]:line.split(':',1)[1].strip() for line in status if ':' in line}
 if fields['NoNewPrivs']!='1' or any(int(fields[key],16) for key in ['CapEff','CapPrm','CapBnd']):raise ValueError('Unexpected capabilities')
 print(json.dumps({'status':'passed','database':'reachable','database_role':row[0],'superuser':row[1],'createdb':row[2],'uid_gid':str(os.getuid())+':'+str(os.getgid()),'external_tcp_probes':outcomes,'default_ipv4_route':False,'network':'Docker internal, not network none','no_new_privileges':True,'capabilities':'zero'}))
except Exception as error:
 print(json.dumps({'status':'failed','error_type':type(error).__name__}))
 sys.exit(1)
'''
        _, output = self.call(directory, "network-probe", self.runner_arguments(value, "network-check", self.config.reports)
                              + [image, "/usr/local/bin/python", "-B", "-c", probe])
        result = json.loads(output)
        require(result.get("status") == "passed" and result.get("uid_gid") == self.config.user, "Network/runner check failed.")
        save_new(directory / "result.json", result)
        summary = {"schema": "clipforge-ci-postgres-isolation-1", "status": "passed", "run_key": value["run_key"],
                   "nonce": value["nonce"], "prefix": value["prefix"], "postgres_image_ref": POSTGRES_IMAGE,
                   "postgres_image_id": prepared["image_id"], "ci_image_id": image,
                   "postgres": {"id": postgres["id"], "name": postgres["name"].lstrip("/"), "published_ports": False},
                   "network": {key: network[key] for key in ("id", "name", "internal", "ipv6")}, "probe": result,
                   "checked_utc": datetime.now(timezone.utc).isoformat(), "report": str(directory)}
        publish_once(self.config.reports / "postgres-isolation.json", summary)
        save_new(self.config.state_root / "checked.json", {"status": "passed", "report": str(directory)})
        return {"status": "passed", "report": str(directory)}

    def run(self, role, command, image_id=None, reports_subdir=None, browser=False, timeout=1200):
        require(ROLE.fullmatch(role), "Invalid test role.")
        value = self.state()
        require((self.config.state_root / "checked.json").is_file(), "Network/database checks must pass before running candidate code.")
        require(role == "migration" or (self.config.state_root / "migrated.json").is_file(), "Real candidate migration must pass before tests.")
        script = validate_command(command)
        directory = self.attempt("run-" + role)
        image = self.candidate(directory, image_id)
        reports = self.report_directory(reports_subdir)
        code, _ = self.call(directory, "candidate", self.runner_arguments(value, role, reports, browser=browser)
                            + [image, *script], timeout=timeout, allowed=tuple(range(256)))
        result = {"status": "passed" if code == 0 else "failed", "exit_code": code, "role": role,
                  "image_id": image, "network": "internal", "report": str(directory)}
        save_new(directory / "result.json", result)
        return result

    def migrate(self):
        result = self.run("migration", ["python", "scripts/auth_migrate.py"], timeout=120)
        require(result["exit_code"] == 0, "Migration failed; no empty success substituted.")
        save_new(self.config.state_root / "migrated.json", result)
        return result

    def owned(self, value, item, kind):
        labels = item.get("labels") or {}
        require(labels.get(OWNER_LABEL) == value["nonce"] and labels.get(MANAGER_LABEL) == MANAGER,
                "Cleanup refused an object without this run's exact ownership labels.")
        name = item.get("name", "").lstrip("/")
        expected = name.startswith(value["prefix"] + "-") if kind == "container" else name == self.network_name(value)
        require(expected, "Cleanup refused an unexpected resource name.")
        require(re.fullmatch(r"[a-f0-9]{12,64}", item.get("id", "")), "Cleanup refused an invalid resource ID.")
        record = self.config.state_root / ("network.json" if kind == "network" else "postgres.json")
        if record.is_file() and (kind == "network" or name == value["prefix"] + "-postgres"):
            known = json.loads(record.read_text(encoding="utf-8"))
            require(known["id"] == item["id"] and known["name"] == name, "Resource name now resolves to another ID.")

    def optional_resource_call(self, directory, label, arguments, identifier):
        """A --rm container can exit while cancellation cleanup is inspecting it."""
        code, output = self.call(directory, label, arguments, allowed=(0, 1))
        if code == 0:
            return output
        error = (directory / (label + ".stderr.log")).read_text(encoding="utf-8").strip().lower()
        missing = ("no such container: " + identifier, "no such object: " + identifier,
                   "network " + identifier + " not found", "no such network: " + identifier)
        require(any(error.endswith(phrase) for phrase in missing), "Docker operation failed; absence was not established.")
        return None

    def cleanup(self):
        directory = self.attempt("cleanup")
        if not (self.config.state_root / "state.json").exists():
            result = {"status": "clean", "containers_removed": [], "networks_removed": [], "private_files_removed": [], "report": str(directory)}
            save_new(directory / "result.json", result)
            return result
        value = self.state()
        removed = {"containers": [], "networks": [], "private_files": []}
        # Query and validate every selected object before removing any of them.
        _, containers = self.call(directory, "list-containers", ["ps", "-aq", "--filter", "label=" + OWNER_LABEL + "=" + value["nonce"]])
        objects = []
        for index, identifier in enumerate(containers.split()):
            require(re.fullmatch(r"[a-f0-9]{12,64}", identifier), "Unexpected container ID from daemon.")
            output = self.optional_resource_call(directory, "inspect-container-" + str(index), ["inspect", "--format",
                '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Config.Labels}}}', identifier], identifier)
            if output is None:
                continue
            item = json.loads(output)
            self.owned(value, item, "container")
            objects.append(item)
        _, networks = self.call(directory, "list-networks", ["network", "ls", "-q", "--filter", "label=" + OWNER_LABEL + "=" + value["nonce"]])
        network_objects = []
        for index, identifier in enumerate(networks.split()):
            require(re.fullmatch(r"[a-f0-9]{12,64}", identifier), "Unexpected network ID from daemon.")
            output = self.optional_resource_call(directory, "inspect-network-" + str(index), ["network", "inspect", "--format",
                '{"id":{{json .Id}},"name":{{json .Name}},"labels":{{json .Labels}}}', identifier], identifier)
            if output is None:
                continue
            item = json.loads(output)
            self.owned(value, item, "network")
            network_objects.append(item)
        for index, item in enumerate(objects):
            self.optional_resource_call(directory, "remove-container-" + str(index), ["rm", "-f", item["id"]], item["id"])
            removed["containers"].append(item["name"].lstrip("/"))
        for index, item in enumerate(network_objects):
            self.optional_resource_call(directory, "remove-network-" + str(index), ["network", "rm", item["id"]], item["id"])
            removed["networks"].append(item["name"])
        _, containers_left = self.call(directory, "remaining-containers", ["ps", "-aq", "--filter", "label=" + OWNER_LABEL + "=" + value["nonce"]])
        _, networks_left = self.call(directory, "remaining-networks", ["network", "ls", "-q", "--filter", "label=" + OWNER_LABEL + "=" + value["nonce"]])
        require(not containers_left.strip() and not networks_left.strip(), "Owned resources remain after cleanup.")
        for name in ("postgres-password", "database-password", "initialize.sql"):
            path = self.config.private / name
            if path.exists():
                context._check_components(path)
                info = context._checked_stat(path)
                require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1, "Refused an unexpected private lifecycle file.")
                path.unlink()  # Three known generated files only; no recursive removal.
                removed["private_files"].append(name)
        result = {"schema": "clipforge-ci-postgres-cleanup-1", "status": "clean", "run_key": value["run_key"],
                  "nonce": value["nonce"], "prefix": value["prefix"], "ownership_verified": True,
                  **{key + "_removed": items for key, items in removed.items()}, "remaining_container_ids": [],
                  "remaining_network_ids": [], "private_files_remaining": [],
                  "checked_utc": datetime.now(timezone.utc).isoformat(), "report": str(directory)}
        save_new(directory / "result.json", result)
        publish_once(self.config.reports / "postgres-cleanup.json", result)
        return result


def interrupted(signum, frame):
    raise InterruptedError("Lifecycle interrupted")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "start", "check", "migrate", "cleanup"):
        commands.add_parser(name)
    run = commands.add_parser("run")
    run.add_argument("--role", required=True)
    run.add_argument("--image-id")
    run.add_argument("--reports-subdir")
    run.add_argument("--browser", action="store_true")
    run.add_argument("--timeout", type=int, default=1200)
    run.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(argv)
    lifecycle = None
    try:
        lifecycle = Lifecycle(Configuration.from_environment())
        if hasattr(signal, "SIGTERM"):
            signal.signal(signal.SIGTERM, interrupted)
        if args.action == "run":
            require(30 <= args.timeout <= 3600, "Candidate timeout outside its permitted bounds.")
            result = lifecycle.run(args.role, args.command, args.image_id, args.reports_subdir, args.browser, args.timeout)
        else:
            result = getattr(lifecycle, args.action)()
        print(json.dumps(result, sort_keys=True))
        return result.get("exit_code", 0)
    except (KeyboardInterrupt, InterruptedError):
        if lifecycle is not None:
            try:
                lifecycle.cleanup()
            except Exception:
                print(json.dumps({"status": "cleanup_failed", "action": "cancel", "follow_up": "Run this lifecycle's cleanup; never prune global Docker resources."}), file=sys.stderr)
        return 130
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        if lifecycle is not None and args.action in {"start", "check", "migrate", "run"}:
            try:
                lifecycle.cleanup()
            except Exception:
                print(json.dumps({"status": "cleanup_failed", "action": args.action}), file=sys.stderr)
        print(json.dumps({"status": "failed", "action": args.action, "error_type": type(error).__name__}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
