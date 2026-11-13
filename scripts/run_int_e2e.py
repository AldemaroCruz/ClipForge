"""Run the INT acceptance on disposable local containers, never on GCP.

Preparation (image/model/voice downloads) is deliberately separate. This command
accepts immutable, already prepared images and a caller-owned synthetic MP4. The
browser communicates with this host controller through a tiny allowlisted file
protocol; it never receives a Docker socket. Only public summaries leave private
scratch. API and worker use the same runtime image.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import signal
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
IMAGE_ID = re.compile(r"sha256:[a-f0-9]{64}")
IMAGE_REF = re.compile(r"[a-z0-9][a-z0-9./_-]+(?::[A-Za-z0-9_.-]+)?@sha256:[a-f0-9]{64}")
EMULATOR_IMAGE = "fsouza/fake-gcs-server@sha256:af5fcc12a29db42953c9659dc44b478c164b78f6303390cf25fc93037d78522b"
OWNER_LABEL = "clipforge.int-e2e"
MANAGER_LABEL = "clipforge.managed-by"
MANAGER = "int-e2e-v1"
ACTIONS = frozenset({"replace_api", "drain", "start_pair", "wait_workers", "start_worker", "kill_worker",
                     "start_worker_chain", "terminate_worker_child"})
DRIVER = "tests/browser_int_e2e.py"
DATABASE_CONTRACT = "tests/cloud_dispatch_contract.py"


class AcceptanceError(ValueError):
    """A failed safety boundary or acceptance assertion; no secret details."""


def require(value, message):
    if not value:
        raise AcceptanceError(message)


def write_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        stream.write(value if isinstance(value, str) else json.dumps(value, sort_keys=True, indent=2) + "\n")


def input_file(path):
    path = Path(path).absolute()
    context._check_components(path)
    info = context._checked_stat(path)
    require(path.is_file() and info.st_nlink == 1, "A regular, unlinked explicit fixture file is required.")
    require(not context._inside(path, ROOT), "Synthetic fixture must be prepared outside the checkout.")
    return path


def validate_request(value, nonce):
    require(isinstance(value, dict) and set(value) == {"nonce", "sequence", "action"}, "Invalid control request shape.")
    require(value["nonce"] == nonce and type(value["sequence"]) is int and 1 <= value["sequence"] <= 100,
            "Control request identity mismatch.")
    require(value["action"] in ACTIONS, "Unapproved control action.")
    return value["sequence"], value["action"]


def owned(item, nonce):
    labels = item.get("labels") or {}
    return labels.get(OWNER_LABEL) == nonce and labels.get(MANAGER_LABEL) == MANAGER


class Harness:
    def __init__(self, *, scratch, runtime_image, browser_image, postgres_image, fixture, user, executor=None):
        self.scratch = Path(scratch).absolute()
        context._check_components(self.scratch)
        require(self.scratch.is_dir(), "Caller must prepare private scratch first.")
        require(not context._inside(self.scratch, ROOT) and not context._inside(ROOT, self.scratch),
                "Private scratch must be outside the checkout.")
        require(re.fullmatch(r"[1-9][0-9]*:[1-9][0-9]*", user), "Explicit non-root UID:GID required.")
        require(IMAGE_ID.fullmatch(runtime_image) and IMAGE_ID.fullmatch(browser_image), "Runtime/browser image IDs must be immutable.")
        require(IMAGE_REF.fullmatch(postgres_image), "PostgreSQL must be pinned by digest.")
        if os.name == "posix":
            info = self.scratch.stat()
            require(user == f"{os.getuid()}:{os.getgid()}" and info.st_mode & 0o777 == 0o700,
                    "Scratch must be owned by the explicit non-root runner with mode 0700.")
        self.fixture = input_file(fixture)
        require(self.fixture.suffix.lower() == ".mp4" and self.fixture.stat().st_size <= 64 * 1024 * 1024,
                "A bounded synthetic MP4 fixture is required.")
        self.runtime_image, self.browser_image, self.postgres_image, self.user = runtime_image, browser_image, postgres_image, user
        self.executor = executor or subprocess.run
        self.nonce = uuid.uuid4().hex
        self.prefix = "clipforge-int-e2e-" + self.nonce[:16]
        self.base = self.scratch / self.prefix
        self.private, self.public = self.base / "private", self.base / "public"
        self.control = self.private / "control"
        self.network = self.prefix + "-network"
        self.containers = []
        self.workers = []
        self.api_name = None
        self.api_replacements = 0
        self.network_created = False
        self.events = []
        self.emulator_id = None
        self.postgres_id = None
        self.anchor = self.prefix + "-anchor"
        self.stage = "inputs"

    def docker(self, arguments, *, timeout=120, allowed=(0,)):
        endpoint = "npipe:////./pipe/dockerDesktopLinuxEngine" if os.name == "nt" else "unix:///var/run/docker.sock"
        argv = [dev_local.host_executable("docker"), "--config", str(self.private / "docker-config"), "--host", endpoint, *arguments]
        result = self.executor(argv, capture_output=True, timeout=timeout)
        # Raw output can contain application exceptions: retain only privately.
        number = len(self.events) + 1
        stdout = result.stdout.decode("utf-8", errors="replace") if isinstance(result.stdout, bytes) else result.stdout
        stderr = result.stderr.decode("utf-8", errors="replace") if isinstance(result.stderr, bytes) else result.stderr
        write_new(self.private / f"command-{number:04d}.stdout", stdout or "")
        write_new(self.private / f"command-{number:04d}.stderr", stderr or "")
        self.events.append({"operation": arguments[0], "exit_code": result.returncode})
        require(result.returncode in allowed, "Disposable Docker operation failed; private diagnostics retained.")
        return stdout or ""

    def labels(self):
        return ["--label", OWNER_LABEL + "=" + self.nonce, "--label", MANAGER_LABEL + "=" + MANAGER]

    def verify_image(self, image):
        result = self.docker(["image", "inspect", "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}", image]).strip().split("|")
        require(len(result) == 3 and IMAGE_ID.fullmatch(result[0]) and result[1:] == ["linux", "amd64"],
                "Prepared image platform/identity mismatch.")
        if IMAGE_ID.fullmatch(image):
            require(result[0] == image, "Prepared image identity changed.")
        return result[0]

    def base_args(self, role, *, namespace=False, memory="1g"):
        uid, gid = self.user.split(":")
        name = self.prefix + "-" + role
        require(name not in self.containers, "A disposable container name cannot be reused.")
        self.containers.append(name)
        return ["run", "-d", "--pull", "never", "--platform", "linux/amd64", "--name", name,
                *self.labels(), "--network", "container:" + self.anchor if namespace else self.network,
                "--user", self.user, "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
                "--memory", memory, "--cpus", "2", "--tmpfs",
                f"/tmp:rw,exec,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=3g"]

    def app_args(self, role, *, namespace=False, memory="1g"):
        arguments = self.base_args(role, namespace=namespace, memory=memory)
        arguments += ["--mount", f"type=bind,src={self.private / 'database-password'},dst=/run/secrets/database-password,readonly"]
        variables = {"CLIPFORGE_DATABASE_HOST": "postgres", "CLIPFORGE_DATABASE_PORT": "5432",
            "CLIPFORGE_DATABASE_NAME": "clipforge_int_e2e", "CLIPFORGE_DATABASE_USER": "clipforge_int_e2e",
            "CLIPFORGE_DATABASE_PASSWORD_FILE": "/run/secrets/database-password",
            "CLIPFORGE_DATABASE_SCHEMA": "int_e2e_" + self.nonce[:16], "CLIPFORGE_AUTH_TEST_DATABASE": "1",
            "CLIPFORGE_AUTH_PROFILE": "local-http", "CLIPFORGE_AUTH_ORIGIN": "http://127.0.0.1:8000",
            "CLIPFORGE_ENVIRONMENT": "", "CLIPFORGE_ENV": "", "CLIPFORGE_REVISION": "",
            "CLIPFORGE_CLOUD_LOCAL_TEST": "1", "CLIPFORGE_STORAGE_BACKEND": "gcs",
            "CLIPFORGE_GCS_BUCKET": self.prefix, "CLIPFORGE_GCS_ENDPOINT": "http://gcs:4443",
            "CLIPFORGE_JOBS_DISPATCH_MODE": "local_manual", "CLIPFORGE_DATA_DIR": "/tmp/clipforge-work",
            "CLIPFORGE_AI_PROVIDER": "disabled", "HF_HUB_OFFLINE": "1", "TRANSFORMERS_OFFLINE": "1",
            "WHISPER_MODEL": "tiny", "HF_HOME": "/opt/clipforge/models",
            "CLIPFORGE_MODEL_LOCK": "/opt/clipforge/whisper-int.json",
            "PYTHONPATH": "/app", "PYTHONDONTWRITEBYTECODE": "1", "OMP_NUM_THREADS": "2", "FFMPEG_THREADS": "2"}
        for key, value in variables.items():
            arguments += ["--env", key + "=" + value]
        return arguments

    def run_and_wait(self, args, *, timeout=600):
        self.docker(args)
        name = args[args.index("--name") + 1]
        result = self.docker(["wait", name], timeout=timeout).strip()
        require(result == "0", "Disposable candidate process failed; inspect private container logs.")
        return name

    def prepare(self):
        self.base.mkdir(mode=0o700)
        for directory in (self.private, self.public, self.control, self.private / "docker-config"):
            directory.mkdir(mode=0o700)
        self.stage = "image_verification"
        self.verify_image(self.runtime_image)
        self.verify_image(self.browser_image)
        self.postgres_id = self.verify_image(self.postgres_image)
        self.emulator_id = self.verify_image(EMULATOR_IMAGE)
        write_new(self.private / "database-password", secrets.token_urlsafe(48))
        write_new(self.private / "postgres-password", secrets.token_urlsafe(48))
        password = (self.private / "database-password").read_text()
        write_new(self.private / "initialize.sql", "CREATE ROLE clipforge_int_e2e LOGIN PASSWORD '" + password
                  + "';\nCREATE DATABASE clipforge_int_e2e OWNER clipforge_int_e2e;\n")
        del password
        self.docker(["network", "create", "--internal", *self.labels(), self.network])
        self.network_created = True
        network = json.loads(self.docker(["network", "inspect", "--format",
            '{"internal":{{json .Internal}},"labels":{{json .Labels}},"ipv6":{{json .EnableIPv6}}}', self.network]))
        require(owned(network, self.nonce) and network["internal"] is True and network["ipv6"] is False,
                "Acceptance network must be an owned internal IPv4 network.")
        uid, gid = self.user.split(":")
        self.stage = "postgres_start"
        args = self.base_args("postgres") + ["--network-alias", "postgres", "--shm-size", "256m",
            "--tmpfs", f"/var/lib/postgresql:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=1g",
            "--tmpfs", f"/var/run/postgresql:rw,nosuid,nodev,uid={uid},gid={gid},mode=0700,size=16m",
            "--mount", f"type=bind,src={self.private / 'postgres-password'},dst=/run/secrets/postgres-password,readonly",
            "--mount", f"type=bind,src={self.private / 'initialize.sql'},dst=/docker-entrypoint-initdb.d/10-e2e.sql,readonly",
            "--env", "POSTGRES_USER=postgres", "--env", "POSTGRES_DB=postgres",
            "--env", "POSTGRES_PASSWORD_FILE=/run/secrets/postgres-password",
            "--env", "POSTGRES_INITDB_ARGS=--auth-host=scram-sha-256", self.postgres_image]
        self.docker(args)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            result = self.docker(["exec", self.prefix + "-postgres", "pg_isready", "-h", "127.0.0.1", "-U", "postgres", "-d", "postgres"], allowed=(0, 1, 2, 3))
            if "accepting connections" in result:
                break
            time.sleep(1)
        else:
            raise AcceptanceError("Disposable PostgreSQL did not become ready.")
        self.stage = "emulator_start"
        self.docker(self.base_args("gcs") + ["--network-alias", "gcs", EMULATOR_IMAGE, "-scheme", "http",
                    "-port", "4443", "-backend", "memory", "-external-url", "http://gcs:4443"])
        self.docker(self.base_args("anchor") + [self.runtime_image, "/usr/local/bin/python", "-c", "import time; time.sleep(21600)"])
        self.stage = "migrations"
        for role in ("migrate-first", "migrate-second"):
            self.run_and_wait(self.app_args(role) + [self.runtime_image, "/usr/local/bin/python", "-m", "app.cloud.migrate"], timeout=120)
        args = self.app_args("fixture", namespace=True) + ["--mount", f"type=bind,src={ROOT / DRIVER},dst=/qa/browser_int_e2e.py,readonly",
            "--mount", f"type=bind,src={self.private},dst=/private", self.runtime_image,
            "/usr/local/bin/python", "-B", "/qa/browser_int_e2e.py", "--prepare"]
        self.stage = "synthetic_fixture"
        self.run_and_wait(args, timeout=120)
        self.stage = "dispatch_contracts"
        self.run_dispatch_contracts()
        self.stage = "api_start"
        self.start_api()

    def run_dispatch_contracts(self):
        args = self.app_args("dispatch-contracts") + ["--mount", f"type=bind,src={ROOT / DATABASE_CONTRACT},dst=/qa/cloud_dispatch_contract.py,readonly",
            "--mount", f"type=bind,src={self.private},dst=/private", "--mount", f"type=bind,src={self.public},dst=/public",
            "--env", "CLIPFORGE_CLOUD_DISPATCH_TEST=1", self.runtime_image, "/usr/local/bin/python", "-B", "/qa/cloud_dispatch_contract.py",
            "--report", "/public/cloud-dispatch-summary.json"]
        self.run_and_wait(args, timeout=120)

    def start_api(self):
        self.api_name = self.prefix + "-api-" + str(self.api_replacements)
        args = self.app_args("api-" + str(self.api_replacements), namespace=True)
        self.docker(args + [self.runtime_image, "/usr/local/bin/python", "-m", "uvicorn", "app.main:app", "--host", "0.0.0.0",
                          "--port", "8000", "--no-access-log", "--log-level", "critical"])

    def remove_container(self, name, *, kill=False):
        output = self.docker(["inspect", "--format", '{"labels":{{json .Config.Labels}}}', name], allowed=(0, 1))
        if not output.strip():
            self.containers.remove(name)  # Launch failed before creating it.
            return
        item = json.loads(output)
        require(owned(item, self.nonce), "Cleanup refused a container owned by another execution.")
        if kill:
            self.docker(["kill", "--signal", "KILL", name])
        self.docker(["logs", name], allowed=(0, 1))
        self.docker(["rm", "-f", name])
        self.containers.remove(name)

    def worker(self, max_tasks=1):
        require(max_tasks in {1, 2}, "Invalid controlled worker task count.")
        role = "worker-" + str(len(self.events))
        args = self.app_args(role, memory="4g")
        name = self.prefix + "-" + role
        self.docker(args + ["--mount", f"type=bind,src={ROOT / DRIVER},dst=/qa/browser_int_e2e.py,readonly",
            "--env", "INT_E2E_NONCE=" + self.nonce, self.runtime_image, "/usr/local/bin/python", "-m", "app.cloud.worker", "--max-tasks", str(max_tasks)])
        self.workers.append(name)
        return name

    def wait_workers(self):
        for name in self.workers:
            require(self.docker(["wait", name], timeout=900).strip() == "0", "Real worker failed; private diagnostics retained.")
        self.workers.clear()

    def action(self, action):
        if action == "replace_api":
            require(self.api_name is not None, "An API must exist before replacement.")
            self.remove_container(self.api_name)
            self.api_replacements += 1
            self.start_api()
        elif action == "drain":
            require(not self.workers, "Drain cannot overlap a controlled worker experiment.")
            self.worker()
            self.wait_workers()
        elif action in {"start_worker", "start_pair", "start_worker_chain"}:
            require(not self.workers, "Controlled workers are already active.")
            for _ in range(2 if action == "start_pair" else 1):
                self.worker(2 if action == "start_worker_chain" else 1)
        elif action == "wait_workers":
            self.wait_workers()
        elif action == "kill_worker":
            require(len(self.workers) == 1, "Interruption requires exactly one owned worker.")
            self.remove_container(self.workers.pop(), kill=True)
        elif action == "terminate_worker_child":
            require(len(self.workers) == 1, "Child interruption requires exactly one owned worker.")
            output = self.docker(["exec", "--user", self.user, self.workers[0], "/usr/local/bin/python", "-B",
                                  "/qa/browser_int_e2e.py", "--terminate-worker-child"], timeout=45)
            result = json.loads(output)
            require(result.get("schema") == "clipforge-int-worker-child-death-1" and result.get("status") == "passed"
                    and result.get("container_preserved") is True and result.get("old_media_active") is False,
                    "Real worker child termination did not stop its media process while the container remained alive.")
            require(self.docker(["inspect", "--format", "{{.State.Status}}", self.workers[0]]).strip() == "running",
                    "Worker container exited before its child-death result could be checked.")
            write_new(self.public / "worker-child-termination-summary.json", result)
        else:
            raise AcceptanceError("Unapproved control action.")

    def acceptance(self):
        self.stage = "browser_acceptance"
        args = self.app_args("browser", namespace=True, memory="2g") + ["--init", "--shm-size", "1g",
            "--mount", f"type=bind,src={ROOT / DRIVER},dst=/qa/browser_int_e2e.py,readonly",
            "--mount", f"type=bind,src={self.private},dst=/private",
            "--mount", f"type=bind,src={self.public},dst=/public",
            "--mount", f"type=bind,src={self.fixture},dst=/fixture/input.mp4,readonly",
            "--env", "INT_E2E_NONCE=" + self.nonce, self.browser_image,
            "/usr/local/bin/python", "-B", "/qa/browser_int_e2e.py"]
        self.docker(args)
        browser_name = self.prefix + "-browser"
        deadline = time.monotonic() + 2400
        sequence = 1
        while time.monotonic() < deadline:
            request = self.control / f"request-{sequence:03d}.json"
            if request.is_file():
                context._check_components(request)
                require(request.stat().st_size <= 512 and request.stat().st_nlink == 1, "Invalid control request file.")
                observed, action = validate_request(json.loads(request.read_text()), self.nonce)
                require(observed == sequence, "Control request order mismatch.")
                self.action(action)
                write_new(self.control / f"response-{sequence:03d}.json", {"nonce": self.nonce, "sequence": sequence, "status": "passed"})
                sequence += 1
            state = self.docker(["inspect", "--format", "{{.State.Status}}|{{.State.ExitCode}}", browser_name]).strip()
            if state.startswith("exited|"):
                require(state == "exited|0", "Browser acceptance failed; sanitized summary retained.")
                report = json.loads((self.public / "browser-summary.json").read_text())
                require(report.get("schema") == "clipforge-int-browser-1" and report.get("status") == "passed"
                        and report.get("real_transcription") is True and report.get("real_render") is True
                        and report.get("api_replacements") == 2 and report.get("cloud_validation") is False,
                        "Browser did not complete real local acceptance.")
                return
            require(state.startswith("running|"), "Browser acceptance stopped unexpectedly.")
            time.sleep(.25)
        raise AcceptanceError("Browser acceptance timed out.")

    def cleanup(self):
        errors = []
        for name in reversed(tuple(self.containers)):
            try:
                self.remove_container(name)
            except (ValueError, OSError, subprocess.SubprocessError):
                errors.append("container_cleanup_failed")
        if self.network_created:
            try:
                item = json.loads(self.docker(["network", "inspect", "--format", '{"labels":{{json .Labels}}}', self.network]))
                require(owned(item, self.nonce), "Cleanup refused a network owned by another execution.")
                self.docker(["network", "rm", self.network])
                self.network_created = False
            except (ValueError, OSError, subprocess.SubprocessError):
                errors.append("network_cleanup_failed")
        return {"status": "passed" if not errors else "failed", "errors": errors, "remaining_owned_containers": len(self.containers),
                "remaining_owned_network": self.network_created, "scope": "exact created names plus matching owner labels; no volumes or global cleanup"}

    def run(self):
        status, error_type = "failed", None
        try:
            self.prepare()
            self.acceptance()
            status = "passed"
        except (Exception, KeyboardInterrupt) as error:
            error_type = type(error).__name__
        finally:
            cleanup = self.cleanup() if self.private.exists() else {"status": "passed", "errors": [], "remaining_owned_containers": 0, "remaining_owned_network": False}
        result = {"schema": "clipforge-int-e2e-local-1", "status": status if cleanup["status"] == "passed" else "failed",
            "error_type": error_type, "failed_stage": getattr(self, "stage", "inputs") if status != "passed" else None,
            "completed_utc": datetime.now(timezone.utc).isoformat(),
            "runtime_image_id": self.runtime_image, "browser_image_id": self.browser_image,
            "postgres_image_ref": self.postgres_image, "postgres_image_id": self.postgres_id,
            "emulator_image_ref": EMULATOR_IMAGE, "emulator_image_id": self.emulator_id,
            "fixture_sha256": hashlib.sha256(self.fixture.read_bytes()).hexdigest(), "container_user": self.user,
            "network": "Docker internal, no host ports; separate prepared downloads", "api_replacements": self.api_replacements,
            "authentication_method": "PostgreSQL/session/CSRF", "transcription_method": "offline Whisper tiny multilingual",
            "worker": "same runtime CLI app.cloud.worker with SQL/outbox; local manual dispatch",
            "cloud_validation": False, "cloud_pending": ["Cloud Run service and Jobs", "real GCS/IAM", "IAP", "private VM/TLS", "protected workflow approvals"],
            "cleanup": cleanup}
        if self.public.exists():
            write_new(self.public / "summary.json", result)
        return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--scratch", type=Path, required=True)
    parser.add_argument("--runtime-image", required=True)
    parser.add_argument("--browser-image", required=True)
    parser.add_argument("--postgres-image", required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    parser.add_argument("--user", required=True)
    args = parser.parse_args(argv)
    harness = Harness(scratch=args.scratch, runtime_image=args.runtime_image, browser_image=args.browser_image,
                      postgres_image=args.postgres_image, fixture=args.fixture, user=args.user)
    def interrupted(_number, _frame):
        raise KeyboardInterrupt()
    signal.signal(signal.SIGTERM, interrupted)
    result = harness.run()
    print(json.dumps({"status": result["status"], "error_type": result["error_type"], "public_summary": str(harness.public / "summary.json")}))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (AcceptanceError, OSError, subprocess.SubprocessError) as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
