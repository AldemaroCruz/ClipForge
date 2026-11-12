"""Private, quiesced ENV-01 backup and restore into a new disposable project.

Invoked by dev_local, not a second launcher. PostgreSQL and application files
are captured while every application writer is stopped. Interrupted renders
are not resumed. Credentials are deliberately neither copied nor archived.
"""
from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import uuid

try:
    from scripts import dev_local as dev
except ModuleNotFoundError:
    import dev_local as dev


BACKUP_SCHEMA = "clipforge-env01-backup-1"
ARCHIVE = """import pathlib,sys,tarfile
from app.lease import data_lease
root=pathlib.Path('/srv/clipforge')
with data_lease(root),tarfile.open(fileobj=sys.stdout.buffer,mode='w|') as archive:
    for path in sorted(root.iterdir()):
        if path.name != '.clipforge-runtime.lock':
            archive.add(path,arcname=path.name,recursive=True)
"""
EXTRACT = """import pathlib,sys,tarfile
root=pathlib.Path('/srv/clipforge')
if any(root.iterdir()):
    raise SystemExit('Restore destination application volume is not empty')
with tarfile.open(fileobj=sys.stdin.buffer,mode='r|') as archive:
    for member in archive:
        path=pathlib.PurePosixPath(member.name)
        if path.is_absolute() or '..' in path.parts or not path.parts or not (member.isfile() or member.isdir()):
            raise SystemExit('Unsafe backup archive member')
        archive.extract(member,path=root,filter='data')
"""


def checked_file(path: Path):
    dev.context._check_components(path)
    metadata = dev.context._checked_stat(path)
    dev.require(stat.S_ISREG(metadata.st_mode) and metadata.st_nlink == 1, "Backup inputs must be regular files without links.")


def new_external(path: Path) -> Path:
    path = Path(os.path.abspath(path))
    dev.context._check_components(path)
    dev.require(not path.exists(), "The backup/restore destination must be new; existing paths are never reused.")
    dev.require(not dev.context._inside(path, dev.ROOT) and not dev.context._inside(dev.ROOT, path), "Backup/restore paths must be outside the checkout.")
    dev.require(path != Path(path.anchor), "A filesystem root is not a destination.")
    return path


def copy_context(source: Path, manifest: Path, destination: Path, target_manifest: Path):
    """Copy a verified source-only snapshot, including under an owned backup path.

    CI preparation's private-path ban remains unchanged. These fresh private
    backup directories are explicitly authorized local outputs, never CI input.
    The same inventory/type/hash checks apply before and after copying.
    """
    checked_file(manifest)
    expected = dev.context._manifest_inventory(json.loads(manifest.read_text(encoding="utf-8")))
    dev.require(dev.context._inventory(source, strict=True) == expected, "Backup source context differs from its manifest.")
    dev.context._check_components(destination)
    dev.require(not destination.exists() and not target_manifest.exists(), "Snapshot destinations must be new.")
    destination.mkdir(mode=0o700)
    for relative, record in expected.items():
        output = destination / relative
        output.parent.mkdir(parents=True, exist_ok=True)
        dev.require(dev.context._stream_record(source / relative, output) == record, "Snapshot copy changed.")
    dev.require(dev.context._inventory(destination, strict=True) == expected, "Backup context verification failed.")
    dev.write_new(target_manifest, manifest.read_text(encoding="utf-8"), private=True)


def stream(directory: Path, label: str, argv: list[str], *, output: Path | None = None, input_file: Path | None = None):
    dev.require((output is None) != (input_file is None), "A single stream direction is required.")
    started = datetime.now(timezone.utc).isoformat()
    environment = {key: value for key, value in os.environ.items() if not key.startswith(("COMPOSE_", "CLIPFORGE_DEV_"))}
    code, failure = None, None
    source = None
    destination = None
    try:
        if input_file is not None:
            checked_file(input_file)
            source = input_file.open("rb")
        if output is not None:
            descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            destination = os.fdopen(descriptor, "wb")
        with (directory / (label + ".stderr.log")).open("xb") as errors:
            code = subprocess.run(argv, stdin=source, stdout=destination or subprocess.DEVNULL,
                                  stderr=errors, env=environment, timeout=1200).returncode
        if destination:
            destination.flush()
            os.fsync(destination.fileno())
    except subprocess.TimeoutExpired:
        failure = "timeout"
    finally:
        if source:
            source.close()
        if destination:
            destination.close()
        dev.save(directory / (label + "-command.json"), {"argv": argv, "exit_code": code, "error": failure,
                 "started_utc": started, "finished_utc": datetime.now(timezone.utc).isoformat(), "private_stream_not_logged": True})
    dev.require(code == 0 and failure is None, "A private backup/restore stream failed; the incomplete attempt is retained.")


def backup(state: Path, value: dict, directory: Path, destination: Path):
    dev.require(value.get("schema") == dev.ENV_SCHEMA, "Backup requires an ENV-01 environment.")
    destination = new_external(destination)
    dev.require(not dev.context._inside(destination, state) and not dev.context._inside(state, destination), "Backup and environment state must not overlap.")
    destination.mkdir(mode=0o700, parents=True)
    dev.require_image(state, value, directory)
    dev.verify_active_image(state, value, directory, require_running=False)
    command = dev.compose(state, value)
    app_name = value["project"] + "-app-1"
    running = dev.run(directory, "backup-app-running", dev.docker(state) + ["ps", "-q", "--filter", "name=^/" + app_name + "$"], timeout=30).strip()
    if running:
        dev.run(directory, "backup-idle-before-stop", command + ["exec", "-T", "app", "python", "-m", "scripts.check_idle", "--data", "/srv/clipforge"], timeout=120)
    # Owned labels were checked by dev_local before entering this helper.
    dev.run(directory, "backup-quiesce", command + ["stop", "--timeout", "60", "app"], timeout=90)
    try:
        remaining = dev.run(directory, "backup-writers", dev.docker(state) + ["ps", "-q", "--filter", "label=com.docker.compose.project=" + value["project"],
            "--filter", "label=com.docker.compose.service=app"], timeout=30).strip()
        dev.require(not remaining, "Application writers remain active; backup consistency cannot be established.")
        dev.run(directory, "backup-idle-after-stop", command + ["run", "--rm", "--no-deps", "-T", "--name", value["project"] + "-app-run-" + uuid.uuid4().hex[:12],
            "app", "python", "-m", "scripts.check_idle", "--data", "/srv/clipforge"], timeout=120)
        revision = dev.schema_revision(state, value, directory, "backup-schema")
        build = dev.read_build(state)
        dev.require(revision == build["migration_revision"], "Application and schema revision differ; backup refused.")
        stream(directory, "database-dump", command + ["exec", "-T", "postgres", "pg_dump", "-U", "postgres", "-d", "clipforge", "--format=custom", "--no-owner", "--no-acl"],
               output=destination / "database.dump")
        stream(directory, "application-archive", command + ["run", "--rm", "--no-deps", "-T", "--name", value["project"] + "-app-run-" + uuid.uuid4().hex[:12],
               "app", "python", "-c", ARCHIVE], output=destination / "app-files.tar")
        copy_context(state / value["context"], state / value["manifest"], destination / "context", destination / "context-manifest.json")
        files = {name: dev.context._stream_record(destination / name) for name in ("database.dump", "app-files.tar", "context-manifest.json")}
        dev.save(destination / "backup.json", {"schema": BACKUP_SCHEMA, "status": "complete", "source_owner": value["owner"],
            "source_environment": value["environment"], "source_project": value["project"], "image_id": build["image_id"],
            "revision": build["revision"], "source_manifest_sha256": build["source_manifest_sha256"], "migration_revision": revision,
            "postgres_image": dev.POSTGRES_IMAGE, "build": build, "files": files, "created_utc": datetime.now(timezone.utc).isoformat(),
            "consistency": "Application stopped and no application writers running during database and file capture. No interrupted-render recovery.",
            "runtime_connection_secrets_included": False,
            "contains_private_account_data": True})
        dev.save(directory / "backup-result.json", {"status": "passed", "destination": str(destination), "migration_revision": revision,
                  "image_id": build["image_id"], "writers_stopped": True, "runtime_connection_secrets_included": False,
                  "contains_private_account_data": True})
    finally:
        if running:
            dev.run(directory, "backup-resume", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)


def read_backup(path: Path) -> tuple[Path, dict]:
    path = Path(os.path.abspath(path))
    dev.context._check_components(path)
    dev.require(not dev.context._inside(path, dev.ROOT) and not dev.context._inside(dev.ROOT, path), "Backup must be an explicit private external directory.")
    checked_file(path / "backup.json")
    value = json.loads((path / "backup.json").read_text(encoding="utf-8"))
    dev.require(value.get("schema") == BACKUP_SCHEMA and value.get("status") == "complete" and value.get("runtime_connection_secrets_included") is False,
                "Not a complete ENV-01 backup.")
    dev.require(value.get("postgres_image") == dev.POSTGRES_IMAGE and re.fullmatch(r"sha256:[a-f0-9]{64}", value.get("image_id", "")), "Unsupported backup image identity.")
    dev.require(re.fullmatch(r"[a-f0-9]{40}", value.get("revision", "")) and re.fullmatch(r"[a-f0-9]{64}", value.get("source_manifest_sha256", "")), "Invalid backup source identity.")
    dev.require(set(value.get("files", {})) == {"database.dump", "app-files.tar", "context-manifest.json"}, "Incomplete backup inventory.")
    for name, record in value["files"].items():
        checked_file(path / name)
        dev.require(dev.context._stream_record(path / name) == record, "A backup file differs from its recorded checksum.")
    dev.require(dev.manifest_hash(path / "context-manifest.json") == value["source_manifest_sha256"], "Backup source manifest changed.")
    return path, value


def restore(backup_path: Path, state: Path, port: int, local_http: bool) -> tuple[Path, Path]:
    dev.require(local_http, "Restore requires an explicit local HTTP profile.")
    backup_path, backup_value = read_backup(backup_path)
    state = new_external(state)
    dev.require(not dev.context._inside(state, backup_path) and not dev.context._inside(backup_path, state), "Restore and backup must not overlap.")
    # Identity is always restore-<random>, never dev/int, even for custom paths.
    # No existing directory, account, container or volume is adopted.
    state = dev.prepare(state, port, local_http, "restore")
    state, value = dev.load_state(state)
    with dev.operation(state):
        directory = dev.attempt(state, "restore")
        dev.verify_ownership(state, value, directory)
        candidate = dict(value)
        candidate["context"] = "snapshot-" + uuid.uuid4().hex[:12]
        candidate["manifest"] = candidate["context"] + "-manifest.json"
        copy_context(backup_path / "context", backup_path / "context-manifest.json", state / candidate["context"], state / candidate["manifest"])
        candidate.update(image=backup_value["image_id"], revision=backup_value["revision"], source_manifest_sha256=backup_value["source_manifest_sha256"])
        build = {**backup_value["build"], "image_id": backup_value["image_id"], "context": candidate["context"], "manifest": candidate["manifest"],
                 "restored_from": str(backup_path), "attempt": str(directory)}
        dev.activate(state, candidate, build)
        value.update(candidate)
        dev.require_image(state, value, directory)
        dev.check_available_port(state, value, directory)
        command = dev.compose(state, value)
        dev.run(directory, "restore-postgres", command + ["up", "-d", "--wait", "--wait-timeout", "90", "postgres"], timeout=120)
        # Only this newly initialized empty database is a restore destination.
        empty = dev.run(directory, "restore-empty-database", command + ["exec", "-T", "postgres", "psql", "-U", "postgres", "-d", "clipforge", "-Atc",
            "SELECT count(*) FROM pg_tables WHERE schemaname='public'"], timeout=30).strip()
        dev.require(empty == "0", "Restore refused: the destination database is not empty.")
        stream(directory, "database-restore", command + ["exec", "-T", "postgres", "pg_restore", "-U", "postgres", "-d", "clipforge", "--no-owner", "--no-acl", "--role=clipforge", "--exit-on-error"],
               input_file=backup_path / "database.dump")
        stream(directory, "application-restore", command + ["run", "--rm", "--no-deps", "-T", "--name", value["project"] + "-app-run-" + uuid.uuid4().hex[:12],
               "app", "python", "-c", EXTRACT], input_file=backup_path / "app-files.tar")
        dev.record_migration(state, value, directory)
        dev.run(directory, "restore-app", command + ["up", "-d", "--wait", "--wait-timeout", "120", "app"], timeout=150)
        dev.verify_runtime_boundary(state, value, directory)
        dev.save(directory / "restore-result.json", {"status": "passed", "disposable": True, "source_environment": backup_value["source_environment"],
                 "project": value["project"], "image_id": value["image"], "migration_revision": backup_value["migration_revision"],
                 "credentials_copied": False, "backup_checksums_verified": True})
    return state, directory
