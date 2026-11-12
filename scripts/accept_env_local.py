"""Real ENV-01 acceptance against two explicitly identified local environments.

Administrator passwords are terminal input or caller-owned in-memory values.
Cookies, passwords and recovery codes never enter reports, argv or files. The
runner creates visibly synthetic ordinary accounts/projects and keeps them for
the persistence check. An explicit interactive bootstrap can create each first
administrator; no operational installation is read. ASR/LLM are not exercised. A successful result is
functional evidence only and never changes the security/release gate.
"""
from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import getpass
import hashlib
import http.cookiejar
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
import warnings
from urllib.error import HTTPError
from urllib.parse import urlsplit
from urllib.request import HTTPCookieProcessor, ProxyHandler, Request, build_opener

try:
    from scripts import dev_local as dev
except ModuleNotFoundError:
    import dev_local as dev


class AcceptanceError(RuntimeError):
    """Only fixed, credential-free step descriptions may be reported."""


def ensure(condition, message):
    if not condition:
        raise AcceptanceError(message)


class Client:
    def __init__(self, origin, jar=None):
        parsed = urlsplit(origin)
        ensure(parsed.scheme == "http" and parsed.hostname == "127.0.0.1"
               and parsed.port and not parsed.path and not parsed.query
               and not parsed.fragment and not parsed.username,
               "Acceptance requires an exact loopback HTTP origin")
        self.origin = origin
        self.jar = jar if jar is not None else http.cookiejar.CookieJar()
        self.opener = build_opener(ProxyHandler({}), HTTPCookieProcessor(self.jar))
        self.csrf = None

    def request(self, path, *, method="GET", body=None, expected=None,
                headers=None, raw=False):
        ensure(path.startswith("/") and not path.startswith("//"), "Invalid acceptance API path")
        fields = {"Origin": self.origin}
        if self.csrf:
            fields["X-CSRF-Token"] = self.csrf
        if body is not None and not isinstance(body, bytes):
            body = json.dumps(body).encode("utf-8")
            fields["Content-Type"] = "application/json"
        fields.update(headers or {})
        request = Request(self.origin + path, data=body, headers=fields, method=method)
        try:
            response = self.opener.open(request, timeout=40)
        except HTTPError as error:
            response = error
        with response:
            code = response.code
            value = response.read(16 * 1024 * 1024 + 1)
            ensure(len(value) <= 16 * 1024 * 1024, "Acceptance response exceeded its bound")
        if expected is not None:
            ensure(code == expected, "Unexpected API status for " + method + " " + path)
        return code, value if raw else json.loads(value)

    def challenge(self):
        _, value = self.request("/auth/csrf", expected=200)
        self.csrf = value["csrf_token"]
        return self.csrf

    def login(self, username, password, *, challenge=True):
        if challenge:
            self.challenge()
        _, value = self.request("/auth/login", method="POST",
            body={"username": username, "password": password}, expected=200)
        self.csrf = value["csrf_token"]
        return value["user"]


def cookie_names(jar):
    return {cookie.name for cookie in jar}


def force_foreign_session(source, target, source_namespace, namespace):
    """Renaming a foreign DB token must still fail at the target boundary."""
    jar = http.cookiejar.CookieJar()
    for cookie in source.jar:
        if cookie.name == "clipforge_" + source_namespace + "_session":
            foreign = copy.copy(cookie)
            foreign.name = "clipforge_" + namespace + "_session"
            jar.set_cookie(foreign)
            break
    ensure(bool(list(jar)), "Source session cookie was absent")
    foreign_client = Client(target.origin, jar)
    foreign_client.request("/auth/me", expected=401)


def synthetic_source(state, value):
    """Generate tiny audiovisual media with the environment's actual FFmpeg.

    Only /tmp inside the already-owned application is used. stdout is the media
    itself and is kept in memory; no credential or user file is read.
    """
    program = ("import sys,tempfile; from pathlib import Path; "
               "from app.check_presentation import make_source; "
               "t=tempfile.TemporaryDirectory(prefix='env01-synthetic-'); "
               "p=Path(t.name)/'source.mp4'; make_source(p,3); "
               "sys.stdout.buffer.write(p.read_bytes()); t.cleanup()")
    completed = subprocess.run(dev.compose(state, value) + ["exec", "-T", "app", "python", "-c", program],
        capture_output=True, timeout=45, check=False)
    ensure(completed.returncode == 0, "Synthetic FFmpeg source generation failed")
    ensure(1000 < len(completed.stdout) < 4 * 1024 * 1024
           and b"ftyp" in completed.stdout[:32], "Synthetic source was not an MP4")
    return completed.stdout


def verify_live_boundary(state, value):
    """Bind live HTTP evidence to the actual container's recorded ImageID."""
    with dev.operation(state):
        directory = dev.attempt(state, "acceptance-boundary")
        dev.verify_ownership(state, value, directory)
        dev.require_image(state, value, directory)
        dev.verify_runtime_boundary(state, value, directory)


def upload_and_render(client, source, label):
    boundary = "env01" + secrets.token_hex(16)
    body = ("--" + boundary + "\r\nContent-Disposition: form-data; name=\"processing_mode\""
            "\r\n\r\nmanual\r\n--" + boundary
            + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"ENV01-synthetic.mp4\""
            "\r\nContent-Type: video/mp4\r\n\r\n").encode() + source + ("\r\n--" + boundary + "--\r\n").encode()
    _, job = client.request("/jobs", method="POST", body=body, expected=202,
        headers={"Content-Type": "multipart/form-data; boundary=" + boundary})
    job_id = job["id"]
    wait_completed(client, "/jobs/" + job_id)
    _, draft = client.request("/jobs/" + job_id + "/drafts", method="POST", expected=201,
        body={"title": "ENV01 synthetic " + label, "clip_file": None, "start": 0, "end": 2,
              "options": {"burn_subtitles": True},
              "cues": [{"start": .1, "end": 1.8, "text": "ENV01 synthetic acceptance " + label}]})
    _, item = client.request("/jobs/" + job_id + "/drafts/" + draft["id"] + "/exports",
        method="POST", expected=202, body={"revision": draft["revision"]})
    export_id = item["id"]
    wait_completed(client, "/jobs/" + job_id + "/exports/" + export_id)
    path = "/jobs/" + job_id + "/exports/" + export_id + "/files/clip.mp4"
    _, download = client.request(path, expected=200, raw=True)
    ensure(len(download) > 1000 and b"ftyp" in download[:32], "Rendered download was not an MP4")
    _, captions = client.request(path[:-3] + "srt", expected=200, raw=True)
    ensure(label.encode() in captions and b"00:00:00,100" in captions,
           "Manual caption download did not preserve synthetic text/timing")
    return {"job_id": job_id, "export_id": export_id, "download_path": path,
            "download_sha256": hashlib.sha256(download).hexdigest(), "download_bytes": len(download)}


def wait_completed(client, path):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        _, value = client.request(path, expected=200)
        if value["status"] in {"completed", "failed"}:
            ensure(value["status"] == "completed", "Real media processing failed")
            return value
        time.sleep(.25)
    raise AcceptanceError("Real media processing timed out")


def verify_persistence(client, user, media):
    _, actual = client.request("/auth/me", expected=200)
    ensure(actual["user"]["id"] == user["id"], "Session identity changed across container recreation")
    client.request("/jobs/" + media["job_id"], expected=200)
    _, payload = client.request(media["download_path"], expected=200, raw=True)
    ensure(hashlib.sha256(payload).hexdigest() == media["download_sha256"],
           "Rendered media changed across container recreation")


def write_report(path, summary):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(summary, stream, indent=2, sort_keys=True)
        stream.write("\n")


def validate_candidate(state, credential, report):
    """Qualify DEV through real AUTH/manual rendering before local promotion."""
    state, value = dev.load_state(Path(state))
    ensure(value.get("environment") == "dev", "Only DEV may validate a candidate")
    ensure(not Path(report).exists(), "Candidate report must be new")
    build = json.loads((state / "build.json").read_text(encoding="utf-8"))
    summary = {"schema": "clipforge-env01-candidate-validation-1", "status": "failed",
               "image_id": build["image_id"], "source_manifest_sha256": build["source_manifest_sha256"],
               "revision": build["revision"], "migration_revision": build["migration_revision"],
               "security_gate": "unchanged_blocked", "steps": []}
    def record(step):
        summary["steps"].append({"id": step, "status": "passed"})
        print("PASS: ENV01 candidate " + step, flush=True)
    try:
        verify_live_boundary(state, value)
        dev.execute("status", state, value)
        admin = Client(value["origin"])
        admin.login(*credential)
        _, identity = admin.request("/environment", expected=200)
        ensure(identity == {"environment": "DEV", "revision": build["revision"]},
               "Candidate visible identity did not match the build")
        admin.request("/auth/users", method="POST", body={"username": "never_created", "password": secrets.token_urlsafe(24)},
            headers={"X-CSRF-Token": "invalid-authored-fixture"}, expected=403)
        record("login_exact_metadata_csrf")
        username, password = "qa_env01_candidate_" + secrets.token_hex(5), secrets.token_urlsafe(24)
        _, result = admin.request("/auth/users", method="POST", expected=201,
            body={"username": username, "password": password})
        user = result["user"]
        client = Client(value["origin"])
        client.login(username, password)
        item = upload_and_render(client, synthetic_source(state, value), "DEV candidate")
        client.request("/auth/admin/audit", expected=403)
        record("ordinary_account_manual_real_ffmpeg_download")
        _, result = admin.request("/auth/admin/users/" + user["id"] + "/recovery", method="POST",
            expected=201, body={"current_password": credential[1]})
        fresh = Client(value["origin"])
        fresh.challenge()
        replacement = secrets.token_urlsafe(24)
        fresh.request("/auth/recover", method="POST", expected=200,
            body={"code": result["recovery_code"], "new_password": replacement})
        client.request("/auth/me", expected=401)
        client.login(username, replacement)
        verify_persistence(client, user, item)
        _, audit = admin.request("/auth/admin/audit?action=recovery.consumed&target_id=" + user["id"], expected=200)
        ensure(any(row["result"] == "success" for row in audit["items"]), "Candidate recovery audit missing")
        record("real_recovery_audit_revocation_project_preserved")
        summary["synthetic_project"] = item
        summary["synthetic_account"] = username
        summary["status"] = "passed"
    except Exception as error:
        summary["error_type"] = type(error).__name__
        if isinstance(error, AcceptanceError):
            summary["failed_check"] = str(error)
    write_report(report, summary)
    return summary


def run_acceptance(dev_state, int_state, credentials, report, *, lifecycle=True,
                   backup_destination=None, restore_state=None):
    """Run real checks; credentials is {'dev': (name,password), 'int': (...)}.

    This callable permits a terminal driver to keep passwords entirely in memory.
    No fixture account is promoted into an operational default administrator.
    """
    details = []
    summary = {"schema": "clipforge-env01-acceptance-1", "status": "failed", "steps": details,
               "started_utc": datetime.now(timezone.utc).isoformat(),
               "transport": "direct_loopback_http", "postgresql": "real", "ffmpeg": "real",
               "asr_tested": False, "llm_tested": False, "security_gate": "unchanged_blocked",
               "scope": "Synthetic functional DEV/INT acceptance; no release approval"}
    def record(step):
        details.append({"id": step, "status": "passed"})
        print("PASS: ENV01 " + step, flush=True)

    try:
        ensure(not Path(report).exists(), "Acceptance report must be new")
        states, values, builds = {}, {}, {}
        for name, path in (("dev", dev_state), ("int", int_state)):
            states[name], values[name] = dev.load_state(Path(path))
            ensure(values[name].get("environment") == name, "Acceptance environment identity mismatch")
            builds[name] = json.loads((states[name] / "build.json").read_text(encoding="utf-8"))
            verify_live_boundary(states[name], values[name])
            dev.execute("status", states[name], values[name])
        ensure(states["dev"] != states["int"] and values["dev"]["origin"] != values["int"]["origin"],
               "Acceptance environments must be independent")
        ensure(builds["dev"]["image_id"] == builds["int"]["image_id"],
               "INT must consume the exact DEV ImageID")
        summary["environments"] = {name: {"origin": values[name]["origin"],
            "project": values[name]["project"], "revision": builds[name]["revision"],
            "image_id": builds[name]["image_id"],
            "source_manifest_sha256": builds[name]["source_manifest_sha256"],
            "migration_revision": builds[name]["migration_revision"]} for name in states}
        shared = http.cookiejar.CookieJar()
        admins = {name: Client(values[name]["origin"], shared) for name in states}
        for name in states:
            admins[name].request("/health", expected=200)
            _, identity = admins[name].request("/environment", expected=200)
            ensure(identity == {"environment": name.upper(), "revision": builds[name]["revision"]},
                   "Visible environment/revision did not match build record")
        record("simultaneous_health_exact_image_metadata")
        admins["dev"].challenge()
        dev_challenge_names = cookie_names(shared)
        admins["int"].challenge()
        ensure(len(cookie_names(shared)) == 2 * len(dev_challenge_names), "Preauthentication cookie names collide")
        admin_users = {name: admins[name].login(*credentials[name], challenge=False) for name in states}
        for name in states:
            _, me = admins[name].request("/auth/me", expected=200)
            ensure(me["user"]["id"] == admin_users[name]["id"], "Shared browser cookie jar changed administrator identity")
        ensure({"clipforge_dev_session", "clipforge_int_session"} <= cookie_names(shared),
               "Environment session cookie names are not distinct")
        admins["dev"].request("/auth/logout", method="POST", expected=200)
        admins["int"].request("/auth/me", expected=200)
        admins["dev"].login(*credentials["dev"])
        force_foreign_session(Client(values["dev"]["origin"], shared), admins["int"], "dev", "int")
        admins["dev"].request("/auth/users", method="POST", body={"username": "never_created", "password": secrets.token_urlsafe(24)},
            headers={"Origin": values["int"]["origin"]}, expected=403)
        record("shared_browser_preauth_sessions_logout_and_exact_origin")
        run_id = secrets.token_hex(5)
        users, clients, synthetic_credentials = {}, {}, {}
        for name in states:
            users[name], clients[name], synthetic_credentials[name] = {}, {}, {}
            for role in ("a", "b"):
                username, password = "qa_env01_" + run_id + "_" + name + "_" + role, secrets.token_urlsafe(24)
                _, result = admins[name].request("/auth/users", method="POST", expected=201,
                    body={"username": username, "password": password})
                users[name][role] = result["user"]
                clients[name][role] = Client(values[name]["origin"])
                clients[name][role].login(username, password)
                synthetic_credentials[name][role] = (username, password)
            foreign = Client(values["int" if name == "dev" else "dev"]["origin"])
            foreign.challenge()
            foreign.request("/auth/login", method="POST", expected=401,
                body={"username": synthetic_credentials[name]["a"][0],
                      "password": synthetic_credentials[name]["a"][1]})
            clients[name]["a"].request("/auth/admin/audit", expected=403)
        record("synthetic_accounts_separate_and_admin_permission_enforced")
        media = {}
        for name in states:
            source = synthetic_source(states[name], values[name])
            media[name] = upload_and_render(clients[name]["a"], source, name.upper())
            clients[name]["b"].request("/jobs/" + media[name]["job_id"], expected=404)
            clients[name]["b"].request(media[name]["download_path"], expected=404)
        for name in states:
            other = "int" if name == "dev" else "dev"
            clients[name]["a"].request("/jobs/" + media[other]["job_id"], expected=404)
            clients[name]["a"].request(media[other]["download_path"], expected=404)
        record("manual_upload_real_ffmpeg_download_and_project_isolation")
        for name in states:
            other = "int" if name == "dev" else "dev"
            admins[name].request("/auth/admin/users/" + users[other]["a"]["id"] + "/recovery",
                method="POST", expected=404, body={"current_password": credentials[name][1]})
            _, issuance = admins[name].request("/auth/admin/users/" + users[name]["a"]["id"] + "/recovery",
                method="POST", expected=201, body={"current_password": credentials[name][1]})
            code, replacement = issuance["recovery_code"], secrets.token_urlsafe(24)
            wrong = Client(values[other]["origin"])
            wrong.challenge()
            wrong.request("/auth/recover", method="POST", expected=400, body={"code": code, "new_password": replacement})
            fresh = Client(values[name]["origin"])
            fresh.challenge()
            fresh.request("/auth/recover", method="POST", expected=200, body={"code": code, "new_password": replacement})
            clients[name]["a"].request("/auth/me", expected=401)
            clients[name]["a"] = Client(values[name]["origin"])
            clients[name]["a"].login(synthetic_credentials[name]["a"][0], replacement)
            synthetic_credentials[name]["a"] = (synthetic_credentials[name]["a"][0], replacement)
            retry = Client(values[name]["origin"])
            retry.challenge()
            retry.request("/auth/recover", method="POST", expected=400, body={"code": code, "new_password": secrets.token_urlsafe(24)})
            _, audit = admins[name].request("/auth/admin/audit?action=recovery.consumed&target_id=" + users[name]["a"]["id"], expected=200)
            ensure(any(row["result"] == "success" for row in audit["items"]), "Successful recovery audit missing")
            serialized = json.dumps(audit)
            ensure(all(secret not in serialized for secret in (code, replacement, credentials[name][1])),
                   "Audit exposed a secret")
            verify_persistence(clients[name]["a"], users[name]["a"], media[name])
        record("recovery_environment_boundary_revocation_single_use_and_audit")
        if lifecycle:
            for name in states:
                other = "int" if name == "dev" else "dev"
                dev.execute("down", states[name], values[name])
                verify_persistence(clients[other]["a"], users[other]["a"], media[other])
                dev.execute("up", states[name], values[name])
                verify_persistence(clients[name]["a"], users[name]["a"], media[name])
                _, listings = admins[name].request("/auth/users", expected=200)
                ensure({users[name][role]["id"] for role in users[name]} <= {row["id"] for row in listings["users"]},
                       "Accounts did not persist across container recreation")
            record("independent_down_up_account_session_and_media_persistence")
        if backup_destination is not None or restore_state is not None:
            ensure(backup_destination is not None and restore_state is not None,
                   "Backup acceptance requires both new backup and restore destinations")
            # Integrated once the launcher has verified the owned quiesced path.
            backup_and_restore(states, values, clients, users, synthetic_credentials, media,
                               Path(backup_destination), Path(restore_state), record, summary)
        summary["synthetic_projects"] = media
        summary["synthetic_accounts"] = {name: [user["username"] for user in users[name].values()] for name in users}
        summary["status"] = "passed"
    except Exception as error:
        # HTTP/Playwright/process errors can contain response bodies or passwords.
        # Only the exception type and a fixed completed-step inventory are safe.
        summary["error_type"] = type(error).__name__
        if isinstance(error, AcceptanceError):
            summary["failed_check"] = str(error)
    summary["finished_utc"] = datetime.now(timezone.utc).isoformat()
    write_report(report, summary)
    return summary


def backup_and_restore(states, values, clients, users, synthetic_credentials, media,
                       destination, restore_state, record, summary):
    try:
        from scripts import dev_backup
    except ModuleNotFoundError:
        import dev_backup
    directory = dev.execute("backup", states["int"], values["int"], destination=destination)
    result = json.loads((directory / "backup-result.json").read_text(encoding="utf-8"))
    ensure(result["status"] == "passed" and result["writers_stopped"]
           and result["runtime_connection_secrets_included"] is False,
           "Backup did not confirm quiescence and runtime-secret exclusion")
    verify_persistence(clients["int"]["a"], users["int"]["a"], media["int"])
    _, backup_record = dev_backup.read_backup(destination)  # Checks exact DB/archive/context checksums.
    ensure(backup_record["contains_private_account_data"] is True,
           "Backup did not classify the private account database")
    record("consistent_quiesced_postgres_and_files_backup")
    restored, restore_directory = dev_backup.restore(destination, restore_state, 0, True)
    restored, restore_value = dev.load_state(restored)
    try:
        ensure(restore_value["environment"] == "restore"
               and restore_value["project"] not in {values[name]["project"] for name in states}
               and restored not in set(states.values()), "Restore adopted a live environment")
        restore_client = Client(restore_value["origin"])
        restored_user = restore_client.login(*synthetic_credentials["int"]["a"])
        ensure(restored_user["id"] == users["int"]["a"]["id"], "Restored database did not preserve the synthetic account")
        verify_persistence(restore_client, restored_user, media["int"])
        _, identity = restore_client.request("/environment", expected=200)
        ensure(identity == {"environment": "RESTORE", "revision": values["int"]["revision"]},
               "Restore runtime identity was not independent")
        restore_result = json.loads((restore_directory / "restore-result.json").read_text(encoding="utf-8"))
        ensure(restore_result["status"] == "passed" and restore_result["disposable"]
               and restore_result["credentials_copied"] is False, "Restore did not confirm independent disposable state")
        summary["backup_restore"] = {"backup": str(destination), "restore_state": str(restored),
            "restore_project": restore_value["project"], "restore_origin": restore_value["origin"],
            "database_and_media_verified": True, "independent_credentials": True,
            "image_id": restore_value["image"], "writers_stopped": True,
            "restored_download_sha256": media["int"]["download_sha256"]}
        record("independent_disposable_restore_database_account_and_media")
    finally:
        dev.execute("down", restored, restore_value)
    for name in states:
        verify_persistence(clients[name]["a"], users[name]["a"], media[name])
    record("restore_stopped_live_dev_int_preserved")


def prompt_credential(label, username=None, *, confirm=False):
    ensure(sys.stdin.isatty(), "Administrator input requires an interactive terminal")
    username = username or input(label + " administrator username: ").strip()
    with warnings.catch_warnings():
        warnings.simplefilter("error", getpass.GetPassWarning)
        password = getpass.getpass(label + " administrator password: ")
        if confirm:
            ensure(password == getpass.getpass(label + " confirm administrator password: "),
                   "Administrator password confirmation did not match")
    return username, password


def bootstrap_interactive(state, value, credential):
    """The host prompts interactively; an anonymous pipe enters only this app.

    Neither Docker argv nor the launched process environment contains a password.
    The existing standalone auth_admin terminal-only interface is unchanged.
    """
    ensure(sys.stdin.isatty(), "Administrator bootstrap requires an interactive terminal")
    ensure(value.get("environment") in {"dev", "int"}, "Bootstrap only applies to identified DEV/INT")
    dev.execute("status", state, value)
    program = ("import json,sys; from app.auth import bootstrap_admin; "
               "v=json.load(sys.stdin); u=bootstrap_admin(v['username'],v['password']); "
               "print(json.dumps({'created': True}))")
    payload = json.dumps({"username": credential[0], "password": credential[1]}).encode("utf-8")
    result = subprocess.run(dev.compose(state, value) + ["exec", "-T", "app", "python", "-c", program],
        input=payload, capture_output=True, timeout=60, check=False)
    del payload
    ensure(result.returncode == 0, "Interactive administrator bootstrap failed")
    ensure(json.loads(result.stdout) == {"created": True}, "Administrator bootstrap did not confirm completion")
    print("ENV01 " + value["environment"].upper() + " administrator created interactively.", flush=True)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev-state", type=Path)
    parser.add_argument("--candidate-state", type=Path)
    parser.add_argument("--int-state", type=Path)
    parser.add_argument("--dev-admin", "--dev-username", dest="dev_admin")
    parser.add_argument("--int-admin", "--int-username", dest="int_admin")
    parser.add_argument("--bootstrap-admins", action="store_true")
    parser.add_argument("--bootstrap-dev", action="store_true")
    parser.add_argument("--bootstrap-int", action="store_true")
    parser.add_argument("--promote", action="store_true")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--backup-destination", type=Path)
    parser.add_argument("--restore-state", type=Path)
    args = parser.parse_args(argv)
    if not sys.stdin.isatty():
        print("ENV01 requires terminal-only administrator password input.", file=sys.stderr)
        return 1
    try:
        ensure(not args.report.exists(), "Acceptance report must be new")
        bootstrap_dev = args.bootstrap_admins or args.bootstrap_dev
        bootstrap_int = args.bootstrap_admins or args.bootstrap_int
        if args.candidate_state is not None:
            ensure(not args.dev_state and not args.int_state and not args.promote and not args.bootstrap_int,
                   "Candidate validation takes only --candidate-state")
            state, value = dev.load_state(args.candidate_state)
            credential = prompt_credential("DEV", args.dev_admin, confirm=bootstrap_dev)
            if bootstrap_dev:
                bootstrap_interactive(state, value, credential)
            summary = validate_candidate(state, credential, args.report)
        else:
            ensure(args.dev_state and args.int_state, "Pair acceptance requires DEV and INT states")
            ensure(not args.bootstrap_admins or args.promote,
                   "Pair administrator bootstrap requires explicit --promote")
            candidate_report = args.report.with_name(args.report.stem + "-candidate.json")
            ensure(not args.promote or not candidate_report.exists(), "Candidate report must be new")
            credentials = {"dev": prompt_credential("DEV", args.dev_admin, confirm=bootstrap_dev)}
            if bootstrap_dev:
                state, value = dev.load_state(args.dev_state)
                bootstrap_interactive(state, value, credentials["dev"])
            if args.promote:
                candidate = validate_candidate(args.dev_state, credentials["dev"], candidate_report)
                ensure(candidate["status"] == "passed", "DEV candidate acceptance blocks promotion")
                state, value = dev.load_state(args.dev_state)
                dev.execute("validate", state, value, report=candidate_report)
                int_state, int_value = dev.load_state(args.int_state)
                dev.promote(int_state, int_value, state)
                int_state, int_value = dev.load_state(args.int_state)
                dev.execute("up", int_state, int_value)
            credentials["int"] = prompt_credential("INT", args.int_admin, confirm=bootstrap_int)
            if bootstrap_int:
                state, value = dev.load_state(args.int_state)
                bootstrap_interactive(state, value, credentials["int"])
            summary = run_acceptance(args.dev_state, args.int_state, credentials, args.report,
                backup_destination=args.backup_destination, restore_state=args.restore_state)
        print(json.dumps({"status": summary["status"], "completed_steps": len(summary["steps"]), "report": str(args.report)}))
        return 0 if summary["status"] == "passed" else 1
    except (AcceptanceError, OSError, ValueError, subprocess.SubprocessError,
            getpass.GetPassWarning, EOFError, KeyboardInterrupt) as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__,
                          "message": "ENV01 acceptance stopped; credential contents were not logged."}), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
