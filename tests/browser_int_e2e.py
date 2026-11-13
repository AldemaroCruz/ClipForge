"""Real local browser/SQL/GCS-emulator/Whisper/FFmpeg acceptance.

Run only through scripts/run_int_e2e.py on its exclusive internal network. No
transcripts or completed jobs are seeded. The host replaces API containers and
controls real worker processes through allowlisted files, without a Docker socket
inside the browser. Reports contain statuses and counts only, never credentials,
captions, raw responses, object names, cookies, signed URLs, HAR or screenshots.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import signal
import sys
import time
import traceback
import urllib.error
import urllib.request


ORIGIN = "http://127.0.0.1:8000"
PRIVATE = Path("/private")
PUBLIC = Path("/public")
STEP_IDS = frozenset({"isolated_database_and_network", "migrations_idempotent", "login_and_two_users",
    "csrf_and_property_rejection", "upload_durable_outbox", "upload_idempotency", "queued_api_replacement",
    "real_transcription_and_selection", "manual_range", "edit_and_draft_revision", "real_render_and_atomic_publication",
    "browser_playback_and_download", "cross_user_object_rejection", "completed_api_replacement",
    "global_single_worker_and_lease_renewal", "interrupted_worker_fenced", "new_export_after_interruption",
    "recovery_and_session_revocation", "disabled_cloud_features", "worker_child_death_stops_media_before_next_task"})


class CheckFailed(RuntimeError):
    """Only constant, source-authored check labels may enter public evidence."""


def ensure(value, message):
    if not value:
        raise CheckFailed(message)


def save_new(path, value):
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, sort_keys=True, indent=2)
        stream.write("\n")


def required_profile():
    ensure(os.getenv("CLIPFORGE_AUTH_TEST_DATABASE") == "1" and os.getenv("CLIPFORGE_CLOUD_LOCAL_TEST") == "1"
           and os.getenv("CLIPFORGE_AUTH_PROFILE") == "local-http" and os.getenv("CLIPFORGE_STORAGE_BACKEND") == "gcs"
           and os.getenv("CLIPFORGE_JOBS_DISPATCH_MODE") == "local_manual"
           and re.fullmatch(r"int_e2e_[a-f0-9]{16}", os.getenv("CLIPFORGE_DATABASE_SCHEMA", "")),
           "Explicit isolated cloud-emulator profile required")


def prepare():
    required_profile()
    from app.auth import bootstrap_admin
    from app.auth_db import get_engine
    from app.model_source import resolve_model
    from sqlalchemy import text
    with get_engine().connect() as connection:
        role = connection.execute(text("SELECT current_user,rolsuper,rolcreatedb FROM pg_roles WHERE rolname=current_user")).one()
        ensure(tuple(role) == ("clipforge_int_e2e", False, False), "Database role must be exclusive and unprivileged")
        ensure(connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one() == 0,
               "Acceptance requires an empty exclusive cloud queue")
    resolve_model()
    lock = json.loads(Path(os.environ["CLIPFORGE_MODEL_LOCK"]).read_text())
    save_new(PRIVATE / "model-identity.json", {"model": lock["model"], "repo_id": lock["repo_id"],
        "revision": lock["revision"], "files": [{key: item[key] for key in ("name", "bytes", "sha256")} for item in lock["files"]]})
    username, password = "int_admin_" + secrets.token_hex(6), secrets.token_urlsafe(30)
    bootstrap_admin(username, password)
    save_new(PRIVATE / "fixture-users.json", {"admin": {"username": username, "password": password},
        "first": {"username": "int_a_" + secrets.token_hex(6), "password": secrets.token_urlsafe(30)},
        "second": {"username": "int_b_" + secrets.token_hex(6), "password": secrets.token_urlsafe(30)}})
    bucket = os.environ["CLIPFORGE_GCS_BUCKET"]
    endpoint = os.environ["CLIPFORGE_GCS_ENDPOINT"]
    deadline = time.monotonic() + 30
    while True:
        try:
            request = urllib.request.Request(endpoint + "/storage/v1/b?project=local-int-e2e",
                data=json.dumps({"name": bucket}).encode(), headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(request, timeout=2) as response:
                ensure(response.status in {200, 201}, "Synthetic emulator bucket creation failed")
            break
        except OSError:
            if time.monotonic() >= deadline:
                raise RuntimeError("Synthetic storage emulator did not become ready") from None
            time.sleep(.25)


class Acceptance:
    def __init__(self):
        required_profile()
        self.nonce = os.environ["INT_E2E_NONCE"]
        ensure(re.fullmatch(r"[a-f0-9]{32}", self.nonce), "Invalid test identity")
        self.sequence = 0
        self.report = {"schema": "clipforge-int-browser-1", "status": "failed", "error_type": None,
            "transport": "direct_http", "postgresql": "real", "object_storage": "fake-gcs-server emulator",
            "cloud_validation": False, "auth_mocked": False, "transcription_mocked": False,
            "steps": [], "real_transcription": False, "real_render": False, "api_replacements": 0,
            "maximum_active_tasks_observed": 0, "lease_renewal_observed": False,
            "whisper": {"model": "tiny multilingual", "weights": "offline runtime directory"}}

    def record(self, step):
        ensure(step in STEP_IDS and step not in {item["id"] for item in self.report["steps"]}, "Invalid public acceptance step")
        self.report["steps"].append({"id": step, "status": "passed"})
        print(json.dumps({"step": step, "status": "passed"}), flush=True)

    def control(self, action):
        ensure(action in {"replace_api", "drain", "start_pair", "wait_workers", "start_worker", "kill_worker",
                          "start_worker_chain", "terminate_worker_child"},
               "Invalid host control action")
        self.sequence += 1
        value = {"nonce": self.nonce, "sequence": self.sequence, "action": action}
        save_new(PRIVATE / "control" / f"request-{self.sequence:03d}.json", value)
        path = PRIVATE / "control" / f"response-{self.sequence:03d}.json"
        deadline = time.monotonic() + 1000
        while not path.is_file():
            ensure(time.monotonic() < deadline, "Host control operation timed out")
            time.sleep(.1)
        response = json.loads(path.read_text())
        ensure(response == {"nonce": self.nonce, "sequence": self.sequence, "status": "passed"}, "Host control response mismatch")

    def health(self, request):
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            try:
                if request.get(ORIGIN + "/health", timeout=2000).status == 200:
                    return
            except Exception:
                pass
            time.sleep(.25)
        raise RuntimeError("Replacement API did not become ready")

    def login(self, page, user):
        page.goto(ORIGIN + "/login", wait_until="networkidle")
        page.locator("#username").fill(user["username"])
        page.locator("#password").fill(user["password"])
        with page.expect_response(lambda r: r.url == ORIGIN + "/auth/login" and r.request.method == "POST") as response:
            page.locator("#login-form button[type=submit]").click()
        ensure(response.value.status == 200, "Real UI login failed")
        page.wait_for_url(ORIGIN + "/", wait_until="networkidle")

    def csrf(self, context):
        response = context.request.get(ORIGIN + "/auth/csrf")
        ensure(response.status == 200, "Authenticated CSRF challenge failed")
        return {"Origin": ORIGIN, "X-CSRF-Token": response.json()["csrf_token"]}

    def mutation(self, context, method, route, *, data=None, key=None):
        headers = self.csrf(context)
        if key:
            headers["Idempotency-Key"] = key
        return context.request.fetch(ORIGIN + route, method=method, data=data, headers=headers)

    def task_rows(self):
        from app.auth_db import get_engine
        from sqlalchemy import text
        with get_engine().connect() as connection:
            return [dict(row) for row in connection.execute(text(
                "SELECT id,job_id,kind,item_id,status,fence,lease_until,cleaned_at FROM cloud_tasks ORDER BY created_at,id")).mappings()]

    def manifest(self, job_id, kind, item_id):
        from app.auth_db import get_engine
        from sqlalchemy import text
        with get_engine().connect() as connection:
            return connection.execute(text("SELECT manifest FROM cloud_documents WHERE job_id=:j AND kind=:k AND id=:i"),
                {"j": job_id, "k": kind, "i": item_id}).scalar_one()

    def check_atomic_publication(self):
        from app.auth_db import get_engine
        from sqlalchemy import text
        # A single statement observes status and manifest together. Separate
        # reads could falsely fail when a valid final transaction commits between
        # sampling a running task and reading its now-completed manifest.
        with get_engine().connect() as connection:
            rows = connection.execute(text("SELECT t.status,d.manifest='{}'::jsonb AS empty_manifest "
                "FROM cloud_tasks t JOIN cloud_documents d ON d.job_id=t.job_id AND d.id=t.item_id "
                "AND d.kind=CASE WHEN t.kind='process' THEN 'job' ELSE 'export' END WHERE t.kind='export'")).mappings()
            ensure(all(row["empty_manifest"] for row in rows if row["status"] == "running"), "In-progress export publishes partial artifacts")

    def wait_status(self, context, route, expected, *, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            response = context.request.get(ORIGIN + route)
            ensure(response.status == 200, "Durable status endpoint failed")
            value = response.json()
            if value["status"] == expected:
                return value
            ensure(value["status"] != "failed" or expected == "failed", "Real worker reported a failed task")
            time.sleep(.1)
        raise RuntimeError("Durable task status timed out")

    def isolation(self):
        import socket
        routes = Path("/proc/net/route").read_text().splitlines()[1:]
        ensure(not any(row.split()[1] == "00000000" for row in routes if row.split()), "Internal network has a default route")
        for address in (("1.1.1.1", 443), ("8.8.8.8", 53)):
            try:
                with socket.create_connection(address, timeout=1):
                    pass
            except OSError:
                continue
            raise RuntimeError("External TCP is reachable")
        fields = dict(line.split(":", 1) for line in Path("/proc/self/status").read_text().splitlines() if ":" in line)
        ensure(fields["NoNewPrivs"].strip() == "1" and all(int(fields[k], 16) == 0 for k in ("CapEff", "CapPrm", "CapBnd")),
               "Acceptance process has unexpected capabilities")
        ensure(os.getuid() != 0 and os.getgid() != 0, "Acceptance process cannot run as root")
        self.record("isolated_database_and_network")
        # Harness ran the real migration twice. Require the same singleton cloud
        # revision and intact two AUTH revisions, rather than invent a mock DDL.
        from app.auth_db import get_engine
        from sqlalchemy import text
        with get_engine().connect() as connection:
            auth = set(connection.execute(text("SELECT revision FROM auth_schema_migrations")).scalars())
            cloud = list(connection.execute(text("SELECT revision FROM cloud_schema_migrations")).scalars())
        ensure(auth == {"auth01_0001", "auth02_0002"} and cloud == ["cloud01_0001"], "Unexpected migration revisions")
        self.record("migrations_idempotent")

    def check_denied(self, context, routes):
        for route in routes:
            response = context.request.get(ORIGIN + route)
            ensure(response.status in {403, 404}, "Other user can access a private project/object")

    def run(self):
        from playwright.sync_api import sync_playwright, expect
        fixture = json.loads((PRIVATE / "fixture-users.json").read_text())
        self.report["whisper"] = json.loads((PRIVATE / "model-identity.json").read_text())
        self.isolation()
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(executable_path=os.getenv("CHROMIUM_EXECUTABLE") or shutil.which("chromium"),
                headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
            try:
                admin_context = browser.new_context()
                first_context = browser.new_context(accept_downloads=True, viewport={"width": 1440, "height": 1100})
                second_context, other_session = browser.new_context(), browser.new_context()
                anonymous = browser.new_context()
                admin, page, other = admin_context.new_page(), first_context.new_page(), second_context.new_page()
                self.health(admin_context.request)
                self.login(admin, fixture["admin"])
                for name in ("first", "second"):
                    response = self.mutation(admin_context, "POST", "/auth/users", data=fixture[name])
                    ensure(response.status == 201, "Administrator must create the synthetic normal user")
                    fixture[name]["id"] = response.json()["user"]["id"]
                self.login(page, fixture["first"])
                self.login(other, fixture["second"])
                self.login(other_session.new_page(), fixture["first"])
                self.record("login_and_two_users")
                ensure(anonymous.request.get(ORIGIN + "/projects").status == 401, "Anonymous project access must fail")
                response = first_context.request.post(ORIGIN + "/jobs/" + "a" * 32 + "/drafts", data={}, headers={"Origin": ORIGIN})
                ensure(response.status == 403, "Authenticated mutation must require CSRF")
                ownership = first_context.request.post(ORIGIN + "/jobs", headers=self.csrf(first_context),
                    multipart={"file": {"name": "input.mp4", "mimeType": "video/mp4", "buffer": b"synthetic"}, "owner_id": fixture["second"]["id"]})
                ensure(ownership.status == 422 and not self.task_rows(), "Upload accepted caller-selected ownership")
                self.record("csrf_and_property_rejection")

                upload_key = secrets.token_hex(20)
                def add_upload_key(route):
                    headers = route.request.headers
                    headers["Idempotency-Key"] = upload_key
                    route.continue_(headers=headers)
                page.route("**/jobs", add_upload_key)
                page.locator("#file").set_input_files("/fixture/input.mp4")
                page.locator("#upload-mode").select_option("auto")
                with page.expect_response(lambda r: r.url == ORIGIN + "/jobs" and r.request.method == "POST") as uploaded:
                    page.locator("#upload-button").click()
                ensure(uploaded.value.status == 202, "Real upload must queue a task")
                job = uploaded.value.json()
                job_id = job["id"]
                ensure(job["status"] == "queued", "API must persist, not execute, multimedia work")
                rows = self.task_rows()
                ensure(len(rows) == 1 and rows[0]["job_id"] == job_id and rows[0]["status"] == "queued", "Upload did not persist its task")
                manifest = self.manifest(job_id, "job", job_id)
                ensure(re.fullmatch(r"workspaces/[a-f0-9]{32}/jobs/[a-f0-9]{32}/original/[a-f0-9]{32}\.mp4", manifest["input.mp4"]["name"]),
                       "Original object name is not an opaque server-owned path")
                from app.auth_db import get_engine
                from sqlalchemy import text
                with get_engine().connect() as connection:
                    ensure(connection.execute(text("SELECT count(*) FROM cloud_outbox WHERE task_id=:i"), {"i": rows[0]["id"]}).scalar_one() == 1,
                           "Upload did not atomically persist dispatch outbox")
                self.record("upload_durable_outbox")
                original_response = first_context.request.get(ORIGIN + f"/jobs/{job_id}/source")
                ensure(original_response.status == 200, "Original proxy did not return HTTP 200")
                source_before = original_response.body()
                ensure(hashlib.sha256(source_before).hexdigest() == hashlib.sha256(Path("/fixture/input.mp4").read_bytes()).hexdigest(),
                       "Persisted original differs from uploaded synthetic fixture")
                headers = {**self.csrf(first_context), "Idempotency-Key": upload_key}
                duplicate = first_context.request.post(ORIGIN + "/jobs", headers=headers,
                    multipart={"file": {"name": "input.mp4", "mimeType": "video/mp4", "buffer": Path("/fixture/input.mp4").read_bytes()},
                               "processing_mode": "auto", **{key: str(value).lower() if type(value) is bool else str(value) for key, value in job["options"].items()}})
                ensure(duplicate.status == 202 and duplicate.json()["id"] == job_id and len(self.task_rows()) == 1,
                       "Duplicate upload must reuse one durable job/task")
                conflict = first_context.request.post(ORIGIN + "/jobs", headers=headers,
                    multipart={"file": {"name": "input.mp4", "mimeType": "video/mp4", "buffer": Path("/fixture/input.mp4").read_bytes()},
                               "processing_mode": "manual", **{key: str(value).lower() if type(value) is bool else str(value) for key, value in job["options"].items()}})
                ensure(conflict.status == 409 and len(self.task_rows()) == 1, "Same key accepted different upload content")
                self.record("upload_idempotency")
                page.unroute("**/jobs", add_upload_key)
                self.check_denied(second_context, [f"/jobs/{job_id}", f"/jobs/{job_id}/source", f"/jobs/{job_id}/workspace"])
                self.control("replace_api")
                self.health(first_context.request)
                ensure(first_context.request.get(ORIGIN + "/auth/me").status == 200, "Session must survive API replacement")
                ensure(first_context.request.get(ORIGIN + f"/jobs/{job_id}").json()["status"] == "queued", "Queue disappeared with API cache")
                self.report["api_replacements"] += 1
                self.record("queued_api_replacement")
                self.control("drain")
                completed = self.wait_status(first_context, f"/jobs/{job_id}", "completed")
                ensure(completed["clips"], "Real heuristic selection produced no clip")
                clip_file = completed["clips"][0]["file"]
                editor = first_context.request.get(ORIGIN + f"/jobs/{job_id}/clips/{clip_file}/editor")
                ensure(editor.status == 200 and any(cue["text"].strip() for cue in editor.json()["cues"]), "Real Whisper transcription has no editable text")
                recognized = set(re.findall(r"[a-z]+", " ".join(cue["text"] for cue in editor.json()["cues"]).lower()))
                matches = recognized & {"speech", "private", "video", "subtitles", "original"}
                ensure(len(matches) >= 3, "Real transcription did not recognize at least three controlled speech keywords")
                self.report["real_transcription"] = True
                self.report["transcript_cues"] = len(editor.json()["cues"])
                self.report["controlled_speech_keywords_matched"] = len(matches)
                self.record("real_transcription_and_selection")
                manual = self.mutation(first_context, "POST", f"/jobs/{job_id}/editor/range", data={"start": 0, "end": 5})
                ensure(manual.status == 200 and manual.json()["duration"] == 5, "Manual clip selection failed")
                self.record("manual_range")
                page.reload(wait_until="networkidle")
                page.locator("#job-details summary").click()
                page.locator("#job-id").fill(job_id)
                page.locator("#job-form button").click()
                expect(page.locator("#status")).to_have_text("Procesamiento completado.")
                page.locator("#clips button").first.click()
                expect(page.locator("#editor")).to_be_visible()
                page.locator("#editor-name").fill("INT synthetic revised clip")
                page.locator("#editor-framing").select_option("crop")
                page.locator("#editor-x").fill("70")
                page.locator("#editor-zoom").fill("1.15")
                page.locator("#editor-burn").check()
                page.locator("#cue-list textarea").first.fill("INT: subtítulo editado y persistente.")
                with page.expect_response(lambda r: re.search(r"/drafts$", r.url) is not None and r.request.method == "POST") as saved:
                    page.locator("#save-draft").click()
                ensure(saved.value.status == 201, "Real editor draft save failed")
                draft = saved.value.json()
                stale = {key: draft[key] for key in ("title", "clip_file", "start", "end", "options", "cues")}
                stale["revision"] = max(1, draft["revision"] - 1)
                # First real update increments the CAS revision. Replaying its old
                # revision must reject an overwrite by another browser instance.
                update = self.mutation(first_context, "PUT", f"/jobs/{job_id}/drafts/{draft['id']}", data=stale)
                ensure(update.status == 200, "Real draft update failed")
                conflict = self.mutation(first_context, "PUT", f"/jobs/{job_id}/drafts/{draft['id']}", data=stale)
                ensure(conflict.status == 409, "Stale draft revision must fail")
                # Reopen editor from the updated API state before rendering.
                page.reload(wait_until="networkidle")
                page.locator("#job-details summary").click()
                page.locator("#job-id").fill(job_id)
                page.locator("#job-form button").click()
                page.locator("#draft-list button").filter(has_text="Abrir borrador").first.click()
                expect(page.locator("#editor-framing")).to_have_value("crop")
                expect(page.locator("#cue-list textarea").first).to_have_value("INT: subtítulo editado y persistente.")
                self.record("edit_and_draft_revision")
                with page.expect_response(lambda r: re.search(r"/drafts/[a-f0-9]{32}/exports$", r.url) is not None and r.request.method == "POST") as queued:
                    page.locator("#export-button").click()
                ensure(queued.value.status == 202, "Editor export must queue real worker work")
                export = queued.value.json()
                export_id = export["id"]
                self.control("drain")
                export = self.wait_status(first_context, f"/jobs/{job_id}/exports/{export_id}", "completed")
                ensure(set(self.manifest(job_id, "export", export_id)) == {"clip.mp4", "clip.srt", "clip.vtt"}, "Export did not atomically publish its complete file set")
                self.report["real_render"] = True
                self.record("real_render_and_atomic_publication")
                expect(page.locator("#exports-list video")).to_have_count(1, timeout=30000)
                page.wait_for_function("document.querySelector('#exports-list video').readyState >= 2", timeout=30000)
                page.locator("#exports-list video").evaluate("v => v.play()")
                page.wait_for_function("document.querySelector('#exports-list video').currentTime > .25", timeout=15000)
                page.locator("#exports-list video").evaluate("v => v.pause()")
                with page.expect_download() as downloaded:
                    page.locator("#exports-list a").filter(has_text="SRT").first.click()
                ensure("INT: subtítulo editado" in Path(downloaded.value.path()).read_text(encoding="utf-8"), "Browser subtitle download differs from editor")
                mp4_route = f"/jobs/{job_id}/exports/{export_id}/files/clip.mp4"
                rendered_bytes = first_context.request.get(ORIGIN + mp4_route).body()
                ensure(len(rendered_bytes) > 1024, "Rendered MP4 download is empty")
                ranged = first_context.request.get(ORIGIN + mp4_route, headers={"Range": "bytes=0-1023"})
                ensure(ranged.status == 206 and ranged.body() == rendered_bytes[:1024], "Generation-pinned byte range failed")
                self.report["render_bytes"] = len(rendered_bytes)
                self.record("browser_playback_and_download")
                self.check_denied(second_context, [f"/jobs/{job_id}", f"/jobs/{job_id}/source", f"/jobs/{job_id}/workspace",
                    f"/jobs/{job_id}/clips/{clip_file}", f"/jobs/{job_id}/clips/{clip_file}/editor", f"/jobs/{job_id}/clips/{clip_file}/subtitles/srt",
                    f"/jobs/{job_id}/drafts/{draft['id']}", f"/jobs/{job_id}/exports/{export_id}", mp4_route,
                    f"/jobs/{job_id}/exports/{export_id}/files/clip.srt"])
                projects = second_context.request.get(ORIGIN + "/projects").json()["projects"]
                ensure(job_id not in {item["id"] for item in projects}, "Other user's project is listed")
                ensure(self.mutation(second_context, "POST", f"/jobs/{job_id}/drafts/{draft['id']}/exports", data={"revision": draft["revision"]}).status in {403, 404},
                       "Other user can render an owned draft")
                self.record("cross_user_object_rejection")
                self.control("replace_api")
                self.health(first_context.request)
                ensure(first_context.request.get(ORIGIN + "/auth/me").status == 200, "Session lost after completed API replacement")
                ensure(first_context.request.get(ORIGIN + mp4_route).body() == rendered_bytes, "API replacement changed durable render")
                ensure(first_context.request.get(ORIGIN + f"/jobs/{job_id}/source").body() == source_before, "API replacement changed original")
                page.reload(wait_until="networkidle")
                expect(page.locator("#project-list")).to_contain_text("input.mp4", timeout=15000)
                self.report["api_replacements"] += 1
                self.record("completed_api_replacement")

                self.concurrency_and_interruption(first_context, job_id, draft)
                self.recovery(admin_context, first_context, other_session, fixture, job_id)
                capabilities = first_context.request.get(ORIGIN + "/cloud/capabilities")
                ensure(capabilities.status == 200 and capabilities.json()["external_llm"] is False
                       and not any(capabilities.json()["features"].values()), "Unsupported cloud feature remains active")
                ensure(first_context.request.get(ORIGIN + "/templates").status == 409, "Local templates remain active in cloud mode")
                ensure(first_context.request.get(ORIGIN + "/ai/config").json()["enabled"] is False, "External LLM remains active")
                self.record("disabled_cloud_features")
                self.report["status"] = "passed"
            finally:
                browser.close()

    def concurrency_and_interruption(self, context, job_id, original_draft):
        draft = context.request.get(ORIGIN + f"/jobs/{job_id}/drafts/{original_draft['id']}").json()
        route = f"/jobs/{job_id}/drafts/{draft['id']}/exports"
        first_key = secrets.token_hex(20)
        one = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=first_key)
        ensure(one.status == 202, "Concurrent export one did not queue")
        duplicate = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=first_key)
        ensure(duplicate.status == 202 and duplicate.json()["id"] == one.json()["id"], "Duplicate export queues a second task")
        two = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=secrets.token_hex(20))
        ensure(two.status == 202 and two.json()["id"] != one.json()["id"], "Second distinct export did not queue")
        target_ids = {one.json()["id"], two.json()["id"]}
        self.control("start_pair")
        leases = {}
        deadline = time.monotonic() + 900
        observed_active = False
        while time.monotonic() < deadline:
            rows = self.task_rows()
            active = [row for row in rows if row["status"] == "running"]
            ensure(len(active) <= 1, "More than one multimedia task is active globally")
            self.report["maximum_active_tasks_observed"] = max(self.report["maximum_active_tasks_observed"], len(active))
            for row in active:
                observed_active = True
                ensure(row["fence"] >= 1 and row["lease_until"] is not None, "Active task lacks a lease/fence")
                before = leases.setdefault(row["id"], row["lease_until"])
                if row["lease_until"] > before:
                    self.report["lease_renewal_observed"] = True
            self.check_atomic_publication()
            targets = [row for row in rows if row["item_id"] in target_ids]
            if len(targets) == 2 and all(row["status"] == "succeeded" for row in targets):
                break
            ensure(not any(row["status"] == "failed" for row in targets), "Concurrent worker failed")
            time.sleep(.1)
        else:
            raise RuntimeError("Concurrent workers did not complete")
        self.control("wait_workers")
        ensure(observed_active and self.report["lease_renewal_observed"], "No real active task/lease renewal was observed")
        self.record("global_single_worker_and_lease_renewal")
        interrupted_child = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=secrets.token_hex(20))
        following_child = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=secrets.token_hex(20))
        ensure(interrupted_child.status == 202 and following_child.status == 202, "Child-death render pair did not queue")
        self.control("start_worker_chain")
        self.control("terminate_worker_child")
        self.control("wait_workers")
        failed_child = self.wait_status(context, f"/jobs/{job_id}/exports/{interrupted_child.json()['id']}", "failed")
        ensure(failed_child.get("error_code") == "WORKER_INTERRUPTED", "Terminated worker child did not persist interruption")
        ensure(not self.manifest(job_id, "export", interrupted_child.json()["id"]), "Terminated worker child published partial output")
        self.wait_status(context, f"/jobs/{job_id}/exports/{following_child.json()['id']}", "completed")
        self.check_atomic_publication()
        self.record("worker_child_death_stops_media_before_next_task")
        interrupted = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=secrets.token_hex(20))
        ensure(interrupted.status == 202, "Interruption export did not queue")
        interrupted_id = interrupted.json()["id"]
        self.control("start_worker")
        deadline = time.monotonic() + 30
        while time.monotonic() < deadline:
            current = next(row for row in self.task_rows() if row["item_id"] == interrupted_id)
            if current["status"] == "running":
                break
            time.sleep(.05)
        else:
            raise RuntimeError("Controlled worker was never active")
        original_fence = current["fence"]
        ensure(not self.manifest(job_id, "export", interrupted_id), "Interrupted attempt already published artifacts")
        self.control("kill_worker")
        unavailable = context.request.get(ORIGIN + f"/jobs/{job_id}/exports/{interrupted_id}/files/clip.mp4")
        ensure(unavailable.status in {404, 409}, "Interrupted export exposes a partial MP4")
        # The real supervisor respects the existing 60-second lease. No SQL time
        # manipulation, force unlock, lock bypass or manual status repair occurs.
        self.control("drain")
        failed = self.wait_status(context, f"/jobs/{job_id}/exports/{interrupted_id}", "failed")
        current = next(row for row in self.task_rows() if row["item_id"] == interrupted_id)
        ensure(failed.get("error_code") == "WORKER_INTERRUPTED" and current["fence"] > original_fence,
               "Interrupted worker was not durably fenced")
        ensure(not self.manifest(job_id, "export", interrupted_id), "Interrupted task published a manifest")
        ensure(current["cleaned_at"] is not None, "Interrupted attempt cleanup remains pending")
        self.record("interrupted_worker_fenced")
        new = self.mutation(context, "POST", route, data={"revision": draft["revision"]}, key=secrets.token_hex(20))
        ensure(new.status == 202, "New explicit variant after interruption did not queue")
        self.control("drain")
        self.wait_status(context, f"/jobs/{job_id}/exports/{new.json()['id']}", "completed")
        self.record("new_export_after_interruption")

    def recovery(self, admin_context, first_context, other_session, fixture, job_id):
        target = fixture["first"]["id"]
        route = "/auth/admin/users/" + target + "/recovery"
        denied = self.mutation(admin_context, "POST", route, data={"current_password": "authored-incorrect-password"})
        ensure(denied.status == 400, "Recovery must reauthenticate administrator")
        issued = self.mutation(admin_context, "POST", route, data={"current_password": fixture["admin"]["password"]})
        ensure(issued.status == 201, "Real recovery issuance failed")
        code = issued.json()["recovery_code"]
        replacement = secrets.token_urlsafe(30)
        # Code stays exclusively in memory; use the real public recovery UI.
        page = first_context.browser.new_context().new_page()
        page.goto(ORIGIN + "/recover", wait_until="networkidle")
        page.locator("#recovery-code").fill(code)
        page.locator("#recovery-new-password").fill(replacement)
        page.locator("#recovery-confirm-password").fill(replacement)
        with page.expect_response(lambda r: r.url == ORIGIN + "/auth/recover" and r.request.method == "POST") as recovered:
            page.locator("#recovery-form button[type=submit]").click()
        ensure(recovered.value.status == 200, "Recovery UI failed")
        ensure(first_context.request.get(ORIGIN + "/auth/me").status == 401 and other_session.request.get(ORIGIN + "/auth/me").status == 401,
               "Recovery failed to revoke both sessions")
        ensure(page.context.request.get(ORIGIN + "/auth/me").status == 401, "Recovery must require explicit login")
        token = page.context.request.get(ORIGIN + "/auth/csrf").json()["csrf_token"]
        replay = page.context.request.post(ORIGIN + "/auth/recover", data={"code": code, "new_password": replacement},
            headers={"Origin": ORIGIN, "X-CSRF-Token": token})
        ensure(replay.status == 400, "Recovery code is reusable")
        self.login(page, {"username": fixture["first"]["username"], "password": replacement})
        ensure(page.context.request.get(ORIGIN + f"/jobs/{job_id}").status == 200, "Recovery changed project ownership")
        page.context.close()
        # The original context was revoked: replace its session explicitly for
        # the final disabled-feature checks without changing users or roles.
        self.login(first_context.new_page(), {"username": fixture["first"]["username"], "password": replacement})
        self.record("recovery_and_session_revocation")


def process_table():
    """Private process inspection inside the exclusive worker PID namespace."""
    result = {}
    for directory in Path("/proc").iterdir():
        if not directory.name.isdigit():
            continue
        try:
            stat = (directory / "stat").read_text().rsplit(") ", 1)[1].split()
            comm = (directory / "comm").read_text().strip()
            command = (directory / "cmdline").read_bytes().split(b"\0") if comm.startswith("python") else []
            result[int(directory.name)] = {"state": stat[0], "parent": int(stat[1]), "start": stat[19], "comm": comm,
                "execute": b"app.cloud.worker" in command and b"--execute" in command,
                "supervisor": b"app.cloud.worker" in command and b"--execute" not in command}
        except (OSError, ValueError, IndexError):
            continue  # A process may finish between directory and metadata reads.
    return result


def terminate_worker_child():
    ensure(os.getenv("CLIPFORGE_CLOUD_LOCAL_TEST") == "1" and os.getenv("CLIPFORGE_AUTH_PROFILE") == "local-http"
           and re.fullmatch(r"[a-f0-9]{32}", os.getenv("INT_E2E_NONCE", "")), "Explicit owned worker test profile required")
    deadline = time.monotonic() + 30
    target = None
    while time.monotonic() < deadline:
        table = process_table()
        for pid, process in table.items():
            parent = table.get(process["parent"], {})
            if process["comm"] == "ffmpeg" and process["state"] != "Z" and parent.get("execute"):
                target = (pid, process, process["parent"], parent)
                break
        if target:
            break
        time.sleep(.02)
    ensure(target is not None, "No real FFmpeg child was observed for controlled interruption")
    media_pid, media, execute_pid, execute = target
    current = process_table()
    ensure(current.get(media_pid, {}).get("start") == media["start"] and current.get(execute_pid, {}).get("start") == execute["start"],
           "Controlled worker process identity changed before interruption")
    ensure(current.get(1, {}).get("supervisor") is True, "Worker PID 1 must remain the real supervisor")
    os.kill(execute_pid, signal.SIGTERM)
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline:
        table = process_table()
        old = table.get(media_pid)
        if old is None or old["start"] != media["start"] or old["state"] == "Z":
            break
        time.sleep(.01)
    else:
        raise CheckFailed("FFmpeg survived worker child termination")
    ensure(table.get(1, {}).get("supervisor") is True and table[1]["state"] != "Z", "Container exited instead of proving media parent-death cleanup")
    active = [process for process in table.values() if process["comm"] == "ffmpeg" and process["state"] != "Z"]
    ensure(len(active) <= 1, "Multiple FFmpeg processes survived controlled child interruption")
    report = {"schema": "clipforge-int-worker-child-death-1", "status": "passed", "signal": "SIGTERM to Python --execute only",
        "real_ffmpeg_observed": True, "old_media_active": False, "container_preserved": True,
        "active_media_after_termination": len(active), "zombie_media_observed": sum(process["comm"] == "ffmpeg" and process["state"] == "Z" for process in table.values()),
        "native_lease_modified": False, "cloud_validation": False}
    print(json.dumps(report), flush=True)
    return 0


def speech_only():
    """Additional real inference check; no API, DB, credentials or egress."""
    ensure(os.getenv("CLIPFORGE_INT_SPEECH_TEST") == "1" and os.getenv("HF_HUB_OFFLINE") == "1"
           and os.getenv("TRANSFORMERS_OFFLINE") == "1", "Explicit offline synthetic speech profile required")
    report = {"schema": "clipforge-int-controlled-speech-1", "status": "failed", "error_type": None,
        "transcription_mocked": False, "cloud_validation": False, "network": "none", "keywords_required": 3,
        "candidate_keywords": 5, "keywords_matched": 0}
    try:
        from app.model_source import resolve_model
        from faster_whisper import WhisperModel
        source = Path("/fixture/input.mp4")
        model = WhisperModel(resolve_model(), device="cpu", compute_type="int8")
        segments, info = model.transcribe(str(source), beam_size=1, vad_filter=True)
        cues = [segment.text for segment in segments if segment.text.strip()]
        recognized = set(re.findall(r"[a-z]+", " ".join(cues).lower()))
        report["keywords_matched"] = len(recognized & {"speech", "private", "video", "subtitles", "original"})
        report["segments"] = len(cues)
        report["fixture_sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
        lock = json.loads(Path(os.environ["CLIPFORGE_MODEL_LOCK"]).read_text())
        report["model"] = {key: lock[key] for key in ("model", "repo_id", "revision")}
        report["status"] = "passed" if report["keywords_matched"] >= 3 else "failed"
    except Exception as error:
        report["error_type"] = type(error).__name__
    save_new(PUBLIC / "controlled-speech-summary.json", report)
    return 0 if report["status"] == "passed" else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--prepare", action="store_true")
    parser.add_argument("--speech-only", action="store_true")
    parser.add_argument("--terminate-worker-child", action="store_true")
    args = parser.parse_args(argv)
    if args.prepare:
        prepare()
        return 0
    if args.speech_only:
        return speech_only()
    if args.terminate_worker_child:
        return terminate_worker_child()
    acceptance = Acceptance()
    try:
        acceptance.run()
    except Exception as error:
        # Playwright exception messages can contain filled password values.
        acceptance.report["error_type"] = type(error).__name__
        if isinstance(error, CheckFailed):
            acceptance.report["failure_check"] = str(error)
        frames = [frame for frame in traceback.extract_tb(error.__traceback__) if Path(frame.filename).name == "browser_int_e2e.py"]
        if frames:
            acceptance.report["failure_location"] = {"function": frames[-1].name, "line": frames[-1].lineno}
    finally:
        save_new(PUBLIC / "browser-summary.json", acceptance.report)
    return 0 if acceptance.report["status"] == "passed" else 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as error:
        print(json.dumps({"status": "failed", "error_type": type(error).__name__}), file=sys.stderr)
        raise SystemExit(1)
