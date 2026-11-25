"""Chromium regression for the INT beta frontend with local synthetic responses."""
import json
import os
from pathlib import Path
import secrets
import unittest
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from scripts.int_hito_a_browser import resolve_browser


STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
ORIGIN = "http://127.0.0.1:48129"
GCS = "https://storage.googleapis.com/clipforge-fixture/session"
JOB = "a" * 32
CLIP = "clip_01.mp4"
EXPORT = "c" * 32
CHUNK = 8 * 1024 * 1024
MAX_SIZE = 2 * CHUNK
CSP = "default-src 'self'; connect-src 'self' https://storage.googleapis.com; media-src 'self'"


class BrowserHitoBTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        driver = sync_playwright().start()
        cls.addClassCleanup(driver.stop)
        executable = resolve_browser({"INT_HITO_A_BROWSER_EXECUTABLE": os.getenv("INT_HITO_B_BROWSER_EXECUTABLE", "")})
        cls.browser = driver.chromium.launch(executable_path=str(executable), headless=True)
        cls.addClassCleanup(cls.browser.close)

    def setUp(self):
        self.state = {"admin": False, "status": None, "reservations": [], "starts": [],
                      "puts": [], "unexpected": [], "hide_range": False,
                      "manual": None, "manual_keys": []}
        self.context = self.browser.new_context(service_workers="block")
        self.addCleanup(self.context.close)
        self.context.route("**/*", self.handle)
        self.page = self.context.new_page()
        self.page.set_default_timeout(12_000)
        self.csrf = secrets.token_urlsafe(32)
        self.errors = []
        self.page.on("pageerror", lambda error: self.errors.append(str(error)))

    def handle(self, route):
        request = route.request
        parsed = urlsplit(request.url)
        if request.url == GCS:
            self.handle_gcs(route)
            return
        self.assertEqual(ORIGIN, f"{parsed.scheme}://{parsed.netloc}")
        path = parsed.path
        assets = {"beta.js": "text/javascript", "auth.js": "text/javascript",
                  "mvp.js": "text/javascript", "mvp.css": "text/css",
                  "beta.css": "text/css", "account.css": "text/css"}
        if path == "/":
            route.fulfill(status=200, content_type="text/html", headers={"Content-Security-Policy": CSP},
                          body=(STATIC / "beta.html").read_bytes())
            return
        asset = path.removeprefix("/static/")
        if path.startswith("/static/") and asset in assets:
            route.fulfill(status=200, content_type=assets[asset], body=(STATIC / asset).read_bytes())
            return
        if path in {f"/jobs/{JOB}/clips/{CLIP}", f"/jobs/{JOB}/source"}:
            route.fulfill(status=503, content_type="video/mp4")
            return
        data, status = self.api(path, request)
        route.fulfill(status=status, content_type="application/json", body=json.dumps(data))

    def handle_gcs(self, route):
        request = route.request
        headers = {"access-control-allow-origin": ORIGIN, "access-control-allow-methods": "PUT",
                   "access-control-allow-headers": "Content-Range, Content-Type",
                   "access-control-expose-headers": "Range"}
        if request.method == "OPTIONS":
            route.fulfill(status=204, headers=headers)
            return
        fields = request.all_headers()
        self.state["puts"].append((request.method, fields.get("content-range"),
                                  bool({"cookie", "x-csrf-token", "authorization", "referer"}.intersection(fields))))
        index = len(self.state["puts"])
        if self.state["hide_range"]:
            route.fulfill(status={1: 308, 2: 200}.get(index, 500), headers=headers)
            return
        if index in {1, 3}:
            headers["Range"] = "bytes=0-" + str(CHUNK - 1)
        route.fulfill(status={1: 308, 2: 503, 3: 308, 4: 200}.get(index, 500), headers=headers)

    def api(self, path, request):
        method = request.method
        if method == "POST":
            self.assertEqual(self.csrf, request.headers.get("x-csrf-token"))
        if path == "/environment":
            return {"environment": "INT", "revision": "b" * 40}, 200
        if path == "/auth/me":
            return {"user": {"username": "fixture", "is_admin": self.state["admin"],
                             "permissions": ["users:manage"] if self.state["admin"] else []},
                    "csrf_token": self.csrf}, 200
        if path == "/beta/limits":
            return {"max_bytes": MAX_SIZE, "min_duration_seconds": 20, "max_duration_seconds": 180,
                    "max_dimension": 1920, "formats": ["MP4 (H.264 + AAC)"], "worker_concurrency": 1,
                    "active_jobs_per_user": 1, "selection_mode": "heuristic_voice"}, 200
        if path == "/beta/uploads" and method == "POST":
            self.state["reservations"].append((request.headers.get("idempotency-key"), request.post_data_json))
            self.state["status"] = "awaiting_upload"
            return {"id": JOB, "status": self.state["status"], "upload_url": GCS}, 201
        if path == f"/beta/uploads/{JOB}/start" and method == "POST":
            self.state["starts"].append(path)
            self.state["status"] = "queued"
            return {"id": JOB, "status": "queued", "dispatch_status": "pending"}, 202
        if path == "/projects":
            state = self.state["status"]
            return {"projects": [{"id": JOB, "status": state, "title": "Video de prueba"}] if state else [],
                    "has_more": False}, 200
        if path == "/jobs/" + JOB:
            state = self.state["status"]
            return {"id": JOB, "status": state, "pilot": True,
                    "media": {"duration_seconds": 426.55},
                    "clips": [{"file": CLIP, "start": 0, "end": 22}] if state == "completed" else []}, 200
        if path == f"/jobs/{JOB}/workspace":
            return {"source_duration": 426.55}, 200
        if path == f"/jobs/{JOB}/editor/range" and method == "POST":
            return request.post_data_json, 200
        if path == f"/jobs/{JOB}/editor/exports" and method == "POST":
            self.state["manual_keys"].append(request.headers.get("idempotency-key"))
            if self.state["manual"] is None:
                self.state["manual"] = {"id": EXPORT, "clip_file": "manual.mp4", "status": "queued",
                                        **request.post_data_json}
            return self.state["manual"], 202
        if path == f"/jobs/{JOB}/exports":
            return {"exports": [self.state["manual"]] if self.state["manual"] else []}, 200
        self.state["unexpected"].append(path)
        return {}, 404

    def until_text(self, selector, contains):
        self.page.wait_for_function("""([selector, contains]) =>
            document.querySelector(selector).textContent.includes(contains)""", arg=[selector, contains])

    def test_creator_resumable_upload_reactivation_and_reload(self):
        self.page.goto(ORIGIN + "/")
        self.until_text("#upload-limits", "16 MiB")
        self.assertEqual(0, self.page.locator("#feedback, #admin-feedback").count())
        field = self.page.locator("#upload-video")
        field.evaluate("""(input, maximum) => {
            const transfer = new DataTransfer();
            transfer.items.add(new File([new Uint8Array(maximum + 1)], 'grande.mp4', {type: 'video/mp4'}));
            input.files = transfer.files;
            input.dispatchEvent(new Event('change'));
        }""", MAX_SIZE)
        self.until_text("#upload-status", "supera el máximo")
        self.assertEqual([], self.state["reservations"])
        size = CHUNK + 10
        field.set_input_files({"name": "valido.mp4", "mimeType": "video/mp4", "buffer": bytes(size)})
        self.page.locator("#upload-submit").click()
        self.until_text("#upload-status", "Video guardado")
        self.until_text("#job-status", "Pendiente")
        self.assertEqual([("PUT", "bytes 0-" + str(CHUNK - 1) + "/" + str(size), False),
                          ("PUT", "bytes " + str(CHUNK) + "-" + str(size - 1) + "/" + str(size), False),
                          ("PUT", "bytes */" + str(size), False),
                          ("PUT", "bytes " + str(CHUNK) + "-" + str(size - 1) + "/" + str(size), False)],
                         self.state["puts"])
        self.assertEqual(1, len(self.state["reservations"]))
        key, body = self.state["reservations"][0]
        self.assertRegex(key, r"^[a-f0-9-]{36}$")
        self.assertEqual({"filename": "valido.mp4", "bytes": size}, body)
        self.assertTrue(self.page.evaluate("() => !JSON.stringify(localStorage).includes('storage.googleapis.com')"))

        self.page.locator("#start-existing").click()
        self.until_text("#job-status", "volver a intentar")
        self.assertEqual([f"/beta/uploads/{JOB}/start"] * 2, self.state["starts"])
        self.state["status"] = "completed"
        self.page.reload()
        self.until_text("#job-status", "Completado")
        self.assertEqual(f"/jobs/{JOB}/clips/{CLIP}?inline=true", self.page.locator("#clip-list video").get_attribute("src"))
        download = self.page.get_by_role("link", name="Descargar Clip 1 en MP4")
        self.assertEqual(f"/jobs/{JOB}/clips/{CLIP}", download.get_attribute("href"))
        self.assertEqual(0, self.page.locator("#feedback, #feedback-job, #admin-feedback").count())
        self.assertTrue(self.page.locator("#job-actions").is_hidden())
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_storage_resume_without_range_header(self):
        self.state["hide_range"] = True
        self.page.goto(ORIGIN + "/")
        self.until_text("#upload-limits", "16 MiB")
        size = CHUNK + 10
        self.page.locator("#upload-video").set_input_files(
            {"name": "respaldo.mp4", "mimeType": "video/mp4", "buffer": bytes(size)}
        )
        self.page.locator("#upload-submit").click()
        self.until_text("#upload-status", "Video guardado")
        self.assertEqual([("PUT", f"bytes 0-{CHUNK - 1}/{size}", False),
                          ("PUT", f"bytes 0-{size - 1}/{size}", False)], self.state["puts"])
        self.assertEqual(1, len(self.state["reservations"]))
        self.assertEqual(1, len(self.state["starts"]))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])


    def test_admin_workspace_has_no_feedback_controls_or_requests(self):
        self.state["admin"] = True
        self.page.goto(ORIGIN + "/")
        self.until_text("#upload-limits", "16 MiB")
        self.assertTrue(self.page.get_by_role("link", name="Mi cuenta fixture").is_visible())
        self.assertEqual(0, self.page.locator("#feedback, #admin-feedback, [href='#feedback']").count())
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_validated_failed_original_can_generate_and_reopen_a_manual_clip(self):
        self.state["status"] = "failed"
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Elegir fragmento del original").click()
        self.page.wait_for_function("() => !document.querySelector('#mvp-start').disabled")
        self.assertEqual(f"/jobs/{JOB}/source", self.page.locator("#mvp-source").get_attribute("src"))
        self.page.locator("#mvp-start").fill("392")
        self.page.locator("#mvp-end").fill("421.5")
        submit = self.page.get_by_role("button", name="Generar clip manual")
        submit.click()
        self.until_text("#mvp-results", "Clip en cola")
        submit.click()
        self.page.wait_for_function("() => !document.querySelector('#mvp-export').disabled")
        self.assertEqual(["manual-" + JOB + "-392000-421500"] * 2, self.state["manual_keys"])
        self.state["manual"]["status"] = "completed"
        download = self.page.get_by_role("link", name="Descargar clip manual")
        download.wait_for()
        self.assertEqual(f"/jobs/{JOB}/exports/{EXPORT}/files/clip.mp4", download.get_attribute("href"))
        self.page.reload()
        self.page.get_by_text("Elegir fragmento del original").click()
        download.wait_for()
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])


if __name__ == "__main__":
    unittest.main()
