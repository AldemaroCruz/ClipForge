"""Chromium regression for the INT beta frontend with local synthetic responses."""
import json
import os
from pathlib import Path
import secrets
import unittest
from urllib.parse import urlsplit

from playwright.sync_api import sync_playwright

from scripts.int_hito_a_browser import resolve_browser
from scripts.int_hito_b_browser_ui import submit_quick_caption_correction


STATIC = Path(__file__).resolve().parent.parent / "app" / "static"
ORIGIN = "http://127.0.0.1:48129"
GCS = "https://storage.googleapis.com/clipforge-fixture/session"
JOB = "a" * 32
OTHER_JOB = "b" * 32
CLIP = "clip_01.mp4"
EXPORT = "c" * 32
DRAFT = "d" * 32
CAPTION = "f" * 32
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
                      "manual": None, "manual_keys": [], "manual_retries": [],
                      "ai_configured": True, "analysis": None, "selection_posts": [], "draft": None,
                      "range_posts": [], "draft_updates": [], "approved": {},
                      "caption": None, "project_caption": None, "caption_updates": [], "deletions": []}
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
                  "mvp.js": "text/javascript", "editorial.js": "text/javascript", "mvp.css": "text/css",
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
            route.fulfill(status=404 if self.state["status"] == "deleted" else 503, content_type="video/mp4")
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
            if index == 2:
                headers["Range"] = "bytes=0-" + str(CHUNK - 1)
            route.fulfill(status={1: 308, 2: 308, 3: 200}.get(index, 500), headers=headers)
            return
        if index in {1, 3}:
            headers["Range"] = "bytes=0-" + str(CHUNK - 1)
        route.fulfill(status={1: 308, 2: 503, 3: 308, 4: 200}.get(index, 500), headers=headers)

    def api(self, path, request):
        method = request.method
        if method in {"POST", "PUT"}:
            self.assertEqual(self.csrf, request.headers.get("x-csrf-token"))
        if path == "/environment":
            return {"environment": "INT", "revision": "b" * 40}, 200
        if path == "/auth/me":
            return {"user": {"id": "2" * 32, "username": "fixture", "is_admin": self.state["admin"],
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
            projects = []
            if state not in {None, "deleted"}:
                projects.append({"id": JOB, "status": state, "title": "Video de prueba"})
            if self.state.get("other_project"):
                projects.append({"id": OTHER_JOB, "status": "completed", "title": "Otro video"})
            return {"projects": projects, "has_more": False}, 200
        if path == f"/jobs/{OTHER_JOB}" and self.state.get("other_project"):
            return {"id": OTHER_JOB, "status": "completed", "pilot": True, "clips": []}, 200
        if path == f"/jobs/{JOB}/deletion":
            if method == "POST":
                self.state["deletions"].append(path)
                if self.state.get("deletion_failed"):
                    return {"detail": "No se pudo eliminar el proyecto."}, 503
                self.state["status"] = "deleted"
            if self.state["status"] == "deleted":
                return {"id": JOB, "status": "deleted"}, 202 if method == "POST" else 200
            return {}, 404
        if self.state["status"] == "deleted" and (path == f"/jobs/{JOB}" or path.startswith(f"/jobs/{JOB}/")):
            return {}, 404
        if path == "/jobs/" + JOB:
            state = self.state["status"]
            clip = {"file": CLIP, "start": 0, "end": 22}
            if self.state["caption"]:
                caption = self.state["caption"]
                clip.update(start=caption["start"], end=caption["end"],
                            captions={key: caption[key] for key in ("status", "output", "revision")})
            clips = [clip] if state == "completed" else []
            if self.state.get("sibling_clip"):
                clips.append(self.state["sibling_clip"])
            return {"id": JOB, "status": state, "pilot": True,
                    "media": {"duration_seconds": self.state.get("duration", 426.55)},
                    "clips": clips,
                    "caption_style": self.state["project_caption"]}, 200
        if path == f"/jobs/{JOB}/clips/{CLIP}/captions" and self.state["caption"]:
            caption = self.state["caption"]
            if method == "PUT":
                update = request.post_data_json
                self.assertEqual(caption["revision"], update["revision"])
                self.state["caption_updates"].append(update)
                caption.update(style=update["style"], cues=update["cues"], revision=caption["revision"] + 1,
                               status="queued", output=None)
                return caption, 202
            return caption, 200
        if path == f"/jobs/{JOB}/captions" and method == "PUT" and self.state["project_caption"]:
            update = request.post_data_json
            self.assertTrue(update["apply_to_all"])
            self.assertNotIn("cues", update)
            self.state["caption_updates"].append(update)
            self.assertEqual(self.state["project_caption"]["revision"], update["revision"])
            state = {"style": update["style"], "revision": update["revision"] + 1}
            self.state["project_caption"] = state
            self.state["caption"].update(style=state["style"], revision=self.state["caption"]["revision"] + 1)
            return state, 200
        if path == f"/jobs/{JOB}/workspace":
            return {"source_duration": self.state.get("duration", 426.55)}, 200
        if path == f"/jobs/{JOB}/editor/range" and method == "POST":
            data = request.post_data_json
            self.state["range_posts"].append(data)
            return {**data, "cues": data.get("cues", self.cue_fixture())}, 200
        if path == f"/jobs/{JOB}/editor/exports" and method == "POST":
            self.state["manual_keys"].append(request.headers.get("idempotency-key"))
            if self.state["manual"] is None:
                self.state["manual"] = {"id": EXPORT, "clip_file": "manual.mp4", "status": "queued",
                                        **request.post_data_json}
            return self.state["manual"], 202
        if path == f"/jobs/{JOB}/exports/{EXPORT}/retry" and method == "POST":
            self.state["manual_retries"].append(path)
            self.state["manual"].update(status="queued", retryable=False)
            return self.state["manual"], 202
        if path == f"/jobs/{JOB}/exports":
            manual = [self.state["manual"]] if self.state["manual"] else []
            return {"exports": manual + list(self.state["approved"].values())}, 200
        if path == "/ai/config":
            if not self.state["ai_configured"]:
                return {"configured": False, "reason": "IA pendiente de configurar."}, 200
            return {"configured": True, "provider": "fixture", "model": "editorial-fixture"}, 200
        if path == f"/jobs/{JOB}/selections/context":
            return {"available": True, "duration": 426.55}, 200
        if path == f"/jobs/{JOB}/selections/preview" and method == "POST":
            spec = request.post_data_json
            return {"spec": spec, "preview_token": "e" * 64, "eligible_range_count": 3,
                    "provider": {"provider": "fixture", "model": "editorial-fixture", "destination": "fixture"},
                    "payload_text": {"editorial_brief": spec["brief"], "transcript": "Una decisión útil"},
                    "system_instructions": "Escoge identificadores del catálogo."}, 200
        if path == f"/jobs/{JOB}/selections":
            if method == "GET":
                return {"analyses": [self.state["analysis"]] if self.state["analysis"] else []}, 200
            submitted = request.post_data_json
            self.state["selection_posts"].append(submitted)
            if self.state["analysis"] is None:
                self.state["analysis"] = {
                    "id": submitted["request_id"], "mode": "llm", "status": "completed", "created_at": 1,
                    "provider": "fixture", "model": "editorial-fixture", "summary": "Una idea práctica.",
                    "candidates": [{"id": "1", "title": "Una decisión útil", "reason": "Explica un paso concreto.",
                                    "start": 392, "end": 421.5, "transcript_excerpt": "Así se hace.",
                                    "context_before": "La pregunta inicial.", "context_after": "El resultado."}],
                }
                return {"detail": "Respuesta interrumpida."}, 503
            return self.state["analysis"], 202
        if self.state["analysis"]:
            selection = f"/jobs/{JOB}/selections/{self.state['analysis']['id']}"
            if path == selection:
                return self.state["analysis"], 200
            if path == selection + "/candidates/1/draft" and method == "POST":
                candidate = self.state["analysis"]["candidates"][0]
                return self.store_draft(title=candidate["title"], start=candidate["start"], end=candidate["end"],
                                        cues=self.cue_fixture()), 201
        if path == f"/jobs/{JOB}/drafts":
            if method == "GET":
                return {"drafts": [self.state["draft"]] if self.state["draft"] else []}, 200
            self.assertTrue(request.headers.get("idempotency-key", "").startswith("manual-draft-"))
            return self.store_draft(**request.post_data_json), 201
        if path == f"/jobs/{JOB}/drafts/{DRAFT}":
            if method == "PUT":
                updated = request.post_data_json
                self.state["draft_updates"].append(updated)
                self.assertEqual(self.state["draft"]["revision"], updated["revision"])
                self.state["draft"].update({**updated, "revision": updated["revision"] + 1})
            return self.state["draft"], 200
        if path == f"/jobs/{JOB}/drafts/{DRAFT}/exports" and method == "POST":
            revision = request.post_data_json["revision"]
            self.assertEqual(f"approved-{DRAFT}-{revision}", request.headers.get("idempotency-key"))
            draft = self.state["draft"]
            item = self.state["approved"].setdefault(revision, {
                **draft, "id": str(revision) * 32, "draft_id": DRAFT,
                "draft_revision": revision, "status": "completed",
            })
            return item, 202
        self.state["unexpected"].append(path)
        return {}, 404

    @staticmethod
    def cue_fixture():
        return [{"start": 1, "end": 3, "text": "Así se hace.\nEl siguiente paso."}]

    def store_draft(self, **draft):
        if self.state["draft"] is None:
            self.state["draft"] = {"id": DRAFT, "revision": 1, "options": {}, **draft}
        return self.state["draft"]

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
        self.assertEqual({"filename": "valido.mp4", "bytes": size, "burn_subtitles": True}, body)
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
        self.assertTrue(self.page.locator("#start-existing").is_hidden())
        self.assertTrue(self.page.locator("#retry-job").is_hidden())
        self.assertTrue(self.page.locator("#delete-project").is_visible())
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
        self.page.locator("#upload-burn-subtitles").uncheck()
        self.page.locator("#upload-submit").click()
        self.until_text("#upload-status", "Video guardado")
        self.assertEqual([("PUT", f"bytes 0-{CHUNK - 1}/{size}", False),
                          ("PUT", f"bytes */{size}", False),
                          ("PUT", f"bytes {CHUNK}-{size - 1}/{size}", False)], self.state["puts"])
        self.assertEqual(1, len(self.state["reservations"]))
        self.assertFalse(self.state["reservations"][0][1]["burn_subtitles"])
        self.assertEqual(1, len(self.state["starts"]))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_automatic_clip_subtitle_download_and_saved_clip_style(self):
        style = {"burn_subtitles": True, "subtitle_font_size": 52, "subtitle_color": "#FFFFFF",
                 "subtitle_position": "bottom", "subtitle_outline": 3}
        base = f"/jobs/{JOB}/clips/{CLIP}"
        variant = f"/jobs/{JOB}/exports/{CAPTION}/files/clip"
        self.state.update(status="completed", caption={
            "start": 392.0, "end": 421.5, "duration": 29.5, "cues": self.cue_fixture(),
            "style": style.copy(), "revision": 0, "status": "completed",
            "output": {"id": "f" * 64, "mp4": base, "srt": base + "/subtitles/srt",
                       "vtt": base + "/subtitles/vtt", "burn_subtitles": True},
        }, project_caption={"style": style.copy(), "revision": 0})
        self.page.goto(ORIGIN + "/?job=" + JOB)
        card = self.page.locator("#clip-list article")
        srt = card.get_by_role("link", name="Descargar SRT")
        srt.wait_for()
        self.assertEqual(base + "/subtitles/srt", srt.get_attribute("href"))
        self.assertEqual(base + "/subtitles/vtt",
                         card.get_by_role("link", name="Descargar WebVTT").get_attribute("href"))
        self.assertTrue(self.page.locator("#clip-caption-editor").is_hidden())
        card.get_by_role("button", name="Editar subtítulos").click()
        editor = self.page.locator("#clip-caption-form")
        editor.wait_for()
        self.until_text("#clip-caption-range", "392.000–421.500")
        self.assertEqual("1", editor.locator('[data-field="start"]').input_value())
        editor.locator('[data-field="start"]').fill("1.250")
        editor.locator("textarea").fill("Texto del recorte.")
        self.page.locator("#clip-caption-size").fill("76")
        self.page.locator("#clip-caption-color").fill("#edad42")
        self.page.locator("#clip-caption-position").select_option("top")
        self.page.locator("#clip-caption-edge").fill("6")
        self.page.locator("#clip-caption-save").click()
        self.until_text("#clip-caption-status", "en cola")
        saved = self.state["caption"]
        self.assertEqual((1.25, "Texto del recorte."), (saved["cues"][0]["start"], saved["cues"][0]["text"]))
        self.assertEqual((76, "#EDAD42", "top", 6), tuple(saved["style"][key] for key in
            ("subtitle_font_size", "subtitle_color", "subtitle_position", "subtitle_outline")))
        saved.update(status="completed", output={"id": CAPTION, "mp4": variant + ".mp4",
                                                 "srt": variant + ".srt", "vtt": variant + ".vtt",
                                                 "burn_subtitles": True})
        self.page.wait_for_function("""expected => document.querySelector('#clip-caption-preview')
                                     .getAttribute('src') === expected""", arg=variant + ".mp4?inline=true")
        self.assertEqual(base, card.get_by_role("link", name="MP4 inicial").get_attribute("href"))
        self.assertEqual(variant + ".srt", srt.get_attribute("href"))
        self.page.locator("#clip-caption-size").fill("88")
        self.page.once("dialog", lambda dialog: dialog.accept())
        self.page.locator("#clip-caption-apply-all").click()
        self.until_text("#clip-caption-status", "Estilo del proyecto guardado")
        self.assertEqual(88, self.state["project_caption"]["style"]["subtitle_font_size"])
        self.assertEqual("Texto del recorte.", self.state["caption"]["cues"][0]["text"])
        self.page.reload()
        card.get_by_role("button", name="Editar subtítulos").click()
        editor.wait_for()
        self.assertEqual("88", self.page.locator("#clip-caption-size").input_value())
        self.assertEqual("Texto del recorte.", editor.locator("textarea").input_value())
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_quick_caption_correction_preserves_intervals_style_and_the_other_clip(self):
        style = {"burn_subtitles": True, "subtitle_font_size": 76, "subtitle_color": "#EDAD42",
                 "subtitle_position": "top", "subtitle_outline": 6}
        cues = [{"start": 1.2, "end": 3.25, "text": "Edición de ClifForge."},
                {"start": 8.25, "end": 10.5, "text": "El siguiente paso."}]
        base = f"/jobs/{JOB}/clips/{CLIP}"
        sibling = f"/jobs/{JOB}/clips/clip_02.mp4"
        variant = f"/jobs/{JOB}/exports/{CAPTION}/files/clip"
        self.state.update(status="completed", caption={
            "start": 392.0, "end": 421.5, "duration": 29.5, "cues": cues, "style": style.copy(),
            "revision": 1, "status": "completed",
            "output": {"id": "9" * 64, "mp4": base, "srt": base + "/subtitles/srt",
                       "vtt": base + "/subtitles/vtt", "burn_subtitles": True},
        }, sibling_clip={"file": "clip_02.mp4", "start": 400, "end": 422, "captions": {
            "revision": 1, "status": "completed",
            "output": {"id": "8" * 64, "mp4": sibling, "srt": sibling + "/subtitles/srt",
                       "vtt": sibling + "/subtitles/vtt", "burn_subtitles": True},
        }})
        self.page.goto(ORIGIN + "/?job=" + JOB)
        card = self.page.locator(f'#clip-list [data-clip-file="{CLIP}"]')
        other = self.page.locator('#clip-list [data-clip-file="clip_02.mp4"]')
        action = card.get_by_role("button", name="Corregir texto", exact=True)
        action.click()
        editor = self.page.locator('#clip-caption-editor[data-mode="quick"]')
        first = editor.get_by_role("textbox", name="Subtítulo 1 · 1.200–3.250 s")
        first.wait_for()
        self.assertTrue(first.evaluate("node => node === document.activeElement"))
        self.assertTrue(editor.locator("#clip-caption-advanced").is_hidden())
        self.assertEqual(0, editor.locator("#clip-caption-cues input").count())
        downloads = editor.locator("#clip-caption-downloads")
        self.assertEqual(base, downloads.get_by_role("link", name="Descargar MP4").get_attribute("href"))
        first.fill("Borrador sin guardar.")
        self.assertTrue(downloads.is_hidden())
        submit_quick_caption_correction(self.page, editor, 0, "Edición de ClipForge.", ORIGIN + base + "/captions")
        self.until_text("#clip-caption-status", "Corrección guardada")
        self.assertTrue(downloads.is_hidden())

        expected = [{**cues[0], "text": "Edición de ClipForge."}, cues[1]]
        self.assertEqual([{"style": style, "revision": 1, "cues": expected}], self.state["caption_updates"])
        self.assertEqual(([], [], []), (self.state["reservations"], self.state["starts"], self.state["selection_posts"]))
        self.state["caption"].update(status="completed", output={
            "id": CAPTION, "mp4": variant + ".mp4", "srt": variant + ".srt",
            "vtt": variant + ".vtt", "burn_subtitles": True,
        })
        self.until_text("#clip-caption-status", "Versión lista para descargar")
        for name, suffix in (("MP4", "mp4"), ("SRT", "srt"), ("WebVTT", "vtt")):
            self.assertEqual(variant + "." + suffix,
                             downloads.get_by_role("link", name="Descargar " + name).get_attribute("href"))
        self.assertEqual(sibling + "/subtitles/srt",
                         other.get_by_role("link", name="Descargar SRT").get_attribute("href"))

        self.page.reload()
        action.click()
        self.assertEqual(expected[0]["text"], first.input_value())
        self.assertEqual(expected[1]["text"], editor.get_by_role("textbox", name="Subtítulo 2 · 8.250–10.500 s").input_value())
        self.assertEqual(variant + ".mp4", downloads.get_by_role("link", name="Descargar MP4").get_attribute("href"))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_project_deletion_withdraws_only_confirmed_project_and_survives_reload(self):
        self.state.update(status="completed", other_project=True)
        self.page.goto(ORIGIN + "/?job=" + JOB)
        other_tab = self.context.new_page()
        other_tab.goto(ORIGIN + "/?job=" + JOB)
        other_tab.locator("#delete-project").wait_for()
        delete = self.page.locator("#delete-project")
        delete.click()
        dialog = self.page.locator("#project-delete-dialog")
        dialog.wait_for()
        self.until_text("#project-delete-title", "Video de prueba")
        self.until_text("#project-delete-scope", "la transcripción")
        self.page.locator("#project-delete-cancel").click()
        self.assertEqual([], self.state["deletions"])

        self.state["deletion_failed"] = True
        delete.click()
        self.page.locator("#project-delete-confirm").click()
        self.until_text("#project-delete-error", "No se pudo eliminar el proyecto.")
        self.assertTrue(dialog.is_visible())
        self.assertEqual(2, self.page.locator("#project-list a").count())
        self.assertEqual(1, self.page.locator("#clip-list article").count())

        self.state["deletion_failed"] = False
        self.page.locator("#project-delete-confirm").click()
        self.page.get_by_text("Proyecto eliminado de tu cuenta", exact=True).wait_for()
        self.assertEqual("Proyecto eliminado de tu cuenta", self.page.locator("#job-status").inner_text())
        self.assertTrue(dialog.is_hidden())
        self.assertTrue(self.page.locator("#editorial").is_hidden())
        self.assertEqual(0, self.page.locator("#clip-list article").count())
        self.assertEqual(["/?job=" + OTHER_JOB], self.page.locator("#project-list a").evaluate_all(
            "links => links.map(link => link.getAttribute('href'))"))
        self.assertFalse(urlsplit(self.page.url).query)
        other_tab.get_by_text("Proyecto eliminado de tu cuenta", exact=True).wait_for(timeout=12_000)
        self.assertTrue(other_tab.locator("#editorial").is_hidden())
        self.assertEqual(0, other_tab.locator("#clip-list article").count())
        self.assertTrue(other_tab.get_by_role("link", name="Otro video").is_visible())

        self.page.reload()
        self.page.get_by_role("link", name="Otro video").wait_for()
        self.assertEqual(1, self.page.locator("#project-list a").count())
        for job, status in ((JOB, 404), (OTHER_JOB, 200)):
            self.assertEqual(status, self.page.evaluate("async path => (await fetch(path)).status", f"/jobs/{job}"))
        self.assertEqual([f"/jobs/{JOB}/deletion"] * 2, self.state["deletions"])
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

    def test_failed_manual_variant_is_retried_by_identity_after_reload(self):
        self.state["status"] = "completed"
        self.state["manual"] = {"id": EXPORT, "clip_file": "manual.mp4", "status": "failed",
                                "retryable": True, "start": 392, "end": 421.5}
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.reload()
        self.page.get_by_text("Elegir fragmento del original").click()
        self.page.get_by_role("button", name="Reintentar clip manual").click()
        self.until_text("#mvp-results", "Clip en cola")
        self.assertEqual([f"/jobs/{JOB}/exports/{EXPORT}/retry"], self.state["manual_retries"])
        self.assertEqual([], self.state["manual_keys"])
        self.state["manual"]["status"] = "completed"
        download = self.page.get_by_role("link", name="Descargar clip manual")
        download.wait_for()
        self.assertEqual(f"/jobs/{JOB}/exports/{EXPORT}/files/clip.mp4", download.get_attribute("href"))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_editorial_consent_replay_and_versioned_subtitles(self):
        self.state["status"] = "completed"
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Propuestas por IA y edición", exact=True).click()
        self.page.locator("#editorial-brief").fill("Busca un consejo concreto.")
        self.page.locator("#editorial-preview-button").click()
        self.page.locator("#editorial-consent").wait_for()
        self.assertTrue(self.page.locator("#editorial-run").is_disabled())
        self.assertEqual([], self.state["selection_posts"])
        self.page.locator("#editorial-consent").check()
        self.page.locator("#editorial-run").click()
        self.until_text("#editorial-status", "Respuesta interrumpida")
        self.page.locator("#editorial-run").click()
        self.until_text("#editorial-candidates", "Explica un paso concreto.")
        first, replay = self.state["selection_posts"]
        self.assertEqual(first, replay)
        self.assertTrue(first["consent"])
        self.assertEqual(("llm", 0, None), (first["mode"], first["window_start"], first["window_end"]))
        self.page.get_by_role("button", name="Crear / abrir borrador").click()
        self.page.locator("#editorial-start").fill("393")
        self.page.locator("#editorial-cues textarea").fill("Decisión práctica.\nUna solución.")
        self.page.locator("#editorial-burn").check()
        self.assertEqual("52", self.page.locator("#editorial-size").input_value())
        self.page.locator("#editorial-export").click()
        self.page.locator("#editorial-exports").get_by_role("link", name="Descargar SRT").wait_for()
        saved = self.state["draft"]
        self.assertEqual(393, saved["start"])
        self.assertEqual("Decisión práctica.\nUna solución.", saved["cues"][0]["text"])
        self.assertEqual(392, self.state["range_posts"][-1]["previous_start"])

        self.page.reload()
        self.page.get_by_text("Propuestas por IA y edición", exact=True).click()
        self.page.locator("#editorial-draft-form").wait_for()
        self.assertEqual("Decisión práctica.\nUna solución.", self.page.locator("#editorial-cues textarea").input_value())
        self.page.locator("#editorial-size").fill("96")
        self.page.locator("#editorial-color").fill("#ffca28")
        self.page.locator("#editorial-export").click()
        self.page.wait_for_function("() => document.querySelectorAll('#editorial-exports article').length === 2")
        self.assertEqual({2, 3}, set(self.state["approved"]))
        self.assertEqual((96, "#FFCA28"), (self.state["draft"]["options"]["subtitle_font_size"],
                                         self.state["draft"]["options"]["subtitle_color"]))
        self.assertEqual(2, len(self.state["draft_updates"]))
        self.assertEqual(2, len(self.state["selection_posts"]))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_unconfigured_ai_preserves_manual_subtitle_draft(self):
        self.state.update(status="completed", ai_configured=False)
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Elegir fragmento del original").click()
        self.page.locator("#mvp-start").fill("392")
        self.page.locator("#mvp-end").fill("421")
        self.page.locator("#mvp-edit-draft").click()
        self.until_text("#editorial-config", "IA pendiente de configurar")
        self.assertTrue(self.page.locator("#editorial-preview-button").is_disabled())
        self.assertEqual("392", self.page.locator("#editorial-start").input_value())
        self.page.locator("#editorial-burn").check()
        self.page.locator("#editorial-export").click()
        self.page.get_by_role("link", name="Descargar VTT").wait_for()
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_late_manual_draft_keeps_editor_disabled_until_its_list_loads(self):
        self.state.update(status="completed", ai_configured=False, duration=1200)
        self.page.add_init_script("""(() => {
            const original = window.fetch.bind(window);
            let draftCreated = false;
            let listingHeld = false;
            window.editorialRequests = [];
            window.fetch = async (url, options) => {
                const path = String(url).replace(/^\\/jobs\\/[a-f0-9]{32}/, "");
                const method = options?.method || "GET";
                if (["/editor/range", "/drafts", "/drafts?limit=100", "/exports", "/ai/config",
                     "/selections?limit=50", "/selections/context"].includes(path)) {
                    window.editorialRequests.push(method + " " + path);
                }
                const hold = draftCreated && !listingHeld && path === "/drafts?limit=100";
                if (hold) listingHeld = true;
                const response = await original(url, options);
                if (path === "/drafts" && method === "POST" && response.ok) {
                    draftCreated = true;
                }
                if (hold) {
                    await new Promise(resolve => { window.releaseDraftList = resolve; });
                }
                return response;
            };
        })();""")
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Elegir fragmento del original").click()
        self.page.locator("#mvp-start").fill("1166")
        self.page.locator("#mvp-end").fill("1195")
        self.page.evaluate("() => { window.editorialRequests.length = 0; }")
        self.page.locator("#mvp-edit-draft").click()
        self.page.wait_for_function("() => typeof window.releaseDraftList === 'function'")
        self.page.locator("#editorial-draft-form").wait_for()
        save = self.page.locator("#editorial-save")
        self.assertTrue(save.is_disabled())
        self.assertTrue(self.page.locator("#editorial-export").is_disabled())
        self.assertEqual([], self.state["draft_updates"])
        draft_requests = ["POST /editor/range", "POST /drafts", "GET /drafts?limit=100"]
        self.assertEqual(draft_requests, self.page.evaluate("() => window.editorialRequests"))

        self.page.evaluate("() => window.releaseDraftList()")
        self.page.wait_for_function("() => window.editorialRequests.includes('GET /selections?limit=50')")
        self.assertEqual(draft_requests + ["GET /exports", "GET /ai/config", "GET /selections?limit=50"],
                         self.page.evaluate("() => window.editorialRequests"))
        self.page.locator("#editorial-burn").check()
        self.page.locator("#editorial-color").fill("#ff0000")
        with self.page.expect_response(lambda item: item.url == f"{ORIGIN}/jobs/{JOB}/drafts/{DRAFT}"
                                       and item.request.method == "PUT") as saved:
            save.click()
        result = saved.value.json()
        self.assertEqual(200, saved.value.status)
        self.assertEqual((1166, 1195, 2), (result["start"], result["end"], result["revision"]))
        self.assertEqual("#FF0000", result["options"]["subtitle_color"])
        self.assertEqual(1, len(self.state["draft_updates"]))
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])


if __name__ == "__main__":
    unittest.main()
