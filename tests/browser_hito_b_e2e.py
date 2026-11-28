"""Chromium regression for the INT beta frontend with local synthetic responses."""
import base64
import json
import os
from pathlib import Path
import secrets
import unittest
from urllib.parse import parse_qs, urlsplit

from playwright.sync_api import expect, sync_playwright

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
STYLE = "9" * 32
FONT = "DejaVu Sans Bold"
CHUNK = 8 * 1024 * 1024
MAX_SIZE = 2 * CHUNK
CSP = "default-src 'self'; connect-src 'self' https://storage.googleapis.com; media-src 'self'"

# Three generated 128×72 frames at 5 fps, six RGB bands (red through cyan) encoded with
# FFmpeg VP8. Inline fixture keeps real Chromium decoding independent of host encoders.
FRAMING_WEBM = base64.b64decode(
    "GkXfo59ChoEBQveBAULygQRC84EIQoKEd2VibUKHgQJChYECGFOAZwH/////////EU2bdKtNu4tT"
    "q4QVSalmU6yBoU27i1OrhBZUrmtTrIHLTbuMU6uEElTDZ1OsggEc7AEAAAAAAABoAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAVSalmpSrXsYMPQkBNgIxMYXZm"
    "NjEuMS4xMDBXQYxMYXZmNjEuMS4xMDAWVK5rzK4BAAAAAAAAQ9eBAXPFiPp5vdwdWdGonIEAIrWc"
    "g3VuZIiBAIaFVl9WUDiDgQEj44OEC+vCAOCUsIGAuoFImoECVbCIVbeBAlW4gQISVMNn1nNzn2PA"
    "gGfImUWjh0VOQ09ERVJEh4xMYXZmNjEuMS4xMDBzc7FjwItjxYj6eb3cHVnRqGfIoEWjh0VOQ09E"
    "RVJEh5NMYXZjNjEuMy4xMDAgbGlidnB4H0O2dUHe54EAo0GJgQAAgPAOAJ0BKoAASAAARwiFhYiF"
    "hIgCAgKUxt/4D+DnLMYF4D+Bn6q8wzoL2c/UDEBfgP4A+yX+A/gD14H0A6kB/Af4D0gPAA/wH+Ie"
    "hP/DOoBdYD+AJTbxe4BhnGwemn3zz+sTHOovVkSbh3qhohDZ03tP1aYiAgtDM8T/fYZoxuBxAP79"
    "bs1Rwdt73auK6KMk5SQOr/4bAM0+3Rphd4cPrCjBO90YjhMGYZnzcR5/8f/Mv/9qI/+RYJPWoSlQ"
    "95FY/ENl3ei6e7X8wEydIS8cAy2WXbLAAAVf//fbD6lZhHPUUaRbOeiyGvkNLQiHNxSYXmQHTAbl"
    "+/9Osb/0sSub3KjPt+y9p+7g4b9MD81x2bks3yKpOIQfyNaqbmrzrSgAKz/6jpIpAmMCT9ya/58x"
    "J7/zcf/2+FzWl9Gr2pgYpyc6M/NILPjln0E05ogboEkkm4wPOnWZb518y2FblmG+IsOW6gBKbloF"
    "IgDiAKBJIAxgAAE3SKKnAHGAAAAvoAVEwAAAAAdAo66BAMgAMQIAARAQABgAGggv9AA/LsKpm4AA"
    "2g3XN/G0ABEA4gA4AxgAACbosAAAo52BAZAAEQIAARAQABgAGNAv9AAZQ8p4AAAAwh2QAA=="
)


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
                      "caption": None, "project_caption": None, "caption_updates": [], "deletions": [],
                      "saved_style": None, "framing_source": None, "source_reads": 0,
                      "zip_requests": [], "zip_stale": False}
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
        if path == "/static/caption-font.ttf":
            font = STATIC / "caption-font.ttf"
            if font.is_file():
                route.fulfill(status=200, content_type="font/ttf", body=font.read_bytes())
            else:
                route.fulfill(status=404)
            return
        if path in {f"/jobs/{JOB}/clips/{CLIP}", f"/jobs/{JOB}/source"}:
            if path.endswith("/source"):
                self.state["source_reads"] += 1
                if self.state["framing_source"] is not None:
                    route.fulfill(status=200, content_type="video/webm", body=self.state["framing_source"])
                    return
            route.fulfill(status=404 if self.state["status"] == "deleted" else 503, content_type="video/mp4")
            return
        if path == f"/jobs/{JOB}/clips.zip":
            params = parse_qs(parsed.query)
            self.state["zip_requests"].append(params)
            self.assertEqual(["1"], params.get("inspect"))
            stale = self.state["zip_stale"]
            result = ({"detail": "La edición cambió."} if stale
                      else {"clips": 1, "bytes": 2048, "max_bytes": 128 * 1024**2})
            route.fulfill(status=409 if stale else 200, content_type="application/json", body=json.dumps(result))
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
        if method in {"POST", "PUT", "DELETE"}:
            self.assertEqual(self.csrf, request.headers.get("x-csrf-token"))
        if path == "/environment":
            return {"environment": "INT", "revision": "b" * 40}, 200
        if path == "/auth/me":
            return {"user": {"id": "2" * 32, "username": "fixture", "is_admin": self.state["admin"],
                             "permissions": ["users:manage"] if self.state["admin"] else []},
                    "csrf_token": self.csrf}, 200
        if path == "/caption-styles":
            item = self.state["saved_style"]
            if method == "GET":
                return {"styles": [item] if item else [], "fonts": [{"id": FONT, "label": FONT}]}, 200
            self.assertIsNone(item)
            self.state["saved_style"] = {"id": STYLE, "revision": 1, "is_default": False, **request.post_data_json}
            return self.state["saved_style"], 201
        if path == "/caption-styles/default" and method == "PUT":
            item = self.state["saved_style"]
            update = request.post_data_json
            if update["id"] is not None:
                self.assertEqual({"id": item["id"], "revision": item["revision"]}, update)
            item["is_default"] = update["id"] is not None
            return {"default": item["id"] if item["is_default"] else None}, 200
        if path == f"/caption-styles/{STYLE}":
            item = self.state["saved_style"]
            if method == "PUT":
                update = request.post_data_json
                self.assertEqual(item["revision"], update["revision"])
                item.update({**update, "revision": item["revision"] + 1})
                return item, 200
            if method == "DELETE":
                self.assertEqual(f"revision={item['revision']}", urlsplit(request.url).query)
                self.state["saved_style"] = None
                return {"deleted": True}, 200
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
                               status="queued" if update.get("render", True) else "draft", output=None)
                self.apply_mock_style(caption, update, "style")
                return caption, 202
            return caption, 200
        if path == f"/jobs/{JOB}/captions" and method == "PUT" and self.state["project_caption"]:
            update = request.post_data_json
            self.assertTrue(update["apply_to_all"])
            self.assertNotIn("cues", update)
            self.state["caption_updates"].append(update)
            self.assertEqual(self.state["project_caption"]["revision"], update["revision"])
            state = {"style": update["style"], "revision": update["revision"] + 1}
            self.apply_mock_style(state, update, "style")
            self.state["project_caption"] = state
            caption = self.state["caption"]
            caption.update({**state, "revision": caption["revision"] + 1})
            if not update.get("render", True):
                caption.update(status="draft", output=None)
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
                self.apply_mock_style(self.state["draft"], updated, "options")
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

    def apply_mock_style(self, destination, update, key):
        if reference := update.get("style_template"):
            item = self.state["saved_style"]
            self.assertEqual({"id": item["id"], "revision": item["revision"]}, reference)
            destination[key] = {**destination[key], **item["style"]}
            destination["style_template"] = {**reference, "font": item["font"]}

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

    def test_zip_preflight_download_and_invalidate_only_selected_revision(self):
        base = f"/jobs/{JOB}/clips/{CLIP}"
        other = "clip_02.mp4"
        self.state.update(status="completed", caption={
            "start": 392, "end": 421.5, "duration": 29.5, "revision": 3, "status": "completed",
            "output": {"id": "f" * 64, "mp4": base, "burn_subtitles": True},
        }, sibling_clip={
            "file": other, "start": 10, "end": 30,
            "captions": {"revision": 1, "status": "completed",
                         "output": {"id": "e" * 64, "mp4": f"/jobs/{JOB}/clips/{other}", "burn_subtitles": True}},
        })
        self.page.goto(ORIGIN + "/?job=" + JOB)
        button = self.page.locator("#clip-zip-download")
        expect(button).to_be_disabled()
        self.page.get_by_role("checkbox", name="Incluir Clip 1 en ZIP", exact=True).check()
        expected = {"selection": [f"{CLIP}:3:" + "f" * 64]}
        self.state["zip_stale"] = True
        button.click()
        self.until_text("#clip-zip-status", "La edición cambió.")
        self.assertEqual([{**expected, "inspect": ["1"]}], self.state["zip_requests"])
        self.state["zip_stale"] = False
        self.page.evaluate("""() => {
            document.addEventListener('click', event => {
                if (event.target instanceof HTMLAnchorElement && event.target.download) {
                    event.preventDefault();
                    window.zipLink = {href: event.target.href, name: event.target.download};
                }
            }, {capture: true});
        }""")
        button.click()
        self.until_text("#clip-zip-status", "Descarga iniciada para 1 clip.")
        link = self.page.evaluate("window.zipLink")
        self.assertEqual("clipforge-clips.zip", link["name"])
        parsed = urlsplit(link["href"])
        self.assertEqual((f"/jobs/{JOB}/clips.zip", expected), (parsed.path, parse_qs(parsed.query)))
        self.assertEqual([expected | {"inspect": ["1"]}, expected | {"inspect": ["1"]}], self.state["zip_requests"])
        self.state["caption"]["revision"] = 4
        self.page.locator("#refresh-projects").click()
        self.until_text("#clip-zip-status", "Un clip cambió de versión")
        expect(button).to_be_disabled()
        expect(self.page.get_by_role("checkbox", name="Incluir Clip 2 en ZIP", exact=True)).not_to_be_checked()
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_caption_preview_tracks_cue_and_export_style_at_both_widths(self):
        style = {"burn_subtitles": True, "subtitle_font_size": 52, "subtitle_color": "#FFFFFF",
                 "subtitle_position": "bottom", "subtitle_outline": 3}
        cues = [{"start": 1.2, "end": 3.25, "text": "Primera frase."},
                {"start": 8.25, "end": 10.5, "text": "Frase posterior."}]
        self.state.update(status="completed", caption={
            "start": 392.0, "end": 421.5, "duration": 29.5, "cues": cues, "style": style,
            "revision": 1, "status": "completed", "output": None,
        })
        self.page.set_viewport_size({"width": 1280, "height": 800})
        self.page.goto(ORIGIN + "/?job=" + JOB)
        open_editor = self.page.get_by_role("button", name="Editar subtítulos", exact=True)
        open_editor.click()
        editor = self.page.locator("#clip-caption-form")
        fields = editor.get_by_role("textbox", name="Texto del subtítulo", exact=True)
        first, later = fields.nth(0), fields.nth(1)
        preview = editor.get_by_role("region", name="Vista previa del subtítulo")
        expect(preview.get_by_role("heading", name="Vista previa del subtítulo")).to_be_visible()
        frame = preview.locator(".caption-frame")
        sample = frame.locator("span")
        expect(sample).to_have_text(cues[0]["text"])
        self.assertEqual(0, preview.get_by_role("textbox").count())

        field_style = """node => {
            const style = getComputedStyle(node);
            return [style.font, style.backgroundColor, style.border, style.padding, style.minHeight];
        }"""
        first.fill("Primera frase editada.")
        expect(sample).to_have_text("Primera frase editada.")
        first_style = first.evaluate(field_style)
        expect(first).to_have_css("outline-width", "2px")
        later.fill("Frase posterior editada.")
        expect(sample).to_have_text("Frase posterior editada.")
        expect(later).to_have_css("outline-width", "2px")
        self.assertEqual(first_style, later.evaluate(field_style))
        later.evaluate("""node => {
            node.setSelectionRange(0, 5);
            node.dispatchEvent(new Event('input', {bubbles: true}));
        }""")
        self.assertEqual([0, 5], later.evaluate("node => [node.selectionStart, node.selectionEnd]"))

        editor.get_by_role("button", name="Añadir subtítulo").click()
        added = fields.nth(2)
        expect(added).to_be_focused()
        expect(added).to_have_css("outline-width", "2px")
        self.assertEqual(first_style, added.evaluate(field_style))
        added.fill("Segmento nuevo.")
        expect(sample).to_have_text("Segmento nuevo.")
        editor.get_by_role("button", name="Quitar subtítulo").nth(2).click()
        expect(fields).to_have_count(2)
        expect(sample).not_to_have_text("Segmento nuevo.")
        later.focus()
        expect(sample).to_have_text("Frase posterior editada.")

        geometry = """node => {
            const {width, height, y, left, right} = node.getBoundingClientRect();
            const text = node.querySelector('span');
            const style = getComputedStyle(text);
            return {width, height, y, left, right, scrollWidth: node.scrollWidth,
                    textY: text.getBoundingClientRect().y, size: parseFloat(style.fontSize),
                    stroke: parseFloat(style.webkitTextStrokeWidth)};
        }"""
        original = frame.evaluate(geometry)
        editor.get_by_label("Tamaño del texto").fill("76")
        editor.get_by_label("Color del texto").fill("#edad42")
        editor.get_by_label("Posición").select_option("top")
        editor.get_by_label("Grosor del contorno").fill("6")
        expect(sample).to_have_text("Frase posterior editada.")
        expect(sample).to_have_css("color", "rgb(237, 173, 66)")
        desktop = frame.evaluate(geometry)
        self.assertLess(desktop["textY"] - desktop["y"], original["textY"] - original["y"])
        self.assertAlmostEqual(desktop["size"] / original["size"], 76 / 52, delta=0.02)
        self.assertAlmostEqual(desktop["stroke"] / original["stroke"], 2, delta=0.05)

        self.page.set_viewport_size({"width": 320, "height": 720})
        narrow = frame.evaluate(geometry)
        for bounds, window in ((desktop, 1280), (narrow, 320)):
            self.assertAlmostEqual(bounds["width"] / bounds["height"], 9 / 16, delta=0.01)
            self.assertGreaterEqual(bounds["left"], 0)
            self.assertLessEqual(bounds["right"], window)
            self.assertLessEqual(bounds["scrollWidth"], bounds["width"] + 1)
        self.assertAlmostEqual(desktop["size"] / desktop["height"], narrow["size"] / narrow["height"], places=4)
        self.assertAlmostEqual(desktop["stroke"] / desktop["height"], narrow["stroke"] / narrow["height"], places=4)
        # A narrow editor can still reach the preview's desktop maximum width.
        frame.evaluate("node => node.style.maxWidth = '90px'")
        small_frame = frame.evaluate(geometry)
        frame.evaluate("node => node.style.removeProperty('max-width')")
        self.assertLess(small_frame["height"], narrow["height"])
        self.assertAlmostEqual(desktop["size"] / desktop["height"], small_frame["size"] / small_frame["height"], places=4)
        self.assertAlmostEqual(desktop["stroke"] / desktop["height"],
                               small_frame["stroke"] / small_frame["height"], places=4)

        editor.get_by_label("Incrustar subtítulos en el MP4").uncheck()
        expect(preview).to_be_hidden()
        editor.get_by_label("Incrustar subtítulos en el MP4").check()
        expect(sample).to_have_text("Frase posterior editada.")
        editor.get_by_role("button", name="Guardar y generar clip").click()
        self.until_text("#clip-caption-status", "Subtítulos guardados")
        expect(sample).to_have_text("Frase posterior editada.")
        saved = self.state["caption_updates"][-1]
        self.assertEqual([(1.2, 3.25, "Primera frase editada."), (8.25, 10.5, "Frase posterior editada.")],
                         [(cue["start"], cue["end"], cue["text"]) for cue in saved["cues"]])
        self.assertEqual({"burn_subtitles": True, "subtitle_font_size": 76, "subtitle_color": "#EDAD42",
                          "subtitle_position": "top", "subtitle_outline": 6}, saved["style"])

        self.page.reload()
        open_editor.click()
        expect(first).to_have_value("Primera frase editada.")
        expect(later).to_have_value("Frase posterior editada.")
        self.assertEqual(["1.2", "8.25"], editor.get_by_label("Inicio desde el recorte (s)").evaluate_all(
            "fields => fields.map(field => field.value)"))
        self.assertEqual(["3.25", "10.5"], editor.get_by_label("Fin desde el recorte (s)").evaluate_all(
            "fields => fields.map(field => field.value)"))
        self.assertEqual("76", editor.get_by_label("Tamaño del texto").input_value())
        self.assertEqual("#edad42", editor.get_by_label("Color del texto").input_value())
        self.assertEqual("top", editor.get_by_label("Posición").input_value())
        self.assertEqual("6", editor.get_by_label("Grosor del contorno").input_value())
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_saved_caption_style_manages_presets_and_applies_without_rendering(self):
        cues = self.cue_fixture()
        style = {"burn_subtitles": True, "subtitle_font_size": 52, "subtitle_color": "#FFFFFF",
                 "subtitle_position": "bottom", "subtitle_outline": 3}
        self.state.update(status="completed", project_caption={"style": style.copy(), "revision": 1},
                          sibling_clip={"file": "clip_02.mp4", "start": 401, "end": 426}, caption={
                              "start": 392, "end": 421.5, "duration": 29.5, "cues": cues,
                              "style": style.copy(), "revision": 1, "status": "completed", "output": None,
                          })
        self.page.set_viewport_size({"width": 390, "height": 844})
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.locator(f'[data-clip-file="{CLIP}"]').get_by_role("button", name="Editar subtítulos").click()
        panel = self.page.locator("#clip-caption-styles")
        panel.locator("summary").click()
        select = panel.get_by_label("Estilo guardado")
        expect(select).to_be_enabled()
        name = panel.get_by_label("Nombre del estilo")
        expect(panel.get_by_label("Fuente")).to_have_value(FONT)
        self.page.locator("#clip-caption-size").fill("76")
        self.page.locator("#clip-caption-color").fill("#b8273d")
        self.page.locator("#clip-caption-position").select_option("top")
        name.fill("Estilo del portal")
        name.press("Enter")
        panel.get_by_role("button", name="Guardar como estilo nuevo").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo guardado.")
        expect(select).to_have_value(STYLE)
        self.assertEqual([], self.state["caption_updates"])
        panel.get_by_role("button", name="Usar en trabajos nuevos").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo predeterminado para trabajos nuevos.")
        self.assertTrue(self.state["saved_style"]["is_default"])
        expect(select.locator("option:checked")).to_have_text("Estilo del portal · predeterminado")

        self.page.locator("#clip-caption-size").fill("61")
        text = self.page.locator("#clip-caption-cues textarea")
        text.fill("Edición todavía sin guardar.")
        self.page.locator('#clip-caption-cues [data-field="start"]').fill("1.25")
        panel.get_by_role("button", name="Aplicar estilo", exact=True).click()
        expect(panel.get_by_role("status")).to_have_text("Estilo aplicado.")
        expect(text).to_have_value("Edición todavía sin guardar.")
        expect(self.page.locator('#clip-caption-cues [data-field="start"]')).to_have_value("1.25")
        expect(self.page.locator("#clip-caption-sample .caption-frame span")).to_have_text("Edición todavía sin guardar.")
        expect(self.page.locator("#clip-caption-size")).to_have_value("76")
        saved = self.state["caption"]
        self.assertEqual(cues, saved["cues"])
        self.assertEqual("draft", saved["status"])
        self.assertFalse(self.state["caption_updates"][-1]["render"])
        self.assertEqual({"id": STYLE, "revision": 1, "font": FONT}, saved["style_template"])

        scope = []

        def confirm_all(dialog):
            scope.append(dialog.message)
            dialog.accept()

        self.page.once("dialog", confirm_all)
        panel.get_by_role("button", name="Aplicar estilo a todos").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo aplicado.")
        self.assertIn("los 2 clips de este proyecto", scope[0])
        self.assertIn("reemplazará", scope[0])
        self.assertNotIn("cues", self.state["caption_updates"][-1])
        self.assertFalse(self.state["caption_updates"][-1]["render"])
        expect(text).to_have_value("Edición todavía sin guardar.")

        name.fill("Estilo renombrado")
        self.page.locator("#clip-caption-size").fill("89")
        panel.get_by_role("button", name="Renombrar estilo").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo actualizado.")
        self.assertEqual(76, self.state["saved_style"]["style"]["subtitle_font_size"])
        panel.get_by_role("button", name="Actualizar con los ajustes del editor").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo actualizado.")
        self.assertEqual(89, self.state["saved_style"]["style"]["subtitle_font_size"])
        self.assertEqual(76, self.state["caption"]["style"]["subtitle_font_size"])
        self.assertEqual(1, self.state["caption"]["style_template"]["revision"])
        self.page.once("dialog", lambda dialog: dialog.accept())
        panel.get_by_role("button", name="Eliminar estilo").click()
        expect(panel.get_by_role("status")).to_have_text("Estilo eliminado.")
        self.assertIsNone(self.state["saved_style"])
        self.assertEqual(2, len(self.state["caption_updates"]))
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_saved_style_applies_to_editorial_draft_without_changing_pending_content(self):
        cues = self.cue_fixture()
        self.state.update(status="completed", saved_style={"id": STYLE, "name": "Estilo del portal",
                          "revision": 1, "font": FONT, "is_default": False, "style": {
                              "subtitle_font_size": 76, "subtitle_color": "#BA2988",
                              "subtitle_position": "top", "subtitle_outline": 6,
                          }})
        self.store_draft(title="Título guardado", start=392, end=421.5, cues=cues,
                         options={"burn_subtitles": True, "subtitle_font_size": 52})
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Propuestas por IA y edición", exact=True).click()
        self.page.locator("#editorial-start").fill("393")
        text = self.page.locator("#editorial-cues textarea")
        text.fill("Edición después de abrir.")
        panel = self.page.locator("#editorial-styles")
        panel.locator("summary").click()
        panel.get_by_label("Estilo guardado").select_option(STYLE)
        panel.get_by_role("button", name="Aplicar estilo", exact=True).click()
        expect(panel.get_by_role("status")).to_have_text("Estilo aplicado.")
        expect(text).to_have_value("Edición después de abrir.")
        expect(self.page.locator("#editorial-start")).to_have_value("393")
        expect(self.page.locator("#editorial-sample .caption-frame span")).to_have_text("Edición después de abrir.")
        expect(self.page.locator("#editorial-size")).to_have_value("76")
        saved = self.state["draft"]
        self.assertEqual((392, 421.5, cues), (saved["start"], saved["end"], saved["cues"]))
        self.assertEqual(2, saved["revision"])
        self.assertEqual({"id": STYLE, "revision": 1, "font": FONT}, saved["style_template"])
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual([], self.state["range_posts"])
        self.assertEqual({}, self.state["approved"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def test_manual_framing_previews_a_real_frame_and_versions_a_crop_only_edit(self):
        cues = [{"start": 0, "end": 1, "text": "Texto que se conserva."},
                {"start": 2, "end": 3, "text": "Segmento posterior."}]
        style = {"id": STYLE, "font": FONT, "revision": 1}
        self.state["status"] = "completed"
        self.store_draft(title="Encuadre de prueba", start=0, end=12, cues=cues,
                         style_template=style, options={"burn_subtitles": True, "subtitle_font_size": 76})
        self.state["framing_source"] = FRAMING_WEBM
        self.page.goto(ORIGIN + "/?job=" + JOB)
        self.page.get_by_text("Propuestas por IA y edición", exact=True).click()
        form = self.page.locator("#editorial-draft-form")
        expect(form).to_be_visible()
        self.page.locator("#editorial-cues textarea").nth(1).focus()
        mode = form.get_by_label("Encuadre de la exportación")
        mode.select_option("crop")
        for suffix, value in (("x", "0"), ("y", "0"), ("zoom", "2.2")):
            self.set_framing_value(suffix, value)
        result = self.page.locator("#editorial-framing-result")
        expect(result).to_be_hidden()
        self.assertEqual(0, self.state["source_reads"])
        form.get_by_role("button", name="Ver encuadre en un fotograma").click()
        expect(result).to_have_attribute("data-mode", "crop")
        expect(result).to_have_attribute("data-time", "0.000")
        box = result.locator("#editorial-framing-box")
        self.assertEqual(["0", "0", "18", "32"], [box.get_attribute("data-" + name)
                         for name in ("x", "y", "width", "height")])
        frame = result.locator("#editorial-framing-canvas")
        pixel = "canvas => Array.from(canvas.getContext('2d').getImageData(135,240,1,1).data)"
        r, g, b, _ = frame.evaluate(pixel)
        self.assertTrue(r > 224 and g < 40 and b < 40)
        reads = self.state["source_reads"]
        self.assertGreater(reads, 0)
        self.set_framing_value("x", "100")
        self.set_framing_value("y", "100")
        self.assertEqual(["110", "40"], [box.get_attribute("data-x"), box.get_attribute("data-y")])
        r, g, b, _ = frame.evaluate(pixel)
        self.assertTrue(r < 40 and g > 224 and b > 224)
        mode.select_option("blur")
        expect(result).to_have_attribute("data-mode", "blur")
        expect(box).to_be_hidden()
        mode.select_option("contain")
        expect(result).to_have_attribute("data-mode", "contain")
        self.assertEqual([0, 0, 0], frame.evaluate(
            "canvas => Array.from(canvas.getContext('2d').getImageData(135,1,1,1).data).slice(0,3)"))
        mode.select_option("crop")
        self.assertEqual(reads, self.state["source_reads"])
        self.page.set_viewport_size({"width": 390, "height": 844})
        layout = frame.bounding_box()
        self.assertAlmostEqual(9 / 16, layout["width"] / layout["height"], places=2)

        self.page.locator("#editorial-save").click()
        self.until_text("#editorial-draft-status", "Borrador guardado")
        saved = self.state["draft"]
        self.assertEqual(2, saved["revision"])
        self.assertEqual((0, 12, cues, style), (saved["start"], saved["end"], saved["cues"], saved["style_template"]))
        self.assertEqual(("crop", 1, 1, 2.2), tuple(saved["options"][name]
                         for name in ("framing", "crop_x", "crop_y", "crop_zoom")))
        expect(self.page.locator("#editorial-sample .caption-frame span")).to_have_text("Segmento posterior.")
        self.assertEqual([], self.state["range_posts"])
        self.assertEqual([], self.state["selection_posts"])
        self.assertEqual({}, self.state["approved"])

        self.page.reload()
        self.page.get_by_text("Propuestas por IA y edición", exact=True).click()
        expect(mode).to_have_value("crop")
        expect(self.page.locator("#editorial-crop-zoom")).to_have_value("2.2")
        expect(result).to_be_hidden()
        self.assertEqual(reads, self.state["source_reads"])
        self.assertEqual([], self.errors)
        self.assertEqual([], self.state["unexpected"])

    def set_framing_value(self, control, value):
        self.page.locator("#editorial-crop-" + control).evaluate("""(field, value) => {
            field.value = value;
            field.dispatchEvent(new Event('input', {bubbles: true}));
        }""", value)

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
        sample = editor.get_by_role("region", name="Vista previa del subtítulo").locator(".caption-frame span")
        expect(sample).to_have_text(cues[0]["text"])
        later = editor.get_by_role("textbox", name="Subtítulo 2 · 8.250–10.500 s")
        later.focus()
        expect(sample).to_have_text(cues[1]["text"])
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
        form = self.page.locator("#editorial-draft-form")
        sample = form.get_by_role("region", name="Vista previa del subtítulo").locator(".caption-frame span")
        expect(sample).to_have_text(self.cue_fixture()[0]["text"])
        form.get_by_role("textbox", name="Texto del subtítulo", exact=True).fill("Desde el borrador manual.")
        expect(sample).to_have_text("Desde el borrador manual.")
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
