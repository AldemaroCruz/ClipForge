"""The creator logo library and edit snapshots on disposable PostgreSQL."""
from hashlib import sha256
from io import BytesIO
import os
import re
import secrets
import unittest
from unittest.mock import Mock, patch

from fastapi import HTTPException
from fastapi.testclient import TestClient
from PIL import Image
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth_db, int_beta, int_beta_proxy as proxy
from app.cloud import caption_styles, clip_captions, creator_logos, migrate_beta, pilot, repository, router
from app.cloud import storage
from app.presentation import Presentation
from auth_support import auth_environment, fixture_user, http_login, prepare_database


def sample_png(size=(24, 12), color=(220, 5, 100, 90), *, animated=False):
    output = BytesIO()
    with Image.new("RGBA", size, color) as image, Image.new("RGBA", size, (0, 0, 0, 0)) as second:
        image.save(output, format="PNG", save_all=animated, append_images=[second] if animated else [])
    return output.getvalue()


class PngValidationTests(unittest.TestCase):
    def test_static_png_normalizes_transparency_and_rejects_corrupt_or_animated(self):
        source, width, height = creator_logos.canonical_png(sample_png())
        self.assertEqual((width, height), (24, 12))
        with Image.open(source) as normalized:
            self.assertEqual(normalized.getpixel((0, 0)), (220, 5, 100, 90))
        for data in (sample_png()[:35], b"GIF89a", sample_png((2049, 1)), sample_png(animated=True)):
            with self.subTest(size=len(data)), self.assertRaises(HTTPException) as invalid:
                creator_logos.canonical_png(data)
            self.assertEqual(invalid.exception.status_code, 422)

    def test_fingerprint_preserves_legacy_and_covers_logo_revision_placement_and_opacity(self):
        original = {"generation": "1", "bytes": 5, "sha256": "a" * 64}
        options = Presentation().model_dump()
        logo = {"id": "1" * 32, "revision": 1}
        bare = clip_captions.render_fingerprint(original, 0, 10, options, [])
        self.assertEqual(bare, clip_captions.render_fingerprint(original, 0, 10, options, [], None))
        values = [bare]
        for adjustment in ({}, {"revision": 2}, {"size": 24}, {"opacity": 15}, {"margin": 9},
                           {"position": "bottom-left"}):
            values.append(clip_captions.render_fingerprint(original, 0, 10, options, [], {**logo, **adjustment}))
        self.assertEqual(len(set(values)), len(values))


class CreatorLogoDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.schema = "auth01_test_creator_logos_" + secrets.token_hex(8)
        environment = patch.dict(os.environ, {
            **auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": self.schema, "CLIPFORGE_INT_BETA": "1",
            "CLIPFORGE_STORAGE_BACKEND": "", "CLIPFORGE_AUTH_COOKIE_NAMESPACE": "",
        })
        environment.start()
        self.addCleanup(environment.stop)
        auth_db.reset_engine()
        self.addCleanup(auth_db.reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["logos_status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["logos_status"], "current")
        self.owner = fixture_user("logos-owner")
        other = fixture_user("logos-neighbor")
        os.environ.update(CLIPFORGE_AUTH_PROFILE="https", CLIPFORGE_AUTH_ORIGIN=proxy.PUBLIC_ORIGIN)
        self.client = self.login(self.owner)
        self.other = self.login(other)
        self.anonymous = self.login()
        self.objects = {}
        for name, replacement in (("upload", self.upload), ("open_object", self.open_object)):
            substitute = patch.object(storage, name, side_effect=replacement)
            substitute.start()
            self.addCleanup(substitute.stop)
        self.dispatch = patch.object(router, "reconcile", return_value={"status": "fixture"})
        self.dispatch.start()
        self.addCleanup(self.dispatch.stop)

    def remove_schema(self):
        if not re.fullmatch(r"auth01_test_creator_logos_[0-9a-f]{16}", self.schema):
            raise ValueError("Refusing to remove an unowned schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def login(self, account=None):
        client = TestClient(int_beta.app, base_url=proxy.PUBLIC_ORIGIN,
                            headers={proxy.PROXY_ORIGIN_HEADER: proxy.PUBLIC_ORIGIN})
        self.addCleanup(client.close)
        if account:
            auth = http_login(client, account["username"], account["password"], proxy.PUBLIC_ORIGIN)
            client.headers.update({"Origin": proxy.PUBLIC_ORIGIN, "X-CSRF-Token": auth})
        return client

    def upload(self, name, source, kind, *, reuse_identical):
        source.seek(0)
        data = source.read()
        self.assertTrue(reuse_identical)
        self.assertTrue(name.startswith(f"workspaces/{self.owner['principal'].workspace_id}/creator-logos/"))
        self.objects[name] = data
        return {"name": name, "generation": str(len(self.objects)), "bytes": len(data),
                "sha256": sha256(data).hexdigest(), "content_type": kind}

    def open_object(self, item):
        response = Mock(_clipforge_session=Mock())
        response.iter_content.return_value = [self.objects[item["name"]]]
        return response

    def create_logo(self):
        response = self.client.post("/creator-logos?name=Marca", content=sample_png(),
                                    headers={"Content-Type": "image/png"})
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    def style(self, logo):
        return {"name": "Logo azul", "font": caption_styles.FONT, "style": {"subtitle_color": "#2233FF"},
                "logo": {"id": logo["id"], "revision": logo["revision"], "opacity": 52}}

    def task_count(self):
        with self.engine.connect() as connection:
            return connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one()

    def complete_job(self, request_id):
        job = pilot._reserve(self.owner["principal"], request_id, "synthetic.mp4", 1024)
        cues = [{"start": 0, "end": 1, "text": "Prueba"}]
        item = {"file": "clip_01.mp4", "start": 5, "end": 30, "options": job["options"],
                "cues": cues, "caption_rendered": True}
        manifest = {"input.mp4": {"generation": "7", "bytes": 10000, "md5": "f" * 32},
                    "clip_01.mp4": {"generation": "9"}}
        job.update(status="completed", media={"duration_seconds": 120}, clips=[item])
        with self.engine.begin() as connection:
            repository.update_document(connection, job["id"], "job", job, manifest=manifest)
        return job

    def test_private_library_replaces_and_retires_without_erasing_previous_png(self):
        first = self.create_logo()
        old = self.client.get(first["url"])
        self.assertEqual((old.status_code, old.headers["content-type"]), (200, "image/png"))
        self.assertEqual(self.anonymous.get(first["url"]).status_code, 401)
        self.assertEqual(self.other.get(first["url"]).status_code, 404)
        self.assertEqual(self.other.get("/creator-logos").json()["logos"], [])
        self.assertEqual(self.other.post("/caption-styles", json=self.style(first)).status_code, 404)
        with patch.object(creator_logos, "MAX_BYTES", 15):
            response = self.client.post("/creator-logos?name=Grande", content=sample_png(),
                                        headers={"Content-Type": "image/png"})
            self.assertEqual(response.status_code, 413)
        old_ref = self.style(first)["logo"]
        project = self.complete_job("logos-fixture")
        self.assertEqual(creator_logos.storage_item_for_job(project["id"], old_ref)["sha256"],
                         sha256(old.content).hexdigest())
        path = f"/creator-logos/{first['id']}"
        next_image = sample_png(color=(0, 140, 200, 130))
        response = self.client.put(path + "?name=Marca&revision=1", content=next_image,
                                   headers={"Content-Type": "image/png"})
        self.assertEqual(response.status_code, 200, response.text)
        second = response.json()
        self.assertEqual(second["revision"], 2)
        self.assertNotEqual(self.client.get(second["url"]).content, old.content)
        self.assertEqual(self.client.get(first["url"]).content, old.content)
        self.assertEqual(self.client.delete(path + "?revision=1").status_code, 409)
        self.assertEqual(self.other.delete(path + "?revision=2").status_code, 404)
        self.assertEqual(self.client.delete(path + "?revision=2").status_code, 200)
        self.assertEqual(self.client.delete(path + "?revision=2").status_code, 200)
        self.assertEqual(self.client.get("/creator-logos").json()["logos"], [])
        self.assertEqual(self.client.get(first["url"]).content, old.content)
        self.assertEqual(self.client.post("/caption-styles", json=self.style(second)).status_code, 409)
        self.assertEqual(self.task_count(), 0)

    def test_template_and_draft_freeze_the_exact_logo_and_queue_only_on_export(self):
        logo = self.create_logo()
        response = self.client.post("/caption-styles", json=self.style(logo))
        self.assertEqual(response.status_code, 201, response.text)
        style = response.json()
        job = self.complete_job("logos-clip")
        root = f"/jobs/{job['id']}"
        style_ref = {"id": style["id"], "revision": style["revision"]}
        original = job["clips"][0]
        captions = self.client.put(root + "/clips/clip_01.mp4/captions", json={
            "revision": 1, "style": {}, "cues": original["cues"], "render": False, "style_template": style_ref,
        })
        self.assertEqual(captions.status_code, 202, captions.text)
        self.assertEqual(captions.json()["logo"], style["logo"])
        self.assertIsNone(captions.json()["output"])
        draft = self.client.post(root + "/drafts", json={
            "title": "Recorte", "start": 7, "end": 29, "options": original["options"], "cues": original["cues"],
            "style_template": style_ref,
        }, headers={"Idempotency-Key": "logos-specific-draft"})
        self.assertEqual(draft.status_code, 201, draft.text)
        path = f"{root}/drafts/{draft.json()['id']}"
        self.assertEqual(draft.json()["logo"], style["logo"])
        self.assertEqual(self.task_count(), 0)
        self.assertEqual(self.client.delete(f"/creator-logos/{logo['id']}?revision=1").status_code, 200)
        future_template = self.client.get(f"/caption-styles/{style['id']}").json()
        self.assertEqual((future_template["logo"], future_template["revision"]), (None, 2))
        self.assertEqual(self.client.delete(f"/caption-styles/{style['id']}?revision=2").status_code, 200)
        self.assertEqual(self.client.get(path).json()["logo"], style["logo"])
        render = self.client.post(path + "/exports", json={"revision": 1})
        self.assertEqual(render.status_code, 202, render.text)
        self.assertEqual(render.json()["logo"], style["logo"])
        self.assertEqual(render.json()["cues"], original["cues"])
        self.assertEqual((render.json()["start"], render.json()["end"]), (7, 29))
        repeat = self.client.post(path + "/exports", json={"revision": 1})
        self.assertEqual(repeat.json()["id"], render.json()["id"])
        self.assertEqual(self.task_count(), 1)
