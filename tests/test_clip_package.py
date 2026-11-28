"""The INT ZIP route assembles exact selected media without creating tasks."""
from hashlib import sha256
from io import BytesIO
import json
import os
import re
import secrets
import unittest
from unittest.mock import Mock, patch
from zipfile import BadZipFile, ZIP_STORED, ZipFile

from fastapi.testclient import TestClient
from requests.structures import CaseInsensitiveDict
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth_db, int_beta, int_beta_proxy as proxy
from app.cloud import clip_captions, clip_package, migrate_beta, pilot, project_deletion, repository
from app.cloud import storage
from app.presentation import Presentation
from auth_support import auth_environment, fixture_user, http_login, prepare_database

FIRST = "clip_01.mp4"
SECOND = "clip_02.mp4"
UNSELECTED = "clip_03.mp4"


def object_item(name, kind, body):
    return {"name": name, "bytes": len(body), "sha256": sha256(body).hexdigest(), "generation": "11",
            "content_type": clip_package.CONTENT_TYPES[kind]}


class ClipPackageDatabaseTests(unittest.TestCase):
    def setUp(self):
        self.schema = "auth01_test_c06_zip_" + secrets.token_hex(8)
        env = patch.dict(os.environ, {
            **auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": self.schema, "CLIPFORGE_INT_BETA": "1",
            "CLIPFORGE_STORAGE_BACKEND": "", "CLIPFORGE_AUTH_COOKIE_NAMESPACE": "",
        })
        env.start()
        self.addCleanup(env.stop)
        auth_db.reset_engine()
        self.addCleanup(auth_db.reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)
        migrate_beta.upgrade_beta(self.engine)
        self.owner = fixture_user("zip-creator")
        self.neighbor = fixture_user("zip-neighbor")
        os.environ.update(CLIPFORGE_AUTH_PROFILE="https", CLIPFORGE_AUTH_ORIGIN=proxy.PUBLIC_ORIGIN)
        self.principal = self.owner["principal"]
        self.variant = secrets.token_hex(16)
        self.job_id = self.complete_job()
        self.path = f"/jobs/{self.job_id}/clips.zip"
        self.headers = {proxy.PROXY_ORIGIN_HEADER: proxy.PUBLIC_ORIGIN}
        self.client = self.login(self.owner)
        self.body = Mock()
        replacement = patch.object(storage, "open_object", side_effect=self.open_object)
        replacement.start()
        self.addCleanup(replacement.stop)

    def remove_schema(self):
        if not re.fullmatch(r"auth01_test_c06_zip_[0-9a-f]{16}", self.schema):
            raise ValueError("Refusing to remove an unowned schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def login(self, account=None):
        client = TestClient(int_beta.app, base_url=proxy.PUBLIC_ORIGIN, headers=self.headers)
        self.addCleanup(client.close)
        if account:
            http_login(client, account["username"], account["password"], proxy.PUBLIC_ORIGIN)
        return client

    def complete_job(self):
        item = pilot._reserve(self.principal, "clip-zip-fixture", "original.mp4", 1024)
        job = item["id"]
        root = f"workspaces/{self.principal.workspace_id}/jobs/{job}/tasks/"
        self.contents = {}

        def media(name, kind, body):
            self.contents[name] = body
            return object_item(name, kind, body)

        manifest = {
            "input.mp4": media(root + "original.mp4", "mp4", b"private original"),
            FIRST: media(root + FIRST, "mp4", b"base mp4"),
            "clip_01.srt": media(root + "clip_01.srt", "srt", b"base subtitles"),
            SECOND: media(root + SECOND, "mp4", b"obsolete mp4"),
            UNSELECTED: media(root + UNSELECTED, "mp4", b"unselected mp4"),
        }
        variant_manifest = {
            "clip.mp4": media(root + "edit/clip.mp4", "mp4", b"approved variant"),
            "clip.srt": media(root + "edit/clip.srt", "srt", b"variant srt"),
            "clip.vtt": media(root + "edit/clip.vtt", "vtt", b"variant vtt"),
        }
        options = Presentation(burn_subtitles=True).model_dump()
        cues = [{"start": 1, "end": 3, "text": "Voz de la prueba."}]
        item.update(status="completed", clips=[
            {"file": name, "start": index * 10, "end": index * 10 + 10, "options": options,
             "cues": cues, "caption_rendered": True}
            for index, name in enumerate((FIRST, SECOND, UNSELECTED))
        ])
        item["clip_caption_settings"] = {SECOND: {"revision": 4, "export_id": self.variant, "cues": cues}}
        with self.engine.begin() as connection:
            repository.update_document(connection, job, "job", item, manifest=manifest)
            repository.insert_document(connection, job, "export", {
                "id": self.variant, "status": "completed", "options": options, "cues": cues,
            }, variant_manifest)
        doc = repository.document(job)
        original_id = clip_captions.clip_context(doc, FIRST)["output"]["id"]
        self.tokens = [f"{FIRST}:1:{original_id}", f"{SECOND}:4:{self.variant}"]
        return job

    def open_object(self, item, *, retry, timeout):
        self.assertFalse(retry)
        self.assertEqual(timeout, clip_package.OBJECT_TIMEOUT)
        self.body(item["name"], item["generation"])
        response = Mock()
        response.iter_content.return_value = iter((self.contents[item["name"]],))
        return response

    def query(self, client=None, *, inspect=False, tokens=None):
        params = [("selection", token) for token in (self.tokens if tokens is None else tokens)]
        if inspect:
            params.append(("inspect", "1"))
        return (client or self.client).get(self.path, params=params)

    def completed_export(self, kind, *, job=None, status="completed", pilot=True,
                         extensions=("mp4", "srt", "vtt"), extra=None):
        job_id = job or self.job_id
        identity = secrets.token_hex(16)
        export = {"id": identity, "job_id": job_id, "status": status, "title": "Fragmento manual",
                  "clip_file": "manual.mp4", "options": Presentation().model_dump(), "cues": []}
        if pilot is not None:
            export["pilot"] = pilot
        if kind == "editorial":
            export.update(title="Recorte seleccionado", draft_id=secrets.token_hex(16), draft_revision=3)
        export.update(extra or {})
        prefix = f"workspaces/{self.principal.workspace_id}/jobs/{job_id}/tasks/{identity}/1/"
        manifest, expected = {}, {}
        for ext in extensions:
            object_name = f"{prefix}clip.{ext}"
            content = f"{kind} {identity} {ext}".encode()
            self.contents[object_name] = content
            manifest[f"clip.{ext}"] = object_item(object_name, ext, content)
            expected[f"{kind}_{identity}.{ext}"] = content
        with self.engine.begin() as connection:
            repository.insert_document(connection, job_id, "export", export, manifest)
        return export, manifest, expected

    def test_streams_exact_base_and_completed_variant_without_creating_a_task(self):
        summary = self.query(inspect=True)
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json(), {"clips": 2, "bytes": 60, "max_clips": 30, "max_bytes": 128 * 1024 * 1024})
        self.body.assert_not_called()

        result = self.query()
        self.assertEqual(result.status_code, 200)
        self.assertNotIn("content-length", result.headers)
        self.assertEqual(result.headers["content-type"], "application/zip")
        self.assertEqual(result.headers["cache-control"], "no-store")
        self.assertTrue(result.headers["content-disposition"].endswith("-clips.zip\""))
        expected = {FIRST: b"base mp4", "clip_01.srt": b"base subtitles", SECOND: b"approved variant",
                    "clip_02.srt": b"variant srt", "clip_02.vtt": b"variant vtt"}
        with ZipFile(BytesIO(result.content)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.namelist(), [*expected, "manifest.json"])
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(set(manifest), {"clips"})
            self.assertEqual([clip["caption_revision"] for clip in manifest["clips"]], [1, 4])
            self.assertEqual(manifest["clips"][1]["output_id"], self.variant)
            for item in manifest["clips"]:
                for file in item["files"]:
                    data = archive.read(file["file"])
                    self.assertEqual(data, expected[file["file"]])
                    self.assertEqual(file["sha256"], sha256(data).hexdigest())
                    self.assertEqual(archive.getinfo(file["file"]).compress_type, ZIP_STORED)
        with self.engine.begin() as connection:
            self.assertEqual(connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one(), 0)

    def test_mixed_zip_preserves_exact_auto_manual_editorial_variants_and_available_sidecars(self):
        manual, _, manual_files = self.completed_export("manual", pilot=None, extensions=("mp4",))
        editorial, _, editorial_files = self.completed_export("editorial")
        rows = self.client.get(f"/jobs/{self.job_id}/exports")
        self.assertEqual(rows.status_code, 200)
        catalog = {item["id"]: item for item in rows.json()["exports"]}
        self.assertNotIn("archive_selection", catalog[self.variant])
        self.assertEqual(catalog[manual["id"]]["archive_files"], ["mp4"])
        self.assertEqual(catalog[editorial["id"]]["archive_files"], ["mp4", "srt", "vtt"])
        def selector(item):
            token = catalog[item["id"]]["archive_selection"]
            self.assertEqual(token, f"export:{item['id']}:1")
            return token
        tokens = [selector(manual), self.tokens[1], selector(editorial)]
        expected = {**manual_files, SECOND: b"approved variant", "clip_02.srt": b"variant srt",
                    "clip_02.vtt": b"variant vtt", **editorial_files}
        summary = self.query(tokens=tokens, inspect=True)
        self.assertEqual(summary.status_code, 200)
        self.assertEqual(summary.json()["clips"], 3)
        self.assertEqual(summary.json()["bytes"], sum(map(len, expected.values())))
        self.body.assert_not_called()
        result = self.query(tokens=tokens)
        self.assertEqual(result.status_code, 200)
        with ZipFile(BytesIO(result.content)) as archive:
            self.assertIsNone(archive.testzip())
            self.assertEqual(archive.namelist(), [*expected, "manifest.json"])
            manifest = json.loads(archive.read("manifest.json"))
            self.assertEqual(set(manifest), {"clips", "exports"})
            self.assertEqual([(item["kind"], item["export_id"], item["revision"]) for item in manifest["exports"]],
                             [("manual", manual["id"], 1), ("editorial", editorial["id"], 1)])
            self.assertEqual([(item["clip"], item["caption_revision"], item["output_id"])
                              for item in manifest["clips"]], [(SECOND, 4, self.variant)])
            for item in manifest["clips"] + manifest["exports"]:
                for file in item["files"]:
                    content = expected[file["file"]]
                    self.assertEqual(archive.read(file["file"]), content)
                    self.assertEqual((file["bytes"], file["sha256"]), (len(content), sha256(content).hexdigest()))
        with self.engine.begin() as connection:
            self.assertEqual(connection.execute(text("SELECT count(*) FROM cloud_tasks")).scalar_one(), 0)

    def test_export_selection_rejects_stale_foreign_incomplete_and_internal_rows(self):
        another = pilot._reserve(self.principal, "other-zip-project", "other.mp4", 2048)
        elsewhere, _, _ = self.completed_export("editorial", job=another["id"])
        chosen, _, _ = self.completed_export("editorial")
        queued, _, _ = self.completed_export("manual", status="queued")
        failed, _, _ = self.completed_export("manual", status="failed")
        internal, _, _ = self.completed_export("editorial", extra={"clip_captions": True})
        without_mp4, _, _ = self.completed_export("manual", extensions=("srt",))
        corrupt, manifest, _ = self.completed_export("manual")
        manifest["clip.vtt"]["name"] = f"workspaces/{self.neighbor['principal'].workspace_id}/foreign.vtt"
        with self.engine.begin() as connection:
            repository.update_document(connection, self.job_id, "export", corrupt, manifest=manifest)
        token = f"export:{chosen['id']}:1"
        self.assertEqual(self.query(tokens=[token], inspect=True).status_code, 200)
        self.assertEqual(self.query(self.login(), tokens=[token]).status_code, 401)
        self.assertEqual(self.query(self.login(self.neighbor), tokens=[token]).status_code, 404)
        self.assertEqual(self.query(tokens=[f"export:{elsewhere['id']}:1"]).status_code, 404)
        self.assertEqual(self.query(tokens=[f"export:{chosen['id']}:2"]).status_code, 409)
        self.assertEqual(self.query(tokens=[token, f"export:{chosen['id']}:2"]).status_code, 422)
        self.assertEqual(self.query(tokens=[f"export:{chosen['id']}:01"]).status_code, 422)
        self.assertEqual(self.query(tokens=[f"export:../{chosen['id']}:1"]).status_code, 422)
        with patch.object(clip_package, "MAX_BYTES", 1):
            self.assertEqual(self.query(tokens=[token]).status_code, 413)
        rows = self.client.get(f"/jobs/{self.job_id}/exports")
        self.assertEqual(rows.status_code, 200)
        catalog = {item["id"]: item for item in rows.json()["exports"]}
        for invalid in (queued, failed, internal, without_mp4, corrupt):
            with self.subTest(status=invalid["status"], selection=invalid["id"]):
                self.assertNotIn("archive_selection", catalog[invalid["id"]])
                self.assertNotIn("archive_files", catalog[invalid["id"]])
                revision = 2 if invalid is corrupt else 1
                self.assertEqual(self.query(tokens=[f"export:{invalid['id']}:{revision}"]).status_code, 409)
        self.assertEqual(project_deletion.begin(self.principal, self.job_id)["status"], "deleted")
        self.assertEqual(self.query(tokens=[token]).status_code, 404)
        self.body.assert_not_called()

    def test_rejects_bad_selection_stale_revision_and_wrong_owners_without_opening_objects(self):
        self.assertEqual(self.query(self.login()).status_code, 401)
        self.assertEqual(self.query(self.login(self.neighbor)).status_code, 404)
        self.assertEqual(self.query(tokens=[self.tokens[0], self.tokens[0]]).status_code, 422)
        self.assertEqual(self.query(tokens=[f"../source.mp4:1:{self.variant}"]).status_code, 422)
        self.assertEqual(self.query(tokens=[f"{SECOND}:3:{self.variant}"]).status_code, 409)
        self.assertEqual(self.query(tokens=[f"{SECOND}:4:{'8' * 32}"]).status_code, 409)
        self.assertEqual(self.client.get(self.path, params=[
            ("selection", self.tokens[0]), ("inspect", "1"), ("inspect", "1"),
        ]).status_code, 422)
        with patch.object(clip_package, "MAX_BYTES", 1):
            self.assertEqual(self.query().status_code, 413)
        with self.engine.begin() as connection:
            doc = repository.document(self.job_id, connection=connection)
            payload = doc["payload"]
            payload["clip_caption_settings"][SECOND] = {"revision": 5, "draft": True, "export_id": None}
            doc["manifest"][FIRST]["name"] = f"workspaces/{self.neighbor['principal'].workspace_id}/foreign.mp4"
            repository.update_document(connection, self.job_id, "job", payload, manifest=doc["manifest"])
        self.assertEqual(self.query(tokens=[self.tokens[1]]).status_code, 409)
        self.assertEqual(self.query(tokens=[self.tokens[0]]).status_code, 409)
        self.assertEqual(project_deletion.begin(self.principal, self.job_id)["status"], "deleted")
        self.assertEqual(self.query().status_code, 404)
        self.body.assert_not_called()


class ClipPackageStreamTests(unittest.TestCase):
    def source(self, chunk, count=1):
        result = Mock()
        result.iter_content.return_value = (chunk for _ in range(count))
        return result

    def test_incomplete_member_does_not_emit_a_valid_footer(self):
        original = object_item("fixture", "mp4", b"valid contents")
        package = clip_package.Package(1, 14, (clip_package.Member(FIRST, original),), ())
        received = BytesIO()
        with (
            patch.object(storage, "open_object", return_value=self.source(b"badly contents")),
            patch.object(storage, "close") as closed,
        ):
            with self.assertRaises(storage.StorageError):
                for chunk in clip_package.chunks(package):
                    received.write(chunk)
            closed.assert_called_once()
        self.assertTrue(received.getvalue().startswith(b"PK"))
        with self.assertRaises(BadZipFile):
            ZipFile(received)

    def test_cancelling_the_download_closes_the_pinned_reader(self):
        original = object_item("fixture", "mp4", b"valid contents")
        package = clip_package.Package(1, 14, (clip_package.Member(FIRST, original),), ())
        with (
            patch.object(storage, "open_object", return_value=self.source(b"valid contents")),
            patch.object(storage, "close") as closed,
        ):
            iterator = clip_package.chunks(package)
            self.assertTrue(next(iterator).startswith(b"PK"))
            iterator.close()
            closed.assert_called_once()

    def test_over_32_mib_is_emitted_as_individual_chunks(self):
        chunk = b"X" * clip_package.CHUNK_BYTES
        digest = sha256()
        count = 33
        for _ in range(count):
            digest.update(chunk)
        size = count * len(chunk)
        item = {"bytes": size, "sha256": digest.hexdigest()}
        package = clip_package.Package(1, size, (clip_package.Member(FIRST, item),), ())
        with patch.object(storage, "open_object", return_value=self.source(chunk, count)), patch.object(storage, "close"):
            total = 0
            for emitted in clip_package.chunks(package):
                self.assertLessEqual(len(emitted), len(chunk))
                total += len(emitted)
            self.assertGreater(total, size)

    def test_public_proxy_preserves_selection_and_streams_without_content_length(self):
        session = Mock()
        response = Mock(status_code=200, headers=CaseInsensitiveDict({"Content-Type": "application/zip"}), raw=Mock())
        response.raw.headers.getlist.return_value = []
        response.iter_content.return_value = iter([b"PK", b"rest of zip"])
        session.request.return_value = response
        job_path = f"/jobs/{'1' * 32}/clips.zip"
        selectors = [("selection", f"{FIRST}:1:{'2' * 64}"), ("selection", f"export:{'3' * 32}:4")]
        with (
            TestClient(proxy.app, base_url=proxy.PUBLIC_ORIGIN) as client,
            patch.object(proxy, "session", return_value=session),
            patch.object(proxy.identity, "token", return_value="fixture.proxy.identity"),
        ):
            result = client.get(job_path, params=selectors, headers={"Range": "bytes=0-10"})
        self.assertEqual((result.status_code, result.content), (200, b"PKrest of zip"))
        self.assertNotIn("content-length", result.headers)
        args, options = session.request.call_args
        self.assertEqual(args, ("GET", proxy.API_ORIGIN + job_path))
        self.assertEqual(options["params"], selectors)
        self.assertNotIn("range", options["headers"])
