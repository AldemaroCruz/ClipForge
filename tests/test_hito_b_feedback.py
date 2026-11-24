"""Feedback acceptance against the disposable PostgreSQL test database."""
import os
import re
import secrets
import unittest
from unittest.mock import patch
import uuid

from fastapi import FastAPI
from fastapi.testclient import TestClient
from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth, auth_db
from app.cloud import feedback, migrate, migrate_beta, repository
from auth_support import auth_environment, http_login, prepare_database

ORIGIN = "http://127.0.0.1"
REVISION = "a" * 40


def app_instance():
    app = FastAPI()
    app.add_middleware(auth.AuthenticationBoundary)
    app.include_router(auth.router)
    app.include_router(feedback.router)
    return app


class FeedbackPostgresTests(unittest.TestCase):
    def setUp(self):
        self.schema = "auth01_test_beta_feedback_" + secrets.token_hex(8)
        state = patch.dict(os.environ, {**auth_environment(),
            "CLIPFORGE_DATABASE_SCHEMA": self.schema, "CLIPFORGE_ENVIRONMENT": "DEV",
            "CLIPFORGE_REVISION": REVISION})
        state.start()
        self.addCleanup(state.stop)
        self.addCleanup(auth_db.reset_engine)
        auth_db.reset_engine()
        self.engine = prepare_database(ORIGIN)
        self.addCleanup(self.remove_schema)
        self.assertEqual(migrate.upgrade(self.engine)["status"], "applied")
        self.password = secrets.token_urlsafe(24)
        self.admin = auth.bootstrap_admin("beta_admin", self.password)
        self.alice = auth.create_user("beta_alice", self.password)
        self.bob = auth.create_user("beta_bob", self.password)
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["status"], "applied")
        self.app = app_instance()

    def remove_schema(self):
        if not re.fullmatch(r"auth01_test_beta_feedback_[0-9a-f]{16}", self.schema):
            raise ValueError("Refusing to remove an unowned schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def client(self, actor=None, app=None):
        client = TestClient(app or self.app, base_url=ORIGIN)
        self.addCleanup(client.close)
        if actor is not None:
            csrf = http_login(client, actor.username, self.password, ORIGIN)
            client.headers.update({"Origin": ORIGIN, "X-CSRF-Token": csrf})
        return client

    def seed_job(self, actor, *, status="completed", error_code=None):
        job = uuid.uuid4().hex
        auth.register_project(job, actor)
        clips = [{"file": "clip_01.mp4", "start": 0, "end": 21}] if status == "completed" else []
        manifest = {"clip_01.mp4": {"name": "private-object-reference"}} if clips else {}
        with self.engine.begin() as connection:
            repository.insert_document(connection, job, "job",
                {"id": job, "status": status, "clips": clips, "error_code": error_code,
                 "error": "private execution diagnostics"}, manifest)
        return job

    def test_owned_feedback_survives_new_application_and_legacy_migration(self):
        job = self.seed_job(self.alice)
        post = self.client(self.alice).post("/beta/feedback", json={
            "category": "quality", "comment": "  El clip se entiende.  ",
            "job_id": job, "clip_file": "clip_01.mp4", "useful": True, "publishable": False,
        })
        self.assertEqual(post.status_code, 201)
        self.assertEqual(post.headers["cache-control"], "no-store")
        item = post.json()["item"]
        self.assertEqual(item["comment"], "El clip se entiende.")
        self.assertEqual(item["application_revision"], REVISION)
        self.assertEqual(item["job_id"], job)
        self.assertTrue(item["useful"])
        self.assertFalse(item["publishable"])
        self.assertEqual(migrate.upgrade(self.engine)["status"], "current")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["status"], "current")
        with self.engine.begin() as connection:
            self.assertTrue(migrate_beta.beta_schema_ready(connection))
            legacy = connection.execute(text("SELECT revision FROM cloud_schema_migrations")).scalars().all()
            self.assertEqual(legacy, ["cloud01_0001"])
        fresh = self.client(self.alice, app_instance())
        self.assertEqual(fresh.get("/beta/feedback").json(), {"items": [item], "has_more": False})

    def test_feedback_requires_session_csrf_and_project_ownership(self):
        alice, bob, admin = (self.client(actor) for actor in (self.alice, self.bob, self.admin))
        job = self.seed_job(self.alice)
        body = {"category": "error", "comment": "No pude descargar", "job_id": job}
        anonymous = self.client().post("/beta/feedback", json=body, headers={"Origin": ORIGIN})
        self.assertEqual(anonymous.status_code, 401)
        self.assertEqual(alice.post("/beta/feedback", json=body, headers={"X-CSRF-Token": ""}).status_code, 403)
        for non_owner in (bob, admin):
            self.assertEqual(non_owner.post("/beta/feedback", json=body).status_code, 404)
        missing_clip = {**body, "clip_file": "clip_09.mp4"}
        self.assertEqual(alice.post("/beta/feedback", json=missing_clip).status_code, 404)
        self.assertEqual(alice.post("/beta/feedback", json=body).status_code, 201)
        self.assertEqual(bob.get("/beta/feedback").json(), {"items": [], "has_more": False})
        self.assertEqual(bob.get("/beta/admin/feedback").status_code, 403)

    def test_admin_pagination_and_error_context_only_use_safe_fields(self):
        client = self.client(self.alice)
        known_job = self.seed_job(self.alice, status="failed", error_code="VIDEO_OUTSIDE_LIMITS")
        unknown_job = self.seed_job(self.alice, status="failed", error_code="private arbitrary execution error")
        for job, expected in ((known_job, "VIDEO_OUTSIDE_LIMITS"), (unknown_job, "PROCESSING_FAILED")):
            response = client.post("/beta/feedback", json={
                "category": "error", "comment": "El trabajo falló", "job_id": job})
            self.assertEqual(response.status_code, 201)
            self.assertEqual(response.json()["item"]["error_code"], expected)
        admin = self.client(self.admin)
        page = admin.get("/beta/admin/feedback?limit=1").json()
        self.assertTrue(page["has_more"])
        self.assertEqual(page["items"][0]["username"], self.alice.username)
        self.assertEqual(page["items"][0]["user_id"], self.alice.id)
        self.assertEqual(page["items"][0]["job_id"], unknown_job)
        next_page = admin.get("/beta/admin/feedback?limit=1&offset=1").json()
        self.assertFalse(next_page["has_more"])
        self.assertEqual(next_page["items"][0]["job_id"], known_job)
        combined = str(page) + str(next_page)
        self.assertNotIn("private execution diagnostics", combined)
        self.assertNotIn("private arbitrary execution error", combined)
        self.assertNotIn("private-object-reference", combined)

    def test_rejects_forged_metadata_and_invalid_feedback(self):
        client = self.client(self.alice)
        base = {"category": "suggestion", "comment": "Añadir ayuda."}
        for change in ({"user_id": self.bob.id}, {"application_revision": "b" * 40},
                       {"error_code": "WORKER_INTERRUPTED"}, {"category": "unknown"},
                       {"useful": True}, {"publishable": "false"}, {"comment": "\u0000"},
                       {"comment": "  "}, {"comment": "x" * 2001}):
            with self.subTest(change=next(iter(change))):
                result = client.post("/beta/feedback", json={**base, **change})
                self.assertEqual(result.status_code, 422)
                self.assertEqual(result.json(), {"detail": "Comentario o contexto de feedback inválido."})
        result = client.post("/beta/feedback", content=b"x" * (feedback.MAX_BODY + 1),
                             headers={"Content-Type": "application/json"})
        self.assertEqual(result.status_code, 413)
        self.assertEqual(client.get("/beta/feedback").json()["items"], [])
