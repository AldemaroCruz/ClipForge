"""Preserve the historical feedback ledger in the disposable test database."""
import os
import re
import secrets
import unittest
from unittest.mock import patch

from sqlalchemy import text
from sqlalchemy.schema import DropSchema

from app import auth, auth_db
from app.cloud import migrate, migrate_beta
from auth_support import auth_environment, prepare_database


class FeedbackMigrationHistoryTests(unittest.TestCase):
    def setUp(self):
        self.schema = "auth01_test_beta_feedback_" + secrets.token_hex(8)
        state = patch.dict(os.environ, {**auth_environment(), "CLIPFORGE_DATABASE_SCHEMA": self.schema})
        state.start()
        self.addCleanup(state.stop)
        auth_db.reset_engine()
        self.addCleanup(auth_db.reset_engine)
        self.engine = prepare_database()
        self.addCleanup(self.remove_schema)

    def remove_schema(self):
        if not re.fullmatch(r"auth01_test_beta_feedback_[0-9a-f]{16}", self.schema):
            raise ValueError("Refusing to remove an unowned schema")
        with self.engine.begin() as connection:
            connection.execute(DropSchema(self.schema, cascade=True))

    def test_applied_migrations_preserve_historical_feedback(self):
        self.assertEqual(migrate.upgrade(self.engine)["status"], "applied")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["status"], "applied")
        user = auth.create_user("beta_history_owner", secrets.token_urlsafe(24))
        job_id = secrets.token_hex(16)
        auth.register_project(job_id, user)
        with self.engine.begin() as connection:
            connection.execute(text("""
                INSERT INTO cloud_feedback
                    (id, user_id, job_id, category, comment, clip_file, useful, publishable, application_revision)
                VALUES
                    (:id, :user_id, :job_id, 'quality', 'Historical fixture', 'clip_01.mp4', true, false, :revision)
                """), {"id": secrets.token_hex(16), "user_id": user.id, "job_id": job_id, "revision": "a" * 40})
            previous = connection.execute(text("SELECT * FROM cloud_feedback")).mappings().one()

        self.assertEqual(migrate.upgrade(self.engine)["status"], "current")
        self.assertEqual(migrate_beta.upgrade_beta(self.engine)["status"], "current")
        with self.engine.begin() as connection:
            self.assertTrue(migrate_beta.beta_schema_ready(connection))
            legacy = connection.execute(text("SELECT revision FROM cloud_schema_migrations")).scalars().all()
            self.assertEqual(legacy, ["cloud01_0001"])
            self.assertEqual(connection.execute(text("SELECT * FROM cloud_feedback")).mappings().one(), previous)
