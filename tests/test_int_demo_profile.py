"""Targeted checks of the INT account demo's registered surface and startup guard."""
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from fastapi import HTTPException
from fastapi.testclient import TestClient

from app.int_demo import app


EXPECTED_ROUTES = {
    ("GET", "/"), ("GET", "/account"), ("GET", "/login"), ("GET", "/recover"),
    ("GET", "/favicon.ico"), ("GET", "/static/{name}"), ("GET", "/environment"),
    ("GET", "/health"), ("GET", "/auth/csrf"), ("POST", "/auth/login"), ("GET", "/auth/me"),
    ("POST", "/auth/logout"), ("POST", "/auth/password"), ("GET", "/auth/users"),
    ("POST", "/auth/users"), ("POST", "/auth/users/{user_id}/deactivate"),
    ("POST", "/auth/admin/users/{user_id}/recovery"), ("POST", "/auth/recover"),
    ("GET", "/auth/admin/audit"),
}


class IntDemoProfile(unittest.TestCase):
    def test_route_and_static_allowlists(self):
        self.assertEqual({(method, route.path) for route in app.routes for method in route.methods},
                         EXPECTED_ROUTES)
        client = TestClient(app, base_url="https://int-demo.invalid")
        for path in ("account.css", "account.js", "auth.js", "recover.js"):
            with self.subTest(path=path):
                self.assertEqual(client.get(f"/static/{path}").status_code, 200)
        for path in ("app.js", "index.html", "ops.js", "%2e%2e/index.html", "media/input.mp4"):
            with self.subTest(path=path):
                self.assertEqual(client.get(f"/static/{path}").status_code, 404)

    def test_startup_rejects_missing_or_insecure_configuration(self):
        with tempfile.TemporaryDirectory() as scratch:
            ca = Path(scratch, "fixture-ca.pem")
            ca.touch()
            configured = {
                "CLIPFORGE_RUNTIME_PROFILE": "int-demo-a", "CLIPFORGE_ENVIRONMENT": "INT",
                "CLIPFORGE_REVISION": "a" * 40, "CLIPFORGE_AUTH_ORIGIN": "https://int-demo.invalid",
                "CLIPFORGE_DATABASE_SSL_MODE": "verify-full", "CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE": str(ca),
            }
            for var, value in (
                ("CLIPFORGE_RUNTIME_PROFILE", ""), ("CLIPFORGE_ENVIRONMENT", "DEV"),
                ("CLIPFORGE_AUTH_PROFILE", "local-http"), ("CLIPFORGE_DATABASE_SSL_MODE", "require"),
                ("CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE", ""), ("CLIPFORGE_DATABASE_URL", "configured"),
                ("CLIPFORGE_STORAGE_BACKEND", "gcs"),
            ):
                with self.subTest(var=var), patch.dict(os.environ, {**configured, var: value}, clear=True):
                    with self.assertRaises((RuntimeError, HTTPException)):
                        with TestClient(app, base_url="https://int-demo.invalid"):
                            pass
            with patch.dict(os.environ, configured, clear=True):
                with TestClient(app, base_url="https://int-demo.invalid") as client:
                    self.assertEqual(client.get("/environment").json()["environment"], "INT")


if __name__ == "__main__":
    unittest.main()
