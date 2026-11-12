"""ENV-01 cookie boundaries and public, non-secret revision metadata."""
import os
from unittest import TestCase
from unittest.mock import patch

from fastapi import HTTPException, Response

from app import auth
from app.environment import identity


class EnvironmentTests(TestCase):
    def config(self, namespace="", profile="local-http"):
        return patch.dict(os.environ, {
            "CLIPFORGE_AUTH_COOKIE_NAMESPACE": namespace,
            "CLIPFORGE_AUTH_PROFILE": profile,
            "CLIPFORGE_AUTH_ORIGIN": "http://127.0.0.1:34567" if profile == "local-http" else "https://example.test",
        })

    def test_all_four_cookie_names_are_distinct_and_host_only(self):
        names = {}
        for namespace in ("dev", "int"):
            with self.config(namespace):
                config = auth.settings()
                response = Response()
                for name in (auth.SESSION_COOKIE, auth.CSRF_COOKIE, auth.PREAUTH_COOKIE, auth.PRECSRF_COOKIE):
                    auth._cookie(response, name, "synthetic-token", config, 600)
                cookies = [value.decode() for key, value in response.raw_headers if key == b"set-cookie"]
                names[namespace] = {value.split("=", 1)[0] for value in cookies}
                self.assertEqual(len(names[namespace]), 4)
                for value in cookies:
                    self.assertIn("HttpOnly", value)
                    self.assertIn("SameSite=strict", value)
                    self.assertNotIn("Domain=", value)
                cleared = Response()
                auth._clear_cookies(cleared, config)
                self.assertEqual({value.decode().split("=", 1)[0] for key, value in cleared.raw_headers
                                  if key == b"set-cookie"}, names[namespace])
        self.assertTrue(names["dev"].isdisjoint(names["int"]))

    def test_namespace_does_not_disable_secure_profile(self):
        with self.config("dev", "https"):
            response = Response()
            auth._cookie(response, auth.SESSION_COOKIE, "synthetic-token", auth.settings(), 600)
            self.assertIn("; Secure", response.headers["set-cookie"])

    def test_missing_profile_keeps_https_default(self):
        with patch.dict(os.environ, {"CLIPFORGE_AUTH_ORIGIN": "http://127.0.0.1:34567"}, clear=True):
            with self.assertRaises(HTTPException) as caught:
                auth.settings()
            self.assertEqual(caught.exception.status_code, 503)

    def test_invalid_namespace_fails_closed(self):
        for namespace in ("dev;path=/", "DEV", "dev\n", "a" * 33):
            with self.config(namespace), self.assertRaises(HTTPException) as caught:
                auth.settings()
            self.assertEqual(caught.exception.status_code, 503)

    def test_legacy_cookie_names_remain_unchanged(self):
        with self.config():
            self.assertEqual(auth.cookie_name(auth.SESSION_COOKIE), "clipforge_session")

    def test_metadata_has_only_public_identity(self):
        with patch.dict(os.environ, {"CLIPFORGE_ENVIRONMENT": "INT", "CLIPFORGE_REVISION": "a" * 40}):
            self.assertEqual(identity(), {"environment": "INT", "revision": "a" * 40})
        with patch.dict(os.environ, {}, clear=True):
            self.assertEqual(identity(), {"environment": "", "revision": ""})

    def test_metadata_never_echoes_unvalidated_values(self):
        for label, revision in (("DEV", "not-a-commit"), ("unexpected-label", "b" * 40)):
            with patch.dict(os.environ, {"CLIPFORGE_ENVIRONMENT": label, "CLIPFORGE_REVISION": revision}):
                with self.assertRaises(HTTPException) as caught:
                    identity()
                self.assertEqual(caught.exception.status_code, 503)
