import base64
import hashlib
import hmac
import io
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import int_hito_a_db_credentials as credentials


def verifier(password, salt=b"0123456789abcdef"):
    salted = hashlib.pbkdf2_hmac("sha256", password.encode("ascii"), salt, 4096)
    client = hmac.new(salted, b"Client Key", hashlib.sha256).digest()
    stored = hashlib.sha256(client).digest()
    server = hmac.new(salted, b"Server Key", hashlib.sha256).digest()
    encoded = lambda value: base64.b64encode(value).decode("ascii")
    return "SCRAM-SHA-256$4096:" + encoded(salt) + "$" + encoded(stored) + ":" + encoded(server)


class HitoADatabaseCredentialTests(unittest.TestCase):
    def test_scram_match_is_exact(self):
        password = "A" * 32 + "-exact"
        value = verifier(password)
        self.assertTrue(credentials.matches(password, value))
        self.assertFalse(credentials.matches("B" * 32 + "-wrong", value))
        with self.assertRaises(ValueError):
            credentials.matches(password, value.replace("$4096:", "$4095:"))

    def test_collect_reads_only_two_verifiers_and_emits_no_sensitive_values(self):
        app = "a" * 40
        migrator = "m" * 40
        stdout = ("clipforge_app\t" + verifier(app) + "\n"
                  "clipforge_migrator\t" + verifier(migrator, b"fedcba9876543210") + "\n").encode()
        protected = ('{"app_password":"' + app + '","migrator_password":"' + migrator + '"}').encode()
        with mock.patch.object(credentials.subprocess, "run", return_value=SimpleNamespace(
                returncode=0, stdout=stdout, stderr=b"")) as command:
            result = credentials.collect(io.BytesIO(protected))
        self.assertEqual(result, {
            "schema": credentials.SCHEMA, "status": "verified",
            "roles": list(credentials.ROLES), "read_only": True,
        })
        rendered = str(result)
        self.assertNotIn(app, rendered)
        self.assertNotIn(migrator, rendered)
        self.assertNotIn("SCRAM-SHA-256", rendered)
        self.assertEqual(command.call_count, 1)


if __name__ == "__main__":
    unittest.main()
