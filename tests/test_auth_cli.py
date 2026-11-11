"""Terminal input contract fixtures; real PostgreSQL provisioning is in test_auth.

These mocks test no-echo failure handling, not database persistence or hashing.
"""
from contextlib import redirect_stderr, redirect_stdout
import getpass
import io
import secrets
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from scripts import auth_admin


class AuthAdminCLIContractTests(unittest.TestCase):
    def test_redirected_stdin_refused_before_password_prompt_or_database(self):
        with patch.object(auth_admin.sys.stdin, 'isatty', return_value=False), \
                patch.object(auth_admin.getpass, 'getpass') as prompt, \
                patch.object(auth_admin, 'bootstrap_admin') as create, redirect_stderr(io.StringIO()):
            result = auth_admin.main(['--username', 'fixture_admin'])
        self.assertEqual(result, 1)
        prompt.assert_not_called()
        create.assert_not_called()

    def test_getpass_fallback_is_rejected_without_echo_or_account_creation(self):
        with patch.object(auth_admin.sys.stdin, 'isatty', return_value=True), \
                patch.object(auth_admin.getpass, 'getpass', side_effect=getpass.GetPassWarning('fixture no terminal')), \
                patch.object(auth_admin, 'bootstrap_admin') as create, redirect_stderr(io.StringIO()):
            result = auth_admin.main(['--username', 'fixture_admin'])
        self.assertEqual(result, 1)
        create.assert_not_called()

    def test_password_confirmation_mismatch_never_reaches_database(self):
        first, second = secrets.token_urlsafe(24), secrets.token_urlsafe(24)
        output = io.StringIO()
        with patch.object(auth_admin.sys.stdin, 'isatty', return_value=True), \
                patch.object(auth_admin.getpass, 'getpass', side_effect=[first, second]), \
                patch.object(auth_admin, 'bootstrap_admin') as create, redirect_stderr(output):
            result = auth_admin.main(['--username', 'fixture_admin'])
        self.assertEqual(result, 1)
        create.assert_not_called()
        self.assertTrue(first not in output.getvalue() and second not in output.getvalue(), 'No password echo')

    def test_matching_secure_prompts_delegate_explicit_username_and_emit_no_password(self):
        password = secrets.token_urlsafe(24)
        output = io.StringIO()
        with patch.object(auth_admin.sys.stdin, 'isatty', return_value=True), \
                patch.object(auth_admin.getpass, 'getpass', side_effect=[password, password]) as prompt, \
                patch.object(auth_admin, 'bootstrap_admin', return_value=SimpleNamespace(username='fixture_admin')) as create, \
                redirect_stdout(output):
            result = auth_admin.main(['--username', 'fixture_admin'])
        self.assertEqual(result, 0)
        self.assertEqual(prompt.call_count, 2)
        create.assert_called_once()
        self.assertTrue(create.call_args.args == ('fixture_admin', password), 'Only explicit username and confirmed password passed')
        self.assertTrue(password not in output.getvalue(), 'No password in CLI output')


if __name__ == '__main__':
    unittest.main()
