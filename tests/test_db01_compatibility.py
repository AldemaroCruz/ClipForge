"""Pure DB-01 harness regressions; live database evidence is separate."""
import unittest
from unittest import mock
from scripts import db01_compatibility as db


class CompatibilityContract(unittest.TestCase):
    def test_only_separate_generated_password_literals_enter_bootstrap(self):
        first, second = "a" * 48, "b" * 48
        sql = db.initial_sql(first, second)
        self.assertIn("CREATE DATABASE clipforge OWNER clipforge_migrator", sql)
        self.assertIn("NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION", sql)
        self.assertIn("REVOKE ALL ON SCHEMA public FROM PUBLIC", sql)
        self.assertIn("GRANT USAGE ON SCHEMA public TO clipforge_app", sql)
        self.assertNotIn("GRANT CREATE", sql)
        self.assertLess(sql.index("SET log_statement='none'"), sql.index("PASSWORD"))
        self.assertLess(sql.index("SET log_min_error_statement='panic'"), sql.index("PASSWORD"))
        for app in (first, "short", "b'" * 24, "b\n" * 24):
            with self.subTest(app=app), self.assertRaises(ValueError):
                db.initial_sql(first, app)

    def test_postgres_pin_tls_and_hba_remain_explicit(self):
        self.assertEqual(db.SERVER_VERSION_NUM, 170012)
        self.assertIn("17.12-trixie@sha256:", db.PG_IMAGE)
        self.assertIn("subjectAltName=DNS:postgres", db.CERT_SCRIPT)
        self.assertIn("ssl_min_protocol_version=TLSv1.2", db.BOOTSTRAP)
        self.assertIn("hostnossl all all 0.0.0.0/0 reject", db.HBA)
        self.assertEqual(db.HBA.count("scram-sha-256"), 2)
        self.assertNotIn(" trust", db.HBA)

    def test_all_twenty_app_privileges_are_checked_individually(self):
        connection = mock.Mock()
        connection.execute.return_value.fetchone.return_value = (True,)
        db.require_all_app_dml(connection)
        calls = [call.args for call in connection.execute.call_args_list]
        self.assertEqual(len(calls), 20)
        self.assertEqual({args[1][1] for args in calls}, {"SELECT", "INSERT", "UPDATE", "DELETE"})
        self.assertTrue(all(args[0] == "SELECT has_table_privilege(current_user,%s,%s)" for args in calls))
        def execute(_sql, args):
            return mock.Mock(fetchone=lambda: (args != ("cloud_tasks", "DELETE"),))
        connection.execute.side_effect = execute
        with self.assertRaisesRegex(ValueError, "Missing app DML"):
            db.require_all_app_dml(connection)


if __name__ == "__main__":
    unittest.main()
