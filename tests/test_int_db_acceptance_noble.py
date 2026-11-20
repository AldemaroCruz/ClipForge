"""Target isolation and receipt fixtures; all Cloud Run and PostgreSQL calls are simulated."""

from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, patch

from scripts import int_db_acceptance_noble as client


NOW = datetime(2026, 11, 20, 16, 30, tzinfo=timezone.utc)
ROOT = Path(__file__).resolve().parents[1]
IMAGE = client.NOBLE_IMAGE
LEGACY_IMAGE = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + "a" * 64
VERSIONS = {"migrator_password": "1", "app_password": "2", "postgres_ca": "3"}
SOURCES = [{"path": path, "sha256": digest} for path, digest in sorted(client.NOBLE_SOURCES.items())]
LEGACY_SOURCES = [row for row in SOURCES if row["path"] in client.SOURCES]
GUEST_SHA256 = client.NOBLE_GUEST_RECEIPT_SHA256
BOOTSTRAP_SHA256_FIXTURE = client.sha(b"synthetic bootstrap receipt; no Noble data or authorization in this fixture")
SOURCE_FIXTURE = b"synthetic client source fixture"
SOURCE_SHA256 = client.sha(SOURCE_FIXTURE)


def noble_job(phase="migrate"):
    return client.job_spec(phase, IMAGE, VERSIONS, SOURCES, source=SOURCE_FIXTURE, target="noble",
                           guest_receipt_sha256=GUEST_SHA256, bootstrap_receipt_sha256=BOOTSTRAP_SHA256_FIXTURE)


def decision(phase="migrate", *, target="noble"):
    routed_job = client.route(phase, target)[0]
    noble = target == "noble"
    value = {"schema": "clipforge-db01-client-decision-2" if noble else "clipforge-db01-client-decision-1",
             "status": "authorized_specific_job_execution", "owner": "admin@ixbalam.studio",
             "job": routed_job, "phase": phase, "operation_id": "1" * 32, "source_sha256": SOURCE_SHA256,
             "image": IMAGE if noble else LEGACY_IMAGE, "secret_versions": dict(VERSIONS),
             "app_sources": list(SOURCES if noble else LEGACY_SOURCES),
             "guest_receipt_sha256": GUEST_SHA256 if noble else client.sha(b"historical guest receipt fixture"),
             "issued_utc": NOW.isoformat(), "expires_utc": (NOW + timedelta(minutes=30)).isoformat()}
    if noble:
        value.update(target=dict(client.NOBLE_SCOPE), bootstrap_receipt_sha256=BOOTSTRAP_SHA256_FIXTURE)
    return value


def env_for(value, *, phase="migrate"):
    container = noble_job(phase)["template"]["template"]["containers"][0]
    raw = json.dumps(value, sort_keys=True)
    return {**{row["name"]: row["value"] for row in container["env"]},
            "CLOUD_RUN_JOB": client.NOBLE_JOBS[phase], "CLOUD_RUN_TASK_INDEX": "0",
            "CLOUD_RUN_TASK_ATTEMPT": "0", "CLOUD_RUN_TASK_COUNT": "1",
            "INT_DB_CLIENT_DECISION_JSON": raw, "INT_DB_CLIENT_DECISION_SHA256": client.sha(raw.encode("ascii"))}


class NobleAcceptance(unittest.TestCase):
    def test_noble_job_binding_keeps_historical_debian_default(self):
        for phase in client.JOBS:
            legacy = client.job_spec(phase, LEGACY_IMAGE, VERSIONS, LEGACY_SOURCES, source=SOURCE_FIXTURE)
            self.assertEqual(legacy, client.job_spec(phase, LEGACY_IMAGE, VERSIONS, LEGACY_SOURCES,
                                                    target="debian", source=SOURCE_FIXTURE))
            noble = noble_job(phase)
            self.assertEqual(noble["name"], client.JOB_PATH + client.NOBLE_JOBS[phase])
            self.assertNotEqual(legacy["name"], noble["name"])
            legacy_task, noble_task = (value["template"]["template"] for value in (legacy, noble))
            for key in ("serviceAccount", "maxRetries", "timeout", "executionEnvironment", "vpcAccess", "volumes"):
                self.assertEqual(legacy_task[key], noble_task[key])
            old_container, container = (task["containers"][0] for task in (legacy_task, noble_task))
            self.assertEqual(old_container["args"][3:], ["execute", phase])
            self.assertEqual(container["args"][3:], ["execute", phase, "--target", "noble"])
            values = {row["name"]: row["value"] for row in container["env"]}
            self.assertEqual(values["CLIPFORGE_DATABASE_HOST"], "10.80.1.3")
            self.assertEqual(values["CLIPFORGE_DATABASE_SSL_MODE"], "verify-full")
            self.assertEqual(values["INT_DB_BOOTSTRAP_RECEIPT_SHA256"], BOOTSTRAP_SHA256_FIXTURE)
            self.assertEqual(values["INT_DB_GUEST_RECEIPT_SHA256"], GUEST_SHA256)

    def test_noble_refuses_wrong_oci_sources_and_unbound_receipts(self):
        for change in ({"image": LEGACY_IMAGE}, {"image": IMAGE.rsplit("@", 1)[0] + "@sha256:" + "a" * 64},
                       {"app_sources": LEGACY_SOURCES}, {"app_sources": [{**SOURCES[0], "sha256": "2" * 64}, *SOURCES[1:]]},
                       {"guest_receipt_sha256": "3" * 64}, {"bootstrap_receipt_sha256": GUEST_SHA256},
                       {"bootstrap_receipt_sha256": None}):
            args = {"phase": "migrate", "image": IMAGE, "versions": VERSIONS, "app_sources": SOURCES,
                    "target": "noble", "guest_receipt_sha256": GUEST_SHA256, "bootstrap_receipt_sha256": BOOTSTRAP_SHA256_FIXTURE}
            with self.subTest(change=change), self.assertRaises(ValueError):
                client.job_spec(**{**args, **change})

    def test_run_request_cannot_move_authority_across_target_phase_or_bootstrap_receipt(self):
        value = decision()
        args = {"phase": "migrate", "image": IMAGE, "versions": VERSIONS, "app_sources": SOURCES, "source_sha256": SOURCE_SHA256,
                "target": "noble", "guest_receipt_sha256": GUEST_SHA256, "bootstrap_receipt_sha256": BOOTSTRAP_SHA256_FIXTURE,
                "now": NOW}
        raw = json.dumps(value, sort_keys=True)
        request = client.job_run_request(raw, client.sha(raw.encode("ascii")), **args)
        self.assertEqual(request["resource"], client.JOB_PATH + client.NOBLE_JOBS["migrate"])
        overrides = request["body"]["overrides"]
        self.assertEqual({row["name"] for row in overrides["containerOverrides"][0]["env"]},
                         {"INT_DB_CLIENT_DECISION_JSON", "INT_DB_CLIENT_DECISION_SHA256"})
        self.assertNotIn("args", overrides["containerOverrides"][0])
        for change in ({"phase": "app"}, {"target": "debian"}, {"bootstrap_receipt_sha256": "3" * 64},
                       {"source_sha256": "4" * 64}, {"versions": {**VERSIONS, "migrator_password": "4"}}):
            with self.subTest(change=change), self.assertRaises(ValueError):
                client.job_run_request(raw, client.sha(raw.encode("ascii")), **{**args, **change})
        moved = {**value, "target": {**value["target"], "database_host": "10.80.1.2"}}
        for changed in (decision(target="debian"), moved):
            raw = json.dumps(changed, sort_keys=True)
            with self.assertRaises(ValueError):
                client.job_run_request(raw, client.sha(raw.encode("ascii")), **args)

    def test_execution_checks_immutable_job_target_and_five_real_source_bytes_before_metadata(self):
        value = decision()
        env = env_for(value)
        scratch = tempfile.TemporaryDirectory()
        self.addCleanup(scratch.cleanup)
        sources = Path(scratch.name)
        for name, checksum in client.NOBLE_SOURCES.items():
            path = sources / name
            path.parent.mkdir(parents=True, exist_ok=True)
            # A Windows checkout may translate LF. The Linux OCI keeps the blobs.
            raw = (ROOT / name).read_bytes().replace(b"\r\n", b"\n")
            self.assertEqual(client.sha(raw), checksum)
            path.write_bytes(raw)
        with (patch.object(client, "Path", return_value=sources),
              patch.object(client, "DB01_ACCEPTANCE_SOURCE_SHA256", SOURCE_SHA256, create=True),
              patch.object(client, "observed_service_account", return_value=client.ACCOUNTS["migrate"]) as observed):
            verified = client.execution_authority(env, "migrate", now=NOW, target="noble")
            self.assertEqual(verified["_observed_service_account"], client.ACCOUNTS["migrate"])
            self.assertEqual(verified["target"], client.NOBLE_SCOPE)
            for change in ({"CLOUD_RUN_JOB": client.JOBS["migrate"]}, {"CLIPFORGE_DATABASE_HOST": "10.80.1.2"},
                           {"INT_DB_BOOTSTRAP_RECEIPT_SHA256": "2" * 64}, {"CLOUD_RUN_TASK_ATTEMPT": "1"}):
                with self.subTest(change=change), self.assertRaises(ValueError):
                    client.execution_authority({**env, **change}, "migrate", now=NOW, target="noble")
            with self.assertRaises(ValueError):
                client.execution_authority(env, "migrate", now=NOW)
            observed.assert_called_once_with()

    def test_noble_connection_and_receipt_match_observed_server(self):
        env = env_for(decision())
        for server, version in (("10.80.1.3", 170012), ("10.80.1.2", 170012), ("10.80.1.3", 170013)):
            connection = MagicMock()
            connection.__enter__.return_value = connection
            rows = [("clipforge_migrator", "10.80.0.4", server, version), (False,) * 5, (0,),
                    (True, "TLSv1.3"), ("scram-sha-256",), ("UTF8",), ("C.UTF-8", "C.UTF-8")]
            connection.execute.side_effect = [Mock(fetchone=Mock(return_value=row)) for row in rows]
            psycopg = SimpleNamespace(connect=Mock(return_value=connection), sql=object())
            with (patch.dict(sys.modules, {"psycopg": psycopg}),
                  patch.object(client.Path, "read_text", return_value="synthetic test password"),
                  patch.object(client, "apply_migrations", return_value=({"status": "applied"}, {"status": "current"})) as mutate):
                report = client.execute("migrate", env, target="noble", authority=lambda *_: decision())
                self.assertEqual(psycopg.connect.call_args.kwargs["host"], "10.80.1.3")
                self.assertEqual(psycopg.connect.call_args.kwargs["sslmode"], "verify-full")
                self.assertEqual(report["schema"], "clipforge-db01-external-acceptance-2")
                self.assertEqual(report["target"], client.NOBLE_SCOPE)
                self.assertEqual(report["bootstrap_receipt_sha256"], BOOTSTRAP_SHA256_FIXTURE)
                self.assertEqual(report["source_sha256"], SOURCE_SHA256)
                self.assertEqual(report["identity"]["source"], "local_fixture_authority_boundary")
                self.assertIs(report["runtime_authorized"], False)
                if server == "10.80.1.3" and version == 170012:
                    self.assertEqual(report["status"], "passed")
                    self.assertEqual(report["checks"][0]["server_address"], server)
                    self.assertEqual(report["checks"][0]["postgres_version_num"], version)
                    mutate.assert_called_once()
                else:
                    self.assertEqual(report["status"], "failed")
                    self.assertEqual(report["checks"], [])
                    mutate.assert_not_called()


if __name__ == "__main__":
    unittest.main()
