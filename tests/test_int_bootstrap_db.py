"""DB-01 candidate authority/transport fixtures; no GCP, SSH or disk operations."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import sys
from types import ModuleType, SimpleNamespace
import unittest
from unittest import mock

from scripts import int_bootstrap_db as b
from scripts import int_db_acceptance as acceptance
REAL_PROCESSES = b.BootstrapProcesses


class BootstrapLauncher(unittest.TestCase):
    def setUp(self):
        self.at = datetime(2026, 11, 19, 12, tzinfo=timezone.utc)
        self.env = {"GITHUB_SHA": "a" * 40, "INT_APPROVED_COMMIT": "a" * 40, "INT_BASELINE_RUN_ID": "123456", "INT_BASELINE_ARTIFACT_ID": "123457"}
        self.proposal = {"schema": "clipforge-db01-bootstrap-proposal-1", "status": "authorized_single_guest_initialization",
            "execution_authorized": True, "cloud_writes_authorized": True, "VM_operations_authorized": True,
            "SQL_on_INT_authorized": True, "format_operation": {"status": "authorized_single_initialization", "authorized": True,
                "argv": ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", "/dev/disk/by-id/google-clipforge-pg-data"],
                "confirmation": "INITIALIZE_NEW_DISK_" + b.DISK_ID, "disk_id": b.DISK_ID, "one_invocation_only": True},
            "target": {"project_id": "clipforgebeta2", "project_number": "816643438938",
                "instance_id": b.t.host.IDENTITY["instance_id"], "disk_id": b.DISK_ID,
                "disk_size_bytes": 21474836480, "attachment_device_name": "clipforge-pg-data"}}
        self.raw_proposal = b.t.canonical(self.proposal)
        self.decision = {"schema": "clipforge-db01-activation-decision-1", "status": "authorized_single_guest_initialization",
            "owner": "admin@ixbalam.studio", "repository": "AldemaroCruz/ClipForge", "branch": "ci/bootstrap-sec03",
            "approved_commit": "a" * 40, "operation_id": "b" * 32, "proposal_sha256": b.t.sha(self.raw_proposal),
            "host_evidence_sha256": b.t.HOST_EVIDENCE_SHA, "baseline_evidence_sha256": b.t.sha(b"owned baseline fixture"),
            "baseline_run_id": "123456", "baseline_artifact_id": "123457",
            "issued_utc": self.at.isoformat(), "expires_utc": (self.at + timedelta(hours=1)).isoformat(),
            "confirmation": "INITIALIZE_NEW_DISK_" + b.DISK_ID}

    def validate(self, decision=None, proposal=None, at=None):
        raw = b.t.canonical(self.decision if decision is None else decision)
        return b.validate_decision(raw, b.t.sha(raw), self.raw_proposal if proposal is None else proposal,
                                   self.env, now=self.at if at is None else at)

    def test_closed_point_decision_binds_proposal_commit_disk_and_window(self):
        decision, _ = self.validate()
        self.assertEqual(decision["operation_id"], "b" * 32)
        for field, value in (("approved_commit", "c" * 40), ("proposal_sha256", b.t.sha(b"other proposal")),
                             ("confirmation", "INITIALIZE_NEW_DISK_999"), ("owner", "other@example.invalid"),
                             ("host_evidence_sha256", b.t.sha(b"other pin")), ("new_field", True)):
            changed = {**self.decision, field: value}
            with self.subTest(field=field), self.assertRaises(ValueError): self.validate(changed)
        for at in (self.at - timedelta(seconds=1), self.at + timedelta(minutes=50), self.at + timedelta(hours=2)):
            with self.subTest(at=at), self.assertRaises(ValueError): self.validate(at=at)
        changed = {**self.decision, "expires_utc": (self.at + timedelta(hours=2)).isoformat()}
        with self.assertRaises(ValueError): self.validate(changed)

    def test_current_preparation_flags_block_even_an_otherwise_valid_owner_document(self):
        for field in ("execution_authorized", "cloud_writes_authorized", "VM_operations_authorized", "SQL_on_INT_authorized"):
            proposal = b.t.canonical({**self.proposal, field: False})
            decision = {**self.decision, "proposal_sha256": b.t.sha(proposal)}
            with self.subTest(field=field), self.assertRaisesRegex(b.t.Blocked, "proposal_blocks"):
                self.validate(decision, proposal)

    def test_format_authorization_is_closed_and_exact_before_any_operation(self):
        mutations = {"status": "prepared_blocked_pending_specific_authorization", "authorized": False,
            "argv": None, "confirmation": None, "disk_id": "other", "one_invocation_only": False, "extra": True}
        for field, value in mutations.items():
            proposal = b.t.canonical({**self.proposal, "format_operation": {**self.proposal["format_operation"], field: value}})
            decision = {**self.decision, "proposal_sha256": b.t.sha(proposal)}
            with self.subTest(field=field), self.assertRaisesRegex(b.t.Blocked, "format_authorization"):
                self.validate(decision, proposal)
        for field in ("authorized", "one_invocation_only"):
            proposal = b.t.canonical({**self.proposal, "format_operation": {**self.proposal["format_operation"], field: 1}})
            decision = {**self.decision, "proposal_sha256": b.t.sha(proposal)}
            with self.subTest(integer_boolean=field), self.assertRaisesRegex(b.t.Blocked, "format_authorization"):
                self.validate(decision, proposal)
        for argv in (["/usr/sbin/mkfs.ext4", "-F", "-L", "clipforge-int-pg", "/dev/disk/by-id/google-clipforge-pg-data"],
                     ["/usr/sbin/mkfs.ext4", "-L", "clipforge-int-pg", "/dev/sdb"]):
            proposal = b.t.canonical({**self.proposal, "format_operation": {**self.proposal["format_operation"], "argv": argv}})
            decision = {**self.decision, "proposal_sha256": b.t.sha(proposal)}
            with self.subTest(argv=argv), self.assertRaisesRegex(b.t.Blocked, "format_authorization"):
                self.validate(decision, proposal)
        proposal = b.t.canonical({**self.proposal, "status": "preparation_only_blocked_before_activation"})
        decision = {**self.decision, "proposal_sha256": b.t.sha(proposal)}
        with self.assertRaisesRegex(b.t.Blocked, "proposal_blocks"):
            self.validate(decision, proposal)

    def test_preflight_rejects_wif_before_source_key_secret_or_network(self):
        with mock.patch.object(b.t, "_credential_document", return_value={}), \
             mock.patch.object(b.t, "validate_deploy_credentials", side_effect=b.t.Blocked("wrong WIF")), \
             mock.patch.object(b, "source_bindings") as source, mock.patch.object(b, "validate_tls") as tls, \
             mock.patch.object(b.t.Client, "request") as request, self.assertRaises(b.t.Blocked):
            b.preflight({}, b"{}", "x", b"{}", b"{}")
        source.assert_not_called(); tls.assert_not_called(); request.assert_not_called()

    def test_reviewed_source_closure_rejects_paths_duplicates_and_drift(self):
        for rows in ([{"path": "../outside", "sha256": "a" * 64}],
                     [{"path": "data/private.json", "sha256": "a" * 64}],
                     [{"path": "scripts/int_bootstrap_db.py", "sha256": "a" * 64}]):
            with mock.patch.object(b.t, "_local_bytes", return_value=b"owned fixture"), self.assertRaises(ValueError):
                b.source_bindings({"source_sha256": rows})

    def test_loader_contains_public_reviewed_source_only_and_no_secret_values(self):
        source = b"# authored operator fixture\n"
        loader = b.remote_loader(source, b.t.sha(source))
        self.assertTrue(loader.startswith("/usr/bin/sudo -n /usr/bin/python3 -I -c '"))
        self.assertIn("DB01_OPERATOR_SHA256", loader)
        with self.assertRaises(b.t.Blocked): b.remote_loader(source, b.t.sha(b"other"))
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory)
            (work / "known_hosts").write_text("owned synthetic host pin fixture\n")
            process = b.BootstrapProcesses(work, "/usr/bin/gcloud", b"authored observer", "owned", operator_source=source,
                operator_sha=b.t.sha(source), maximum_process_seconds=600)
            process.username = "sa_owned"
            process.bootstrap_input = b'{"secrets":"owned synthetic private sentinel"}'
            argv = b.bootstrap_ssh_command(work, "sa_owned", 32123, loader)
            self.assertEqual(process._kind(argv, process.bootstrap_input), "ssh")
            self.assertNotIn("owned synthetic private sentinel", " ".join(argv))
            with self.assertRaises(b.t.Blocked): process._kind(argv, b"different unapproved stdin")
            argv[-1] = "unreviewed command"
            with self.assertRaises(b.t.Blocked): process._kind(argv, process.bootstrap_input)

    def test_same_disk_check_allows_fresh_receipt_but_never_new_disk_boot_or_serial(self):
        at = datetime.now(timezone.utc).isoformat()
        baseline = {"disk_id": b.DISK_ID, "guest_serial": "owned", "boot_timestamp": "bound", "observed_utc": at,
                    "guest_read_receipt_sha256": b.t.sha(b"old"), "guest_read_source_sha256": b.t.sha(b"source")}
        fresh = {**baseline, "guest_read_receipt_sha256": b.t.sha(b"new")}
        b.same_disk_identity(baseline, fresh)
        for field in ("disk_id", "guest_serial", "boot_timestamp"):
            with self.subTest(field=field), self.assertRaises(b.t.Blocked): b.same_disk_identity(baseline, {**fresh, field: "other"})
        with self.assertRaises(b.t.Blocked):
            b.same_disk_identity(baseline, {**fresh, "observed_utc": (datetime.now(timezone.utc)-timedelta(seconds=301)).isoformat()})

    def test_phase_journal_contains_metadata_only_and_refuses_ambiguous_pending_write(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory); journal = {"operation_id": "a" * 32, "phases": []}
            b.phase(work, journal, "bootstrap", "started")
            self.assertEqual(json.loads((work / "db01-journal.json").read_bytes())["phases"][0]["status"], "started")
            (work / "db01-journal.next.json").write_bytes(b"owned unfinished write")
            with self.assertRaises(b.t.Blocked): b.phase(work, journal, "bootstrap", "completed")

    def test_changed_package_source_or_kernel_is_not_silently_adopted(self):
        import copy
        source = {"guest": {"packages_source": [["owned", "1", "installed", "all", "owned", "1", "owned"]],
                  "base_inventory": {"inventory": {"packages": [["owned", "1", "installed", "all"]], "os_release": {"ID": "debian"}, "kernel": "owned-kernel"}}}}
        b.same_observed_inputs(source, copy.deepcopy(source))
        fresh = copy.deepcopy(source); fresh["guest"]["packages_source"][0][1] = "2"
        with self.assertRaises(b.t.Blocked): b.same_observed_inputs(source, fresh)
        fresh = copy.deepcopy(source); fresh["guest"]["base_inventory"]["inventory"]["kernel"] = "other"
        with self.assertRaises(b.t.Blocked): b.same_observed_inputs(source, fresh)

    def test_cloud_clients_keep_vpc_roles_versions_and_no_retries_separate(self):
        records = [{"path": path, "sha256": b.t.sha(path.encode())} for path in sorted(acceptance.SOURCES)]
        versions = {"migrator_password": "1", "app_password": "2", "postgres_ca": "3"}
        image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + b.t.sha(b"owned OCI fixture")
        for phase, account, password in (("migrate", acceptance.ACCOUNTS["migrate"], "clipforge-int-pg-migrator-password"),
                                         ("app", acceptance.ACCOUNTS["app"], "clipforge-int-pg-app-password")):
            value = acceptance.job_spec(phase, image, versions, records, source=b"# owned public source fixture")
            task = value["template"]["template"]
            self.assertEqual((value["template"]["taskCount"], task["maxRetries"], task["serviceAccount"]), (1, 0, account))
            self.assertEqual(task["vpcAccess"]["networkInterfaces"], [{"network": "clipforge-int-base", "subnetwork": "clipforge-int-base-run"}])
            self.assertEqual(task["volumes"][0]["secret"]["secret"], password)
            self.assertNotIn("latest", json.dumps(value))
            self.assertNotIn(b.t.DEPLOY, json.dumps(value))
        with self.assertRaises(ValueError): acceptance.job_spec("app", image, {**versions, "app_password": "latest"}, records, source=b"owned")
        with self.assertRaises(ValueError): acceptance.execution_authority({}, "migrate")

    def test_native_receipt_exit_mismatch_preserves_unknown_operation(self):
        expected = {"operation_id": "a" * 32, "approved_commit": "b" * 40,
                    "proposal_sha256": b.t.sha(b"owned proposal"), "operator_sha256": b.t.sha(b"owned source")}
        receipt = {**expected, "exit_code": 0, "status": "configured_guest_verified_external_acceptance_pending"}
        with self.assertRaises(b.t.Blocked): b.checked_guest_result(receipt, 3, expected)
        journal = {"phases": [{"phase": "bootstrap", "status": "started"}]}
        self.assertEqual(b.failure_status(journal), "unknown_preserve_and_review")
        self.assertEqual(b.checked_guest_result(receipt, 0, expected), receipt)

    def test_cleanup_transport_failure_still_removes_only_known_tls_files(self):
        with tempfile.TemporaryDirectory() as directory:
            work = Path(directory); output = work / "reports"; output.mkdir()
            for name in ("db01-server.key", "db01-server.crt", "other-owned-retained"):
                (work / name).write_text("synthetic fixture, never a real private key")
            with mock.patch.object(b.t, "_validate_paths", return_value=(work, output)), \
                 mock.patch.object(b.t, "cleanup", side_effect=ValueError("synthetic transport failure")):
                result = b.cleanup({}, work, output)
            self.assertEqual(result["status"], "cleanup_unconfirmed_TTL_pending")
            self.assertFalse((work / "db01-server.key").exists())
            self.assertFalse((work / "db01-server.crt").exists())
            self.assertTrue((work / "other-owned-retained").exists())

    def test_specific_job_run_request_contains_only_reviewed_authority_overrides(self):
        records = [{"path": path, "sha256": b.t.sha(path.encode())} for path in sorted(acceptance.SOURCES)]
        versions = {"migrator_password": "1", "app_password": "2", "postgres_ca": "3"}
        image = "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:" + b.t.sha(b"owned OCI")
        source_sha = b.t.sha(b"owned client source")
        decision = {"schema": "clipforge-db01-client-decision-1", "status": "authorized_specific_job_execution", "owner": "admin@ixbalam.studio",
                    "job": acceptance.JOBS["app"], "phase": "app", "operation_id": "a" * 32, "source_sha256": source_sha,
                    "image": image, "secret_versions": versions, "app_sources": records, "guest_receipt_sha256": b.t.sha(b"owned guest receipt"),
                    "issued_utc": self.at.isoformat(), "expires_utc": (self.at+timedelta(minutes=30)).isoformat()}
        raw = json.dumps(decision, sort_keys=True)
        request = acceptance.job_run_request(raw, b.t.sha(raw.encode()), phase="app", image=image, versions=versions,
                                            app_sources=records, source_sha256=source_sha, now=self.at)
        overrides = request["body"]["overrides"]
        self.assertEqual(set(overrides), {"taskCount", "timeout", "containerOverrides"})
        self.assertEqual({row["name"] for row in overrides["containerOverrides"][0]["env"]}, {"INT_DB_CLIENT_DECISION_JSON", "INT_DB_CLIENT_DECISION_SHA256"})
        self.assertNotIn("args", json.dumps(request))
        with self.assertRaises(ValueError):
            acceptance.job_run_request(raw, b.t.sha(raw.encode()), phase="migrate", image=image, versions=versions,
                                       app_sources=records, source_sha256=source_sha, now=self.at)
        with self.assertRaises(ValueError): acceptance.decode('{"same":1,"same":2}')

    def test_migration_engine_sets_deadlines_on_its_own_connections_without_reusable_pool(self):
        engine, url = mock.Mock(), mock.Mock()
        sqlalchemy = ModuleType("sqlalchemy")
        sqlalchemy.URL = SimpleNamespace(create=mock.Mock(return_value=url))
        sqlalchemy.create_engine = mock.Mock(return_value=engine)
        pool = ModuleType("sqlalchemy.pool")
        pool.NullPool = type("AuthoredNullPool", (), {})
        options = {"host": "postgres", "port": 5432, "dbname": "clipforge", "user": "clipforge_migrator",
                   "password": "".join(chr(65 + i % 26) for i in range(48)), "sslmode": "verify-full",
                   "sslrootcert": "/run/db01/ca.crt", "connect_timeout": 999, "options": "-cstatement_timeout=0"}
        with mock.patch.dict(sys.modules, {"sqlalchemy": sqlalchemy, "sqlalchemy.pool": pool}):
            self.assertIs(acceptance.migration_engine(options), engine)
        kwargs = sqlalchemy.create_engine.call_args.kwargs
        self.assertIs(kwargs["poolclass"], pool.NullPool)
        self.assertFalse(kwargs["echo"])
        self.assertTrue(kwargs["hide_parameters"])
        self.assertEqual(kwargs["connect_args"], {"connect_timeout": 5, "sslmode": "verify-full",
            "sslrootcert": "/run/db01/ca.crt", "options": "-csearch_path=public -cstatement_timeout=15000 -clock_timeout=3000"})

    def test_migration_passes_receive_explicit_engine_and_dispose_even_after_failure(self):
        module = ModuleType("app.cloud.migrate")
        engine = mock.Mock()
        for fail in (False, True):
            module.upgrade = mock.Mock(side_effect=RuntimeError("authored failure") if fail else
                                      [{"status": "applied"}, {"status": "current"}])
            with self.subTest(fail=fail), mock.patch.dict(sys.modules, {"app.cloud.migrate": module}), \
                 mock.patch.object(acceptance, "migration_engine", return_value=engine):
                if fail:
                    with self.assertRaises(RuntimeError):
                        acceptance.apply_migrations({})
                else:
                    self.assertEqual(acceptance.apply_migrations({}), ({"status": "applied"}, {"status": "current"}))
            self.assertEqual(module.upgrade.call_args_list, [mock.call(engine)] * (1 if fail else 2))
            engine.dispose.assert_called_once()
            engine.reset_mock()

    def test_service_identity_reads_only_fixed_metadata_email_without_token(self):
        response = mock.MagicMock(); response.__enter__.return_value = response
        response.headers = {"Metadata-Flavor": "Google"}
        response.read.return_value = acceptance.ACCOUNTS["app"].encode()
        opener = mock.Mock(); opener.open.return_value = response
        with mock.patch.object(acceptance, "build_opener", return_value=opener):
            self.assertEqual(acceptance.observed_service_account(), acceptance.ACCOUNTS["app"])
        request = opener.open.call_args.args[0]
        self.assertEqual(request.full_url, acceptance.METADATA_EMAIL_URL)
        self.assertEqual(request.get_method(), "GET")
        self.assertEqual(request.get_header("Metadata-flavor"), "Google")
        self.assertIsNone(request.data)
        self.assertNotIn("Authorization", request.headers)
        self.assertEqual(opener.open.call_args.kwargs, {"timeout": 3})
        response.headers = {}
        with mock.patch.object(acceptance, "build_opener", return_value=opener), self.assertRaises(ValueError):
            acceptance.observed_service_account()

    def orchestration(self, *, ssh_exit=0, receipt_exit=0, cleanup_failure=False, process_failure=False,
                      containment_authorized=False, containment_unknown=False, lost_receipt=False,
                      scope_mismatch=False, insufficient_margin=False, containment_scope_mismatch=False, token_only_expiring=False):
        """Real launcher framing/finally with synthetic crypto, cloud and process boundaries."""
        import base64
        from contextlib import ExitStack
        from scripts import int_guest_db_observe as observer
        from scripts import int_bootstrap_vm as operator
        from scripts import int_bootstrap_containment as containment
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        work = Path(temporary.name); reports = work / "reports"; reports.mkdir()
        program = str(work / "gcloud")
        public = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
        source = b"# authored public operator fixture\n"
        containment_source = b"# authored public containment fixture; never executed\n"
        now = datetime.now(timezone.utc).isoformat()
        baseline = {"guest": {"packages_source": [], "base_inventory": {"inventory": {"packages": [], "os_release": {}, "kernel": {}}}}}
        proof = {"disk_id": b.DISK_ID, "observed_utc": now, "guest_boot_id": "owned_fixture_boot",
                 "guest_read_receipt_sha256": b.t.sha(b"owned observer receipt"), "guest_read_source_sha256": b.t.sha(b"owned observer source")}
        ready = {"decision": {"operation_id": "a"*32, "host_evidence_sha256": b.t.HOST_EVIDENCE_SHA, "proposal_sha256": b.t.sha(b"owned proposal"), "confirmation": "INITIALIZE_NEW_DISK_" + b.DISK_ID},
                 "source_bindings": {"scripts/int_bootstrap_vm.py": b.t.sha(source)}, "pin": {"known_hosts": b"owned public host fixture\n"},
                 "baseline": baseline, "baseline_proof": proof}
        env = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b"*40,
               "INT_DB_OBSERVATION_PAYLOAD_SHA256": b.t.sha(b"owned observer"), "INT_GCP_AUTH_STARTED_EPOCH": str(int(time.time()))}
        at=datetime.now(timezone.utc)
        proposal={**self.proposal,'target':{**self.proposal['target'],'zone':'us-central1-a'},
            'containment':containment.containment_policy(b.t.sha(containment_source),b.t.sha(source),authorized=containment_authorized)}
        # Deliberately noncanonical original bytes: the dispatch decision binds
        # the exact proposal, including whitespace, throughout containment.
        proposal_raw=json.dumps(proposal,indent=3).encode('ascii')
        decision={**self.decision,'operation_id':'a'*32,'approved_commit':env['GITHUB_SHA'],'proposal_sha256':b.t.sha(proposal_raw),
            'issued_utc':(at-timedelta(seconds=1)).isoformat(),'expires_utc':(at+timedelta(seconds=3599)).isoformat()}
        decision_raw=json.dumps(decision,indent=2).encode('ascii');decision_sha=b.t.sha(decision_raw)
        ready.update(decision=decision,proposal=proposal,proposal_raw=proposal_raw)
        ready['source_bindings']['scripts/int_bootstrap_containment.py']=b.t.sha(containment_source)
        statuses = {0: "configured_guest_verified_external_acceptance_pending", 2: "blocked", 3: "partial_preserved"}
        receipt = {"operation_id": "a"*32, "approved_commit": env["GITHUB_SHA"], "proposal_sha256": ready["decision"]["proposal_sha256"],
                   "operator_sha256": b.t.sha(source), "exit_code": receipt_exit, "status": statuses[receipt_exit],
                   "disk_id": b.DISK_ID, "guest_boot_id": proof["guest_boot_id"], "disk_proof_sha256": b.t.sha(b.t.canonical(proof)),
                   "guest_read_receipt_sha256": proof["guest_read_receipt_sha256"], "guest_read_source_sha256": proof["guest_read_source_sha256"]}
        receipt.update(finished_utc=at.isoformat(),journal_error_code=None,journal_sha256='c'*64,
            filesystem_uuid='12345678-1234-1234-1234-123456789abc',native_operations=[{
                'operation':'start','exit_code':0,'status':'ok','duration_ms':1,'stdout_bytes':0,'stderr_bytes':0,'messages':[],'unclassified_stderr_lines':0}])
        if scope_mismatch:receipt['operation_id']='f'*32
        class Client:
            actor_verified, profile_name = True, "owned_profile"
            def __init__(self, provider): self.provider = provider
            def request(self, *args): return {}
            def profile(self): return {"name": "owned_profile"}
            def arm_key(self, *args): pass
            def prepare_import(self): pass
            def import_key(self): return {"fingerprint": "OWNED_FINGERPRINT_001", "username": "sa_owned"}
        calls = []
        class Processes:
            username, bootstrap_input, loader, owned = None, None, "owned_public_loader", []
            def __init__(self, *args, **kwargs):
                self.closed = False;self.operator_source=kwargs['operator_source'];self.operator_sha=kwargs['operator_sha']
                self.containment_armed=self.containment_invoked=self.containment_inflight=False
            def arm_containment(self,*args):
                return REAL_PROCESSES.arm_containment(self,*args)
            def keygen_command(self): return ["owned-keygen"]
            def start_tunnel(self, port): calls.append("tunnel")
            def run(self, argv, input_data=None, **kwargs):
                calls.append((argv, input_data, kwargs))
                if argv == [program, "version", "--format=json"]: return 0, b'{"Google Cloud SDK":"582.0.0"}', b""
                if argv == ["owned-keygen"]:
                    (work / "id_ed25519").write_bytes(b"synthetic private fixture, not a real key"); (work / "id_ed25519").chmod(0o600)
                    (work / "id_ed25519.pub").write_bytes(public.encode()); return 0, b"", b""
                if input_data == b"owned observer":
                    self_test.assertEqual(kwargs["stdout_limit"], b.t.MAX_JSON)
                    return 0, b"{}", b""
                self_test.assertEqual(input_data, self.bootstrap_input)
                if self.containment_armed:
                    calls.append('containment_invoked')
                    payload=b.t.decode(input_data)
                    self_test.assertEqual(payload['proposal_json'].encode('ascii'),proposal_raw)
                    self_test.assertEqual(payload['owner_decision_json'].encode('ascii'),decision_raw)
                    self_test.assertNotIn('secrets',payload);self_test.assertEqual(kwargs['timeout'],100)
                    native={**receipt['native_operations'][0],'operation':'containment_stop'}
                    if containment_unknown:native.update(status='interrupted',exit_code=-9)
                    value={'schema':'clipforge-db01-containment-receipt-1','status':'stop_outcome_unknown_preserve_and_review' if containment_unknown else 'created_cluster_stopped_preserved',
                        'stop_attempted':True,'native_operations':[native],'data_reinitialized':False,'configuration_restored':False,'restart_attempted':False,
                        'IAM_or_state_written':False,'configuration_and_journal_preserved':not containment_unknown,'intent_creation_attempted':True,'intent_created':True,
                        'intent_path':containment.INTENT.as_posix(),'intent_sha256':'d'*64,'operation_id':receipt['operation_id'],'approved_commit':env['GITHUB_SHA'],
                        'owner_decision_sha256':decision_sha,'journal_sha256':receipt['journal_sha256']}
                    if not containment_unknown:value.update(filesystem_uuid=receipt['filesystem_uuid'],mount_preserved=True)
                    if containment_scope_mismatch:value['operation_id']='f'*32
                    return (1 if containment_unknown else 0),b.t.canonical(value),b''
                if insufficient_margin:clock['value']+=650
                if token_only_expiring:env['INT_GCP_AUTH_STARTED_EPOCH']=str(int(time.time())-650)
                return ssh_exit, (b'{}' if lost_receipt else b.t.canonical(receipt)), b""
            def close(self):
                self.closed = True
                calls.append('processes_closed')
                if process_failure: raise OSError("owned synthetic process close failure")
        self_test = self
        clock={'value':time.time()}
        stack = ExitStack(); self.addCleanup(stack.close)
        patches = [(b, "preflight", mock.Mock(return_value=ready)), (b, "validate_decision", mock.Mock()), (b, "validate_tls", mock.Mock(return_value={"status": "verified"})),
                   (b, "BootstrapProcesses", Processes), (b.t, "Client", Client), (b.t, "_validate_paths", mock.Mock(return_value=(work, reports))),
                   (b.t, "_local_bytes", mock.Mock(side_effect=lambda p,*args: source if p==b.OPERATOR
                        else containment_source if p==b.CONTAINMENT else proposal_raw if p==b.PROPOSAL else p.read_bytes())),
                   (b.t, "readinesscheck", mock.Mock(return_value={"payload": b"owned observer"})),
                   (b.t, "validate_compute_snapshot", mock.Mock(return_value={"unchanged": True})), (b.t, "parse_inventory", mock.Mock(return_value={})),
                   (observer, "make_evidence", mock.Mock(return_value=baseline)), (observer, "disk_proof", mock.Mock(return_value=proof)),
                   (operator, "validate_receipt", mock.Mock(side_effect=lambda value:value)), (b.shutil, "which", mock.Mock(return_value=program))]
        for target, name, value in patches: stack.enter_context(mock.patch.object(target,name,value))
        if insufficient_margin:stack.enter_context(mock.patch.object(b.time,'time',side_effect=lambda:clock['value']))
        original_stat = Path.stat
        def owned_stat(path, *args, **kwargs):
            value = original_stat(path,*args,**kwargs)
            if path == work / "id_ed25519":
                return os.stat_result(((value.st_mode & ~0o777) | 0o600, *value[1:]))
            return value
        stack.enter_context(mock.patch.object(Path,"stat",owned_stat))
        cleanup = mock.Mock(side_effect=OSError("synthetic transport failure")) if cleanup_failure else mock.Mock(return_value={"status":"own_key_removed"})
        stack.enter_context(mock.patch.object(b.t,"cleanup",cleanup))
        result = b.run(env,workdir=work,reports=reports,decision_raw=decision_raw,decision_sha=decision_sha,host_raw=b"{}",baseline_raw=b"{}",
                       protected_values={"app_password":"owned","migrator_password":"different","server_cert":"fixture","server_key":"fixture","ca_cert":"fixture"})
        self.assertTrue((reports / "db01-result.json").is_file())
        cleanup.assert_called_once()
        self.assertTrue(any(isinstance(call,tuple) and call[1] not in (None,b"owned observer") for call in calls), result)
        self.last_orchestration_calls=calls
        stack.close()
        return result

    def test_orchestration_partial_and_unknown_exits_never_turn_green(self):
        for code in (0,2,3):
            with self.subTest(code=code):
                result = self.orchestration(ssh_exit=code,receipt_exit=code)
                self.assertEqual(result["status"], {0:"configured_guest_verified_external_acceptance_pending",2:"blocked",3:"partial_preserved"}[code])
        result = self.orchestration(ssh_exit=3,receipt_exit=0)
        self.assertEqual(result["status"],"unknown_preserve_and_review")
        self.assertIn("exit_mismatch",result["error_code"])

    def test_orchestration_cleanup_errors_keep_sanitized_receipt_and_unknown_status(self):
        for options in ({"cleanup_failure":True},{"process_failure":True}):
            with self.subTest(options=options):
                result = self.orchestration(**options)
                self.assertEqual(result["status"],"unknown_preserve_and_review")
                self.assertTrue(result["phases"])

    def test_optional_containment_never_runs_on_success_unapproved_or_missing_receipt(self):
        for options in ({'containment_authorized':True},
                        {'ssh_exit':3,'receipt_exit':3},
                        {'ssh_exit':3,'receipt_exit':3,'containment_authorized':True,'lost_receipt':True},
                        {'ssh_exit':3,'receipt_exit':3,'containment_authorized':True,'scope_mismatch':True}):
            with self.subTest(options=options):
                result=self.orchestration(**options)
                self.assertFalse(result['containment'].get('ssh_attempted',False))
                self.assertNotIn('containment_invoked',self.last_orchestration_calls)
                self.assertIn('processes_closed',self.last_orchestration_calls)
                if options.get('scope_mismatch'):self.assertIs(result['guest_receipt_scope_verified'],False)

    def test_partial_authorized_containment_uses_same_transport_once_and_keeps_failure(self):
        result=self.orchestration(ssh_exit=3,receipt_exit=3,containment_authorized=True)
        self.assertEqual(result['status'],'partial_preserved',result)
        self.assertEqual(result['containment']['status'],'created_cluster_stopped_preserved',result)
        self.assertTrue(result['containment']['receipt_scope_verified'])
        self.assertEqual(result['bootstrap_ssh']['exit_code'],3)
        self.assertEqual(result['containment']['ssh']['exit_code'],0)
        self.assertEqual(self.last_orchestration_calls.count('containment_invoked'),1)
        self.assertEqual(self.last_orchestration_calls.count('tunnel'),1)
        self.assertEqual(sum(isinstance(row,tuple) and row[0]==['owned-keygen'] for row in self.last_orchestration_calls),1)
        self.assertLess(self.last_orchestration_calls.index('containment_invoked'),self.last_orchestration_calls.index('processes_closed'))

    def test_unknown_containment_keeps_native_exit_no_retry_and_cleans_up(self):
        result=self.orchestration(ssh_exit=3,receipt_exit=3,containment_authorized=True,containment_unknown=True)
        self.assertEqual(result['status'],'partial_preserved')
        self.assertEqual(result['containment']['status'],'stop_outcome_unknown_preserve_and_review')
        self.assertEqual(result['containment']['receipt']['native_operations'][0]['exit_code'],-9)
        self.assertEqual(self.last_orchestration_calls.count('containment_invoked'),1)
        self.assertEqual(result['cleanup']['status'],'own_key_removed')

    def test_insufficient_key_token_time_never_extends_or_attempts_containment(self):
        for option in ({'insufficient_margin':True},{'token_only_expiring':True}):
            with self.subTest(option=option):
                result=self.orchestration(ssh_exit=3,receipt_exit=3,containment_authorized=True,**option)
                self.assertEqual(result['status'],'partial_preserved')
                self.assertFalse(result['containment']['ssh_attempted'])
                self.assertIn('margin_insufficient',result['containment']['reason'])
                self.assertNotIn('containment_invoked',self.last_orchestration_calls)

    def test_containment_scope_mismatch_keeps_both_observed_exits_but_never_green(self):
        result=self.orchestration(ssh_exit=3,receipt_exit=3,containment_authorized=True,containment_scope_mismatch=True)
        self.assertEqual(result['status'],'partial_preserved')
        self.assertEqual(result['bootstrap_ssh']['exit_code'],3)
        self.assertEqual(result['containment']['ssh']['exit_code'],0)
        self.assertEqual(result['containment']['status'],'unknown_preserve_and_review')
        self.assertFalse(result['containment']['receipt_scope_verified'])
        self.assertIn('scope_mismatch',result['containment']['error_code'])
        self.assertEqual(self.last_orchestration_calls.count('containment_invoked'),1)

    def test_partial_intent_receipt_cannot_omit_its_operation_scope(self):
        result=self.orchestration(ssh_exit=3,receipt_exit=3,containment_authorized=True)
        value=dict(result['containment']['receipt'])
        decision_sha=value['owner_decision_sha256']
        value.pop('operation_id')
        value.update(status='blocked_before_stop',stop_attempted=False,native_operations=[],configuration_and_journal_preserved=False)
        with self.assertRaises(b.t.Blocked):
            b.checked_containment_result(value,1,result['guest_receipt'],decision_sha)

    def test_real_process_capability_consumes_containment_even_when_first_call_is_unknown(self):
        with tempfile.TemporaryDirectory(prefix='db01-finite-transport-') as directory:
            work=Path(directory);source=b'PUBLIC_OPERATOR = 1\n'
            (work/'known_hosts').write_text('public synthetic pin fixture\n')
            processes=REAL_PROCESSES(work,'/usr/bin/gcloud',b'public observer','own_fixture',operator_source=source,
                operator_sha=b.t.sha(source),maximum_process_seconds=600)
            processes.username='sa_owned';processes.bootstrap_input=b'closed authored metadata input'
            processes.containment_armed=True
            argv=b.bootstrap_ssh_command(work,'sa_owned',32123,processes.loader)
            with mock.patch.object(b.t.ProcessRunner,'run',side_effect=b.t.Blocked('local_process_timeout')) as run:
                with self.assertRaisesRegex(b.t.Blocked,'local_process_timeout'):
                    processes.run(argv,processes.bootstrap_input,timeout=100)
                with self.assertRaisesRegex(b.t.Blocked,'cannot_be_replayed'):
                    processes.run(argv,processes.bootstrap_input,timeout=100)
                with self.assertRaisesRegex(b.t.Blocked,'cannot_be_replayed'):
                    processes._kind(argv,processes.bootstrap_input)
                run.assert_called_once()


if __name__ == "__main__": unittest.main()
