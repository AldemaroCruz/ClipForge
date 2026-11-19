"""DB-01 candidate authority/transport fixtures; no GCP, SSH or disk operations."""
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest import mock

from scripts import int_bootstrap_db as b
from scripts import int_db_acceptance as acceptance


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

    def orchestration(self, *, ssh_exit=0, receipt_exit=0, cleanup_failure=False, process_failure=False):
        """Real launcher framing/finally with synthetic crypto, cloud and process boundaries."""
        import base64
        from contextlib import ExitStack
        from scripts import int_guest_db_observe as observer
        from scripts import int_bootstrap_vm as operator
        temporary = tempfile.TemporaryDirectory(); self.addCleanup(temporary.cleanup)
        work = Path(temporary.name); reports = work / "reports"; reports.mkdir()
        program = str(work / "gcloud")
        public = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode()
        source = b"# authored public operator fixture\n"
        now = datetime.now(timezone.utc).isoformat()
        baseline = {"guest": {"packages_source": [], "base_inventory": {"inventory": {"packages": [], "os_release": {}, "kernel": {}}}}}
        proof = {"disk_id": b.DISK_ID, "observed_utc": now, "guest_boot_id": "owned_fixture_boot",
                 "guest_read_receipt_sha256": b.t.sha(b"owned observer receipt"), "guest_read_source_sha256": b.t.sha(b"owned observer source")}
        ready = {"decision": {"operation_id": "a"*32, "host_evidence_sha256": b.t.HOST_EVIDENCE_SHA, "proposal_sha256": b.t.sha(b"owned proposal"), "confirmation": "INITIALIZE_NEW_DISK_" + b.DISK_ID},
                 "source_bindings": {"scripts/int_bootstrap_vm.py": b.t.sha(source)}, "pin": {"known_hosts": b"owned public host fixture\n"},
                 "baseline": baseline, "baseline_proof": proof}
        env = {"GITHUB_REPOSITORY": "AldemaroCruz/ClipForge", "GITHUB_RUN_ID": "12345", "GITHUB_RUN_ATTEMPT": "1", "GITHUB_SHA": "b"*40,
               "INT_DB_OBSERVATION_PAYLOAD_SHA256": b.t.sha(b"owned observer"), "INT_GCP_AUTH_STARTED_EPOCH": str(int(time.time()))}
        statuses = {0: "configured_guest_verified_external_acceptance_pending", 2: "blocked", 3: "partial_preserved"}
        receipt = {"operation_id": "a"*32, "approved_commit": env["GITHUB_SHA"], "proposal_sha256": ready["decision"]["proposal_sha256"],
                   "operator_sha256": b.t.sha(source), "exit_code": receipt_exit, "status": statuses[receipt_exit],
                   "disk_id": b.DISK_ID, "guest_boot_id": proof["guest_boot_id"], "disk_proof_sha256": b.t.sha(b.t.canonical(proof)),
                   "guest_read_receipt_sha256": proof["guest_read_receipt_sha256"], "guest_read_source_sha256": proof["guest_read_source_sha256"]}
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
            def __init__(self, *args, **kwargs): self.closed = False
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
                return ssh_exit, b.t.canonical(receipt), b""
            def close(self):
                self.closed = True
                if process_failure: raise OSError("owned synthetic process close failure")
        self_test = self
        stack = ExitStack(); self.addCleanup(stack.close)
        patches = [(b, "preflight", mock.Mock(return_value=ready)), (b, "validate_decision", mock.Mock()), (b, "validate_tls", mock.Mock(return_value={"status": "verified"})),
                   (b, "BootstrapProcesses", Processes), (b.t, "Client", Client), (b.t, "_validate_paths", mock.Mock(return_value=(work, reports))),
                   (b.t, "_local_bytes", mock.Mock(side_effect=lambda p,*args: source if p==b.OPERATOR
                        else self.raw_proposal if p==b.PROPOSAL else p.read_bytes())),
                   (b.t, "readinesscheck", mock.Mock(return_value={"payload": b"owned observer"})),
                   (b.t, "validate_compute_snapshot", mock.Mock(return_value={"unchanged": True})), (b.t, "parse_inventory", mock.Mock(return_value={})),
                   (observer, "make_evidence", mock.Mock(return_value=baseline)), (observer, "disk_proof", mock.Mock(return_value=proof)),
                   (operator, "validate_receipt", mock.Mock(side_effect=lambda value:value)), (b.shutil, "which", mock.Mock(return_value=program))]
        for target, name, value in patches: stack.enter_context(mock.patch.object(target,name,value))
        original_stat = Path.stat
        def owned_stat(path, *args, **kwargs):
            value = original_stat(path,*args,**kwargs)
            if path == work / "id_ed25519":
                return os.stat_result(((value.st_mode & ~0o777) | 0o600, *value[1:]))
            return value
        stack.enter_context(mock.patch.object(Path,"stat",owned_stat))
        cleanup = mock.Mock(side_effect=OSError("synthetic transport failure")) if cleanup_failure else mock.Mock(return_value={"status":"own_key_removed"})
        stack.enter_context(mock.patch.object(b.t,"cleanup",cleanup))
        result = b.run(env,workdir=work,reports=reports,decision_raw=b"{}",decision_sha=b.t.sha(b"owned decision"),host_raw=b"{}",baseline_raw=b"{}",
                       protected_values={"app_password":"owned","migrator_password":"different","server_cert":"fixture","server_key":"fixture","ca_cert":"fixture"})
        self.assertTrue((reports / "db01-result.json").is_file())
        cleanup.assert_called_once()
        self.assertTrue(any(isinstance(call,tuple) and call[1] not in (None,b"owned observer") for call in calls), result)
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


if __name__ == "__main__": unittest.main()
