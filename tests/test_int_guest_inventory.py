"""Authored evidence and mocked transport only; no GCP, SSH or VM operations."""
import base64
import copy
from contextlib import ExitStack
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock
from urllib.error import HTTPError
from urllib.parse import quote

from scripts import int_guest_inventory as inv
from scripts import int_guest_inventory_guest as guest
from tests import test_int_guest_inventory_guest as payload_tests


PUBLIC = "ssh-ed25519 " + base64.b64encode(b"\x00\x00\x00\x0bssh-ed25519\x00\x00\x00\x20" + bytes(range(32))).decode("ascii")
NONCE = "ab" * 32
FINGERPRINT = "AUTHORED_FINGERPRINT_001"


class GuestInventoryRunner(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory(prefix="clipforge-inventory-unit-")
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        (self.root / "scripts").mkdir()
        self.work = self.root / "own-run"
        self.work.mkdir()
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        # Any new I/O path fails closed unless that test explicitly mocks HTTP.
        self.stack.enter_context(mock.patch.object(inv, "build_opener", side_effect=AssertionError("network forbidden in unit fixture")))
        operator = b"# authored operator fixture, never executed\n"
        template = b"# authored publisher template, never executed\nBINDING = None\n"
        (self.root / "scripts/int_vm_hostkey.py").write_bytes(operator)
        (self.root / "scripts/int_vm_hostkey_guest.py").write_bytes(template)
        self.startup = "# authored unchanged startup, never executed\n"
        selectors = {"ROOT": self.root, "OPERATOR_SHA": inv.sha(operator), "HOST_GUEST_SHA": inv.sha(template),
                     "PUBLISHER_SHA": inv.sha(inv.host.render(template, NONCE)),
                     "PROPOSAL_SHA": inv.sha(b"authored proposal"), "OWNER_DECISION_SHA256": inv.sha(b"authored authorization"),
                     "STARTUP_SHA": inv.sha(self.startup.encode())}
        for name, value in selectors.items():
            self.stack.enter_context(mock.patch.object(inv, name, value))
        public, fingerprint = inv.host_guest.public_key(PUBLIC.encode())
        known = (inv.VM_NAME + "." + inv.host.IDENTITY["instance_id"] + " " + public + "\n").encode()
        self.bundle = {"schema": "clipforge-int-guest-hostkey-evidence-1", "original_proposal_sha256": inv.PROPOSAL_SHA,
            "operator_sha256": inv.OPERATOR_SHA, "guest_source_sha256": inv.HOST_GUEST_SHA,
            "publisher_sha256": inv.PUBLISHER_SHA, "identity": copy.deepcopy(inv.host.IDENTITY),
            "initial_last_start_timestamp": "2026-11-18T20:30:00Z", "observed_last_start_timestamp": "2026-11-18T21:30:00Z",
            "hostkey_record": {"schema": "clipforge-int-hostkey-record-1", **inv.host_guest.IDENTITY,
                "nonce": NONCE, "guest_source_sha256": inv.HOST_GUEST_SHA, "script_sha256": inv.PUBLISHER_SHA,
                "public_key": public, "fingerprint": fingerprint},
            "journal": {"sha256": inv.sha(b"authored complete journal"), "phase": "complete"},
            "restore": {"type": "setMetadata", "request_id": "12345678-1234-1234-1234-123456789abc",
                "operation": {"name": "authored-done", "id": "1234", "status": "DONE"}, "done_success": True},
            "known_hosts_sha256": inv.sha(known), "restored_startup_sha256": inv.STARTUP_SHA,
            "authorization": {"sha256": inv.OWNER_DECISION_SHA256, "approved_at": "2026-11-18T21:22:08Z",
                "expires_at": "2026-11-18T22:22:08Z", "completed_utc": "2026-11-18T21:31:00Z"}}
        commit = "a" * 40
        self.env = {"GITHUB_ACTIONS": "true", "GITHUB_REPOSITORY": "AldemaroCruz/ClipForge",
                    "GITHUB_REF": "refs/heads/ci/bootstrap-sec03", "GITHUB_EVENT_NAME": "workflow_dispatch",
                    "GITHUB_SHA": commit, "GUEST_APPROVED_COMMIT": commit, "GUEST_ENVIRONMENT": "int",
                    "GITHUB_RUN_ID": "123456", "GITHUB_RUN_ATTEMPT": "1", "GCP_PROJECT_ID": "clipforgebeta2",
                    "GCP_PROJECT_NUMBER": "816643438938", "GCP_REGION": "us-central1", "GCP_DEPLOY_SA": inv.DEPLOY,
                    "GCP_WIF_PROVIDER": inv.PROVIDER, "GOOGLE_APPLICATION_CREDENTIALS": str(self.work / "gha-creds-authored.json")}
        self.adc = {"type": "external_account", "audience": "//iam.googleapis.com/" + inv.PROVIDER,
                    "token_url": "https://sts.googleapis.com/v1/token",
                    "service_account_impersonation_url": "https://iamcredentials.googleapis.com/v1/projects/-/serviceAccounts/" + inv.DEPLOY + ":generateAccessToken",
                    "credential_source": {"url": "https://invalid.example/oidc", "format": {"type": "json", "subject_token_field_name": "value"}}}

    def pin(self, bundle=None):
        raw = inv.canonical(self.bundle if bundle is None else bundle)
        # Select honest authored bytes; never pretend they hash to real evidence.
        with mock.patch.object(inv, "HOST_EVIDENCE_SHA", inv.sha(raw)):
            return inv.validate_hostkey_bundle(raw, inv.sha(raw))

    def profile(self, *, key=True, expiration=100000001):
        value = {"name": "users/" + inv.DEPLOY_UNIQUE_ID, "posixAccounts": [
            {"username": "sa_clipforge", "uid": "10001", "operatingSystemType": "LINUX", "primary": True}],
            "sshPublicKeys": {}}
        if key:
            value["sshPublicKeys"][FINGERPRINT] = {"key": PUBLIC, "fingerprint": FINGERPRINT,
                                                    "expirationTimeUsec": str(expiration)}
        return value

    def snapshot(self):
        host = inv.host
        link = "https://www.googleapis.com"
        metadata = {**host.SECURITY, "startup-script": self.startup}
        vm = {"id": host.IDENTITY["instance_id"], "name": inv.VM_NAME, "selfLink": link + host.VM,
              "zone": link + host.ZONE, "creationTimestamp": host.IDENTITY["creation_timestamp"], "status": "RUNNING",
              "lastStartTimestamp": self.bundle["observed_last_start_timestamp"],
              "metadata": {"fingerprint": "authored-fingerprint", "items": [{"key": k, "value": v} for k, v in metadata.items()]},
              "networkInterfaces": [{"networkIP": "10.80.1.2", "accessConfigs": [], "ipv6AccessConfigs": []}],
              "disks": [{"boot": True, "autoDelete": False, "source": link + host.ZONE + "/disks/" + inv.VM_NAME},
                        {"boot": False, "autoDelete": False, "source": link + host.ZONE + "/disks/" + inv.VM_NAME + "-data"}]}
        disks = [{"id": host.IDENTITY[key], "name": name, "status": "READY", "selfLink": link + host.ZONE + "/disks/" + name,
                  "users": [link + host.VM], "sourceImageId": host.IDENTITY["image_id"]}
                 for key, name in (("boot_disk_id", inv.VM_NAME), ("data_disk_id", inv.VM_NAME + "-data"))]
        return vm, *disks

    def test_host_pin_requires_completed_restoration_and_bound_nonce(self):
        pin = self.pin()
        self.assertEqual(pin["known_hosts"], (inv.VM_NAME + ".1670495097211408131 " + PUBLIC + "\n").encode())
        for mutate in (lambda b: b["journal"].update(phase="restore_pending"),
                       lambda b: b["restore"].update(done_success=False),
                       lambda b: b["restore"]["operation"].update(status="RUNNING"),
                       lambda b: b["hostkey_record"].update(nonce="cd" * 32),
                       lambda b: b["hostkey_record"].update(fingerprint="SHA256:wrong"),
                       lambda b: b.update(observed_last_start_timestamp=b["initial_last_start_timestamp"]),
                       lambda b: b.update(known_hosts_sha256="0" * 64),
                       lambda b: b.update(restored_startup_sha256="0" * 64),
                       lambda b: b["authorization"].update(completed_utc="2026-11-18T22:22:08Z"),
                       lambda b: b["identity"].update(instance_id="1")):
            value = copy.deepcopy(self.bundle); mutate(value)
            with self.subTest(mutate=mutate), self.assertRaises(ValueError):
                self.pin(value)
        (self.root / "scripts/int_vm_hostkey.py").write_bytes(b"changed authored operator")
        with self.assertRaisesRegex(inv.Blocked, "frozen_host_operator_changed"):
            self.pin()

    def test_wif_deploy_selection_is_strict_and_does_not_claim_effective_identity(self):
        value = inv.validate_deploy_credentials(self.env, self.adc)
        self.assertEqual(value["configured_service_account"], "clipforge-deploy-int@clipforgebeta2.iam.gserviceaccount.com")
        self.assertFalse(value["configured_identity_is_effective_identity"])
        self.assertNotIn("credential_source", value)
        env_cases = {"GCP_DEPLOY_SA": "admin@example.invalid", "GCP_WIF_PROVIDER": "wrong-provider",
                     "GITHUB_REF": "refs/heads/main", "GUEST_APPROVED_COMMIT": "b" * 40,
                     "GOOGLE_APPLICATION_CREDENTIALS": str(self.work / "personal.json"),
                     "GOOGLE_GHA_CREDS_PATH": str(self.work / "gha-creds-different.json"),
                     "CLOUDSDK_AUTH_IMPERSONATE_SERVICE_ACCOUNT": "admin@example.invalid",
                     "GOOGLE_CREDENTIALS": "authored-private-content", "TF_VAR_project_id": "unreviewed"}
        for key, value in env_cases.items():
            with self.subTest(key=key), self.assertRaises(inv.Blocked):
                inv.validate_deploy_credentials({**self.env, key: value}, self.adc)
        for update in ({"type": "service_account"}, {"audience": "wrong"}, {"token_url": "https://invalid.example/token"},
                       {"service_account_impersonation_url": self.adc["service_account_impersonation_url"].replace("clipforge-deploy-int", "clipforge-terraform-int")},
                       {"private_key": "authored fixture"}, {"credential_source": {"executable": {"command": "unreviewed"}}}):
            with self.subTest(update=update), self.assertRaises(inv.Blocked):
                inv.validate_deploy_credentials(self.env, {**self.adc, **update})

    def test_only_execution_owned_sdk_configuration_is_allowed(self):
        temporary = self.root / "runner-temp"
        temporary.mkdir()
        work = temporary / "clipforge-guest-inventory.authored"
        work.mkdir()
        sdk = work / "gcloud"
        sdk.mkdir()
        env = {**self.env, "RUNNER_TEMP": str(temporary), "GUEST_WORK": str(work), "CLOUDSDK_CONFIG": str(sdk)}
        self.assertEqual(inv.validate_deploy_credentials(env, self.adc)["source"], "external_account_WIF")
        for change in ({"CLOUDSDK_CONFIG": str(self.root / "ambient-sdk")},
                       {"CLOUDSDK_CONFIG": str(work / "other")}, {"GUEST_WORK": str(temporary / "wrong-prefix")},
                       {"GUEST_WORK": str(self.root / "clipforge-guest-inventory.outside")}, {"RUNNER_TEMP": "relative"}):
            with self.subTest(change=change), self.assertRaises(inv.Blocked):
                inv.validate_deploy_credentials({**env, **change}, self.adc)
        with mock.patch.object(Path, "is_symlink", return_value=True), self.assertRaises(inv.Blocked):
            inv.validate_deploy_credentials(env, self.adc)

    def test_current_vm_and_disks_must_match_restored_new_boot(self):
        vm, boot, data = self.snapshot()
        self.assertTrue(inv.validate_compute_snapshot(vm, boot, data, self.pin())["startup_restored"])
        cases = [("vm", "status", "TERMINATED"), ("vm", "lastStartTimestamp", "2026-11-18T21:32:00Z"),
                 ("vm", "id", "1"), ("boot", "id", "1"), ("data", "id", "1"), ("boot", "sourceImageId", "1")]
        for target, key, value in cases:
            rows = dict(zip(("vm", "boot", "data"), self.snapshot()))
            rows[target][key] = value
            with self.subTest(target=target, key=key), self.assertRaises(ValueError):
                inv.validate_compute_snapshot(rows["vm"], rows["boot"], rows["data"], self.pin())
        for key, value in (("startup-script", "changed"), ("enable-guest-attributes", "TRUE"), ("startup-script-url", "gs://unreviewed/script")):
            vm, boot, data = self.snapshot()
            if key == "startup-script":
                next(row for row in vm["metadata"]["items"] if row["key"] == key)["value"] = value
            else:
                vm["metadata"]["items"].append({"key": key, "value": value})
            with self.subTest(key=key), self.assertRaises(ValueError):
                inv.validate_compute_snapshot(vm, boot, data, self.pin())

    def test_http_capabilities_reject_before_token_or_network(self):
        token = mock.Mock(return_value="authored-short-lived-token")
        client = inv.Client(token)
        cases = [("POST", inv.VM_URL + "/stop", {}), ("POST", inv.VM_URL + "/setMetadata", {}),
                 ("DELETE", inv.DATA_URL, None), ("GET", "https://invalid.example/", None),
                 ("GET", inv.VM_URL.replace("clipforgebeta2", "other-project"), None),
                 ("GET", inv.PROFILE_URL.replace(inv.DEPLOY_UNIQUE_ID, "me"), None),
                 ("GET", inv.PROFILE_URL, {}), ("POST", inv.IMPORT_URL, {"key": PUBLIC}),
                 ("DELETE", inv.OSLOGIN_USER + "/sshPublicKeys/foreign-fingerprint", None),
                 ("POST", "https://storage.googleapis.com/upload/storage/v1/b/clipforgebeta2-tfstate-int/o", {})]
        with mock.patch.object(inv, "build_opener") as opener:
            for method, url, body in cases:
                with self.subTest(method=method, url=url), self.assertRaisesRegex(inv.Blocked, "before_token"):
                    client.request(method, url, body)
        token.assert_not_called(); opener.assert_not_called()

    def test_own_key_ttl_is_at_most_fifteen_minutes_and_one_import(self):
        client = inv.Client(lambda: "authored-short-lived-token")
        now = 100
        for expiry in (int(now * 1000000), int((now + 901) * 1000000), True):
            with self.subTest(expiry=expiry), self.assertRaises(inv.Blocked):
                client.arm_key(PUBLIC, expiry, now=now)
        client.arm_key(PUBLIC, 100000001, now=now)
        with self.assertRaisesRegex(inv.Blocked, "already_armed"):
            client.arm_key(PUBLIC, 100000001, now=now)
        with self.assertRaisesRegex(inv.Blocked, "before_token"):
            client.request("POST", inv.IMPORT_URL, {"key": PUBLIC, "expirationTimeUsec": "100000001"})
        absent_reply, import_reply = mock.MagicMock(), mock.MagicMock()
        absent_reply.__enter__.return_value.read.return_value = inv.canonical(self.profile(key=False))
        import_reply.__enter__.return_value.read.return_value = inv.canonical({"loginProfile": self.profile()})
        opener = mock.Mock(); opener.open.side_effect = [absent_reply, import_reply]
        with mock.patch.object(inv, "build_opener", return_value=opener):
            self.assertEqual(client.import_key(), {"fingerprint": FINGERPRINT, "username": "sa_clipforge"})
            with self.assertRaisesRegex(inv.Blocked, "before_token"):
                client.import_key()
        self.assertEqual(opener.open.call_count, 2)
        self.assertEqual(opener.open.call_args_list[0].args[0].method, "GET")
        self.assertEqual(opener.open.call_args_list[0].args[0].full_url, inv.PROFILE_URL)
        request = opener.open.call_args.args[0]
        self.assertEqual((request.method, request.full_url), ("POST", inv.IMPORT_URL))
        self.assertEqual(json.loads(request.data), {"key": PUBLIC, "expirationTimeUsec": "100000001"})

    def test_preexisting_public_key_with_any_expiration_is_never_owned_or_imported(self):
        for expiration in (100000001, 999, 999999999999):
            with self.subTest(expiration=expiration):
                client = inv.Client(lambda: "authored-short-lived-token")
                client.arm_key(PUBLIC, 100000001, now=100)
                with mock.patch.object(client, "request", return_value=self.profile(expiration=expiration)) as request:
                    with self.assertRaisesRegex(inv.Blocked, "preexisting_oslogin_key_not_owned"):
                        client.import_key()
                    self.assertEqual(request.call_args_list, [mock.call("GET", inv.PROFILE_URL)])
                    self.assertFalse(client.import_attempted)
                    self.assertFalse(client.key_absent_before_import)
                    client.fingerprint = FINGERPRINT
                    with self.assertRaisesRegex(inv.Blocked, "delete_only_confirmed"):
                        client.delete_own_key(FINGERPRINT)
                    self.assertEqual(request.call_count, 1)

    def test_oslogin_profile_identity_and_exact_key_fingerprint_are_required(self):
        profile = self.profile()
        self.assertEqual(inv.validate_import_response({"loginProfile": profile}, PUBLIC, 100000001)["fingerprint"], FINGERPRINT)
        self.assertFalse(inv.validate_deploy_profile(profile)["OAuth_token_subject_introspected"])
        for mutate in (lambda p: p.update(name="users/999999999999999999999"),
                       lambda p: p["sshPublicKeys"][FINGERPRINT].update(expirationTimeUsec="100000002"),
                       lambda p: p["sshPublicKeys"][FINGERPRINT].update(fingerprint="wrong-fingerprint"),
                       lambda p: p["sshPublicKeys"].update({"DUPLICATE_FINGERPRINT_001": p["sshPublicKeys"][FINGERPRINT]}),
                       lambda p: p["posixAccounts"][0].update(username="root"),
                       lambda p: p["posixAccounts"].append(copy.deepcopy(p["posixAccounts"][0]))):
            row = self.profile(); mutate(row)
            with self.subTest(mutate=mutate), self.assertRaises(inv.Blocked):
                inv.validate_import_response({"loginProfile": row}, PUBLIC, 100000001)

    def test_http_failure_bounds_private_body_and_only_publishes_closed_diagnostic(self):
        token = "authored-short-lived-token"
        body = mock.Mock()
        body.read.return_value = inv.canonical({"error": {"message": "authored-private-server-message compute.instances.get",
            "details": [{"reason": "IAM_PERMISSION_DENIED", "private": "authored-private-sentinel"}]}})
        error = HTTPError(inv.VM_URL, 403, "authored-private-server-message", {"private-header": "sentinel"}, body)
        opener = mock.Mock(); opener.open.side_effect = error
        with mock.patch.object(inv, "build_opener", return_value=opener), self.assertRaises(inv.Blocked) as failure:
            inv.Client(lambda: token).request("GET", inv.VM_URL)
        self.assertEqual(str(failure.exception), "cloud_http_403")
        self.assertNotIn(token, str(failure.exception))
        body.read.assert_called_once_with(16384)
        self.assertEqual(failure.exception.receipt["permissions"], ["compute.instances.get"])
        self.assertTrue(failure.exception.receipt["response_body_withheld"])
        self.assertNotIn("authored-private", json.dumps(failure.exception.receipt))

    def test_cleanup_confirms_public_key_ttl_and_fingerprint_before_delete(self):
        client = inv.Client(lambda: "authored-short-lived-token")
        client.arm_key(PUBLIC, 100000001, now=100)
        client.fingerprint = FINGERPRINT
        client.key_absent_before_import = True
        with mock.patch.object(client, "profile", side_effect=[self.profile(), self.profile(key=False)]) as profile, \
             mock.patch.object(client, "request", return_value={}) as request:
            self.assertEqual(client.delete_own_key(FINGERPRINT), {"removed_exact_own_key": True})
        self.assertEqual(profile.call_count, 2)
        request.assert_called_once_with("DELETE", inv.OSLOGIN_USER + "/sshPublicKeys/" + quote(FINGERPRINT, safe=""))
        for profile in (self.profile(key=False), self.profile(expiration=100000002)):
            with self.subTest(profile=profile), mock.patch.object(client, "profile", return_value=profile), \
                 mock.patch.object(client, "request") as request, self.assertRaises(inv.Blocked):
                client.delete_own_key(FINGERPRINT)
            request.assert_not_called()
        with mock.patch.object(client, "request") as request, self.assertRaises(inv.Blocked):
            client.delete_own_key("FOREIGN_FINGERPRINT_001")
        request.assert_not_called()

    def test_direct_delete_without_fresh_exact_profile_is_denied_before_token(self):
        token = mock.Mock(return_value="authored-short-lived-token")
        client = inv.Client(token)
        client.arm_key(PUBLIC, 100000001, now=100)
        client.actor_verified = client.key_absent_before_import = True
        client.fingerprint = FINGERPRINT
        with self.assertRaisesRegex(inv.Blocked, "before_token"):
            client.request("DELETE", inv.OSLOGIN_USER + "/sshPublicKeys/" + quote(FINGERPRINT, safe=""))
        token.assert_not_called()

    def test_unknown_stderr_is_counted_without_publishing_arbitrary_error_lines(self):
        private = b"ERROR: authored-private-sentinel\nPermission denied (publickey).\n"
        value = inv.process_diagnostic(private)
        self.assertNotIn("authored-private-sentinel", json.dumps(value))
        self.assertEqual(value["stderr_sha256"], inv.sha(private))
        self.assertEqual(value["stderr_bytes"], len(private))
        self.assertGreaterEqual(value["unclassified_lines"], 1)
        self.assertTrue(any("Permission denied" in message for message in value["messages"]))

    def test_ssh_and_tunnel_commands_are_fixed_and_strict(self):
        (self.work / "known_hosts").write_bytes(self.pin()["known_hosts"])
        command = inv.ssh_command(self.work, "sa_clipforge", 32123)
        self.assertEqual(command[-2:], ["127.0.0.1", "/usr/bin/sudo -n /usr/bin/python3 -I -"])
        for option in ("-F", "/dev/null", "-oStrictHostKeyChecking=yes", "-oUpdateHostKeys=no", "-oHostKeyAlgorithms=ssh-ed25519",
                       "-oBatchMode=yes", "-oIdentityAgent=none", "-oIdentitiesOnly=yes", "-oPermitLocalCommand=no",
                       "-oPasswordAuthentication=no", "-oForwardAgent=no"):
            self.assertIn(option, command)
        tunnel = inv.tunnel_command(str(self.root / "gcloud"), 32123)
        self.assertEqual(tunnel[1:5], ["compute", "start-iap-tunnel", inv.VM_NAME, "22"])
        self.assertIn("--account=" + inv.DEPLOY, tunnel)
        self.assertIn("--local-host-port=127.0.0.1:32123", tunnel)
        runner = inv.ProcessRunner(self.work, str(self.root / "gcloud"), b"authored payload", "authored-run")
        runner.username = "sa_clipforge"
        self.assertEqual(runner._kind(command, b"authored payload"), "ssh")
        for argv, data in ((command + ["; arbitrary"], b"authored payload"), (command, b"changed payload"),
                           (["/usr/bin/ssh", "unreviewed"], None), (["/usr/bin/python3", "-c", "pass"], None)):
            with self.subTest(argv=argv), self.assertRaises(inv.Blocked):
                runner._kind(argv, data)
        for name, port in (("root", 32123), ("sa;command", 32123), ("sa_clipforge", 0), ("sa_clipforge", True)):
            with self.subTest(name=name, port=port), self.assertRaises(inv.Blocked):
                inv.ssh_command(self.work, name, port)

    def test_report_protocol_preserves_safety_stop_and_failure(self):
        good = payload_tests.collect()
        self.assertEqual(inv.parse_inventory(guest.encoded(good), 0), good)
        for key, raw in (("clusters", b"17 main 5432 down postgres data log\n"),
                         ("kernel", b"unparseable kernel\x00")):
            report = payload_tests.collect(payload_tests.AuthoredRunner({key: raw}))
            self.assertEqual(inv.parse_inventory(guest.encoded(report), report["exit_code"]), report)
            with self.assertRaises(inv.Blocked):
                inv.parse_inventory(guest.encoded(report), 0)
        good["environment"] = {"private": "sentinel"}
        with self.assertRaises(ValueError):
            inv.parse_inventory(guest.encoded(good), 0)

    def test_process_cleanup_rejects_foreign_processes(self):
        runner = inv.ProcessRunner(self.work, str(self.root / "gcloud"), b"payload", "authored-run")
        with mock.patch.object(inv.os, "killpg", create=True) as kill, self.assertRaises(inv.Blocked):
            runner.stop(mock.Mock(pid=987654))
        kill.assert_not_called()
        own = mock.Mock(pid=123456)
        own.poll.return_value = None
        runner.owned.append(own)
        with mock.patch.object(inv.os, "killpg", create=True) as kill:
            runner.close()
        kill.assert_called_once_with(123456, inv.signal.SIGTERM)
        own.wait.assert_called_once_with(timeout=3)

    def test_process_runner_caps_while_running_and_closes_owned_group(self):
        runner = inv.ProcessRunner(self.work, str(self.root / "gcloud"), b"authored payload", "authored-run")
        process = mock.Mock(pid=654320, stdin=None)
        process.poll.return_value = None
        process.stdout.closed = process.stderr.closed = False
        process.stdout.fileno.return_value, process.stderr.fileno.return_value = 10, 11
        runner.owned.append(process)
        selector = mock.Mock()
        selector.get_map.return_value = {10: True}
        selector.select.return_value = [(SimpleNamespace(data="stdout", fileobj=process.stdout), 1)]
        with mock.patch.object(runner, "_start", return_value=process), \
             mock.patch.object(inv.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(inv.os, "set_blocking", create=True), mock.patch.object(inv.os, "read", return_value=b"12345"), \
             mock.patch.object(inv.os, "killpg", create=True) as kill, self.assertRaisesRegex(inv.Blocked, "output_limit"):
            runner.run([runner.gcloud, "version", "--format=json"], stdout_limit=4, stderr_limit=2)
        kill.assert_called_once_with(654320, inv.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=3)
        process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_process_runner_timeout_reaps_and_unreviewed_argv_never_starts(self):
        runner = inv.ProcessRunner(self.work, str(self.root / "gcloud"), b"authored payload", "authored-run")
        process = mock.Mock(pid=654322, stdin=None)
        process.poll.return_value = None
        process.stdout.closed = process.stderr.closed = False
        runner.owned.append(process)
        selector = mock.Mock(); selector.get_map.return_value = {10: True}
        with mock.patch.object(runner, "_start", return_value=process), \
             mock.patch.object(inv.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(inv.os, "set_blocking", create=True), \
             mock.patch.object(inv.time, "monotonic", side_effect=[0, 31]), \
             mock.patch.object(inv.os, "killpg", create=True) as kill, self.assertRaisesRegex(inv.Blocked, "timeout"):
            runner.run([runner.gcloud, "version", "--format=json"], timeout=30)
        kill.assert_called_once_with(654322, inv.signal.SIGTERM)
        process.wait.assert_called_once_with(timeout=3)
        with mock.patch.object(runner, "_start") as start, self.assertRaises(inv.Blocked):
            runner.run(["/usr/bin/python3", "-c", "unreviewed"])
        start.assert_not_called()

    def orchestration(self, *, guest_report=None, ssh_error=None, unknown_import=False, collision=False, close_error=False):
        """Real orchestration/cleanup, with explicit OS/HTTP/process boundaries."""
        test = self
        vm, boot, data = self.snapshot()
        class AuthoredClient(inv.Client):
            def __init__(self):
                super().__init__(lambda: "authored-short-lived-token")
                self.calls, self.present = [], collision

            def request(self, method, url, payload=None):
                self.calls.append((method, url, copy.deepcopy(payload)))
                if method == "GET" and url in {inv.VM_URL, inv.BOOT_URL, inv.DATA_URL}:
                    return copy.deepcopy({inv.VM_URL: vm, inv.BOOT_URL: boot, inv.DATA_URL: data}[url])
                if method == "GET" and url == inv.PROFILE_URL:
                    return test.profile(key=self.present, expiration=999 if collision else self.expiration_us)
                if method == "POST" and url == inv.IMPORT_URL:
                    if not self.key_absent_before_import or self.import_attempted:
                        raise AssertionError("unreviewed synthetic import")
                    self.import_attempted, self.present = True, True
                    if unknown_import:
                        raise inv.Failure("authored_import_response_unknown", {"operation": "POST OSLogin", "http_status": 500})
                    return {"loginProfile": test.profile(expiration=self.expiration_us)}
                if method == "DELETE" and url == inv.OSLOGIN_USER + "/sshPublicKeys/" + quote(FINGERPRINT, safe=""):
                    if not self.key_absent_before_import or not self.present:
                        raise AssertionError("unowned synthetic deletion")
                    self.present = False
                    return {}
                raise AssertionError("unexpected synthetic capability")
        class AuthoredProcesses:
            def __init__(self):
                self.calls, self.closed, self.username = [], False, None

            def keygen_command(self):
                return ["/usr/bin/ssh-keygen", "authored-fixed-boundary"]

            def run(self, argv, input_data=None, **bounds):
                self.calls.append((argv, input_data, bounds))
                if argv == [program, "version", "--format=json"]:
                    return 0, inv.canonical({"Google Cloud SDK": "582.0.0"}), b""
                if argv == self.keygen_command():
                    (test.work / "id_ed25519").write_bytes(b"authored private fixture, never a real key")
                    (test.work / "id_ed25519.pub").write_bytes(PUBLIC.encode())
                    return 0, b"", b""
                if argv == inv.ssh_command(test.work, self.username, 32123) and input_data == b"authored payload":
                    if ssh_error is not None:
                        raise ssh_error
                    report = guest_report or payload_tests.collect()
                    return report["exit_code"], guest.encoded(report), b""
                raise AssertionError("unreviewed synthetic process")

            def start_tunnel(self, port):
                test.assertEqual(port, 32123)
                self.calls.append(("tunnel", port))

            def close(self):
                self.closed = True
                if close_error:
                    raise OSError("authored private close diagnostic")
        client, processes = AuthoredClient(), AuthoredProcesses()
        output = self.root / "own-reports"
        output.mkdir()
        program = str(self.root / "gcloud")
        ready = {"pin": self.pin(), "payload": b"authored payload", "payload_sha256": inv.sha(b"authored payload"),
                 "credential_selection": inv.validate_deploy_credentials(self.env, self.adc)}
        reserved = mock.MagicMock()
        reserved.__enter__.return_value.getsockname.return_value = ("127.0.0.1", 32123)
        with mock.patch.object(inv, "readinesscheck", return_value=ready), \
             mock.patch.object(inv, "_credential_document", return_value=self.adc), \
             mock.patch.object(inv, "_validate_paths", return_value=(self.work, output)), \
             mock.patch.object(inv, "_local_bytes", side_effect=lambda p, *_: p.read_bytes()), \
             mock.patch.object(inv.shutil, "which", return_value=program), \
             mock.patch.object(inv.socket, "socket", return_value=reserved), \
             mock.patch.object(inv.signal, "signal"), \
             mock.patch.object(inv.os, "chmod"), \
             mock.patch.object(inv.stat, "S_IMODE", return_value=0o600):
            # POSIX path/mode and process creation are boundary mocks on Windows.
            result = inv.run(environ=self.env, workdir=self.work, reports=output,
                             host_evidence_raw=b"authored selected evidence", host_evidence_sha=inv.sha(b"authored selected evidence"),
                             payload_sha=ready["payload_sha256"], client=client, processes=processes)
        return result, client, processes, output

    def assert_own_cleanup(self, result, client, processes):
        self.assertTrue(processes.closed)
        self.assertFalse(client.present)
        self.assertEqual(result["cleanup"]["status"], "own_key_removed")
        for name in ("id_ed25519", "id_ed25519.pub", "known_hosts"):
            self.assertFalse((self.work / name).exists())
        self.assertEqual(sum(method == "POST" for method, _, _ in client.calls), 1)
        deletions = [url for method, url, _ in client.calls if method == "DELETE"]
        self.assertEqual(deletions, [inv.OSLOGIN_USER + "/sshPublicKeys/" + quote(FINGERPRINT, safe="")])
        self.assertFalse(result["runtime_authorized"])
        self.assertFalse(result["database_initialized"])

    def test_orchestration_completes_with_exact_cleanup_and_no_vm_writes(self):
        result, client, processes, output = self.orchestration()
        self.assertEqual(result["status"], "inventory_complete")
        self.assert_own_cleanup(result, client, processes)
        self.assertEqual(json.loads((output / "inventory.json").read_bytes())["status"], "inventory_complete")
        self.assertEqual(json.loads((output / "guest-summary.json").read_bytes()), result)
        self.assertFalse(any("PRIVATE" in value for value in (output / "guest-summary.json").read_text().split()))
        compute = [(method, url) for method, url, _ in client.calls if "compute.googleapis.com" in url]
        self.assertEqual(len(compute), 6)
        self.assertTrue(all(method == "GET" for method, _ in compute))

    def test_safety_stop_remains_failure_but_still_cleans_own_key(self):
        report = payload_tests.collect(payload_tests.AuthoredRunner({"clusters": b"17 main 5432 down postgres data log\n"}))
        result, client, processes, _ = self.orchestration(guest_report=report)
        self.assertEqual((result["status"], result["guest_exit_code"]), ("safety_stop", 2))
        self.assert_own_cleanup(result, client, processes)

    def test_ssh_interruption_cleans_key_and_private_files_without_retry(self):
        result, client, processes, output = self.orchestration(ssh_error=inv.Blocked("local_process_timeout"))
        self.assertEqual((result["status"], result["error_code"]), ("blocked", "local_process_timeout"))
        self.assert_own_cleanup(result, client, processes)
        self.assertFalse((output / "inventory.json").exists())
        self.assertEqual(sum(isinstance(row[0], list) and row[0][0] == "/usr/bin/ssh" for row in processes.calls), 1)

    def test_unknown_import_response_is_resolved_by_exact_read_delete_not_reimport(self):
        result, client, processes, output = self.orchestration(unknown_import=True)
        self.assertEqual(result["error_code"], "authored_import_response_unknown")
        self.assert_own_cleanup(result, client, processes)
        self.assertFalse((output / "inventory.json").exists())
        self.assertFalse(any(row[0] == "tunnel" for row in processes.calls))

    def test_collision_orchestration_never_imports_or_deletes_preexisting_key(self):
        result, client, processes, _ = self.orchestration(collision=True)
        self.assertEqual(result["error_code"], "preexisting_oslogin_key_not_owned")
        self.assertTrue(client.present)
        self.assertFalse(client.import_attempted)
        self.assertTrue(processes.closed)
        self.assertEqual(result["cleanup"]["status"], "no_registered_key")
        self.assertFalse(any(method in {"POST", "DELETE"} for method, _, _ in client.calls))
        self.assertFalse((self.work / "id_ed25519").exists())

    def test_local_process_cleanup_failure_still_removes_exact_oslogin_key(self):
        result, client, processes, _ = self.orchestration(close_error=True)
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["local_process_cleanup_error"], "own_process_cleanup_unconfirmed")
        self.assert_own_cleanup(result, client, processes)
        self.assertNotIn("authored private close diagnostic", json.dumps(result))

    def test_restart_cleanup_never_signals_reused_pid(self):
        row = {"pid": 654321, "start_ticks": "999", "kind": "ssh"}
        with mock.patch.object(inv, "_process_ticks", return_value="1000"), mock.patch.object(inv.os, "killpg", create=True) as kill:
            self.assertEqual(inv._cleanup_process(row), "foreign_or_reused_pid_not_touched")
        kill.assert_not_called()


if __name__ == "__main__":
    unittest.main()
