"""Synthetic, isolated checks of the read-only guest payload; no guest access."""
import io
import json
import stat
from types import SimpleNamespace
import unittest
from unittest import mock

from scripts import int_guest_inventory_guest as g


def path_rows():
    return [{"path": path, "exists": True, "uid": 0, "gid": 0, "mode": "0o755",
             "entries_count": 1 if path == g.PATHS[-1] else 0,
             "provenance_metadata_only": path == g.PATHS[-1],
             "known_shell_dotfiles": [], "empty_version_dirs": [], "absent_version_dirs": ["17", "18"] if path != g.PATHS[-1] else []} for path in g.PATHS]


def outputs():
    return {
        "unit_files": b"postgresql.service masked enabled\npostgresql@.service masked enabled\n",
        "unit_state": b"Type=oneshot\nActiveState=inactive\nSubState=dead\nLoadState=masked\nUnitFileState=masked\n",
        "units": b"postgresql.service masked inactive dead PostgreSQL RDBMS\n",
        "processes": b"systemd\nsshd\npython3\n",
        "tcp": b"LISTEN 0 4096 127.0.0.1:22 0.0.0.0:*\n",
        "unix": b"u_str LISTEN 0 4096 /run/systemd/private 12345 * 0\n",
        "clusters": b"",
        "kernel": b"6.12.57-deb13-cloud-amd64 x86_64\n",
        "packages": (b"base-files\t13.8+deb13u1\tinstalled\tamd64\n"
                     b"postgresql-17\t17.12-0+deb13u1\tinstalled\tamd64\n"
                     b"postgresql-client-17\t17.12-0+deb13u1\tinstalled\tamd64\n"),
        "blockdevices": g.encoded({"blockdevices": [{"name": "sda", "kname": "sda", "type": "disk",
                            "size": 21474836480, "fstype": None, "mountpoints": [None]}]}),
        "mounts": g.encoded({"filesystems": [{"target": "/", "source": "/dev/sda1", "fstype": "ext4"}]}),
    }


class AuthoredRunner:
    def __init__(self, changes=None):
        self.values = outputs()
        self.values.update(changes or {})
        self.calls = []

    def __call__(self, key, **bounds):
        self.calls.append((key, bounds))
        value = self.values[key]
        return value if isinstance(value, g.CommandResult) else g.CommandResult(0, value, duration_ms=1)


def collect(runner=None, **kwargs):
    return g.collect(runner=runner or AuthoredRunner(), clock=lambda: 10.0,
                     metadata_reader=kwargs.pop("metadata_reader", lambda **_: path_rows()),
                     release_reader=kwargs.pop("release_reader", lambda **_: {
                         "ID": "debian", "NAME": "Debian GNU/Linux", "VERSION_ID": "13",
                         "PRETTY_NAME": "Debian GNU/Linux 13 (trixie)", "VERSION_CODENAME": "trixie"}), **kwargs)


class GuestInventoryPayload(unittest.TestCase):
    def test_complete_metadata_and_single_full_package_query(self):
        runner = AuthoredRunner()
        report = collect(runner)
        self.assertEqual(g.validate_report(report), report)
        self.assertEqual((report["status"], report["exit_code"]), ("inventory_complete", 0))
        self.assertEqual([key for key, _ in runner.calls], ["unit_files", "unit_state", "units", "processes",
                         "tcp", "unix", "clusters", "kernel", "packages", "blockdevices", "mounts"])
        self.assertEqual(report["safety"]["unit_state"], {"Type": "oneshot", "ActiveState": "inactive",
                         "SubState": "dead", "LoadState": "masked", "UnitFileState": "masked"})
        selected = report["inventory"]["postgresql_packages"]
        self.assertEqual(selected["postgresql-17"][1], "17.12-0+deb13u1")
        self.assertIsNone(selected["postgresql-18"])
        self.assertEqual(sum(key == "packages" for key, _ in runner.calls), 1)
        for key, bounds in runner.calls:
            self.assertEqual(bounds["timeout_seconds"], 15)
            self.assertEqual(bounds["deadline"], 130)
            self.assertLessEqual(bounds["stderr_limit"], 8192)
            self.assertLessEqual(bounds["stdout_limit"], 1048576 if key == "packages" else 262144)

    def test_each_database_signal_stops_before_later_commands(self):
        cases = [
            ("unit_files", b"postgresql.service enabled enabled\npostgresql@.service masked enabled\n", "POSTGRES_UNMASKED"),
            ("unit_state", outputs()["unit_state"].replace(b"ActiveState=inactive", b"ActiveState=active").replace(b"SubState=dead", b"SubState=exited"), "POSTGRES_ACTIVE"),
            ("units", b"postgresql@17-main.service loaded inactive dead PostgreSQL Cluster\n", "POSTGRES_ACTIVE"),
            ("processes", b"systemd\npostgres\n", "POSTGRES_PROCESS"),
            ("processes", b"pg_ctlcluster\n", "POSTGRES_PROCESS"),
            ("tcp", b"LISTEN 0 128 [::]:5432 [::]:*\n", "TCP_5432_PRESENT"),
            ("unix", b"u_str LISTEN 0 100 /var/run/postgresql/.s.PGSQL.5432 7 * 0\n", "UNIX_5432_PRESENT"),
            ("clusters", b"17 main 5432 down postgres /var/lib/postgresql/17/main /var/log/postgresql/postgresql-17-main.log\n", "CLUSTER_PRESENT"),
            ("clusters", b"18 main 5432 online postgres /var/lib/postgresql/18/main /var/log/postgresql/postgresql-18-main.log\n", "CLUSTER_PRESENT"),
        ]
        for key, raw, reason in cases:
            with self.subTest(key=key, reason=reason):
                runner = AuthoredRunner({key: raw})
                metadata, release = mock.Mock(), mock.Mock()
                report = collect(runner, metadata_reader=metadata, release_reader=release)
                self.assertEqual((report["status"], report["exit_code"], report["reason"]), ("safety_stop", 2, reason))
                self.assertEqual(runner.calls[-1][0], key)
                self.assertIsNone(report["inventory"])
                self.assertFalse(report["safety"]["passed"])
                metadata.assert_not_called(); release.assert_not_called()
                g.validate_report(report)
        self.assertEqual(report["safety"]["clusters"], None)

    def test_active_exited_umbrella_is_recorded_without_claiming_daemon(self):
        state = outputs()["unit_state"].replace(b"ActiveState=inactive", b"ActiveState=active").replace(b"SubState=dead", b"SubState=exited")
        runner = AuthoredRunner({"unit_state": state})
        report = collect(runner)
        self.assertEqual(report["safety"]["unit_state"]["SubState"], "exited")
        self.assertIsNone(report["safety"]["postgres_processes"])
        self.assertEqual(len(runner.calls), 2)
        g.validate_report(report)

    def test_query_failures_preserve_closed_evidence_and_private_stderr(self):
        for status in ("nonzero_exit", "timeout", "stdout_limit", "stderr_limit", "spawn_error", "unsafe_binary", "budget_exhausted"):
            with self.subTest(status=status):
                sentinel = b"authored-private-diagnostic-never-public"
                result = g.CommandResult(1 if status == "nonzero_exit" else None, b"", sentinel, 15, status, status.upper())
                private = io.BytesIO()
                report = collect(AuthoredRunner({"unit_files": result}), stderr_sink=private)
                self.assertEqual(report["status"], "safety_stop")
                self.assertEqual(report["commands"][0]["status"], status)
                self.assertEqual(report["commands"][0]["error_code"], status.upper())
                self.assertEqual(report["stderr"]["sha256"], g.digest(sentinel))
                self.assertEqual(private.getvalue(), sentinel)
                self.assertNotIn(sentinel.decode(), json.dumps(report))
                g.validate_report(report)

    def test_unknown_query_output_and_missing_properties_fail_closed(self):
        for key, value in (("tcp", b"unknown ss layout\n"), ("processes", b""),
                           ("unit_state", b"Type=oneshot\n"), ("unit_state", outputs()["unit_state"] + b"Type=oneshot\n"),
                           ("unit_files", outputs()["unit_files"] + b"unreviewed.service masked enabled\n")):
            with self.subTest(key=key, value=value):
                runner = AuthoredRunner({key: value})
                report = collect(runner)
                self.assertEqual(report["status"], "safety_stop")
                self.assertEqual(runner.calls[-1][0], key)

    def test_inventory_failure_is_not_reported_as_complete(self):
        runner = AuthoredRunner({"packages": g.CommandResult(127, b"", b"authored missing dpkg", 0, "nonzero_exit", "NONZERO_EXIT")})
        report = collect(runner)
        self.assertEqual((report["status"], report["exit_code"]), ("inventory_incomplete", 3))
        self.assertTrue(report["safety"]["passed"])
        self.assertIsNone(report["inventory"])
        self.assertEqual(runner.calls[-1][0], "packages")
        g.validate_report(report)
        metadata = mock.Mock(side_effect=OSError("private path details"))
        report = collect(metadata_reader=metadata)
        self.assertEqual((report["status"], report["reason"]), ("safety_stop", "PATHS_UNSAFE"))
        self.assertNotIn("private path details", json.dumps(report))

    def test_full_package_inventory_distinguishes_17_18_and_residual_config(self):
        extra = b"postgresql-18\t18.1-1\tconfig-files\tamd64\npostgresql-client-18\t18.1-1\tinstalled\tamd64\n"
        report = collect(AuthoredRunner({"packages": outputs()["packages"] + extra}))
        selected = report["inventory"]["postgresql_packages"]
        self.assertEqual(selected["postgresql-18"][2], "config-files")
        self.assertEqual(selected["postgresql-client-18"][2], "installed")
        self.assertEqual(len(report["inventory"]["packages"]), 5)
        for raw in (outputs()["packages"] * 2, b"postgresql-17\t17.12\tunknown\tamd64\n", b"x\t1\tinstalled\n"):
            with self.subTest(raw=raw), self.assertRaises(g.InventoryError):
                g.parse_packages(raw)

    def test_os_release_is_parsed_without_execution_and_extra_fields_are_not_published(self):
        raw = b'ID=debian\nVERSION_CODENAME=trixie\nPRETTY_NAME="Debian GNU/Linux 13"\nAUTHORED_PRIVATE_FIELD=sentinel\n'
        result = g.parse_os_release(raw)
        self.assertEqual(result["PRETTY_NAME"], "Debian GNU/Linux 13")
        self.assertNotIn("AUTHORED_PRIVATE_FIELD", result)
        for extra in (b"ID=debian\n", b"NAME=bad\x00value\n", b'NAME="unterminated\n'):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                g.parse_os_release(raw + extra)

    def test_path_inspection_reads_metadata_only_and_rejects_data_or_links(self):
        def item(name, directory=False, mode=None):
            info = SimpleNamespace(st_mode=mode or ((stat.S_IFDIR | 0o755) if directory else (stat.S_IFREG | 0o644)),
                                   st_uid=0, st_gid=0, st_nlink=1, st_size=10)
            return SimpleNamespace(name=name, path="/var/lib/postgresql/" + name, stat=lambda **_: info)
        def directory(rows):
            context = mock.MagicMock()
            context.__enter__.return_value = iter(rows)
            return context
        root_info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        listing = {g.PATHS[0]: [], g.PATHS[1]: [item(".bashrc"), item("17", True)],
                   g.PATHS[2]: [item("package-provenance.txt")], "/var/lib/postgresql/17": []}
        with mock.patch.object(g.os, "lstat", return_value=root_info), \
             mock.patch.object(g.os, "scandir", side_effect=lambda path: directory(listing[path])), \
             mock.patch("builtins.open", side_effect=AssertionError("contents must not be read")):
            rows = g.inspect_paths(deadline=100, clock=lambda: 1)
            self.assertEqual(rows[1]["known_shell_dotfiles"], [".bashrc"])
            self.assertEqual(rows[1]["empty_version_dirs"], ["17"])
            for entry in (item("main", True), item("PG_VERSION"), item(".bashrc", mode=stat.S_IFLNK | 0o777)):
                with self.subTest(entry=entry.name), self.assertRaises(g.InventoryError):
                    listing[g.PATHS[1]] = [entry]
                    g.inspect_paths(deadline=100, clock=lambda: 1)
            listing[g.PATHS[1]] = [item("17", True)]
            listing["/var/lib/postgresql/17"] = [item("main", True)]
            with self.assertRaises(g.InventoryError):
                g.inspect_paths(deadline=100, clock=lambda: 1)

    def test_report_is_closed_and_cannot_turn_incomplete_into_success(self):
        for mutate in (lambda r: r.update(environment={"private": "sentinel"}),
                       lambda r: r.update(exit_code=False),
                       lambda r: r["stderr"].update(raw="private"),
                       lambda r: r["inventory"].update(private="sentinel"),
                       lambda r: r["commands"].pop(),
                       lambda r: r["commands"][0].update(error_code="TIMEOUT"),
                       lambda r: r["safety"].update(postgres_processes=1),
                       lambda r: r["safety"]["paths"][0].update(entries_count=1),
                       lambda r: r["inventory"]["postgresql_packages"].update({"postgresql-18": ["invented"]})):
            report = collect()
            mutate(report)
            with self.subTest(mutate=mutate), self.assertRaises((ValueError, TypeError)):
                g.validate_report(report)

    def test_absent_pg_directories_are_explicit_and_permission_failure_is_not_absence(self):
        info = SimpleNamespace(st_mode=stat.S_IFDIR | 0o755, st_uid=0, st_gid=0)
        provenance = SimpleNamespace(name="package-provenance.txt", stat=lambda **_: SimpleNamespace(
            st_mode=stat.S_IFREG | 0o644, st_uid=0, st_size=10))
        listing = mock.MagicMock(); listing.__enter__.return_value = iter([provenance])
        def lookup(path):
            if path in g.PATHS[:2]:
                raise FileNotFoundError("authored missing directory")
            return info
        with mock.patch.object(g.os, "lstat", side_effect=lookup), mock.patch.object(g.os, "scandir", return_value=listing):
            rows = g.inspect_paths(deadline=100, clock=lambda: 1)
        self.assertFalse(rows[0]["exists"]); self.assertFalse(rows[1]["exists"])
        self.assertTrue(rows[2]["exists"])
        self.assertIsNone(rows[0]["uid"])
        self.assertEqual(rows[1]["absent_version_dirs"], ["17", "18"])
        g.validate_report(collect(metadata_reader=lambda **_: rows))
        with mock.patch.object(g.os, "lstat", side_effect=PermissionError("authored inaccessible directory")), self.assertRaises(PermissionError):
            g.inspect_paths(deadline=100, clock=lambda: 1)
        with mock.patch.object(g.os, "lstat", side_effect=FileNotFoundError("authored missing parent")), self.assertRaises(FileNotFoundError):
            g.inspect_paths(deadline=100, clock=lambda: 1)

    def test_main_forbids_arguments_without_invoking_any_command(self):
        output = mock.Mock(); output.buffer = io.BytesIO()
        with mock.patch.object(g.sys, "argv", ["guest-inventory", "unreviewed"]), \
             mock.patch.object(g.sys, "stdout", output), \
             mock.patch.object(g.subprocess, "Popen", side_effect=AssertionError("no process permitted")) as popen:
            self.assertEqual(g.main(), 2)
        value = json.loads(output.buffer.getvalue())
        self.assertEqual((value["status"], value["reason"]), ("safety_stop", "ARGUMENTS_FORBIDDEN"))
        popen.assert_not_called()

    def test_fixed_runner_unsafe_missing_and_budget_errors_do_not_launch_commands(self):
        kwargs = dict(timeout_seconds=15, stdout_limit=1024, stderr_limit=100, deadline=120, clock=lambda: 0)
        with mock.patch.object(g, "_trusted_regular", side_effect=OSError("authored missing tool")), mock.patch.object(g.subprocess, "Popen") as popen:
            result = g.run_fixed("clusters", **kwargs)
            self.assertEqual((result.status, result.error_code), ("unsafe_binary", "UNSAFE_BINARY"))
            popen.assert_not_called()
        with mock.patch.object(g, "_trusted_regular"), mock.patch.object(g.subprocess, "Popen", side_effect=OSError("authored spawn failure")):
            self.assertEqual(g.run_fixed("clusters", **kwargs).error_code, "SPAWN_ERROR")
        with mock.patch.object(g.subprocess, "Popen") as popen:
            result = g.run_fixed("clusters", **{**kwargs, "deadline": 0})
            self.assertEqual(result.error_code, "BUDGET_EXHAUSTED")
            popen.assert_not_called()
        with mock.patch.object(g.subprocess, "Popen") as popen, self.assertRaises(g.InventoryError):
            g.run_fixed("arbitrary shell command", **kwargs)
        popen.assert_not_called()

    def test_realtime_stdout_cap_kills_only_owned_process_and_bounds_capture(self):
        process = mock.Mock(pid=543210, returncode=-9)
        process.stdout.fileno.return_value, process.stderr.fileno.return_value = 10, 11
        process.poll.return_value = -9
        selector = mock.Mock()
        selector.get_map.return_value = {10: True, 11: True}
        selector.select.return_value = [(SimpleNamespace(data="stdout", fileobj=process.stdout), 1)]
        with mock.patch.object(g, "_trusted_regular"), mock.patch.object(g.subprocess, "Popen", return_value=process) as popen, \
             mock.patch.object(g.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(g.os, "set_blocking", create=True), mock.patch.object(g.os, "read", return_value=b"12345") as read, \
             mock.patch.object(g.os, "killpg", create=True) as kill, mock.patch.object(g.signal, "SIGKILL", 9, create=True):
            result = g.run_fixed("kernel", timeout_seconds=15, stdout_limit=4, stderr_limit=2, deadline=120, clock=lambda: 0)
        self.assertEqual((result.status, result.stdout), ("stdout_limit", b"1234"))
        kill.assert_called_once_with(543210, 9)
        read.assert_called_once_with(10, 5)
        process.wait.assert_called_once_with(timeout=1)
        self.assertEqual(popen.call_args.args[0], ("/usr/bin/uname", "--kernel-release", "--machine"))
        self.assertEqual(popen.call_args.kwargs["env"], g.ENVIRONMENT)
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        process.stdout.close.assert_called_once(); process.stderr.close.assert_called_once()

    def test_realtime_timeout_kills_and_reaps_own_group(self):
        process = mock.Mock(pid=543211, returncode=-9)
        process.poll.return_value = -9
        selector = mock.Mock()
        selector.get_map.return_value = {10: True}
        ticks = iter([0, 16, 16])
        with mock.patch.object(g, "_trusted_regular"), mock.patch.object(g.subprocess, "Popen", return_value=process), \
             mock.patch.object(g.selectors, "DefaultSelector", return_value=selector), \
             mock.patch.object(g.os, "set_blocking", create=True), mock.patch.object(g.os, "killpg", create=True) as kill, \
             mock.patch.object(g.signal, "SIGKILL", 9, create=True):
            result = g.run_fixed("kernel", timeout_seconds=15, stdout_limit=4, stderr_limit=2, deadline=120, clock=lambda: next(ticks))
        self.assertEqual((result.status, result.error_code), ("timeout", "TIMEOUT"))
        kill.assert_called_once_with(543211, 9)
        process.wait.assert_called_once_with(timeout=1)


if __name__ == "__main__":
    unittest.main()
