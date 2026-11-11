"""Synthetic collector contracts only: no Docker, DB, scanner or installed packages.

Actual image capture is a separately recorded integration operation. These
fixtures verify malformed/missing scope and command isolation fail closed.
"""
from datetime import datetime
import base64
import hashlib
import io
import json
from pathlib import Path
import subprocess
import struct
import tempfile
import unittest
from unittest.mock import patch

from scripts import capture_postgres_inventory as capture


IMAGE_ID = "sha256:" + "a" * 64


def fixture_go_binary(module_text=None):
    """Minimal synthetic ELF64 with explicit, non-production Go metadata."""
    if module_text is None:
        module_text = ("path\tgithub.com/tianon/gosu\nmod\tgithub.com/tianon/gosu\tv1.19.0\t\n"
                       "dep\tgithub.com/moby/sys/user\tv0.1.0\th1:" + "a" * 43 + "=\n"
                       "dep\tgolang.org/x/sys\tv0.1.0\th1:" + "b" * 43 + "=\n"
                       "build\tGOOS=linux\nbuild\tGOARCH=amd64\n")
    def sized(value):
        size, prefix = len(value), bytearray()
        while size >= 128:
            prefix.append((size & 127) | 128)
            size >>= 7
        prefix.append(size)
        return bytes(prefix) + value
    framed = bytes.fromhex("3077af0c9274080241e1c107e6d618e6") + module_text.encode() + bytes.fromhex("f932433186182072008242104116d8f2")
    info = b"\xff Go buildinf:\x08\x02" + b"\0" * 16 + sized(b"go1.24.6") + sized(framed)
    names = b"\0.shstrtab\0.go.buildinfo\0"
    info_offset = 96
    table = ((info_offset + len(info) + 15) // 16) * 16
    binary = bytearray(table + 3 * 64)
    struct.pack_into("<16sHHIQQQIHHHHHH", binary, 0, b"\x7fELF\x02\x01\x01" + b"\0" * 9,
                     2, 62, 1, 0, 0, table, 0, 64, 0, 0, 64, 3, 1)
    binary[64:64 + len(names)] = names
    binary[info_offset:info_offset + len(info)] = info
    struct.pack_into("<IIQQQQIIQQ", binary, table + 64, 1, 3, 0, 0, 64, len(names), 0, 0, 1, 0)
    struct.pack_into("<IIQQQQIIQQ", binary, table + 128, 11, 1, 0, 0, info_offset, len(info), 0, 0, 16, 0)
    return bytes(binary)


def fixture_sections():
    gosu = fixture_go_binary()
    return {
        "os-release": b'ID=debian\nVERSION_ID="13"\nPRETTY_NAME="Debian GNU/Linux 13 (trixie)"\n',
        "debian-version": b"13.7\n",
        "dpkg-status": (
            b"Package: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 13.7\n"
            b"Description: Synthetic baseline\n continuation with a colon: preserved\n\n"
            b"Package: libfixture\nStatus: install ok installed\nArchitecture: all\nVersion: 2:1.2-3\n"
            b"Source: fixture-source (2:1.2-4)\n\n"
            b"Package: postgresql-18\nStatus: install ok installed\nArchitecture: amd64\nVersion: 18.6-1.pgdg13+2\n\n"
            b"Package: old-removed\nStatus: deinstall ok config-files\nArchitecture: amd64\nVersion: 1.0-1\n"
        ),
        "postgres-version": b"postgres (PostgreSQL) 18.6 (Debian 18.6-1.pgdg13+2)\n",
        "postgres-resolved": (capture.POSTGRES_BINARY + "\n").encode(),
        "postgres-stat": b"0 0 755 123456 regular file\n",
        "postgres-sha256": ("b" * 64 + "  " + capture.POSTGRES_BINARY + "\n").encode(),
        "postgres-owner": (capture.POSTGRES_PACKAGE + ": " + capture.POSTGRES_BINARY + "\n").encode(),
        "postgres-file-list": ("/.\n/usr\n/usr/lib\n" + capture.POSTGRES_BINARY + "\n").encode(),
        "gosu-version": b"1.19 (go1.24.6 on linux/amd64; gc)\n",
        "gosu-resolved": (capture.GOSU_BINARY + "\n").encode(),
        "gosu-stat": ("0 0 755 " + str(len(gosu)) + " regular file\n").encode(),
        "gosu-sha256": (hashlib.sha256(gosu).hexdigest() + "  " + capture.GOSU_BINARY + "\n").encode(),
        "gosu-binary": base64.b64encode(gosu),
    }


def encoded(sections):
    raw = bytearray()
    for name in capture.SECTIONS:
        raw.extend(capture.MARKER + name.encode() + b"\n")
        if name != "end":
            raw.extend(sections[name] + b"\n")
    return bytes(raw)


class PostgresInventoryParserTests(unittest.TestCase):
    def parse(self, sections=None):
        return capture.parse_probe(encoded(sections or fixture_sections()),
            image_id=IMAGE_ID, image_reference=capture.POSTGRES_IMAGE)

    def test_complete_inventory_preserves_all_installed_packages_and_sources(self):
        sections = fixture_sections()
        report = self.parse(sections)
        self.assertEqual(report["schema"], capture.SCHEMA)
        self.assertEqual(report["image_id"], report["image_config_id"])
        self.assertEqual(report["os"], {"family": "debian", "name": "13.7", "id": "debian", "version_id": "13"})
        self.assertEqual([(item["Class"], item["Type"]) for item in report["targets"]],
                         [("os-pkgs", "debian"), ("lang-pkgs", "gobinary")])
        packages = report["targets"][0]["Packages"]
        self.assertEqual([item["Name"] for item in packages], ["base-files", "libfixture", "postgresql-18"])
        self.assertEqual(packages[1]["Version"], "2:1.2-3")
        self.assertEqual(packages[1]["SourceVersion"], "2:1.2-4")
        self.assertEqual(report["dpkg"]["installed_package_count"], 3)
        self.assertEqual(report["dpkg"]["status_sha256"], hashlib.sha256(sections["dpkg-status"]).hexdigest())
        self.assertEqual(report["dpkg"]["status_bytes"], len(sections["dpkg-status"]))
        self.assertEqual(report["postgres"]["package_file_list"]["sha256"], hashlib.sha256(sections["postgres-file-list"]).hexdigest())
        self.assertTrue(report["postgres"]["package_owned"])
        self.assertEqual(report["postgres"]["binary"]["mode"], "0o755")
        self.assertEqual(report["postgres"]["binary"]["uid"], 0)
        self.assertFalse(report["scope"]["database_started"])

    def test_go_inventory_contains_main_dependencies_and_toolchain(self):
        report = self.parse()
        go = report["go_binaries"][0]
        self.assertEqual(go["go_version"], "go1.24.6")
        self.assertEqual(go["main_module"]["Version"], "v1.19.0")
        self.assertEqual(len(go["dependencies"]), 2)
        self.assertEqual(report["targets"][1]["Target"], "usr/local/bin/gosu")
        self.assertEqual(report["targets"][1]["Packages"], [
            {"Name": "github.com/moby/sys/user", "Version": "v0.1.0"},
            {"Name": "github.com/tianon/gosu", "Version": "v1.19.0"},
            {"Name": "golang.org/x/sys", "Version": "v0.1.0"},
            {"Name": "stdlib", "Version": "v1.24.6"}])
        self.assertEqual(go["sha256"], hashlib.sha256(fixture_go_binary()).hexdigest())

    def test_go_malformed_elf_and_module_info_fail_closed(self):
        good = fixture_go_binary()
        variants = [b"", good[:64], b"notELF" + good[6:], good.replace(b".go.buildinfo", b".xx.buildinfo"),
                    good.replace(b"\xff Go buildinf:\x08\x02", b"\xff Go buildinf:\x08\x00"),
                    good.replace(b"go1.24.6", b"goinvalid"),
                    fixture_go_binary("path\tgithub.com/tianon/gosu\nmod\tgithub.com/tianon/gosu\t(devel)\n"),
                    fixture_go_binary("path\tgithub.com/tianon/gosu\nmod\tgithub.com/tianon/gosu\tv1.19.0\n=>\tx\tv1.0.0\n")]
        for binary in variants:
            with self.subTest(size=len(binary)), self.assertRaises(capture.InventoryError):
                capture.parse_go_build_info(binary)

    def test_gosu_binary_hash_metadata_and_platform_must_match(self):
        variants = [("gosu-sha256", b"a" * 64 + b"  /usr/local/bin/gosu\n"),
                    ("gosu-stat", b"0 0 755 1 regular file\n"),
                    ("gosu-resolved", b"/tmp/gosu\n"), ("gosu-binary", b"not base64"),
                    ("gosu-version", b"1.19 (go1.24.7 on linux/amd64; gc)\n")]
        for key, value in variants:
            sections = fixture_sections()
            sections[key] = value
            with self.subTest(key=key), self.assertRaises(capture.InventoryError):
                self.parse(sections)

    def test_missing_or_extra_or_reordered_sections_are_rejected(self):
        raw = encoded(fixture_sections())
        variants = [raw[:-1], raw + b"unexpected", b"prefix" + raw,
                    raw.replace(capture.MARKER + b"postgres-version", capture.MARKER + b"wrong-version"),
                    raw.replace(capture.MARKER + b"end\n", b""),
                    raw.replace(capture.MARKER + b"end\n", capture.MARKER + b"end\n" + capture.MARKER + b"end\n")]
        for value in variants:
            with self.subTest(value=value[:32]), self.assertRaises(capture.InventoryError):
                capture.parse_sections(value)

    def test_wrong_image_or_configuration_id_is_rejected(self):
        for reference, image_id in [("postgres:latest", IMAGE_ID), (capture.POSTGRES_IMAGE, "abc"),
                                     (capture.POSTGRES_IMAGE, "sha256:" + "A" * 64)]:
            with self.subTest(reference=reference, image_id=image_id), self.assertRaises(capture.InventoryError):
                capture.parse_probe(encoded(fixture_sections()), image_id=image_id, image_reference=reference)

    def test_wrong_or_ambiguous_os_identity_is_rejected(self):
        for raw in [b"ID=ubuntu\nVERSION_ID=13\n", b"ID=debian\nVERSION_ID=12\n", b"ID=debian\nID=debian\nVERSION_ID=13\n",
                    b"ID=debian\nVERSION_ID=13 extra\n", b"ID=debian\nVERSION_ID='unterminated\n"]:
            sections = fixture_sections()
            sections["os-release"] = raw
            with self.subTest(raw=raw), self.assertRaises(capture.InventoryError):
                self.parse(sections)

    def test_missing_duplicate_and_incomplete_installed_packages_are_rejected(self):
        good = fixture_sections()["dpkg-status"]
        variants = [b"", good.replace(b"Package: postgresql-18", b"Package: another-package"),
                    good + b"\nPackage: base-files\nStatus: install ok installed\nArchitecture: amd64\nVersion: 13.7\n",
                    good.replace(b"Version: 13.7\n", b""), good.replace(b"Architecture: amd64", b"Architecture: arm64", 1),
                    good.replace(b"Status: install ok installed\n", b"", 1),
                    good.replace(b"Status: install ok installed", b"Status: install reinstreq installed", 1),
                    good.replace(b"Status: install ok installed", b"Status: install ok unpacked", 1),
                    good.replace(b"Version: 13.7\n", b"Version: 13.7\nVersion: 13.7\n"),
                    good.replace(b"Source: fixture-source (2:1.2-4)", b"Source: malformed source")]
        for raw in variants:
            with self.subTest(raw=raw[:64]), self.assertRaises(capture.InventoryError):
                capture.parse_packages(raw)

    def test_installed_held_packages_are_not_omitted(self):
        raw = fixture_sections()["dpkg-status"].replace(b"Status: install ok installed", b"Status: hold ok installed", 1)
        self.assertEqual([item["Name"] for item in capture.parse_packages(raw)],
                         ["base-files", "libfixture", "postgresql-18"])

    def test_runtime_version_must_match_packaged_postgres(self):
        for version in [b"postgres (PostgreSQL) 18.5\n", b"postgres (PostgreSQL) 18.6 (Debian 18.6-2)\n"]:
            sections = fixture_sections()
            sections["postgres-version"] = version
            with self.subTest(version=version), self.assertRaises(capture.InventoryError):
                self.parse(sections)

    def test_binary_identity_hash_permissions_and_ownership_are_required(self):
        variants = [("postgres-resolved", b"/tmp/postgres\n"),
                    ("postgres-stat", b"1000 0 755 123456 regular file\n"),
                    ("postgres-stat", b"0 0 777 123456 regular file\n"),
                    ("postgres-stat", b"0 0 4755 123456 regular file\n"),
                    ("postgres-stat", b"0 0 644 123456 regular file\n"),
                    ("postgres-stat", b"0 0 755 123456 symbolic link\n"),
                    ("postgres-sha256", b"missing\n"),
                    ("postgres-owner", b"another-package: /usr/lib/postgresql/18/bin/postgres\n"),
                    ("postgres-file-list", b"/.\n/usr\n"),
                    ("postgres-file-list", (capture.POSTGRES_BINARY + "\n/tmp/../escape\n").encode())]
        for key, value in variants:
            sections = fixture_sections()
            sections[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(capture.InventoryError):
                self.parse(sections)


class PostgresInventoryExecutionContractTests(unittest.TestCase):
    def test_probe_uses_verified_id_no_network_no_mounts_and_no_database_entrypoint(self):
        calls = []
        def fake_runner(argv, directory, label):
            calls.append(argv)
            if label == "image-identity":
                return (IMAGE_ID + "|linux|amd64\n").encode()
            if label == "probe-cleanup-list":
                return b""
            return encoded(fixture_sections())
        with tempfile.TemporaryDirectory() as temporary, patch.object(capture, "host_executable", return_value="/usr/bin/docker"):
            result = capture.capture(capture.POSTGRES_IMAGE, IMAGE_ID, "clipforge-ci-pg-inventory-fixture",
                                     artifacts=Path(temporary) / "capture", runner=fake_runner)
        self.assertEqual(len(calls), 3)
        inspect, run, cleanup = calls
        self.assertIn("{{.Id}}|{{.Os}}|{{.Architecture}}", inspect)
        self.assertNotIn(".Config.Env", " ".join(inspect))
        self.assertEqual(run[0], "/usr/bin/docker")
        for flag, value in [("--network", "none"), ("--user", "65534:65534"), ("--entrypoint", "/bin/sh"),
                            ("--pull", "never"), ("--cap-drop", "ALL"), ("--security-opt", "no-new-privileges")]:
            self.assertEqual(run[run.index(flag) + 1], value)
        self.assertIn("--read-only", run)
        self.assertNotIn("--mount", run)
        self.assertNotIn("--volume", run)
        self.assertNotIn("--env", run)
        self.assertIn(IMAGE_ID, run)
        self.assertNotIn(capture.POSTGRES_IMAGE, run)
        self.assertEqual(run[-1], capture.PROBE)
        self.assertNotIn("initdb", capture.PROBE)
        self.assertNotIn("pg_ctl", capture.PROBE)
        self.assertTrue(result["capture"]["probe_identity"])
        self.assertIn("label=clipforge.inventory.probe=" + result["capture"]["probe_identity"], cleanup)

    def test_cleanup_after_failure_or_cancellation_uses_exact_name_label_and_id(self):
        identifier = "c" * 64
        for failure in [capture.InventoryError("probe timeout"), KeyboardInterrupt()]:
            calls, identity = [], {}
            def fake_runner(argv, directory, label):
                calls.append((label, argv))
                if label == "image-identity":
                    return (IMAGE_ID + "|linux|amd64\n").encode()
                if label == "package-probe":
                    identity["label"] = argv[argv.index("--label") + 1].split("=", 1)[1]
                    raise failure
                if label == "probe-cleanup-list":
                    return (identifier + "\n").encode()
                if label == "probe-cleanup-identity":
                    return (identifier + "|/clipforge-ci-pg-inventory-fixture|" + identity["label"] + "\n").encode()
                return (identifier + "\n").encode()
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary, patch.object(capture, "host_executable", return_value="/usr/bin/docker"):
                with self.assertRaises(type(failure)):
                    capture.capture(capture.POSTGRES_IMAGE, IMAGE_ID, "clipforge-ci-pg-inventory-fixture",
                                    artifacts=Path(temporary) / "capture", runner=fake_runner)
            self.assertEqual(calls[-1][0], "probe-cleanup-remove")
            self.assertEqual(calls[-1][1][-4:], ["container", "rm", "--force", identifier])
            self.assertNotIn(".Config.Env", " ".join(calls[-2][1]))

    def test_cleanup_refuses_foreign_or_ambiguous_resources(self):
        for identity in [b"wrong|/foreign|wrong\n", b"ambiguous"]:
            calls = []
            def fake_runner(argv, directory, label):
                calls.append(label)
                if label == "probe-cleanup-list":
                    return ("c" * 64 + "\n" + ("d" * 64 + "\n" if identity == b"ambiguous" else "")).encode()
                return identity
            with self.subTest(identity=identity), self.assertRaises(capture.InventoryError):
                capture._cleanup_probe(["/usr/bin/docker"], "clipforge-ci-pg-inventory-fixture", "a" * 32, Path("fixture"), fake_runner)
            self.assertNotIn("probe-cleanup-remove", calls)

    def test_mismatched_image_id_or_platform_never_runs_probe(self):
        for identity in ["sha256:" + "b" * 64 + "|linux|amd64", IMAGE_ID + "|linux|arm64"]:
            calls = []
            def fake_runner(argv, directory, label):
                calls.append(argv)
                return (identity + "\n").encode()
            with self.subTest(identity=identity), tempfile.TemporaryDirectory() as temporary, patch.object(capture, "host_executable", return_value="/usr/bin/docker"):
                with self.assertRaises(capture.InventoryError):
                    capture.capture(capture.POSTGRES_IMAGE, IMAGE_ID, "clipforge-ci-pg-inventory-fixture",
                                    artifacts=Path(temporary) / "capture", runner=fake_runner)
            self.assertEqual(len(calls), 1)

    def test_invalid_name_or_existing_attempt_is_rejected_without_docker(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(capture, "host_executable") as executable:
            with self.assertRaises(capture.InventoryError):
                capture.capture(capture.POSTGRES_IMAGE, IMAGE_ID, "operational-container", artifacts=Path(temporary) / "new")
            with self.assertRaises(capture.InventoryError):
                capture.capture(capture.POSTGRES_IMAGE, IMAGE_ID, "clipforge-ci-pg-inventory-fixture", artifacts=Path(temporary))
            executable.assert_not_called()

    def test_failed_and_timed_out_commands_preserve_exit_evidence(self):
        for failure in [subprocess.CompletedProcess([], 23), subprocess.TimeoutExpired(["/usr/bin/docker"], 45)]:
            with self.subTest(failure=type(failure).__name__), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                with patch.object(capture.subprocess, "run", side_effect=failure if isinstance(failure, Exception) else None,
                                  return_value=failure if not isinstance(failure, Exception) else None):
                    with self.assertRaises(capture.InventoryError):
                        capture._execute(["/usr/bin/docker", "fixture"], directory, "probe")
                record = json.loads((directory / "probe-execution.json").read_text())
                self.assertEqual(record["exit_code"], 23 if not isinstance(failure, Exception) else None)
                self.assertEqual(record["error_type"], None if not isinstance(failure, Exception) else "TimeoutExpired")
                self.assertIsNotNone(datetime.fromisoformat(record["finished_utc"]).tzinfo)
                self.assertTrue((directory / "probe.stdout.log").is_file())

    def test_cli_never_overwrites_existing_report(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(capture, "capture") as collector, patch("sys.stderr", new=io.StringIO()):
            report = Path(temporary) / "postgres-image-inventory.json"
            report.write_text("previous evidence", encoding="utf-8")
            code = capture.main(["--image", capture.POSTGRES_IMAGE, "--image-id", IMAGE_ID,
                                 "--container-name", "clipforge-ci-pg-inventory-fixture", "--output", str(report)])
            self.assertEqual(code, 1)
            self.assertEqual(report.read_text(), "previous evidence")
            collector.assert_not_called()

    def test_diagnostic_output_is_not_silently_accepted(self):
        def diagnostic(argv, **kwargs):
            kwargs["stdout"].write(b"synthetic output")
            kwargs["stderr"].write(b"synthetic diagnostic requires review")
            return subprocess.CompletedProcess(argv, 0)
        with tempfile.TemporaryDirectory() as temporary, patch.object(capture.subprocess, "run", side_effect=diagnostic):
            with self.assertRaises(capture.InventoryError):
                capture._execute(["/usr/bin/docker", "fixture"], Path(temporary), "diagnostic")
            record = json.loads((Path(temporary) / "diagnostic-execution.json").read_text())
            self.assertEqual(record["exit_code"], 0)
            self.assertGreater(record["stderr_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
