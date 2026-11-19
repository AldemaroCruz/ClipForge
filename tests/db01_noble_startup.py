"""Directed local tests for the Noble startup contract with authored fixtures."""
from pathlib import Path
import os
import re
import shutil
import subprocess
import tempfile
import unittest


SOURCE = Path(__file__).resolve().parents[1] / "infra" / "gcp" / "int-base" / "db01-noble-startup.sh"
BASH = (Path(os.environ.get("ProgramFiles", "C:/Program Files")) / "Git" / "bin" / "bash.exe"
        if os.name == "nt" else shutil.which("bash"))
STATE_CALLBACKS = r'''
trusted_directory() { [[ -d $1 && ! -L $1 ]]; }
trusted_receipt() { [[ -f $1 && ! -L $1 ]]; }
verify_pinned_install() { printf 'verified pins\n'; }
verify_masks() { printf 'verified masks\n'; }
verify_blank_postgres() { printf 'verified no PostgreSQL\n'; }
prepare_first_boot() { printf 'APT and masks called\n'; return "$3"; }
route_startup "$2"
printf 'publisher=%s\n' "$NOBLE_FIRST_INSTALL"
'''


class NobleStartupTests(unittest.TestCase):
    def run_bash(self, command, *arguments):
        return subprocess.run([str(BASH), "--noprofile", "--norc", "-c",
                               'source "$1"\n' + command, "db01-noble-test", SOURCE.as_posix(),
                               *(str(item) for item in arguments)],
                              capture_output=True, text=True, timeout=12, check=False)

    def route(self, directories=(), files=(), install_result="0"):
        with tempfile.TemporaryDirectory(prefix="db01-noble-authored-") as temporary:
            root = Path(temporary) / "postgres"
            for name in directories:
                (root / name).mkdir(parents=True)
            for name in files:
                (root / name).parent.mkdir(exist_ok=True, parents=True)
                (root / name).touch()
            script = STATE_CALLBACKS.replace('return "$3"', f'return {int(install_result)}')
            return self.run_bash(script, root.as_posix())

    def test_initialized_boot_preserves_state_without_install_masks_or_publish(self):
        result = self.route(directories=("db01", "data"), files=("db01/operation.json", "package-provenance.txt"))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["CLIPFORGE_DB01_NOBLE_BOOTSTRAP_STATE_PRESERVED", "publisher=0"])

    def test_partial_bootstrap_journal_directory_also_preserves_state(self):
        result = self.route(directories=("db01",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertNotIn("verified", result.stdout)
        self.assertNotIn("APT", result.stdout)
        self.assertIn("publisher=0", result.stdout)

    def test_installed_reboot_reads_checks_without_writing_or_publishing(self):
        result = self.route(files=("package-provenance.txt",))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.splitlines(), ["verified pins", "verified masks", "verified no PostgreSQL",
                                                      "CLIPFORGE_DB01_NOBLE_PRIOR_INSTALL_VERIFIED", "publisher=0"])

    def test_incomplete_install_or_unfamiliar_data_blocks_replay(self):
        for directory in ("noble-install.partial", "data", ""):
            with self.subTest(directory=directory):
                result = self.route(directories=(directory,))
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertIn("prior_install_or_storage_preserved", result.stderr)

    def test_fresh_success_is_the_only_path_that_signals_publisher(self):
        success = self.route()
        self.assertEqual(success.returncode, 0, success.stderr)
        self.assertEqual(success.stdout.splitlines(), ["APT and masks called",
                                                       "CLIPFORGE_DB01_NOBLE_INSTALLED_MASKED_UNINITIALIZED", "publisher=1"])
        failed = self.route(install_result="9")
        self.assertEqual(failed.returncode, 9)
        self.assertEqual(failed.stdout.splitlines(), ["APT and masks called"])

    def test_apt_policy_only_uses_reviewed_https_origins_and_nonpermissive_flags(self):
        with tempfile.TemporaryDirectory(prefix="db01-noble-apt-authored-") as temporary:
            root = Path(temporary)
            result = self.run_bash('write_apt_policy "$2"', root.as_posix())
            self.assertEqual(result.returncode, 0, result.stderr)
            apt_source = (root / "reviewed.sources").read_text(encoding="utf-8")
            apt_config = (root / "reviewed.conf").read_text(encoding="utf-8")
            pins = (root / "reviewed.preferences").read_text(encoding="utf-8")
        self.assertEqual(re.findall(r"^URIs: (\S+)$", apt_source, re.M),
                         ["https://archive.ubuntu.com/ubuntu/", "https://security.ubuntu.com/ubuntu/",
                          "https://apt.postgresql.org/pub/repos/apt/"])
        self.assertEqual(re.findall(r"^Suites: (.+)$", apt_source, re.M),
                         ["noble noble-updates", "noble-security", "noble-pgdg"])
        self.assertIn("B97B0AFCAA1A47F044F244A07FCC7D46ACCC4CF8", apt_source)
        self.assertIn('Dir::Etc::SourceParts "-";', apt_config)
        self.assertIn('DPkg::Lock::Timeout "45";', apt_config)
        self.assertIn('Acquire::Retries "0";', apt_config)
        self.assertIn('Acquire::Check-Valid-Until "true";', apt_config)
        self.assertIn('APT::Get::AllowUnauthenticated "false";', apt_config)
        self.assertIn('Acquire::AllowInsecureRepositories "false";', apt_config)
        self.assertIn('Acquire::https::Verify-Peer "true";', apt_config)
        self.assertIn('Acquire::https::Verify-Host "true";', apt_config)
        self.assertIn("Package: postgresql-17 postgresql-client-17 postgresql-common postgresql-client-common libpq5\n", pins)
        self.assertIn("Package: *\nPin: release n=noble-pgdg\nPin-Priority: -1", pins)

    def test_archive_hash_and_identity_must_be_in_same_signed_index_record(self):
        test = r'''
timeout() { shift; "$@"; }
apt-cache() { cat "$fixture"; }
fixture=$2
verify_apt_record libexample 1.0 amd64 "$3"
'''
        header = "Package: libexample\nVersion: 1.0\nArchitecture: amd64\nFilename: pool/main/l/libexample.deb\n"
        digest = "a" * 64
        with tempfile.TemporaryDirectory(prefix="db01-noble-index-authored-") as temporary:
            fixture = Path(temporary) / "index"
            fixture.write_text(header + "SHA256: " + digest + "\n", encoding="utf-8", newline="\n")
            self.assertEqual(self.run_bash(test, fixture.as_posix(), digest).returncode, 0)
            fixture.write_text(header + "\nPackage: other\nSHA256: " + digest + "\n", encoding="utf-8", newline="\n")
            self.assertEqual(self.run_bash(test, fixture.as_posix(), digest).returncode, 1)

    def test_both_exact_masks_are_verified_and_extra_units_or_enabled_state_fail(self):
        test = r'''
timeout() { printf '%s\n' "$unit_rows"; }
cat() { printf 'create_main_cluster = false\n'; }
unit_rows=$2
verify_masks
'''
        masked = "postgresql.service masked enabled\npostgresql@.service masked enabled"
        for rows, status in ((masked, 0), (masked.replace("service masked", "service enabled", 1), 1),
                             (masked + "\npostgresql@17-main.service enabled", 1)):
            with self.subTest(rows=rows):
                self.assertEqual(self.run_bash(test, rows).returncode, status)

    def test_mutation_order_and_no_bootstrap_commands(self):
        script = SOURCE.read_text(encoding="utf-8")
        sequence = ("cloud-init status --wait", "apt-get update", "resolve_archives \"$dir\"", "systemctl mask",
                    "ln -- \"$policy\" /usr/sbin/policy-rc.d", "apt-get --no-download", "verify_pinned_install",
                    "verify_masks", "verify_blank_postgres", "mv -T --")
        stop = script.index("prepare_first_boot() (")
        for expression in sequence:
            stop = script.index(expression, stop + 1)
        self.assertNotRegex(script, r"(?m)^\s*(?:mkfs\S*|mount|psql|initdb|pg_createcluster|systemctl (?:start|enable|unmask))\b")


if __name__ == "__main__":
    unittest.main()
