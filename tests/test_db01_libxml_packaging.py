"""Own archive and ABI fixtures; no builds, containers or network."""
from io import BytesIO
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest import mock

from scripts import db01_libxml_packaging as lab


class OrdinaryPackaging(unittest.TestCase):
    def archive(self, rows):
        data = BytesIO()
        with tarfile.open(fileobj=data, mode="w:xz") as stream:
            for name, kind in rows:
                item = tarfile.TarInfo(name)
                item.type = kind
                if kind == tarfile.REGTYPE:
                    item.size = 1; stream.addfile(item, BytesIO(b"x"))
                else:
                    item.linkname = "../../outside"; stream.addfile(item)
        data.seek(0)
        return tarfile.open(fileobj=data, mode="r:xz")

    def test_archive_cannot_escape_or_import_links_special_files_or_duplicates(self):
        variants = [[("root/../outside", tarfile.REGTYPE)], [("/root/file", tarfile.REGTYPE)],
            [("root/link", tarfile.SYMTYPE)], [("root/fifo", tarfile.FIFOTYPE)],
            [("root/file", tarfile.REGTYPE), ("root/file", tarfile.REGTYPE)], [("other/file", tarfile.REGTYPE)]]
        for rows in variants:
            with self.subTest(rows=rows), self.archive(rows) as stream, self.assertRaises(ValueError):
                lab.safe_members(stream, "root")
        with self.archive([("root/file", tarfile.REGTYPE)]) as stream:
            self.assertEqual(len(lab.safe_members(stream, "root")), 1)

    def test_reviewed_input_bytes_are_required_before_native_commands(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory); path = root / "owned.tar.xz"; path.write_bytes(b"authored-source")
            with mock.patch.object(lab, "INPUTS", {path.name: lab.sha(path.read_bytes())}):
                lab.validate_inputs(root)
                path.write_bytes(b"different-unreviewed-source")
                with self.assertRaisesRegex(ValueError, "digest"):
                    lab.validate_inputs(root)

    def test_export_comparison_preserves_symbol_versions(self):
        baseline = lab.symbol_set(b"0000 T xmlReadMemory@@LIBXML2_2.6.0\n0001 D xmlParserVersion@@LIBXML2_2.4.30\n")
        changed = lab.symbol_set(b"0000 T xmlReadMemory@@LIBXML2_2.9.0\n0001 D xmlParserVersion@@LIBXML2_2.4.30\n")
        self.assertEqual(baseline - changed, {"xmlReadMemory@@LIBXML2_2.6.0"})
        with self.assertRaisesRegex(ValueError, "empty"):
            lab.symbol_set(b"")

    def test_lab_package_is_separate_from_system_replacement(self):
        control = lab.package_control()
        self.assertIn("Package: clipforge-db01-libxml-lab\n", control)
        self.assertIn("/opt/clipforge-db01", control)
        self.assertNotIn("Provides:", control)
        self.assertNotIn("Conflicts:", control)
        self.assertNotIn("Replaces:", control)
        self.assertIn("Not a Debian security update", control)

    def test_native_entry_rejects_other_identity_before_any_process(self):
        with tempfile.TemporaryDirectory() as directory, mock.patch.object(lab.os, "getuid", return_value=0, create=True), \
             mock.patch.object(lab.subprocess, "run", side_effect=AssertionError("native forbidden")) as run:
            with self.assertRaisesRegex(ValueError, "private_linux"):
                lab.native(Path(directory))
            run.assert_not_called()

    def test_only_ordinary_xml_examples_are_supplied(self):
        self.assertIn("XML_PARSE_NONET", lab.ORDINARY_C)
        self.assertIn("XMLTABLE", lab.ORDINARY_PG_SQL)
        self.assertNotIn("DOCTYPE", lab.ORDINARY_C + lab.ORDINARY_PG_SQL)
        self.assertNotIn("ENTITY", lab.ORDINARY_C + lab.ORDINARY_PG_SQL)
        self.assertNotIn("http://", lab.ORDINARY_C + lab.ORDINARY_PG_SQL)
        self.assertNotIn("CVE-", lab.ORDINARY_C + lab.ORDINARY_PG_SQL)


if __name__ == "__main__":
    unittest.main()
