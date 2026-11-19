"""Offline ordinary libxml build/ABI/XML lab; never a vulnerability experiment.

No upstream regression suite, exploit input, sanitizer, package installation,
network access, VM operation or assertion of CVE resolution is supplied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]
VERSION = "2.12.7+dfsg+really2.9.14-2.1+deb13u3"
INPUTS = {
    "libxml2_2.12.7+dfsg+really2.9.14.orig.tar.xz": "4fe913dec8b1ab89d13b489b419a8203176ea39e931eaa0d25b17eafb9c279e9",
    "libxml2_2.12.7+dfsg+really2.9.14-2.1+deb13u3.debian.tar.xz": "3b6d265f482d6a8fbe3c056d2006fb3b563b4a838f7258b388ac5f0b29206921",
    "patch_2.8-2_amd64.deb": "80c46a0085b33acc74bf451fddb6a70cb43d4ebcc4a873aec04d8d0a63ffc630",
    "CVE-2026-6653-reference.patch": "6c2b8a7b6fa470efcb1854e5c73bd7e1ae1663d8b111e27ce9232bbc1fe44f54",
}
CONFIGURE = ["--prefix=/usr", "--libdir=/usr/lib/x86_64-linux-gnu", "--without-python", "--disable-static",
             "--with-history", "--disable-maintainer-mode"]
LAYOUT_C = r'''#include <stdio.h>
#include <stddef.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
int main(void) {
 printf("{\"xmlParserCtxt\":%zu,\"xmlParserInput\":%zu,\"xmlNode\":%zu,\"xmlDoc\":%zu,\"ctxt_input\":%zu,\"ctxt_sax\":%zu,\"ctxt_userData\":%zu}\n",
 sizeof(xmlParserCtxt),sizeof(xmlParserInput),sizeof(xmlNode),sizeof(xmlDoc),offsetof(xmlParserCtxt,input),offsetof(xmlParserCtxt,sax),offsetof(xmlParserCtxt,userData));
 return 0;
}
'''
ORDINARY_C = r'''#include <stdio.h>
#include <string.h>
#include <libxml/parser.h>
#include <libxml/tree.h>
#include <libxml/xpath.h>
#include <libxml/xmlreader.h>
#include <libxml/xmlwriter.h>
int main(void) {
 const char *text="<root><value>ordinary</value><value>xml</value></root>";
 xmlDocPtr doc=xmlReadMemory(text,(int)strlen(text),"ordinary.xml",NULL,XML_PARSE_NONET);
 if(!doc) return 10;
 xmlXPathContextPtr ctx=xmlXPathNewContext(doc);
 xmlXPathObjectPtr value=xmlXPathEvalExpression(BAD_CAST "count(/root/value)",ctx);
 if(!value || value->type!=XPATH_NUMBER || value->floatval!=2.0) return 11;
 xmlXPathFreeObject(value); xmlXPathFreeContext(ctx); xmlFreeDoc(doc);
 xmlTextReaderPtr reader=xmlReaderForMemory(text,(int)strlen(text),"ordinary.xml",NULL,XML_PARSE_NONET);
 int count=0,code;
 while((code=xmlTextReaderRead(reader))==1) if(xmlTextReaderNodeType(reader)==XML_READER_TYPE_ELEMENT) count++;
 xmlFreeTextReader(reader); if(code!=0 || count!=3) return 12;
 xmlBufferPtr buffer=xmlBufferCreate(); xmlTextWriterPtr writer=xmlNewTextWriterMemory(buffer,0);
 if(!writer || xmlTextWriterStartDocument(writer,NULL,"UTF-8",NULL)<0 || xmlTextWriterWriteElement(writer,BAD_CAST "root",BAD_CAST "ordinary")<0 || xmlTextWriterEndDocument(writer)<0) return 13;
 xmlFreeTextWriter(writer); doc=xmlReadMemory((const char*)buffer->content,(int)buffer->use,"ordinary-output.xml",NULL,XML_PARSE_NONET);
 if(!doc) return 14;
 xmlFreeDoc(doc); xmlBufferFree(buffer); xmlCleanupParser();
 puts("ordinary_parse_xpath_reader_writer_roundtrip_passed"); return 0;
}
'''
ORDINARY_PG_SQL = """SELECT current_setting('server_version_num')::integer=170012;
SELECT xpath('/root/value/text()',XMLPARSE(DOCUMENT '<root><value>ordinary</value></root>'))::text='{ordinary}';
SELECT XMLSERIALIZE(DOCUMENT XMLELEMENT(NAME root,'ordinary') AS text)='<root>ordinary</root>';
SELECT count(*)=2 FROM XMLTABLE('/root/value' PASSING XMLPARSE(DOCUMENT '<root><value>one</value><value>two</value></root>') COLUMNS value text PATH '.') AS ordinary_rows;
"""


def require(condition, code):
    if not condition:
        raise ValueError(code)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def regular(path, maximum=32 * 1024 * 1024):
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= maximum, "ordinary_input_regular_bounded")
    return path.read_bytes()


def validate_inputs(directory):
    require(directory.is_dir() and not directory.is_symlink(), "ordinary_inputs_directory")
    for name, digest in INPUTS.items():
        require(sha(regular(directory / name)) == digest, "ordinary_input_digest")


def safe_members(stream, prefix):
    members = stream.getmembers()
    require(0 < len(members) <= 12000, "ordinary_archive_member_count")
    seen, total = set(), 0
    for item in members:
        path = PurePosixPath(item.name)
        require(not path.is_absolute() and ".." not in path.parts and "\\" not in item.name and ":" not in item.name
                and path.parts and path.parts[0] == prefix and item.name not in seen
                and (item.isdir() or item.isfile()) and item.size <= 32 * 1024 * 1024, "ordinary_archive_member")
        seen.add(item.name); total += item.size
    require(total <= 200 * 1024 * 1024, "ordinary_archive_total")
    return members


def extract(path, directory, prefix):
    with tarfile.open(path, "r:xz") as stream:
        members = safe_members(stream, prefix)
        for item in members:
            target = directory / item.name
            require(not target.is_symlink(), "ordinary_archive_destination")
            if item.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with stream.extractfile(item) as source, target.open("xb") as output:
                    shutil.copyfileobj(source, output)
                target.chmod(0o755 if item.mode & 0o111 else 0o644)


def symbol_set(raw):
    result = set()
    for line in raw.decode("ascii").splitlines():
        parts = line.split()
        if len(parts) >= 3 and re.fullmatch(r"[0-9a-fA-F]+", parts[0]):
            result.add(parts[-1])
    require(result, "ordinary_export_inventory_empty")
    return result


def package_control():
    # A separate /opt lab artifact cannot replace the distro's system package.
    return ("Package: clipforge-db01-libxml-lab\nVersion: " + VERSION + "+clipforge.lab1\nArchitecture: amd64\n"
            "Maintainer: ClipForge local laboratory <noreply@example.invalid>\nSection: libs\nPriority: optional\n"
            "Depends: libc6, liblzma5, zlib1g\nDescription: Offline ordinary XML and ABI laboratory artifact\n"
            " Installs only under /opt/clipforge-db01. Not a Debian security update.\n"
            " CVE resolution, VM deployment and replacement compatibility are not approved.\n")


def native(output):
    require(os.name == "posix" and os.getuid() == 10001 and Path("/work").is_dir(), "ordinary_private_linux_lab_required")
    require(output.is_dir() and not output.is_symlink() and not (output / "ordinary-build.json").exists(), "ordinary_new_output_required")
    inputs = output / "inputs"; validate_inputs(inputs)
    report = {"schema": "clipforge-db01-libxml-ordinary-build-1", "status": "incomplete", "operations": [],
        "source_version": VERSION, "upstream_regression_suite_run": False, "vulnerability_regression_run": False,
        "sanitizers_used": False, "exploit_inputs_used": False, "CVE_resolution_proven": False,
        "VM_install_authorized": False, "system_package_replaced": False, "Debian_official_package_parity_claimed": False}
    work = Path(tempfile.mkdtemp(prefix="ordinary-", dir="/work"))

    def call(name, args, *, cwd=work, timeout=180, env=None):
        require(all(isinstance(value, str) for value in args), "ordinary_native_argv")
        stdout, stderr = output / (name + ".stdout.log"), output / (name + ".stderr.log")
        try:
            with stdout.open("xb") as out, stderr.open("xb") as err:
                result = subprocess.run(args, cwd=cwd, env=env, stdout=out, stderr=err, timeout=timeout, check=False)
            code = result.returncode
        except subprocess.TimeoutExpired:
            code = None
        record = {"operation": name, "argv": args, "exit_code": code,
            "stdout_sha256": sha(regular(stdout, 16 * 1024 * 1024)), "stderr_sha256": sha(regular(stderr, 16 * 1024 * 1024))}
        report["operations"].append(record)
        require(code == 0, "ordinary_native_failed_" + name)
        return stdout.read_bytes()

    try:
        # Debian's /etc/os-release is a standard symlink. Read its fixed
        # package-owned target; input archives still reject every symlink.
        report["os_release"] = regular(Path("/usr/lib/os-release")).decode()
        require('VERSION_ID="13"' in report["os_release"], "ordinary_Debian13_required")
        report["baseline_package"] = call("baseline-package", ["/usr/bin/dpkg-query", "-W", "-f=${Version}", "libxml2"]).decode()
        require(report["baseline_package"] == VERSION, "ordinary_matching_baseline_package_required")
        extract(inputs / next(name for name in INPUTS if name.endswith("orig.tar.xz")), work, "libxml2-2.9.14")
        source = work / "libxml2-2.9.14"
        extract(inputs / next(name for name in INPUTS if name.endswith("debian.tar.xz")), source, "debian")
        call("unpack-patch", ["/usr/bin/dpkg-deb", "-x", str(inputs / "patch_2.8-2_amd64.deb"), str(work / "tools")])
        patch = str(work / "tools/usr/bin/patch")
        series = [line.strip() for line in regular(source / "debian/patches/series").decode().splitlines() if line.strip() and not line.lstrip().startswith("#")]
        require(len(series) == 40 and len(set(series)) == 40, "ordinary_exact_40_patches")
        for index, name in enumerate(series):
            require(re.fullmatch(r"[A-Za-z0-9_.+/-]+", name) and ".." not in PurePosixPath(name).parts, "ordinary_patch_path")
            call("debian-patch-" + str(index + 1).zfill(2), [patch, "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(source / "debian/patches" / name)], cwd=source)
        baseline_headers = work / "baseline-headers"; shutil.copytree(source / "include", baseline_headers / "include")
        call("reference-adaptation", [patch, "--batch", "--forward", "--fuzz=0", "-p1", "-i", str(inputs / "CVE-2026-6653-reference.patch")], cwd=source)
        build = work / "build"; build.mkdir()
        call("configure", [str(source / "configure"), *CONFIGURE], cwd=build)
        call("compile-library-and-tools", ["/usr/bin/make", "-j2"], cwd=build, timeout=900)
        stage = work / "stage"; stage.mkdir()
        call("stage-only-not-install", ["/usr/bin/make", "DESTDIR=" + str(stage), "install"], cwd=build)
        libraries = list((stage / "usr/lib/x86_64-linux-gnu").glob("libxml2.so.2.*"))
        require(len(libraries) == 1 and libraries[0].is_file() and not libraries[0].is_symlink(), "ordinary_single_library")
        candidate = libraries[0]; baseline = "/usr/lib/x86_64-linux-gnu/libxml2.so.2"
        old_symbols = symbol_set(call("baseline-exports", ["/usr/bin/nm", "-D", "--defined-only", baseline]))
        new_symbols = symbol_set(call("candidate-exports", ["/usr/bin/nm", "-D", "--defined-only", str(candidate)]))
        report["exports"] = {"baseline": len(old_symbols), "candidate": len(new_symbols), "removed": sorted(old_symbols - new_symbols), "added": sorted(new_symbols - old_symbols)}
        old_dynamic = call("baseline-dynamic", ["/usr/bin/readelf", "-d", baseline]).decode()
        new_dynamic = call("candidate-dynamic", ["/usr/bin/readelf", "-d", str(candidate)]).decode()
        report["SONAME_unchanged"] = "[libxml2.so.2]" in old_dynamic and "[libxml2.so.2]" in new_dynamic
        include = stage / "usr/include/libxml2"
        (work / "layout.c").write_text(LAYOUT_C); (work / "ordinary.c").write_text(ORDINARY_C)
        shutil.copyfile(build / "include/libxml/xmlversion.h", baseline_headers / "include/libxml/xmlversion.h")
        layouts = {}
        for key, headers in (("baseline", baseline_headers / "include"), ("candidate", include)):
            call(key + "-layout-compile", ["/usr/bin/gcc", "-Wall", "-Wextra", "-Werror", "-I" + str(headers), str(work / "layout.c"), "-o", str(work / key)])
            layouts[key] = json.loads(call(key + "-layout", [str(work / key)]))
        report["selected_public_layouts"] = layouts; report["selected_public_layouts_equal"] = layouts["baseline"] == layouts["candidate"]
        call("ordinary-client-compile", ["/usr/bin/gcc", "-Wall", "-Wextra", "-Werror", "-I" + str(include), str(work / "ordinary.c"),
             "-L" + str(candidate.parent), "-Wl,-rpath," + str(candidate.parent), "-lxml2", "-o", str(work / "ordinary")])
        report["ordinary_XML"] = call("ordinary-client-run", [str(work / "ordinary")]).decode().strip()
        package = work / "package"; (package / "DEBIAN").mkdir(parents=True)
        (package / "DEBIAN/control").write_text(package_control())
        libdir = package / "opt/clipforge-db01/lib"; libdir.mkdir(parents=True)
        shutil.copyfile(candidate, libdir / candidate.name)
        (libdir / "libxml2.so.2").symlink_to(candidate.name)
        (libdir / "libxml2.so").symlink_to("libxml2.so.2")
        deb = output / "clipforge-db01-libxml-lab_amd64.deb"
        call("package-lab-only", ["/usr/bin/dpkg-deb", "--root-owner-group", "--build", str(package), str(deb)])
        call("package-metadata", ["/usr/bin/dpkg-deb", "--info", str(deb)])
        call("package-files", ["/usr/bin/dpkg-deb", "--contents", str(deb)])
        exported = output / "candidate-lib"; exported.mkdir()
        shutil.copyfile(candidate, exported / candidate.name)
        # Desktop bind mounts need not support symlinks; export the SONAME as
        # regular bytes. The Debian artifact itself retains normal symlinks.
        shutil.copyfile(candidate, exported / "libxml2.so.2")
        report["selected_ABI_checks_passed"] = (report["SONAME_unchanged"] and not report["exports"]["removed"]
                                                and report["selected_public_layouts_equal"])
        report["library"] = {"file": candidate.name, "sha256": sha(regular(candidate)), "bytes": candidate.stat().st_size}
        report["lab_deb"] = {"sha256": sha(regular(deb)), "bytes": deb.stat().st_size, "installed": False}
        report["status"] = "ordinary_build_packaging_completed_security_not_approved"
    except Exception as error:
        report["status"] = "ordinary_build_incomplete_preserved"
        report["error"] = str(error) if isinstance(error, ValueError) else type(error).__name__
    finally:
        (output / "ordinary-build.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--native-output", type=Path, required=True)
    args = parser.parse_args()
    report = native(args.native_output)
    print(json.dumps({"status": report["status"], "CVE_resolution_proven": False, "VM_install_authorized": False}))
    return 0 if report["status"] == "ordinary_build_packaging_completed_security_not_approved" else 1


if __name__ == "__main__":
    raise SystemExit(main())
