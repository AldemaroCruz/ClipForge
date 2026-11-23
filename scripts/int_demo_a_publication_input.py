"""Pack one allowlisted review bundle and hydrate it from its exact private GCS generation."""

import argparse
from datetime import datetime, timezone
from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import tarfile
import time
from urllib.error import HTTPError
from urllib.parse import quote, urlencode
from urllib.request import ProxyHandler, Request, build_opener

from scripts import int_demo_a_receipts as receipts
from scripts import int_guest_inventory as transport


LIMIT = 512 * 1024 * 1024
MEMBER_LIMIT = 256 * 1024 * 1024
DEADLINE = 240
SCHEMA = "clipforge-int-demo-a-native-publication-pointer-1"
ESSENTIAL = {"decision.json", "binding.json", "review.json", "native-publication-host.json",
             "native-publication-rehearsal.json", "db01-noble-client.oci.tar", "runtime.oci.tar",
             "publisher.oci.tar", "publisher-build.json", "publisher-go-build-info.txt",
             "publisher-grype.json", "publisher-lab.json"}
require = transport.require


def name(commit, operation_id):
    require(re.fullmatch(r"[a-f0-9]{40}", commit) and re.fullmatch(r"[a-f0-9]{32}", operation_id),
            "native_publication_input_identity")
    return f"{receipts.PREFIX}{commit}/decisions/{operation_id}/publication-input.tar"


def pointer(raw, pin, commit, decision_hash):
    require(isinstance(raw, str) and 0 < len(raw) <= 16384 and re.fullmatch(receipts.SHA, pin),
            "native_publication_protected_pointer")
    value = transport.decode(raw)
    require(set(value) == {"schema", "commit", "operation_id", "gate_mode", "decision_sha256", "issued_utc",
                           "expires_utc", "host", "input"}
            and value["schema"] == SCHEMA and value["commit"] == commit and value["decision_sha256"] == decision_hash
            and value["gate_mode"] in {"global", "demo-a"}
            and transport.sha(transport.canonical(value)) == pin, "native_publication_pointer_scope_or_sha")
    issued, expires = (datetime.fromisoformat(value[key]) for key in ("issued_utc", "expires_utc"))
    require(issued.utcoffset() == expires.utcoffset() == timezone.utc.utcoffset(None)
            and issued <= datetime.now(timezone.utc) < expires and 0 < (expires - issued).total_seconds() <= 3600,
            "native_publication_pointer_expired")
    reference = value["input"]
    require(set(reference) == {"name", "generation", "size", "sha256"}
            and reference["name"] == name(commit, value["operation_id"])
            and re.fullmatch(receipts.RUN, reference["generation"])
            and re.fullmatch(receipts.SHA, reference["sha256"])
            and type(reference["size"]) is int and 0 < reference["size"] <= LIMIT, "native_publication_input_reference")
    return value


def member_name(name):
    require(isinstance(name, str) and len(name) <= 180
            and (name in ESSENTIAL or name.endswith(".json") and all(
                re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", item) for item in name.split("/"))),
            "native_publication_unsafe_bundle_member")
    return name


def stream(source, destination, limit, *, deadline=None):
    total = 0
    digest = sha256()
    while block := source.read(1024 * 1024):
        total += len(block)
        require(total <= limit and (deadline is None or time.monotonic() < deadline),
                "native_publication_input_size_or_deadline")
        destination.write(block)
        digest.update(block)
    require(total == limit, "native_publication_input_incomplete")
    return digest.hexdigest()


def download(reference, token, path):
    require(re.fullmatch(r"[A-Za-z0-9._~+/=-]{20,16384}", token), "native_publication_missing_read_token")
    require(re.fullmatch(re.escape(receipts.PREFIX) + r"[a-f0-9]{40}/decisions/[a-f0-9]{32}/publication-input\.tar",
                         reference["name"]) and re.fullmatch(receipts.RUN, reference["generation"])
            and type(reference["size"]) is int and 0 < reference["size"] <= LIMIT, "native_publication_read_scope")
    generation = reference["generation"]
    query = urlencode({"alt": "media", "generation": generation, "ifGenerationMatch": generation})
    obj = quote(reference["name"], safe="")
    request = Request(f"{receipts.GCS}storage/v1/b/{receipts.BUCKET}/o/{obj}?{query}",
                      headers={"Authorization": "Bearer " + token}, method="GET")
    opener = build_opener(ProxyHandler({}), transport.NoRedirect())
    try:
        deadline = time.monotonic() + DEADLINE
        with (opener.open(request, timeout=30) as response,
              os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as output):
            length = response.headers.get("Content-Length")
            require(length in (None, str(reference["size"])), "native_publication_input_length_header")
            require(stream(response, output, reference["size"], deadline=deadline) == reference["sha256"],
                    "native_publication_input_digest")
    except HTTPError as error:
        status = error.code
        error.close()
        raise transport.Failure("native_publication_input_get", {"http_status": status, "method": "GET"}) from None


def unpack(archive, root):
    root.mkdir(mode=0o700)
    seen = set()
    total = 0
    with tarfile.open(archive, "r:") as source:
        for member in source:
            name = member_name(member.name)
            total += member.size
            require(name not in seen and len(seen) < 4096 and member.type in {tarfile.REGTYPE, tarfile.AREGTYPE}
                    and not member.pax_headers and 0 < member.size <= MEMBER_LIMIT and total <= LIMIT,
                    "native_publication_bundle_member_shape")
            seen.add(name)
            target = root / name
            target.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            require(target.resolve() == target, "native_publication_bundle_member_path")
            with source.extractfile(member) as entry, os.fdopen(
                os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o400), "wb"
            ) as output:
                stream(entry, output, member.size)
    require(ESSENTIAL <= seen, "native_publication_bundle_incomplete")


def pack(root, files, output):
    require(isinstance(files, list), "native_publication_bundle_file_list")
    names = sorted(member_name(name) for name in files)
    require(ESSENTIAL <= set(names) and len(set(names)) == len(names) <= 4096, "native_publication_bundle_file_list")
    total = 0
    with (os.fdopen(os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600), "wb") as target,
          tarfile.open(fileobj=target, mode="w:", format=tarfile.USTAR_FORMAT) as archive):
        for name in names:
            path = root / name
            info = path.lstat()
            total += info.st_size
            require(path.resolve() == path and stat.S_ISREG(info.st_mode) and info.st_nlink == 1
                    and 0 < info.st_size <= MEMBER_LIMIT and total <= LIMIT, "native_publication_pack_file_shape")
            member = tarfile.TarInfo(name)
            member.size, member.mode = info.st_size, 0o400
            with path.open("rb") as stream:
                archive.addfile(member, stream)
    require(output.stat().st_size <= LIMIT, "native_publication_pack_bound")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--folder", type=Path, required=True)
    parser.add_argument("--file-list", type=Path, required=True, help="Exact JSON array of intended bundle paths")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    names = transport.decode(transport._local_bytes(args.file_list, limit=65536))
    pack(args.folder.resolve(strict=True), names, args.output)
    with args.output.open("rb") as result:
        hashed = sha256()
        while block := result.read(1024 * 1024):
            hashed.update(block)
    print(transport.canonical({"sha256": hashed.hexdigest(), "size": args.output.stat().st_size}).decode("ascii"))


if __name__ == "__main__":
    main()
