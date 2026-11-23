"""Run the previously reviewed static Skopeo executable without its container."""

from hashlib import sha256
import os
from pathlib import Path
import re
import stat
import struct
import subprocess
import tarfile
from tempfile import TemporaryDirectory

from scripts import int_guest_inventory as transport


ARCHIVE_BYTES = 39735808
ARCHIVE_SHA256 = "3f6a8f90fffc5133cfc78f49ebf308656604813b157dca43a23660e27212eacb"
MANIFEST = "edb24ff2219bd534b34896b0c675d890808372fd10387ec3c4deab70fd309dc1"
FILES = {
    "usr/bin/skopeo": ("skopeo", 0o500, "fcb3f82e81d4f4aafe81a6aa4121d6f9fb06cb2fc884a69ded306966c723ee0c"),
    "etc/ssl/certs/ca-certificates.crt": ("ca.pem", 0o400, "64e7c24b0536b525fb19b145768bd5e6e12ced0df3db837c34553ea789acd143"),
    "etc/containers/policy.json": ("policy.json", 0o400, "e69fc43eb736c76f09e39e6439a21a14b3cd7c2132c985c7b3dde8f2b6f219d5"),
}
DIRECTORIES = ("tmp", "registries.d", "certs.d")
CONFIG = b"unqualified-search-registries = []\n"
CONTAINER_SOURCE = "/input/image.oci.tar"
SETPRIV = Path("/usr/bin/setpriv")
TARGETS = {
    "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/runtime@sha256:40a22f3fcceccfe163958d9c22882fc22070807bd061de836ce94b9a7d805e15",
    "us-central1-docker.pkg.dev/clipforgebeta2/clipforge-int/db01-noble-client@sha256:24e4d9ccea365859c6f455c3780c8abe6a0df3f1150e60380e2b2cc73e0dc5b5",
}
SCHEMA = "clipforge-int-demo-a-standalone-skopeo-1"
MAX_BLOB = 64 * 1024 * 1024
require = transport.require


def identity(path):
    info = path.lstat()
    require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and path.resolve() == path,
            "demo_a_native_regular_file")
    return info


def hash_stream(stream, maximum, *, output=None):
    digest = sha256()
    total = 0
    while block := stream.read(1024 * 1024):
        total += len(block)
        require(total <= maximum, "demo_a_native_file_limit")
        digest.update(block)
        if output is not None:
            output.write(block)
    require(total == maximum, "demo_a_native_file_size")
    return digest.hexdigest()


def hash_file(path, limit=MAX_BLOB):
    before = identity(path)
    require(0 < before.st_size <= limit, "demo_a_native_file_limit")
    with path.open("rb") as stream:
        after = os.fstat(stream.fileno())
        require((after.st_dev, after.st_ino) == (before.st_dev, before.st_ino), "demo_a_native_file_changed")
        result = hash_stream(stream, after.st_size)
        observed = os.fstat(stream.fileno())
    require((observed.st_ctime_ns, observed.st_mtime_ns) == (before.st_ctime_ns, before.st_mtime_ns),
            "demo_a_native_file_changed")
    return result


def private_directory(path, *, empty=False):
    info = path.lstat()
    require(stat.S_ISDIR(info.st_mode) and path.resolve() == path and info.st_uid == os.geteuid()
            and stat.S_IMODE(info.st_mode) == 0o700 and (not empty or not any(path.iterdir())),
            "demo_a_native_private_directory")


def write_private(path, mode, contents):
    with os.fdopen(os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb") as stream:
        stream.write(contents)


def verify_static_elf(binary):
    with binary.open("rb") as stream:
        header = stream.read(64)
        require(len(header) == 64 and header[:7] == b"\x7fELF\x02\x01\x01", "demo_a_native_skopeo_elf")
        kind, cpu = struct.unpack_from("<HH", header, 16)
        segment_offset = struct.unpack_from("<Q", header, 32)[0]
        width, segments = struct.unpack_from("<HH", header, 54)
        require(kind == 2 and cpu == 62 and width == 56 and 0 < segments <= 24 and 64 <= segment_offset < 4096,
                "demo_a_native_skopeo_elf")
        stream.seek(segment_offset)
        table = stream.read(width * segments)
    require(len(table) == width * segments and all(
        struct.unpack_from("<I", table, index * width)[0] not in {2, 3} for index in range(segments)
    ), "demo_a_native_skopeo_dynamic_loader")


def verify_privilege():
    require(os.getuid() == os.geteuid() != 0 and os.getgid() == os.getegid() != 0, "demo_a_native_unprivileged_user")
    status = Path("/proc/self/status").read_text(encoding="ascii")
    masks = re.findall(r"^Cap(Eff|Prm|Inh|Amb):\s+([0-9a-f]+)$", status, re.MULTILINE)
    require({field for field, _ in masks} == {"Eff", "Prm", "Inh", "Amb"} and all(int(mask, 16) == 0 for _, mask in masks),
            "demo_a_native_unprivileged_capabilities")
    binary = identity(SETPRIV)
    require(binary.st_uid == 0 and stat.S_IMODE(binary.st_mode) == 0o755, "demo_a_native_setpriv_provenance")
    return hash_file(SETPRIV)


def stage(archive, root):
    archive = Path(archive)
    root = Path(root)
    verify_privilege()
    private_directory(root.parent)
    require(identity(archive).st_size == ARCHIVE_BYTES and hash_file(archive) == ARCHIVE_SHA256,
            "demo_a_native_publisher_archive")
    root.mkdir(mode=0o700)
    for dirname in DIRECTORIES:
        (root / dirname).mkdir(mode=0o700)
    write_private(root / "registries.conf", 0o400, CONFIG)
    found = set()
    with tarfile.open(archive, "r:") as outer:
        member = outer.getmember("blobs/sha256/" + MANIFEST)
        require(member.isfile() and 0 < member.size < 16384, "demo_a_native_publisher_manifest")
        with outer.extractfile(member) as source:
            raw = source.read()
        require(sha256(raw).hexdigest() == MANIFEST, "demo_a_native_publisher_manifest")
        for layer in transport.decode(raw)["layers"]:
            digest = layer["digest"]
            require(re.fullmatch(r"sha256:[a-f0-9]{64}", digest) and layer["mediaType"] == "application/vnd.oci.image.layer.v1.tar",
                    "demo_a_native_publisher_layer")
            member = outer.getmember("blobs/sha256/" + digest[7:])
            require(member.isfile() and member.size == layer["size"] and 0 < member.size <= MAX_BLOB,
                    "demo_a_native_publisher_layer")
            with outer.extractfile(member) as source:
                require(hash_stream(source, member.size) == digest[7:], "demo_a_native_publisher_layer")
            with outer.extractfile(member) as source, tarfile.open(fileobj=source, mode="r|") as files:
                for item in files:
                    name = item.name.removeprefix("./")
                    if name in FILES:
                        require(name not in found and item.isfile() and 0 < item.size <= MAX_BLOB,
                                "demo_a_native_publisher_member")
                        local, mode, expected = FILES[name]
                        with files.extractfile(item) as data, os.fdopen(
                            os.open(root / local, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode), "wb"
                        ) as output:
                            require(hash_stream(data, item.size, output=output) == expected, "demo_a_native_publisher_member")
                        found.add(name)
    require(found == FILES.keys() and hash_file(archive) == ARCHIVE_SHA256, "demo_a_native_publisher_archive_changed")
    return verify(root)


def verify(root):
    root = Path(root)
    privilege_hash = verify_privilege()
    private_directory(root)
    require({item.name for item in root.iterdir()} == {*DIRECTORIES, "registries.conf", *(row[0] for row in FILES.values())},
            "demo_a_native_staging_contents")
    for name in DIRECTORIES:
        private_directory(root / name, empty=True)
    for name, mode, expected in (*FILES.values(), ("registries.conf", 0o400, sha256(CONFIG).hexdigest())):
        path = root / name
        info = identity(path)
        require(info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == mode and hash_file(path) == expected,
                "demo_a_native_staged_file_changed")
    verify_static_elf(root / "skopeo")
    return {"schema": SCHEMA, "publisher_manifest": "sha256:" + MANIFEST, "publisher_archive_sha256": ARCHIVE_SHA256,
            "publisher_files": {name: row[2] for name, row in FILES.items()}, "setpriv_sha256": privilege_hash,
            "uid": os.geteuid(), "gid": os.getegid(), "no_effective_permitted_inheritable_or_ambient_caps": True}


def _args(root, source, authfile, destination, cert_dir, tmp):
    return [str(SETPRIV), "--no-new-privs", "--inh-caps=-all", "--ambient-caps=-all", "--",
            str(root / "skopeo"), "--tmpdir=" + tmp, "--policy=" + str(Path(tmp) / "policy.json"),
            "--registries.d=" + str(root / "registries.d"), "copy", "--preserve-digests", "--dest-tls-verify=true",
            "--retry-times=0", "--dest-cert-dir=" + str(cert_dir), "--dest-authfile=" + str(authfile),
            "oci-archive:" + str(source), "docker://" + destination]


def native_policy(raw, source):
    policy = transport.decode(raw)
    allowance = [{"type": "insecureAcceptAnything"}]
    require(policy == {"default": [{"type": "reject"}], "transports": {"oci-archive": {CONTAINER_SOURCE: allowance}}},
            "demo_a_native_policy_exact_source_only")
    policy["transports"]["oci-archive"] = {str(source): allowance}
    return transport.canonical(policy)


def _run_copy(root, source, authfile, destination, *, ca, cert_dir, timeout):
    verify(root)
    info = identity(source)
    require(0 < info.st_size <= 256 * 1024 * 1024 and info.st_uid == os.geteuid() and stat.S_IMODE(info.st_mode) == 0o400
            and source.parent == root.parent and ":" not in str(source), "demo_a_native_staged_source")
    auth = identity(authfile)
    require(authfile.parent == root.parent and auth.st_uid == os.geteuid() and stat.S_IMODE(auth.st_mode) == 0o400
            and 0 < auth.st_size <= 4096, "demo_a_native_private_credential")
    with TemporaryDirectory(prefix="copy.", dir=root / "tmp") as tmp:
        ephemeral = Path(tmp)
        for dirname in ("home", "xdg-config", "xdg-cache", "xdg-data", "xdg-runtime"):
            (ephemeral / dirname).mkdir(mode=0o700)
        write_private(ephemeral / "policy.json", 0o400, native_policy((root / "policy.json").read_bytes(), source))
        child = {
            "PATH": "/usr/bin:/bin", "LANG": "C.UTF-8", "HOME": str(ephemeral / "home"), "TMPDIR": tmp,
            "XDG_CONFIG_HOME": str(ephemeral / "xdg-config"), "XDG_CACHE_HOME": str(ephemeral / "xdg-cache"),
            "XDG_DATA_HOME": str(ephemeral / "xdg-data"), "XDG_RUNTIME_DIR": str(ephemeral / "xdg-runtime"),
            "SSL_CERT_FILE": str(ca), "SSL_CERT_DIR": str(root / "certs.d"),
            "CONTAINERS_REGISTRIES_CONF": str(root / "registries.conf"),
        }
        return subprocess.run(_args(root, source, authfile, destination, cert_dir, tmp), cwd=tmp, env=child, stdin=subprocess.DEVNULL,
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout, check=False).returncode


def copy(root, source, authfile, destination):
    require(destination in TARGETS, "demo_a_native_destination_not_approved")
    root, source, authfile = Path(root), Path(source), Path(authfile)
    return _run_copy(root, source, authfile, destination, ca=root / "ca.pem", cert_dir=root / "certs.d", timeout=360)
