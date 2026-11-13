"""Publish the already scanned OCI archive without changing its manifest digest.

Future manual INT operation only; source commit/application CI and exact expected
digest are checked before any registry write. Credentials use a private authfile.
"""
import base64
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile

from scripts import int_release
from scripts.check_tf_int import require

SKOPEO = "quay.io/skopeo/stable:v1.20.0@sha256:47853bb9fb24202af9110531ebd6e43c5f97701254ca290596640290d17942f4"


def archive_digest(path):
    with tarfile.open(path, "r") as archive:
        member = archive.getmember("index.json")
        require(member.isfile() and member.size <= 65536, "Invalid OCI index")
        index = json.load(archive.extractfile(member))
        require(len(index.get("manifests", [])) == 1, "Only the reviewed single-platform runtime may be published")
        descriptor = index["manifests"][0]
        digest = descriptor.get("digest", "")
        require(digest.startswith("sha256:") and len(digest) == 71, "Invalid OCI manifest descriptor")
        member = archive.getmember("blobs/sha256/" + digest[7:])
        require(member.isfile() and member.size <= 4 * 1024 * 1024, "Invalid OCI image manifest")
        raw = archive.extractfile(member).read()
        require("sha256:" + hashlib.sha256(raw).hexdigest() == digest, "OCI manifest descriptor differs from bytes")
        value = json.loads(raw)
        require(value.get("mediaType") in {"application/vnd.oci.image.manifest.v1+json", "application/vnd.docker.distribution.manifest.v2+json"},
                "Expected an image manifest, never a config ID or unreviewed index")
        return digest


def publish(path, environ):
    int_release.hosted_context(environ)
    require(environ.get("INT_APPROVED_COMMIT") == environ.get("GITHUB_SHA"), "Exact owner-approved source commit required")
    int_release.require_application_ci(environ)
    image = environ.get("RUNTIME_IMAGE", "")
    int_release.inputs(environ)
    digest = archive_digest(path)
    require(image.rsplit("@", 1)[1] == digest, "Rebuilt archive differs from the approved manifest; review instead of publishing")
    require(environ.get("INT_RUNTIME_SCANS_PASSED") == "true", "All runtime scans must succeed before publication")
    authfile = path.parent / "registry-auth-private.json"
    value = {"auths": {"us-central1-docker.pkg.dev": {"auth": base64.b64encode(("oauth2accesstoken:" + environ["GCP_ACCESS_TOKEN"]).encode()).decode()}}}
    try:
        with authfile.open("x", encoding="utf-8") as stream:
            json.dump(value, stream)
        authfile.chmod(0o600)
        (path.parent / "skopeo-publish-temp").mkdir(mode=0o700)
        uid, gid = str(os.getuid()), str(os.getgid())
        target = image
        args = ["docker", "run", "--rm", "--pull=never", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges",
                "--user=" + uid + ":" + gid, "--tmpfs=/tmp:rw,nosuid,nodev,noexec,size=64m",
                "--mount=type=bind,source=" + str(path.parent) + ",target=/private", SKOPEO,
                "--tmpdir=/private/skopeo-publish-temp", "copy", "--preserve-digests", "--authfile=/private/" + authfile.name,
                "oci-archive:/private/" + path.name, "docker://" + target]
        result = subprocess.run(args, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=1200, check=False)
        require(result.returncode == 0, "Exact-digest publication failed; never retry automatically")
        # Same OAuth token reads actual registry manifest headers + bytes.
        int_release.verify_published_runtime(image, environ)
        print(json.dumps({"commit": environ["GITHUB_SHA"], "image": image, "digest_verified": True}))
    finally:
        if authfile.exists():
            authfile.unlink()


if __name__ == "__main__":
    try:
        publish(Path(os.environ["INT_RUNTIME_ARCHIVE"]), os.environ)
    except Exception:
        print("INT publication blocked; no credentials or registry response logged. Preserve scan evidence.")
        raise SystemExit(1)
