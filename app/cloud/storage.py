"""Private GCS JSON API using only runtime metadata credentials or test emulator."""
import hashlib
from pathlib import Path
import re
from urllib.parse import quote
import requests
from .config import settings


class StorageError(RuntimeError):
    pass


def token():
    # Fixed metadata identity: no gcloud, user ADC file, key or configurable URL.
    with requests.Session() as session:
        session.trust_env = False
        response = session.get("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                               headers={"Metadata-Flavor": "Google"}, timeout=(3, 10), allow_redirects=False)
        if response.status_code != 200 or response.headers.get("Metadata-Flavor") != "Google":
            raise StorageError("Runtime metadata identity unavailable")
        value = response.json().get("access_token")
        if not isinstance(value, str) or not value:
            raise StorageError("Runtime metadata identity unavailable")
        return value


def request(method, url, *, stream=False, **kwargs):
    cfg = settings()
    headers = kwargs.pop("headers", {})
    if not cfg.local_test:
        headers["Authorization"] = "Bearer " + token()
    session = requests.Session()
    session.trust_env = False
    try:
        response = session.request(method, url, headers=headers, timeout=(5, 120), stream=stream, allow_redirects=False, **kwargs)
    except requests.RequestException:
        session.close()
        raise StorageError("Cloud request transport failed") from None
    if response.status_code not in {200, 201, 206} and not (method == "DELETE" and response.status_code == 204):
        status = response.status_code
        response.close()
        session.close()
        raise StorageError(f"Cloud request denied or unavailable (HTTP {status})")
    # Closing the response also returns its connection; retain session for stream.
    response._clipforge_session = session
    return response


def close(response):
    response.close()
    response._clipforge_session.close()


def object_url(name):
    cfg = settings()
    if not re.fullmatch(r"[a-z0-9/._-]+", name) or ".." in name:
        raise StorageError("Invalid opaque object name")
    return cfg.endpoint + "/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o/" + quote(name, safe="")


def upload(name, source, content_type):
    cfg = settings()
    source.seek(0)
    digest = hashlib.sha256()
    size = 0
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
        size += len(chunk)
    source.seek(0)
    url = cfg.endpoint + "/upload/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    response = request("POST", url, params={"uploadType": "media", "name": name, "ifGenerationMatch": "0"},
                       data=source, headers={"Content-Type": content_type, "Content-Length": str(size)})
    try:
        result = response.json()
        if result.get("name") != name or not str(result.get("generation", "")).isdigit() or int(result.get("size", -1)) != size:
            raise StorageError("Object publication metadata mismatch")
        return {"name": name, "generation": str(result["generation"]), "bytes": size,
                "sha256": digest.hexdigest(), "content_type": content_type}
    finally:
        close(response)


def open_object(item, range_header=None):
    headers = {}
    if range_header:
        if not re.fullmatch(r"bytes=(?:[0-9]+-[0-9]*|-[0-9]+)", range_header):
            raise StorageError("Unsupported byte range")
        headers["Range"] = range_header
    return request("GET", object_url(item["name"]), params={"alt": "media", "generation": item["generation"]}, headers=headers, stream=True)


def download(item, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    response = open_object(item)
    digest = hashlib.sha256()
    size = 0
    try:
        with path.open("xb") as target:
            for chunk in response.iter_content(1024 * 1024):
                size += len(chunk)
                if size > item["bytes"]:
                    raise StorageError("Stored object size mismatch")
                target.write(chunk)
                digest.update(chunk)
        if size != item["bytes"] or digest.hexdigest() != item["sha256"]:
            raise StorageError("Stored object integrity mismatch")
    finally:
        close(response)


def list_staged(prefix):
    """Only exact server-generated task prefixes can enter cleanup inventory."""
    if not re.fullmatch(r"workspaces/[a-f0-9]{32}/jobs/[a-f0-9]{32}/tasks/[a-f0-9]{32}/", prefix):
        raise StorageError("Invalid staged task prefix")
    cfg = settings()
    url = cfg.endpoint + "/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    params = {"prefix": prefix, "maxResults": "1000", "fields": "items(name,generation),nextPageToken"}
    result = []
    while True:
        response = request("GET", url, params=params)
        try:
            data = response.json()
            for item in data.get("items", []):
                if not item.get("name", "").startswith(prefix) or not re.fullmatch(r"[1-9][0-9]*/[a-z0-9._-]+", item["name"][len(prefix):]) or not str(item.get("generation", "")).isdigit():
                    raise StorageError("Unexpected staged object inventory")
                result.append({"name": item["name"], "generation": str(item["generation"])})
            page = data.get("nextPageToken")
            if not page:
                return result
            params["pageToken"] = page
        finally:
            close(response)


def delete_staged(item, prefix):
    if not item["name"].startswith(prefix) or not re.fullmatch(r"workspaces/[a-f0-9]{32}/jobs/[a-f0-9]{32}/tasks/[a-f0-9]{32}/", prefix):
        raise StorageError("Cleanup escaped its task prefix")
    response = request("DELETE", object_url(item["name"]), params={"generation": item["generation"], "ifGenerationMatch": item["generation"]})
    close(response)
