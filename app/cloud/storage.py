"""Private GCS JSON API using only runtime metadata credentials or test emulator."""
import base64
import binascii
import hashlib
from pathlib import Path
import re
from urllib.parse import parse_qs, quote, urlsplit
import requests
from .config import settings

_TRANSPORT_ERRORS = (requests.ConnectionError, requests.Timeout, requests.exceptions.ChunkedEncodingError)


class StorageError(RuntimeError):
    pass


class TransportError(StorageError):
    pass


class PreconditionFailed(StorageError):
    pass


class ObjectMissing(StorageError):
    pass


class InvalidUpload(StorageError):
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


def request(method, url, *, stream=False, timeout=(5, 120), extra_statuses=(), **kwargs):
    cfg = settings()
    headers = dict(kwargs.pop("headers", {}))
    session = requests.Session()
    session.trust_env = False
    try:
        if not cfg.local_test:
            headers["Authorization"] = "Bearer " + token()
        response = session.request(method, url, headers=headers, timeout=timeout, stream=stream, allow_redirects=False, **kwargs)
    except _TRANSPORT_ERRORS:
        session.close()
        raise TransportError("Cloud request transport failed") from None
    except requests.RequestException:
        session.close()
        raise StorageError("Cloud request invalid") from None
    except BaseException:
        session.close()
        raise
    if (response.status_code not in {200, 201, 206} and response.status_code not in extra_statuses
            and not (method == "DELETE" and response.status_code == 204)):
        status = response.status_code
        response.close()
        session.close()
        if status == 404:
            raise ObjectMissing("Cloud object or endpoint unavailable (HTTP 404)")
        if status == 412:
            raise PreconditionFailed("Cloud request denied or unavailable (HTTP 412)")
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


def beta_original(workspace_id, job_id):
    for part in (workspace_id, job_id):
        if not isinstance(part, str) or not re.fullmatch(r"[a-f0-9]{32}", part):
            raise StorageError("Invalid pilot original identity")
    return f"workspaces/{workspace_id}/jobs/{job_id}/original/input.mp4"


def _resumable_location(location, name):
    """Check a private resumable capability against its server-owned destination."""
    cfg = settings()
    endpoint = urlsplit(cfg.endpoint)
    path = "/upload/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    if not isinstance(location, str) or len(location) > 4096 or not location.isascii() \
            or any(ord(char) < 33 or ord(char) > 126 for char in location):
        raise StorageError("Invalid resumable upload destination")
    try:
        parsed = urlsplit(location)
        query = parse_qs(parsed.query, keep_blank_values=True, max_num_fields=8)
        upload_id = query.get("upload_id", [])
        if (parsed.scheme != endpoint.scheme or parsed.netloc != endpoint.netloc or parsed.path != path
                or parsed.fragment or len(upload_id) != 1
                or not re.fullmatch(r"[A-Za-z0-9_-]+", upload_id[0])
                or query.get("name", [name]) != [name]
                or query.get("uploadType", ["resumable"]) != ["resumable"]
                or query.get("ifGenerationMatch", ["0"]) != ["0"]):
            raise ValueError("Invalid resumable upload destination")
    except ValueError:
        raise StorageError("Invalid resumable upload destination") from None
    return location


def start_resumable(name, size, origin):
    """Mint a create-only capability for exactly one server-selected object."""
    cfg = settings()
    endpoint = urlsplit(cfg.endpoint)
    path = "/upload/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    response = request(
        "POST", cfg.endpoint + path,
        params={"uploadType": "resumable", "name": name, "ifGenerationMatch": "0"},
        json={"contentType": "video/mp4"},
        headers={"Origin": origin, "X-Upload-Content-Type": "video/mp4",
                 "X-Upload-Content-Length": str(size)},
        timeout=(4, 10),
    )
    try:
        return _resumable_location(response.headers.get("Location", ""), name)
    finally:
        close(response)


def cancel_resumable(location, name):
    location = _resumable_location(location, name)
    try:
        response = request("DELETE", location, timeout=(4, 10), extra_statuses=(410, 499),
                           headers={"Content-Length": "0"})
    except ObjectMissing:
        return
    close(response)


def beta_original_metadata(name):
    """Read only trusted GCS metadata for the allocated original."""
    try:
        response = request("GET", object_url(name), timeout=(4, 10),
                           params={"fields": "name,generation,size,contentType,contentEncoding,md5Hash"})
    except ObjectMissing:
        return None
    try:
        item = response.json()
        if (not isinstance(item, dict) or item.get("name") != name
                or item.get("contentType") != "video/mp4" or item.get("contentEncoding")):
            raise InvalidUpload("Original upload metadata mismatch")
        size, generation = item.get("size"), item.get("generation")
        if (not isinstance(size, str) or not re.fullmatch(r"[1-9][0-9]{0,19}", size)
                or not isinstance(generation, str) or not re.fullmatch(r"[1-9][0-9]{0,30}", generation)):
            raise InvalidUpload("Original upload size or generation is invalid")
        digest = base64.b64decode(item["md5Hash"], validate=True)
        if len(digest) != 16:
            raise InvalidUpload("Original upload integrity metadata mismatch")
        return {"name": name, "bytes": int(size), "generation": generation,
                "content_type": "video/mp4", "md5": digest.hex()}
    except (ValueError, TypeError, KeyError, binascii.Error):
        raise InvalidUpload("Original upload integrity metadata mismatch") from None
    finally:
        close(response)


def _read_with_retry(url, **options):
    try:
        return request("GET", url, **options)
    except TransportError:
        return request("GET", url, **options)


def _recover_upload(name, size, content_type, md5):
    """Verify the exact live object after losing a create-only POST response."""
    try:
        response = _read_with_retry(object_url(name), timeout=(4, 10),
                                    params={"fields": "name,generation,size,contentType,contentEncoding,md5Hash"})
    except ObjectMissing:
        return None
    try:
        item = response.json()
        generation = item["generation"]
        if (item["name"] != name or not isinstance(generation, str)
                or not re.fullmatch(r"[1-9][0-9]{0,30}", generation)
                or item["size"] != str(size) or item["contentType"] != content_type
                or item.get("contentEncoding")
                or base64.b64decode(item["md5Hash"], validate=True) != md5):
            raise ValueError("Upload receipt mismatch")
        return generation
    except (KeyError, TypeError, ValueError, binascii.Error):
        raise StorageError("Object publication metadata mismatch") from None
    finally:
        close(response)


def _publish_upload(url, name, source, size, content_type):
    response = request("POST", url, params={"uploadType": "media", "name": name, "ifGenerationMatch": "0"},
                       data=source, headers={"Content-Type": content_type, "Content-Length": str(size)})
    try:
        item = response.json()
        generation = str(item["generation"])
        if item["name"] != name or not re.fullmatch(r"[1-9][0-9]{0,30}", generation) or int(item["size"]) != size:
            raise ValueError("Upload receipt mismatch")
        return generation
    except (KeyError, TypeError, ValueError):
        raise StorageError("Object publication metadata mismatch") from None
    finally:
        close(response)


def upload(name, source, content_type):
    cfg = settings()
    source.seek(0)
    digest = hashlib.sha256()
    checksum = hashlib.md5(usedforsecurity=False)
    size = 0
    for chunk in iter(lambda: source.read(1024 * 1024), b""):
        digest.update(chunk)
        checksum.update(chunk)
        size += len(chunk)
    url = cfg.endpoint + "/upload/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    for attempt in range(2):
        source.seek(0)
        try:
            generation = _publish_upload(url, name, source, size, content_type)
        except (TransportError, PreconditionFailed) as error:
            if attempt == 0 and isinstance(error, PreconditionFailed):
                raise
            generation = _recover_upload(name, size, content_type, checksum.digest())
            if generation is None:
                if attempt:
                    raise
                continue
        return {"name": name, "generation": generation, "bytes": size,
                "sha256": digest.hexdigest(), "content_type": content_type}


def _pinned_options(item, range_header=None):
    generation = item["generation"]
    if not isinstance(generation, str) or not re.fullmatch(r"[1-9][0-9]{0,30}", generation):
        raise StorageError("Invalid stored object generation")
    headers = {}
    if range_header:
        if not re.fullmatch(r"bytes=(?:[0-9]+-[0-9]*|-[0-9]+)", range_header):
            raise StorageError("Unsupported byte range")
        headers["Range"] = range_header
    return {"params": {"alt": "media", "generation": generation}, "headers": headers, "stream": True}


def open_object(item, range_header=None, *, retry=True):
    url = object_url(item["name"])
    options = _pinned_options(item, range_header)
    if retry:
        return _read_with_retry(url, **options)
    return request("GET", url, **options)


def _download_once(item, path):
    # GCS exposes MD5 for non-composite browser uploads. This checks the
    # transport checksum, while the immutable object generation pins identity.
    if "sha256" in item:
        digest, expected = hashlib.sha256(), item["sha256"]
    else:
        digest, expected = hashlib.md5(usedforsecurity=False), item["md5"]
    size = 0
    created = False
    complete = False
    response = open_object(item, retry=False)
    try:
        with path.open("xb") as target:
            created = True
            for chunk in response.iter_content(1024 * 1024):
                size += len(chunk)
                if size > item["bytes"]:
                    raise StorageError("Stored object size mismatch")
                target.write(chunk)
                digest.update(chunk)
        if size != item["bytes"] or digest.hexdigest() != expected:
            raise StorageError("Stored object integrity mismatch")
        complete = True
    except _TRANSPORT_ERRORS:
        raise TransportError("Cloud object transfer interrupted") from None
    finally:
        close(response)
        if created and not complete:
            path.unlink(missing_ok=True)


def download(item, path):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        _download_once(item, path)
    except TransportError:
        _download_once(item, path)


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


def delete_staged(item, prefix, *, live_only=False):
    if not item["name"].startswith(prefix) or not re.fullmatch(r"workspaces/[a-f0-9]{32}/jobs/[a-f0-9]{32}/tasks/[a-f0-9]{32}/", prefix):
        raise StorageError("Cleanup escaped its task prefix")
    if live_only:
        project_scope = prefix.split("tasks/", 1)[0]
        return delete_project_live(item, project_scope)
    response = request("DELETE", object_url(item["name"]), params={"generation": item["generation"], "ifGenerationMatch": item["generation"]})
    close(response)


def _project_prefix(prefix):
    if not re.fullmatch(r"workspaces/[a-f0-9]{32}/jobs/[a-f0-9]{32}/", prefix):
        raise StorageError("Invalid project cleanup prefix")


def _project_object(item, prefix):
    name, generation = item.get("name", ""), item.get("generation", "")
    if (not isinstance(name, str) or not name.startswith(prefix)
            or not re.fullmatch(r"(?:original/(?:input|[a-f0-9]{32})[.]mp4|"
                                r"tasks/[a-f0-9]{32}/[1-9][0-9]*/[a-z0-9._-]+)",
                                name[len(prefix):])
            or not isinstance(generation, str) or not re.fullmatch(r"[1-9][0-9]{0,30}", generation)):
        raise StorageError("Unexpected project object inventory")
    return name, generation


def list_project_live(prefix):
    """Enumerate only current objects, after project publishers were fenced."""
    _project_prefix(prefix)
    cfg = settings()
    listing = cfg.endpoint + "/storage/v1/b/" + quote(cfg.bucket, safe="") + "/o"
    params = {"prefix": prefix, "fields": "items(name,generation),nextPageToken"}
    result = []
    pages = set()
    while True:
        response = request("GET", listing, params=params, timeout=(4, 15))
        try:
            data = response.json()
        finally:
            close(response)
        for item in data.get("items", []):
            name, generation = _project_object(item, prefix)
            result.append({"name": name, "generation": generation})
        page = data.get("nextPageToken")
        if not page:
            return result
        if not isinstance(page, str) or page in pages or len(page) > 4096:
            raise StorageError("Invalid project inventory pagination")
        pages.add(page)
        params["pageToken"] = page


def delete_project_live(item, prefix):
    """Detach the live version while preserving bucket retention and versioning."""
    _project_prefix(prefix)
    name, generation = _project_object(item, prefix)
    try:
        response = request("DELETE", object_url(name), timeout=(4, 15),
                           params={"ifGenerationMatch": generation})
    except ObjectMissing:
        return
    close(response)
