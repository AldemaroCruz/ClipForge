"""Small explicit runtime configuration; local emulators cannot enter INT."""
from dataclasses import dataclass
import ipaddress
import os
import re
from urllib.parse import urlsplit


BETA_MAX_BYTES = 2 * 1024 ** 3
BETA_MIN_SECONDS = 20
BETA_MAX_SECONDS = 20 * 60
BETA_AUDIO_PADDING_SECONDS = 0.15
BETA_MAX_DIMENSION = 1920
BETA_MAX_ACTIVE = 4
BETA_WORKER_CONCURRENCY = 3
BETA_UPLOAD_SECONDS = 24 * 60 * 60
BETA_RETRIES = 1
BETA_RETRYABLE = frozenset({"WORKER_INTERRUPTED", "SOURCE_UNAVAILABLE", "PROCESSING_FAILED"})


def beta_enabled() -> bool:
    return os.getenv("CLIPFORGE_INT_BETA") == "1"


@dataclass(frozen=True)
class Settings:
    bucket: str
    endpoint: str
    local_test: bool
    dispatch_mode: str
    project: str
    region: str
    job: str


def settings() -> Settings:
    local = os.getenv("CLIPFORGE_CLOUD_LOCAL_TEST", "0") == "1"
    endpoint = os.getenv("CLIPFORGE_GCS_ENDPOINT", "https://storage.googleapis.com").rstrip("/")
    mode = os.getenv("CLIPFORGE_JOBS_DISPATCH_MODE", "cloud_run")
    profile = os.getenv("CLIPFORGE_AUTH_PROFILE", "secure")
    environment = os.getenv("CLIPFORGE_ENVIRONMENT", os.getenv("CLIPFORGE_ENV", "")).lower()
    if local and (profile != "local-http" or environment in {"int", "prod", "production"}):
        raise ValueError("Cloud local test configuration is forbidden in a secure environment")
    if mode not in {"cloud_run", "local_manual"} or (mode == "local_manual" and not local):
        raise ValueError("Invalid Jobs dispatch configuration")
    parsed = urlsplit(endpoint)
    if parsed.username or parsed.password or parsed.query or parsed.fragment or parsed.path:
        raise ValueError("Invalid object storage endpoint")
    if endpoint != "https://storage.googleapis.com" and not (local and parsed.scheme == "http" and parsed.hostname):
        raise ValueError("Only the explicit local test profile can use a storage emulator")
    if local:
        host = parsed.hostname or ""
        try:
            address = ipaddress.ip_address(host)
            private_endpoint = address.is_private or address.is_loopback
        except ValueError:
            private_endpoint = re.fullmatch(r"[a-z0-9][a-z0-9-]*", host) is not None
        if parsed.scheme != "http" or not private_endpoint or mode != "local_manual":
            raise ValueError("Local acceptance requires an explicit private emulator and manual dispatch")
    bucket = os.getenv("CLIPFORGE_GCS_BUCKET", "")
    if not re.fullmatch(r"[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]", bucket):
        raise ValueError("Missing or invalid storage bucket")
    project = os.getenv("CLIPFORGE_CLOUD_PROJECT", "")
    region = os.getenv("CLIPFORGE_CLOUD_REGION", "")
    job = os.getenv("CLIPFORGE_CLOUD_JOB", "")
    if mode == "cloud_run" and not all(re.fullmatch(r"[a-z][a-z0-9-]{1,62}", v) for v in (project, region, job)):
        raise ValueError("Missing Cloud Run Jobs identity")
    return Settings(bucket, endpoint, local, mode, project, region, job)
