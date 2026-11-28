"""Public beta origin, fixed-route Cloud Run IAM proxy and static assets."""

from pathlib import Path
import re
from threading import Lock
from time import monotonic

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, JSONResponse, StreamingResponse
import requests
from starlette.background import BackgroundTask
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders


PUBLIC_HOST = "clipforge-int-beta-816643438938.us-central1.run.app"
PUBLIC_ORIGIN = "https://" + PUBLIC_HOST
API_ORIGIN = "https://clipforge-int-beta-api-816643438938.us-central1.run.app"
PROXY_ORIGIN_HEADER = "x-clipforge-public-origin"
METADATA_IDENTITY = (
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/identity"
)
REQUEST_SIZE = 32 * 1024
LOGO_REQUEST_SIZE = 5 * 1024 * 1024
ASSETS = frozenset({
    "account.css", "account.js", "auth.js", "recover.js", "beta.css", "beta.js", "mvp.css", "mvp.js", "editorial.js",
    "caption-font.ttf", "caption-font-license.txt", "logos.js", "transcript.js", "publication.js",
})
STATIC = Path(__file__).with_name("static")
JOB = r"[a-f0-9]{32}"
CLIP = r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}\.mp4"
EXPORT_FILE = r"clip\.(?:mp4|srt|vtt)"
MEDIA_ROUTE = rf"/jobs/{JOB}/(?:clips/{CLIP}|source|exports/{JOB}/files/clip\.mp4)"
LOGO_UPLOAD_ROUTE = rf"/creator-logos(?:/{JOB})?"
ROUTES = {
    "GET": (
        r"/(?:|login|recover|account|health|environment)",
        r"/auth/(?:csrf|me|users|admin/audit)",
        rf"/projects|/jobs/{JOB}(?:/clips/{CLIP}|/source|/workspace|/exports|/exports/{JOB}/files/{EXPORT_FILE})?",
        rf"/jobs/{JOB}/clips[.]zip",
        r"/beta/limits",
        r"/ai/config",
        rf"/caption-styles(?:/{JOB})?",
        rf"/creator-logos(?:/{JOB}/[1-9][0-9]{{0,9}})?",
        rf"/jobs/{JOB}/(?:selections(?:/context|/{JOB})?|drafts(?:/{JOB})?|deletion)",
        rf"/jobs/{JOB}/transcript-selection",
        rf"/jobs/{JOB}/publication(?:/file)?",
        rf"/jobs/{JOB}/clips/{CLIP}/(?:captions|subtitles/(?:srt|vtt))",
    ),
    "POST": (
        r"/auth/(?:login|logout|password|recover|users)",
        r"/caption-styles",
        r"/creator-logos",
        rf"/auth/(?:users/{JOB}/deactivate|admin/users/{JOB}/recovery)",
        rf"/beta/(?:uploads|uploads/{JOB}/start|jobs/{JOB}/retry)",
        rf"/jobs/{JOB}/editor/(?:range|exports)",
        rf"/jobs/{JOB}/transcript-selection/(?:prepare|drafts)",
        rf"/jobs/{JOB}/caption-highlight",
        rf"/jobs/{JOB}/publication/(?:preview|suggestions|reuse)",
        rf"/jobs/{JOB}/exports/{JOB}/retry",
        rf"/jobs/{JOB}/(?:selections(?:/preview|/{JOB}/candidates/[1-5]/draft)?|drafts(?:/{JOB}/exports)?|deletion)",
        rf"/jobs/{JOB}/clips/{CLIP}/captions/retry",
    ),
    "PUT": (rf"/jobs/{JOB}/(?:drafts/{JOB}|clips/{CLIP}/captions|captions)",
            rf"/caption-styles/(?:{JOB}|default)", rf"/creator-logos/{JOB}", rf"/jobs/{JOB}/publication"),
    "DELETE": (rf"/caption-styles/{JOB}", rf"/creator-logos/{JOB}"),
}
INBOUND = {
    "accept", "content-type", "cookie", "idempotency-key", "origin",
    "sec-fetch-site", "x-csrf-token",
}
OUTBOUND = {
    "accept-ranges", "content-disposition", "content-length", "content-range",
    "content-type", "retry-after",
}
REDIRECTS = frozenset({"/", "/login", "/account", "/recover"})
READ_METHODS = frozenset({"GET", "HEAD"})


def allowed(method, path):
    method = "GET" if method == "HEAD" else method
    return ".." not in path and any(re.fullmatch(rule, path) for rule in ROUTES.get(method, ()))


def validate_request(request):
    if request.headers.getlist("host") != [PUBLIC_HOST]:
        raise HTTPException(421, "Abre la URL oficial de ClipForge INT.")
    origins = request.headers.getlist("origin")
    if origins not in ([], [PUBLIC_ORIGIN]) or request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "Origen de la solicitud no permitido.")
    if request.method not in READ_METHODS and origins != [PUBLIC_ORIGIN]:
        raise HTTPException(403, "Origen de la solicitud no permitido.")


def session():
    client = requests.Session()
    client.trust_env = False
    return client


class Identity:
    def __init__(self):
        self._lock = Lock()
        self._cached = ""
        self._expires = 0

    def token(self):
        with self._lock:
            if monotonic() >= self._expires:
                with session() as client:
                    response = client.get(
                        METADATA_IDENTITY, params={"audience": API_ORIGIN},
                        headers={"Metadata-Flavor": "Google"},
                        timeout=(2, 5), allow_redirects=False,
                    )
                    token = response.text.strip()
                    if (response.status_code != 200 or response.headers.get("Metadata-Flavor") != "Google"
                            or len(token) > 8192 or not re.fullmatch(r"[\w-]+\.[\w-]+\.[\w-]+", token, re.ASCII)):
                        raise RuntimeError("Identidad del proxy no disponible")
                    self._cached = token
                    self._expires = monotonic() + 900
            return self._cached


identity = Identity()


def upstream(request, path, body):
    # Host, Authorization and forwarded headers supplied by the browser are
    # never propagated. Cloud Run checks this credentials header before ASGI.
    headers = {name: request.headers[name] for name in INBOUND if name in request.headers}
    if request.method in READ_METHODS and re.fullmatch(MEDIA_ROUTE, path) and "range" in request.headers:
        headers["range"] = request.headers["range"]
    headers.update({
        "X-Serverless-Authorization": "Bearer " + identity.token(),
        PROXY_ORIGIN_HEADER: PUBLIC_ORIGIN,
        "Accept-Encoding": "identity",
    })
    target = API_ORIGIN + path
    client = session()
    try:
        method = "GET" if request.method == "HEAD" else request.method
        response = client.request(method, target, params=list(request.query_params.multi_items()),
                                  data=body, headers=headers, stream=True, allow_redirects=False,
                                  timeout=(5, 60))
        return client, response
    except BaseException:
        client.close()
        raise


async def bounded_body(request, limit=REQUEST_SIZE):
    too_large = ("El logo supera el límite de 5 MiB." if limit == LOGO_REQUEST_SIZE
                 else "La solicitud supera el límite. Sube el video por la carga directa.")
    length = request.headers.get("content-length")
    if length is not None and (not length.isdecimal() or len(length) > 10 or int(length) > limit):
        raise HTTPException(413, too_large)
    collected = bytearray()
    async for chunk in request.stream():
        if len(collected) + len(chunk) > limit:
            raise HTTPException(413, too_large)
        collected.extend(chunk)
    if request.method in READ_METHODS and collected:
        raise HTTPException(400, "Este método no acepta un cuerpo de solicitud.")
    return bytes(collected)


class PublicHeaders:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        async def add_headers(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "no-referrer"
                headers["Content-Security-Policy"] = (
                    "default-src 'self'; connect-src 'self' https://storage.googleapis.com; "
                    "object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
                    "media-src 'self'; img-src 'self' data:"
                )
            await send(message)

        await self.app(scope, receive, add_headers)


app = FastAPI(title="ClipForge beta INT", docs_url=None, redoc_url=None, openapi_url=None,
              redirect_slashes=False)
app.add_middleware(PublicHeaders)


@app.get("/static/{name}")
def asset(request: Request, name: str):
    validate_request(request)
    if name not in ASSETS:
        raise HTTPException(404, "Recurso no disponible.")
    return FileResponse(STATIC / name)


@app.api_route("/{path:path}", methods=["GET", "HEAD", "POST", "PUT", "DELETE"])
async def forward(request: Request, path: str):
    validate_request(request)
    path = "/" + path
    if not allowed(request.method, path):
        raise HTTPException(404, "Recurso no disponible.")
    if request.method in READ_METHODS and re.fullmatch(MEDIA_ROUTE, path):
        ranges = request.headers.getlist("range")
        if ranges and (len(ranges) != 1 or not re.fullmatch(r"bytes=(?:[0-9]{1,19}-[0-9]{0,19}|-[1-9][0-9]{0,18})", ranges[0])):
            raise HTTPException(416, "Rango de reproducción no válido.")
    if len(request.scope.get("query_string", b"")) > 4096:
        raise HTTPException(414, "La consulta supera el límite.")
    logo_upload = request.method in {"POST", "PUT"} and re.fullmatch(LOGO_UPLOAD_ROUTE, path)
    if logo_upload and request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "image/png":
        raise HTTPException(415, "Elegí un PNG estático.")
    body = await bounded_body(request, LOGO_REQUEST_SIZE if logo_upload else REQUEST_SIZE)
    try:
        client, response = await run_in_threadpool(upstream, request, path, body)
    except (requests.RequestException, RuntimeError, ValueError):
        return JSONResponse({"detail": "ClipForge no está disponible temporalmente."}, status_code=502)

    def close():
        response.close()
        client.close()

    location = response.headers.get("Location")
    if (location and location not in REDIRECTS
            or response.headers.get("Content-Encoding", "identity").lower() != "identity"):
        close()
        return JSONResponse({"detail": "Respuesta de ClipForge no válida."}, status_code=502)
    headers = {name: value for name, value in response.headers.items() if name.lower() in OUTBOUND}
    if location:
        headers["Location"] = location

    def chunks():
        try:
            if request.method != "HEAD":
                yield from response.iter_content(128 * 1024)
        finally:
            close()

    outgoing = StreamingResponse(chunks(), response.status_code, headers=headers,
                                 background=BackgroundTask(close))
    for cookie in response.raw.headers.getlist("Set-Cookie"):
        outgoing.raw_headers.append((b"set-cookie", cookie.encode("latin-1")))
    return outgoing
