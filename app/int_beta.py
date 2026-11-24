"""Private INT beta API, reachable from the public ClipForge proxy by IAM."""

from contextlib import asynccontextmanager

from fastapi import APIRouter, Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, JSONResponse
from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError

from .auth import AuthenticationBoundary, require_access, router as auth_router, settings
from .auth_db import AuthConfigurationError, database_ready, get_engine
from .cloud.config import beta_enabled, settings as cloud_settings
from .cloud.feedback import router as feedback_router
from .cloud.migrate import REVISION
from .cloud.migrate_beta import beta_schema_ready
from .cloud.pilot import router as pilot_router
from .cloud.router import router as media_router
from .environment import identity
from .int_beta_proxy import PROXY_ORIGIN_HEADER, PUBLIC_HOST, PUBLIC_ORIGIN, STATIC


class TrustedPublicOrigin:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        # The Cloud Run invoker grant limits access to the frontend identity.
        # It supplies this exact header independently of the browser request.
        marker = PROXY_ORIGIN_HEADER.encode("ascii")
        supplied = [value for name, value in scope["headers"] if name == marker]
        if supplied != [PUBLIC_ORIGIN.encode("ascii")]:
            await JSONResponse({"detail": "Origen del proxy incorrecto."}, status_code=403)(
                scope, receive, send)
            return
        rewritten = dict(scope, scheme="https", server=(PUBLIC_HOST, 443))
        rewritten["headers"] = [(name, value) for name, value in scope["headers"]
                                if name not in {b"host", marker}]
        rewritten["headers"].append((b"host", PUBLIC_HOST.encode("ascii")))
        await self.app(rewritten, receive, send)


@asynccontextmanager
async def lifespan(application):
    auth = settings()
    cloud = cloud_settings()
    if (identity()["environment"] != "INT" or auth.origin != PUBLIC_ORIGIN
            or not auth.secure or cloud.local_test or not beta_enabled()):
        raise RuntimeError("La API beta requiere el perfil HTTPS de INT.")
    yield


app = FastAPI(title="ClipForge INT beta API", lifespan=lifespan, docs_url=None, redoc_url=None,
              openapi_url=None, redirect_slashes=False)
app.add_middleware(AuthenticationBoundary)
app.add_middleware(TrustedPublicOrigin)
app.include_router(auth_router, dependencies=[Depends(require_access)])
media_reads = APIRouter(routes=[
    route for route in media_router.routes
    if route.methods == {"GET"}
    and route.path in {"/projects", "/jobs/{job_id}", "/jobs/{job_id}/clips/{filename}"}
])
app.include_router(media_reads, dependencies=[Depends(require_access)])
app.include_router(pilot_router, dependencies=[Depends(require_access)])
app.include_router(feedback_router, dependencies=[Depends(require_access)])


@app.get("/", dependencies=[Depends(require_access)])
def home():
    return FileResponse(STATIC / "beta.html")


@app.get("/login")
def login():
    return FileResponse(STATIC / "login.html")


@app.get("/recover")
def recover():
    return FileResponse(STATIC / "recover.html")


@app.get("/account", dependencies=[Depends(require_access)])
def account():
    return FileResponse(STATIC / "account.html")


@app.get("/environment")
def environment():
    return identity()


@app.get("/health")
def health():
    try:
        with get_engine().connect() as connection:
            revisions = connection.execute(text(
                "SELECT revision FROM cloud_schema_migrations ORDER BY revision"
            )).scalars().all()
            if revisions == [REVISION] and beta_schema_ready(connection) and database_ready():
                return {"status": "ok", "profile": "int-beta"}
    except (SQLAlchemyError, AuthConfigurationError):
        raise HTTPException(503, "El almacenamiento persistente todavía no está disponible.") from None
    raise HTTPException(503, "El almacenamiento persistente todavía no está disponible.")
