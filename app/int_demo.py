"""INT entry point for the account demo with PostgreSQL-only persistence."""
from contextlib import asynccontextmanager
import os
from pathlib import Path

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import FileResponse, HTMLResponse, Response
from sqlalchemy import text

from .auth import AuthenticationBoundary, require_access, router as auth_router, settings
from .auth_db import database_ready, get_engine
from .cloud.migrate import REVISION
from .environment import identity


ASSETS = Path(__file__).with_name("static")
ASSET_NAMES = frozenset({"account.css", "account.js", "auth.js", "recover.js"})
PROFILE = "int-demo-a"


@asynccontextmanager
async def lifespan(application: FastAPI):
    if (os.getenv("CLIPFORGE_RUNTIME_PROFILE") != PROFILE or identity()["environment"] != "INT"
            or not settings().secure or os.getenv("CLIPFORGE_DATABASE_SSL_MODE") != "verify-full"
            or not Path(os.getenv("CLIPFORGE_DATABASE_SSL_ROOT_CERT_FILE", "")).is_file()
            or os.getenv("CLIPFORGE_DATABASE_URL")
            or os.getenv("CLIPFORGE_STORAGE_BACKEND", "local") != "local"):
        raise RuntimeError("INT account demo requires its explicit profile, HTTPS and verified PostgreSQL TLS")
    yield


app = FastAPI(title="ClipForge INT", lifespan=lifespan,
              docs_url=None, redoc_url=None, openapi_url=None, redirect_slashes=False)
app.add_middleware(AuthenticationBoundary)
app.include_router(auth_router, dependencies=[Depends(require_access)])


def page(name):
    value = (ASSETS / name).read_text(encoding="utf-8").replace("ClipForge · Estudio local", "ClipForge · INT")
    if name == "account.html":
        value = value.replace('<a href="/">Volver al estudio</a>', "").replace(
            "Tu espacio es privado. Solo puedes abrir los proyectos que te pertenecen.",
            "Demo parcial. Puedes gestionar tu cuenta y tu sesión. La carga de vídeos, la edición y el procesamiento estarán disponibles en el siguiente hito.")
    if name == "login.html":
        value = value.replace("Inicia sesión para abrir tus proyectos y continuar editando.",
                              "Inicia sesión para probar tu cuenta en la demo de integración.")
    return HTMLResponse(value)


@app.get("/", dependencies=[Depends(require_access)])
@app.get("/account", dependencies=[Depends(require_access)])
def account_page():
    return page("account.html")


@app.get("/login")
def login_page():
    return page("login.html")


@app.get("/recover")
def recovery_page():
    return page("recover.html")


@app.get("/favicon.ico", include_in_schema=False, status_code=204)
def favicon():
    return Response(status_code=204)


@app.get("/static/{name}")
def static_asset(name: str):
    if name not in ASSET_NAMES:
        raise HTTPException(404, "Recurso no disponible.")
    return FileResponse(ASSETS / name, headers={"X-Content-Type-Options": "nosniff"})


@app.get("/environment")
def environment():
    return identity()


@app.get("/health")
def health():
    try:
        with get_engine().connect() as connection:
            revisions = connection.execute(text("SELECT revision FROM cloud_schema_migrations ORDER BY revision")).scalars().all()
        if revisions == [REVISION] and database_ready():
            return {"status": "ok", "profile": PROFILE}
    except Exception:
        pass
    raise HTTPException(503, "El almacenamiento persistente todavía no está disponible.")
