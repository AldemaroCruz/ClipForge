"""Local AUTH-01: Argon2id, revocable PostgreSQL sessions and private resources.

There is no anonymous development bypass. Local HTTP requires an explicit
loopback profile and exact origin. Tokens/passwords never enter logs or reports.
"""
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from functools import lru_cache
import hashlib
import json
import os
import re
import secrets
import uuid
from urllib.parse import urlsplit

from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError
from fastapi import APIRouter, HTTPException, Query, Request, Response
from pydantic import BaseModel, ConfigDict, Field, SecretStr, ValidationError
from sqlalchemy import delete, func, select, text, update
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import MutableHeaders
from starlette.responses import JSONResponse

from .auth_db import AuthConfigurationError, AuthDatabaseError, database_ready, session_scope
from .auth_models import (AuditEvent, AuthChallenge, AuthSession, LoginAttempt, Membership,
                          Project, RecoveryCode, SecurityAttempt, User, Workspace)


router = APIRouter(prefix="/auth", tags=["account"])
PASSWORDS = PasswordHasher(type=Type.ID, memory_cost=65536, time_cost=3, parallelism=4)
SESSION_COOKIE = "clipforge_session"
CSRF_COOKIE = "clipforge_csrf"
PREAUTH_COOKIE = "clipforge_preauth"
PRECSRF_COOKIE = "clipforge_precsrf"
TOKEN_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}")
USER_PATTERN = re.compile(r"[a-z0-9][a-z0-9_.-]{2,63}")
ID_PATTERN = re.compile(r"[0-9a-f]{32}")
LOGIN_WINDOW = timedelta(minutes=15)
LOGIN_ACCOUNT_LIMIT = 5
LOGIN_CLIENT_LIMIT = 30
CHALLENGE_LIFETIME = timedelta(minutes=10)
RECOVERY_LIFETIME = timedelta(minutes=15)
SECURITY_WINDOW = timedelta(minutes=15)
SECURITY_ACCOUNT_LIMIT = 5
SECURITY_CLIENT_LIMIT = 30
AUDIT_ACTIONS = frozenset({"user.created", "user.deactivated", "recovery.issued",
                           "recovery.consumed", "password.changed"})
SHELL_PATHS = frozenset({"/", "/ops", "/account", "/admin/users"})
PUBLIC_PATHS = frozenset({"/health", "/login", "/recover", "/favicon.ico", "/auth/csrf"})


@dataclass(frozen=True)
class Principal:
    id: str
    username: str
    is_admin: bool
    is_active: bool
    workspace_id: str

    @property
    def permissions(self):
        return ["users:manage"] if self.is_admin else []

    def public(self):
        return {"id": self.id, "username": self.username, "is_admin": self.is_admin,
                "is_active": self.is_active, "workspace_id": self.workspace_id,
                "permissions": self.permissions}


@dataclass(frozen=True)
class Settings:
    origin: str
    secure: bool
    ttl_seconds: int


def settings() -> Settings:
    origin = os.getenv("CLIPFORGE_AUTH_ORIGIN", "")
    profile = os.getenv("CLIPFORGE_AUTH_PROFILE", "https")
    try:
        parsed = urlsplit(origin)
        if (not parsed.hostname or parsed.username or parsed.password or parsed.path
                or parsed.query or parsed.fragment or origin != origin.strip()):
            raise ValueError("Invalid origin")
        if profile == "local-http":
            if parsed.scheme != "http" or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}:
                raise ValueError("Local HTTP requires loopback")
        elif profile == "https":
            if parsed.scheme != "https":
                raise ValueError("HTTPS required")
        else:
            raise ValueError("Unknown auth profile")
        if parsed.port is not None and not 1 <= parsed.port <= 65535:
            raise ValueError("Invalid port")
        ttl = int(os.getenv("CLIPFORGE_SESSION_TTL_SECONDS", "43200"))
        if not 60 <= ttl <= 86400:
            raise ValueError("Invalid session lifetime")
        return Settings(origin=origin, secure=profile == "https", ttl_seconds=ttl)
    except (ValueError, TypeError):
        raise HTTPException(503, "La configuración de autenticación no está disponible.") from None


def now_utc():
    return datetime.now(timezone.utc)


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _token(value):
    return value if isinstance(value, str) and TOKEN_PATTERN.fullmatch(value) else None


def _client_hash(request):
    # Forwarded headers are not an identity source. Only the ASGI client address.
    address = request.client.host if request.client else "unknown-client"
    return token_hash("client:" + address)


def _context(request: Request, config: Settings, *, mutation=False):
    expected = urlsplit(config.origin)
    actual = request.url
    expected_port = expected.port or (443 if expected.scheme == "https" else 80)
    try:
        actual_port = actual.port or (443 if actual.scheme == "https" else 80)
    except ValueError:
        raise HTTPException(400, "Origen de la solicitud no permitido.") from None
    if (actual.scheme != expected.scheme or actual.hostname != expected.hostname
            or actual_port != expected_port):
        raise HTTPException(400, "Origen de la solicitud no permitido.")
    origin = request.headers.get("origin")
    if (mutation and origin != config.origin) or (origin is not None and origin != config.origin):
        raise HTTPException(403, "La verificación de origen falló.")
    if request.headers.get("sec-fetch-site") == "cross-site":
        raise HTTPException(403, "La verificación de origen falló.")


@contextmanager
def _http_storage():
    try:
        with session_scope() as database:
            yield database
    except (AuthConfigurationError, AuthDatabaseError):
        raise HTTPException(503, "El almacenamiento de autenticación no está disponible.") from None


def _principal(database, user):
    workspace = database.execute(select(Workspace).join(
        Membership, Membership.workspace_id == Workspace.id).where(
        Workspace.owner_id == user.id, Membership.user_id == user.id,
        Membership.role == "owner")).scalar_one_or_none()
    if workspace is None:
        raise AuthDatabaseError("Private workspace membership is incomplete")
    return Principal(user.id, user.username, user.is_admin, user.is_active, workspace.id)


def _session(database, raw_token, *, lock_user=False):
    token = _token(raw_token)
    if token is None:
        return None
    query = select(AuthSession, User).join(User, User.id == AuthSession.user_id).where(
        AuthSession.token_hash == token_hash(token), AuthSession.revoked_at.is_(None),
        AuthSession.expires_at > now_utc(), User.is_active.is_(True))
    if lock_user:
        query = query.with_for_update(of=User)
    row = database.execute(query.execution_options(populate_existing=True)).first()
    if row is None or row[0].expires_at <= now_utc() or not row[1].is_active:
        return None
    return row[0], row[1], _principal(database, row[1])


def _cookie(response, name, value, config, age):
    response.set_cookie(name, value, max_age=age, path="/", secure=config.secure,
                        httponly=True, samesite="strict")


def _clear_cookies(response, config):
    for name in (SESSION_COOKIE, CSRF_COOKIE, PREAUTH_COOKIE, PRECSRF_COOKIE):
        response.delete_cookie(name, path="/", secure=config.secure,
                               httponly=True, samesite="strict")


def _csrf_matches(request, expected_hash):
    supplied = _token(request.headers.get("x-csrf-token"))
    return supplied is not None and secrets.compare_digest(token_hash(supplied), expected_hash)


def require_access(request: Request):
    """Global route dependency; checks route job_id before any filesystem access."""
    path = request.url.path
    if request.method in {"GET", "HEAD"} and path in PUBLIC_PATHS:
        return
    if request.method == "POST" and path in {"/auth/login", "/auth/recover"}:
        return  # Each anonymous mutation verifies its challenge and origin itself.
    config = settings()
    mutation = request.method not in {"GET", "HEAD", "OPTIONS"}
    _context(request, config, mutation=mutation)
    with _http_storage() as database:
        result = _session(database, request.cookies.get(SESSION_COOKIE))
        if result is None:
            if request.method in {"GET", "HEAD"} and path in SHELL_PATHS:
                raise HTTPException(303, headers={"Location": "/login", "Cache-Control": "no-store"})
            raise HTTPException(401, "Inicia sesión para continuar.", headers={"Cache-Control": "no-store"})
        session, _, principal = result
        if mutation and not _csrf_matches(request, session.csrf_hash):
            raise HTTPException(403, "La verificación CSRF falló.")
        if path.startswith("/auth/admin/") and not principal.is_admin:
            raise HTTPException(403, "Se requiere el permiso users:manage.")
        job_id = request.path_params.get("job_id")
        if job_id is not None:
            if not ID_PATTERN.fullmatch(job_id):
                raise HTTPException(404, "Job no encontrado")
            owned = database.execute(select(Project.id).where(
                Project.id == job_id, Project.owner_id == principal.id,
                Project.workspace_id == principal.workspace_id)).scalar_one_or_none()
            if owned is None:
                raise HTTPException(404, "Job no encontrado")
        request.state.principal = principal


class AuthenticationBoundary:
    """Authenticate before multipart parsing; keep streaming/FileResponse intact.

    The global FastAPI dependency remains necessary: route path_params become
    available only after routing, when resource ownership can be checked.
    """
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path = scope.get("path", "")
        if path.startswith("/static/"):
            await self.app(scope, receive, send)
            return

        async def send_private(message):
            if message["type"] == "http.response.start":
                headers = MutableHeaders(scope=message)
                headers["Cache-Control"] = "no-store"
                varies = [part.strip() for part in headers.get("vary", "").split(",") if part.strip()]
                if not any(part.lower() == "cookie" for part in varies):
                    varies.append("Cookie")
                headers["Vary"] = ", ".join(varies)
                headers["X-Content-Type-Options"] = "nosniff"
                headers["Referrer-Policy"] = "same-origin"
            await send(message)

        request = Request(scope)
        try:
            await run_in_threadpool(require_access, request)
        except HTTPException as error:
            action, target_id = _mutation_audit_scope(request)
            if action and error.status_code != 503:
                try:
                    await run_in_threadpool(_audit_failed_action, request, action, target_id)
                except HTTPException as audit_error:
                    error = audit_error  # Failure to record a rejection is fail-closed.
            response = JSONResponse({"detail": error.detail}, status_code=error.status_code,
                                    headers=error.headers)
            await response(scope, receive, send_private)
            return
        await self.app(scope, receive, send_private)


def _normalize_username(username):
    if not isinstance(username, str):
        raise ValueError("El nombre de usuario no es válido.")
    value = username.strip().lower()
    if not USER_PATTERN.fullmatch(value):
        raise ValueError("Usa 3–64 letras sin acentos, números, puntos, guiones o guiones bajos.")
    return value


def _validate_password(password):
    if not isinstance(password, str) or not 12 <= len(password) <= 128 or not password.strip():
        raise ValueError("La contraseña debe tener entre 12 y 128 caracteres.")
    return password


def _new_user(database, username, password, *, is_admin, actor_id=None, correlation_id=None):
    username = _normalize_username(username)
    _validate_password(password)
    _lock_scope(database, "new-user:" + username)
    if database.execute(select(User.id).where(User.username == username)).first():
        raise ValueError("El nombre de usuario ya está ocupado.")
    user = User(id=uuid.uuid4().hex, username=username, password_hash=PASSWORDS.hash(password),
                is_admin=is_admin, is_active=True, created_at=now_utc())
    database.add(user)
    database.flush()
    workspace = Workspace(id=uuid.uuid4().hex, owner_id=user.id, created_at=now_utc())
    database.add(workspace)
    database.flush()
    database.add(Membership(workspace_id=workspace.id, user_id=user.id, role="owner"))
    database.flush()
    _audit_event(database, actor_id=actor_id, target_id=user.id, action="user.created",
                 result="success", correlation_id=correlation_id or str(uuid.uuid4()))
    return _principal(database, user)


def bootstrap_admin(username, password):
    """Explicit local-only provisioning, serialized and allowed only on no users."""
    with session_scope() as database:
        database.execute(text("SELECT pg_advisory_xact_lock(1837086402)"))
        if database.execute(select(User.id).limit(1)).first():
            raise ValueError("La creación inicial ya no está disponible: existen usuarios.")
        return _new_user(database, username, password, is_admin=True)


def create_user(username, password, *, is_admin=False):
    """Trusted local provisioning for isolated fixtures; never a public route."""
    with session_scope() as database:
        return _new_user(database, username, password, is_admin=is_admin)


def principal_for_user(user_id):
    with session_scope() as database:
        user = database.get(User, user_id)
        if user is None or not user.is_active:
            raise ValueError("Usuario activo no encontrado.")
        return _principal(database, user)


def register_project(job_id, principal):
    if not ID_PATTERN.fullmatch(job_id):
        raise ValueError("Invalid project identifier")
    with _http_storage() as database:
        user = database.get(User, principal.id)
        if user is None or not user.is_active:
            raise HTTPException(401, "Inicia sesión para continuar.")
        actual = _principal(database, user)
        if actual.workspace_id != principal.workspace_id:
            raise HTTPException(404, "Recurso no encontrado.")
        if database.get(Project, job_id) is not None:
            raise HTTPException(409, "El recurso ya tiene propietario.")
        database.add(Project(id=job_id, workspace_id=actual.workspace_id,
                             owner_id=actual.id, created_at=now_utc()))


def unregister_project(job_id, principal):
    with _http_storage() as database:
        database.execute(delete(Project).where(Project.id == job_id,
            Project.owner_id == principal.id, Project.workspace_id == principal.workspace_id))


def visible_project_ids(principal):
    with _http_storage() as database:
        user = database.get(User, principal.id)
        if user is None or not user.is_active or _principal(database, user).workspace_id != principal.workspace_id:
            raise HTTPException(401, "Inicia sesión para continuar.")
        return frozenset(database.execute(select(Project.id).where(
            Project.owner_id == principal.id, Project.workspace_id == principal.workspace_id)).scalars())


class LoginBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=1, max_length=64, strict=True)
    password: SecretStr = Field(min_length=1, max_length=128)


class CreateUserBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    username: str = Field(min_length=3, max_length=64, strict=True)
    password: SecretStr = Field(min_length=12, max_length=128)


class PasswordBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)


class RecoveryIssueBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    current_password: SecretStr = Field(min_length=1, max_length=128)


class RecoveryBody(BaseModel):
    model_config = ConfigDict(extra="forbid")
    code: SecretStr = Field(min_length=1, max_length=128)
    new_password: SecretStr = Field(min_length=12, max_length=128)


async def _body(request, model):
    if request.headers.get("content-type", "").split(";", 1)[0].strip().lower() != "application/json":
        raise HTTPException(415, "Envía un objeto JSON.")
    chunks = bytearray()
    async for chunk in request.stream():
        if len(chunks) + len(chunk) > 16384:
            raise HTTPException(413, "Solicitud demasiado grande.")
        chunks.extend(chunk)
    try:
        return model.model_validate(json.loads(chunks))
    except (ValueError, TypeError, ValidationError):
        # Pydantic's default HTTP validation output can echo a password input.
        raise HTTPException(422, "Datos de cuenta inválidos o campos no permitidos.") from None


@lru_cache(maxsize=1)
def _dummy_hash():
    return PASSWORDS.hash(secrets.token_urlsafe(32))


def _verify(password, encoded):
    try:
        return PASSWORDS.verify(encoded, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _lock_scope(database, label):
    key = int.from_bytes(hashlib.sha256(label.encode()).digest()[:8], "big", signed=True)
    database.execute(text("SELECT pg_advisory_xact_lock(:key)"), {"key": key})


def _correlation_id(request):
    value = getattr(request.state, "auth_correlation_id", None)
    if value is None:
        value = str(uuid.uuid4())
        request.state.auth_correlation_id = value
    return value


def _audit_event(database, *, actor_id, target_id, action, result, correlation_id, timestamp=None):
    # Explicit fixed fields only: never credentials, tokens, hashes, client input,
    # exception messages, project identifiers or media paths.
    database.add(AuditEvent(id=uuid.uuid4().hex, actor_id=actor_id, target_id=target_id,
                           action=action, created_at=timestamp or now_utc(), result=result,
                           correlation_id=correlation_id))
    database.flush()  # An audit insertion failure rolls the entire action back.


def _mutation_audit_scope(request):
    if request.method != "POST":
        return None, None
    path = request.url.path
    if path == "/auth/password":
        return "password.changed", None
    if path == "/auth/users":
        return "user.created", None
    if path == "/auth/recover":
        return "recovery.consumed", None
    match = re.fullmatch(r"/auth/users/([0-9a-f]{32})/deactivate", path)
    if match:
        return "user.deactivated", match[1]
    match = re.fullmatch(r"/auth/admin/users/([0-9a-f]{32})/recovery", path)
    return ("recovery.issued", match[1]) if match else (None, None)


def _audit_failed_action(request, action, target_id=None):
    if getattr(request.state, "auth_audit_recorded", False):
        return
    with _http_storage() as database:
        authenticated = _session(database, request.cookies.get(SESSION_COOKIE))
        actor_id = authenticated[1].id if authenticated else None
        if action == "password.changed":
            target_id = actor_id
        _audit_event(database, actor_id=actor_id, target_id=target_id, action=action,
                     result="failure", correlation_id=_correlation_id(request))
    request.state.auth_audit_recorded = True


async def _account_request(request, response, model, operation, action, target_id=None, **operation_kwargs):
    try:
        body = await _body(request, model)
        return await run_in_threadpool(operation, request, response, body, **operation_kwargs)
    except HTTPException as error:
        if error.status_code != 503:
            await run_in_threadpool(_audit_failed_action, request, action, target_id)
        raise


def _security_attempt(database, request, purpose, identity_hash):
    client_hash = _client_hash(request)
    # Same order for every attempt; PostgreSQL serializes competing identities
    # and clients so concurrent requests cannot step over persistent quotas.
    _lock_scope(database, "security-identity:" + purpose + ":" + identity_hash)
    _lock_scope(database, "security-client:" + purpose + ":" + client_hash)
    timestamp = now_utc()
    cutoff = timestamp - SECURITY_WINDOW
    count_identity = database.scalar(select(func.count()).select_from(SecurityAttempt).where(
        SecurityAttempt.purpose == purpose, SecurityAttempt.identity_hash == identity_hash,
        SecurityAttempt.attempted_at > cutoff))
    count_client = database.scalar(select(func.count()).select_from(SecurityAttempt).where(
        SecurityAttempt.purpose == purpose, SecurityAttempt.client_hash == client_hash,
        SecurityAttempt.attempted_at > cutoff))
    if count_identity >= SECURITY_ACCOUNT_LIMIT or count_client >= SECURITY_CLIENT_LIMIT:
        return HTTPException(429, "Demasiados intentos. Reintenta más tarde.", headers={"Retry-After": "900"})
    database.add(SecurityAttempt(purpose=purpose, identity_hash=identity_hash,
                                client_hash=client_hash, attempted_at=timestamp))
    return None


def _revoke_recovery(database, user_id, timestamp):
    database.execute(update(RecoveryCode).where(RecoveryCode.user_id == user_id,
        RecoveryCode.consumed_at.is_(None), RecoveryCode.revoked_at.is_(None)).values(revoked_at=timestamp))


def _lock_users(database, *user_ids):
    # Always users (ordered by ID) before recovery rows. Issue/deactivate can
    # involve two users; consume/password involve one. Never lock a code first.
    database.execute(select(User).where(User.id.in_(set(user_ids))).order_by(User.id).with_for_update()
                     .execution_options(populate_existing=True)).scalars().all()


def _locked_administrator(database, request, target_id):
    actor = _administrator(database, request, lock_user=False)
    _lock_users(database, actor.id, target_id)
    # Recheck after waiting: a password change/deactivation may have revoked the
    # actor's session while this request was blocked on a user row.
    return _administrator(database, request, lock_user=False)


def _utc_string(value):
    return value.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


@router.get("/csrf")
def csrf(request: Request, response: Response):
    config = settings()
    _context(request, config)
    response.headers["Cache-Control"] = "no-store"
    with _http_storage() as database:
        result = _session(database, request.cookies.get(SESSION_COOKIE))
        if result:
            session, _, _ = result
            supplied = _token(request.cookies.get(CSRF_COOKIE))
            if not supplied or not secrets.compare_digest(token_hash(supplied), session.csrf_hash):
                supplied = secrets.token_urlsafe(32)
                session.csrf_hash = token_hash(supplied)
                _cookie(response, CSRF_COOKIE, supplied, config, config.ttl_seconds)
            return {"csrf_token": supplied}
        timestamp = now_utc()
        database.execute(delete(AuthChallenge).where(AuthChallenge.expires_at <= timestamp))
        challenge_token = _token(request.cookies.get(PREAUTH_COOKIE))
        supplied = _token(request.cookies.get(PRECSRF_COOKIE))
        challenge = database.get(AuthChallenge, token_hash(challenge_token)) if challenge_token else None
        if challenge and supplied and secrets.compare_digest(token_hash(supplied), challenge.csrf_hash):
            return {"csrf_token": supplied}
        client_hash = _client_hash(request)
        _lock_scope(database, "challenge:" + client_hash)
        count = database.scalar(select(func.count()).select_from(AuthChallenge).where(
            AuthChallenge.client_hash == client_hash, AuthChallenge.created_at > timestamp - timedelta(minutes=1)))
        if count >= 60:
            raise HTTPException(429, "Demasiadas solicitudes. Reintenta más tarde.", headers={"Retry-After": "60"})
        challenge_token, supplied = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        database.add(AuthChallenge(token_hash=token_hash(challenge_token), csrf_hash=token_hash(supplied),
                     client_hash=client_hash, created_at=timestamp, expires_at=timestamp + CHALLENGE_LIFETIME))
        _clear_cookies(response, config)
        _cookie(response, PREAUTH_COOKIE, challenge_token, config, 600)
        _cookie(response, PRECSRF_COOKIE, supplied, config, 600)
        return {"csrf_token": supplied}


def _login(request, response, body):
    config = settings()
    _context(request, config, mutation=True)
    raw_challenge = _token(request.cookies.get(PREAUTH_COOKIE))
    supplied_session = _token(request.cookies.get(SESSION_COOKIE))
    username = body.username.strip().lower()
    identity_hash = token_hash("identity:" + username)
    client_hash = _client_hash(request)
    failure = None
    with _http_storage() as database:
        existing_session = _session(database, supplied_session)
        challenge = database.execute(select(AuthChallenge).where(
            AuthChallenge.token_hash == token_hash(raw_challenge)).with_for_update()).scalar_one_or_none() if raw_challenge else None
        challenge_valid = (challenge is not None and challenge.expires_at > now_utc()
                           and challenge.client_hash == client_hash and _csrf_matches(request, challenge.csrf_hash))
        session_valid = existing_session is not None and _csrf_matches(request, existing_session[0].csrf_hash)
        if not (challenge_valid or session_valid):
            raise HTTPException(403, "La verificación CSRF falló.")
        _lock_scope(database, "login-identity:" + identity_hash)
        _lock_scope(database, "login-client:" + client_hash)
        timestamp = now_utc()
        cutoff = timestamp - LOGIN_WINDOW
        database.execute(delete(LoginAttempt).where(LoginAttempt.attempted_at <= cutoff))
        account_count = database.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.identity_hash == identity_hash))
        client_count = database.scalar(select(func.count()).select_from(LoginAttempt).where(LoginAttempt.client_hash == client_hash))
        if account_count >= LOGIN_ACCOUNT_LIMIT or client_count >= LOGIN_CLIENT_LIMIT:
            raise HTTPException(429, "Demasiados intentos. Reintenta más tarde.", headers={"Retry-After": "900"})
        dummy = _dummy_hash()  # First-use hashing cost is independent of account existence.
        user = database.execute(select(User).where(User.username == username).with_for_update()).scalar_one_or_none()
        valid = _verify(body.password.get_secret_value(), user.password_hash if user else dummy)
        if not valid or user is None or not user.is_active:
            database.add(LoginAttempt(identity_hash=identity_hash, client_hash=client_hash, attempted_at=timestamp))
            failure = HTTPException(401, "Usuario o contraseña incorrectos.", headers={"Cache-Control": "no-store"})
        else:
            if PASSWORDS.check_needs_rehash(user.password_hash):
                user.password_hash = PASSWORDS.hash(body.password.get_secret_value())
            principal = _principal(database, user)
            if supplied_session:
                database.execute(update(AuthSession).where(AuthSession.token_hash == token_hash(supplied_session),
                    AuthSession.revoked_at.is_(None)).values(revoked_at=timestamp))
            if challenge is not None:
                database.delete(challenge)
            raw_session, raw_csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            database.add(AuthSession(token_hash=token_hash(raw_session), user_id=user.id, csrf_hash=token_hash(raw_csrf),
                         created_at=timestamp, expires_at=timestamp + timedelta(seconds=config.ttl_seconds)))
            result = {"user": principal.public(), "csrf_token": raw_csrf}
    if failure is not None:
        raise failure  # Failed-attempt evidence must commit before returning 401.
    _clear_cookies(response, config)
    _cookie(response, SESSION_COOKIE, raw_session, config, config.ttl_seconds)
    _cookie(response, CSRF_COOKIE, raw_csrf, config, config.ttl_seconds)
    response.headers["Cache-Control"] = "no-store"
    return result


@router.post("/login")
async def login(request: Request, response: Response):
    body = await _body(request, LoginBody)
    return await run_in_threadpool(_login, request, response, body)


@router.get("/me")
def me(request: Request, response: Response):
    config = settings()
    with _http_storage() as database:
        result = _session(database, request.cookies.get(SESSION_COOKIE))
        if result is None:
            raise HTTPException(401, "Inicia sesión para continuar.")
        session, _, principal = result
        raw_csrf = _token(request.cookies.get(CSRF_COOKIE))
        if not raw_csrf or not secrets.compare_digest(token_hash(raw_csrf), session.csrf_hash):
            raw_csrf = secrets.token_urlsafe(32)
            session.csrf_hash = token_hash(raw_csrf)
            _cookie(response, CSRF_COOKIE, raw_csrf, config, config.ttl_seconds)
        response.headers["Cache-Control"] = "no-store"
        return {"user": principal.public(), "csrf_token": raw_csrf}


@router.post("/logout")
def logout(request: Request, response: Response):
    config = settings()
    token = _token(request.cookies.get(SESSION_COOKIE))
    with _http_storage() as database:
        if token:
            database.execute(update(AuthSession).where(AuthSession.token_hash == token_hash(token),
                AuthSession.revoked_at.is_(None)).values(revoked_at=now_utc()))
    _clear_cookies(response, config)
    response.headers["Cache-Control"] = "no-store"
    return {"status": "logged_out"}


def _change_password(request, response, body):
    config = settings()
    failure = None
    with _http_storage() as database:
        result = _session(database, request.cookies.get(SESSION_COOKIE), lock_user=True)
        if result is None:
            raise HTTPException(401, "Inicia sesión para continuar.")
        _, user, _ = result
        failure = _security_attempt(database, request, "password_change", token_hash("user:" + user.id))
        if failure is None and not _verify(body.current_password.get_secret_value(), user.password_hash):
            failure = HTTPException(400, "La contraseña actual no coincide.")
        try:
            password = _validate_password(body.new_password.get_secret_value())
        except ValueError:
            if failure is None:
                failure = HTTPException(422, "La contraseña nueva debe tener entre 12 y 128 caracteres.")
        timestamp = now_utc()
        if failure is None:
            user.password_hash = PASSWORDS.hash(password)
            database.execute(update(AuthSession).where(AuthSession.user_id == user.id,
                AuthSession.revoked_at.is_(None)).values(revoked_at=timestamp))
            _revoke_recovery(database, user.id, timestamp)
        _audit_event(database, actor_id=user.id, target_id=user.id, action="password.changed",
                     result="failure" if failure else "success", correlation_id=_correlation_id(request), timestamp=timestamp)
    request.state.auth_audit_recorded = True
    if failure is not None:
        raise failure
    _clear_cookies(response, config)
    response.headers["Cache-Control"] = "no-store"
    return {"status": "password_changed", "login_required": True}


@router.post("/password")
async def change_password(request: Request, response: Response):
    return await _account_request(request, response, PasswordBody, _change_password, "password.changed")


def _administrator(database, request, *, lock_user=True):
    result = _session(database, request.cookies.get(SESSION_COOKIE), lock_user=lock_user)
    if result is None:
        raise HTTPException(401, "Inicia sesión para continuar.")
    if not result[2].is_admin:
        raise HTTPException(403, "Se requiere el permiso users:manage.")
    return result[2]


@router.get("/users")
def users(request: Request, response: Response):
    with _http_storage() as database:
        _administrator(database, request)
        items = database.execute(select(User).order_by(User.username)).scalars().all()
        result = [{"id": user.id, "username": user.username, "is_admin": user.is_admin,
                   "is_active": user.is_active, "permissions": ["users:manage"] if user.is_admin else []}
                  for user in items]
    response.headers["Cache-Control"] = "no-store"
    return {"users": result}


def _create_user(request, response, body):
    failure = None
    with _http_storage() as database:
        actor = _administrator(database, request)
        try:
            principal = _new_user(database, body.username, body.password.get_secret_value(), is_admin=False,
                                  actor_id=actor.id, correlation_id=_correlation_id(request))
        except ValueError as error:
            failure = HTTPException(409 if "ocupado" in str(error) else 422, str(error))
            _audit_event(database, actor_id=actor.id, target_id=None, action="user.created",
                         result="failure", correlation_id=_correlation_id(request))
    request.state.auth_audit_recorded = True
    if failure is not None:
        raise failure
    response.headers["Cache-Control"] = "no-store"
    return {"user": principal.public()}


@router.post("/users", status_code=201)
async def add_user(request: Request, response: Response):
    return await _account_request(request, response, CreateUserBody, _create_user, "user.created")


def _deactivate_user(user_id, request, response):
    if not ID_PATTERN.fullmatch(user_id):
        raise HTTPException(404, "Usuario no encontrado.")
    with _http_storage() as database:
        actor = _locked_administrator(database, request, user_id)
        if user_id == actor.id:
            raise HTTPException(409, "No puedes desactivar tu propia cuenta administrativa.")
        user = database.get(User, user_id)
        if user is None:
            raise HTTPException(404, "Usuario no encontrado.")
        user.is_active = False
        timestamp = now_utc()
        database.execute(update(AuthSession).where(AuthSession.user_id == user.id,
            AuthSession.revoked_at.is_(None)).values(revoked_at=timestamp))
        _revoke_recovery(database, user.id, timestamp)
        _audit_event(database, actor_id=actor.id, target_id=user.id, action="user.deactivated",
                     result="success", correlation_id=_correlation_id(request), timestamp=timestamp)
    request.state.auth_audit_recorded = True
    response.headers["Cache-Control"] = "no-store"
    return {"status": "deactivated", "id": user_id}


@router.post("/users/{user_id}/deactivate")
def deactivate_user(user_id: str, request: Request, response: Response):
    try:
        return _deactivate_user(user_id, request, response)
    except HTTPException as error:
        if error.status_code != 503:
            _audit_failed_action(request, "user.deactivated", user_id if ID_PATTERN.fullmatch(user_id) else None)
        raise


def _issue_recovery(request, response, body, *, user_id):
    if not ID_PATTERN.fullmatch(user_id):
        raise HTTPException(404, "Usuario no encontrado.")
    failure = None
    with _http_storage() as database:
        actor = _locked_administrator(database, request, user_id)
        failure = _security_attempt(database, request, "recovery_issue", token_hash("user:" + actor.id))
        if failure is None and not _verify(body.current_password.get_secret_value(), database.get(User, actor.id).password_hash):
            failure = HTTPException(400, "La contraseña actual no coincide.")
        user = database.get(User, user_id)
        if failure is None:
            if user is None:
                failure = HTTPException(404, "Usuario no encontrado.")
            elif user.is_admin or not user.is_active:
                failure = HTTPException(409, "Solo se recuperan cuentas normales activas.")
        timestamp = now_utc()
        if failure is None:
            raw_code = secrets.token_urlsafe(32)
            expires_at = timestamp + RECOVERY_LIFETIME
            _revoke_recovery(database, user.id, timestamp)
            database.add(RecoveryCode(token_hash=token_hash(raw_code), user_id=user.id,
                                     issued_by_id=actor.id, created_at=timestamp, expires_at=expires_at))
        _audit_event(database, actor_id=actor.id, target_id=user_id, action="recovery.issued",
                     result="failure" if failure else "success", correlation_id=_correlation_id(request), timestamp=timestamp)
    request.state.auth_audit_recorded = True
    if failure is not None:
        raise failure
    response.headers["Cache-Control"] = "no-store"
    return {"recovery_code": raw_code, "expires_at": _utc_string(expires_at)}


@router.post("/admin/users/{user_id}/recovery", status_code=201)
async def issue_recovery(user_id: str, request: Request, response: Response):
    return await _account_request(request, response, RecoveryIssueBody, _issue_recovery,
                                  "recovery.issued", user_id if ID_PATTERN.fullmatch(user_id) else None, user_id=user_id)


def _recover(request, response, body):
    config = settings()
    _context(request, config, mutation=True)
    try:
        password = _validate_password(body.new_password.get_secret_value())
    except ValueError:
        raise HTTPException(422, "La contraseña nueva debe tener entre 12 y 128 caracteres.") from None
    code = _token(body.code.get_secret_value())
    raw_challenge = _token(request.cookies.get(PREAUTH_COOKIE))
    raw_session = _token(request.cookies.get(SESSION_COOKIE))
    client_hash = _client_hash(request)
    failure = None
    target_id = None
    with _http_storage() as database:
        existing_session = _session(database, raw_session)
        actor_id = existing_session[1].id if existing_session else None
        challenge = database.execute(select(AuthChallenge).where(AuthChallenge.token_hash == token_hash(raw_challenge))
            .with_for_update()).scalar_one_or_none() if raw_challenge else None
        challenge_valid = (challenge is not None and challenge.expires_at > now_utc()
                           and challenge.client_hash == client_hash and _csrf_matches(request, challenge.csrf_hash))
        session_valid = existing_session is not None and _csrf_matches(request, existing_session[0].csrf_hash)
        if not (challenge_valid or session_valid):
            failure = HTTPException(403, "La verificación CSRF falló.")
        if failure is None:
            failure = _security_attempt(database, request, "recovery_consume",
                                        token_hash("recovery:" + token_hash(code or "invalid-format")))
        if failure is None:
            # Read only the ID first: never hold a code row while waiting for a
            # user. All mutations acquire user(s) before changing recovery rows.
            target_id = database.scalar(select(RecoveryCode.user_id).where(RecoveryCode.token_hash == token_hash(code))) if code else None
            user = None
            recovery = None
            if target_id is not None:
                # A session may belong to somebody other than the recovering
                # user. Lock both by ID before any code row, never impersonate.
                _lock_users(database, *({target_id, actor_id} if actor_id else {target_id}))
                user = database.get(User, target_id)
                recovery = database.execute(select(RecoveryCode).where(RecoveryCode.token_hash == token_hash(code))
                    .with_for_update()).scalar_one_or_none()
            timestamp = now_utc()  # Expiry is checked after waiting for all locks.
            existing_session = _session(database, raw_session)
            challenge_valid = (challenge is not None and challenge.expires_at > timestamp
                               and challenge.client_hash == client_hash and _csrf_matches(request, challenge.csrf_hash))
            session_valid = existing_session is not None and _csrf_matches(request, existing_session[0].csrf_hash)
            if not (challenge_valid or session_valid):
                failure = HTTPException(403, "La verificación CSRF falló.")
            elif (recovery is None or user is None or user.is_admin or not user.is_active
                    or recovery.expires_at <= timestamp or recovery.revoked_at is not None or recovery.consumed_at is not None):
                failure = HTTPException(400, "El código no es válido o ha caducado.")
            else:
                user.password_hash = PASSWORDS.hash(password)
                recovery.consumed_at = timestamp
                database.flush()
                _revoke_recovery(database, user.id, timestamp)
                database.execute(update(AuthSession).where(AuthSession.user_id == user.id,
                    AuthSession.revoked_at.is_(None)).values(revoked_at=timestamp))
                if challenge_valid:
                    database.delete(challenge)
        _audit_event(database, actor_id=actor_id, target_id=target_id, action="recovery.consumed",
                     result="failure" if failure else "success", correlation_id=_correlation_id(request))
    request.state.auth_audit_recorded = True
    if failure is not None:
        raise failure
    _clear_cookies(response, config)
    response.headers["Cache-Control"] = "no-store"
    return {"status": "password_recovered", "login_required": True}


@router.post("/recover")
async def recover(request: Request, response: Response):
    return await _account_request(request, response, RecoveryBody, _recover, "recovery.consumed")


@router.get("/admin/audit")
def audit_events(request: Request, response: Response, page: int = Query(1, ge=1),
                 page_size: int = Query(25, ge=1, le=100), action: str = "",
                 target_id: str = "", result: str = ""):
    if ((action and action not in AUDIT_ACTIONS) or (target_id and not ID_PATTERN.fullmatch(target_id))
            or (result and result not in {"success", "failure"})):
        raise HTTPException(422, "Filtros de auditoría inválidos.")
    with _http_storage() as database:
        # Count and page use one read-only snapshot; concurrent audit inserts
        # cannot make their totals disagree within a response.
        database.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY"))
        _administrator(database, request, lock_user=False)
        filters = []
        if action:
            filters.append(AuditEvent.action == action)
        if target_id:
            filters.append(AuditEvent.target_id == target_id)
        if result:
            filters.append(AuditEvent.result == result)
        total = database.scalar(select(func.count()).select_from(AuditEvent).where(*filters))
        events = database.execute(select(AuditEvent).where(*filters).order_by(AuditEvent.created_at.desc(),
            AuditEvent.id.desc()).offset((page - 1) * page_size).limit(page_size)).scalars().all()
        items = [{"actor_id": event.actor_id, "target_id": event.target_id, "action": event.action,
                  "created_at": _utc_string(event.created_at), "result": event.result,
                  "correlation_id": event.correlation_id} for event in events]
    response.headers["Cache-Control"] = "no-store"
    return {"items": items, "page": page, "page_size": page_size, "total": total}
