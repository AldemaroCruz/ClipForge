"""Explicit PostgreSQL configuration; never logs connection strings or secrets."""
from contextlib import contextmanager
from functools import lru_cache
import os
from pathlib import Path
import re

from sqlalchemy import URL, create_engine, text
from sqlalchemy.engine import make_url
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session


class AuthConfigurationError(ValueError):
    pass


class AuthDatabaseError(RuntimeError):
    pass


def database_schema() -> str:
    value = os.getenv("CLIPFORGE_DATABASE_SCHEMA", "public")
    if not re.fullmatch(r"[a-z][a-z0-9_]{0,62}", value):
        raise AuthConfigurationError("Invalid database schema configuration")
    return value


def _configuration() -> tuple:
    return tuple(os.getenv(name, "") for name in (
        "CLIPFORGE_DATABASE_URL", "CLIPFORGE_DATABASE_HOST", "CLIPFORGE_DATABASE_PORT",
        "CLIPFORGE_DATABASE_NAME", "CLIPFORGE_DATABASE_USER", "CLIPFORGE_DATABASE_PASSWORD_FILE",
    )) + (database_schema(),)


@lru_cache(maxsize=8)
def _engine(configuration):
    raw_url, host, port, name, user, password_file, schema = configuration
    try:
        if raw_url:
            if any((host, port, name, user, password_file)):
                raise ValueError("Ambiguous database configuration")
            url = make_url(raw_url)
            if url.drivername != "postgresql+psycopg":
                raise ValueError("Only PostgreSQL with psycopg is supported")
        else:
            if not all((host, name, user, password_file)):
                raise ValueError("Database configuration is incomplete")
            # This is an explicitly supplied candidate secret, not a dotenv search.
            password = Path(password_file).read_text(encoding="utf-8").rstrip("\r\n")
            if not password or len(password) > 4096 or "\n" in password:
                raise ValueError("Invalid database password file")
            url = URL.create("postgresql+psycopg", username=user, password=password,
                             host=host, port=int(port or "5432"), database=name)
        if not url.host or not url.database or not url.username:
            raise ValueError("Database identity is required")
        engine = create_engine(url, pool_pre_ping=True, pool_size=5, max_overflow=5,
                               pool_timeout=10, echo=False, hide_parameters=True,
                               connect_args={"connect_timeout": 5, "options": "-csearch_path=" + schema})
        _ENGINES.add(engine)
        return engine
    except (ValueError, OSError, TypeError):
        raise AuthConfigurationError("Database configuration is unavailable or invalid") from None


def get_engine():
    return _engine(_configuration())


def reset_engine():
    """Forget configuration for explicit test isolation or process reconfiguration."""
    # Checked-out connections must have been closed by the caller. Cached engines
    # are disposed through the tracked registry before clearing configuration.
    for engine in list(_ENGINES):
        engine.dispose()
    _ENGINES.clear()
    _engine.cache_clear()


_ENGINES = set()


@contextmanager
def session_scope():
    try:
        engine = get_engine()
        _ENGINES.add(engine)
        with Session(engine, expire_on_commit=False) as session:
            with session.begin():
                yield session
    except SQLAlchemyError:
        raise AuthDatabaseError("Authentication storage is unavailable") from None


def database_ready() -> bool:
    try:
        with get_engine().connect() as connection:
            revisions = connection.execute(text("SELECT revision FROM auth_schema_migrations ORDER BY revision")).scalars().all()
        return revisions == ["auth01_0001"]
    except (AuthConfigurationError, SQLAlchemyError):
        return False
