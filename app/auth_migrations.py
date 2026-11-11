"""Versioned, forward-only AUTH-01 migration. Never imports media or old projects.

Revision auth01_0001 is deliberately frozen SQL, independent from future ORM
model edits. PostgreSQL transactional DDL and an advisory lock protect upgrades.
"""
from datetime import datetime, timezone

from sqlalchemy import text
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.schema import CreateSchema

from .auth_db import AuthConfigurationError, database_schema, get_engine


INITIAL_REVISION = "auth01_0001"
REVISION = "auth02_0002"
DDL_0001 = (
    """CREATE TABLE auth_users (
        id VARCHAR(32) PRIMARY KEY, username VARCHAR(64) NOT NULL UNIQUE,
        password_hash VARCHAR(512) NOT NULL, is_admin BOOLEAN NOT NULL,
        is_active BOOLEAN NOT NULL, created_at TIMESTAMPTZ NOT NULL)""",
    """CREATE TABLE auth_workspaces (
        id VARCHAR(32) PRIMARY KEY, owner_id VARCHAR(32) NOT NULL UNIQUE REFERENCES auth_users(id),
        created_at TIMESTAMPTZ NOT NULL)""",
    """CREATE TABLE auth_memberships (
        workspace_id VARCHAR(32) REFERENCES auth_workspaces(id),
        user_id VARCHAR(32) REFERENCES auth_users(id), role VARCHAR(16) NOT NULL,
        PRIMARY KEY (workspace_id,user_id), CONSTRAINT auth_membership_owner_only CHECK (role = 'owner'))""",
    """CREATE TABLE auth_projects (
        id VARCHAR(32) PRIMARY KEY, workspace_id VARCHAR(32) NOT NULL, owner_id VARCHAR(32) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL,
        FOREIGN KEY (workspace_id,owner_id) REFERENCES auth_memberships(workspace_id,user_id))""",
    "CREATE INDEX auth_projects_owner_idx ON auth_projects(owner_id,workspace_id)",
    """CREATE TABLE auth_sessions (
        token_hash VARCHAR(64) PRIMARY KEY, user_id VARCHAR(32) NOT NULL REFERENCES auth_users(id),
        csrf_hash VARCHAR(64) NOT NULL, created_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL, revoked_at TIMESTAMPTZ)""",
    "CREATE INDEX auth_sessions_user_idx ON auth_sessions(user_id)",
    "CREATE INDEX auth_sessions_expiry_idx ON auth_sessions(expires_at)",
    """CREATE TABLE auth_challenges (
        token_hash VARCHAR(64) PRIMARY KEY, csrf_hash VARCHAR(64) NOT NULL, client_hash VARCHAR(64) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL, expires_at TIMESTAMPTZ NOT NULL)""",
    "CREATE INDEX auth_challenges_expiry_idx ON auth_challenges(expires_at)",
    """CREATE TABLE auth_login_attempts (
        id SERIAL PRIMARY KEY, identity_hash VARCHAR(64) NOT NULL, client_hash VARCHAR(64) NOT NULL,
        attempted_at TIMESTAMPTZ NOT NULL)""",
    "CREATE INDEX auth_login_identity_idx ON auth_login_attempts(identity_hash,attempted_at)",
    "CREATE INDEX auth_login_client_idx ON auth_login_attempts(client_hash,attempted_at)",
)

# auth01_0001 is immutable. Existing installations advance through this separate
# transactional revision, while new fixture databases apply both in order.
DDL_0002 = (
    """CREATE TABLE auth_recovery_codes (
        token_hash VARCHAR(64) PRIMARY KEY, user_id VARCHAR(32) NOT NULL REFERENCES auth_users(id),
        issued_by_id VARCHAR(32) NOT NULL REFERENCES auth_users(id), created_at TIMESTAMPTZ NOT NULL,
        expires_at TIMESTAMPTZ NOT NULL, consumed_at TIMESTAMPTZ, revoked_at TIMESTAMPTZ)""",
    "CREATE INDEX auth_recovery_user_idx ON auth_recovery_codes(user_id)",
    "CREATE INDEX auth_recovery_expiry_idx ON auth_recovery_codes(expires_at)",
    """CREATE TABLE auth_audit_events (
        id VARCHAR(32) PRIMARY KEY, actor_id VARCHAR(32), target_id VARCHAR(32),
        action VARCHAR(32) NOT NULL, created_at TIMESTAMPTZ NOT NULL,
        result VARCHAR(16) NOT NULL, correlation_id VARCHAR(36) NOT NULL,
        CONSTRAINT auth_audit_result_valid CHECK (result IN ('success','failure')),
        CONSTRAINT auth_audit_action_valid CHECK (action IN ('user.created','user.deactivated',
            'recovery.issued','recovery.consumed','password.changed')))""",
    "CREATE INDEX auth_audit_created_idx ON auth_audit_events(created_at,id)",
    "CREATE INDEX auth_audit_target_idx ON auth_audit_events(target_id,created_at)",
    """CREATE TABLE auth_security_attempts (
        id SERIAL PRIMARY KEY, purpose VARCHAR(32) NOT NULL, identity_hash VARCHAR(64) NOT NULL,
        client_hash VARCHAR(64) NOT NULL, attempted_at TIMESTAMPTZ NOT NULL,
        CONSTRAINT auth_security_purpose_valid CHECK (purpose IN (
            'recovery_issue','recovery_consume','password_change')))""",
    "CREATE INDEX auth_security_identity_idx ON auth_security_attempts(purpose,identity_hash,attempted_at)",
    "CREATE INDEX auth_security_client_idx ON auth_security_attempts(purpose,client_hash,attempted_at)",
)
MIGRATIONS = ((INITIAL_REVISION, DDL_0001), (REVISION, DDL_0002))


class MigrationError(RuntimeError):
    pass


def upgrade(engine=None) -> dict:
    try:
        engine = engine or get_engine()
        if engine.dialect.name != "postgresql":
            raise MigrationError("AUTH-01 requires PostgreSQL")
        with engine.begin() as connection:
            connection.execute(text("SELECT pg_advisory_xact_lock(1837086401)"))
            connection.execute(CreateSchema(database_schema(), if_not_exists=True))
            connection.execute(text("""CREATE TABLE IF NOT EXISTS auth_schema_migrations (
                revision VARCHAR(32) PRIMARY KEY, applied_at TIMESTAMPTZ NOT NULL)"""))
            revisions = connection.execute(text("SELECT revision FROM auth_schema_migrations ORDER BY revision")).scalars().all()
            expected = [revision for revision, _ in MIGRATIONS]
            if revisions == expected:
                return {"status": "current", "revision": REVISION}
            if revisions != expected[:len(revisions)]:
                raise MigrationError("Unknown schema revision; no migration applied")
            for revision, statements in MIGRATIONS[len(revisions):]:
                for statement in statements:
                    connection.execute(text(statement))
                connection.execute(text("INSERT INTO auth_schema_migrations(revision,applied_at) VALUES (:revision,:time)"),
                                   {"revision": revision, "time": datetime.now(timezone.utc)})
        return {"status": "applied", "revision": REVISION}
    except (SQLAlchemyError, AuthConfigurationError):
        raise MigrationError("Migration failed; transaction rolled back. Check candidate database configuration and schema.") from None
