"""AUTH-01 PostgreSQL identity and ownership metadata; media stays in its store."""
from datetime import datetime

from sqlalchemy import (Boolean, CheckConstraint, DateTime, ForeignKey,
                        ForeignKeyConstraint, Index, Integer, String)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column


class Base(DeclarativeBase):
    pass


class User(Base):
    __tablename__ = "auth_users"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(String(512), nullable=False)
    is_admin: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    is_active: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Workspace(Base):
    __tablename__ = "auth_workspaces"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    owner_id: Mapped[str] = mapped_column(ForeignKey("auth_users.id"), unique=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class Membership(Base):
    __tablename__ = "auth_memberships"
    workspace_id: Mapped[str] = mapped_column(ForeignKey("auth_workspaces.id"), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("auth_users.id"), primary_key=True)
    role: Mapped[str] = mapped_column(String(16), nullable=False, default="owner")
    __table_args__ = (CheckConstraint("role = 'owner'", name="auth_membership_owner_only"),)


class Project(Base):
    __tablename__ = "auth_projects"
    id: Mapped[str] = mapped_column(String(32), primary_key=True)
    workspace_id: Mapped[str] = mapped_column(String(32), nullable=False)
    owner_id: Mapped[str] = mapped_column(String(32), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (
        ForeignKeyConstraint(["workspace_id", "owner_id"],
                             ["auth_memberships.workspace_id", "auth_memberships.user_id"]),
        Index("auth_projects_owner_idx", "owner_id", "workspace_id"),
    )


class AuthSession(Base):
    __tablename__ = "auth_sessions"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    user_id: Mapped[str] = mapped_column(ForeignKey("auth_users.id"), nullable=False)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
    __table_args__ = (Index("auth_sessions_user_idx", "user_id"),
                      Index("auth_sessions_expiry_idx", "expires_at"))


class AuthChallenge(Base):
    __tablename__ = "auth_challenges"
    token_hash: Mapped[str] = mapped_column(String(64), primary_key=True)
    csrf_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (Index("auth_challenges_expiry_idx", "expires_at"),)


class LoginAttempt(Base):
    __tablename__ = "auth_login_attempts"
    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    identity_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    client_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    attempted_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    __table_args__ = (Index("auth_login_identity_idx", "identity_hash", "attempted_at"),
                      Index("auth_login_client_idx", "client_hash", "attempted_at"))
