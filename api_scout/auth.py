"""Authentication, RBAC, and session management for the dashboard.

Design:
  - Passwords hashed with bcrypt (cost factor 12).
  - Sessions are server-side rows keyed by a random 256-bit token.
  - The session token is delivered to the browser as a *signed* cookie via
    itsdangerous, so an attacker cannot forge a session ID even if they
    learn the cookie name. The signature is rotated when the secret changes.
  - Three roles: admin, analyst, viewer. RBAC is enforced via FastAPI
    dependencies (`require_role(...)`).
  - Account lockout after 5 failed logins for 15 minutes.

Bootstrap:
  - The signing secret is persisted in the `app_meta` table on first run
    (auto-generated, 32 bytes urandom). Override via API_SCOUT_SECRET env var.
  - The dashboard refuses to start if no admin user exists. Bootstrap with
    `api-scout user create --role admin <username>`.
"""
from __future__ import annotations

import os
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    """Naive UTC datetime (keeps comparisons simple across the codebase)."""
    return datetime.now(timezone.utc).replace(tzinfo=None)
from enum import Enum
from typing import Optional

import bcrypt
from fastapi import Cookie, Depends, HTTPException, Request, status
from itsdangerous import BadSignature, SignatureExpired, URLSafeTimedSerializer

from .database import Database

SESSION_COOKIE_NAME = "api_scout_session"
SESSION_TTL_HOURS = 12
LOCKOUT_THRESHOLD = 5
LOCKOUT_MINUTES = 15
SECRET_META_KEY = "session_secret"


class Role(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# Role hierarchy: admin >= analyst >= viewer
_ROLE_RANK = {Role.VIEWER: 0, Role.ANALYST: 1, Role.ADMIN: 2}


def role_at_least(user_role: str, required: Role) -> bool:
    try:
        return _ROLE_RANK[Role(user_role)] >= _ROLE_RANK[required]
    except (ValueError, KeyError):
        return False


@dataclass
class AuthenticatedUser:
    id: int
    username: str
    role: str
    session_id: str


class AuthError(HTTPException):
    def __init__(self, detail: str = "Not authenticated"):
        super().__init__(status_code=status.HTTP_401_UNAUTHORIZED, detail=detail)


class ForbiddenError(HTTPException):
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


# ── Password hashing ──

def hash_password(plaintext: str) -> str:
    if not plaintext or len(plaintext) < 8:
        raise ValueError("Password must be at least 8 characters")
    return bcrypt.hashpw(plaintext.encode("utf-8"), bcrypt.gensalt(rounds=12)).decode("utf-8")


def verify_password(plaintext: str, hashed: str) -> bool:
    try:
        return bcrypt.checkpw(plaintext.encode("utf-8"), hashed.encode("utf-8"))
    except (ValueError, TypeError):
        return False


# ── Session signing ──

def get_or_create_secret(db: Database) -> str:
    """Return the cookie-signing secret, generating one on first run."""
    env_secret = os.environ.get("API_SCOUT_SECRET")
    if env_secret:
        if len(env_secret) < 32:
            raise RuntimeError("API_SCOUT_SECRET must be at least 32 characters")
        return env_secret
    existing = db.meta_get(SECRET_META_KEY)
    if existing:
        return existing
    new_secret = secrets.token_urlsafe(48)
    db.meta_set(SECRET_META_KEY, new_secret)
    return new_secret


class SessionManager:
    """Server-side session store with signed-cookie delivery."""

    def __init__(self, db: Database, secret: str):
        self.db = db
        self.serializer = URLSafeTimedSerializer(secret, salt="api_scout.session.v1")

    def create(
        self,
        user_id: int,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> tuple[str, datetime]:
        """Create a new session and return (signed_cookie_value, expires_at)."""
        session_id = secrets.token_urlsafe(32)
        expires_at = _utcnow() + timedelta(hours=SESSION_TTL_HOURS)
        self.db.create_session(
            session_id=session_id,
            user_id=user_id,
            expires_at=expires_at,
            user_agent=user_agent,
            ip_address=ip_address,
        )
        return self.serializer.dumps(session_id), expires_at

    def resolve(self, signed_cookie: str) -> Optional[dict]:
        """Verify the signature, look up the session row, return joined user data."""
        try:
            session_id = self.serializer.loads(
                signed_cookie,
                max_age=SESSION_TTL_HOURS * 3600,
            )
        except (BadSignature, SignatureExpired):
            return None
        return self.db.get_session(session_id)

    def revoke(self, signed_cookie: str) -> None:
        try:
            session_id = self.serializer.loads(
                signed_cookie,
                max_age=SESSION_TTL_HOURS * 3600,
            )
            self.db.delete_session(session_id)
        except (BadSignature, SignatureExpired):
            pass


# ── Login flow ──

# Pre-computed bcrypt hash used as a timing-equalizer when the user doesn't
# exist. Generated once at import so unknown-user lookups take roughly as long
# as known-user lookups (mitigates user-enumeration via response time).
_DUMMY_HASH = bcrypt.hashpw(b"dummy-password", bcrypt.gensalt(rounds=12))


def authenticate(db: Database, username: str, password: str) -> Optional[dict]:
    """Verify credentials. Returns the user row or None.

    Side effects: increments failed_login_count on bad password,
    resets it on success, applies lockout.
    """
    user = db.get_user_by_username(username)
    if not user:
        # Timing-equalizer: always run a bcrypt check, even for unknown users
        bcrypt.checkpw(password.encode("utf-8"), _DUMMY_HASH)
        return None

    if user["locked_until"]:
        try:
            locked_until = datetime.fromisoformat(user["locked_until"])
            if locked_until > _utcnow():
                return None
        except (ValueError, TypeError):
            pass

    if not user["is_active"]:
        return None

    if not verify_password(password, user["password_hash"]):
        db.record_login_failure(user["id"], LOCKOUT_THRESHOLD, LOCKOUT_MINUTES)
        return None

    db.record_login_success(user["id"])
    return user


# ── FastAPI dependencies ──

def get_session_manager(request: Request) -> SessionManager:
    sm = getattr(request.app.state, "session_manager", None)
    if sm is None:
        raise RuntimeError("SessionManager not configured on app.state")
    return sm


def get_current_user(
    request: Request,
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    sm: SessionManager = Depends(get_session_manager),
) -> AuthenticatedUser:
    if not session:
        raise AuthError()
    row = sm.resolve(session)
    if not row:
        raise AuthError("Session expired or invalid")
    user = AuthenticatedUser(
        id=row["user_id"],
        username=row["username"],
        role=row["role"],
        session_id=row["id"],
    )
    # Stash on request.state for audit middleware
    request.state.user = user
    return user


def get_optional_user(
    request: Request,
    session: Optional[str] = Cookie(default=None, alias=SESSION_COOKIE_NAME),
    sm: SessionManager = Depends(get_session_manager),
) -> Optional[AuthenticatedUser]:
    if not session:
        return None
    row = sm.resolve(session)
    if not row:
        return None
    user = AuthenticatedUser(
        id=row["user_id"],
        username=row["username"],
        role=row["role"],
        session_id=row["id"],
    )
    request.state.user = user
    return user


def require_role(required: Role):
    """Return a FastAPI dependency that enforces a minimum role."""
    def _dep(user: AuthenticatedUser = Depends(get_current_user)) -> AuthenticatedUser:
        if not role_at_least(user.role, required):
            raise ForbiddenError(f"Requires role {required.value} or higher")
        return user
    return _dep


require_admin = require_role(Role.ADMIN)
require_analyst = require_role(Role.ANALYST)
require_viewer = require_role(Role.VIEWER)
