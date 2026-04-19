"""Unit tests for api_scout.auth."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)

import pytest

from api_scout.auth import (
    LOCKOUT_THRESHOLD,
    Role,
    SessionManager,
    authenticate,
    get_or_create_secret,
    hash_password,
    role_at_least,
    verify_password,
)


class TestPasswordHashing:
    def test_hash_and_verify_roundtrip(self):
        h = hash_password("CorrectHorse1")
        assert verify_password("CorrectHorse1", h)
        assert not verify_password("wrongpassword", h)

    def test_hashes_are_salted(self):
        a = hash_password("samepass1")
        b = hash_password("samepass1")
        assert a != b  # bcrypt salts => distinct hashes for same input

    def test_rejects_short_password(self):
        with pytest.raises(ValueError):
            hash_password("short")

    def test_verify_rejects_garbage(self):
        assert not verify_password("whatever", "not-a-bcrypt-hash")


class TestRoleHierarchy:
    def test_admin_covers_all(self):
        assert role_at_least("admin", Role.ADMIN)
        assert role_at_least("admin", Role.ANALYST)
        assert role_at_least("admin", Role.VIEWER)

    def test_analyst_covers_viewer_not_admin(self):
        assert role_at_least("analyst", Role.ANALYST)
        assert role_at_least("analyst", Role.VIEWER)
        assert not role_at_least("analyst", Role.ADMIN)

    def test_viewer_only_viewer(self):
        assert role_at_least("viewer", Role.VIEWER)
        assert not role_at_least("viewer", Role.ANALYST)
        assert not role_at_least("viewer", Role.ADMIN)

    def test_unknown_role_denies(self):
        assert not role_at_least("superuser", Role.VIEWER)
        assert not role_at_least("", Role.VIEWER)


class TestAuthenticate:
    def test_success(self, db, admin_user):
        user = authenticate(db, "admin", "adminpass1")
        assert user is not None
        assert user["username"] == "admin"

    def test_wrong_password(self, db, admin_user):
        assert authenticate(db, "admin", "wrong") is None

    def test_unknown_user(self, db):
        assert authenticate(db, "ghost", "whatever") is None

    def test_inactive_user_cannot_login(self, db, admin_user):
        db.set_user_active(admin_user["id"], False)
        assert authenticate(db, "admin", "adminpass1") is None

    def test_lockout_after_threshold(self, db, admin_user):
        for _ in range(LOCKOUT_THRESHOLD):
            assert authenticate(db, "admin", "wrongpw") is None
        # Even the correct password is rejected while locked
        assert authenticate(db, "admin", "adminpass1") is None
        # Verify locked_until was set
        row = db.get_user_by_username("admin")
        assert row["locked_until"] is not None


class TestSessionManager:
    def test_create_and_resolve(self, db, admin_user):
        secret = get_or_create_secret(db)
        sm = SessionManager(db, secret)
        cookie, expires = sm.create(admin_user["id"], user_agent="pytest", ip_address="127.0.0.1")
        assert cookie  # signed string
        row = sm.resolve(cookie)
        assert row is not None
        assert row["user_id"] == admin_user["id"]
        assert row["username"] == "admin"
        assert expires > _utcnow()

    def test_tampered_cookie_rejected(self, db, admin_user):
        secret = get_or_create_secret(db)
        sm = SessionManager(db, secret)
        cookie, _ = sm.create(admin_user["id"])
        # Flip a character — signature should no longer verify
        tampered = cookie[:-2] + ("aa" if cookie[-2:] != "aa" else "bb")
        assert sm.resolve(tampered) is None

    def test_revoke_deletes_session(self, db, admin_user):
        secret = get_or_create_secret(db)
        sm = SessionManager(db, secret)
        cookie, _ = sm.create(admin_user["id"])
        assert sm.resolve(cookie) is not None
        sm.revoke(cookie)
        assert sm.resolve(cookie) is None

    def test_different_secret_invalidates(self, db, admin_user):
        sm1 = SessionManager(db, "secret-one-at-least-32-chars-long-x")
        sm2 = SessionManager(db, "secret-two-at-least-32-chars-long-x")
        cookie, _ = sm1.create(admin_user["id"])
        assert sm2.resolve(cookie) is None

    def test_inactive_user_session_resolves_to_none(self, db, admin_user):
        secret = get_or_create_secret(db)
        sm = SessionManager(db, secret)
        cookie, _ = sm.create(admin_user["id"])
        db.set_user_active(admin_user["id"], False)
        # DB join filters on is_active=1
        assert sm.resolve(cookie) is None


class TestSecretProvisioning:
    def test_first_call_persists_secret(self, db):
        s1 = get_or_create_secret(db)
        s2 = get_or_create_secret(db)
        assert s1 == s2
        assert len(s1) >= 32

    def test_env_override(self, db, monkeypatch):
        monkeypatch.setenv("API_SCOUT_SECRET", "x" * 40)
        assert get_or_create_secret(db) == "x" * 40

    def test_env_rejects_short_secret(self, db, monkeypatch):
        monkeypatch.setenv("API_SCOUT_SECRET", "tooshort")
        with pytest.raises(RuntimeError):
            get_or_create_secret(db)
