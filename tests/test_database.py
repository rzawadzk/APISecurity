"""Tests for Database user/session/audit methods."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class TestUsers:
    def test_create_and_fetch(self, db):
        uid = db.create_user("alice", "hash", role="admin", email="a@b.c")
        row = db.get_user_by_id(uid)
        assert row["username"] == "alice"
        assert row["role"] == "admin"
        assert row["email"] == "a@b.c"

    def test_unique_username(self, db):
        db.create_user("bob", "h1")
        import sqlite3
        try:
            db.create_user("bob", "h2")
        except sqlite3.IntegrityError:
            pass
        else:
            raise AssertionError("duplicate username should have failed")

    def test_list_excludes_password_hash(self, db):
        db.create_user("c", "supersecret-hash")
        users = db.list_users()
        assert all("password_hash" not in u for u in users)

    def test_update_role_and_active(self, db):
        uid = db.create_user("x", "h", role="viewer")
        db.update_user_role(uid, "analyst")
        db.set_user_active(uid, False)
        row = db.get_user_by_id(uid)
        assert row["role"] == "analyst"
        assert row["is_active"] == 0

    def test_count_users(self, db):
        assert db.count_users() == 0
        db.create_user("a", "h")
        db.create_user("b", "h")
        db.set_user_active(db.get_user_by_username("b")["id"], False)
        assert db.count_users() == 2
        assert db.count_users(active_only=True) == 1


class TestSessions:
    def test_create_resolve_delete(self, db):
        uid = db.create_user("s", "h")
        exp = _utcnow() + timedelta(hours=1)
        db.create_session("sid-123", uid, exp, user_agent="ua", ip_address="1.2.3.4")
        row = db.get_session("sid-123")
        assert row is not None
        assert row["username"] == "s"
        db.delete_session("sid-123")
        assert db.get_session("sid-123") is None

    def test_expired_sessions_not_returned(self, db):
        uid = db.create_user("s", "h")
        past = _utcnow() - timedelta(hours=1)
        db.create_session("sid-exp", uid, past)
        assert db.get_session("sid-exp") is None

    def test_purge_expired(self, db):
        uid = db.create_user("s", "h")
        past = _utcnow() - timedelta(hours=1)
        future = _utcnow() + timedelta(hours=1)
        db.create_session("s1", uid, past)
        db.create_session("s2", uid, future)
        purged = db.purge_expired_sessions()
        assert purged == 1

    def test_delete_sessions_for_user(self, db):
        uid = db.create_user("s", "h")
        future = _utcnow() + timedelta(hours=1)
        db.create_session("a", uid, future)
        db.create_session("b", uid, future)
        db.delete_sessions_for_user(uid)
        assert db.get_session("a") is None
        assert db.get_session("b") is None


class TestAuditLog:
    def test_write_and_read(self, db):
        db.write_audit(
            action="test.action",
            user_id=1,
            username="tester",
            method="POST",
            path="/api/thing",
            ip_address="10.0.0.1",
            status_code=200,
            details={"foo": "bar"},
        )
        entries = db.get_audit_log()
        assert len(entries) == 1
        assert entries[0]["action"] == "test.action"
        assert entries[0]["status_code"] == 200

    def test_filter_by_action(self, db):
        db.write_audit(action="auth.login.success", username="a")
        db.write_audit(action="auth.logout", username="a")
        db.write_audit(action="auth.login.success", username="b")
        hits = db.get_audit_log(action="auth.login.success")
        assert len(hits) == 2

    def test_filter_by_username(self, db):
        db.write_audit(action="x", username="alice")
        db.write_audit(action="x", username="bob")
        hits = db.get_audit_log(username="alice")
        assert len(hits) == 1


class TestAppMeta:
    def test_set_get_update(self, db):
        assert db.meta_get("k") is None
        db.meta_set("k", "v1")
        assert db.meta_get("k") == "v1"
        db.meta_set("k", "v2")
        assert db.meta_get("k") == "v2"
