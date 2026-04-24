"""End-to-end Database tests against a real Postgres server.

These tests are skipped unless ``API_SCOUT_TEST_POSTGRES_URL`` is set
to a libpq-style connection URL for a Postgres instance the test
harness is allowed to write to (it creates and drops tables).

Running locally:

    docker run --rm -d --name apiscout-pg -p 5432:5432 \\
        -e POSTGRES_PASSWORD=secret postgres:16-alpine
    export API_SCOUT_TEST_POSTGRES_URL=postgresql://postgres:secret@localhost:5432/postgres
    pytest tests/test_postgres_backend.py -v

In CI, a services: postgres: block provides the same URL.

The fixture truncates every table between tests so each run gets a
clean slate without the overhead of re-applying migrations.
"""

from __future__ import annotations

import os
from datetime import datetime, timedelta, timezone

import pytest

# Optional psycopg import — skip cleanly if the postgres extra isn't
# installed in this environment.
psycopg = pytest.importorskip("psycopg")

from api_scout.auth import hash_password
from api_scout.database import Database

PG_URL = os.environ.get("API_SCOUT_TEST_POSTGRES_URL")

pytestmark = pytest.mark.skipif(
    not PG_URL,
    reason="Set API_SCOUT_TEST_POSTGRES_URL to run Postgres integration tests",
)


@pytest.fixture
def pg_db():
    """Fresh Database bound to the shared Postgres, cleaned between tests."""
    db = Database(PG_URL)
    # Wipe everything the schema created. Cheaper than drop+reapply.
    _truncate_all(PG_URL)
    yield db


def _truncate_all(url: str) -> None:
    tables = [
        "audit_log",
        "sessions",
        "alerts",
        "scan_history",
        "traffic_log",
        "app_meta",
        "users",
        "endpoints",
    ]
    with psycopg.connect(url) as conn:
        with conn.cursor() as cur:
            for t in tables:
                # CASCADE handles FK from sessions->users, alerts->endpoints.
                cur.execute(f"TRUNCATE TABLE {t} RESTART IDENTITY CASCADE")
        conn.commit()


# ── Users ─────────────────────────────────────────────────────────


class TestPgUsers:
    def test_create_and_fetch(self, pg_db):
        uid = pg_db.create_user("alice", "hash", role="admin", email="a@b.c")
        row = pg_db.get_user_by_id(uid)
        assert row["username"] == "alice"
        assert row["role"] == "admin"
        assert row["email"] == "a@b.c"
        assert row["is_active"] == 1

    def test_unique_username(self, pg_db):
        pg_db.create_user("bob", "h1")
        with pytest.raises(psycopg.errors.IntegrityError):
            pg_db.create_user("bob", "h2")

    def test_count_users(self, pg_db):
        assert pg_db.count_users() == 0
        pg_db.create_user("a", "h")
        pg_db.create_user("b", "h")
        assert pg_db.count_users() == 2

    def test_login_failure_locks_after_threshold(self, pg_db):
        uid = pg_db.create_user("x", "h")
        for _ in range(5):
            pg_db.record_login_failure(uid, lockout_threshold=5, lockout_minutes=10)
        row = pg_db.get_user_by_id(uid)
        assert row["failed_login_count"] == 5
        assert row["locked_until"] is not None

    def test_login_success_resets_counters(self, pg_db):
        uid = pg_db.create_user("x", "h")
        pg_db.record_login_failure(uid)
        pg_db.record_login_success(uid)
        row = pg_db.get_user_by_id(uid)
        assert row["failed_login_count"] == 0
        assert row["locked_until"] is None


# ── Sessions ──────────────────────────────────────────────────────


class TestPgSessions:
    def test_create_resolve_delete(self, pg_db):
        uid = pg_db.create_user("s", "h")
        exp = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        pg_db.create_session("sid-a", uid, exp)
        row = pg_db.get_session("sid-a")
        assert row is not None
        assert row["username"] == "s"
        pg_db.delete_session("sid-a")
        assert pg_db.get_session("sid-a") is None

    def test_expired_not_returned(self, pg_db):
        uid = pg_db.create_user("s", "h")
        past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        pg_db.create_session("sid-b", uid, past)
        assert pg_db.get_session("sid-b") is None

    def test_purge_expired(self, pg_db):
        uid = pg_db.create_user("s", "h")
        past = datetime.now(timezone.utc).replace(tzinfo=None) - timedelta(hours=1)
        future = datetime.now(timezone.utc).replace(tzinfo=None) + timedelta(hours=1)
        pg_db.create_session("s1", uid, past)
        pg_db.create_session("s2", uid, future)
        assert pg_db.purge_expired_sessions() == 1


# ── Audit log ─────────────────────────────────────────────────────


class TestPgAuditLog:
    def test_write_and_read(self, pg_db):
        pg_db.write_audit(
            action="test.action",
            username="tester",
            method="POST",
            path="/api/thing",
            status_code=200,
            details={"foo": "bar"},
        )
        entries = pg_db.get_audit_log()
        assert len(entries) == 1
        assert entries[0]["action"] == "test.action"
        assert entries[0]["status_code"] == 200

    def test_filter_by_action(self, pg_db):
        pg_db.write_audit(action="auth.login.success", username="a")
        pg_db.write_audit(action="auth.logout", username="a")
        hits = pg_db.get_audit_log(action="auth.login.success")
        assert len(hits) == 1


# ── App meta ──────────────────────────────────────────────────────


class TestPgAppMeta:
    def test_set_get_update(self, pg_db):
        assert pg_db.meta_get("k") is None
        pg_db.meta_set("k", "v1")
        assert pg_db.meta_get("k") == "v1"
        pg_db.meta_set("k", "v2")
        assert pg_db.meta_get("k") == "v2"


# ── Migrations tracking ───────────────────────────────────────────


class TestPgMigrations:
    def test_initial_migration_recorded(self, pg_db):
        with psycopg.connect(PG_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT version FROM schema_migrations ORDER BY version")
                rows = cur.fetchall()
        assert [r[0] for r in rows] == [1]

    def test_reopening_db_is_idempotent(self):
        # Second Database() against the same URL must not re-run the
        # migration (which would fail because tables already exist
        # without IF NOT EXISTS... actually ours uses IF NOT EXISTS,
        # but we also must not duplicate the schema_migrations row).
        Database(PG_URL)
        Database(PG_URL)
        with psycopg.connect(PG_URL) as conn:
            with conn.cursor() as cur:
                cur.execute("SELECT COUNT(*) FROM schema_migrations WHERE version = 1")
                n = cur.fetchone()[0]
        assert n == 1


# ── Traffic stats (exercises hour_bucket_sql + interval cutoff) ───


class TestPgTrafficQueries:
    def test_traffic_timeline_buckets_by_hour(self, pg_db):
        from api_scout.models import TrafficRecord, AuthMethod, DiscoverySource

        now = datetime.now(timezone.utc).replace(tzinfo=None)
        recs = [
            TrafficRecord(
                timestamp=now - timedelta(minutes=5),
                method="GET",
                path="/x",
                status_code=200,
                source_ip="1.1.1.1",
                source_service=None,
                auth_method=AuthMethod.NONE,
                auth_subject=None,
                response_time_ms=12.3,
                host="h",
                discovery_source=DiscoverySource.LOG_NGINX,
            ),
        ]
        pg_db.log_traffic(recs, path_patterns={"/x": "/x"})
        timeline = pg_db.get_traffic_timeline(hours=1)
        assert len(timeline) == 1
        assert timeline[0]["requests"] == 1
