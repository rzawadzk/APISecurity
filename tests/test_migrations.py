"""Tests for the schema-migrations runner.

The runner is backend-agnostic by design. These tests drive it with a
plain :mod:`sqlite3` connection because that's the default backend and
it exercises the same code path Postgres will use (modulo placeholder
style and multi-statement execution, which the runner auto-detects).
"""

from __future__ import annotations

import sqlite3

import pytest

from api_scout import migrations as mig


# ── Filename discovery ────────────────────────────────────────────────


class TestDiscover:
    def test_empty_dir_returns_empty(self, tmp_path):
        result = mig.discover(mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        assert result == []

    def test_picks_only_matching_dialect(self, tmp_path):
        (tmp_path / "0001_a.sqlite.sql").write_text("SELECT 1;")
        (tmp_path / "0001_a.postgres.sql").write_text("SELECT 1;")
        (tmp_path / "0002_b.sqlite.sql").write_text("SELECT 1;")

        sqlite_migs = mig.discover(mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        pg_migs = mig.discover(mig.DIALECT_POSTGRES, migrations_dir=tmp_path)

        assert [m.version for m in sqlite_migs] == [1, 2]
        assert [m.version for m in pg_migs] == [1]

    def test_versions_are_sorted(self, tmp_path):
        # Write files out of order to confirm the sort.
        (tmp_path / "0003_c.sqlite.sql").write_text("SELECT 3;")
        (tmp_path / "0001_a.sqlite.sql").write_text("SELECT 1;")
        (tmp_path / "0002_b.sqlite.sql").write_text("SELECT 2;")

        result = mig.discover(mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        assert [m.version for m in result] == [1, 2, 3]

    def test_duplicate_version_raises(self, tmp_path):
        (tmp_path / "0001_a.sqlite.sql").write_text("SELECT 1;")
        (tmp_path / "0001_b.sqlite.sql").write_text("SELECT 1;")

        with pytest.raises(ValueError, match="Duplicate migration version 0001"):
            mig.discover(mig.DIALECT_SQLITE, migrations_dir=tmp_path)

    def test_ignores_non_migration_files(self, tmp_path):
        (tmp_path / "__init__.py").write_text("")
        (tmp_path / "README.md").write_text("")
        (tmp_path / "0001_real.sqlite.sql").write_text("SELECT 1;")
        (tmp_path / "malformed.sql").write_text("SELECT 1;")
        (tmp_path / "0001_wrongshape.sql").write_text("SELECT 1;")  # no dialect

        result = mig.discover(mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        assert [m.version for m in result] == [1]
        assert result[0].name == "real"


# ── apply_pending: end-to-end against a real sqlite connection ────────


@pytest.fixture
def sqlite_conn():
    """An in-memory SQLite connection (autocommit off)."""
    conn = sqlite3.connect(":memory:")
    yield conn
    conn.close()


class TestApplyPending:
    def test_creates_tracking_table(self, sqlite_conn, tmp_path):
        mig.apply_pending(sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        # Tracking table exists and is empty (no migrations to apply).
        rows = sqlite_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations'"
        ).fetchall()
        assert len(rows) == 1

    def test_applies_pending_and_records_version(self, sqlite_conn, tmp_path):
        (tmp_path / "0001_create_thing.sqlite.sql").write_text(
            "CREATE TABLE thing (id INTEGER PRIMARY KEY, name TEXT);"
        )
        applied = mig.apply_pending(
            sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path
        )

        assert [m.version for m in applied] == [1]
        # The table was created.
        rows = sqlite_conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='thing'"
        ).fetchall()
        assert len(rows) == 1
        # The version was recorded.
        assert mig.applied_versions(sqlite_conn) == {1}

    def test_idempotent_rerun(self, sqlite_conn, tmp_path):
        (tmp_path / "0001_x.sqlite.sql").write_text(
            "CREATE TABLE IF NOT EXISTS x (id INTEGER PRIMARY KEY);"
        )
        mig.apply_pending(sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path)
        # Second call should apply nothing.
        applied = mig.apply_pending(
            sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path
        )
        assert applied == []

    def test_applies_in_version_order(self, sqlite_conn, tmp_path):
        # 0002 references a table that 0001 creates. If order is wrong
        # the second would fail with "no such table".
        (tmp_path / "0001_create.sqlite.sql").write_text(
            "CREATE TABLE t (id INTEGER PRIMARY KEY);"
        )
        (tmp_path / "0002_add_col.sqlite.sql").write_text(
            "ALTER TABLE t ADD COLUMN n TEXT;"
        )
        applied = mig.apply_pending(
            sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path
        )
        assert [m.version for m in applied] == [1, 2]

    def test_failure_does_not_record_version(self, sqlite_conn, tmp_path):
        (tmp_path / "0001_bad.sqlite.sql").write_text("NOT VALID SQL AT ALL;")
        with pytest.raises(sqlite3.Error):
            mig.apply_pending(
                sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path
            )
        # The tracking table exists (created before the first apply)
        # but the failed version is NOT recorded.
        assert mig.applied_versions(sqlite_conn) == set()

    def test_partial_chain_resumes_from_last_applied(self, sqlite_conn, tmp_path):
        (tmp_path / "0001_a.sqlite.sql").write_text(
            "CREATE TABLE a (id INTEGER PRIMARY KEY);"
        )
        mig.apply_pending(sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path)

        # Now drop a second migration in and re-run.
        (tmp_path / "0002_b.sqlite.sql").write_text(
            "CREATE TABLE b (id INTEGER PRIMARY KEY);"
        )
        applied = mig.apply_pending(
            sqlite_conn, dialect=mig.DIALECT_SQLITE, migrations_dir=tmp_path
        )
        assert [m.version for m in applied] == [2]
        assert mig.applied_versions(sqlite_conn) == {1, 2}


# ── Integration: the real shipped 0001 applies cleanly ────────────────


class TestShippedInitialMigration:
    def test_applies_against_fresh_sqlite(self, tmp_path):
        """The packaged 0001_initial.sqlite.sql should apply cleanly on a
        fresh database created via the public Database() constructor."""
        from api_scout.database import Database

        db = Database(tmp_path / "fresh.db")
        # Migration runner ran in _init_db. schema_migrations should
        # show version 1 applied.
        conn = sqlite3.connect(str(db.db_path))
        try:
            versions = mig.applied_versions(conn)
        finally:
            conn.close()
        assert 1 in versions

    def test_opening_existing_db_is_idempotent(self, tmp_path):
        """Re-opening a Database twice must not re-apply or error out."""
        from api_scout.database import Database

        path = tmp_path / "reopen.db"
        Database(path)
        # Second open would raise if the migration tried to run again
        # with CREATE TABLE (without IF NOT EXISTS) or duplicated a
        # schema_migrations row.
        Database(path)

        conn = sqlite3.connect(str(path))
        try:
            rows = conn.execute(
                "SELECT version FROM schema_migrations"
            ).fetchall()
        finally:
            conn.close()
        assert [r[0] for r in rows] == [1]
