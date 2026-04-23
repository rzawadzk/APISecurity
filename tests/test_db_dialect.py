"""Unit tests for the SQL dialect abstraction.

These tests exercise the dialect in isolation — no database server
required. End-to-end Postgres tests live in ``test_postgres_backend.py``
and are skipped unless ``API_SCOUT_TEST_POSTGRES_URL`` is set.
"""

from __future__ import annotations

import pytest

from api_scout import db_dialect as dd


class TestDialectForUrl:
    def test_sqlite_url(self):
        d = dd.dialect_for_url("sqlite:///tmp/foo.db")
        assert isinstance(d, dd.SQLiteDialect)
        assert d.name == dd.SQLITE
        assert d.ph == "?"

    def test_sqlite_memory(self):
        d = dd.dialect_for_url("sqlite::memory:")
        assert isinstance(d, dd.SQLiteDialect)
        assert d.path == ":memory:"

    def test_sqlite_memory_triple_slash(self):
        d = dd.dialect_for_url("sqlite:///:memory:")
        assert isinstance(d, dd.SQLiteDialect)
        assert d.path == ":memory:"

    def test_bare_path_defaults_to_sqlite(self):
        d = dd.dialect_for_url("foo.db")
        assert isinstance(d, dd.SQLiteDialect)
        assert d.path == "foo.db"

    def test_postgres_url(self):
        d = dd.dialect_for_url("postgresql://u:p@host:5432/db")
        assert isinstance(d, dd.PostgresDialect)
        assert d.name == dd.POSTGRES
        assert d.ph == "%s"

    def test_postgres_short_scheme(self):
        d = dd.dialect_for_url("postgres://u:p@host/db")
        assert isinstance(d, dd.PostgresDialect)


class TestSqliteFragments:
    def setup_method(self):
        self.d = dd.SQLiteDialect(path=":memory:")

    def test_least(self):
        assert self.d.least_sql("a", "b") == "MIN(a, b)"

    def test_greatest(self):
        assert self.d.greatest_sql("a", "b") == "MAX(a, b)"

    def test_hour_bucket(self):
        assert self.d.hour_bucket_sql("timestamp") == "strftime('%Y-%m-%dT%H:00:00', timestamp)"


class TestPostgresFragments:
    def setup_method(self):
        self.d = dd.PostgresDialect()

    def test_least(self):
        assert self.d.least_sql("a", "b") == "LEAST(a, b)"

    def test_greatest(self):
        assert self.d.greatest_sql("a", "b") == "GREATEST(a, b)"

    def test_hour_bucket_quotes_T_literal(self):
        """The hour-bucket expression must emit a T as a literal, not
        an identifier. In Postgres to_char, double-quoted runs in the
        format string pass through as literal characters."""
        out = self.d.hour_bucket_sql("timestamp")
        assert 'to_char' in out
        # The T between date and time must be quoted so to_char treats
        # it as a literal (unquoted T has no meaning as a format code,
        # so this isn't strictly required, but being explicit is safer).
        assert '"T"' in out


class TestEnvReader:
    def test_default_returned_when_unset(self, monkeypatch):
        monkeypatch.delenv("API_SCOUT_DATABASE_URL", raising=False)
        assert dd.database_url_from_env(default="sqlite:///x.db") == "sqlite:///x.db"

    def test_env_wins_over_default(self, monkeypatch):
        monkeypatch.setenv("API_SCOUT_DATABASE_URL", "postgresql://pghost/db")
        assert dd.database_url_from_env(default="sqlite:///x.db") == "postgresql://pghost/db"

    def test_unset_no_default_returns_none(self, monkeypatch):
        monkeypatch.delenv("API_SCOUT_DATABASE_URL", raising=False)
        assert dd.database_url_from_env() is None


class TestIntegrityErrorType:
    def test_sqlite_returns_sqlite3_integrityerror(self):
        import sqlite3
        assert dd.SQLiteDialect(":memory:").integrity_error_type() is sqlite3.IntegrityError

    def test_postgres_returns_psycopg_integrityerror(self):
        # psycopg is installed for the test env but only optional at
        # runtime. Import it here (same as the dialect) to compare.
        psycopg = pytest.importorskip("psycopg")
        assert dd.PostgresDialect().integrity_error_type() is psycopg.errors.IntegrityError


class TestPostgresInsertReturning:
    """The Postgres dialect must append RETURNING id to plain INSERTs
    when the caller uses insert_returning_id. Verified with a stub
    connection that records the executed SQL."""

    def test_appends_returning_id(self):
        d = dd.PostgresDialect()

        class StubCursor:
            def fetchone(self):
                return {"id": 42}

        class StubConn:
            def __init__(self):
                self.last_sql = None
                self.last_params = None

            def execute(self, sql, params):
                self.last_sql = sql
                self.last_params = params
                return StubCursor()

        conn = StubConn()
        got = d.insert_returning_id(conn, "INSERT INTO t (a) VALUES (%s)", ("x",))
        assert got == 42
        assert conn.last_sql.endswith("RETURNING id")
        assert conn.last_params == ("x",)

    def test_does_not_double_append_if_already_present(self):
        d = dd.PostgresDialect()

        class StubCursor:
            def fetchone(self):
                return (7,)

        class StubConn:
            def __init__(self):
                self.last_sql = None

            def execute(self, sql, params):
                self.last_sql = sql
                return StubCursor()

        conn = StubConn()
        d.insert_returning_id(
            conn, "INSERT INTO t (a) VALUES (%s) RETURNING id", ("x",)
        )
        # Should not have "RETURNING id RETURNING id".
        assert conn.last_sql.count("RETURNING") == 1
