"""Schema migrations runner.

Migrations live in this directory as SQL files named
``NNNN_<name>.<dialect>.sql`` — for example ``0001_initial.sqlite.sql``.

The runner is called from :meth:`api_scout.database.Database._init_db`
on every startup. It is idempotent: migrations that have already been
recorded in ``schema_migrations`` are skipped.

Design notes
------------

* Dialect suffix in the filename lets us ship SQLite-flavoured and
  Postgres-flavoured versions of each migration side-by-side. The
  runner loads only files matching the active dialect.
* Each migration is applied inside its own transaction so a partially
  applied migration never ends up recorded. If the SQL fails, the
  transaction is rolled back and the exception is re-raised.
* The ``schema_migrations`` table itself is created with portable
  SQL — INTEGER primary key, TEXT columns — so it is readable by
  both SQLite and Postgres without needing dialect-specific DDL.
* Applied-at timestamps are written from Python (ISO-8601 UTC strings)
  rather than via a SQL ``now()``-style expression, so the runner has
  zero dialect awareness beyond placeholder style.

The runner never executes arbitrary SQL from user input — migration
files are shipped in the package and discovered via the filesystem.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger(__name__)

# NNNN_name.dialect.sql — e.g. 0001_initial.sqlite.sql
_FILENAME_RE = re.compile(r"^(\d{4})_([a-z0-9_]+)\.([a-z0-9]+)\.sql$")


# Public dialect identifiers. The runner does not care about the value
# beyond filename matching, but callers should use these constants to
# keep things uniform.
DIALECT_SQLITE = "sqlite"
DIALECT_POSTGRES = "postgres"


@dataclass(frozen=True)
class Migration:
    """A single discovered migration file."""

    version: int
    name: str
    dialect: str
    path: Path

    def read_sql(self) -> str:
        return self.path.read_text(encoding="utf-8")


def _default_migrations_dir() -> Path:
    """Return the directory this package lives in (where .sql files are)."""
    return Path(__file__).resolve().parent


def discover(
    dialect: str,
    migrations_dir: Path | None = None,
) -> list[Migration]:
    """Return all migrations for the given dialect, sorted by version.

    Raises :class:`ValueError` if two files claim the same version.
    """
    mdir = migrations_dir or _default_migrations_dir()
    found: dict[int, Migration] = {}
    for path in sorted(mdir.iterdir()):
        if not path.is_file():
            continue
        m = _FILENAME_RE.match(path.name)
        if not m:
            # Skip __init__.py, READMEs, and anything else that isn't a
            # properly-named migration.
            continue
        file_dialect = m.group(3)
        if file_dialect != dialect:
            continue
        version = int(m.group(1))
        name = m.group(2)
        if version in found:
            raise ValueError(
                f"Duplicate migration version {version:04d} for dialect "
                f"{dialect}: {path.name} and {found[version].path.name}"
            )
        found[version] = Migration(
            version=version, name=name, dialect=dialect, path=path
        )
    return [found[v] for v in sorted(found)]


def _ensure_migrations_table(conn: Any, dialect: str) -> None:
    """Create the schema_migrations tracking table if it does not exist.

    Uses portable DDL that both SQLite and Postgres accept.
    """
    # Note: both backends accept this form. applied_at is TEXT to avoid
    # any dialect-specific timestamp handling; we write ISO-8601 strings
    # from Python.
    ddl = (
        "CREATE TABLE IF NOT EXISTS schema_migrations ("
        "    version INTEGER PRIMARY KEY,"
        "    name TEXT NOT NULL,"
        "    applied_at TEXT NOT NULL"
        ")"
    )
    conn.execute(ddl)


def applied_versions(conn: Any) -> set[int]:
    """Return the set of migration versions already recorded."""
    cur = conn.execute("SELECT version FROM schema_migrations")
    rows = cur.fetchall()
    # sqlite3.Row and psycopg tuple-ish rows both support index access.
    return {int(r[0]) for r in rows}


def _utc_iso_now() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def apply_pending(
    conn: Any,
    dialect: str,
    migrations_dir: Path | None = None,
    *,
    placeholder: str = "?",
) -> list[Migration]:
    """Apply every pending migration for ``dialect`` on ``conn``.

    Returns the list of migrations that were applied on this call. An
    empty list means the database is already up to date.

    The connection is expected to be in auto-commit-off / transactional
    mode. Each migration's DDL + the ``schema_migrations`` insert are
    wrapped in a single transaction; on failure the transaction is
    rolled back and the exception is re-raised so the caller sees the
    original error.

    ``placeholder`` is the parameter marker used by the connection's
    DB-API driver — ``?`` for :mod:`sqlite3`, ``%s`` for :mod:`psycopg`.
    """
    _ensure_migrations_table(conn, dialect)
    # Commit the table-creation so a subsequent migration failure
    # doesn't roll away our tracking table on backends where DDL is
    # transactional.
    try:
        conn.commit()
    except Exception:
        # Some callers pass an autocommit connection — be tolerant.
        pass

    already = applied_versions(conn)
    pending = [m for m in discover(dialect, migrations_dir) if m.version not in already]

    applied: list[Migration] = []
    for migration in pending:
        sql = migration.read_sql()
        log.info(
            "applying migration",
            extra={"version": migration.version, "migration_name": migration.name, "dialect": dialect},
        )
        try:
            # Execute the migration body. sqlite3 has .executescript for
            # multi-statement scripts; psycopg's .execute accepts a
            # multi-statement string directly. Detect and dispatch.
            _execute_script(conn, sql)
            conn.execute(
                f"INSERT INTO schema_migrations (version, name, applied_at) "
                f"VALUES ({placeholder}, {placeholder}, {placeholder})",
                (migration.version, migration.name, _utc_iso_now()),
            )
            conn.commit()
        except Exception:
            try:
                conn.rollback()
            except Exception:
                pass
            log.error(
                "migration failed",
                extra={"version": migration.version, "migration_name": migration.name},
            )
            raise
        applied.append(migration)

    return applied


def _execute_script(conn: Any, sql: str) -> None:
    """Execute a possibly multi-statement SQL script.

    SQLite's Python DB-API has :meth:`executescript` specifically for
    this; for psycopg we fall back to the ordinary :meth:`execute`
    which tolerates multi-statement input.
    """
    executescript = getattr(conn, "executescript", None)
    if callable(executescript):
        executescript(sql)
    else:
        conn.execute(sql)
