"""Persistence layer. Supports SQLite and Postgres behind a single API.

Backends
--------

The backend is chosen by a URL passed to :class:`Database`:

* ``sqlite:///path/to/file.db`` — local SQLite (default)
* ``postgresql://user:pass@host:5432/dbname`` — Postgres (requires the
  optional ``psycopg`` dependency: ``pip install 'api-scout[postgres]'``)

For backward compatibility, a bare path or a :class:`pathlib.Path` is
also accepted and treated as SQLite — the old
``Database(Path("api_scout.db"))`` calling convention still works.

The backend URL can also be supplied via the ``API_SCOUT_DATABASE_URL``
environment variable; see :func:`api_scout.db_dialect.database_url_from_env`.

Timestamp policy
----------------

All timestamp values written by this module are Python-side ISO-8601
strings of the form ``YYYY-MM-DDTHH:MM:SS`` (T-separator, no
microseconds, no timezone suffix), stored as ``TEXT`` on both
backends. The SQL layer never calls ``datetime('now')`` or ``NOW()``;
the cutoff for time-window queries is computed in Python and passed as
a bound parameter. This keeps the SQL portable and avoids subtle
cross-backend differences in default-expression behaviour.

Schema
------

The schema is applied by :mod:`api_scout.migrations` on every startup,
which is idempotent. See the migration files in that package for the
source of truth.
"""

from __future__ import annotations

import json
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterator, Optional

from . import migrations as _migrations
from .db_dialect import SQLDialect, dialect_for_url
from .models import (
    APIEndpoint,
    APIStatus,
    AuthMethod,
    DiscoverySource,
    InventoryReport,
    TrafficRecord,
)

DEFAULT_DB_PATH = Path("api_scout.db")


# ── Timestamp helpers ──────────────────────────────────────────────


def _iso_now() -> str:
    """Return the current time as a naive ISO-8601 UTC string.

    Format: ``YYYY-MM-DDTHH:MM:SS`` (T separator, second precision, no
    timezone). Lexicographically sortable; parses back via
    :func:`datetime.fromisoformat` on Python 3.10+ (which requires T).
    """
    return datetime.now(timezone.utc).replace(tzinfo=None, microsecond=0).isoformat()


def _iso_at(dt: datetime) -> str:
    """Serialise an arbitrary datetime to our canonical ISO-8601 form."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt.replace(microsecond=0).isoformat()


def _iso_hours_ago(hours: int) -> str:
    return _iso_at(datetime.now(timezone.utc) - timedelta(hours=hours))


def _iso_minutes_from_now(minutes: int) -> str:
    return _iso_at(datetime.now(timezone.utc) + timedelta(minutes=minutes))


# ── Backend URL normalisation ──────────────────────────────────────


def _normalise_url(db_url: Path | str) -> str:
    """Accept legacy Path / bare path inputs and return a proper URL."""
    if isinstance(db_url, Path):
        return f"sqlite:///{db_url}"
    if isinstance(db_url, str):
        if db_url.startswith(("sqlite:", "postgresql:", "postgres:")):
            return db_url
        # Bare filesystem path.
        return f"sqlite:///{db_url}"
    raise TypeError(
        f"db_url must be a pathlib.Path or str, not {type(db_url).__name__}"
    )


class Database:
    """Application persistence layer.

    Parameters
    ----------
    db_url:
        A DB URL (``sqlite:///...`` or ``postgresql://...``), a
        filesystem path string, or a :class:`~pathlib.Path`. Plain
        paths are treated as SQLite for backward compatibility.
    """

    def __init__(self, db_url: Path | str = DEFAULT_DB_PATH):
        self.url: str = _normalise_url(db_url)
        self.dialect: SQLDialect = dialect_for_url(self.url)
        # ``db_path`` is retained for SQLite backward compat — a number
        # of existing callers read it (tests, CLI). For Postgres URLs
        # it is the URL itself; this is a no-op for callers that only
        # touch it on SQLite.
        if isinstance(db_url, Path):
            self.db_path = db_url
        elif isinstance(db_url, str) and not db_url.startswith(("sqlite:", "postgresql:", "postgres:")):
            self.db_path = Path(db_url)
        else:
            # Best-effort: for sqlite URLs expose the underlying file.
            from .db_dialect import _sqlite_path_from_url  # lazy to avoid circular
            if self.url.startswith("sqlite:"):
                self.db_path = Path(_sqlite_path_from_url(self.url))
            else:
                self.db_path = Path(self.url)
        self._init_db()

    # Short alias for the placeholder marker, used by every query
    # constructor. E.g. f"INSERT INTO t (a, b) VALUES ({self._ph}, {self._ph})".
    @property
    def _ph(self) -> str:
        return self.dialect.ph

    # ── Low-level connection lifecycle ──────────────────────────────

    def _init_db(self):
        """Apply any pending migrations at startup.

        Uses a single dedicated connection for the migration loop so
        the runner can see its own commits; regular calls after this
        open their own connection via :meth:`_connect`.
        """
        conn = self.dialect.connect(self.url)
        try:
            _migrations.apply_pending(
                conn,
                dialect=self.dialect.name,
                placeholder=self.dialect.ph,
            )
        finally:
            conn.close()

    @contextmanager
    def _connect(self) -> Iterator[Any]:
        conn = self.dialect.connect(self.url)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Endpoints ──────────────────────────────────────────────────

    def upsert_endpoint(self, ep: APIEndpoint) -> None:
        ph = self._ph
        d = self.dialect
        # Scalar min/max of two values differs between dialects.
        min_first = d.least_sql("endpoints.first_seen", "excluded.first_seen")
        max_last = d.greatest_sql("endpoints.last_seen", "excluded.last_seen")
        max_declared = d.greatest_sql(
            "endpoints.declared_in_spec", "excluded.declared_in_spec"
        )
        now = _iso_now()
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO endpoints (
                    endpoint_id, method, path_pattern, host, service_name,
                    owning_team, status, auth_methods_seen, consumers,
                    first_seen, last_seen, total_calls, error_count,
                    avg_response_time_ms, declared_in_spec, discovery_sources,
                    created_at, updated_at
                ) VALUES (
                    {ph}, {ph}, {ph}, {ph}, {ph},
                    {ph}, {ph}, {ph}, {ph},
                    {ph}, {ph}, {ph}, {ph},
                    {ph}, {ph}, {ph},
                    {ph}, {ph}
                )
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    status = excluded.status,
                    auth_methods_seen = excluded.auth_methods_seen,
                    consumers = excluded.consumers,
                    first_seen = COALESCE({min_first}, excluded.first_seen),
                    last_seen = COALESCE({max_last}, excluded.last_seen),
                    total_calls = excluded.total_calls,
                    error_count = excluded.error_count,
                    avg_response_time_ms = excluded.avg_response_time_ms,
                    declared_in_spec = {max_declared},
                    discovery_sources = excluded.discovery_sources,
                    updated_at = excluded.updated_at
                """,
                (
                    ep.endpoint_id,
                    ep.method,
                    ep.path_pattern,
                    ep.host,
                    ep.service_name,
                    ep.owning_team,
                    ep.status.value,
                    json.dumps([a.value for a in ep.auth_methods_seen]),
                    json.dumps(ep.consumers),
                    _iso_at(ep.first_seen) if ep.first_seen else None,
                    _iso_at(ep.last_seen) if ep.last_seen else None,
                    ep.total_calls,
                    ep.error_count,
                    ep.avg_response_time_ms,
                    1 if ep.declared_in_spec else 0,
                    json.dumps([s.value for s in ep.discovery_sources]),
                    now,
                    now,
                ),
            )

    def save_endpoints(self, endpoints: list[APIEndpoint]) -> None:
        for ep in endpoints:
            self.upsert_endpoint(ep)

    def get_all_endpoints(self) -> list[APIEndpoint]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints ORDER BY status, method, path_pattern"
            ).fetchall()
        return [self._row_to_endpoint(self.dialect.row_to_dict(r)) for r in rows]

    def get_endpoints_by_status(self, status: APIStatus) -> list[APIEndpoint]:
        ph = self._ph
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM endpoints WHERE status = {ph} "
                f"ORDER BY method, path_pattern",
                (status.value,),
            ).fetchall()
        return [self._row_to_endpoint(self.dialect.row_to_dict(r)) for r in rows]

    def get_endpoint(self, endpoint_id: str) -> Optional[APIEndpoint]:
        ph = self._ph
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM endpoints WHERE endpoint_id = {ph}",
                (endpoint_id,),
            ).fetchone()
        d = self.dialect.row_to_dict(row)
        return self._row_to_endpoint(d) if d else None

    def search_endpoints(self, query: str) -> list[APIEndpoint]:
        ph = self._ph
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM endpoints WHERE path_pattern LIKE {ph} "
                f"OR host LIKE {ph} OR service_name LIKE {ph}",
                (f"%{query}%", f"%{query}%", f"%{query}%"),
            ).fetchall()
        return [self._row_to_endpoint(self.dialect.row_to_dict(r)) for r in rows]

    @staticmethod
    def _row_to_endpoint(row: dict) -> APIEndpoint:
        return APIEndpoint(
            method=row["method"],
            path_pattern=row["path_pattern"],
            host=row["host"],
            service_name=row["service_name"],
            owning_team=row["owning_team"],
            status=APIStatus(row["status"]),
            auth_methods_seen=[AuthMethod(a) for a in json.loads(row["auth_methods_seen"])],
            consumers=json.loads(row["consumers"]),
            first_seen=_parse_iso(row["first_seen"]),
            last_seen=_parse_iso(row["last_seen"]),
            total_calls=row["total_calls"],
            error_count=row["error_count"],
            avg_response_time_ms=row["avg_response_time_ms"],
            declared_in_spec=bool(row["declared_in_spec"]),
            discovery_sources=[DiscoverySource(s) for s in json.loads(row["discovery_sources"])],
        )

    # ── Traffic Log ────────────────────────────────────────────────

    def log_traffic(
        self,
        records: list[TrafficRecord],
        path_patterns: dict[str, str] | None = None,
    ) -> None:
        """Store raw traffic records for historical analysis."""
        ph = self._ph
        now = _iso_now()
        sql = f"""
            INSERT INTO traffic_log (
                timestamp, method, path, path_pattern, status_code,
                source_ip, source_service, auth_method, auth_subject,
                response_time_ms, host, discovery_source, ingested_at
            ) VALUES (
                {ph}, {ph}, {ph}, {ph}, {ph},
                {ph}, {ph}, {ph}, {ph},
                {ph}, {ph}, {ph}, {ph}
            )
        """
        params = [
            (
                _iso_at(r.timestamp),
                r.method,
                r.path,
                path_patterns.get(r.path) if path_patterns else None,
                r.status_code,
                r.source_ip,
                r.source_service,
                r.auth_method.value,
                r.auth_subject,
                r.response_time_ms,
                r.host,
                r.discovery_source.value,
                now,
            )
            for r in records
        ]
        with self._connect() as conn:
            # sqlite3.Connection has executemany on the connection object;
            # psycopg.Connection does not — batch inserts always go via a
            # cursor. Use a cursor for both so the code is portable.
            cur = conn.cursor()
            try:
                cur.executemany(sql, params)
            finally:
                cur.close()

    def get_traffic_stats(self, hours: int = 24) -> dict:
        """Get traffic statistics for the last N hours."""
        ph = self._ph
        cutoff = _iso_hours_ago(hours)
        with self._connect() as conn:
            row = self.dialect.row_to_dict(
                conn.execute(
                    f"""
                    SELECT
                        COUNT(*) AS total_requests,
                        COUNT(DISTINCT path_pattern) AS unique_endpoints,
                        COUNT(DISTINCT source_ip) AS unique_clients,
                        AVG(response_time_ms) AS avg_latency,
                        SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS error_count,
                        SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) AS server_errors
                    FROM traffic_log
                    WHERE timestamp >= {ph}
                    """,
                    (cutoff,),
                ).fetchone()
            ) or {}

            top_endpoints = [
                self.dialect.row_to_dict(r)
                for r in conn.execute(
                    f"""
                    SELECT path_pattern, method, COUNT(*) AS calls,
                           AVG(response_time_ms) AS avg_latency
                    FROM traffic_log
                    WHERE timestamp >= {ph} AND path_pattern IS NOT NULL
                    GROUP BY path_pattern, method
                    ORDER BY calls DESC
                    LIMIT 10
                    """,
                    (cutoff,),
                ).fetchall()
            ]

            top_errors = [
                self.dialect.row_to_dict(r)
                for r in conn.execute(
                    f"""
                    SELECT path_pattern, method, status_code, COUNT(*) AS count
                    FROM traffic_log
                    WHERE timestamp >= {ph} AND status_code >= 400
                        AND path_pattern IS NOT NULL
                    GROUP BY path_pattern, method, status_code
                    ORDER BY count DESC
                    LIMIT 10
                    """,
                    (cutoff,),
                ).fetchall()
            ]

        avg_latency = row.get("avg_latency")
        return {
            "total_requests": row.get("total_requests") or 0,
            "unique_endpoints": row.get("unique_endpoints") or 0,
            "unique_clients": row.get("unique_clients") or 0,
            "avg_latency_ms": round(avg_latency, 2) if avg_latency else 0,
            "error_count": row.get("error_count") or 0,
            "server_errors": row.get("server_errors") or 0,
            "top_endpoints": top_endpoints,
            "top_errors": top_errors,
        }

    def get_traffic_timeline(self, hours: int = 24) -> list[dict]:
        """Get request counts bucketed by time (hour granularity).

        The bucket size is fixed at one hour because both backends
        compute it via :meth:`SQLDialect.hour_bucket_sql`. A
        sub-hour-granularity timeline would need a second dialect
        helper; until there's a caller for it, the parameter is gone.
        """
        ph = self._ph
        cutoff = _iso_hours_ago(hours)
        bucket_expr = self.dialect.hour_bucket_sql("timestamp")
        with self._connect() as conn:
            rows = conn.execute(
                f"""
                SELECT
                    {bucket_expr} AS bucket,
                    COUNT(*) AS requests,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) AS errors,
                    AVG(response_time_ms) AS avg_latency
                FROM traffic_log
                WHERE timestamp >= {ph}
                GROUP BY bucket
                ORDER BY bucket
                """,
                (cutoff,),
            ).fetchall()
        return [self.dialect.row_to_dict(r) for r in rows]

    # ── Scan History ───────────────────────────────────────────────

    def start_scan(self, scan_type: str, targets: str) -> int:
        ph = self._ph
        sql = (
            f"INSERT INTO scan_history (scan_type, targets, started_at) "
            f"VALUES ({ph}, {ph}, {ph})"
        )
        with self._connect() as conn:
            return self.dialect.insert_returning_id(
                conn, sql, (scan_type, targets, _iso_now())
            )

    def complete_scan(
        self,
        scan_id: int,
        endpoints_found: int,
        new_endpoints: int,
        alerts: int,
    ):
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"""
                UPDATE scan_history
                SET completed_at = {ph}, status = 'completed',
                    endpoints_found = {ph}, new_endpoints = {ph},
                    alerts_generated = {ph}
                WHERE id = {ph}
                """,
                (_iso_now(), endpoints_found, new_endpoints, alerts, scan_id),
            )

    def fail_scan(self, scan_id: int, error: str):
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE scan_history SET completed_at = {ph}, status = {ph} "
                f"WHERE id = {ph}",
                (_iso_now(), f"failed: {error}", scan_id),
            )

    def get_scan_history(self, limit: int = 20) -> list[dict]:
        ph = self._ph
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM scan_history ORDER BY started_at DESC LIMIT {ph}",
                (limit,),
            ).fetchall()
        return [self.dialect.row_to_dict(r) for r in rows]

    # ── Alerts ─────────────────────────────────────────────────────

    def save_alerts(
        self,
        alerts: list[str],
        endpoint_map: dict[str, str] | None = None,
    ) -> None:
        ph = self._ph
        now = _iso_now()
        with self._connect() as conn:
            for alert in alerts:
                if "SHADOW" in alert:
                    severity, alert_type = "high", "shadow_api"
                elif "UNAUTHENTICATED" in alert:
                    severity, alert_type = "high", "unauthenticated"
                elif "HIGH ERROR" in alert:
                    severity, alert_type = "medium", "high_error_rate"
                elif "NEW ENDPOINT" in alert:
                    severity, alert_type = "info", "new_endpoint"
                elif "ZOMBIE" in alert:
                    severity, alert_type = "low", "zombie_api"
                else:
                    severity, alert_type = "info", "other"

                conn.execute(
                    f"INSERT INTO alerts (alert_type, severity, message, created_at) "
                    f"VALUES ({ph}, {ph}, {ph}, {ph})",
                    (alert_type, severity, alert, now),
                )

    def get_alerts(
        self, unacknowledged_only: bool = False, limit: int = 100
    ) -> list[dict]:
        ph = self._ph
        with self._connect() as conn:
            query = "SELECT * FROM alerts"
            if unacknowledged_only:
                query += " WHERE acknowledged = 0"
            query += f" ORDER BY created_at DESC LIMIT {ph}"
            rows = conn.execute(query, (limit,)).fetchall()
        return [self.dialect.row_to_dict(r) for r in rows]

    def count_open_alerts_by_severity(self) -> dict[str, int]:
        """Return ``{severity: count}`` for unacknowledged alerts.

        Used by the Prometheus exporter; doing the GROUP BY in SQL keeps
        ``/metrics`` fast even when the alert table is large (the old
        code pulled every row into Python).
        """
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT severity, COUNT(*) AS n FROM alerts "
                "WHERE acknowledged = 0 GROUP BY severity"
            ).fetchall()
        out: dict[str, int] = {}
        for r in rows:
            d = self.dialect.row_to_dict(r) or {}
            sev = d.get("severity")
            if sev:
                out[sev] = int(d.get("n") or 0)
        return out

    def acknowledge_alert(self, alert_id: int) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE alerts SET acknowledged = 1 WHERE id = {ph}",
                (alert_id,),
            )

    # ── Dashboard Stats ────────────────────────────────────────────

    def get_dashboard_summary(self) -> dict:
        with self._connect() as conn:
            status_counts = [
                self.dialect.row_to_dict(r)
                for r in conn.execute(
                    "SELECT status, COUNT(*) AS count FROM endpoints GROUP BY status"
                ).fetchall()
            ]

            total = self.dialect.row_to_dict(
                conn.execute("SELECT COUNT(*) AS c FROM endpoints").fetchone()
            )["c"]

            unauth = self.dialect.row_to_dict(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM endpoints "
                    "WHERE auth_methods_seen LIKE '%none%'"
                ).fetchone()
            )["c"]

            active_alerts = self.dialect.row_to_dict(
                conn.execute(
                    "SELECT COUNT(*) AS c FROM alerts WHERE acknowledged = 0"
                ).fetchone()
            )["c"]

            recent_scans = [
                self.dialect.row_to_dict(r)
                for r in conn.execute(
                    "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 5"
                ).fetchall()
            ]

        status_map = {row["status"]: row["count"] for row in status_counts}

        return {
            "total_endpoints": total,
            "active": status_map.get("active", 0),
            "shadow": status_map.get("shadow", 0),
            "zombie": status_map.get("zombie", 0),
            "undocumented": status_map.get("undocumented", 0),
            "deprecated": status_map.get("deprecated", 0),
            "unauthenticated": unauth,
            "active_alerts": active_alerts,
            "recent_scans": recent_scans,
        }

    # ── App metadata (KV store) ────────────────────────────────────

    def meta_get(self, key: str) -> Optional[str]:
        ph = self._ph
        with self._connect() as conn:
            row = self.dialect.row_to_dict(
                conn.execute(
                    f"SELECT value FROM app_meta WHERE key = {ph}", (key,)
                ).fetchone()
            )
        return row["value"] if row else None

    def meta_set(self, key: str, value: str) -> None:
        ph = self._ph
        now = _iso_now()
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO app_meta (key, value, updated_at)
                VALUES ({ph}, {ph}, {ph})
                ON CONFLICT(key) DO UPDATE SET
                    value = excluded.value,
                    updated_at = excluded.updated_at
                """,
                (key, value, now),
            )

    # ── Users ──────────────────────────────────────────────────────

    def create_user(
        self,
        username: str,
        password_hash: str,
        role: str = "viewer",
        email: Optional[str] = None,
    ) -> int:
        ph = self._ph
        now = _iso_now()
        sql = (
            f"INSERT INTO users (username, password_hash, role, email, created_at) "
            f"VALUES ({ph}, {ph}, {ph}, {ph}, {ph})"
        )
        with self._connect() as conn:
            return self.dialect.insert_returning_id(
                conn, sql, (username, password_hash, role, email, now)
            )

    def get_user_by_username(self, username: str) -> Optional[dict]:
        ph = self._ph
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM users WHERE username = {ph}", (username,)
            ).fetchone()
        return self.dialect.row_to_dict(row)

    def get_user_by_id(self, user_id: int) -> Optional[dict]:
        ph = self._ph
        with self._connect() as conn:
            row = conn.execute(
                f"SELECT * FROM users WHERE id = {ph}", (user_id,)
            ).fetchone()
        return self.dialect.row_to_dict(row)

    def list_users(self) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT id, username, role, email, is_active, created_at, last_login_at "
                "FROM users ORDER BY username"
            ).fetchall()
        return [self.dialect.row_to_dict(r) for r in rows]

    def count_users(self, active_only: bool = False) -> int:
        with self._connect() as conn:
            if active_only:
                row = self.dialect.row_to_dict(
                    conn.execute(
                        "SELECT COUNT(*) AS c FROM users WHERE is_active = 1"
                    ).fetchone()
                )
            else:
                row = self.dialect.row_to_dict(
                    conn.execute("SELECT COUNT(*) AS c FROM users").fetchone()
                )
        return row["c"]

    def update_user_password(self, user_id: int, password_hash: str) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET password_hash = {ph}, failed_login_count = 0, "
                f"locked_until = NULL WHERE id = {ph}",
                (password_hash, user_id),
            )

    def update_user_role(self, user_id: int, role: str) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET role = {ph} WHERE id = {ph}",
                (role, user_id),
            )

    def set_user_active(self, user_id: int, is_active: bool) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET is_active = {ph} WHERE id = {ph}",
                (1 if is_active else 0, user_id),
            )

    def delete_user(self, user_id: int) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM users WHERE id = {ph}", (user_id,)
            )

    def record_login_success(self, user_id: int) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET last_login_at = {ph}, failed_login_count = 0, "
                f"locked_until = NULL WHERE id = {ph}",
                (_iso_now(), user_id),
            )

    def record_login_failure(
        self,
        user_id: int,
        lockout_threshold: int = 5,
        lockout_minutes: int = 15,
    ) -> None:
        """Increment failed login counter; lock account after threshold."""
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"UPDATE users SET failed_login_count = failed_login_count + 1 "
                f"WHERE id = {ph}",
                (user_id,),
            )
            row = self.dialect.row_to_dict(
                conn.execute(
                    f"SELECT failed_login_count FROM users WHERE id = {ph}",
                    (user_id,),
                ).fetchone()
            )
            if row and row["failed_login_count"] >= lockout_threshold:
                conn.execute(
                    f"UPDATE users SET locked_until = {ph} WHERE id = {ph}",
                    (_iso_minutes_from_now(lockout_minutes), user_id),
                )

    # ── Sessions ───────────────────────────────────────────────────

    def create_session(
        self,
        session_id: str,
        user_id: int,
        expires_at: datetime,
        user_agent: Optional[str] = None,
        ip_address: Optional[str] = None,
    ) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO sessions
                    (id, user_id, created_at, expires_at, user_agent, ip_address)
                VALUES ({ph}, {ph}, {ph}, {ph}, {ph}, {ph})
                """,
                (
                    session_id,
                    user_id,
                    _iso_now(),
                    _iso_at(expires_at),
                    user_agent,
                    ip_address,
                ),
            )

    def get_session(self, session_id: str) -> Optional[dict]:
        ph = self._ph
        now = _iso_now()
        with self._connect() as conn:
            row = conn.execute(
                f"""
                SELECT s.*, u.username, u.role, u.is_active
                FROM sessions s JOIN users u ON s.user_id = u.id
                WHERE s.id = {ph} AND s.expires_at > {ph} AND u.is_active = 1
                """,
                (session_id, now),
            ).fetchone()
        return self.dialect.row_to_dict(row)

    def delete_session(self, session_id: str) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM sessions WHERE id = {ph}", (session_id,)
            )

    def delete_sessions_for_user(self, user_id: int) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"DELETE FROM sessions WHERE user_id = {ph}", (user_id,)
            )

    def purge_expired_sessions(self) -> int:
        ph = self._ph
        now = _iso_now()
        with self._connect() as conn:
            cur = conn.execute(
                f"DELETE FROM sessions WHERE expires_at <= {ph}", (now,)
            )
            return cur.rowcount

    # ── Audit log ──────────────────────────────────────────────────

    def write_audit(
        self,
        action: str,
        *,
        user_id: Optional[int] = None,
        username: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        method: Optional[str] = None,
        path: Optional[str] = None,
        ip_address: Optional[str] = None,
        user_agent: Optional[str] = None,
        status_code: Optional[int] = None,
        details: Optional[dict] = None,
    ) -> None:
        ph = self._ph
        with self._connect() as conn:
            conn.execute(
                f"""
                INSERT INTO audit_log (
                    timestamp, user_id, username, action, resource_type, resource_id,
                    method, path, ip_address, user_agent, status_code, details
                ) VALUES (
                    {ph}, {ph}, {ph}, {ph}, {ph}, {ph},
                    {ph}, {ph}, {ph}, {ph}, {ph}, {ph}
                )
                """,
                (
                    _iso_now(),
                    user_id,
                    username,
                    action,
                    resource_type,
                    resource_id,
                    method,
                    path,
                    ip_address,
                    user_agent,
                    status_code,
                    json.dumps(details) if details else None,
                ),
            )

    def get_audit_log(
        self,
        limit: int = 200,
        action: Optional[str] = None,
        username: Optional[str] = None,
    ) -> list[dict]:
        ph = self._ph
        clauses = []
        params: list = []
        if action:
            clauses.append(f"action = {ph}")
            params.append(action)
        if username:
            clauses.append(f"username = {ph}")
            params.append(username)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        params.append(limit)
        with self._connect() as conn:
            rows = conn.execute(
                f"SELECT * FROM audit_log {where} ORDER BY timestamp DESC LIMIT {ph}",
                tuple(params),
            ).fetchall()
        return [self.dialect.row_to_dict(r) for r in rows]


# ── Helpers ──────────────────────────────────────────────────────────


def _parse_iso(s: Optional[str]) -> Optional[datetime]:
    """Parse our canonical ISO-8601 form back to a naive datetime.

    Accepts both T-separator and space-separator variants so data
    written by older versions (which relied on SQLite's
    ``datetime('now')`` output, space-separated) still round-trips.
    """
    if s is None:
        return None
    if isinstance(s, datetime):
        return s
    # Normalise legacy space-separator to T so fromisoformat works on 3.10.
    return datetime.fromisoformat(s.replace(" ", "T", 1))
