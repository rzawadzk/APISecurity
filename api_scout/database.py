"""SQLite persistence layer for API inventory."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from datetime import datetime
from pathlib import Path
from typing import Iterator, Optional

from .models import (
    APIEndpoint,
    APIStatus,
    AuthMethod,
    DiscoverySource,
    InventoryReport,
    TrafficRecord,
)

DEFAULT_DB_PATH = Path("api_scout.db")

SCHEMA = """
CREATE TABLE IF NOT EXISTS endpoints (
    endpoint_id TEXT PRIMARY KEY,
    method TEXT NOT NULL,
    path_pattern TEXT NOT NULL,
    host TEXT,
    service_name TEXT,
    owning_team TEXT,
    status TEXT NOT NULL DEFAULT 'undocumented',
    auth_methods_seen TEXT NOT NULL DEFAULT '[]',
    consumers TEXT NOT NULL DEFAULT '[]',
    first_seen TEXT,
    last_seen TEXT,
    total_calls INTEGER NOT NULL DEFAULT 0,
    error_count INTEGER NOT NULL DEFAULT 0,
    avg_response_time_ms REAL,
    declared_in_spec INTEGER NOT NULL DEFAULT 0,
    discovery_sources TEXT NOT NULL DEFAULT '[]',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS traffic_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL,
    method TEXT NOT NULL,
    path TEXT NOT NULL,
    path_pattern TEXT,
    status_code INTEGER NOT NULL,
    source_ip TEXT,
    source_service TEXT,
    auth_method TEXT,
    auth_subject TEXT,
    response_time_ms REAL,
    host TEXT,
    discovery_source TEXT,
    ingested_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE TABLE IF NOT EXISTS scan_history (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_type TEXT NOT NULL,
    targets TEXT,
    endpoints_found INTEGER NOT NULL DEFAULT 0,
    new_endpoints INTEGER NOT NULL DEFAULT 0,
    alerts_generated INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL,
    completed_at TEXT,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id TEXT,
    alert_type TEXT NOT NULL,
    severity TEXT NOT NULL,
    message TEXT NOT NULL,
    acknowledged INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    FOREIGN KEY (endpoint_id) REFERENCES endpoints(endpoint_id)
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_path ON traffic_log(path_pattern);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
"""


class Database:
    """SQLite database for persistent API inventory storage."""

    def __init__(self, db_path: Path | str = DEFAULT_DB_PATH):
        self.db_path = Path(db_path)
        self._init_db()

    def _init_db(self):
        with self._connect() as conn:
            conn.executescript(SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ── Endpoints ──

    def upsert_endpoint(self, ep: APIEndpoint) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO endpoints (
                    endpoint_id, method, path_pattern, host, service_name,
                    owning_team, status, auth_methods_seen, consumers,
                    first_seen, last_seen, total_calls, error_count,
                    avg_response_time_ms, declared_in_spec, discovery_sources
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(endpoint_id) DO UPDATE SET
                    status = excluded.status,
                    auth_methods_seen = excluded.auth_methods_seen,
                    consumers = excluded.consumers,
                    first_seen = COALESCE(
                        MIN(endpoints.first_seen, excluded.first_seen),
                        excluded.first_seen
                    ),
                    last_seen = COALESCE(
                        MAX(endpoints.last_seen, excluded.last_seen),
                        excluded.last_seen
                    ),
                    total_calls = excluded.total_calls,
                    error_count = excluded.error_count,
                    avg_response_time_ms = excluded.avg_response_time_ms,
                    declared_in_spec = MAX(endpoints.declared_in_spec, excluded.declared_in_spec),
                    discovery_sources = excluded.discovery_sources,
                    updated_at = datetime('now')
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
                    ep.first_seen.isoformat() if ep.first_seen else None,
                    ep.last_seen.isoformat() if ep.last_seen else None,
                    ep.total_calls,
                    ep.error_count,
                    ep.avg_response_time_ms,
                    1 if ep.declared_in_spec else 0,
                    json.dumps([s.value for s in ep.discovery_sources]),
                ),
            )

    def save_endpoints(self, endpoints: list[APIEndpoint]) -> None:
        for ep in endpoints:
            self.upsert_endpoint(ep)

    def get_all_endpoints(self) -> list[APIEndpoint]:
        with self._connect() as conn:
            rows = conn.execute("SELECT * FROM endpoints ORDER BY status, method, path_pattern").fetchall()
        return [self._row_to_endpoint(r) for r in rows]

    def get_endpoints_by_status(self, status: APIStatus) -> list[APIEndpoint]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE status = ? ORDER BY method, path_pattern",
                (status.value,),
            ).fetchall()
        return [self._row_to_endpoint(r) for r in rows]

    def get_endpoint(self, endpoint_id: str) -> Optional[APIEndpoint]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM endpoints WHERE endpoint_id = ?", (endpoint_id,)
            ).fetchone()
        return self._row_to_endpoint(row) if row else None

    def search_endpoints(self, query: str) -> list[APIEndpoint]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM endpoints WHERE path_pattern LIKE ? OR host LIKE ? OR service_name LIKE ?",
                (f"%{query}%", f"%{query}%", f"%{query}%"),
            ).fetchall()
        return [self._row_to_endpoint(r) for r in rows]

    @staticmethod
    def _row_to_endpoint(row: sqlite3.Row) -> APIEndpoint:
        return APIEndpoint(
            method=row["method"],
            path_pattern=row["path_pattern"],
            host=row["host"],
            service_name=row["service_name"],
            owning_team=row["owning_team"],
            status=APIStatus(row["status"]),
            auth_methods_seen=[AuthMethod(a) for a in json.loads(row["auth_methods_seen"])],
            consumers=json.loads(row["consumers"]),
            first_seen=datetime.fromisoformat(row["first_seen"]) if row["first_seen"] else None,
            last_seen=datetime.fromisoformat(row["last_seen"]) if row["last_seen"] else None,
            total_calls=row["total_calls"],
            error_count=row["error_count"],
            avg_response_time_ms=row["avg_response_time_ms"],
            declared_in_spec=bool(row["declared_in_spec"]),
            discovery_sources=[DiscoverySource(s) for s in json.loads(row["discovery_sources"])],
        )

    # ── Traffic Log ──

    def log_traffic(self, records: list[TrafficRecord], path_patterns: dict[str, str] | None = None) -> None:
        """Store raw traffic records for historical analysis."""
        with self._connect() as conn:
            conn.executemany(
                """
                INSERT INTO traffic_log (
                    timestamp, method, path, path_pattern, status_code,
                    source_ip, source_service, auth_method, auth_subject,
                    response_time_ms, host, discovery_source
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                [
                    (
                        r.timestamp.isoformat(),
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
                    )
                    for r in records
                ],
            )

    def get_traffic_stats(self, hours: int = 24) -> dict:
        """Get traffic statistics for the last N hours."""
        with self._connect() as conn:
            cutoff = datetime.now().isoformat()
            row = conn.execute(
                """
                SELECT
                    COUNT(*) as total_requests,
                    COUNT(DISTINCT path_pattern) as unique_endpoints,
                    COUNT(DISTINCT source_ip) as unique_clients,
                    AVG(response_time_ms) as avg_latency,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as error_count,
                    SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as server_errors
                FROM traffic_log
                WHERE timestamp >= datetime('now', ?)
                """,
                (f"-{hours} hours",),
            ).fetchone()

            top_endpoints = conn.execute(
                """
                SELECT path_pattern, method, COUNT(*) as calls,
                       AVG(response_time_ms) as avg_latency
                FROM traffic_log
                WHERE timestamp >= datetime('now', ?) AND path_pattern IS NOT NULL
                GROUP BY path_pattern, method
                ORDER BY calls DESC
                LIMIT 10
                """,
                (f"-{hours} hours",),
            ).fetchall()

            top_errors = conn.execute(
                """
                SELECT path_pattern, method, status_code, COUNT(*) as count
                FROM traffic_log
                WHERE timestamp >= datetime('now', ?) AND status_code >= 400
                    AND path_pattern IS NOT NULL
                GROUP BY path_pattern, method, status_code
                ORDER BY count DESC
                LIMIT 10
                """,
                (f"-{hours} hours",),
            ).fetchall()

        return {
            "total_requests": row["total_requests"],
            "unique_endpoints": row["unique_endpoints"],
            "unique_clients": row["unique_clients"],
            "avg_latency_ms": round(row["avg_latency"], 2) if row["avg_latency"] else 0,
            "error_count": row["error_count"],
            "server_errors": row["server_errors"],
            "top_endpoints": [dict(r) for r in top_endpoints],
            "top_errors": [dict(r) for r in top_errors],
        }

    def get_traffic_timeline(self, hours: int = 24, bucket_minutes: int = 60) -> list[dict]:
        """Get request counts bucketed by time."""
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT
                    strftime('%Y-%m-%dT%H:00:00', timestamp) as bucket,
                    COUNT(*) as requests,
                    SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
                    AVG(response_time_ms) as avg_latency
                FROM traffic_log
                WHERE timestamp >= datetime('now', ?)
                GROUP BY bucket
                ORDER BY bucket
                """,
                (f"-{hours} hours",),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Scan History ──

    def start_scan(self, scan_type: str, targets: str) -> int:
        with self._connect() as conn:
            cursor = conn.execute(
                "INSERT INTO scan_history (scan_type, targets, started_at) VALUES (?, ?, datetime('now'))",
                (scan_type, targets),
            )
            return cursor.lastrowid

    def complete_scan(self, scan_id: int, endpoints_found: int, new_endpoints: int, alerts: int):
        with self._connect() as conn:
            conn.execute(
                """
                UPDATE scan_history
                SET completed_at = datetime('now'), status = 'completed',
                    endpoints_found = ?, new_endpoints = ?, alerts_generated = ?
                WHERE id = ?
                """,
                (endpoints_found, new_endpoints, alerts, scan_id),
            )

    def fail_scan(self, scan_id: int, error: str):
        with self._connect() as conn:
            conn.execute(
                "UPDATE scan_history SET completed_at = datetime('now'), status = ? WHERE id = ?",
                (f"failed: {error}", scan_id),
            )

    def get_scan_history(self, limit: int = 20) -> list[dict]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT ?",
                (limit,),
            ).fetchall()
        return [dict(r) for r in rows]

    # ── Alerts ──

    def save_alerts(self, alerts: list[str], endpoint_map: dict[str, str] | None = None) -> None:
        with self._connect() as conn:
            for alert in alerts:
                # Determine severity and type from alert prefix
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
                    "INSERT INTO alerts (alert_type, severity, message) VALUES (?, ?, ?)",
                    (alert_type, severity, alert),
                )

    def get_alerts(self, unacknowledged_only: bool = False, limit: int = 100) -> list[dict]:
        with self._connect() as conn:
            query = "SELECT * FROM alerts"
            if unacknowledged_only:
                query += " WHERE acknowledged = 0"
            query += " ORDER BY created_at DESC LIMIT ?"
            rows = conn.execute(query, (limit,)).fetchall()
        return [dict(r) for r in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._connect() as conn:
            conn.execute("UPDATE alerts SET acknowledged = 1 WHERE id = ?", (alert_id,))

    # ── Dashboard Stats ──

    def get_dashboard_summary(self) -> dict:
        with self._connect() as conn:
            status_counts = conn.execute(
                "SELECT status, COUNT(*) as count FROM endpoints GROUP BY status"
            ).fetchall()

            total = conn.execute("SELECT COUNT(*) as c FROM endpoints").fetchone()["c"]

            unauth = conn.execute(
                "SELECT COUNT(*) as c FROM endpoints WHERE auth_methods_seen LIKE '%none%'"
            ).fetchone()["c"]

            active_alerts = conn.execute(
                "SELECT COUNT(*) as c FROM alerts WHERE acknowledged = 0"
            ).fetchone()["c"]

            recent_scans = conn.execute(
                "SELECT * FROM scan_history ORDER BY started_at DESC LIMIT 5"
            ).fetchall()

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
            "recent_scans": [dict(r) for r in recent_scans],
        }
