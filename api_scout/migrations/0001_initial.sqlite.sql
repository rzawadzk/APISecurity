-- Migration 0001: initial schema (SQLite)
--
-- Everything here is written with CREATE TABLE IF NOT EXISTS so that
-- re-running the migration on an existing database is a no-op. Prior
-- deployments of API Scout created these tables directly from an
-- inline schema string; the migrations tracking table records this as
-- version 1 regardless of which path created the tables.

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

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role TEXT NOT NULL DEFAULT 'viewer',
    email TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_login_at TEXT,
    failed_login_count INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    expires_at TEXT NOT NULL,
    user_agent TEXT,
    ip_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp TEXT NOT NULL DEFAULT (datetime('now')),
    user_id INTEGER,
    username TEXT,
    action TEXT NOT NULL,
    resource_type TEXT,
    resource_id TEXT,
    method TEXT,
    path TEXT,
    ip_address TEXT,
    user_agent TEXT,
    status_code INTEGER,
    details TEXT
);

CREATE TABLE IF NOT EXISTS app_meta (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL,
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
);

CREATE INDEX IF NOT EXISTS idx_endpoints_status ON endpoints(status);
CREATE INDEX IF NOT EXISTS idx_endpoints_last_seen ON endpoints(last_seen);
CREATE INDEX IF NOT EXISTS idx_traffic_timestamp ON traffic_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_traffic_path ON traffic_log(path_pattern);
CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
CREATE INDEX IF NOT EXISTS idx_alerts_ack ON alerts(acknowledged);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_user ON audit_log(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
