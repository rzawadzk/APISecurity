"""Structured JSON logging + Prometheus metrics + health checks.

Exports:
  - configure_logging(level): root JSON logger
  - get_logger(name): child logger with structured fields
  - PrometheusMiddleware: per-request HTTP metrics
  - metrics_endpoint(): FastAPI handler returning text/plain Prometheus exposition
  - health_check(db): liveness/readiness checks
"""
from __future__ import annotations

import json
import logging
import sys
import time
from datetime import datetime
from typing import Optional

from fastapi import Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Gauge,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware

from .database import Database


# ── Structured JSON logging ──

class JsonFormatter(logging.Formatter):
    """Emit one JSON object per log record."""

    # Standard LogRecord attributes — everything else is treated as "extra".
    _STD = {
        "args", "msg", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno",
        "funcName", "created", "msecs", "relativeCreated", "thread",
        "threadName", "processName", "process", "name", "message",
        "taskName",
    }

    def format(self, record: logging.LogRecord) -> str:
        # Build the UTC timestamp directly — logging.formatTime's strftime
        # doesn't expand %f (microseconds).
        dt = datetime.utcfromtimestamp(record.created)
        payload = {
            "ts": dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z",
            "level": record.levelname.lower(),
            "logger": record.name,
            "msg": record.getMessage(),
        }
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        # Any attribute that isn't a standard LogRecord field is treated as
        # a structured "extra" (e.g. log.info("msg", extra={"foo": "bar"})).
        for key, value in record.__dict__.items():
            if key in self._STD or key.startswith("_"):
                continue
            try:
                json.dumps(value)
                payload[key] = value
            except (TypeError, ValueError):
                payload[key] = repr(value)
        return json.dumps(payload, default=str)


def configure_logging(level: str = "INFO") -> None:
    """Replace root handlers with a single JSON-formatted stdout handler."""
    root = logging.getLogger()
    root.setLevel(level.upper())
    for h in list(root.handlers):
        root.removeHandler(h)
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root.addHandler(handler)
    # Quiet noisy libraries
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)


def get_logger(name: str) -> logging.Logger:
    """Return a standard logger. Use with `log.info('msg', extra={...})` for structured fields."""
    return logging.getLogger(name)


# ── Prometheus metrics ──

HTTP_REQUESTS = Counter(
    "api_scout_http_requests_total",
    "Total HTTP requests received by the dashboard",
    ["method", "path_template", "status"],
)
HTTP_LATENCY = Histogram(
    "api_scout_http_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "path_template"],
    buckets=(0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0),
)
LOGIN_ATTEMPTS = Counter(
    "api_scout_login_attempts_total",
    "Login attempts",
    ["result"],  # success | failure | locked
)
INVENTORY_ENDPOINTS = Gauge(
    "api_scout_inventory_endpoints",
    "Number of endpoints in inventory by status",
    ["status"],
)
ALERTS_OPEN = Gauge(
    "api_scout_alerts_open",
    "Open (unacknowledged) alerts by severity",
    ["severity"],
)


def update_inventory_gauges(db: Database) -> None:
    """Refresh gauges from the DB. Called by /metrics on scrape."""
    summary = db.get_dashboard_summary()
    for status_name in ("active", "shadow", "zombie", "undocumented", "deprecated"):
        INVENTORY_ENDPOINTS.labels(status=status_name).set(summary.get(status_name, 0))
    # Severity breakdown for open alerts
    for alert in db.get_alerts(unacknowledged_only=True, limit=10000):
        pass  # scan to avoid unused warning
    # Counts by severity
    severity_counts: dict[str, int] = {}
    for alert in db.get_alerts(unacknowledged_only=True, limit=10000):
        severity_counts[alert["severity"]] = severity_counts.get(alert["severity"], 0) + 1
    # Reset and set
    for sev in ("high", "medium", "low", "info"):
        ALERTS_OPEN.labels(severity=sev).set(severity_counts.get(sev, 0))


class PrometheusMiddleware(BaseHTTPMiddleware):
    """Record per-request metrics. Uses route template so cardinality stays bounded."""

    async def dispatch(self, request: Request, call_next):
        start = time.perf_counter()
        response = await call_next(request)
        elapsed = time.perf_counter() - start
        # Use the matched route path (template) — never the raw URL with IDs
        route = request.scope.get("route")
        path_template = getattr(route, "path", "unmatched") if route else "unmatched"
        HTTP_REQUESTS.labels(
            method=request.method,
            path_template=path_template,
            status=str(response.status_code),
        ).inc()
        HTTP_LATENCY.labels(
            method=request.method,
            path_template=path_template,
        ).observe(elapsed)
        return response


def metrics_endpoint(db: Optional[Database] = None) -> Response:
    if db is not None:
        try:
            update_inventory_gauges(db)
        except Exception as exc:
            get_logger(__name__).warning("metrics_gauge_update_failed", extra={"error": str(exc)})
    return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)


# ── Health checks ──

def liveness() -> dict:
    return {"status": "ok"}


def readiness(db: Database) -> tuple[dict, int]:
    """Check DB is reachable. Returns (payload, status_code)."""
    try:
        db.count_users()
        return {"status": "ready", "db": "ok"}, 200
    except Exception as exc:  # pragma: no cover
        return {"status": "not_ready", "db": "error", "error": str(exc)}, 503
