"""Generic log parser — handles common patterns and JSON logs."""

from __future__ import annotations

import json
import re
from datetime import datetime

from ..models import AuthMethod, DiscoverySource, TrafficRecord
from .base import BaseLogParser

# Matches lines like: 2024-01-15T10:30:00Z GET /api/users 200 45ms
SIMPLE_RE = re.compile(
    r'(?P<timestamp>\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}\S*)\s+'
    r'(?P<method>GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+'
    r'(?P<path>/\S+)\s+'
    r'(?P<status>\d{3})'
    r'(?:\s+(?P<response_time>[\d.]+)\s*(?:ms|s)?)?'
)

# Common JSON log keys for HTTP method/path/status
METHOD_KEYS = ("method", "httpMethod", "http_method", "request_method", "verb")
PATH_KEYS = ("path", "url", "uri", "request_uri", "resourcePath", "request_path")
STATUS_KEYS = ("status", "status_code", "statusCode", "response_code", "http_status")


class GenericLogParser(BaseLogParser):
    """Flexible parser that handles JSON and common text log formats."""

    def parse_line(self, line: str) -> TrafficRecord | None:
        # Try JSON first
        if line.lstrip().startswith("{"):
            return self._parse_json(line)
        return self._parse_text(line)

    def _parse_json(self, line: str) -> TrafficRecord | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        method = self._find_key(data, METHOD_KEYS)
        path = self._find_key(data, PATH_KEYS)
        status = self._find_key(data, STATUS_KEYS)

        if not method or not path:
            return None

        # Parse timestamp from various keys
        ts_raw = self._find_key(data, ("timestamp", "time", "@timestamp", "date", "requestTime"))
        timestamp = self._parse_timestamp(ts_raw) if ts_raw else datetime.now()

        status_code = int(status) if status else 0

        # Response time
        rt_raw = self._find_key(data, ("response_time", "responseTime", "latency", "duration", "responseLatency"))
        response_time = None
        if rt_raw:
            try:
                response_time = float(rt_raw)
            except (ValueError, TypeError):
                pass

        source_ip = self._find_key(data, ("ip", "client_ip", "remote_addr", "source_ip", "clientIp"))
        host = self._find_key(data, ("host", "hostname", "domainName", "server_name"))
        auth_header = self._find_key(data, ("authorization", "auth", "auth_type")) or ""

        return TrafficRecord(
            timestamp=timestamp,
            method=method.upper(),
            path=path.split("?")[0],  # Strip query params
            status_code=status_code,
            source_ip=source_ip,
            auth_method=self.detect_auth_method(auth_header),
            response_time_ms=response_time,
            host=host,
            discovery_source=DiscoverySource.LOG_GENERIC,
        )

    def _parse_text(self, line: str) -> TrafficRecord | None:
        match = SIMPLE_RE.search(line)
        if not match:
            return None

        groups = match.groupdict()
        timestamp = self._parse_timestamp(groups["timestamp"])

        response_time = None
        if groups.get("response_time"):
            try:
                val = float(groups["response_time"])
                # If line says "s" not "ms", convert
                if "s" in line[match.end():match.end() + 5] and "ms" not in line[match.end():match.end() + 5]:
                    val *= 1000
                response_time = val
            except ValueError:
                pass

        return TrafficRecord(
            timestamp=timestamp,
            method=groups["method"],
            path=groups["path"].split("?")[0],
            status_code=int(groups["status"]),
            response_time_ms=response_time,
            discovery_source=DiscoverySource.LOG_GENERIC,
        )

    @staticmethod
    def _find_key(data: dict, keys: tuple[str, ...]) -> str | None:
        for key in keys:
            if key in data and data[key] is not None:
                return str(data[key])
        return None

    @staticmethod
    def _parse_timestamp(raw: str) -> datetime:
        for fmt in (
            "%Y-%m-%dT%H:%M:%S%z",
            "%Y-%m-%dT%H:%M:%SZ",
            "%Y-%m-%dT%H:%M:%S.%f%z",
            "%Y-%m-%dT%H:%M:%S.%fZ",
            "%Y-%m-%d %H:%M:%S",
            "%d/%b/%Y:%H:%M:%S %z",
        ):
            try:
                return datetime.strptime(raw, fmt)
            except ValueError:
                continue
        return datetime.now()
