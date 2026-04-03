"""Nginx access log parser."""

from __future__ import annotations

import re
from datetime import datetime

from ..models import AuthMethod, DiscoverySource, TrafficRecord
from .base import BaseLogParser

# Default combined log format:
# $remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent"
# Extended format may include $upstream_response_time and $http_authorization
NGINX_COMBINED_RE = re.compile(
    r'(?P<remote_addr>\S+)\s+-\s+(?P<remote_user>\S+)\s+'
    r'\[(?P<time>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<path>\S+)\s+\S+"\s+'
    r'(?P<status>\d{3})\s+(?P<bytes>\d+)\s+'
    r'"(?P<referer>[^"]*)"\s+"(?P<user_agent>[^"]*)"'
    r'(?:\s+(?P<response_time>[\d.]+))?'
    r'(?:\s+"(?P<auth_header>[^"]*)")?'
)


class NginxLogParser(BaseLogParser):
    """Parser for Nginx access logs (combined format)."""

    def parse_line(self, line: str) -> TrafficRecord | None:
        match = NGINX_COMBINED_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()
        method = groups["method"]
        path = groups["path"]

        # Skip non-API paths
        if path in ("/favicon.ico", "/robots.txt", "/health", "/healthz"):
            return None

        try:
            timestamp = datetime.strptime(groups["time"], "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            timestamp = datetime.now()

        status_code = int(groups["status"])
        auth_header = groups.get("auth_header") or ""
        auth_method = self.detect_auth_method(auth_header) if auth_header else AuthMethod.UNKNOWN

        response_time = None
        if groups.get("response_time"):
            try:
                response_time = float(groups["response_time"]) * 1000  # s -> ms
            except ValueError:
                pass

        return TrafficRecord(
            timestamp=timestamp,
            method=method,
            path=path,
            status_code=status_code,
            source_ip=groups["remote_addr"],
            auth_method=auth_method,
            response_time_ms=response_time,
            discovery_source=DiscoverySource.LOG_NGINX,
        )
