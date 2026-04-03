"""AWS API Gateway access log parser (JSON format)."""

from __future__ import annotations

import json
from datetime import datetime

from ..models import AuthMethod, DiscoverySource, TrafficRecord
from .base import BaseLogParser


class APIGatewayLogParser(BaseLogParser):
    """Parser for AWS API Gateway access logs (JSON format).

    Expected log format (configured in API Gateway stage settings):
    {
        "requestId": "...",
        "ip": "...",
        "caller": "...",
        "user": "...",
        "requestTime": "...",
        "httpMethod": "GET",
        "resourcePath": "/users/{id}",
        "path": "/prod/users/123",
        "status": "200",
        "protocol": "HTTP/1.1",
        "responseLength": "...",
        "responseLatency": "...",
        "domainName": "...",
        "authorizerType": "..."
    }
    """

    def parse_line(self, line: str) -> TrafficRecord | None:
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return None

        method = data.get("httpMethod") or data.get("method")
        path = data.get("resourcePath") or data.get("path")
        if not method or not path:
            return None

        # Parse timestamp
        request_time = data.get("requestTime", "")
        try:
            timestamp = datetime.strptime(request_time, "%d/%b/%Y:%H:%M:%S %z")
        except ValueError:
            timestamp = datetime.now()

        status_code = int(data.get("status", 0))

        # Detect auth from authorizer type
        auth_type = data.get("authorizerType", "").lower()
        if "cognito" in auth_type or "jwt" in auth_type or "token" in auth_type:
            auth_method = AuthMethod.BEARER
        elif "iam" in auth_type:
            auth_method = AuthMethod.API_KEY
        elif auth_type == "" or auth_type == "none":
            auth_method = AuthMethod.NONE
        else:
            auth_method = AuthMethod.UNKNOWN

        response_time = None
        if data.get("responseLatency"):
            try:
                response_time = float(data["responseLatency"])
            except (ValueError, TypeError):
                pass

        return TrafficRecord(
            timestamp=timestamp,
            method=method,
            path=path,
            status_code=status_code,
            source_ip=data.get("ip"),
            auth_method=auth_method,
            auth_subject=data.get("user") or data.get("caller"),
            response_time_ms=response_time,
            host=data.get("domainName"),
            discovery_source=DiscoverySource.LOG_API_GATEWAY,
        )
