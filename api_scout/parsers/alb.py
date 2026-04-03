"""AWS Application Load Balancer access log parser."""

from __future__ import annotations

import re
from datetime import datetime

from ..models import AuthMethod, DiscoverySource, TrafficRecord
from .base import BaseLogParser

# ALB log format (space-delimited, some fields quoted):
# type timestamp elb client:port target:port request_processing_time
# target_processing_time response_processing_time elb_status_code
# target_status_code received_bytes sent_bytes "request" "user_agent"
# ssl_cipher ssl_protocol target_group_arn "trace_id" "domain_name"
# "chosen_cert_arn" matched_rule_priority request_creation_time
# "actions_executed" "redirect_url" "error_reason"
ALB_RE = re.compile(
    r'(?P<type>\S+)\s+'
    r'(?P<timestamp>\S+)\s+'
    r'(?P<elb>\S+)\s+'
    r'(?P<client>\S+)\s+'
    r'(?P<target>\S+)\s+'
    r'(?P<request_processing_time>\S+)\s+'
    r'(?P<target_processing_time>\S+)\s+'
    r'(?P<response_processing_time>\S+)\s+'
    r'(?P<elb_status>\d{3})\s+'
    r'(?P<target_status>\d{3}|-)\s+'
    r'(?P<received_bytes>\S+)\s+'
    r'(?P<sent_bytes>\S+)\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+'
    r'"(?P<user_agent>[^"]*)"'
)


class ALBLogParser(BaseLogParser):
    """Parser for AWS ALB access logs."""

    def parse_line(self, line: str) -> TrafficRecord | None:
        match = ALB_RE.match(line)
        if not match:
            return None

        groups = match.groupdict()

        try:
            timestamp = datetime.fromisoformat(groups["timestamp"].replace("Z", "+00:00"))
        except ValueError:
            timestamp = datetime.now()

        # Extract path from full URL
        url = groups["url"]
        path = url.split("?")[0] if "?" in url else url
        # Strip scheme+host if present
        if path.startswith("http"):
            from urllib.parse import urlparse
            path = urlparse(path).path

        client_ip = groups["client"].rsplit(":", 1)[0] if ":" in groups["client"] else groups["client"]

        status = groups["target_status"]
        status_code = int(status) if status != "-" else int(groups["elb_status"])

        response_time = None
        try:
            response_time = float(groups["target_processing_time"]) * 1000
        except (ValueError, TypeError):
            pass

        # Extract host from URL
        host = None
        if url.startswith("http"):
            from urllib.parse import urlparse
            host = urlparse(url).hostname

        return TrafficRecord(
            timestamp=timestamp,
            method=groups["method"],
            path=path,
            status_code=status_code,
            source_ip=client_ip,
            response_time_ms=response_time,
            host=host,
            discovery_source=DiscoverySource.LOG_ALB,
        )
