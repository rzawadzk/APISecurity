"""Egress & Third-Party API Tracking — OWASP API10.

Monitors outbound API calls to:
- Build a third-party API inventory (Stripe, Twilio, OpenAI, etc.)
- Detect potential secret leakage in outbound requests
- Track SLA compliance of external dependencies
"""

from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Iterator, Optional
from urllib.parse import urlparse

from .models import TrafficRecord, DiscoverySource


# ── Known Third-Party API Providers ──

KNOWN_PROVIDERS: dict[str, list[str]] = {
    "Stripe": ["api.stripe.com"],
    "Twilio": ["api.twilio.com"],
    "SendGrid": ["api.sendgrid.com"],
    "OpenAI": ["api.openai.com"],
    "Anthropic": ["api.anthropic.com"],
    "AWS S3": ["s3.amazonaws.com", "s3.us-east-1.amazonaws.com"],
    "AWS SES": ["email.us-east-1.amazonaws.com"],
    "Google APIs": ["googleapis.com", "oauth2.googleapis.com"],
    "GitHub": ["api.github.com"],
    "Slack": ["slack.com", "hooks.slack.com"],
    "Datadog": ["api.datadoghq.com"],
    "PagerDuty": ["api.pagerduty.com"],
    "Sentry": ["sentry.io"],
    "LaunchDarkly": ["app.launchdarkly.com"],
    "Auth0": ["auth0.com"],
    "Okta": ["okta.com"],
    "Firebase": ["firebaseio.com", "fcm.googleapis.com"],
    "Cloudflare": ["api.cloudflare.com"],
}

# ── Secret Patterns ──

SECRET_PATTERNS = [
    (re.compile(r'(?:sk|pk)[-_](?:live|test)[-_][A-Za-z0-9]{20,}'), "Stripe API Key"),
    (re.compile(r'Bearer\s+eyJ[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}'), "JWT Token"),
    (re.compile(r'(?:api[_-]?key|apikey|token|secret|password|passwd|pwd)\s*[=:]\s*["\']?[A-Za-z0-9_\-]{16,}', re.I), "Generic Secret"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "AWS Access Key"),
    (re.compile(r'ghp_[A-Za-z0-9]{36}'), "GitHub Personal Token"),
    (re.compile(r'xoxb-[0-9]+-[A-Za-z0-9]+'), "Slack Bot Token"),
    (re.compile(r'sk-[A-Za-z0-9]{20,}'), "OpenAI API Key"),
    (re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'), "Email Address (PII)"),
    (re.compile(r'\b\d{3}-\d{2}-\d{4}\b'), "SSN Pattern (PII)"),
]


class EgressRiskLevel(str, Enum):
    CRITICAL = "critical"   # Secret leakage detected
    HIGH = "high"           # PII in outbound traffic
    MEDIUM = "medium"       # Unknown third-party destination
    LOW = "low"             # Known provider, normal traffic
    INFO = "info"


@dataclass
class ThirdPartyAPI:
    """A discovered external API dependency."""

    provider_name: str          # "Stripe", "Unknown", etc.
    host: str                   # api.stripe.com
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_calls: int = 0
    error_count: int = 0
    methods_seen: set = field(default_factory=set)
    paths_seen: set = field(default_factory=set)
    calling_services: set = field(default_factory=set)  # Which internal services call this
    avg_latency_ms: Optional[float] = None
    secret_leaks_detected: int = 0
    risk_level: EgressRiskLevel = EgressRiskLevel.LOW

    @property
    def error_rate(self) -> float:
        return self.error_count / self.total_calls if self.total_calls else 0

    def to_dict(self) -> dict:
        return {
            "provider_name": self.provider_name,
            "host": self.host,
            "first_seen": self.first_seen.isoformat() if self.first_seen else None,
            "last_seen": self.last_seen.isoformat() if self.last_seen else None,
            "total_calls": self.total_calls,
            "error_count": self.error_count,
            "error_rate": round(self.error_rate, 3),
            "methods": sorted(self.methods_seen),
            "paths_sample": sorted(list(self.paths_seen)[:10]),
            "calling_services": sorted(self.calling_services),
            "avg_latency_ms": round(self.avg_latency_ms, 2) if self.avg_latency_ms else None,
            "secret_leaks_detected": self.secret_leaks_detected,
            "risk_level": self.risk_level.value,
        }


@dataclass
class SecretLeak:
    """A detected potential secret in outbound traffic."""

    secret_type: str
    destination_host: str
    source_service: Optional[str] = None
    path: Optional[str] = None
    matched_pattern: Optional[str] = None  # Redacted match
    timestamp: datetime = field(default_factory=datetime.now)

    def to_dict(self) -> dict:
        return {
            "secret_type": self.secret_type,
            "destination_host": self.destination_host,
            "source_service": self.source_service,
            "path": self.path,
            "matched_pattern": self.matched_pattern,
            "timestamp": self.timestamp.isoformat(),
        }


class EgressTracker:
    """Tracks outbound API calls and detects security issues."""

    def __init__(self):
        self.third_parties: dict[str, ThirdPartyAPI] = {}  # keyed by host
        self.secret_leaks: list[SecretLeak] = []
        self._internal_domains: set[str] = set()

    def add_internal_domains(self, domains: list[str]):
        """Register internal domains to exclude from third-party tracking."""
        self._internal_domains.update(d.lower() for d in domains)

    def _identify_provider(self, host: str) -> str:
        """Match a host to a known provider."""
        host_lower = host.lower()
        for provider, domains in KNOWN_PROVIDERS.items():
            for domain in domains:
                if host_lower == domain or host_lower.endswith("." + domain):
                    return provider
        return "Unknown"

    def _is_internal(self, host: str) -> bool:
        """Check if a host is internal."""
        host_lower = host.lower()

        # Internal IPs
        if host_lower.startswith(("10.", "172.16.", "172.17.", "172.18.", "172.19.",
                                   "172.20.", "172.21.", "172.22.", "172.23.",
                                   "172.24.", "172.25.", "172.26.", "172.27.",
                                   "172.28.", "172.29.", "172.30.", "172.31.",
                                   "192.168.", "127.", "localhost")):
            return True

        # Registered internal domains
        for domain in self._internal_domains:
            if host_lower == domain or host_lower.endswith("." + domain):
                return True

        return False

    def _check_secrets(self, line: str, host: str, source: Optional[str], path: Optional[str], ts: datetime) -> list[SecretLeak]:
        """Scan a log line for potential secrets."""
        leaks = []
        for pattern, secret_type in SECRET_PATTERNS:
            matches = pattern.findall(line)
            for match in matches:
                # Redact the match for logging (show first 8 chars only)
                redacted = match[:8] + "..." + match[-4:] if len(match) > 16 else match[:4] + "****"
                leaks.append(SecretLeak(
                    secret_type=secret_type,
                    destination_host=host,
                    source_service=source,
                    path=path,
                    matched_pattern=redacted,
                    timestamp=ts,
                ))
        return leaks

    def ingest_egress_records(
        self,
        records: list[TrafficRecord],
        raw_lines: Optional[list[str]] = None,
    ) -> tuple[int, int]:
        """Ingest outbound traffic records. Returns (new_providers, secret_leaks)."""
        new_providers = 0
        new_leaks = 0

        for i, record in enumerate(records):
            host = record.host
            if not host:
                continue

            if self._is_internal(host):
                continue

            # Get or create third-party entry
            if host not in self.third_parties:
                provider = self._identify_provider(host)
                self.third_parties[host] = ThirdPartyAPI(
                    provider_name=provider,
                    host=host,
                    risk_level=EgressRiskLevel.MEDIUM if provider == "Unknown" else EgressRiskLevel.LOW,
                )
                new_providers += 1

            tp = self.third_parties[host]
            tp.total_calls += 1
            tp.methods_seen.add(record.method)
            tp.paths_seen.add(record.path)

            if record.status_code >= 400:
                tp.error_count += 1

            source = record.source_service or record.source_ip or "unknown"
            tp.calling_services.add(source)

            ts = record.timestamp
            if tp.first_seen is None or ts < tp.first_seen:
                tp.first_seen = ts
            if tp.last_seen is None or ts > tp.last_seen:
                tp.last_seen = ts

            if record.response_time_ms is not None:
                if tp.avg_latency_ms is None:
                    tp.avg_latency_ms = record.response_time_ms
                else:
                    n = tp.total_calls
                    tp.avg_latency_ms = (tp.avg_latency_ms * (n - 1) + record.response_time_ms) / n

            # Check for secrets in raw log lines
            if raw_lines and i < len(raw_lines):
                leaks = self._check_secrets(
                    raw_lines[i], host, source, record.path, record.timestamp
                )
                if leaks:
                    self.secret_leaks.extend(leaks)
                    tp.secret_leaks_detected += len(leaks)
                    tp.risk_level = EgressRiskLevel.CRITICAL
                    new_leaks += len(leaks)

        return new_providers, new_leaks

    def parse_egress_log(self, path: Path, parser) -> tuple[int, int]:
        """Parse an egress/proxy log file and track third-party calls."""
        raw_lines = []
        with open(path, "r", errors="replace") as f:
            raw_lines = [line.strip() for line in f if line.strip()]

        records = []
        for line in raw_lines:
            record = parser.parse_line(line)
            if record:
                records.append(record)

        return self.ingest_egress_records(records, raw_lines)

    def get_inventory(self) -> list[ThirdPartyAPI]:
        """Get all discovered third-party APIs."""
        return sorted(self.third_parties.values(), key=lambda tp: tp.total_calls, reverse=True)

    def get_risk_summary(self) -> dict:
        """Get a risk-level summary."""
        risk_counts = defaultdict(int)
        for tp in self.third_parties.values():
            risk_counts[tp.risk_level.value] += 1

        return {
            "total_third_parties": len(self.third_parties),
            "risk_distribution": dict(risk_counts),
            "total_secret_leaks": len(self.secret_leaks),
            "unknown_providers": sum(
                1 for tp in self.third_parties.values() if tp.provider_name == "Unknown"
            ),
            "providers_with_errors": sum(
                1 for tp in self.third_parties.values() if tp.error_rate > 0.1
            ),
        }
