"""API Inventory Engine — aggregates, deduplicates, classifies, and alerts."""

from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

from .models import (
    APIEndpoint,
    APIStatus,
    AuthMethod,
    DiscoverySource,
    InventoryReport,
    ScanResult,
    TrafficRecord,
)


# Patterns to normalize path parameters
# /users/123 -> /users/{id}
# /orders/abc-def-123 -> /orders/{id}
# /v2/items/42/reviews -> /v2/items/{id}/reviews
PATH_PARAM_PATTERNS = [
    (re.compile(r'/\d+'), r'/{id}'),
    (re.compile(r'/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', re.I), r'/{uuid}'),
    (re.compile(r'/[0-9a-f]{24}', re.I), r'/{objectId}'),  # MongoDB ObjectId
    (re.compile(r'/[A-Za-z0-9_-]{20,}'), r'/{token}'),  # Long tokens/hashes
]


class APIInventory:
    """Central inventory that collects and manages discovered API endpoints."""

    def __init__(self, zombie_threshold_days: int = 30):
        self._endpoints: dict[str, APIEndpoint] = {}  # keyed by endpoint_id
        self.zombie_threshold = timedelta(days=zombie_threshold_days)

    @property
    def endpoints(self) -> list[APIEndpoint]:
        return list(self._endpoints.values())

    @staticmethod
    def normalize_path(path: str) -> str:
        """Normalize a concrete path into a pattern.

        /users/123/orders/456 -> /users/{id}/orders/{id}
        """
        normalized = path.rstrip("/")
        for pattern, replacement in PATH_PARAM_PATTERNS:
            normalized = pattern.sub(replacement, normalized)
        return normalized or "/"

    def _get_or_create(self, method: str, path_pattern: str, host: Optional[str] = None) -> APIEndpoint:
        """Get existing endpoint or create a new one."""
        # Create a temp endpoint to compute its ID
        temp = APIEndpoint(method=method, path_pattern=path_pattern, host=host)
        eid = temp.endpoint_id

        if eid not in self._endpoints:
            self._endpoints[eid] = temp
        return self._endpoints[eid]

    def ingest_traffic(self, records: list[TrafficRecord]) -> int:
        """Ingest traffic records into the inventory. Returns count of new endpoints discovered."""
        new_count = 0
        existing_ids = set(self._endpoints.keys())

        for record in records:
            path_pattern = self.normalize_path(record.path)
            endpoint = self._get_or_create(record.method, path_pattern, record.host)

            if endpoint.endpoint_id not in existing_ids:
                new_count += 1
                existing_ids.add(endpoint.endpoint_id)

            # Update stats
            endpoint.total_calls += 1
            if record.status_code >= 400:
                endpoint.error_count += 1

            # Normalize to naive UTC for comparison
            ts = record.timestamp.replace(tzinfo=None) if record.timestamp.tzinfo else record.timestamp
            if endpoint.first_seen is None or ts < endpoint.first_seen.replace(tzinfo=None):
                endpoint.first_seen = record.timestamp
            if endpoint.last_seen is None or ts > endpoint.last_seen.replace(tzinfo=None):
                endpoint.last_seen = record.timestamp

            # Track auth methods
            if record.auth_method not in endpoint.auth_methods_seen:
                endpoint.auth_methods_seen.append(record.auth_method)

            # Track consumers
            consumer = record.auth_subject or record.source_ip or record.source_service
            if consumer and consumer not in endpoint.consumers:
                endpoint.consumers.append(consumer)

            # Track discovery source
            if record.discovery_source not in endpoint.discovery_sources:
                endpoint.discovery_sources.append(record.discovery_source)

            # Update avg response time
            if record.response_time_ms is not None:
                if endpoint.avg_response_time_ms is None:
                    endpoint.avg_response_time_ms = record.response_time_ms
                else:
                    # Running average
                    n = endpoint.total_calls
                    endpoint.avg_response_time_ms = (
                        endpoint.avg_response_time_ms * (n - 1) + record.response_time_ms
                    ) / n

        return new_count

    def ingest_scan_results(self, scan_results: list[ScanResult]) -> int:
        """Ingest results from active scanning. Returns count of new endpoints."""
        new_count = 0
        existing_ids = set(self._endpoints.keys())

        for scan in scan_results:
            for ep in scan.endpoints_found:
                existing = self._get_or_create(ep.method, ep.path_pattern, ep.host)

                if existing.endpoint_id not in existing_ids:
                    new_count += 1
                    existing_ids.add(existing.endpoint_id)

                existing.declared_in_spec = True
                if DiscoverySource.SCAN_OPENAPI not in existing.discovery_sources:
                    existing.discovery_sources.append(DiscoverySource.SCAN_OPENAPI)
                if ep.status == APIStatus.DEPRECATED:
                    existing.status = APIStatus.DEPRECATED

        return new_count

    def classify(self) -> None:
        """Classify all endpoints (active, shadow, zombie, etc.)."""
        now = datetime.now()

        for endpoint in self._endpoints.values():
            if endpoint.status == APIStatus.DEPRECATED:
                continue

            has_traffic = endpoint.total_calls > 0
            in_spec = endpoint.declared_in_spec
            recent_traffic = (
                endpoint.last_seen is not None
                and (now - endpoint.last_seen.replace(tzinfo=None)) < self.zombie_threshold
            )

            if in_spec and has_traffic and recent_traffic:
                endpoint.status = APIStatus.ACTIVE
            elif in_spec and not recent_traffic:
                endpoint.status = APIStatus.ZOMBIE
            elif has_traffic and not in_spec:
                endpoint.status = APIStatus.SHADOW
            else:
                endpoint.status = APIStatus.UNDOCUMENTED

    def generate_alerts(self) -> list[str]:
        """Generate security and operational alerts."""
        alerts = []
        now = datetime.now()

        for ep in self._endpoints.values():
            # Shadow API alert
            if ep.status == APIStatus.SHADOW:
                alerts.append(
                    f"🔴 SHADOW API: {ep.method} {ep.path_pattern} "
                    f"({ep.total_calls} calls, not in any spec)"
                )

            # Unauthenticated endpoint
            if AuthMethod.NONE in ep.auth_methods_seen and ep.total_calls > 0:
                alerts.append(
                    f"⚠️  UNAUTHENTICATED: {ep.method} {ep.path_pattern} "
                    f"receives unauthenticated traffic"
                )

            # High error rate
            if ep.total_calls > 10 and ep.error_rate > 0.5:
                alerts.append(
                    f"🟡 HIGH ERROR RATE: {ep.method} {ep.path_pattern} "
                    f"({ep.error_rate:.0%} errors over {ep.total_calls} calls)"
                )

            # New endpoint (last 24h)
            if ep.first_seen and (now - ep.first_seen.replace(tzinfo=None)) < timedelta(hours=24):
                alerts.append(
                    f"🆕 NEW ENDPOINT: {ep.method} {ep.path_pattern} "
                    f"(first seen {ep.first_seen.isoformat()})"
                )

            # Zombie API
            if ep.status == APIStatus.ZOMBIE:
                alerts.append(
                    f"💀 ZOMBIE API: {ep.method} {ep.path_pattern} "
                    f"(in spec but no traffic since {ep.last_seen})"
                )

        return sorted(alerts)

    def generate_report(self) -> InventoryReport:
        """Generate a full inventory report."""
        self.classify()
        alerts = self.generate_alerts()

        now = datetime.now()
        new_24h = sum(
            1 for ep in self._endpoints.values()
            if ep.first_seen and (now - ep.first_seen.replace(tzinfo=None)) < timedelta(hours=24)
        )

        unauth = sum(
            1 for ep in self._endpoints.values()
            if AuthMethod.NONE in ep.auth_methods_seen
        )

        return InventoryReport(
            total_endpoints=len(self._endpoints),
            active_endpoints=sum(1 for ep in self._endpoints.values() if ep.status == APIStatus.ACTIVE),
            shadow_endpoints=sum(1 for ep in self._endpoints.values() if ep.status == APIStatus.SHADOW),
            zombie_endpoints=sum(1 for ep in self._endpoints.values() if ep.status == APIStatus.ZOMBIE),
            undocumented_endpoints=sum(1 for ep in self._endpoints.values() if ep.status == APIStatus.UNDOCUMENTED),
            unauthenticated_endpoints=unauth,
            new_last_24h=new_24h,
            endpoints=sorted(self.endpoints, key=lambda e: (e.status.value, e.method, e.path_pattern)),
            alerts=alerts,
        )
