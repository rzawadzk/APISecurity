"""Behavioral Fingerprinting & Anomaly Detection.

Creates a "normal" behavioral profile for each endpoint and detects
deviations that may indicate BOLA attacks, data exfiltration,
credential stuffing, or other API abuse patterns.
"""

from __future__ import annotations

import math
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import Optional

from .models import TrafficRecord


class AnomalyType(str, Enum):
    DATA_EXFILTRATION = "data_exfiltration"         # Unusual response sizes
    ENUMERATION = "enumeration"                      # Rapid sequential ID access
    BOLA = "bola"                                    # Single user hitting many IDs
    CREDENTIAL_STUFFING = "credential_stuffing"      # High auth failure rate
    RATE_ANOMALY = "rate_anomaly"                    # Unusual request rate
    SEQUENCE_ANOMALY = "sequence_anomaly"            # Unusual call sequence
    NEW_CONSUMER = "new_consumer"                    # Previously unseen caller


class AnomalySeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Anomaly:
    anomaly_type: AnomalyType
    severity: AnomalySeverity
    endpoint: str
    message: str
    source: Optional[str] = None      # IP/service that triggered it
    score: float = 0.0                # 0-1 confidence score
    timestamp: datetime = field(default_factory=datetime.now)
    details: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "type": self.anomaly_type.value,
            "severity": self.severity.value,
            "endpoint": self.endpoint,
            "message": self.message,
            "source": self.source,
            "score": self.score,
            "timestamp": self.timestamp.isoformat(),
            "details": self.details,
        }


@dataclass
class EndpointProfile:
    """Behavioral fingerprint for a single endpoint."""

    method: str
    path_pattern: str

    # Response size statistics
    response_sizes: list[int] = field(default_factory=list)
    avg_response_size: float = 0.0
    std_response_size: float = 0.0

    # Latency statistics
    latencies: list[float] = field(default_factory=list)
    avg_latency: float = 0.0
    std_latency: float = 0.0

    # Rate statistics (requests per minute per source)
    rates_per_source: dict[str, list[float]] = field(default_factory=lambda: defaultdict(list))
    avg_rate_per_source: float = 0.0

    # Status code distribution
    status_distribution: dict[int, int] = field(default_factory=lambda: defaultdict(int))

    # Known consumers
    known_consumers: set[str] = field(default_factory=set)

    # Unique resource IDs accessed per source (for BOLA detection)
    resource_ids_per_source: dict[str, set[str]] = field(default_factory=lambda: defaultdict(set))

    # Call sequences: what endpoints a source typically calls before/after this one
    preceding_calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))

    # Training state
    sample_count: int = 0
    is_trained: bool = False

    @property
    def endpoint_key(self) -> str:
        return f"{self.method} {self.path_pattern}"

    def _compute_stats(self):
        """Recompute running statistics."""
        if self.response_sizes:
            self.avg_response_size = sum(self.response_sizes) / len(self.response_sizes)
            variance = sum((x - self.avg_response_size) ** 2 for x in self.response_sizes) / max(len(self.response_sizes), 1)
            self.std_response_size = math.sqrt(variance)

        if self.latencies:
            self.avg_latency = sum(self.latencies) / len(self.latencies)
            variance = sum((x - self.avg_latency) ** 2 for x in self.latencies) / max(len(self.latencies), 1)
            self.std_latency = math.sqrt(variance)


class AnomalyDetector:
    """Detects behavioral anomalies across API endpoints."""

    def __init__(
        self,
        training_window: int = 1000,      # Records needed before detection starts
        rate_window_seconds: int = 60,     # Window for rate calculation
        bola_threshold: int = 20,          # Unique IDs per source before flagging
        exfil_std_multiplier: float = 3.0, # Standard deviations for size anomaly
        rate_std_multiplier: float = 3.0,  # Standard deviations for rate anomaly
        auth_failure_threshold: float = 0.8, # Failure rate for credential stuffing
    ):
        self.training_window = training_window
        self.rate_window_seconds = rate_window_seconds
        self.bola_threshold = bola_threshold
        self.exfil_std_multiplier = exfil_std_multiplier
        self.rate_std_multiplier = rate_std_multiplier
        self.auth_failure_threshold = auth_failure_threshold

        self.profiles: dict[str, EndpointProfile] = {}
        self._source_timestamps: dict[str, dict[str, list[datetime]]] = defaultdict(lambda: defaultdict(list))
        self._source_call_history: dict[str, list[tuple[str, datetime]]] = defaultdict(list)

    def _get_profile(self, method: str, path_pattern: str) -> EndpointProfile:
        key = f"{method} {path_pattern}"
        if key not in self.profiles:
            self.profiles[key] = EndpointProfile(method=method, path_pattern=path_pattern)
        return self.profiles[key]

    def _extract_resource_id(self, path: str, pattern: str) -> Optional[str]:
        """Extract the resource ID from a path using the pattern."""
        path_parts = path.rstrip("/").split("/")
        pattern_parts = pattern.rstrip("/").split("/")

        for pp, pat in zip(path_parts, pattern_parts):
            if pat.startswith("{") and pat.endswith("}"):
                return pp
        return None

    def train(self, records: list[TrafficRecord], path_patterns: dict[str, str]) -> None:
        """Train profiles from historical traffic data."""
        for record in records:
            pattern = path_patterns.get(record.path, record.path)
            profile = self._get_profile(record.method, pattern)

            # Collect stats
            if record.response_time_ms is not None:
                profile.latencies.append(record.response_time_ms)

            profile.status_distribution[record.status_code] += 1

            source = record.source_ip or record.source_service or "unknown"
            profile.known_consumers.add(source)

            # Track resource IDs for BOLA baseline
            resource_id = self._extract_resource_id(record.path, pattern)
            if resource_id:
                profile.resource_ids_per_source[source].add(resource_id)

            profile.sample_count += 1

        # Compute stats for all profiles
        for profile in self.profiles.values():
            profile._compute_stats()
            if profile.sample_count >= self.training_window:
                profile.is_trained = True

    def analyze(
        self,
        records: list[TrafficRecord],
        path_patterns: dict[str, str],
    ) -> list[Anomaly]:
        """Analyze new traffic records for anomalies."""
        anomalies = []

        # Group records by source for rate analysis
        source_records: dict[str, list[TrafficRecord]] = defaultdict(list)
        for record in records:
            source = record.source_ip or record.source_service or "unknown"
            source_records[source].append(record)

        for record in records:
            pattern = path_patterns.get(record.path, record.path)
            profile = self._get_profile(record.method, pattern)
            source = record.source_ip or record.source_service or "unknown"
            endpoint_key = f"{record.method} {pattern}"

            if not profile.is_trained:
                # Still in training mode — just collect data
                if record.response_time_ms is not None:
                    profile.latencies.append(record.response_time_ms)
                profile.status_distribution[record.status_code] += 1
                profile.known_consumers.add(source)

                resource_id = self._extract_resource_id(record.path, pattern)
                if resource_id:
                    profile.resource_ids_per_source[source].add(resource_id)

                profile.sample_count += 1
                if profile.sample_count >= self.training_window:
                    profile._compute_stats()
                    profile.is_trained = True
                continue

            # ── Detection 1: Data Exfiltration (unusual response sizes) ──
            if record.response_time_ms is not None and profile.std_latency > 0:
                latency_zscore = abs(record.response_time_ms - profile.avg_latency) / profile.std_latency
                if latency_zscore > self.exfil_std_multiplier and record.response_time_ms > profile.avg_latency:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.DATA_EXFILTRATION,
                        severity=AnomalySeverity.HIGH,
                        endpoint=endpoint_key,
                        message=(
                            f"Unusual response time on {endpoint_key}: "
                            f"{record.response_time_ms:.0f}ms vs avg {profile.avg_latency:.0f}ms "
                            f"({latency_zscore:.1f} std devs) — possible data exfiltration"
                        ),
                        source=source,
                        score=min(latency_zscore / 10, 1.0),
                        timestamp=record.timestamp,
                        details={
                            "observed_latency_ms": record.response_time_ms,
                            "avg_latency_ms": profile.avg_latency,
                            "z_score": round(latency_zscore, 2),
                        },
                    ))

            # ── Detection 2: BOLA (single source accessing many unique IDs) ──
            resource_id = self._extract_resource_id(record.path, pattern)
            if resource_id:
                profile.resource_ids_per_source[source].add(resource_id)
                unique_ids = len(profile.resource_ids_per_source[source])

                if unique_ids > self.bola_threshold:
                    anomalies.append(Anomaly(
                        anomaly_type=AnomalyType.BOLA,
                        severity=AnomalySeverity.CRITICAL,
                        endpoint=endpoint_key,
                        message=(
                            f"Possible BOLA attack: {source} has accessed "
                            f"{unique_ids} unique resource IDs on {endpoint_key}"
                        ),
                        source=source,
                        score=min(unique_ids / (self.bola_threshold * 5), 1.0),
                        timestamp=record.timestamp,
                        details={
                            "unique_ids_accessed": unique_ids,
                            "threshold": self.bola_threshold,
                            "sample_ids": list(profile.resource_ids_per_source[source])[:5],
                        },
                    ))

            # ── Detection 3: New Consumer ──
            if source not in profile.known_consumers:
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.NEW_CONSUMER,
                    severity=AnomalySeverity.LOW,
                    endpoint=endpoint_key,
                    message=f"New consumer {source} accessing {endpoint_key}",
                    source=source,
                    score=0.3,
                    timestamp=record.timestamp,
                ))
                profile.known_consumers.add(source)

            # Track for sequence analysis
            self._source_call_history[source].append((endpoint_key, record.timestamp))

        # ── Detection 4: Credential Stuffing (per-source auth failure rate) ──
        for source, recs in source_records.items():
            auth_attempts = [r for r in recs if r.status_code in (401, 403)]
            total = len(recs)
            if total >= 10 and len(auth_attempts) / total > self.auth_failure_threshold:
                failure_rate = len(auth_attempts) / total
                anomalies.append(Anomaly(
                    anomaly_type=AnomalyType.CREDENTIAL_STUFFING,
                    severity=AnomalySeverity.CRITICAL,
                    endpoint="multiple",
                    message=(
                        f"Possible credential stuffing from {source}: "
                        f"{len(auth_attempts)}/{total} requests failed auth "
                        f"({failure_rate:.0%})"
                    ),
                    source=source,
                    score=failure_rate,
                    details={
                        "total_requests": total,
                        "auth_failures": len(auth_attempts),
                        "failure_rate": round(failure_rate, 3),
                    },
                ))

        # ── Detection 5: Rate Anomaly (per-source burst detection) ──
        for source, recs in source_records.items():
            if len(recs) < 5:
                continue

            # Calculate requests per minute
            sorted_recs = sorted(recs, key=lambda r: r.timestamp)
            ts_naive = [r.timestamp.replace(tzinfo=None) for r in sorted_recs]
            if len(ts_naive) >= 2:
                time_span = (ts_naive[-1] - ts_naive[0]).total_seconds()
                if time_span > 0:
                    rpm = len(recs) / (time_span / 60)
                    if rpm > 100:  # More than 100 RPM from a single source
                        anomalies.append(Anomaly(
                            anomaly_type=AnomalyType.RATE_ANOMALY,
                            severity=AnomalySeverity.HIGH if rpm > 500 else AnomalySeverity.MEDIUM,
                            endpoint="multiple",
                            message=(
                                f"High request rate from {source}: {rpm:.0f} requests/min "
                                f"over {time_span:.0f}s"
                            ),
                            source=source,
                            score=min(rpm / 1000, 1.0),
                            details={
                                "requests_per_minute": round(rpm, 1),
                                "total_requests": len(recs),
                                "time_span_seconds": round(time_span, 1),
                            },
                        ))

        # ── Detection 6: Enumeration (sequential ID access) ──
        for source, recs in source_records.items():
            for record in recs:
                pattern = path_patterns.get(record.path, record.path)
                resource_id = self._extract_resource_id(record.path, pattern)
                if resource_id and resource_id.isdigit():
                    profile = self._get_profile(record.method, pattern)
                    numeric_ids = sorted(
                        int(rid) for rid in profile.resource_ids_per_source.get(source, set())
                        if rid.isdigit()
                    )
                    if len(numeric_ids) >= 10:
                        # Check for sequential pattern
                        diffs = [numeric_ids[i+1] - numeric_ids[i] for i in range(len(numeric_ids)-1)]
                        sequential_count = sum(1 for d in diffs if d == 1)
                        if sequential_count > len(diffs) * 0.7:
                            anomalies.append(Anomaly(
                                anomaly_type=AnomalyType.ENUMERATION,
                                severity=AnomalySeverity.HIGH,
                                endpoint=f"{record.method} {pattern}",
                                message=(
                                    f"Sequential ID enumeration detected from {source} "
                                    f"on {record.method} {pattern}: "
                                    f"{len(numeric_ids)} IDs, {sequential_count}/{len(diffs)} sequential"
                                ),
                                source=source,
                                score=sequential_count / len(diffs),
                                details={
                                    "total_ids": len(numeric_ids),
                                    "sequential_pairs": sequential_count,
                                    "id_range": f"{numeric_ids[0]}-{numeric_ids[-1]}",
                                },
                            ))

        # Deduplicate by (type, source, endpoint)
        seen = set()
        deduped = []
        for a in anomalies:
            key = (a.anomaly_type, a.source, a.endpoint)
            if key not in seen:
                seen.add(key)
                deduped.append(a)

        return sorted(deduped, key=lambda a: a.severity.value)

    def get_profiles_summary(self) -> list[dict]:
        """Get summary of all endpoint profiles."""
        return [
            {
                "endpoint": p.endpoint_key,
                "sample_count": p.sample_count,
                "is_trained": p.is_trained,
                "avg_latency_ms": round(p.avg_latency, 2),
                "known_consumers": len(p.known_consumers),
                "status_codes": dict(p.status_distribution),
            }
            for p in sorted(self.profiles.values(), key=lambda p: p.sample_count, reverse=True)
        ]
