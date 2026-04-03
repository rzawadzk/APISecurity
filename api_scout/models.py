"""Core data models for API inventory."""

from __future__ import annotations

import hashlib
from datetime import datetime
from enum import Enum
from typing import Optional

from pydantic import BaseModel, Field, computed_field


class APIStatus(str, Enum):
    ACTIVE = "active"
    ZOMBIE = "zombie"  # Declared in spec but no recent traffic
    SHADOW = "shadow"  # Traffic observed but not in any spec
    UNDOCUMENTED = "undocumented"  # No spec, no owner
    DEPRECATED = "deprecated"


class AuthMethod(str, Enum):
    BEARER = "bearer"
    API_KEY = "api_key"
    BASIC = "basic"
    NONE = "none"
    UNKNOWN = "unknown"


class DiscoverySource(str, Enum):
    LOG_NGINX = "log_nginx"
    LOG_ALB = "log_alb"
    LOG_API_GATEWAY = "log_api_gateway"
    LOG_GENERIC = "log_generic"
    SCAN_NETWORK = "scan_network"
    SCAN_OPENAPI = "scan_openapi"


class TrafficRecord(BaseModel):
    """A single observed API call from logs or traffic capture."""

    timestamp: datetime
    method: str
    path: str
    status_code: int
    source_ip: Optional[str] = None
    source_service: Optional[str] = None
    auth_method: AuthMethod = AuthMethod.UNKNOWN
    auth_subject: Optional[str] = None  # e.g. JWT sub, API key ID
    response_time_ms: Optional[float] = None
    host: Optional[str] = None
    discovery_source: DiscoverySource = DiscoverySource.LOG_GENERIC


class APIEndpoint(BaseModel):
    """An discovered API endpoint in the inventory."""

    method: str
    path_pattern: str  # Normalized (e.g. /users/{id})
    host: Optional[str] = None
    service_name: Optional[str] = None
    owning_team: Optional[str] = None
    status: APIStatus = APIStatus.UNDOCUMENTED
    auth_methods_seen: list[AuthMethod] = Field(default_factory=list)
    consumers: list[str] = Field(default_factory=list)  # Unique callers
    first_seen: Optional[datetime] = None
    last_seen: Optional[datetime] = None
    total_calls: int = 0
    error_count: int = 0
    avg_response_time_ms: Optional[float] = None
    declared_in_spec: bool = False
    discovery_sources: list[DiscoverySource] = Field(default_factory=list)

    @computed_field
    @property
    def endpoint_id(self) -> str:
        key = f"{self.method}:{self.host or ''}:{self.path_pattern}"
        return hashlib.sha256(key.encode()).hexdigest()[:12]

    @computed_field
    @property
    def error_rate(self) -> float:
        if self.total_calls == 0:
            return 0.0
        return self.error_count / self.total_calls


class ScanResult(BaseModel):
    """Result from active network scanning."""

    host: str
    port: int
    is_http: bool = False
    openapi_spec_url: Optional[str] = None
    openapi_spec: Optional[dict] = None
    endpoints_found: list[APIEndpoint] = Field(default_factory=list)
    scanned_at: datetime = Field(default_factory=datetime.now)


class InventoryReport(BaseModel):
    """Summary report of the API inventory."""

    generated_at: datetime = Field(default_factory=datetime.now)
    total_endpoints: int = 0
    active_endpoints: int = 0
    shadow_endpoints: int = 0
    zombie_endpoints: int = 0
    undocumented_endpoints: int = 0
    unauthenticated_endpoints: int = 0
    new_last_24h: int = 0
    endpoints: list[APIEndpoint] = Field(default_factory=list)
    alerts: list[str] = Field(default_factory=list)
