"""CI/CD Spec-to-Code Validation — shift-left API security.

Compares a proposed OpenAPI spec against the live inventory to detect:
- Breaking changes: removing endpoints that still have active traffic
- Shadow policy violations: new code routes not declared in the spec
- Deprecation warnings: endpoints marked deprecated but still heavily used
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional

import yaml

from .database import Database
from .models import APIEndpoint, APIStatus


class Severity(str, Enum):
    ERROR = "error"      # Fails the build
    WARNING = "warning"  # Logged but doesn't fail
    INFO = "info"


@dataclass
class PolicyViolation:
    severity: Severity
    rule: str
    message: str
    endpoint: Optional[str] = None
    details: Optional[str] = None


@dataclass
class ValidationResult:
    passed: bool
    violations: list[PolicyViolation] = field(default_factory=list)
    spec_endpoints: int = 0
    inventory_endpoints: int = 0
    new_in_spec: int = 0
    removed_from_spec: int = 0

    @property
    def errors(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.severity == Severity.ERROR]

    @property
    def warnings(self) -> list[PolicyViolation]:
        return [v for v in self.violations if v.severity == Severity.WARNING]

    def to_dict(self) -> dict:
        return {
            "passed": self.passed,
            "spec_endpoints": self.spec_endpoints,
            "inventory_endpoints": self.inventory_endpoints,
            "new_in_spec": self.new_in_spec,
            "removed_from_spec": self.removed_from_spec,
            "errors": len(self.errors),
            "warnings": len(self.warnings),
            "violations": [
                {
                    "severity": v.severity.value,
                    "rule": v.rule,
                    "message": v.message,
                    "endpoint": v.endpoint,
                    "details": v.details,
                }
                for v in self.violations
            ],
        }


def load_openapi_spec(spec_path: Path) -> dict:
    """Load an OpenAPI spec from JSON or YAML."""
    content = spec_path.read_text()
    if spec_path.suffix in (".yaml", ".yml"):
        return yaml.safe_load(content)
    return json.loads(content)


def extract_spec_endpoints(spec: dict) -> set[tuple[str, str]]:
    """Extract (METHOD, PATH) pairs from an OpenAPI spec."""
    endpoints = set()
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method in methods:
                endpoints.add((method.upper(), path))
    return endpoints


def extract_deprecated_endpoints(spec: dict) -> set[tuple[str, str]]:
    """Extract endpoints marked as deprecated."""
    deprecated = set()
    paths = spec.get("paths", {})
    for path, methods in paths.items():
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method in methods and methods[method].get("deprecated", False):
                deprecated.add((method.upper(), path))
    return deprecated


def validate_spec_against_inventory(
    spec_path: Path,
    db: Database,
    fail_on_breaking: bool = True,
    fail_on_shadow: bool = True,
    min_traffic_for_breaking: int = 1,
    deprecation_traffic_threshold: int = 100,
) -> ValidationResult:
    """Validate a proposed OpenAPI spec against the live API inventory.

    Args:
        spec_path: Path to the proposed OpenAPI spec
        db: Database with the live inventory
        fail_on_breaking: Treat breaking changes as errors (fail CI)
        fail_on_shadow: Treat shadow policy violations as errors (fail CI)
        min_traffic_for_breaking: Minimum calls to consider an endpoint "active"
        deprecation_traffic_threshold: Warn if deprecated endpoints exceed this traffic
    """
    result = ValidationResult(passed=True)

    # Load spec
    spec = load_openapi_spec(spec_path)
    spec_endpoints = extract_spec_endpoints(spec)
    deprecated_endpoints = extract_deprecated_endpoints(spec)
    result.spec_endpoints = len(spec_endpoints)

    # Load live inventory
    inventory_endpoints = db.get_all_endpoints()
    result.inventory_endpoints = len(inventory_endpoints)

    # Build lookup: (METHOD, PATH_PATTERN) -> APIEndpoint
    inventory_map: dict[tuple[str, str], APIEndpoint] = {
        (ep.method, ep.path_pattern): ep for ep in inventory_endpoints
    }
    inventory_keys = set(inventory_map.keys())

    # ── Rule 1: Breaking Changes ──
    # Endpoints in the live inventory that are being removed from the spec
    removed = inventory_keys - spec_endpoints
    result.removed_from_spec = len(removed)

    for method, path in removed:
        ep = inventory_map[(method, path)]
        if ep.total_calls >= min_traffic_for_breaking and ep.status == APIStatus.ACTIVE:
            result.violations.append(PolicyViolation(
                severity=Severity.ERROR if fail_on_breaking else Severity.WARNING,
                rule="BREAKING_CHANGE",
                message=f"Removing {method} {path} which has active traffic ({ep.total_calls} calls)",
                endpoint=f"{method} {path}",
                details=f"Last seen: {ep.last_seen}, consumers: {len(ep.consumers)}",
            ))
        elif ep.total_calls >= min_traffic_for_breaking:
            result.violations.append(PolicyViolation(
                severity=Severity.WARNING,
                rule="ENDPOINT_REMOVAL",
                message=f"Removing {method} {path} which has {ep.total_calls} historical calls",
                endpoint=f"{method} {path}",
            ))

    # ── Rule 2: Shadow API Policy Violations ──
    # Endpoints in the inventory that have traffic but are NOT in the proposed spec
    for (method, path), ep in inventory_map.items():
        if (method, path) not in spec_endpoints and ep.total_calls > 0:
            # Check if this is a known internal/infrastructure endpoint
            is_infra = any(
                path.startswith(prefix)
                for prefix in ("/health", "/ready", "/metrics", "/internal/", "/.well-known/")
            )

            if is_infra:
                result.violations.append(PolicyViolation(
                    severity=Severity.INFO,
                    rule="INFRA_ENDPOINT_NOT_IN_SPEC",
                    message=f"Infrastructure endpoint {method} {path} not in spec (OK if intentional)",
                    endpoint=f"{method} {path}",
                ))
            else:
                result.violations.append(PolicyViolation(
                    severity=Severity.ERROR if fail_on_shadow else Severity.WARNING,
                    rule="SHADOW_POLICY_VIOLATION",
                    message=f"{method} {path} has traffic ({ep.total_calls} calls) but is not in the spec",
                    endpoint=f"{method} {path}",
                    details=f"Status: {ep.status.value}, auth: {[a.value for a in ep.auth_methods_seen]}",
                ))

    # ── Rule 3: New Endpoints (informational) ──
    new_in_spec = spec_endpoints - inventory_keys
    result.new_in_spec = len(new_in_spec)

    for method, path in new_in_spec:
        result.violations.append(PolicyViolation(
            severity=Severity.INFO,
            rule="NEW_ENDPOINT",
            message=f"New endpoint {method} {path} added to spec (no traffic history yet)",
            endpoint=f"{method} {path}",
        ))

    # ── Rule 4: Deprecated but High Traffic ──
    for method, path in deprecated_endpoints:
        if (method, path) in inventory_map:
            ep = inventory_map[(method, path)]
            if ep.total_calls > deprecation_traffic_threshold:
                result.violations.append(PolicyViolation(
                    severity=Severity.WARNING,
                    rule="DEPRECATED_HIGH_TRAFFIC",
                    message=(
                        f"{method} {path} is deprecated but has {ep.total_calls} calls. "
                        f"Consumers may break when removed."
                    ),
                    endpoint=f"{method} {path}",
                    details=f"Consumers: {ep.consumers[:5]}",
                ))

    # ── Rule 5: Unauthenticated Endpoints in Spec ──
    from .models import AuthMethod
    for (method, path), ep in inventory_map.items():
        if (method, path) in spec_endpoints and AuthMethod.NONE in ep.auth_methods_seen:
            # Skip health/infra endpoints
            if not any(path.startswith(p) for p in ("/health", "/ready", "/metrics")):
                result.violations.append(PolicyViolation(
                    severity=Severity.WARNING,
                    rule="UNAUTHENTICATED_IN_SPEC",
                    message=f"{method} {path} is in the spec but receives unauthenticated traffic",
                    endpoint=f"{method} {path}",
                ))

    # Determine pass/fail
    result.passed = len(result.errors) == 0

    return result


def generate_github_annotations(result: ValidationResult) -> str:
    """Generate GitHub Actions annotation format for CI output."""
    lines = []
    for v in result.violations:
        if v.severity == Severity.ERROR:
            lines.append(f"::error title={v.rule}::{v.message}")
        elif v.severity == Severity.WARNING:
            lines.append(f"::warning title={v.rule}::{v.message}")
        else:
            lines.append(f"::notice title={v.rule}::{v.message}")
    return "\n".join(lines)
