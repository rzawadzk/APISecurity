"""Active network scanner — discovers HTTP services and OpenAPI specs."""

from __future__ import annotations

import asyncio
import ipaddress
import socket
from datetime import datetime
from typing import Optional

import httpx

from .models import APIEndpoint, APIStatus, DiscoverySource, ScanResult


# Common ports for HTTP/API services
DEFAULT_PORTS = [80, 443, 8080, 8443, 3000, 5000, 8000, 8888, 9090, 4000]

# Common OpenAPI/Swagger spec paths
OPENAPI_PATHS = [
    "/openapi.json",
    "/openapi.yaml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api/docs",
    "/docs/openapi.json",
    "/api-docs",
    "/.well-known/openapi.json",
]


async def check_port(host: str, port: int, timeout: float = 2.0) -> bool:
    """Check if a TCP port is open."""
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        return True
    except (asyncio.TimeoutError, OSError):
        return False


async def check_http(
    client: httpx.AsyncClient, url: str, timeout: float = 5.0
) -> tuple[bool, int]:
    """Check if a URL responds to HTTP."""
    try:
        resp = await client.get(url, timeout=timeout, follow_redirects=True)
        return True, resp.status_code
    except (httpx.HTTPError, Exception):
        return False, 0


async def discover_openapi_spec(
    client: httpx.AsyncClient, base_url: str
) -> Optional[dict]:
    """Try to find and fetch an OpenAPI spec from common paths."""
    for path in OPENAPI_PATHS:
        url = f"{base_url}{path}"
        try:
            resp = await client.get(url, timeout=5.0, follow_redirects=True)
            if resp.status_code == 200:
                content_type = resp.headers.get("content-type", "")
                if "json" in content_type or "yaml" in content_type or "yml" in content_type:
                    try:
                        return {"url": url, "spec": resp.json()}
                    except Exception:
                        pass
        except (httpx.HTTPError, Exception):
            continue
    return None


def extract_endpoints_from_spec(spec: dict, host: str) -> list[APIEndpoint]:
    """Extract API endpoints from an OpenAPI spec."""
    endpoints = []
    paths = spec.get("paths", {})
    now = datetime.now()

    for path, methods in paths.items():
        for method in ("get", "post", "put", "patch", "delete", "head", "options"):
            if method in methods:
                operation = methods[method]
                deprecated = operation.get("deprecated", False)

                endpoints.append(APIEndpoint(
                    method=method.upper(),
                    path_pattern=path,
                    host=host,
                    status=APIStatus.DEPRECATED if deprecated else APIStatus.ACTIVE,
                    declared_in_spec=True,
                    first_seen=now,
                    last_seen=now,
                    discovery_sources=[DiscoverySource.SCAN_OPENAPI],
                ))

    return endpoints


async def scan_host(host: str, ports: list[int] | None = None) -> list[ScanResult]:
    """Scan a single host for HTTP services and OpenAPI specs."""
    ports = ports or DEFAULT_PORTS
    results = []

    # Check which ports are open
    open_ports = []
    port_checks = await asyncio.gather(
        *[check_port(host, port) for port in ports]
    )
    for port, is_open in zip(ports, port_checks):
        if is_open:
            open_ports.append(port)

    if not open_ports:
        return results

    async with httpx.AsyncClient(verify=False) as client:
        for port in open_ports:
            for scheme in ("https", "http"):
                base_url = f"{scheme}://{host}:{port}"
                is_http, status = await check_http(client, base_url)

                if not is_http:
                    continue

                result = ScanResult(
                    host=host,
                    port=port,
                    is_http=True,
                    scanned_at=datetime.now(),
                )

                # Try to discover OpenAPI spec
                spec_result = await discover_openapi_spec(client, base_url)
                if spec_result:
                    result.openapi_spec_url = spec_result["url"]
                    result.openapi_spec = spec_result["spec"]
                    result.endpoints_found = extract_endpoints_from_spec(
                        spec_result["spec"], host
                    )

                results.append(result)
                break  # Found working scheme, skip the other

    return results


async def scan_network(
    targets: list[str],
    ports: list[int] | None = None,
    concurrency: int = 20,
) -> list[ScanResult]:
    """Scan multiple hosts/CIDRs for HTTP services.

    Args:
        targets: List of hostnames, IPs, or CIDR ranges (e.g. "192.168.1.0/24")
        ports: Ports to scan (defaults to common HTTP ports)
        concurrency: Max concurrent host scans
    """
    # Expand CIDR ranges
    hosts = []
    for target in targets:
        try:
            network = ipaddress.ip_network(target, strict=False)
            hosts.extend(str(ip) for ip in network.hosts())
        except ValueError:
            hosts.append(target)

    # Scan with concurrency limit
    semaphore = asyncio.Semaphore(concurrency)
    all_results = []

    async def _scan_with_limit(host: str) -> list[ScanResult]:
        async with semaphore:
            return await scan_host(host, ports)

    task_results = await asyncio.gather(
        *[_scan_with_limit(h) for h in hosts],
        return_exceptions=True,
    )

    for result in task_results:
        if isinstance(result, list):
            all_results.extend(result)

    return all_results
