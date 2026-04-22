"""Trusted-proxy handling for X-Forwarded-For / X-Forwarded-Proto.

Problem: when API Scout sits behind a reverse proxy (nginx, ALB, Cloudflare),
the TCP peer of every request is the proxy, not the real client. If we use
`request.client.host` as "the client IP," every audit entry and every
rate-limit bucket is keyed on the proxy — which lumps the whole world
into a single bucket.

The fix is to honour ``X-Forwarded-For`` — but only when the request came
from a proxy we actually trust, because anyone can set that header
themselves.

Configuration: ``API_SCOUT_TRUSTED_PROXIES`` is a comma-separated list of
IPs or CIDRs. Examples::

    API_SCOUT_TRUSTED_PROXIES="10.0.0.1"
    API_SCOUT_TRUSTED_PROXIES="10.0.0.1,172.16.0.0/12"

Resolution rules:

  1. If the TCP peer is **not** in the trust list → ignore XFF entirely
     and use ``request.client.host`` as the client IP. This is the
     safe-by-default behaviour when the env var is unset or empty.
  2. If the TCP peer **is** in the trust list → take the leftmost entry
     from XFF as the client IP. This handles the common single-proxy
     case correctly. For multi-hop chains, configure the outermost
     proxy to sanitise/replace XFF.
  3. ``X-Forwarded-Proto`` is also honoured (for cookie-``Secure``
     inference) only when the peer is trusted.

Residual risk: if you add a proxy to this list that itself honours
unvalidated upstream XFF headers, an attacker can spoof the client IP
end-to-end. Operators are responsible for ensuring trusted proxies
rewrite, not append, the XFF header.
"""
from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass
from typing import Iterable, List, Optional, Union

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware

IPNetwork = Union[ipaddress.IPv4Network, ipaddress.IPv6Network]

ENV_VAR = "API_SCOUT_TRUSTED_PROXIES"


def parse_trusted_proxies(value: Optional[str]) -> List[IPNetwork]:
    """Parse a comma-separated list of IPs/CIDRs into networks.

    Bare IPs are widened to single-host networks (/32 for v4, /128 for v6).
    Raises ValueError on any invalid token — we'd rather fail fast at
    startup than silently ignore a misconfigured trust entry.
    """
    if not value:
        return []
    nets: List[IPNetwork] = []
    for raw in value.split(","):
        token = raw.strip()
        if not token:
            continue
        try:
            nets.append(ipaddress.ip_network(token, strict=False))
        except ValueError as exc:
            raise ValueError(f"Invalid entry in {ENV_VAR}: {token!r} ({exc})") from exc
    return nets


def is_trusted(peer_ip: Optional[str], trusted: Iterable[IPNetwork]) -> bool:
    if not peer_ip:
        return False
    try:
        addr = ipaddress.ip_address(peer_ip)
    except ValueError:
        return False
    return any(addr in net for net in trusted)


@dataclass(frozen=True)
class ResolvedPeer:
    ip: Optional[str]
    tls: bool


class ClientIPResolver:
    """Resolve the real client IP + TLS state for an incoming request."""

    def __init__(
        self,
        trusted_proxies: Iterable[IPNetwork],
        *,
        trust_forwarded_proto: bool = True,
    ):
        self.trusted = list(trusted_proxies)
        self.trust_forwarded_proto = trust_forwarded_proto

    def resolve(self, request: Request) -> ResolvedPeer:
        peer = request.client.host if request.client else None
        tls = request.url.scheme == "https"

        if peer and is_trusted(peer, self.trusted):
            xff = request.headers.get("x-forwarded-for")
            if xff:
                candidate = xff.split(",")[0].strip()
                if candidate:
                    peer = candidate
            if self.trust_forwarded_proto:
                xfp = request.headers.get("x-forwarded-proto", "").lower().strip()
                if xfp == "https":
                    tls = True

        return ResolvedPeer(ip=peer, tls=tls)

    @classmethod
    def from_env(cls, env_name: str = ENV_VAR) -> "ClientIPResolver":
        return cls(parse_trusted_proxies(os.environ.get(env_name)))


class ClientIPMiddleware(BaseHTTPMiddleware):
    """Stash the resolved client IP + TLS state on ``request.state``.

    Must be installed as the outermost middleware so the populated state
    is visible to every downstream middleware and route handler.
    """

    def __init__(self, app, resolver: ClientIPResolver):
        super().__init__(app)
        self.resolver = resolver

    async def dispatch(self, request: Request, call_next):
        resolved = self.resolver.resolve(request)
        request.state.client_ip = resolved.ip
        request.state.tls = resolved.tls
        return await call_next(request)


# Convenience accessor for route handlers.
def client_ip_of(request: Request) -> Optional[str]:
    return getattr(request.state, "client_ip", None) or (
        request.client.host if request.client else None
    )


def tls_of(request: Request) -> bool:
    return bool(getattr(request.state, "tls", False))
