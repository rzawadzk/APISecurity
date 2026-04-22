"""Unit tests for proxy.py — trusted-proxy XFF / XFP resolution."""
from __future__ import annotations

import ipaddress
from unittest.mock import MagicMock

import pytest

from api_scout.proxy import (
    ClientIPResolver,
    is_trusted,
    parse_trusted_proxies,
)


# ── parse_trusted_proxies ──

class TestParse:
    def test_empty_returns_empty_list(self):
        assert parse_trusted_proxies(None) == []
        assert parse_trusted_proxies("") == []
        assert parse_trusted_proxies("   ") == []

    def test_single_ip(self):
        nets = parse_trusted_proxies("10.0.0.1")
        assert len(nets) == 1
        assert nets[0] == ipaddress.ip_network("10.0.0.1/32")

    def test_single_cidr(self):
        nets = parse_trusted_proxies("192.168.1.0/24")
        assert nets[0] == ipaddress.ip_network("192.168.1.0/24")

    def test_mixed(self):
        nets = parse_trusted_proxies("10.0.0.1,172.16.0.0/12 , 192.168.0.0/16")
        assert len(nets) == 3
        assert ipaddress.ip_address("172.20.5.1") in nets[1]
        assert ipaddress.ip_address("192.168.100.50") in nets[2]

    def test_ipv6(self):
        nets = parse_trusted_proxies("::1,2001:db8::/32")
        assert ipaddress.ip_address("::1") in nets[0]
        assert ipaddress.ip_address("2001:db8::1") in nets[1]

    def test_invalid_token_raises(self):
        with pytest.raises(ValueError, match="API_SCOUT_TRUSTED_PROXIES"):
            parse_trusted_proxies("not-an-ip")

    def test_host_bits_set_does_not_raise(self):
        """CIDRs with host bits set are silently normalised (strict=False)."""
        nets = parse_trusted_proxies("10.0.0.5/24")
        assert nets[0] == ipaddress.ip_network("10.0.0.0/24")


# ── is_trusted ──

class TestIsTrusted:
    def test_hit(self):
        trusted = parse_trusted_proxies("10.0.0.0/8")
        assert is_trusted("10.5.5.5", trusted)

    def test_miss(self):
        trusted = parse_trusted_proxies("10.0.0.0/8")
        assert not is_trusted("192.168.1.1", trusted)

    def test_empty_trust_list_rejects_everything(self):
        assert not is_trusted("10.0.0.1", [])
        assert not is_trusted("::1", [])

    def test_none_peer(self):
        assert not is_trusted(None, parse_trusted_proxies("10.0.0.0/8"))

    def test_invalid_peer_string(self):
        """Hostnames (e.g. 'testclient' from TestClient) are not trusted."""
        assert not is_trusted("testclient", parse_trusted_proxies("10.0.0.0/8"))


# ── ClientIPResolver ──

def _fake_request(peer_ip=None, headers=None, scheme="http"):
    """Construct a minimal object that looks enough like a FastAPI Request."""
    req = MagicMock()
    req.client = MagicMock(host=peer_ip) if peer_ip else None
    req.headers = headers or {}
    url = MagicMock()
    url.scheme = scheme
    req.url = url
    return req


class TestResolver:
    def test_no_trust_list_ignores_xff(self):
        r = ClientIPResolver(trusted_proxies=[])
        req = _fake_request("10.0.0.1", {"x-forwarded-for": "203.0.113.5"})
        res = r.resolve(req)
        assert res.ip == "10.0.0.1"

    def test_trusted_peer_uses_xff_leftmost(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("10.0.0.1", {"x-forwarded-for": "203.0.113.5, 10.1.2.3"})
        assert r.resolve(req).ip == "203.0.113.5"

    def test_trusted_peer_no_xff_keeps_peer(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("10.0.0.1", {})
        assert r.resolve(req).ip == "10.0.0.1"

    def test_untrusted_peer_ignores_xff(self):
        """The whole point: an attacker at 1.2.3.4 cannot spoof 9.9.9.9."""
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("1.2.3.4", {"x-forwarded-for": "9.9.9.9"})
        assert r.resolve(req).ip == "1.2.3.4"

    def test_no_client_returns_none_ip(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request(None, {"x-forwarded-for": "9.9.9.9"})
        assert r.resolve(req).ip is None

    def test_xfp_https_when_peer_trusted(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("10.0.0.1", {"x-forwarded-proto": "https"})
        assert r.resolve(req).tls is True

    def test_xfp_ignored_when_peer_untrusted(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("1.2.3.4", {"x-forwarded-proto": "https"})
        assert r.resolve(req).tls is False

    def test_scheme_https_sets_tls_without_xfp(self):
        r = ClientIPResolver(trusted_proxies=[])
        req = _fake_request("1.2.3.4", scheme="https")
        assert r.resolve(req).tls is True

    def test_empty_xff_value_falls_back_to_peer(self):
        r = ClientIPResolver(parse_trusted_proxies("10.0.0.0/8"))
        req = _fake_request("10.0.0.1", {"x-forwarded-for": "   "})
        assert r.resolve(req).ip == "10.0.0.1"

    def test_from_env_reads_env_var(self, monkeypatch):
        monkeypatch.setenv("API_SCOUT_TRUSTED_PROXIES", "192.168.0.0/16")
        r = ClientIPResolver.from_env()
        assert len(r.trusted) == 1
        assert ipaddress.ip_address("192.168.1.1") in r.trusted[0]

    def test_from_env_unset_empty_trust(self, monkeypatch):
        monkeypatch.delenv("API_SCOUT_TRUSTED_PROXIES", raising=False)
        r = ClientIPResolver.from_env()
        assert r.trusted == []

    def test_trust_forwarded_proto_disabled(self):
        r = ClientIPResolver(
            parse_trusted_proxies("10.0.0.0/8"),
            trust_forwarded_proto=False,
        )
        req = _fake_request("10.0.0.1", {"x-forwarded-proto": "https"})
        assert r.resolve(req).tls is False
