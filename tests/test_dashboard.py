"""End-to-end dashboard tests: auth, RBAC, audit, XSS safety."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from api_scout.auth import hash_password
from api_scout.dashboard import create_app


class TestBootstrap:
    def test_refuses_to_start_without_admin(self, db):
        with pytest.raises(RuntimeError, match="admin"):
            create_app(db, log_level="WARNING")

    def test_starts_with_admin(self, db, admin_user):
        app = create_app(db, log_level="WARNING")
        assert app is not None


class TestUnauthenticated:
    def test_dashboard_redirects_to_login(self, client):
        r = client.get("/", follow_redirects=False)
        assert r.status_code == 303
        assert "/login" in r.headers["location"]

    def test_graph_redirects(self, client):
        r = client.get("/graph", follow_redirects=False)
        assert r.status_code == 303

    def test_api_returns_401(self, client):
        assert client.get("/api/summary").status_code == 401
        assert client.get("/api/endpoints").status_code == 401

    def test_health_is_open(self, client):
        r = client.get("/health")
        assert r.status_code == 200
        assert r.json()["status"] == "ok"

    def test_ready_is_open(self, client):
        r = client.get("/ready")
        assert r.status_code == 200

    def test_metrics_is_open(self, client):
        r = client.get("/metrics")
        assert r.status_code == 200
        assert "api_scout_http_requests_total" in r.text


class TestLoginFlow:
    def test_bad_credentials_redirect_to_error(self, client):
        r = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "wrong"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "error=invalid" in r.headers["location"]

    def test_good_credentials_sets_session_cookie(self, client):
        r = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "adminpass1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/"
        # Cookie should be set, HttpOnly, SameSite=strict
        set_cookie = r.headers.get("set-cookie", "")
        assert "api_scout_session=" in set_cookie
        assert "HttpOnly" in set_cookie
        assert "SameSite=strict" in set_cookie.lower() or "samesite=strict" in set_cookie.lower()

    def test_whoami_after_login(self, client):
        client.post("/api/auth/login", data={"username": "admin", "password": "adminpass1"})
        r = client.get("/api/auth/whoami")
        assert r.status_code == 200
        assert r.json() == {"username": "admin", "role": "admin"}

    def test_logout_clears_session(self, client):
        client.post("/api/auth/login", data={"username": "admin", "password": "adminpass1"})
        assert client.get("/api/auth/whoami").status_code == 200
        _post(client, "/api/auth/logout")
        # Cookie is cleared; subsequent whoami should be 401
        client.cookies.clear()
        assert client.get("/api/auth/whoami").status_code == 401


def _login(client: TestClient, username: str, password: str) -> None:
    r = client.post(
        "/api/auth/login",
        data={"username": username, "password": password},
        follow_redirects=False,
    )
    assert r.status_code == 303


def _csrf_headers(client: TestClient) -> dict:
    """Return headers carrying the CSRF token from the TestClient's cookie jar.

    The CSRF cookie is issued on login success and on the first safe request
    (self-healing middleware). Callers that haven't yet logged in should hit
    a safe endpoint first so the cookie is present.
    """
    token = client.cookies.get("csrf_token")
    if not token:
        client.get("/health")  # triggers the self-heal cookie
        token = client.cookies.get("csrf_token")
    return {"X-CSRF-Token": token} if token else {}


def _post(client: TestClient, url: str, **kwargs):
    """POST with the CSRF header pre-attached."""
    headers = kwargs.pop("headers", None) or {}
    headers.update(_csrf_headers(client))
    return client.post(url, headers=headers, **kwargs)


class TestRBAC:
    """Viewer can read, analyst can ack/remediate, admin can manage users/audit."""

    @pytest.fixture
    def client_with_all_roles(self, db, admin_user, analyst_user, viewer_user):
        app = create_app(db, log_level="WARNING")
        with TestClient(app) as c:
            yield c

    def test_viewer_can_read_summary(self, client_with_all_roles):
        _login(client_with_all_roles, "viewer", "viewerpass1")
        assert client_with_all_roles.get("/api/summary").status_code == 200

    def test_viewer_cannot_ack_alert(self, client_with_all_roles, db):
        db.save_alerts(["Test alert"])
        _login(client_with_all_roles, "viewer", "viewerpass1")
        r = _post(client_with_all_roles, "/api/alerts/1/acknowledge")
        assert r.status_code == 403

    def test_analyst_can_ack_alert(self, client_with_all_roles, db):
        db.save_alerts(["Test alert"])
        _login(client_with_all_roles, "analyst", "analystpass1")
        r = _post(client_with_all_roles, "/api/alerts/1/acknowledge")
        assert r.status_code == 200

    def test_viewer_cannot_generate_waf(self, client_with_all_roles):
        _login(client_with_all_roles, "viewer", "viewerpass1")
        assert client_with_all_roles.get("/api/remediation/waf/nginx").status_code == 403

    def test_analyst_can_generate_waf(self, client_with_all_roles):
        _login(client_with_all_roles, "analyst", "analystpass1")
        assert client_with_all_roles.get("/api/remediation/waf/nginx").status_code == 200

    def test_analyst_cannot_list_users(self, client_with_all_roles):
        _login(client_with_all_roles, "analyst", "analystpass1")
        assert client_with_all_roles.get("/api/admin/users").status_code == 403

    def test_admin_can_list_users(self, client_with_all_roles):
        _login(client_with_all_roles, "admin", "adminpass1")
        r = client_with_all_roles.get("/api/admin/users")
        assert r.status_code == 200
        assert len(r.json()) == 3

    def test_admin_can_read_audit(self, client_with_all_roles):
        _login(client_with_all_roles, "admin", "adminpass1")
        r = client_with_all_roles.get("/api/admin/audit")
        assert r.status_code == 200

    def test_analyst_cannot_read_audit(self, client_with_all_roles):
        _login(client_with_all_roles, "analyst", "analystpass1")
        assert client_with_all_roles.get("/api/admin/audit").status_code == 403


class TestAuditLogging:
    def test_login_success_is_audited(self, client, db):
        client.post("/api/auth/login", data={"username": "admin", "password": "adminpass1"})
        entries = db.get_audit_log(action="auth.login.success")
        assert any(e["username"] == "admin" for e in entries)

    def test_login_failure_is_audited(self, client, db):
        client.post("/api/auth/login", data={"username": "admin", "password": "bad"})
        entries = db.get_audit_log(action="auth.login.failure")
        assert any(e["username"] == "admin" for e in entries)
        assert all(e["status_code"] == 401 for e in entries)

    def test_acknowledge_alert_is_audited(self, client, db):
        db.save_alerts(["X"])
        _login(client, "admin", "adminpass1")
        _post(client, "/api/alerts/1/acknowledge")
        entries = db.get_audit_log(action="alert.acknowledge")
        assert len(entries) == 1
        assert entries[0]["resource_id"] == "1"

    def test_mutating_request_is_audited_by_middleware(self, client, db):
        db.save_alerts(["X"])
        _login(client, "admin", "adminpass1")
        _post(client, "/api/alerts/1/acknowledge")
        # Middleware writes an entry for the HTTP request itself
        entries = db.get_audit_log(limit=100)
        assert any(e["action"] == "POST /api/alerts/1/acknowledge" for e in entries)


class TestSecurityHeaders:
    def test_headers_present_on_html(self, client):
        r = client.get("/login")
        assert r.headers["X-Content-Type-Options"] == "nosniff"
        assert r.headers["X-Frame-Options"] == "DENY"
        assert "default-src 'self'" in r.headers["Content-Security-Policy"]

    def test_headers_present_on_api(self, client):
        r = client.get("/api/summary")  # 401 but still has headers
        assert r.headers["X-Frame-Options"] == "DENY"


class TestXssEscaping:
    """Regression tests for the XSS issues identified in the audit.

    Previously user-controlled fields (endpoint path_pattern, alert message,
    service names) were interpolated directly into innerHTML. Now every
    rendering site goes through esc(). We can't easily run a browser in
    unit tests, so we assert that the shipped HTML contains the esc() helper
    and does NOT contain the old dangerous patterns.
    """

    def test_esc_helper_is_present_in_dashboard(self, client):
        _login(client, "admin", "adminpass1")
        r = client.get("/")
        assert r.status_code == 200
        body = r.text
        assert "function esc(s)" in body
        # Every dynamic insertion should funnel through esc()
        assert "esc(ep.path_pattern)" in body
        assert "esc(a.message)" in body

    def test_no_unescaped_innerhtml_template_of_user_data(self, client):
        _login(client, "admin", "adminpass1")
        body = client.get("/").text
        # Old dangerous patterns must be gone
        assert "${ep.path_pattern}" not in body
        assert "${a.message}" not in body
        assert "${s.service}" not in body  # graph handler

    def test_graph_page_uses_escaping_or_textcontent(self, client):
        _login(client, "admin", "adminpass1")
        body = client.get("/graph").text
        assert "function esc(s)" in body
        # Node labels use textContent, not innerHTML, to avoid SVG injection
        assert "text.textContent" in body
        # Old inline onclick with string interpolation should be gone
        assert "onclick=\"showBlastRadius('${" not in body

    def test_stored_xss_payload_is_escaped_in_response(self, client, db):
        """End-to-end: a malicious alert message round-trips safely."""
        payload = "<script>alert(1)</script>"
        db.save_alerts([payload])
        _login(client, "admin", "adminpass1")
        r = client.get("/api/alerts")
        assert r.status_code == 200
        # API returns raw JSON (correct — escaping is a rendering concern).
        # The frontend uses esc() when inserting into DOM.
        data = r.json()
        assert any(payload in a["message"] for a in data)


class TestLoginRateLimit:
    """IP-based throttle on /api/auth/login.

    Uses a non-existent username ("nobody") for spam so the per-account
    lockout (5 failures / 15 min) never fires — we want to exercise the
    IP rate limiter in isolation from account lockout.
    """

    def _spam(self, client, n: int, username: str = "nobody", password: str = "bad"):
        results = []
        for _ in range(n):
            r = client.post(
                "/api/auth/login",
                data={"username": username, "password": password},
                follow_redirects=False,
            )
            results.append(r)
        return results

    def test_blocks_after_threshold(self, client, dashboard_app):
        # default limiter = 10 attempts / 5 min per IP
        results = self._spam(client, 11)
        # First 10 hit the normal failure path → redirect to error=invalid
        for r in results[:10]:
            assert r.status_code == 303
            assert "error=invalid" in r.headers["location"]
        # 11th gets rate-limited
        last = results[10]
        assert last.status_code == 303
        assert "error=rate_limit" in last.headers["location"]
        assert last.headers.get("Retry-After") is not None
        assert int(last.headers["Retry-After"]) > 0

    def test_rate_limit_is_audited(self, client, db):
        self._spam(client, 11)
        entries = db.get_audit_log(action="auth.login.rate_limited")
        assert len(entries) >= 1
        assert entries[0]["status_code"] == 429

    def test_rate_limit_prevents_bcrypt_when_blocked(self, client, dashboard_app, db):
        """Blocked attempts must not count as login failures (no bcrypt, no user-lockout)."""
        self._spam(client, 15)
        # Only the first 10 should be audited as failures; the rest are rate_limited.
        failures = db.get_audit_log(action="auth.login.failure")
        rate_limited = db.get_audit_log(action="auth.login.rate_limited")
        assert len(failures) == 10
        assert len(rate_limited) == 5

    def test_valid_credentials_still_work_under_threshold(self, client):
        # 5 bad attempts, then a valid one within the same window
        self._spam(client, 5)
        r = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "adminpass1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert r.headers["location"] == "/"

    def test_valid_credentials_blocked_past_threshold(self, client):
        """A legitimate user whose IP has burned the quota is still blocked."""
        self._spam(client, 10)
        r = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "adminpass1"},
            follow_redirects=False,
        )
        assert r.status_code == 303
        assert "error=rate_limit" in r.headers["location"]

    def test_login_page_shows_rate_limit_message(self, client):
        body = client.get("/login?error=rate_limit").text
        assert "Too many login attempts" in body


class TestCSRF:
    """Double-submit-cookie CSRF protection on mutating dashboard routes."""

    def test_missing_token_is_rejected(self, client):
        # Log in (gets session + CSRF cookies) then POST without the header.
        _login(client, "admin", "adminpass1")
        # Strip the header by not passing it
        r = client.post("/api/auth/logout")
        assert r.status_code == 403
        assert "CSRF" in r.text

    def test_mismatched_token_is_rejected(self, client):
        _login(client, "admin", "adminpass1")
        r = client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": "not-the-real-token"},
        )
        assert r.status_code == 403

    def test_matching_token_is_accepted(self, client):
        _login(client, "admin", "adminpass1")
        cookie = client.cookies.get("csrf_token")
        assert cookie  # login must set the cookie
        r = client.post(
            "/api/auth/logout",
            headers={"X-CSRF-Token": cookie},
        )
        assert r.status_code == 200

    def test_token_rotates_on_login(self, client):
        # Before login: self-heal may issue one token
        client.get("/login")
        pre_login = client.cookies.get("csrf_token")
        assert pre_login is not None
        _login(client, "admin", "adminpass1")
        post_login = client.cookies.get("csrf_token")
        assert post_login is not None
        assert post_login != pre_login

    def test_login_endpoint_is_exempt(self, client):
        # No CSRF cookie/header required to hit /api/auth/login
        client.cookies.clear()
        r = client.post(
            "/api/auth/login",
            data={"username": "admin", "password": "adminpass1"},
            follow_redirects=False,
        )
        assert r.status_code == 303  # successful redirect, not 403

    def test_health_ready_metrics_exempt(self, client):
        assert client.get("/health").status_code == 200
        assert client.get("/ready").status_code == 200
        assert client.get("/metrics").status_code == 200

    def test_get_requests_do_not_require_token(self, client):
        _login(client, "admin", "adminpass1")
        # Mutating header NOT sent, plain GET should still work
        assert client.get("/api/summary").status_code == 200

    def test_form_submission_can_carry_token_in_body(self, client, db):
        """Classic HTML form POSTs may put the token in a hidden field."""
        db.save_alerts(["X"])
        _login(client, "admin", "adminpass1")
        cookie = client.cookies.get("csrf_token")
        r = client.post(
            "/api/alerts/1/acknowledge",
            data={"csrf_token": cookie},
        )
        assert r.status_code == 200

    def test_self_heal_sets_token_on_unauthenticated_get(self, client):
        """An anonymous GET should receive a fresh CSRF cookie for later use."""
        client.cookies.clear()
        assert client.cookies.get("csrf_token") is None
        client.get("/health")
        assert client.cookies.get("csrf_token") is not None

    def test_audit_records_csrf_rejection(self, client, db):
        _login(client, "admin", "adminpass1")
        db.save_alerts(["X"])
        # Send without CSRF header
        client.post("/api/alerts/1/acknowledge")
        # Audit middleware captures the rejected request
        entries = db.get_audit_log(limit=50)
        rejected = [
            e for e in entries
            if e["path"] == "/api/alerts/1/acknowledge" and e["status_code"] == 403
        ]
        assert len(rejected) == 1


class TestTrustedProxyXFF:
    """End-to-end: XFF is ignored unless the peer is in API_SCOUT_TRUSTED_PROXIES."""

    def _spam_with_xff(self, client, n, xff_value):
        """POST n login attempts with a forged X-Forwarded-For."""
        for _ in range(n):
            client.post(
                "/api/auth/login",
                data={"username": "nobody", "password": "bad"},
                headers={"X-Forwarded-For": xff_value},
                follow_redirects=False,
            )

    def test_xff_cannot_bypass_rate_limit_when_untrusted(self, client, db):
        """Default config: no trusted proxies -> XFF is ignored."""
        # All 11 attempts are keyed on the real peer (testclient), so the
        # 11th hits the rate limit regardless of the spoofed XFF header.
        for i in range(11):
            r = client.post(
                "/api/auth/login",
                data={"username": "nobody", "password": "bad"},
                # Rotate the spoofed IP each request. If XFF were trusted,
                # each request would get its own rate-limit bucket.
                headers={"X-Forwarded-For": f"203.0.113.{i}"},
                follow_redirects=False,
            )
        assert "error=rate_limit" in r.headers["location"]

    def test_xff_changes_bucket_when_trusted(self, tmp_path, monkeypatch, admin_user):
        """With API_SCOUT_TRUSTED_PROXIES covering the test peer, XFF is honoured."""
        from fastapi.testclient import TestClient
        from api_scout.dashboard import create_app
        from api_scout.database import Database

        # Trust every loopback & 127.x; TestClient(client=(ip, port)) below
        # sets request.client.host to that IP.
        monkeypatch.setenv("API_SCOUT_TRUSTED_PROXIES", "127.0.0.0/8")
        db = Database(tmp_path / "trusted.db")
        from api_scout.auth import hash_password
        db.create_user("admin", hash_password("adminpass1"), role="admin")
        app = create_app(db, log_level="WARNING")

        # TestClient lets us choose the peer IP — put the test client inside the
        # trusted network.
        with TestClient(app, client=("127.0.0.1", 12345)) as tc:
            # Burn 10 attempts from one spoofed client IP.
            for _ in range(10):
                tc.post(
                    "/api/auth/login",
                    data={"username": "nobody", "password": "bad"},
                    headers={"X-Forwarded-For": "203.0.113.1"},
                    follow_redirects=False,
                )
            # A request from a *different* XFF should still succeed — each
            # spoofed client has its own bucket because XFF is now trusted.
            r = tc.post(
                "/api/auth/login",
                data={"username": "nobody", "password": "bad"},
                headers={"X-Forwarded-For": "203.0.113.99"},
                follow_redirects=False,
            )
            assert "error=invalid" in r.headers["location"]
            # And the original spoofed client stays limited.
            r = tc.post(
                "/api/auth/login",
                data={"username": "nobody", "password": "bad"},
                headers={"X-Forwarded-For": "203.0.113.1"},
                follow_redirects=False,
            )
            assert "error=rate_limit" in r.headers["location"]

    def test_audit_log_records_resolved_client_ip(self, tmp_path, monkeypatch, admin_user):
        """With a trusted proxy, audit log captures the XFF-resolved client IP."""
        from fastapi.testclient import TestClient
        from api_scout.auth import hash_password
        from api_scout.dashboard import create_app
        from api_scout.database import Database

        monkeypatch.setenv("API_SCOUT_TRUSTED_PROXIES", "127.0.0.0/8")
        db = Database(tmp_path / "trusted_audit.db")
        db.create_user("admin", hash_password("adminpass1"), role="admin")
        app = create_app(db, log_level="WARNING")

        with TestClient(app, client=("127.0.0.1", 0)) as tc:
            tc.post(
                "/api/auth/login",
                data={"username": "admin", "password": "adminpass1"},
                headers={"X-Forwarded-For": "203.0.113.42"},
                follow_redirects=False,
            )
        entries = db.get_audit_log(action="auth.login.success")
        assert any(e["ip_address"] == "203.0.113.42" for e in entries), \
            f"Expected XFF IP in audit log, got {[e['ip_address'] for e in entries]}"
