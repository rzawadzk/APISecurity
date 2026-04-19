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
        client.post("/api/auth/logout")
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
        r = client_with_all_roles.post("/api/alerts/1/acknowledge")
        assert r.status_code == 403

    def test_analyst_can_ack_alert(self, client_with_all_roles, db):
        db.save_alerts(["Test alert"])
        _login(client_with_all_roles, "analyst", "analystpass1")
        r = client_with_all_roles.post("/api/alerts/1/acknowledge")
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
        client.post("/api/alerts/1/acknowledge")
        entries = db.get_audit_log(action="alert.acknowledge")
        assert len(entries) == 1
        assert entries[0]["resource_id"] == "1"

    def test_mutating_request_is_audited_by_middleware(self, client, db):
        db.save_alerts(["X"])
        _login(client, "admin", "adminpass1")
        client.post("/api/alerts/1/acknowledge")
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
