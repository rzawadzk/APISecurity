"""Web dashboard — FastAPI backend with embedded HTML frontend.

Security model:
  - Every browser-facing route requires an authenticated session.
  - Mutating routes additionally enforce a minimum role (analyst or admin).
  - Every login attempt and every mutation is recorded in audit_log.
  - User-controlled strings are escaped at the JS layer (esc()) before being
    inserted into the DOM. Click handlers use data-attributes + delegated
    listeners (no string interpolation into JS literals).

Bootstrap:
  - On startup the app refuses to serve traffic unless at least one
    user with role 'admin' exists. Create one with:
       api-scout user create --role admin <username>
"""
from __future__ import annotations

import json
from typing import Optional

from fastapi import Depends, FastAPI, Form, HTTPException, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.middleware.base import BaseHTTPMiddleware

from .auth import (
    SESSION_COOKIE_NAME,
    SESSION_TTL_HOURS,
    AuthenticatedUser,
    Role,
    SessionManager,
    authenticate,
    get_current_user,
    get_optional_user,
    get_or_create_secret,
    require_admin,
    require_analyst,
    require_viewer,
)
from .database import Database
from .models import APIStatus
from .observability import (
    LOGIN_ATTEMPTS,
    PrometheusMiddleware,
    configure_logging,
    get_logger,
    liveness,
    metrics_endpoint,
    readiness,
)


log = get_logger(__name__)


def create_app(database: Database, *, log_level: str = "INFO") -> FastAPI:
    """Build the FastAPI app, attach DB + session manager + middleware."""
    configure_logging(log_level)

    # Refuse to start if no admin exists. Operators must bootstrap one via CLI.
    admins = [u for u in database.list_users() if u["role"] == Role.ADMIN.value and u["is_active"]]
    if not admins:
        raise RuntimeError(
            "No active admin user exists. Bootstrap with:\n"
            "    api-scout user create --role admin <username>"
        )

    secret = get_or_create_secret(database)

    app = FastAPI(title="API Scout Dashboard", version="0.2.0", docs_url=None, redoc_url=None)
    app.state.db = database
    app.state.session_manager = SessionManager(database, secret)

    app.add_middleware(PrometheusMiddleware)
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(AuditMiddleware, db=database)

    _register_routes(app)
    return app


# Module-level handle used by route handlers (set by _register_routes via closure)
def _db_dep(request: Request) -> Database:
    return request.app.state.db


# ── Security headers + audit middleware ──

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """Apply baseline security headers to every response."""

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        # CSP: only same-origin scripts + inline styles (we ship inline CSS).
        # No remote scripts at all.
        resp.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline'; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "object-src 'none'; "
            "base-uri 'self'; "
            "frame-ancestors 'none'"
        )
        resp.headers["Permissions-Policy"] = "geolocation=(), microphone=(), camera=()"
        return resp


class AuditMiddleware(BaseHTTPMiddleware):
    """Audit-log every mutating request (POST/PUT/PATCH/DELETE) and login attempts."""

    AUDITED_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
    SKIP_PATHS = {"/api/auth/login", "/health", "/ready", "/metrics"}

    def __init__(self, app, db: Database):
        super().__init__(app)
        self.db = db

    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        if request.method not in self.AUDITED_METHODS:
            return resp
        if request.url.path in self.SKIP_PATHS:
            return resp
        user = getattr(request.state, "user", None)
        try:
            self.db.write_audit(
                action=f"{request.method} {request.url.path}",
                user_id=user.id if user else None,
                username=user.username if user else None,
                method=request.method,
                path=request.url.path,
                ip_address=_client_ip(request),
                user_agent=request.headers.get("user-agent"),
                status_code=resp.status_code,
            )
        except Exception as exc:  # don't break the request on audit failure
            log.warning("audit_write_failed", extra={"error": str(exc), "path": request.url.path})
        return resp


def _client_ip(request: Request) -> Optional[str]:
    fwd = request.headers.get("x-forwarded-for")
    if fwd:
        return fwd.split(",")[0].strip()
    return request.client.host if request.client else None


# ── Routes ──

def _register_routes(app: FastAPI) -> None:

    # Health & ops (unauthenticated by design)
    @app.get("/health")
    async def health():
        return liveness()

    @app.get("/ready")
    async def ready(request: Request):
        payload, code = readiness(request.app.state.db)
        return JSONResponse(payload, status_code=code)

    @app.get("/metrics")
    async def metrics(request: Request):
        return metrics_endpoint(request.app.state.db)

    # ── Auth ──

    @app.get("/login", response_class=HTMLResponse)
    async def login_page(error: Optional[str] = None):
        # `error` is reflected as a query param. Keep the allowlist small to avoid XSS.
        safe_error = ""
        if error == "invalid":
            safe_error = "Invalid username or password."
        elif error == "locked":
            safe_error = "Account locked. Try again in 15 minutes."
        elif error == "expired":
            safe_error = "Session expired. Please sign in again."
        return LOGIN_HTML.replace("{{ERROR}}", safe_error)

    @app.post("/api/auth/login")
    async def login_submit(
        request: Request,
        username: str = Form(...),
        password: str = Form(...),
    ):
        db: Database = request.app.state.db
        sm: SessionManager = request.app.state.session_manager
        ip = _client_ip(request)
        ua = request.headers.get("user-agent")

        user = authenticate(db, username, password)
        if not user:
            LOGIN_ATTEMPTS.labels(result="failure").inc()
            db.write_audit(
                action="auth.login.failure",
                username=username,
                ip_address=ip,
                user_agent=ua,
                status_code=401,
            )
            return RedirectResponse("/login?error=invalid", status_code=303)

        signed_cookie, expires_at = sm.create(user["id"], user_agent=ua, ip_address=ip)
        LOGIN_ATTEMPTS.labels(result="success").inc()
        db.write_audit(
            action="auth.login.success",
            user_id=user["id"],
            username=user["username"],
            ip_address=ip,
            user_agent=ua,
            status_code=200,
        )
        resp = RedirectResponse("/", status_code=303)
        resp.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=signed_cookie,
            max_age=SESSION_TTL_HOURS * 3600,
            httponly=True,
            secure=False,  # set True behind TLS-terminating proxy in prod
            samesite="strict",
            path="/",
        )
        return resp

    @app.post("/api/auth/logout")
    async def logout(request: Request, user: AuthenticatedUser = Depends(get_current_user)):
        sm: SessionManager = request.app.state.session_manager
        cookie = request.cookies.get(SESSION_COOKIE_NAME)
        if cookie:
            sm.revoke(cookie)
        request.app.state.db.write_audit(
            action="auth.logout",
            user_id=user.id,
            username=user.username,
            ip_address=_client_ip(request),
            user_agent=request.headers.get("user-agent"),
            status_code=200,
        )
        resp = JSONResponse({"status": "ok"})
        resp.delete_cookie(SESSION_COOKIE_NAME, path="/")
        return resp

    @app.get("/api/auth/whoami")
    async def whoami(user: AuthenticatedUser = Depends(get_current_user)):
        return {"username": user.username, "role": user.role}

    # ── Pages ──

    @app.get("/", response_class=HTMLResponse)
    async def dashboard_page(request: Request, user: Optional[AuthenticatedUser] = Depends(get_optional_user)):
        if user is None:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(DASHBOARD_HTML)

    @app.get("/graph", response_class=HTMLResponse)
    async def graph_page(user: Optional[AuthenticatedUser] = Depends(get_optional_user)):
        if user is None:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(GRAPH_HTML)

    @app.get("/audit", response_class=HTMLResponse)
    async def audit_page(user: Optional[AuthenticatedUser] = Depends(get_optional_user)):
        if user is None:
            return RedirectResponse("/login", status_code=303)
        return HTMLResponse(AUDIT_HTML)

    # ── Read-only API (any authenticated user) ──

    @app.get("/api/summary")
    async def api_summary(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        return request.app.state.db.get_dashboard_summary()

    @app.get("/api/endpoints")
    async def api_endpoints(
        request: Request,
        status: Optional[str] = None,
        search: Optional[str] = None,
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        db = request.app.state.db
        if search:
            endpoints = db.search_endpoints(search)
        elif status:
            try:
                endpoints = db.get_endpoints_by_status(APIStatus(status))
            except ValueError:
                raise HTTPException(400, "invalid status")
        else:
            endpoints = db.get_all_endpoints()
        return [ep.model_dump(mode="json") for ep in endpoints]

    @app.get("/api/endpoints/{endpoint_id}")
    async def api_endpoint_detail(
        request: Request,
        endpoint_id: str,
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        ep = request.app.state.db.get_endpoint(endpoint_id)
        if not ep:
            return JSONResponse({"error": "Not found"}, status_code=404)
        return ep.model_dump(mode="json")

    @app.get("/api/traffic/stats")
    async def api_traffic_stats(
        request: Request,
        hours: int = Query(default=24, ge=1, le=720),
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        return request.app.state.db.get_traffic_stats(hours)

    @app.get("/api/traffic/timeline")
    async def api_traffic_timeline(
        request: Request,
        hours: int = Query(default=24, ge=1, le=720),
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        return request.app.state.db.get_traffic_timeline(hours)

    @app.get("/api/alerts")
    async def api_alerts(
        request: Request,
        unacknowledged: bool = Query(default=False),
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        return request.app.state.db.get_alerts(unacknowledged_only=unacknowledged)

    @app.get("/api/scans")
    async def api_scan_history(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        return request.app.state.db.get_scan_history()

    # ── Mutations (analyst+) ──

    @app.post("/api/alerts/{alert_id}/acknowledge")
    async def api_acknowledge_alert(
        request: Request,
        alert_id: int,
        user: AuthenticatedUser = Depends(require_analyst),
    ):
        request.app.state.db.acknowledge_alert(alert_id)
        request.app.state.db.write_audit(
            action="alert.acknowledge",
            user_id=user.id,
            username=user.username,
            resource_type="alert",
            resource_id=str(alert_id),
            ip_address=_client_ip(request),
        )
        return {"status": "ok"}

    # ── Dependency Graph API ──

    @app.get("/api/graph")
    async def api_dependency_graph(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        from .graph import DependencyGraph
        graph = DependencyGraph()
        graph.build_from_database(request.app.state.db)
        return graph.to_dict()

    @app.get("/api/graph/blast-radius/{service_name}")
    async def api_blast_radius(
        request: Request,
        service_name: str,
        _: AuthenticatedUser = Depends(require_viewer),
    ):
        from .graph import DependencyGraph
        graph = DependencyGraph()
        graph.build_from_database(request.app.state.db)
        return graph.blast_radius(service_name)

    @app.get("/api/graph/critical-paths")
    async def api_critical_paths(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        from .graph import DependencyGraph
        graph = DependencyGraph()
        graph.build_from_database(request.app.state.db)
        return {
            "critical_services": [n.to_dict() for n in graph.find_critical_paths()],
            "spofs": graph.find_single_points_of_failure(),
            "orphaned": [n.to_dict() for n in graph.find_orphaned_services()],
        }

    @app.get("/api/graph/d3")
    async def api_graph_d3(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        from .graph import DependencyGraph
        graph = DependencyGraph()
        graph.build_from_database(request.app.state.db)
        return json.loads(graph.to_d3_json())

    @app.get("/api/graph/mermaid")
    async def api_graph_mermaid(request: Request, _: AuthenticatedUser = Depends(require_viewer)):
        from .graph import DependencyGraph
        graph = DependencyGraph()
        graph.build_from_database(request.app.state.db)
        return {"mermaid": graph.to_mermaid()}

    # ── Remediation API (analyst+) ──

    @app.get("/api/remediation/waf/nginx")
    async def api_waf_nginx(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
        from .remediation import WAFRuleGenerator
        return {"rules": WAFRuleGenerator(request.app.state.db).generate_nginx_rules()}

    @app.get("/api/remediation/waf/modsecurity")
    async def api_waf_modsecurity(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
        from .remediation import WAFRuleGenerator
        return {"rules": WAFRuleGenerator(request.app.state.db).generate_modsecurity_rules()}

    @app.get("/api/remediation/waf/aws")
    async def api_waf_aws(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
        from .remediation import WAFRuleGenerator
        return WAFRuleGenerator(request.app.state.db).generate_aws_waf_rules()

    @app.get("/api/remediation/spec")
    async def api_generate_spec(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
        from .remediation import SpecGenerator
        return SpecGenerator(request.app.state.db).generate_spec()

    @app.get("/api/remediation/spec/undocumented")
    async def api_generate_spec_undocumented(request: Request, _: AuthenticatedUser = Depends(require_analyst)):
        from .remediation import SpecGenerator
        return SpecGenerator(request.app.state.db).generate_for_undocumented()

    # ── Admin API: users + audit log ──

    @app.get("/api/admin/users")
    async def admin_list_users(request: Request, _: AuthenticatedUser = Depends(require_admin)):
        return request.app.state.db.list_users()

    @app.get("/api/admin/audit")
    async def admin_audit_log(
        request: Request,
        limit: int = Query(default=200, ge=1, le=1000),
        action: Optional[str] = None,
        username: Optional[str] = None,
        _: AuthenticatedUser = Depends(require_admin),
    ):
        return request.app.state.db.get_audit_log(limit=limit, action=action, username=username)


# ── HTML ──
# Important: every dynamic value rendered into the DOM goes through esc().
# Click handlers use data-* attributes + addEventListener — no string
# interpolation of user-controlled data into onclick="" or JS literals.

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>Sign in — API Scout</title>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --border:#2e3245; --text:#e4e6f0; --dim:#8b8fa3; --accent:#6c8cff; --red:#f87171; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; background: var(--bg); color: var(--text); min-height:100vh; display:flex; align-items:center; justify-content:center; }
.card { background: var(--surface); border:1px solid var(--border); border-radius:12px; padding:32px; width:360px; }
.card h1 { font-size:20px; margin-bottom:24px; display:flex; align-items:center; gap:8px; }
label { display:block; font-size:12px; color:var(--dim); text-transform:uppercase; letter-spacing:.5px; margin-bottom:6px; margin-top:14px; }
input { width:100%; background:#242736; border:1px solid var(--border); border-radius:8px; padding:10px 12px; color:var(--text); font-size:14px; outline:none; }
input:focus { border-color: var(--accent); }
button { width:100%; margin-top:20px; background:var(--accent); color:white; border:none; border-radius:8px; padding:12px; font-size:14px; font-weight:600; cursor:pointer; }
.error { color: var(--red); font-size:13px; margin-top:14px; min-height:18px; }
.hint { color: var(--dim); font-size:11px; margin-top:18px; line-height:1.5; }
</style>
</head>
<body>
<form class="card" method="POST" action="/api/auth/login">
  <h1>🔍 API Scout</h1>
  <label for="username">Username</label>
  <input id="username" name="username" type="text" autocomplete="username" required autofocus>
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password" required>
  <button type="submit">Sign in</button>
  <div class="error">{{ERROR}}</div>
  <div class="hint">Bootstrap an admin with <code>api-scout user create --role admin &lt;username&gt;</code></div>
</form>
</body>
</html>
"""


# Common JS helpers shared across pages — escapes everything that touches the DOM.
_JS_HELPERS = """
function esc(s) {
  return String(s == null ? '' : s).replace(/[&<>"'`=\\/]/g, c => ({
    '&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;','`':'&#96;','=':'&#61;','/':'&#47;'
  }[c]));
}
async function fetchJSON(url, opts) {
  const resp = await fetch(url, opts);
  if (resp.status === 401) { window.location.href = '/login?error=expired'; throw new Error('unauth'); }
  if (resp.status === 403) { throw new Error('forbidden'); }
  return resp.json();
}
async function whoami() { try { return await fetchJSON('/api/auth/whoami'); } catch { return null; } }
async function logout() {
  try { await fetch('/api/auth/logout', { method: 'POST' }); } catch {}
  window.location.href = '/login';
}
"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Scout Dashboard</title>
<style>
:root {
  --bg:#0f1117; --surface:#1a1d27; --surface2:#242736; --border:#2e3245;
  --text:#e4e6f0; --text-dim:#8b8fa3; --accent:#6c8cff; --green:#4ade80;
  --red:#f87171; --yellow:#fbbf24; --cyan:#22d3ee; --purple:#a78bfa;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif; background:var(--bg); color:var(--text); min-height:100vh; }
.header { background:var(--surface); border-bottom:1px solid var(--border); padding:16px 32px; display:flex; align-items:center; justify-content:space-between; }
.header h1 { font-size:20px; font-weight:600; display:flex; align-items:center; gap:10px; }
.header .logo { font-size:24px; }
.header-actions { display:flex; gap:12px; align-items:center; }
.search-box { background:var(--surface2); border:1px solid var(--border); border-radius:8px; padding:8px 14px; color:var(--text); font-size:14px; width:280px; outline:none; }
.search-box:focus { border-color:var(--accent); }
.refresh-btn, .logout-btn { background:var(--accent); color:white; border:none; border-radius:8px; padding:8px 16px; font-size:14px; cursor:pointer; font-weight:500; }
.logout-btn { background: var(--surface2); color: var(--text-dim); border: 1px solid var(--border); }
.refresh-btn:hover { opacity:0.9; }
.user-pill { background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:4px 10px; font-size:12px; color:var(--text-dim); }
.container { max-width:1400px; margin:0 auto; padding:24px 32px; }
.stats-grid { display:grid; grid-template-columns:repeat(auto-fit, minmax(180px, 1fr)); gap:16px; margin-bottom:24px; }
.stat-card { background:var(--surface); border:1px solid var(--border); border-radius:12px; padding:20px; text-align:center; }
.stat-card .value { font-size:32px; font-weight:700; line-height:1.2; }
.stat-card .label { font-size:12px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px; margin-top:4px; }
.stat-card.total .value { color:var(--accent); }
.stat-card.active .value { color:var(--green); }
.stat-card.shadow .value { color:var(--red); }
.stat-card.zombie .value { color:var(--yellow); }
.stat-card.unauth .value { color:var(--purple); }
.stat-card.alerts .value { color:var(--red); }
.panels { display:grid; grid-template-columns:1fr 1fr; gap:20px; margin-bottom:24px; }
.panel { background:var(--surface); border:1px solid var(--border); border-radius:12px; overflow:hidden; }
.panel-full { grid-column:1 / -1; }
.panel-header { padding:16px 20px; border-bottom:1px solid var(--border); display:flex; align-items:center; justify-content:space-between; }
.panel-header h2 { font-size:15px; font-weight:600; }
.panel-body { padding:16px 20px; }
.filter-tabs { display:flex; gap:8px; }
.filter-tab { background:var(--surface2); border:1px solid var(--border); border-radius:6px; padding:4px 12px; font-size:12px; color:var(--text-dim); cursor:pointer; }
.filter-tab.active { background:var(--accent); color:white; border-color:var(--accent); }
table { width:100%; border-collapse:collapse; font-size:13px; }
th { text-align:left; padding:10px 12px; color:var(--text-dim); font-weight:500; font-size:11px; text-transform:uppercase; letter-spacing:0.5px; border-bottom:1px solid var(--border); }
td { padding:10px 12px; border-bottom:1px solid var(--border); vertical-align:middle; }
tr:last-child td { border-bottom:none; }
tr:hover { background:var(--surface2); }
.badge { display:inline-block; padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; text-transform:uppercase; }
.badge-active { background:rgba(74,222,128,0.15); color:var(--green); }
.badge-shadow { background:rgba(248,113,113,0.15); color:var(--red); }
.badge-zombie { background:rgba(251,191,36,0.15); color:var(--yellow); }
.badge-undocumented { background:rgba(139,143,163,0.15); color:var(--text-dim); }
.badge-deprecated { background:rgba(167,139,250,0.15); color:var(--purple); }
.method-badge { display:inline-block; padding:2px 6px; border-radius:3px; font-size:10px; font-weight:700; font-family:monospace; }
.method-GET { background:rgba(74,222,128,0.15); color:var(--green); }
.method-POST { background:rgba(108,140,255,0.15); color:var(--accent); }
.method-PUT { background:rgba(251,191,36,0.15); color:var(--yellow); }
.method-PATCH { background:rgba(34,211,238,0.15); color:var(--cyan); }
.method-DELETE { background:rgba(248,113,113,0.15); color:var(--red); }
.method-OPTIONS, .method-HEAD { background:rgba(139,143,163,0.15); color:var(--text-dim); }
.severity-high { color:var(--red); }
.severity-medium { color:var(--yellow); }
.severity-low { color:var(--cyan); }
.severity-info { color:var(--text-dim); }
.mono { font-family:'SF Mono', Menlo, monospace; font-size:12px; }
.ack-btn { background:var(--surface2); border:1px solid var(--border); border-radius:4px; padding:2px 8px; font-size:11px; color:var(--text-dim); cursor:pointer; }
.ack-btn:hover { color:var(--green); border-color:var(--green); }
.empty-state { text-align:center; padding:40px; color:var(--text-dim); }
.chart-container { height:200px; display:flex; align-items:flex-end; gap:4px; padding:20px 0; }
.chart-bar { flex:1; background:var(--accent); border-radius:3px 3px 0 0; min-height:4px; position:relative; opacity:0.7; transition:opacity 0.2s; }
.chart-bar:hover { opacity:1; }
.chart-bar.error { background:var(--red); opacity:0.5; }
.last-updated { font-size:12px; color:var(--text-dim); }
@media (max-width:900px) {
  .panels { grid-template-columns:1fr; }
  .stats-grid { grid-template-columns:repeat(3,1fr); }
  .container { padding:16px; }
}
</style>
</head>
<body>
<div class="header">
  <h1><span class="logo">🔍</span> API Scout</h1>
  <div class="header-actions">
    <a href="/graph" style="color:var(--accent);text-decoration:none;font-size:13px;">Dependency Graph</a>
    <a href="/audit" id="auditLink" style="color:var(--accent);text-decoration:none;font-size:13px;display:none;">Audit Log</a>
    <input type="text" class="search-box" id="searchBox" placeholder="Search endpoints…">
    <button class="refresh-btn" id="refreshBtn">Refresh</button>
    <span class="user-pill" id="userPill"></span>
    <button class="logout-btn" id="logoutBtn">Sign out</button>
    <span class="last-updated" id="lastUpdated"></span>
  </div>
</div>

<div class="container">
  <div class="stats-grid" id="statsGrid"></div>

  <div class="panels">
    <div class="panel panel-full">
      <div class="panel-header"><h2>Traffic Timeline (24h)</h2></div>
      <div class="panel-body"><div class="chart-container" id="trafficChart"></div></div>
    </div>

    <div class="panel panel-full">
      <div class="panel-header">
        <h2>Endpoints</h2>
        <div class="filter-tabs" id="filterTabs">
          <div class="filter-tab active" data-filter="all">All</div>
          <div class="filter-tab" data-filter="shadow">Shadow</div>
          <div class="filter-tab" data-filter="active">Active</div>
          <div class="filter-tab" data-filter="zombie">Zombie</div>
          <div class="filter-tab" data-filter="undocumented">Undocumented</div>
        </div>
      </div>
      <div class="panel-body" style="padding:0;">
        <table>
          <thead><tr>
            <th>Status</th><th>Method</th><th>Path</th><th>Host</th>
            <th>Calls</th><th>Error %</th><th>Avg Latency</th>
            <th>Auth</th><th>Consumers</th><th>Source</th>
          </tr></thead>
          <tbody id="endpointsTable"></tbody>
        </table>
        <div class="empty-state" id="endpointsEmpty" style="display:none;">No endpoints found. Run a scan or analyze logs first.</div>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <h2>Alerts</h2>
        <div class="filter-tabs">
          <div class="filter-tab active" id="alertFilterAll" data-unack="0">All</div>
          <div class="filter-tab" id="alertFilterNew" data-unack="1">Unacknowledged</div>
        </div>
      </div>
      <div class="panel-body" style="padding:0; max-height:400px; overflow-y:auto;">
        <table>
          <thead><tr><th>Severity</th><th>Message</th><th>Time</th><th></th></tr></thead>
          <tbody id="alertsTable"></tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header"><h2>Recent Scans</h2></div>
      <div class="panel-body" style="padding:0;">
        <table>
          <thead><tr><th>Type</th><th>Targets</th><th>Found</th><th>New</th><th>Status</th><th>Time</th></tr></thead>
          <tbody id="scansTable"></tbody>
        </table>
      </div>
    </div>
  </div>
</div>

<script>
__JS_HELPERS__

let currentFilter = 'all';
let allEndpoints = [];
let canAck = false;

function statRow(cls, value, label) {
  return `<div class="stat-card ${esc(cls)}"><div class="value">${esc(value)}</div><div class="label">${esc(label)}</div></div>`;
}

async function loadSummary() {
  const data = await fetchJSON('/api/summary');
  document.getElementById('statsGrid').innerHTML =
    statRow('total', data.total_endpoints, 'Total Endpoints') +
    statRow('active', data.active, 'Active') +
    statRow('shadow', data.shadow, 'Shadow APIs') +
    statRow('zombie', data.zombie, 'Zombie APIs') +
    statRow('unauth', data.unauthenticated, 'Unauthenticated') +
    statRow('alerts', data.active_alerts, 'Active Alerts');
}

async function loadEndpoints() {
  const search = document.getElementById('searchBox').value;
  const params = new URLSearchParams();
  if (search) params.set('search', search);
  else if (currentFilter !== 'all') params.set('status', currentFilter);
  allEndpoints = await fetchJSON('/api/endpoints?' + params);
  renderEndpoints();
}

function renderEndpoints() {
  const tbody = document.getElementById('endpointsTable');
  const empty = document.getElementById('endpointsEmpty');
  if (allEndpoints.length === 0) {
    tbody.innerHTML = ''; empty.style.display = 'block'; return;
  }
  empty.style.display = 'none';
  tbody.innerHTML = allEndpoints.map(ep => {
    const errRate = ep.total_calls > 0 ? Math.round((ep.error_count / ep.total_calls) * 100) : 0;
    const auth = ep.auth_methods_seen.length > 0 ? ep.auth_methods_seen.join(', ') : '-';
    const sources = ep.discovery_sources.map(s => s.split('_').slice(1).join('_')).join(', ');
    const latency = ep.avg_response_time_ms ? Math.round(ep.avg_response_time_ms) + 'ms' : '-';
    const status = String(ep.status || '');
    const method = String(ep.method || '');
    return `<tr>
      <td><span class="badge badge-${esc(status)}">${esc(status)}</span></td>
      <td><span class="method-badge method-${esc(method)}">${esc(method)}</span></td>
      <td class="mono">${esc(ep.path_pattern)}</td>
      <td>${esc(ep.host || '-')}</td>
      <td>${esc(Number(ep.total_calls).toLocaleString())}</td>
      <td>${errRate > 0 ? esc(errRate + '%') : '-'}</td>
      <td>${esc(latency)}</td>
      <td>${esc(auth)}</td>
      <td>${esc(ep.consumers.length)}</td>
      <td>${esc(sources)}</td>
    </tr>`;
  }).join('');
}

async function loadTimeline() {
  const data = await fetchJSON('/api/traffic/timeline?hours=24');
  const chart = document.getElementById('trafficChart');
  if (data.length === 0) { chart.innerHTML = '<div class="empty-state">No traffic data yet</div>'; return; }
  const maxReqs = Math.max(...data.map(d => d.requests), 1);
  chart.innerHTML = data.map(d => {
    const height = Math.max((d.requests / maxReqs) * 100, 2);
    const errHeight = d.errors > 0 ? Math.max((d.errors / maxReqs) * 100, 2) : 0;
    const time = d.bucket ? (d.bucket.split('T')[1] || '').substring(0,5) : '';
    return `<div style="flex:1; display:flex; flex-direction:column; align-items:stretch; gap:2px; justify-content:flex-end;">
      <div class="chart-bar" style="height:${esc(height)}%" title="${esc(time)} — ${esc(d.requests)} reqs, ${esc(d.errors)} errs"></div>
      ${errHeight > 0 ? `<div class="chart-bar error" style="height:${esc(errHeight)}%"></div>` : ''}
    </div>`;
  }).join('');
}

async function loadAlerts(unackOnly = false) {
  document.getElementById('alertFilterAll').classList.toggle('active', !unackOnly);
  document.getElementById('alertFilterNew').classList.toggle('active', unackOnly);
  const data = await fetchJSON('/api/alerts?unacknowledged=' + (unackOnly ? 'true' : 'false'));
  const tbody = document.getElementById('alertsTable');
  tbody.innerHTML = data.map(a => {
    const time = a.created_at ? new Date(a.created_at).toLocaleTimeString() : '';
    const sev = String(a.severity || '');
    const ackBtn = (!a.acknowledged && canAck)
      ? `<button class="ack-btn" data-ack-id="${esc(a.id)}">Ack</button>`
      : '';
    return `<tr style="${a.acknowledged ? 'opacity:0.5' : ''}">
      <td><span class="severity-${esc(sev)}">${esc(sev.toUpperCase())}</span></td>
      <td style="font-size:12px;">${esc(a.message)}</td>
      <td style="font-size:11px; color:var(--text-dim);">${esc(time)}</td>
      <td>${ackBtn}</td>
    </tr>`;
  }).join('');
}

async function loadScans() {
  const data = await fetchJSON('/api/scans');
  const tbody = document.getElementById('scansTable');
  tbody.innerHTML = data.map(s => {
    const time = s.started_at ? new Date(s.started_at).toLocaleString() : '';
    const status = String(s.status || '');
    const statusColor = status === 'completed' ? 'var(--green)' : status === 'running' ? 'var(--yellow)' : 'var(--red)';
    return `<tr>
      <td>${esc(s.scan_type)}</td>
      <td class="mono" style="font-size:11px;">${esc(s.targets || '-')}</td>
      <td>${esc(s.endpoints_found)}</td>
      <td>${esc(s.new_endpoints)}</td>
      <td style="color:${statusColor}">${esc(status)}</td>
      <td style="font-size:11px; color:var(--text-dim);">${esc(time)}</td>
    </tr>`;
  }).join('');
}

async function ackAlert(id) {
  await fetch('/api/alerts/' + encodeURIComponent(id) + '/acknowledge', { method: 'POST' });
  loadAlerts();
  loadSummary();
}

async function refreshAll() {
  document.getElementById('lastUpdated').textContent = 'Updated ' + new Date().toLocaleTimeString();
  await Promise.all([loadSummary(), loadEndpoints(), loadTimeline(), loadAlerts(), loadScans()]);
}

// Event delegation: no inline onclick handlers anywhere
document.getElementById('filterTabs').addEventListener('click', (e) => {
  const t = e.target.closest('.filter-tab');
  if (!t) return;
  document.querySelectorAll('#filterTabs .filter-tab').forEach(x => x.classList.remove('active'));
  t.classList.add('active');
  currentFilter = t.dataset.filter;
  loadEndpoints();
});
document.getElementById('alertFilterAll').addEventListener('click', () => loadAlerts(false));
document.getElementById('alertFilterNew').addEventListener('click', () => loadAlerts(true));
document.getElementById('alertsTable').addEventListener('click', (e) => {
  const btn = e.target.closest('[data-ack-id]');
  if (btn) ackAlert(btn.dataset.ackId);
});
document.getElementById('refreshBtn').addEventListener('click', refreshAll);
document.getElementById('logoutBtn').addEventListener('click', logout);

let searchTimeout;
document.getElementById('searchBox').addEventListener('input', () => {
  clearTimeout(searchTimeout);
  searchTimeout = setTimeout(loadEndpoints, 300);
});

setInterval(refreshAll, 30000);

(async () => {
  const me = await whoami();
  if (me) {
    document.getElementById('userPill').textContent = me.username + ' · ' + me.role;
    canAck = (me.role === 'admin' || me.role === 'analyst');
    if (me.role === 'admin') document.getElementById('auditLink').style.display = 'inline';
  }
  refreshAll();
})();
</script>
</body>
</html>
""".replace("__JS_HELPERS__", _JS_HELPERS)


GRAPH_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>API Scout — Dependency Graph</title>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --surface2:#242736; --border:#2e3245;
  --text:#e4e6f0; --text-dim:#8b8fa3; --accent:#6c8cff; --green:#4ade80;
  --red:#f87171; --yellow:#fbbf24; --cyan:#22d3ee; --purple:#a78bfa; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,BlinkMacSystemFont,system-ui,sans-serif; background:var(--bg); color:var(--text); }
.header { background:var(--surface); border-bottom:1px solid var(--border); padding:16px 32px; display:flex; align-items:center; justify-content:space-between; }
.header h1 { font-size:20px; font-weight:600; }
.header a { color:var(--accent); text-decoration:none; font-size:14px; }
.container { display:grid; grid-template-columns:1fr 320px; height:calc(100vh - 60px); }
#graphCanvas { width:100%; height:100%; background:var(--bg); }
.sidebar { background:var(--surface); border-left:1px solid var(--border); padding:20px; overflow-y:auto; }
.sidebar h3 { font-size:14px; margin-bottom:12px; color:var(--text-dim); text-transform:uppercase; letter-spacing:0.5px; }
.sidebar-section { margin-bottom:24px; }
.node-list { list-style:none; }
.node-list li { padding:8px 12px; border-radius:6px; margin-bottom:4px; font-size:13px; cursor:pointer; display:flex; justify-content:space-between; }
.node-list li:hover { background:var(--surface2); }
.node-list .count { color:var(--text-dim); font-size:11px; }
.badge-critical { color:var(--red); }
.badge-service { color:var(--accent); }
.badge-third-party { color:var(--purple); }
.blast-panel { display:none; background:var(--surface2); border-radius:8px; padding:16px; margin-top:12px; }
.blast-panel.visible { display:block; }
.blast-panel h4 { font-size:13px; margin-bottom:8px; word-break:break-all; }
.blast-value { font-size:28px; font-weight:700; color:var(--red); }
svg text { fill:var(--text); font-size:11px; font-family:-apple-system,system-ui,sans-serif; pointer-events:none; }
svg line { stroke:var(--border); stroke-opacity:0.6; }
svg circle { cursor:pointer; }
</style>
</head>
<body>
<div class="header">
  <h1>Dependency Graph</h1>
  <a href="/">← Back to Dashboard</a>
</div>
<div class="container">
  <svg id="graphCanvas"></svg>
  <div class="sidebar">
    <div class="sidebar-section"><h3>Critical Services</h3><ul class="node-list" id="criticalList"></ul></div>
    <div class="sidebar-section"><h3>Single Points of Failure</h3><ul class="node-list" id="spofList"></ul></div>
    <div class="sidebar-section"><h3>Blast Radius</h3>
      <div class="blast-panel" id="blastPanel">
        <h4 id="blastService"></h4>
        <div class="blast-value" id="blastCount">0</div>
        <div style="color:var(--text-dim); font-size:12px; margin-top:4px;">services affected</div>
        <ul class="node-list" id="blastList" style="margin-top:12px;"></ul>
      </div>
    </div>
    <div class="sidebar-section"><h3>Orphaned Services</h3><ul class="node-list" id="orphanList"></ul></div>
  </div>
</div>
<script>
__JS_HELPERS__

let nodeIdByIndex = {};   // numeric index -> node.id (for click delegation)

async function loadGraph() {
  const [graphData, analysis] = await Promise.all([
    fetchJSON('/api/graph/d3'),
    fetchJSON('/api/graph/critical-paths'),
  ]);
  renderForceGraph(graphData);
  renderSidebar(analysis);
}

function renderForceGraph(data) {
  const svg = document.getElementById('graphCanvas');
  const rect = svg.getBoundingClientRect();
  const w = rect.width, h = rect.height;
  if (!data.nodes.length) {
    svg.innerHTML = '<text x="50%" y="50%" text-anchor="middle" fill="#8b8fa3">No graph data. Run analyze or scan first.</text>';
    return;
  }

  const nodes = data.nodes.map(n => ({...n, x: w/2 + (Math.random()-0.5)*300, y: h/2 + (Math.random()-0.5)*300, vx:0, vy:0}));
  const links = data.links.filter(l => nodes.find(n=>n.id===l.source) && nodes.find(n=>n.id===l.target));
  const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

  for (let tick = 0; tick < 200; tick++) {
    for (let i = 0; i < nodes.length; i++) {
      for (let j = i+1; j < nodes.length; j++) {
        const dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
        const dist = Math.sqrt(dx*dx + dy*dy) || 1;
        const force = 5000 / (dist*dist);
        nodes[i].vx -= dx/dist*force; nodes[i].vy -= dy/dist*force;
        nodes[j].vx += dx/dist*force; nodes[j].vy += dy/dist*force;
      }
    }
    for (const l of links) {
      const s = nodeMap[l.source], t = nodeMap[l.target];
      if (!s || !t) continue;
      const dx = t.x - s.x, dy = t.y - s.y;
      const dist = Math.sqrt(dx*dx + dy*dy) || 1;
      const force = (dist - 150) * 0.01;
      s.vx += dx/dist*force; s.vy += dy/dist*force;
      t.vx -= dx/dist*force; t.vy -= dy/dist*force;
    }
    for (const n of nodes) {
      n.vx += (w/2 - n.x) * 0.001;
      n.vy += (h/2 - n.y) * 0.001;
      n.x += n.vx*0.3; n.y += n.vy*0.3;
      n.vx *= 0.9; n.vy *= 0.9;
      n.x = Math.max(40, Math.min(w-40, n.x));
      n.y = Math.max(40, Math.min(h-40, n.y));
    }
  }

  // Build SVG via DOM API to avoid any string injection
  while (svg.firstChild) svg.removeChild(svg.firstChild);
  const NS = 'http://www.w3.org/2000/svg';

  for (const l of links) {
    const s = nodeMap[l.source], t = nodeMap[l.target];
    if (!s || !t) continue;
    const line = document.createElementNS(NS, 'line');
    line.setAttribute('x1', s.x); line.setAttribute('y1', s.y);
    line.setAttribute('x2', t.x); line.setAttribute('y2', t.y);
    line.setAttribute('stroke-width', String(Math.min(l.width || 1, 5)));
    svg.appendChild(line);
  }
  const colors = {1:'#6c8cff', 2:'#4ade80', 3:'#a78bfa'};
  nodeIdByIndex = {};
  nodes.forEach((n, i) => {
    const r = Math.max(8, Math.min(30, n.size || 10));
    const c = colors[n.group] || '#8b8fa3';
    const circle = document.createElementNS(NS, 'circle');
    circle.setAttribute('cx', n.x); circle.setAttribute('cy', n.y);
    circle.setAttribute('r', String(r));
    circle.setAttribute('fill', c); circle.setAttribute('opacity', '0.8');
    circle.setAttribute('data-node-idx', String(i));
    svg.appendChild(circle);
    nodeIdByIndex[i] = n.id;

    const text = document.createElementNS(NS, 'text');
    text.setAttribute('x', n.x); text.setAttribute('y', n.y - r - 5);
    text.setAttribute('text-anchor', 'middle');
    text.textContent = n.id.length > 20 ? n.id.slice(0, 18) + '…' : n.id;
    svg.appendChild(text);
  });
}

function renderSidebar(analysis) {
  document.getElementById('criticalList').innerHTML = analysis.critical_services.map(s =>
    `<li data-blast="${esc(s.id)}"><span class="badge-service">${esc(s.id)}</span><span class="count">${esc(s.total_calls)} calls</span></li>`
  ).join('') || '<li style="color:var(--text-dim)">None found</li>';

  document.getElementById('spofList').innerHTML = analysis.spofs.map(s =>
    `<li data-blast="${esc(s.service)}"><span class="badge-critical">${esc(s.service)}</span><span class="count">${esc(s.affected_percentage)}%</span></li>`
  ).join('') || '<li style="color:var(--text-dim)">None found</li>';

  document.getElementById('orphanList').innerHTML = analysis.orphaned.map(s =>
    `<li><span class="badge-third-party">${esc(s.id)}</span><span class="count">${esc(s.type)}</span></li>`
  ).join('') || '<li style="color:var(--text-dim)">None found</li>';
}

async function showBlastRadius(service) {
  const data = await fetchJSON('/api/graph/blast-radius/' + encodeURIComponent(service));
  document.getElementById('blastPanel').classList.add('visible');
  document.getElementById('blastService').textContent = service;
  document.getElementById('blastCount').textContent = String(data.affected_count);
  document.getElementById('blastList').innerHTML = data.affected_services.length
    ? data.affected_services.map(s => `<li>${esc(s)}</li>`).join('')
    : '<li style="color:var(--text-dim)">No downstream impact</li>';
}

// Event delegation for SVG node clicks + sidebar list
document.getElementById('graphCanvas').addEventListener('click', (e) => {
  const idx = e.target.dataset && e.target.dataset.nodeIdx;
  if (idx != null && nodeIdByIndex[idx]) showBlastRadius(nodeIdByIndex[idx]);
});
document.querySelector('.sidebar').addEventListener('click', (e) => {
  const li = e.target.closest('[data-blast]');
  if (li) showBlastRadius(li.dataset.blast);
});

loadGraph();
</script>
</body>
</html>
""".replace("__JS_HELPERS__", _JS_HELPERS)


AUDIT_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>API Scout — Audit Log</title>
<style>
:root { --bg:#0f1117; --surface:#1a1d27; --surface2:#242736; --border:#2e3245; --text:#e4e6f0; --dim:#8b8fa3; --accent:#6c8cff; --red:#f87171; --green:#4ade80; }
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:-apple-system,system-ui,sans-serif; background:var(--bg); color:var(--text); }
.header { background:var(--surface); border-bottom:1px solid var(--border); padding:16px 32px; display:flex; justify-content:space-between; align-items:center; }
.header a { color:var(--accent); text-decoration:none; font-size:14px; }
.container { max-width:1200px; margin:0 auto; padding:24px 32px; }
input { background:var(--surface2); border:1px solid var(--border); color:var(--text); border-radius:6px; padding:6px 10px; font-size:13px; margin-right:8px; }
table { width:100%; border-collapse:collapse; font-size:12px; background:var(--surface); border:1px solid var(--border); border-radius:8px; overflow:hidden; margin-top:16px; }
th { text-align:left; padding:10px; color:var(--dim); border-bottom:1px solid var(--border); font-size:11px; text-transform:uppercase; }
td { padding:10px; border-bottom:1px solid var(--border); }
tr:hover { background:var(--surface2); }
.code-2xx { color:var(--green); }
.code-4xx, .code-5xx { color:var(--red); }
.mono { font-family:'SF Mono',Menlo,monospace; }
</style>
</head>
<body>
<div class="header">
  <h1>Audit Log</h1>
  <a href="/">← Back to Dashboard</a>
</div>
<div class="container">
  <div>
    <input id="filterAction" placeholder="Filter by action…">
    <input id="filterUser" placeholder="Filter by user…">
    <button id="applyBtn" style="background:var(--accent);color:white;border:none;border-radius:6px;padding:6px 14px;cursor:pointer;">Apply</button>
  </div>
  <table>
    <thead><tr><th>Time</th><th>User</th><th>Action</th><th>Method</th><th>Path</th><th>Status</th><th>IP</th></tr></thead>
    <tbody id="auditBody"></tbody>
  </table>
</div>
<script>
__JS_HELPERS__

async function load() {
  const action = document.getElementById('filterAction').value;
  const username = document.getElementById('filterUser').value;
  const params = new URLSearchParams();
  if (action) params.set('action', action);
  if (username) params.set('username', username);
  const data = await fetchJSON('/api/admin/audit?' + params);
  const tbody = document.getElementById('auditBody');
  tbody.innerHTML = data.map(r => {
    const code = r.status_code || '';
    const codeClass = code >= 200 && code < 300 ? 'code-2xx' : code >= 400 ? 'code-4xx' : '';
    return `<tr>
      <td class="mono">${esc(r.timestamp)}</td>
      <td>${esc(r.username || '-')}</td>
      <td>${esc(r.action)}</td>
      <td class="mono">${esc(r.method || '-')}</td>
      <td class="mono">${esc(r.path || '-')}</td>
      <td class="${codeClass}">${esc(code)}</td>
      <td class="mono">${esc(r.ip_address || '-')}</td>
    </tr>`;
  }).join('');
}
document.getElementById('applyBtn').addEventListener('click', load);
load();
</script>
</body>
</html>
""".replace("__JS_HELPERS__", _JS_HELPERS)
