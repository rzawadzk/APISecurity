"""Web dashboard — FastAPI backend with embedded HTML frontend."""

import json
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse

from .database import Database
from .models import APIStatus

app = FastAPI(title="API Scout Dashboard", version="0.1.0")
db: Optional[Database] = None


def create_app(database: Database) -> FastAPI:
    """Create the FastAPI app with a database instance."""
    global db
    db = database
    return app


# ── API Endpoints ──


@app.get("/api/summary")
async def api_summary():
    return db.get_dashboard_summary()


@app.get("/api/endpoints")
async def api_endpoints(
    status: Optional[str] = None,
    search: Optional[str] = None,
):
    if search:
        endpoints = db.search_endpoints(search)
    elif status:
        endpoints = db.get_endpoints_by_status(APIStatus(status))
    else:
        endpoints = db.get_all_endpoints()

    return [ep.model_dump(mode="json") for ep in endpoints]


@app.get("/api/endpoints/{endpoint_id}")
async def api_endpoint_detail(endpoint_id: str):
    ep = db.get_endpoint(endpoint_id)
    if not ep:
        return JSONResponse({"error": "Not found"}, status_code=404)
    return ep.model_dump(mode="json")


@app.get("/api/traffic/stats")
async def api_traffic_stats(hours: int = Query(default=24)):
    return db.get_traffic_stats(hours)


@app.get("/api/traffic/timeline")
async def api_traffic_timeline(hours: int = Query(default=24)):
    return db.get_traffic_timeline(hours)


@app.get("/api/alerts")
async def api_alerts(unacknowledged: bool = Query(default=False)):
    return db.get_alerts(unacknowledged_only=unacknowledged)


@app.post("/api/alerts/{alert_id}/acknowledge")
async def api_acknowledge_alert(alert_id: int):
    db.acknowledge_alert(alert_id)
    return {"status": "ok"}


@app.get("/api/scans")
async def api_scan_history():
    return db.get_scan_history()


# ── Dependency Graph API ──

@app.get("/api/graph")
async def api_dependency_graph():
    from .graph import DependencyGraph
    graph = DependencyGraph()
    graph.build_from_database(db)
    return graph.to_dict()


@app.get("/api/graph/blast-radius/{service_name}")
async def api_blast_radius(service_name: str):
    from .graph import DependencyGraph
    graph = DependencyGraph()
    graph.build_from_database(db)
    return graph.blast_radius(service_name)


@app.get("/api/graph/critical-paths")
async def api_critical_paths():
    from .graph import DependencyGraph
    graph = DependencyGraph()
    graph.build_from_database(db)
    return {
        "critical_services": [n.to_dict() for n in graph.find_critical_paths()],
        "spofs": graph.find_single_points_of_failure(),
        "orphaned": [n.to_dict() for n in graph.find_orphaned_services()],
    }


@app.get("/api/graph/mermaid")
async def api_graph_mermaid():
    from .graph import DependencyGraph
    graph = DependencyGraph()
    graph.build_from_database(db)
    return {"mermaid": graph.to_mermaid()}


@app.get("/api/graph/d3")
async def api_graph_d3():
    from .graph import DependencyGraph
    graph = DependencyGraph()
    graph.build_from_database(db)
    return json.loads(graph.to_d3_json())


# ── Remediation API ──

@app.get("/api/remediation/waf/nginx")
async def api_waf_nginx():
    from .remediation import WAFRuleGenerator
    gen = WAFRuleGenerator(db)
    return {"rules": gen.generate_nginx_rules()}


@app.get("/api/remediation/waf/modsecurity")
async def api_waf_modsecurity():
    from .remediation import WAFRuleGenerator
    gen = WAFRuleGenerator(db)
    return {"rules": gen.generate_modsecurity_rules()}


@app.get("/api/remediation/waf/aws")
async def api_waf_aws():
    from .remediation import WAFRuleGenerator
    gen = WAFRuleGenerator(db)
    return gen.generate_aws_waf_rules()


@app.get("/api/remediation/spec")
async def api_generate_spec():
    from .remediation import SpecGenerator
    gen = SpecGenerator(db)
    return gen.generate_spec()


@app.get("/api/remediation/spec/undocumented")
async def api_generate_spec_undocumented():
    from .remediation import SpecGenerator
    gen = SpecGenerator(db)
    return gen.generate_for_undocumented()


# ── Graph Visualization Page ──

@app.get("/graph", response_class=HTMLResponse)
async def graph_page():
    return GRAPH_HTML


# ── HTML Dashboard ──


@app.get("/", response_class=HTMLResponse)
async def dashboard_page():
    return DASHBOARD_HTML


DASHBOARD_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Scout Dashboard</title>
    <style>
        :root {
            --bg: #0f1117;
            --surface: #1a1d27;
            --surface2: #242736;
            --border: #2e3245;
            --text: #e4e6f0;
            --text-dim: #8b8fa3;
            --accent: #6c8cff;
            --green: #4ade80;
            --red: #f87171;
            --yellow: #fbbf24;
            --cyan: #22d3ee;
            --purple: #a78bfa;
        }

        * { margin: 0; padding: 0; box-sizing: border-box; }

        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', system-ui, sans-serif;
            background: var(--bg);
            color: var(--text);
            min-height: 100vh;
        }

        .header {
            background: var(--surface);
            border-bottom: 1px solid var(--border);
            padding: 16px 32px;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .header h1 {
            font-size: 20px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .header .logo { font-size: 24px; }

        .header-actions {
            display: flex;
            gap: 12px;
            align-items: center;
        }

        .search-box {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 8px;
            padding: 8px 14px;
            color: var(--text);
            font-size: 14px;
            width: 280px;
            outline: none;
        }

        .search-box:focus { border-color: var(--accent); }

        .refresh-btn {
            background: var(--accent);
            color: white;
            border: none;
            border-radius: 8px;
            padding: 8px 16px;
            font-size: 14px;
            cursor: pointer;
            font-weight: 500;
        }

        .refresh-btn:hover { opacity: 0.9; }

        .container { max-width: 1400px; margin: 0 auto; padding: 24px 32px; }

        /* Stats Cards */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
            gap: 16px;
            margin-bottom: 24px;
        }

        .stat-card {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }

        .stat-card .value {
            font-size: 32px;
            font-weight: 700;
            line-height: 1.2;
        }

        .stat-card .label {
            font-size: 12px;
            color: var(--text-dim);
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-top: 4px;
        }

        .stat-card.total .value { color: var(--accent); }
        .stat-card.active .value { color: var(--green); }
        .stat-card.shadow .value { color: var(--red); }
        .stat-card.zombie .value { color: var(--yellow); }
        .stat-card.unauth .value { color: var(--purple); }
        .stat-card.alerts .value { color: var(--red); }

        /* Panels */
        .panels {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-bottom: 24px;
        }

        .panel {
            background: var(--surface);
            border: 1px solid var(--border);
            border-radius: 12px;
            overflow: hidden;
        }

        .panel-full { grid-column: 1 / -1; }

        .panel-header {
            padding: 16px 20px;
            border-bottom: 1px solid var(--border);
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .panel-header h2 {
            font-size: 15px;
            font-weight: 600;
        }

        .panel-body { padding: 16px 20px; }

        /* Filter tabs */
        .filter-tabs {
            display: flex;
            gap: 8px;
        }

        .filter-tab {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 6px;
            padding: 4px 12px;
            font-size: 12px;
            color: var(--text-dim);
            cursor: pointer;
        }

        .filter-tab.active {
            background: var(--accent);
            color: white;
            border-color: var(--accent);
        }

        /* Tables */
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 13px;
        }

        th {
            text-align: left;
            padding: 10px 12px;
            color: var(--text-dim);
            font-weight: 500;
            font-size: 11px;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid var(--border);
        }

        td {
            padding: 10px 12px;
            border-bottom: 1px solid var(--border);
            vertical-align: middle;
        }

        tr:last-child td { border-bottom: none; }
        tr:hover { background: var(--surface2); }

        /* Badges */
        .badge {
            display: inline-block;
            padding: 2px 8px;
            border-radius: 4px;
            font-size: 11px;
            font-weight: 600;
            text-transform: uppercase;
        }

        .badge-active { background: rgba(74, 222, 128, 0.15); color: var(--green); }
        .badge-shadow { background: rgba(248, 113, 113, 0.15); color: var(--red); }
        .badge-zombie { background: rgba(251, 191, 36, 0.15); color: var(--yellow); }
        .badge-undocumented { background: rgba(139, 143, 163, 0.15); color: var(--text-dim); }
        .badge-deprecated { background: rgba(167, 139, 250, 0.15); color: var(--purple); }

        .method-badge {
            display: inline-block;
            padding: 2px 6px;
            border-radius: 3px;
            font-size: 10px;
            font-weight: 700;
            font-family: monospace;
        }

        .method-GET { background: rgba(74, 222, 128, 0.15); color: var(--green); }
        .method-POST { background: rgba(108, 140, 255, 0.15); color: var(--accent); }
        .method-PUT { background: rgba(251, 191, 36, 0.15); color: var(--yellow); }
        .method-PATCH { background: rgba(34, 211, 238, 0.15); color: var(--cyan); }
        .method-DELETE { background: rgba(248, 113, 113, 0.15); color: var(--red); }
        .method-OPTIONS { background: rgba(139, 143, 163, 0.15); color: var(--text-dim); }
        .method-HEAD { background: rgba(139, 143, 163, 0.15); color: var(--text-dim); }

        .severity-high { color: var(--red); }
        .severity-medium { color: var(--yellow); }
        .severity-low { color: var(--cyan); }
        .severity-info { color: var(--text-dim); }

        .mono { font-family: 'SF Mono', Menlo, monospace; font-size: 12px; }

        .ack-btn {
            background: var(--surface2);
            border: 1px solid var(--border);
            border-radius: 4px;
            padding: 2px 8px;
            font-size: 11px;
            color: var(--text-dim);
            cursor: pointer;
        }

        .ack-btn:hover { color: var(--green); border-color: var(--green); }

        .empty-state {
            text-align: center;
            padding: 40px;
            color: var(--text-dim);
        }

        /* Traffic chart placeholder */
        .chart-container {
            height: 200px;
            display: flex;
            align-items: flex-end;
            gap: 4px;
            padding: 20px 0;
        }

        .chart-bar {
            flex: 1;
            background: var(--accent);
            border-radius: 3px 3px 0 0;
            min-height: 4px;
            position: relative;
            opacity: 0.7;
            transition: opacity 0.2s;
        }

        .chart-bar:hover { opacity: 1; }

        .chart-bar .tooltip {
            display: none;
            position: absolute;
            bottom: 100%;
            left: 50%;
            transform: translateX(-50%);
            background: var(--surface2);
            border: 1px solid var(--border);
            padding: 4px 8px;
            border-radius: 4px;
            font-size: 11px;
            white-space: nowrap;
            z-index: 10;
        }

        .chart-bar:hover .tooltip { display: block; }

        .chart-bar.error {
            background: var(--red);
            opacity: 0.5;
        }

        .last-updated {
            font-size: 12px;
            color: var(--text-dim);
        }

        @media (max-width: 900px) {
            .panels { grid-template-columns: 1fr; }
            .stats-grid { grid-template-columns: repeat(3, 1fr); }
            .container { padding: 16px; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1><span class="logo">🔍</span> API Scout</h1>
        <div class="header-actions">
            <a href="/graph" style="color:var(--accent);text-decoration:none;font-size:13px;margin-right:8px;">Dependency Graph</a>
            <input type="text" class="search-box" id="searchBox" placeholder="Search endpoints...">
            <button class="refresh-btn" onclick="refreshAll()">Refresh</button>
            <span class="last-updated" id="lastUpdated"></span>
        </div>
    </div>

    <div class="container">
        <div class="stats-grid" id="statsGrid"></div>

        <div class="panels">
            <div class="panel panel-full">
                <div class="panel-header">
                    <h2>Traffic Timeline (24h)</h2>
                </div>
                <div class="panel-body">
                    <div class="chart-container" id="trafficChart"></div>
                </div>
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
                <div class="panel-body" style="padding: 0;">
                    <table>
                        <thead>
                            <tr>
                                <th>Status</th>
                                <th>Method</th>
                                <th>Path</th>
                                <th>Host</th>
                                <th>Calls</th>
                                <th>Error %</th>
                                <th>Avg Latency</th>
                                <th>Auth</th>
                                <th>Consumers</th>
                                <th>Source</th>
                            </tr>
                        </thead>
                        <tbody id="endpointsTable"></tbody>
                    </table>
                    <div class="empty-state" id="endpointsEmpty" style="display:none;">
                        No endpoints found. Run a scan or analyze some logs first.
                    </div>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h2>Alerts</h2>
                    <div class="filter-tabs">
                        <div class="filter-tab active" id="alertFilterAll" onclick="loadAlerts(false)">All</div>
                        <div class="filter-tab" id="alertFilterNew" onclick="loadAlerts(true)">Unacknowledged</div>
                    </div>
                </div>
                <div class="panel-body" style="padding: 0; max-height: 400px; overflow-y: auto;">
                    <table>
                        <thead>
                            <tr>
                                <th>Severity</th>
                                <th>Message</th>
                                <th>Time</th>
                                <th></th>
                            </tr>
                        </thead>
                        <tbody id="alertsTable"></tbody>
                    </table>
                </div>
            </div>

            <div class="panel">
                <div class="panel-header">
                    <h2>Recent Scans</h2>
                </div>
                <div class="panel-body" style="padding: 0;">
                    <table>
                        <thead>
                            <tr>
                                <th>Type</th>
                                <th>Targets</th>
                                <th>Found</th>
                                <th>New</th>
                                <th>Status</th>
                                <th>Time</th>
                            </tr>
                        </thead>
                        <tbody id="scansTable"></tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>

    <script>
        let currentFilter = 'all';
        let allEndpoints = [];

        async function fetchJSON(url) {
            const resp = await fetch(url);
            return resp.json();
        }

        async function loadSummary() {
            const data = await fetchJSON('/api/summary');
            document.getElementById('statsGrid').innerHTML = `
                <div class="stat-card total">
                    <div class="value">${data.total_endpoints}</div>
                    <div class="label">Total Endpoints</div>
                </div>
                <div class="stat-card active">
                    <div class="value">${data.active}</div>
                    <div class="label">Active</div>
                </div>
                <div class="stat-card shadow">
                    <div class="value">${data.shadow}</div>
                    <div class="label">Shadow APIs</div>
                </div>
                <div class="stat-card zombie">
                    <div class="value">${data.zombie}</div>
                    <div class="label">Zombie APIs</div>
                </div>
                <div class="stat-card unauth">
                    <div class="value">${data.unauthenticated}</div>
                    <div class="label">Unauthenticated</div>
                </div>
                <div class="stat-card alerts">
                    <div class="value">${data.active_alerts}</div>
                    <div class="label">Active Alerts</div>
                </div>
            `;
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
                tbody.innerHTML = '';
                empty.style.display = 'block';
                return;
            }
            empty.style.display = 'none';

            tbody.innerHTML = allEndpoints.map(ep => {
                const errRate = ep.total_calls > 0 ? Math.round((ep.error_count / ep.total_calls) * 100) : 0;
                const auth = ep.auth_methods_seen.length > 0 ? ep.auth_methods_seen.join(', ') : '-';
                const sources = ep.discovery_sources.map(s => s.split('_').slice(1).join('_')).join(', ');
                const latency = ep.avg_response_time_ms ? Math.round(ep.avg_response_time_ms) + 'ms' : '-';

                return `<tr>
                    <td><span class="badge badge-${ep.status}">${ep.status}</span></td>
                    <td><span class="method-badge method-${ep.method}">${ep.method}</span></td>
                    <td class="mono">${ep.path_pattern}</td>
                    <td>${ep.host || '-'}</td>
                    <td>${ep.total_calls.toLocaleString()}</td>
                    <td>${errRate > 0 ? errRate + '%' : '-'}</td>
                    <td>${latency}</td>
                    <td>${auth}</td>
                    <td>${ep.consumers.length}</td>
                    <td>${sources}</td>
                </tr>`;
            }).join('');
        }

        async function loadTimeline() {
            const data = await fetchJSON('/api/traffic/timeline?hours=24');
            const chart = document.getElementById('trafficChart');

            if (data.length === 0) {
                chart.innerHTML = '<div class="empty-state">No traffic data yet</div>';
                return;
            }

            const maxReqs = Math.max(...data.map(d => d.requests), 1);

            chart.innerHTML = data.map(d => {
                const height = Math.max((d.requests / maxReqs) * 100, 2);
                const errHeight = d.errors > 0 ? Math.max((d.errors / maxReqs) * 100, 2) : 0;
                const time = d.bucket ? d.bucket.split('T')[1]?.substring(0, 5) || '' : '';

                return `
                    <div style="flex:1; display:flex; flex-direction:column; align-items:stretch; gap:2px; justify-content:flex-end;">
                        <div class="chart-bar" style="height:${height}%">
                            <div class="tooltip">${time} — ${d.requests} reqs, ${d.errors} errs</div>
                        </div>
                        ${errHeight > 0 ? `<div class="chart-bar error" style="height:${errHeight}%"></div>` : ''}
                    </div>
                `;
            }).join('');
        }

        async function loadAlerts(unackOnly = false) {
            document.getElementById('alertFilterAll').classList.toggle('active', !unackOnly);
            document.getElementById('alertFilterNew').classList.toggle('active', unackOnly);

            const data = await fetchJSON(`/api/alerts?unacknowledged=${unackOnly}`);
            const tbody = document.getElementById('alertsTable');

            tbody.innerHTML = data.map(a => {
                const time = a.created_at ? new Date(a.created_at).toLocaleTimeString() : '';
                const ackBtn = a.acknowledged ? '' :
                    `<button class="ack-btn" onclick="ackAlert(${a.id})">Ack</button>`;

                return `<tr style="${a.acknowledged ? 'opacity:0.5' : ''}">
                    <td><span class="severity-${a.severity}">${a.severity.toUpperCase()}</span></td>
                    <td style="font-size:12px;">${a.message}</td>
                    <td style="font-size:11px; color:var(--text-dim);">${time}</td>
                    <td>${ackBtn}</td>
                </tr>`;
            }).join('');
        }

        async function loadScans() {
            const data = await fetchJSON('/api/scans');
            const tbody = document.getElementById('scansTable');

            tbody.innerHTML = data.map(s => {
                const time = s.started_at ? new Date(s.started_at).toLocaleString() : '';
                const statusColor = s.status === 'completed' ? 'var(--green)' :
                    s.status === 'running' ? 'var(--yellow)' : 'var(--red)';

                return `<tr>
                    <td>${s.scan_type}</td>
                    <td class="mono" style="font-size:11px;">${s.targets || '-'}</td>
                    <td>${s.endpoints_found}</td>
                    <td>${s.new_endpoints}</td>
                    <td style="color:${statusColor}">${s.status}</td>
                    <td style="font-size:11px; color:var(--text-dim);">${time}</td>
                </tr>`;
            }).join('');
        }

        async function ackAlert(id) {
            await fetch(`/api/alerts/${id}/acknowledge`, { method: 'POST' });
            loadAlerts();
            loadSummary();
        }

        async function refreshAll() {
            document.getElementById('lastUpdated').textContent =
                'Updated ' + new Date().toLocaleTimeString();

            await Promise.all([
                loadSummary(),
                loadEndpoints(),
                loadTimeline(),
                loadAlerts(),
                loadScans(),
            ]);
        }

        // Filter tabs
        document.getElementById('filterTabs').addEventListener('click', (e) => {
            if (e.target.classList.contains('filter-tab')) {
                document.querySelectorAll('#filterTabs .filter-tab').forEach(t => t.classList.remove('active'));
                e.target.classList.add('active');
                currentFilter = e.target.dataset.filter;
                loadEndpoints();
            }
        });

        // Search with debounce
        let searchTimeout;
        document.getElementById('searchBox').addEventListener('input', () => {
            clearTimeout(searchTimeout);
            searchTimeout = setTimeout(loadEndpoints, 300);
        });

        // Auto-refresh every 30s
        setInterval(refreshAll, 30000);

        // Initial load
        refreshAll();
    </script>
</body>
</html>
"""


GRAPH_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>API Scout — Dependency Graph</title>
    <style>
        :root {
            --bg: #0f1117; --surface: #1a1d27; --surface2: #242736;
            --border: #2e3245; --text: #e4e6f0; --text-dim: #8b8fa3;
            --accent: #6c8cff; --green: #4ade80; --red: #f87171;
            --yellow: #fbbf24; --cyan: #22d3ee; --purple: #a78bfa;
        }
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: -apple-system, BlinkMacSystemFont, system-ui, sans-serif; background: var(--bg); color: var(--text); }
        .header { background: var(--surface); border-bottom: 1px solid var(--border); padding: 16px 32px; display: flex; align-items: center; justify-content: space-between; }
        .header h1 { font-size: 20px; font-weight: 600; }
        .header a { color: var(--accent); text-decoration: none; font-size: 14px; }
        .container { display: grid; grid-template-columns: 1fr 320px; height: calc(100vh - 60px); }
        #graphCanvas { width: 100%; height: 100%; background: var(--bg); }
        .sidebar { background: var(--surface); border-left: 1px solid var(--border); padding: 20px; overflow-y: auto; }
        .sidebar h3 { font-size: 14px; margin-bottom: 12px; color: var(--text-dim); text-transform: uppercase; letter-spacing: 0.5px; }
        .sidebar-section { margin-bottom: 24px; }
        .node-list { list-style: none; }
        .node-list li { padding: 8px 12px; border-radius: 6px; margin-bottom: 4px; font-size: 13px; cursor: pointer; display: flex; justify-content: space-between; }
        .node-list li:hover { background: var(--surface2); }
        .node-list .count { color: var(--text-dim); font-size: 11px; }
        .badge-critical { color: var(--red); }
        .badge-service { color: var(--accent); }
        .badge-third-party { color: var(--purple); }
        .blast-panel { display: none; background: var(--surface2); border-radius: 8px; padding: 16px; margin-top: 12px; }
        .blast-panel.visible { display: block; }
        .blast-panel h4 { font-size: 13px; margin-bottom: 8px; }
        .blast-value { font-size: 28px; font-weight: 700; color: var(--red); }
        svg text { fill: var(--text); font-size: 11px; font-family: -apple-system, system-ui, sans-serif; }
        svg line { stroke: var(--border); stroke-opacity: 0.6; }
        svg circle { cursor: pointer; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Dependency Graph</h1>
        <a href="/">Back to Dashboard</a>
    </div>
    <div class="container">
        <svg id="graphCanvas"></svg>
        <div class="sidebar">
            <div class="sidebar-section">
                <h3>Critical Services</h3>
                <ul class="node-list" id="criticalList"></ul>
            </div>
            <div class="sidebar-section">
                <h3>Single Points of Failure</h3>
                <ul class="node-list" id="spofList"></ul>
            </div>
            <div class="sidebar-section">
                <h3>Blast Radius</h3>
                <div class="blast-panel" id="blastPanel">
                    <h4 id="blastService"></h4>
                    <div class="blast-value" id="blastCount">0</div>
                    <div style="color:var(--text-dim); font-size:12px; margin-top:4px;">services affected</div>
                    <ul class="node-list" id="blastList" style="margin-top:12px;"></ul>
                </div>
            </div>
            <div class="sidebar-section">
                <h3>Orphaned Services</h3>
                <ul class="node-list" id="orphanList"></ul>
            </div>
        </div>
    </div>
    <script>
        async function fetchJSON(url) { return (await fetch(url)).json(); }

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

            // Simple force layout (no D3 dependency — uses basic simulation)
            const nodes = data.nodes.map(n => ({...n, x: w/2 + (Math.random()-0.5)*300, y: h/2 + (Math.random()-0.5)*300, vx:0, vy:0}));
            const links = data.links.filter(l => nodes.find(n=>n.id===l.source) && nodes.find(n=>n.id===l.target));
            const nodeMap = Object.fromEntries(nodes.map(n => [n.id, n]));

            // Run simple force simulation
            for (let tick = 0; tick < 200; tick++) {
                // Repulsion
                for (let i = 0; i < nodes.length; i++) {
                    for (let j = i+1; j < nodes.length; j++) {
                        let dx = nodes[j].x - nodes[i].x, dy = nodes[j].y - nodes[i].y;
                        let dist = Math.sqrt(dx*dx + dy*dy) || 1;
                        let force = 5000 / (dist * dist);
                        nodes[i].vx -= dx/dist * force; nodes[i].vy -= dy/dist * force;
                        nodes[j].vx += dx/dist * force; nodes[j].vy += dy/dist * force;
                    }
                }
                // Attraction (links)
                for (const l of links) {
                    const s = nodeMap[l.source], t = nodeMap[l.target];
                    if (!s || !t) continue;
                    let dx = t.x - s.x, dy = t.y - s.y;
                    let dist = Math.sqrt(dx*dx + dy*dy) || 1;
                    let force = (dist - 150) * 0.01;
                    s.vx += dx/dist * force; s.vy += dy/dist * force;
                    t.vx -= dx/dist * force; t.vy -= dy/dist * force;
                }
                // Center gravity
                for (const n of nodes) {
                    n.vx += (w/2 - n.x) * 0.001;
                    n.vy += (h/2 - n.y) * 0.001;
                    n.x += n.vx * 0.3; n.y += n.vy * 0.3;
                    n.vx *= 0.9; n.vy *= 0.9;
                    n.x = Math.max(40, Math.min(w-40, n.x));
                    n.y = Math.max(40, Math.min(h-40, n.y));
                }
            }

            const colors = {1: '#6c8cff', 2: '#4ade80', 3: '#a78bfa'};
            let svgContent = '';

            // Draw links
            for (const l of links) {
                const s = nodeMap[l.source], t = nodeMap[l.target];
                if (!s || !t) continue;
                svgContent += `<line x1="${s.x}" y1="${s.y}" x2="${t.x}" y2="${t.y}" stroke-width="${Math.min(l.width||1,5)}" />`;
            }
            // Draw nodes
            for (const n of nodes) {
                const r = Math.max(8, Math.min(30, n.size || 10));
                const c = colors[n.group] || '#8b8fa3';
                svgContent += `<circle cx="${n.x}" cy="${n.y}" r="${r}" fill="${c}" opacity="0.8" onclick="showBlastRadius('${n.id}')" />`;
                svgContent += `<text x="${n.x}" y="${n.y - r - 5}" text-anchor="middle">${n.id.length > 20 ? n.id.slice(0,18)+'...' : n.id}</text>`;
            }
            svg.innerHTML = svgContent;
        }

        function renderSidebar(analysis) {
            document.getElementById('criticalList').innerHTML = analysis.critical_services.map(s =>
                `<li onclick="showBlastRadius('${s.id}')"><span class="badge-service">${s.id}</span><span class="count">${s.total_calls} calls</span></li>`
            ).join('') || '<li style="color:var(--text-dim)">None found</li>';

            document.getElementById('spofList').innerHTML = analysis.spofs.map(s =>
                `<li onclick="showBlastRadius('${s.service}')"><span class="badge-critical">${s.service}</span><span class="count">${s.affected_percentage}%</span></li>`
            ).join('') || '<li style="color:var(--text-dim)">None found</li>';

            document.getElementById('orphanList').innerHTML = analysis.orphaned.map(s =>
                `<li><span class="badge-third-party">${s.id}</span><span class="count">${s.type}</span></li>`
            ).join('') || '<li style="color:var(--text-dim)">None found</li>';
        }

        async function showBlastRadius(service) {
            const data = await fetchJSON(`/api/graph/blast-radius/${encodeURIComponent(service)}`);
            document.getElementById('blastPanel').classList.add('visible');
            document.getElementById('blastService').textContent = service;
            document.getElementById('blastCount').textContent = data.affected_count;
            document.getElementById('blastList').innerHTML = data.affected_services.map(s =>
                `<li>${s}</li>`
            ).join('') || '<li style="color:var(--text-dim)">No downstream impact</li>';
        }

        loadGraph();
    </script>
</body>
</html>
"""
