# API Scout

**API Discovery & Inventory Tool** — Find, catalog, and monitor every API in your environment.

API Scout combines passive log analysis with active network scanning to build a complete picture of your API landscape. It identifies shadow APIs, unauthenticated endpoints, zombie services, and more — addressing [OWASP API Security Top 10 #9: Improper Inventory Management](https://owasp.org/API-Security/editions/2023/en/0xa9-improper-inventory-management/).

---

## Features

### Multi-Format Log Parsing

API Scout auto-detects and parses access logs from multiple sources:

| Format | Source | What It Extracts |
|---|---|---|
| **Nginx** | Combined log format | Method, path, status, IP, response time, auth headers |
| **AWS ALB** | Application Load Balancer access logs | Full request URL, client IP, target processing time, host |
| **AWS API Gateway** | JSON-formatted stage logs | Resource path, authorizer type, domain, caller identity |
| **Generic** | JSON logs or simple text patterns | Flexible key matching across common field names |

The auto-detection engine samples the first 10 lines of each file, scores each parser by match rate, and selects the best fit. Specific parsers take priority over the generic fallback to avoid false positives.

### Active Network Scanning

Discovers HTTP services and API specifications across your infrastructure:

- **Port scanning** — Checks common HTTP ports (80, 443, 8080, 8443, 3000, 5000, 8000, etc.) with configurable port lists
- **OpenAPI/Swagger discovery** — Probes 10+ common spec paths (`/openapi.json`, `/swagger.json`, `/v3/api-docs`, etc.)
- **Endpoint extraction** — Parses discovered OpenAPI specs to extract all declared endpoints with their methods and deprecation status
- **CIDR support** — Accepts individual hosts, IPs, or CIDR ranges (e.g., `10.0.0.0/24`) with configurable concurrency

### Path Normalization

Concrete paths are normalized into patterns for accurate deduplication:

| Raw Path | Normalized Pattern |
|---|---|
| `/users/123` | `/users/{id}` |
| `/orders/550e8400-e29b-41d4-a716-446655440000` | `/orders/{uuid}` |
| `/items/507f1f77bcf86cd799439011` | `/items/{objectId}` |
| `/tokens/a1b2c3d4e5f6g7h8i9j0k1l2m3n4` | `/tokens/{token}` |

### Endpoint Classification

Every discovered endpoint is classified into one of five statuses:

| Status | Meaning | Risk Level |
|---|---|---|
| **Active** | In spec and receiving recent traffic | Normal |
| **Shadow** | Receiving traffic but not declared in any spec | High — unknown, unreviewed endpoints |
| **Zombie** | Declared in spec but no traffic in N days | Medium — forgotten, possibly unpatched |
| **Undocumented** | No spec, no owner assigned | Medium — governance gap |
| **Deprecated** | Marked deprecated in OpenAPI spec | Low — should be decommissioned |

### Security Alerts

API Scout generates alerts for common security and operational concerns:

| Alert | Trigger |
|---|---|
| **Shadow API** | Endpoint receives traffic but isn't in any OpenAPI spec |
| **Unauthenticated** | Traffic observed with no authentication headers |
| **High Error Rate** | More than 50% error responses over 10+ calls |
| **New Endpoint** | First seen within the last 24 hours |
| **Zombie API** | In spec but no traffic for the configured threshold (default: 30 days) |

### SQLite Persistence

All data is stored in a local SQLite database with four tables:

- **endpoints** — Full inventory with upsert-on-rescan semantics. Tracks method, path pattern, host, status, auth methods seen, consumers, call counts, error rates, response times, and discovery sources.
- **traffic_log** — Raw traffic records for historical analysis. Enables timeline charts and trend detection.
- **scan_history** — Audit trail of every analysis run and network scan with timestamps, target lists, and result counts.
- **alerts** — Persistent alert store with severity levels, types, acknowledgement status, and timestamps.

The database uses WAL mode for concurrent read/write access, allowing the dashboard to query while the watcher writes.

### Continuous Monitoring (Watch Mode)

Long-running process that provides real-time API discovery:

- **Log tailing** — Watches log files for new lines (similar to `tail -f`), handles log rotation gracefully
- **Periodic scanning** — Runs network scans on a configurable interval (default: hourly)
- **Live persistence** — Saves discoveries to the database as they happen
- **Configurable intervals** — Log check frequency and scan frequency are independently tunable
- **Graceful shutdown** — Saves final state on `SIGINT`/`SIGTERM`

### Web Dashboard

Single-page dashboard built with FastAPI and vanilla JavaScript:

- **Summary cards** — Total endpoints, active, shadow, zombie, unauthenticated, active alerts
- **Traffic timeline** — Bar chart showing request volume and errors over the last 24 hours
- **Endpoint table** — Filterable by status (all/shadow/active/zombie/undocumented), searchable by path/host
- **Alert panel** — Lists all alerts with severity, supports acknowledgement
- **Scan history** — Shows recent scans with type, targets, results, and status
- **Auto-refresh** — Polls the API every 30 seconds for live updates
- **Dark theme** — Designed for SOC/operations use

### Docker Support

Production-ready containerization with Docker Compose:

- **Dashboard service** — Always-on web interface on port 8080
- **Watcher service** — Continuous monitoring with log tailing and periodic scans (via `monitoring` profile)
- **One-shot tools** — Run analysis or scans as ephemeral containers (via `tools` profile)
- **Shared volume** — Dashboard and watcher share the same SQLite database for real-time visibility
- **Log mounting** — Mount host log directories as read-only volumes

---

## Quick Start

### Local

```bash
# Install dependencies
pip install rich httpx pydantic click pyyaml fastapi uvicorn

# Analyze sample data
python3 -m api_scout.cli analyze samples/nginx_access.log samples/generic_json.log

# Launch dashboard
python3 -m api_scout.cli dashboard
# Open http://127.0.0.1:8080
```

### Docker

```bash
# Dashboard only
docker compose up dashboard

# Dashboard + continuous monitoring
docker compose --profile monitoring up -d

# One-shot log analysis
docker compose run analyze analyze /logs/access.log

# One-shot network scan
docker compose run scan scan 192.168.1.0/24
```

---

## CLI Reference

```
api-scout [--db DB_PATH] COMMAND [OPTIONS]
```

| Command | Description |
|---|---|
| `analyze <logs...>` | Parse log files and discover endpoints |
| `scan <targets...>` | Active network scan for HTTP services and OpenAPI specs |
| `full <logs...> -s <targets>` | Combined log analysis + network scanning |
| `watch -l <logs> -s <targets>` | Continuous monitoring mode |
| `dashboard [-h HOST] [-p PORT]` | Launch the web dashboard |
| `status` | Show inventory summary from the database |
| `alerts [-u]` | View alerts (optionally unacknowledged only) |
| `search <query>` | Search endpoints by path, host, or service name |

### Global Options

| Option | Default | Description |
|---|---|---|
| `--db` | `api_scout.db` | Path to the SQLite database file |

### Analyze Options

| Option | Default | Description |
|---|---|---|
| `-f, --format` | `auto` | Log format: `nginx`, `alb`, `apigateway`, `generic`, `auto` |
| `-o, --output` | — | Save report as JSON |
| `--zombie-days` | `30` | Days without traffic before marking as zombie |

### Watch Options

| Option | Default | Description |
|---|---|---|
| `-l, --logs` | — | Log file(s) to watch |
| `-s, --scan-targets` | — | Hosts/CIDRs for periodic scanning |
| `--log-interval` | `30` | Seconds between log checks |
| `--scan-interval` | `3600` | Seconds between network scans |

---

## Architecture

```
┌──────────────────────────────────────────────────────────┐
│                    Web Dashboard (:8080)                  │
│            FastAPI + Vanilla JS, auto-refresh             │
├──────────────────────────────────────────────────────────┤
│                     REST API Layer                        │
│    /api/summary  /api/endpoints  /api/alerts  /api/scans │
├──────────────────────────────────────────────────────────┤
│                   SQLite Database                         │
│         endpoints | traffic_log | alerts | scans          │
├────────────────┬─────────────────────────────────────────┤
│   Inventory    │            Scheduler                     │
│    Engine      │     Log Watcher + Periodic Scans         │
├────────┬───────┴──┬──────────────────────────────────────┤
│ Parsers│  Scanner │                                       │
│ Nginx  │  Port    │                                       │
│ ALB    │  OpenAPI  │                                       │
│ APIGW  │  CIDR    │                                       │
│ Generic│          │                                       │
└────────┴──────────┴──────────────────────────────────────┘
```

---

## OWASP API Security Coverage

API Scout directly addresses **OWASP API9: Improper Inventory Management** and provides visibility that supports mitigating several other OWASP API Top 10 risks:

| OWASP Risk | How API Scout Helps |
|---|---|
| **API1: BOLA** | Identifies endpoints and their consumers — review access patterns |
| **API2: Broken Authentication** | Flags endpoints receiving unauthenticated traffic |
| **API5: BFLA** | Discovers admin/internal endpoints that may lack authorization |
| **API8: Security Misconfiguration** | Detects debug endpoints (`/pprof`, `/metrics`) exposed externally |
| **API9: Improper Inventory Management** | Core purpose — full API catalog with shadow/zombie detection |
| **API10: Unsafe Consumption** | DNS/outbound log analysis reveals third-party API dependencies |
