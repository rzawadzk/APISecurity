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

### Authentication, RBAC, and audit

Dashboard access is authenticated and role-gated — no endpoint other than
`/login`, `/health`, `/ready`, and `/metrics` is reachable anonymously.

- **Three roles** — `viewer` (read-only), `analyst` (read + mutations like
  acknowledging alerts), `admin` (read + mutations + user management).
- **Sessions** — 256-bit random tokens stored server-side, signed cookies
  with `HttpOnly`, `SameSite=strict`, and `Secure` when behind TLS.
- **Passwords** — bcrypt (cost 12) with a timing-equalised check on unknown
  usernames. Account lockout after 5 failed attempts in 15 minutes.
- **Login throttling** — IP-based sliding-window rate limiter
  (10 attempts per 5 minutes per client IP) gates `/api/auth/login`
  before the bcrypt check so rate-exceeding attackers don't burn CPU.
- **CSRF** — double-submit cookie protection on every state-changing
  route. A `csrf_token` cookie is issued on login (and self-healed on
  safe requests); mutating requests must echo it in `X-CSRF-Token` or a
  matching form field. Enforcement is constant-time.
- **Audit log** — every mutating request (POST/PUT/PATCH/DELETE) and every
  auth event is recorded with timestamp, actor, action, target, and IP.
  Queryable via `api-scout audit` and via `/audit` in the dashboard.

### Operations & observability

- **`/health`** — liveness probe (always 200 when the process is up).
- **`/ready`** — readiness probe (checks SQLite is reachable).
- **`/metrics`** — Prometheus exposition with bounded-cardinality labels
  (route templates, never raw paths) covering request counts, latency
  histograms, endpoint totals by status, and active alert counts.
- **Structured JSON logs** — one event per line with `ts`, `level`,
  `logger`, `msg`, plus any structured fields attached via `extra={}`.
- **Security headers** — CSP, `X-Frame-Options: DENY`,
  `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`,
  `Permissions-Policy` locked down.
- **Non-root container** — the shipped Docker image runs as UID 10001.

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

Requires Python 3.10+.

```bash
# 1. Install (editable, with test extras optional)
pip install -e .

# 2. Populate inventory from sample data
api-scout --db api_scout.db analyze samples/nginx_access.log samples/generic_json.log

# 3. Bootstrap an admin user — the dashboard refuses to start without one
api-scout --db api_scout.db user create --role admin admin
#   (or pass --password devpass01 for non-interactive bootstrap)

# 4. Launch the dashboard
api-scout --db api_scout.db dashboard -p 8080

# 5. Sign in at http://127.0.0.1:8080/login with the admin credentials.
```

Open-to-the-world endpoints (no auth required):

- `http://127.0.0.1:8080/health` — liveness
- `http://127.0.0.1:8080/ready` — readiness
- `http://127.0.0.1:8080/metrics` — Prometheus

### Docker

The shipped image runs as the non-root `apiscout` user (UID 10001) and has
a built-in `HEALTHCHECK` hitting `/health`.

```bash
# Build once
docker build -t api-scout:local .

# Bootstrap admin inside a shared volume
docker run --rm -v api-scout-data:/data api-scout:local \
    --db /data/api_scout.db user create --role admin --password devpass01 admin

# Run the dashboard (terminate TLS in front of it in production)
docker run -d --name api-scout \
    -p 8080:8080 \
    -v api-scout-data:/data \
    -e API_SCOUT_SECRET="$(python3 -c 'import secrets;print(secrets.token_urlsafe(48))')" \
    api-scout:local --db /data/api_scout.db dashboard -h 0.0.0.0 -p 8080
```

Or with Docker Compose:

```bash
# Dashboard only (bootstrap admin first — see above)
docker compose up dashboard

# Dashboard + continuous monitoring
docker compose --profile monitoring up -d

# One-shot log analysis
docker compose run analyze analyze /logs/access.log

# One-shot network scan
docker compose run scan scan 192.168.1.0/24
```

### Environment variables

| Variable | Default | Purpose |
|---|---|---|
| `API_SCOUT_SECRET` | auto-generated, persisted to DB | Session-cookie signing key. Set to a 48+ character random string in production so you can rotate it without rebuilding. Must be at least 32 characters if set. |

Everything else is configured via CLI flags (`--db`, `--log-level`, etc.).

---

## CLI Reference

```
api-scout [--db DB_PATH] COMMAND [OPTIONS]
```

### Inventory & discovery

| Command | Description |
|---|---|
| `analyze <logs...>` | Parse log files and discover endpoints |
| `scan <targets...>` | Active network scan for HTTP services and OpenAPI specs |
| `full <logs...> -s <targets>` | Combined log analysis + network scanning |
| `watch -l <logs> -s <targets>` | Continuous monitoring mode |
| `status` | Show inventory summary from the database |
| `alerts [-u]` | View alerts (optionally unacknowledged only) |
| `search <query>` | Search endpoints by path, host, or service name |
| `graph` | Show service dependency graph and blast-radius analysis |
| `validate <spec>` | Validate an OpenAPI spec against observed traffic |
| `generate-spec` | Auto-generate an OpenAPI spec from observed traffic |
| `generate-waf` | Generate WAF rules to block shadow APIs |

### Dashboard, auth, and audit

| Command | Description |
|---|---|
| `dashboard [-h HOST] [-p PORT] [--log-level LVL]` | Launch the web dashboard (refuses to start without an admin user) |
| `user create <username> [--role admin\|analyst\|viewer] [--password PWD] [--email ADDR]` | Create a dashboard user |
| `user list` | List all dashboard users |
| `user passwd <username>` | Reset a user's password (prompts) |
| `user role <username> <admin\|analyst\|viewer>` | Change a user's role |
| `user disable <username>` | Disable a user (preserves audit history) |
| `user enable <username>` | Re-enable a disabled user |
| `user delete <username>` | Permanently delete a user (refuses if it would remove the last admin) |
| `audit [--limit N] [--action A] [--username U]` | Show recent audit log entries |

### Global options

| Option | Default | Description |
|---|---|---|
| `--db` | `api_scout.db` | Path to the SQLite database file |

### `analyze` options

| Option | Default | Description |
|---|---|---|
| `-f, --format` | `auto` | Log format: `nginx`, `alb`, `apigateway`, `generic`, `auto` |
| `-o, --output` | — | Save report as JSON |
| `--zombie-days` | `30` | Days without traffic before marking as zombie |

### `watch` options

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

---

## Community & governance

| Document | Purpose |
|---|---|
| [CONTRIBUTING.md](CONTRIBUTING.md) | Development setup, test commands, code style, PR workflow, DCO sign-off |
| [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | Contributor Covenant 2.1 — community behaviour standards |
| [SECURITY.md](SECURITY.md) | How to report a vulnerability; SLA commitments; in/out of scope |
| [NOTICE](NOTICE) | Third-party attribution required by Apache 2.0 §4(d) |
| [LICENSE](LICENSE) | Apache License 2.0 full text |

### Reporting issues

- **Bug reports and feature requests** — open a GitHub issue.
- **Security vulnerabilities** — **do not** open a public issue. Use GitHub
  Security Advisories or email `rafzaw@gmail.com`; see
  [SECURITY.md](SECURITY.md) for details.
- **Code of Conduct incidents** — email `rafzaw@gmail.com` with subject
  `[conduct] api-scout: <short description>`.

## License

API Scout is licensed under the [Apache License 2.0](LICENSE). In short:

- **Free for commercial and private use.** You can run, modify, and
  redistribute API Scout in your own projects, including commercial ones.
- **Attribution required.** Redistributions must retain the
  [LICENSE](LICENSE) and [NOTICE](NOTICE) files.
- **Patent grant.** Contributors grant you a royalty-free patent licence
  covering their contributions (and that grant terminates if you sue the
  project over patents).
- **No warranty.** The software is provided "as is".

Contributions are licensed under the same Apache 2.0 terms. We use the
[Developer Certificate of Origin](CONTRIBUTING.md#developer-certificate-of-origin)
rather than a CLA — just sign your commits with `git commit -s`.
