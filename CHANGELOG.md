# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] — 2026-04-21

This is the first release intended for operation outside a developer's
laptop. It adds authentication, role-based access control, an audit log,
defensive controls against XSS/CSRF/brute-force, operational endpoints
(health/readiness/metrics), and the legal foundations (LICENSE, NOTICE,
SECURITY, CONTRIBUTING, CODE_OF_CONDUCT) needed to accept contributions
and disclosures.

### Added

- **Authentication.** Dashboard sign-in flow at `/login`, bcrypt password
  hashing (cost 12), timing-equalised credential check on unknown
  usernames, account lockout (5 failures / 15 minutes).
- **Server-side sessions** with 256-bit random tokens delivered in a
  signed cookie (`HttpOnly`, `SameSite=strict`, `Secure`-when-TLS) and
  a 12-hour TTL.
- **RBAC.** Three roles — `viewer` (read), `analyst` (read + alert
  triage + WAF generation), `admin` (everything including user
  management). Enforced via FastAPI dependencies.
- **Audit log.** Every mutating HTTP request (POST/PUT/PATCH/DELETE),
  every login attempt, and every admin action is recorded with timestamp,
  actor, method, path, IP, user agent, and status code. Queryable via
  `api-scout audit` and via `/audit` in the dashboard (admin-only).
- **Login rate limiting.** IP-based sliding-window limiter, 10 attempts
  per 5 minutes per client IP. Rejects before `bcrypt` runs, so
  rate-exceeding attackers cannot burn CPU. Rate-limited attempts are
  audited as `auth.login.rate_limited` and exposed via the
  `api_scout_login_attempts_total{result="rate_limited"}` counter.
- **CSRF protection.** Double-submit-cookie model on every mutating
  route. `csrf_token` cookie issued on login success and self-healed on
  safe requests; `X-CSRF-Token` header (or `csrf_token` form field)
  required on unsafe methods. Constant-time compare.
- **Operations endpoints** (open, no auth):
  - `GET /health` — liveness.
  - `GET /ready` — readiness (checks SQLite reachable).
  - `GET /metrics` — Prometheus exposition with bounded-cardinality
    labels (route templates, never raw paths).
- **Structured JSON logs.** One event per line with `ts`, `level`,
  `logger`, `msg`, and caller-attached `extra` fields.
- **Security headers.** CSP (`default-src 'self'`), `X-Frame-Options:
  DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy:
  no-referrer`, restrictive `Permissions-Policy`.
- **CLI user management.** `api-scout user {create,list,passwd,role,
  disable,enable,delete}`; refuses to delete the last admin.
- **CLI audit command.** `api-scout audit [--limit N] [--action A]
  [--username U]`.
- **Non-root Docker image.** Container runs as UID 10001 with a built-in
  `HEALTHCHECK` hitting `/health`.
- **Secret management.** `API_SCOUT_SECRET` env var for the
  session-cookie signing key (must be ≥ 32 chars); auto-generated and
  persisted in the `app_meta` table if unset.
- **Test suite.** 92 tests covering auth, RBAC, audit, rate limiting,
  CSRF, XSS regressions, and database invariants. `pytest` and
  `pytest-asyncio` as test-extras.
- **Legal foundations.**
  - `LICENSE` — Apache License 2.0.
  - `NOTICE` — third-party attribution as required by Apache 2.0 §4(d).
  - `SECURITY.md` — responsible disclosure policy with CVSS-based SLAs,
    safe harbour, and an explicit in/out-of-scope list.
  - `CONTRIBUTING.md` — development setup, code style, security-
    sensitive-change guidance, PR workflow, DCO 1.1 sign-off.
  - `CODE_OF_CONDUCT.md` — Contributor Covenant 2.1.

### Changed

- **Dashboard refuses to start without an active admin user.** Bootstrap
  with `api-scout user create --role admin <username>`.
- **README.md** — rewritten quick-start to match the authenticated
  deployment flow, documented the full CLI surface including
  `user`/`audit` subcommands, and added Community & governance and
  License sections.
- **`pyproject.toml`** — added `bcrypt`, `itsdangerous`,
  `prometheus-client`; added PEP 639 `license = "Apache-2.0"` +
  `license-files`; added classifiers, keywords, and `project.urls`;
  restricted `[tool.setuptools.packages.find]` so `tests/` is excluded
  from the built distribution.

### Fixed

- **Stored XSS in the dashboard.** All user-controlled strings that
  reach the DOM now go through an `esc()` helper. Event handlers use
  data-attributes + delegated listeners instead of string interpolation
  into inline `onclick`. Graph SVG nodes are built with
  `createElementNS` + `textContent`.
- **User enumeration via timing.** Unknown-username login now runs a
  bcrypt check against a pre-computed hash so response time does not
  reveal whether the account exists.
- **Session expiry off-by-a-timezone.** Session timestamps are stored in
  the native SQLite `YYYY-MM-DD HH:MM:SS` format, matching
  `datetime('now')`, so `expires_at < now` comparisons work across the
  T-separator vs space boundary.
- **JSON log timestamps** now include millisecond precision; the
  previous `%f` format specifier was not expanded by `logging.Formatter`.

### Security

- No known vulnerabilities in this release. See `SECURITY.md` for
  disclosure channels.

## [0.1.0] — 2026-04-08

Initial feature-complete milestone — the "single-user, local-laptop"
tool before the shipping-readiness work.

### Added

- Multi-format log parser (Nginx combined, AWS ALB, AWS API Gateway,
  generic JSON) with auto-detection by sampling + scoring.
- Active network scanner for HTTP services and OpenAPI/Swagger specs
  across hosts, IPs, and CIDRs.
- Path normalisation (`/users/123` → `/users/{id}`,
  `/orders/<uuid>` → `/orders/{uuid}`, etc.) for deduplication.
- Endpoint classification: active / shadow / zombie / undocumented /
  deprecated.
- SQLite persistence (`endpoints`, `traffic_log`, `scan_history`,
  `alerts`) with WAL mode.
- Alerting for shadow APIs, unauthenticated traffic, high error rates,
  new endpoints, and zombies.
- Watch mode (log tailing + periodic scans).
- Web dashboard (single page) with summary cards, traffic timeline,
  endpoint table, alert panel, scan history.
- CLI: `analyze`, `scan`, `full`, `watch`, `dashboard`, `status`,
  `alerts`, `search`, `graph`, `validate`, `generate-spec`,
  `generate-waf`.
- Docker + Compose packaging with `dashboard`, `watcher`, `analyze`,
  and `scan` services.
- ASPM features: CI/CD validation of OpenAPI specs against live
  inventory (GitHub Actions annotations supported), anomaly detection,
  egress tracking, dependency graph with blast-radius analysis,
  remediation (auto-generated OpenAPI stubs and WAF rules).

[Unreleased]: https://github.com/rzawadzk/APISecurity/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/rzawadzk/APISecurity/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/rzawadzk/APISecurity/releases/tag/v0.1.0
