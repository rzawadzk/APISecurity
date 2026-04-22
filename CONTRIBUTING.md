# Contributing to API Scout

Thanks for your interest in improving API Scout. This document covers how to
set up a development environment, run tests, style conventions, and the
contribution process.

If you are reporting a security vulnerability, **do not open a public issue**
— follow [SECURITY.md](SECURITY.md) instead.

## Ground rules

- By submitting a contribution, you license it under the [Apache License 2.0](LICENSE)
  and certify that you have the right to do so (see [Developer Certificate
  of Origin](#developer-certificate-of-origin) below).
- Be respectful. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
- Small, focused PRs are much easier to review than large ones. If you are
  making a significant change, open a GitHub issue first to discuss the
  approach.

## Development setup

Requires Python 3.10+. Recommended: a clean virtualenv.

```bash
git clone https://github.com/rzawadzk/APISecurity.git
cd APISecurity
python3 -m venv .venv
source .venv/bin/activate
pip install -e '.[test]'
```

Bootstrap a local admin so you can actually open the dashboard:

```bash
api-scout --db dev.db user create --role admin --password devpass01 dev
api-scout --db dev.db dashboard -p 8080
```

Then sign in at http://127.0.0.1:8080/login with `dev` / `devpass01`.

## Running tests

```bash
pytest                       # full suite
pytest tests/test_auth.py    # one file
pytest -k xss                # one test expression
pytest -x --tb=short         # stop on first failure, short traceback
```

The test suite must be green before a PR is merged. CI will run the same
command on every push.

### Coverage

```bash
pip install coverage
coverage run --source=api_scout -m pytest
coverage report --show-missing
```

**Current coverage** is ~29% overall but ≥86% on the security-critical
modules (`auth.py`, `csrf.py`, `ratelimit.py`, `proxy.py`,
`dashboard.py`, `database.py`, `observability.py`). CI hard-gates that
subset at ≥75%.

**Expectations for contributions:**

- New code in a security-critical module: **≥90% line coverage**, and
  CI will fail if the subset drops below 75%.
- New code elsewhere: a unit test covering the happy path plus at least
  one failure mode. No hard gate yet — raising overall coverage to 60%
  is a roadmap item. New code should not make the overall number worse.

## Code style

- **Formatting**: 4-space indent, no tabs, max line length ~100. If you want
  a formatter, use `black` (the repo is compatible). No configuration yet,
  but contributions that introduce one are welcome.
- **Types**: prefer explicit type hints on public functions. Use
  `from __future__ import annotations` in new modules so forward references
  work without quoting.
- **Imports**: standard library first, then third-party, then local — each
  block separated by a blank line. Within a block, sort alphabetically.
- **Logging**: use `observability.get_logger(__name__)`. Attach structured
  fields via `log.info("event_name", extra={"field": value})` — the
  JSON formatter will include them automatically. Never log passwords,
  session tokens, full request bodies, or PII.
- **Error handling**: catch narrow exceptions. A bare `except:` or
  `except Exception:` that swallows and logs is acceptable only at
  middleware boundaries where the alternative is crashing the server.

## Testing guidance

- Every new public function should have a unit test.
- Every new HTTP route should have a test that covers:
  1. An unauthenticated request returns the expected status (401/303).
  2. A user without the required role returns 403.
  3. A user with the right role can perform the action.
  4. Mutations appear in the audit log.
- Tests that hit the database should use the `db` fixture in
  `tests/conftest.py` — it creates a fresh SQLite DB under `tmp_path`.
- Tests that hit the dashboard should use the `client` fixture.

## Security-sensitive changes

Anything touching authentication, session management, RBAC, XSS/injection
escaping, or audit logging gets extra scrutiny. Specifically:

- Never concatenate user-controlled strings into SQL. Use parameterised
  queries via `sqlite3`'s `?` placeholders.
- Never interpolate user-controlled strings into HTML or JavaScript
  literals. The frontend uses an `esc()` helper for this — see the JS
  prelude at the top of `DASHBOARD_HTML` in `api_scout/dashboard.py`.
- New dashboard routes must declare a role dependency
  (`require_viewer`, `require_analyst`, or `require_admin`) unless they
  are intentionally public (`/health`, `/ready`, `/metrics`, `/login`).
- Mutating routes (POST/PUT/PATCH/DELETE) must either be covered by
  `AuditMiddleware` (automatic) or write an explicit audit entry with
  `db.write_audit(...)` if you need richer detail.

If you are unsure whether a change is security-sensitive, open an issue and
ask.

## Pull-request workflow

1. Fork the repo and create a feature branch:
   `git checkout -b feat/short-description` or `fix/short-description`.
2. Make changes with tests.
3. Run the full test suite locally.
4. Commit with a descriptive message (see below).
5. Push and open a PR against `main`.
6. Respond to review feedback; force-pushes on your feature branch are fine.
7. A maintainer merges once CI is green and review is approved.

### Commit message format

```
<component>: <imperative one-line summary, under 72 chars>

<optional longer body explaining the *why*, wrapped at ~72 columns>

Signed-off-by: Your Name <your.email@example.com>
```

Examples:

- `auth: add IP-based rate limiting to login endpoint`
- `dashboard: fix off-by-one in traffic timeline bucketing`
- `docs: clarify TLS termination requirements in SECURITY.md`

## Developer Certificate of Origin

By signing off your commit (`git commit -s`) you certify the following
(from https://developercertificate.org):

> Developer's Certificate of Origin 1.1
>
> By making a contribution to this project, I certify that:
>
> (a) The contribution was created in whole or in part by me and I
>     have the right to submit it under the open source license
>     indicated in the file; or
>
> (b) The contribution is based upon previous work that, to the best
>     of my knowledge, is licensed under an appropriate open source
>     license and I have the right under that license to submit that
>     work with modifications, whether created in whole or in part
>     by me, under the same open source license (unless I am
>     permitted to submit under a different license), as indicated
>     in the file; or
>
> (c) The contribution was provided directly to me by some other
>     person who certified (a), (b) or (c) and I have not modified
>     it.
>
> (d) I understand and agree that this project and the contribution
>     are public and that a record of the contribution (including all
>     personal information I submit with it, including my sign-off) is
>     maintained indefinitely and may be redistributed consistent with
>     this project or the open source license(s) involved.

Enable sign-off automatically with:

```bash
git config --local format.signOff true
```

## Roadmap & priorities

If you are looking for a good first contribution, check the
[open issues labelled `good-first-issue`](https://github.com/rzawadzk/APISecurity/issues?q=is%3Aissue+is%3Aopen+label%3Agood-first-issue).

Larger contributions in these areas are especially welcome:

- **Integrations**: Slack / PagerDuty / Jira / generic webhook outbound
  connectors.
- **Parsers**: additional log formats (Caddy, Traefik, Envoy, GCP load
  balancer, Azure App Gateway).
- **Postgres backend** alongside SQLite — see the
  [roadmap discussion](https://github.com/rzawadzk/APISecurity/discussions)
  for the migration strategy.
- **SSO** (OIDC, SAML).

## Licensing of contributions

All contributions are licensed under Apache 2.0 (the project's license).
If your contribution incorporates third-party code, it must be compatible
with Apache 2.0 and you must update [NOTICE](NOTICE) with the appropriate
attribution.

We may in the future offer a separate commercial / enterprise tier of
specific features. Any such tier will be in a clearly-labelled directory
or repository under its own license, and **will not retroactively relicense
contributions you have submitted under Apache 2.0**.

## Questions?

Open a [GitHub Discussion](https://github.com/rzawadzk/APISecurity/discussions)
or email rafzaw@gmail.com.
