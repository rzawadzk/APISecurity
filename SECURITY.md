# Security Policy

API Scout is itself a security tool, so we take vulnerability reports seriously.
This document describes how to report a vulnerability, what is in scope, and
the commitments we make in return.

## Reporting a vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Use one of the following private channels:

1. **GitHub Security Advisories (preferred)** — open a private advisory at
   https://github.com/rzawadzk/APISecurity/security/advisories/new
2. **Email** — send a report to **rafzaw@gmail.com** with the subject line
   `[security] api-scout: <short description>`.

To help us triage quickly, please include:

- The version / commit SHA you tested against.
- A description of the vulnerability and its impact.
- Reproduction steps, ideally a minimal proof-of-concept (log snippets,
  HTTP requests, or a short script).
- Any suggested mitigation.
- Whether you wish to be credited in the public advisory and under what name.

If you need to send encrypted material, request a PGP key in the first
message and we will provide one.

## Our commitments

| Stage | Commitment |
|---|---|
| Acknowledgement | We acknowledge every report within **3 business days**. |
| Triage | Initial severity and in-scope determination within **10 business days**. |
| Fix | Critical (CVSS >= 9.0) vulnerabilities: patch within **30 days** of confirmation. High (7.0–8.9): **60 days**. Medium and below: **90 days**. |
| Disclosure | Coordinated public disclosure by default, no later than **90 days** after the initial report. We may publish earlier once a fix ships and users have had a reasonable window to upgrade. |
| Credit | Researchers are credited in the public advisory unless they request otherwise. |

If we cannot meet a timeline — for example because a fix requires upstream
work on a dependency — we will tell the reporter and agree a revised schedule.

## Safe harbour

We will not pursue legal action or law-enforcement investigation against
security researchers who:

- Act in good faith and follow this policy.
- Avoid privacy violations, data destruction, or service disruption
  beyond what is strictly necessary to demonstrate the vulnerability.
- Give us a reasonable window to remediate before public disclosure.
- Test only against their own installations or explicitly authorised
  test environments — **not against any third-party system that happens to
  run API Scout**.
- Do not exfiltrate customer data or credentials.

If you are unsure whether an activity falls within this policy, ask first.

## Scope

**In scope:**

- The `api_scout` Python package shipped from this repository.
- The official Docker image built from the `Dockerfile` in this repository.
- The dashboard HTTP endpoints (auth, API, health, metrics).
- The CLI (`api-scout ...`).
- Documentation that, if followed, would lead a user into a vulnerable
  configuration.

**Out of scope:**

- Vulnerabilities that require an already-compromised admin account
  (e.g. SQL injection via an admin-only `--db` path argument is not
  a vulnerability — that argument is trusted input from the operator).
- Rate limiting on the dashboard is a known gap and tracked publicly;
  reports about it are welcome but do not qualify as novel findings.
- Issues in third-party dependencies that have not been published as CVEs
  upstream — please report those to the dependency first; we will track
  and update once a fix ships.
- Social engineering, physical attacks, or attacks requiring physical
  access to the host.
- Self-XSS (the user pasting JavaScript into their own browser console).
- Vulnerabilities that require using a `--secret` or `API_SCOUT_SECRET`
  value shorter than the documented minimum.
- Findings reported from automated scanners without a working
  proof-of-concept against a running instance.

## Severity ratings

We use CVSS v3.1 base score plus our own judgement of real-world impact.
The ratings below guide SLA and public-disclosure timing:

| Rating | CVSS | Examples |
|---|---|---|
| Critical | 9.0 – 10.0 | Pre-auth RCE, authentication bypass, arbitrary DB write |
| High | 7.0 – 8.9 | Privilege escalation, stored XSS in an authenticated view, session hijack |
| Medium | 4.0 – 6.9 | Audit-log tampering by admin, CSRF on non-mutating endpoint |
| Low | 0.1 – 3.9 | Information disclosure that is already public; missing header of defence-in-depth value only |

## Hardening recommendations for operators

Independent of specific vulnerability reports, API Scout should be deployed
with the following controls in place. Reports that reduce to "operator did not
follow these" are treated as documentation bugs, not product vulnerabilities.

1. **Terminate TLS in front of the dashboard.** The shipped server speaks HTTP
   and sets `Secure` on the session cookie only when behind a TLS proxy.
2. **Set `API_SCOUT_SECRET`** to a random 48+ character value in production
   instead of relying on the auto-generated secret, so you can rotate it
   without rebuilding the container.
3. **Run the container as the non-root `apiscout` user** (this is the default
   in the shipped `Dockerfile`).
4. **Restrict network access** to the dashboard to your internal network or
   a VPN; the dashboard is not designed to be internet-exposed.
5. **Back up the SQLite database** (or move to Postgres — planned, see
   roadmap). Audit-log integrity depends on the file being preserved.
6. **Rotate admin passwords** periodically and disable the bootstrap admin
   once delegated admins exist.

## Version support

We currently support only the `main` branch. Once the project reaches a
tagged `1.0.0` release we will commit to supporting the two most recent
minor versions.

## Public advisories

Fixed vulnerabilities are published as GitHub Security Advisories with CVE
identifiers when appropriate. You can subscribe at
https://github.com/rzawadzk/APISecurity/security/advisories to receive
notifications.
