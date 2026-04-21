<!--
Thanks for contributing to API Scout.

Before opening this PR, please confirm:
  - You've read CONTRIBUTING.md
  - Tests pass locally (`pytest`)
  - Your commits are signed off (`git commit -s`) per the DCO
-->

## Summary

<!-- 1–3 sentences on what changes and why. The "why" matters more than
     the "what" — reviewers can read the diff. -->

## Linked issue

<!-- e.g. "Closes #123" or "Refs #456". If there is no issue, say why
     one wasn't needed. -->

## Type of change

- [ ] Bug fix (non-breaking)
- [ ] New feature (non-breaking)
- [ ] Breaking change (API, CLI flag, DB schema, or wire format change)
- [ ] Docs-only
- [ ] Chore / refactor (no behaviour change)

## Security considerations

<!-- Tick all that apply. If any are ticked, flag them in the PR body
     so reviewers can give the change extra scrutiny — see
     CONTRIBUTING.md → "Security-sensitive changes". -->

- [ ] Touches authentication, session, or RBAC code
- [ ] Touches CSRF, rate limiting, or the audit log
- [ ] Renders user-controlled data in HTML or JS
- [ ] Touches SQL or constructs queries dynamically
- [ ] Changes what is logged, or could affect log contents
- [ ] Adds or changes a dashboard route (specify the role dependency)

## Test plan

<!-- Checklist of what you tested. Example:
       - [ ] `pytest` — all 92 tests green
       - [ ] Bootstrapped a fresh DB with `api-scout user create` and
             signed in via the browser
       - [ ] Verified `/health`, `/ready`, `/metrics` still respond
-->

- [ ] `pytest` locally
- [ ] Manual test (describe below)

## Checklist

- [ ] I have read `CONTRIBUTING.md`
- [ ] Commits are signed off (`git commit -s`)
- [ ] I added or updated tests for the change
- [ ] I updated `CHANGELOG.md` under `## [Unreleased]` if this is a
      user-visible change
- [ ] Docs (`README.md`, `SECURITY.md`, etc.) updated if the public
      interface changed
