"""Cross-Site Request Forgery protection.

Defence model: double-submit cookie.

  1. The server issues a random 256-bit token to the browser in a cookie
     named ``csrf_token``. The cookie is **not** HttpOnly so same-origin
     JavaScript can read it (that's the whole point).
  2. On every unsafe request (POST/PUT/PATCH/DELETE) the client must send
     the same value back in the ``X-CSRF-Token`` header (or a form field
     of the same name for classic ``application/x-www-form-urlencoded``
     submissions).
  3. The middleware uses a constant-time compare to reject mismatches
     with HTTP 403.

Why this is enough for our deployment model:

  - An attacker on ``evil.com`` cannot read cookies scoped to
     ``scout.internal`` — so they cannot learn the token value.
  - They cannot set the header either: ``fetch()`` on a cross-origin
     request cannot add custom headers without a preflight, and our CORS
     policy denies cross-origin requests. Forms can carry a field but
     cannot read the cookie to fill it.

Residual risk: a compromised same-site subdomain could set a cookie on
the parent domain and pair it with a matching header. Operators are
expected to deploy the dashboard on an internal-only network (see
``SECURITY.md`` — "not designed to be internet-exposed") and to restrict
which hosts can serve on the same site. ``SameSite=strict`` on the
session cookie further limits cross-site inclusion.

Exempt paths:

  - ``/api/auth/login`` — no pre-login session exists; the login flow
    is protected by SameSite=strict, the sliding-window rate limiter,
    and the credential check itself.
  - ``/health``, ``/ready``, ``/metrics`` — GETs, not state-changing.
"""
from __future__ import annotations

import hmac
import secrets
from typing import Iterable, Optional

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse, Response

CSRF_COOKIE_NAME = "csrf_token"
CSRF_HEADER_NAME = "X-CSRF-Token"
CSRF_FORM_FIELD = "csrf_token"

UNSAFE_METHODS = frozenset({"POST", "PUT", "PATCH", "DELETE"})

# Paths that legitimately mutate state without holding a pre-existing token.
# Each entry is an exact path string. Prefix matching is deliberate-only.
DEFAULT_EXEMPT_PATHS: frozenset[str] = frozenset({
    "/api/auth/login",
    "/health",
    "/ready",
    "/metrics",
})


def generate_token() -> str:
    """Return a new random token (256 bits, URL-safe)."""
    return secrets.token_urlsafe(32)


def set_csrf_cookie(response: Response, token: str, *, secure: bool = False) -> None:
    """Attach the CSRF cookie to a response. Intentionally NOT HttpOnly."""
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=token,
        max_age=12 * 3600,
        httponly=False,          # JS needs to read it — that's the point
        secure=secure,
        samesite="strict",
        path="/",
    )


def _extract_submitted_token(request: Request, form_cache: Optional[dict]) -> Optional[str]:
    header = request.headers.get(CSRF_HEADER_NAME)
    if header:
        return header
    # Form-encoded submissions may put the token in a hidden field.
    if form_cache is not None and CSRF_FORM_FIELD in form_cache:
        return form_cache[CSRF_FORM_FIELD]
    return None


class CSRFMiddleware(BaseHTTPMiddleware):
    """Enforce double-submit CSRF validation on unsafe methods."""

    def __init__(
        self,
        app,
        *,
        exempt_paths: Optional[Iterable[str]] = None,
    ):
        super().__init__(app)
        self.exempt_paths: frozenset[str] = frozenset(exempt_paths or DEFAULT_EXEMPT_PATHS)

    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        method = request.method.upper()

        if method in UNSAFE_METHODS and path not in self.exempt_paths:
            cookie_token = request.cookies.get(CSRF_COOKIE_NAME)
            if not cookie_token:
                return _deny("Missing CSRF cookie")

            # Peek at form body if Content-Type warrants it. Reading the body
            # here consumes the stream — Starlette's _receive is re-wound by
            # the framework when the downstream handler re-reads it, so we
            # stash a parsed copy on request.state for potential reuse.
            form_cache: Optional[dict] = None
            ctype = request.headers.get("content-type", "")
            if ctype.startswith("application/x-www-form-urlencoded") or ctype.startswith("multipart/form-data"):
                try:
                    form = await request.form()
                    form_cache = {k: v for k, v in form.items() if isinstance(v, str)}
                except Exception:
                    form_cache = None

            submitted = _extract_submitted_token(request, form_cache)
            if not submitted:
                return _deny("Missing CSRF token in header or form")
            if not hmac.compare_digest(submitted, cookie_token):
                return _deny("CSRF token mismatch")

        response = await call_next(request)

        # Self-heal: ensure the browser always has a usable token for its
        # next unsafe request. Only set on safe methods to avoid races.
        # The Secure flag is inherited from ClientIPMiddleware's tls resolution.
        if method in {"GET", "HEAD"} and CSRF_COOKIE_NAME not in request.cookies:
            tls = bool(getattr(request.state, "tls", False))
            set_csrf_cookie(response, generate_token(), secure=tls)

        return response


def _deny(reason: str) -> Response:
    return JSONResponse({"detail": f"CSRF: {reason}"}, status_code=403)
