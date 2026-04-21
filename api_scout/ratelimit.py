"""In-memory sliding-window rate limiting.

Scope: used to throttle authentication endpoints (per-IP). The same class
can be reused for other endpoints later.

Design:
  - Sliding-window counter per key: each call records a timestamp; the
    window is `window_seconds` wide.
  - Thread-safe via a coarse `threading.Lock`. The critical section is
    tiny (a deque append + a few pops), so contention is negligible at
    realistic request rates.
  - Lazy cleanup: expired timestamps are pruned when the key is next
    touched. No background sweeper.
  - Bounded memory: when we exceed `_MAX_KEYS`, stale keys (last-hit
    older than the window) are swept. Prevents unbounded growth under
    IP-rotation attacks.
  - Monotonic time so wall-clock jumps don't reset the window.

In-memory on purpose: restart resets counters. Acceptable for a single
process (the default deployment). For multi-process / multi-replica
setups, back this with Redis — the interface (`check(key) -> decision`)
is designed to be swappable.
"""
from __future__ import annotations

import threading
import time
from collections import deque
from dataclasses import dataclass
from typing import Deque, Dict, Optional

# Soft cap: above this many distinct keys, we sweep stale entries.
_MAX_KEYS = 50_000


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    retry_after_seconds: int  # 0 when allowed
    remaining: int            # attempts remaining in the current window


class SlidingWindowLimiter:
    """Allows up to `max_attempts` events per key per `window_seconds`."""

    def __init__(self, max_attempts: int, window_seconds: int):
        if max_attempts <= 0:
            raise ValueError("max_attempts must be positive")
        if window_seconds <= 0:
            raise ValueError("window_seconds must be positive")
        self.max_attempts = max_attempts
        self.window_seconds = window_seconds
        self._hits: Dict[str, Deque[float]] = {}
        self._lock = threading.Lock()
        # Injected clock for deterministic tests. Default: monotonic.
        self._now = time.monotonic

    def check(self, key: str) -> RateLimitDecision:
        """Record an attempt for `key` and return a decision.

        When `allowed=False`, no hit is recorded (so the block does not
        extend the window by refreshing the oldest timestamp).
        """
        if not key:
            # Anonymous / unknown client: we still rate-limit under a shared
            # bucket so we don't silently let them through, but prefer that
            # callers supply a key.
            key = "_anon"
        now = self._now()
        cutoff = now - self.window_seconds
        with self._lock:
            if len(self._hits) > _MAX_KEYS:
                self._sweep_locked(cutoff)
            q = self._hits.get(key)
            if q is None:
                q = deque()
                self._hits[key] = q
            while q and q[0] < cutoff:
                q.popleft()
            if len(q) >= self.max_attempts:
                oldest = q[0]
                retry = int(oldest + self.window_seconds - now) + 1
                return RateLimitDecision(
                    allowed=False,
                    retry_after_seconds=max(retry, 1),
                    remaining=0,
                )
            q.append(now)
            return RateLimitDecision(
                allowed=True,
                retry_after_seconds=0,
                remaining=self.max_attempts - len(q),
            )

    def reset(self, key: str) -> None:
        """Forget all recorded hits for a key (e.g. on successful auth)."""
        with self._lock:
            self._hits.pop(key, None)

    def peek(self, key: str) -> int:
        """Return current attempt count within window (read-only)."""
        now = self._now()
        cutoff = now - self.window_seconds
        with self._lock:
            q = self._hits.get(key)
            if q is None:
                return 0
            while q and q[0] < cutoff:
                q.popleft()
            return len(q)

    # -- internal --

    def _sweep_locked(self, cutoff: float) -> None:
        stale = [k for k, d in self._hits.items() if not d or d[-1] < cutoff]
        for k in stale:
            del self._hits[k]

    # -- test hooks --

    def _set_clock(self, clock) -> None:
        """Replace the monotonic clock (tests only)."""
        self._now = clock


def build_login_limiter(max_attempts: int = 10, window_seconds: int = 300) -> SlidingWindowLimiter:
    """Sensible defaults for authentication: 10 attempts per 5 minutes per IP."""
    return SlidingWindowLimiter(max_attempts=max_attempts, window_seconds=window_seconds)
