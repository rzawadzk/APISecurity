"""Unit tests for the SlidingWindowLimiter."""
from __future__ import annotations

import pytest

from api_scout.ratelimit import SlidingWindowLimiter, build_login_limiter


class FakeClock:
    def __init__(self, start: float = 1_000_000.0):
        self.now = start

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@pytest.fixture
def limiter():
    lim = SlidingWindowLimiter(max_attempts=3, window_seconds=60)
    clock = FakeClock()
    lim._set_clock(clock)
    return lim, clock


def test_first_attempt_allowed(limiter):
    lim, _ = limiter
    d = lim.check("1.2.3.4")
    assert d.allowed is True
    assert d.retry_after_seconds == 0
    assert d.remaining == 2


def test_allows_up_to_max_then_blocks(limiter):
    lim, _ = limiter
    assert lim.check("ip").allowed
    assert lim.check("ip").allowed
    assert lim.check("ip").allowed
    fourth = lim.check("ip")
    assert fourth.allowed is False
    assert fourth.retry_after_seconds > 0
    assert fourth.remaining == 0


def test_blocked_attempt_does_not_extend_window(limiter):
    """A denied check must not refresh the oldest timestamp."""
    lim, clock = limiter
    lim.check("ip")  # t=0
    clock.advance(10)
    lim.check("ip")  # t=10
    clock.advance(10)
    lim.check("ip")  # t=20
    # fully used. Now hammer it; window should still expire based on t=0.
    clock.advance(20)
    for _ in range(5):
        assert lim.check("ip").allowed is False
    # oldest hit was at t=0, window is 60, so at t=40 we still have ~20s left
    # advance past the oldest and a slot should open
    clock.advance(25)  # t=65
    d = lim.check("ip")
    assert d.allowed is True


def test_window_slides_forward(limiter):
    lim, clock = limiter
    lim.check("ip")
    lim.check("ip")
    lim.check("ip")
    # Move one full window past the oldest; everything should clear
    clock.advance(61)
    d = lim.check("ip")
    assert d.allowed is True
    assert d.remaining == 2


def test_distinct_keys_isolated(limiter):
    lim, _ = limiter
    for _ in range(3):
        assert lim.check("10.0.0.1").allowed
    # 10.0.0.1 is exhausted
    assert lim.check("10.0.0.1").allowed is False
    # 10.0.0.2 still fresh — first hit should leave 2 remaining
    d = lim.check("10.0.0.2")
    assert d.allowed
    assert d.remaining == 2


def test_reset_clears_key(limiter):
    lim, _ = limiter
    for _ in range(3):
        lim.check("ip")
    assert lim.check("ip").allowed is False
    lim.reset("ip")
    assert lim.check("ip").allowed


def test_peek_does_not_consume(limiter):
    lim, _ = limiter
    lim.check("ip")
    lim.check("ip")
    assert lim.peek("ip") == 2
    assert lim.peek("ip") == 2
    assert lim.check("ip").allowed  # 3rd attempt still allowed


def test_empty_key_uses_anon_bucket(limiter):
    lim, _ = limiter
    # Both empty-string calls hit the same bucket
    assert lim.check("").allowed
    assert lim.check("").allowed
    assert lim.check("").allowed
    assert lim.check("").allowed is False


def test_retry_after_is_positive_integer_on_block(limiter):
    lim, clock = limiter
    for _ in range(3):
        lim.check("ip")
    clock.advance(30)
    d = lim.check("ip")
    assert d.allowed is False
    # oldest was at t=0, window is 60; at t=30 the oldest releases at t=60 → retry ≈ 30
    assert 25 <= d.retry_after_seconds <= 35


def test_invalid_construction_raises():
    with pytest.raises(ValueError):
        SlidingWindowLimiter(max_attempts=0, window_seconds=60)
    with pytest.raises(ValueError):
        SlidingWindowLimiter(max_attempts=5, window_seconds=0)


def test_default_login_limiter_values():
    lim = build_login_limiter()
    assert lim.max_attempts == 10
    assert lim.window_seconds == 300
