"""Sliding-window rate limiter (P1-γ) — pure unit, deterministic fake clock."""

from __future__ import annotations

from guardian_api.ratelimit import SlidingWindowLimiter


class _Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_allows_up_to_the_limit_then_rejects():
    c = _Clock()
    lim = SlidingWindowLimiter(3, 60.0, clock=c)
    assert [lim.hit("k")[0] for _ in range(3)] == [True, True, True]
    allowed, retry = lim.hit("k")
    assert allowed is False and 0 < retry <= 60.0     # 4th rejected, with a retry-after hint


def test_window_slides_and_frees_capacity():
    c = _Clock()
    lim = SlidingWindowLimiter(2, 60.0, clock=c)
    assert lim.hit("k")[0] and lim.hit("k")[0]
    assert lim.hit("k")[0] is False                   # at limit
    c.t += 61                                          # whole window elapsed
    assert lim.hit("k")[0] is True                     # capacity restored


def test_partial_window_expiry_frees_one_slot():
    c = _Clock()
    lim = SlidingWindowLimiter(2, 60.0, clock=c)
    lim.hit("k")                                       # t=1000
    c.t += 30
    lim.hit("k")                                       # t=1030 (2 in window ⇒ full)
    assert lim.hit("k")[0] is False
    c.t += 31                                          # t=1061: first hit (1000) aged out, second stays
    assert lim.hit("k")[0] is True                     # exactly one slot freed


def test_keys_are_independent():
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    assert lim.hit("a")[0] is True and lim.hit("a")[0] is False
    assert lim.hit("b")[0] is True                     # a different key has its own budget


def test_rejected_attempt_is_not_recorded():
    # A blocked caller must not keep extending its own window by hammering.
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    assert lim.hit("k")[0] is True
    for _ in range(5):
        assert lim.hit("k")[0] is False                # rejected, not appended
    c.t += 61
    assert lim.hit("k")[0] is True                     # window clears on schedule despite the hammering


def test_reset_clears_state():
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    lim.hit("k")
    assert lim.hit("k")[0] is False
    lim.reset()
    assert lim.hit("k")[0] is True


def test_zero_limit_disables_the_limiter():
    lim = SlidingWindowLimiter(0, 60.0)
    assert all(lim.hit("k")[0] for _ in range(100))    # disabled ⇒ always allowed
