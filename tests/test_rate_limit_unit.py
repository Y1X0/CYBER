"""Sliding-window rate limiter (P1-γ) — pure unit, deterministic fake clock."""

from __future__ import annotations

from guardian_api import ratelimit
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


# ── capacity-pressure eviction (must NEVER erase active blocks) ──────────────────────────────────
def test_active_block_survives_capacity_pressure_from_key_churn(monkeypatch):
    # An attacker churning many arbitrary keys must not be able to reset an unrelated active block.
    # The old code called `self._hits.clear()` at the cap, wiping every lockout; this proves it does
    # not (requirements 1 and 3).
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 5)
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    assert lim.hit("victim")[0] is True
    assert lim.hit("victim")[0] is False               # victim is now blocked
    for i in range(100):                               # churn well past the cap with active keys
        lim.hit(f"junk{i}")
    assert lim.hit("victim")[0] is False               # the block is intact, not erased


def test_expired_entries_are_reclaimed_under_pressure(monkeypatch):
    # Memory is bounded by evicting only entries whose whole window has expired (requirement 4/5).
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 5)
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    for i in range(5):
        lim.hit(f"old{i}")                             # 5 keys at t=1000
    c.t += 61                                          # every window has now expired
    lim.hit("fresh")                                   # pressure → evict the 5 stale, keep 'fresh'
    assert set(lim._hits) == {"fresh"}


def test_table_full_of_active_blocks_admits_new_key_without_evicting(monkeypatch):
    # When the table is full of ACTIVE blocks, a brand-new key is admitted untracked rather than an
    # active block being evicted — existing limits stay intact and memory stays bounded (req 3).
    monkeypatch.setattr(ratelimit, "_MAX_KEYS", 3)
    c = _Clock()
    lim = SlidingWindowLimiter(1, 60.0, clock=c)
    for k in ("a", "b", "c"):
        assert lim.hit(k)[0] is True
        assert lim.hit(k)[0] is False                  # three active blocks; table full
    assert lim.hit("d")[0] is True                     # new key admitted, not blocked, not tracked
    assert set(lim._hits) == {"a", "b", "c"}           # no active block was evicted
    assert lim.hit("a")[0] is False                    # existing blocks still enforced
