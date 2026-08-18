"""What one tenant may consume (WP-G2).

The rules that decide how much of a shared platform one customer can take. Two of them are about
the direction a mistake falls in, and that is the part worth pinning down:

* an unreadable quota override must leave the platform default in place, never be read as
  "unlimited" — the two directions of that mistake are not equally survivable;
* `limit=0` and `limit=-1` mean "all of them" to almost every client that sends them, and answering
  with a default page is how a script silently processes fifty of nine thousand rows and reports a
  clean run.
"""

from __future__ import annotations

import pytest
from guardian_core import quota


# ── overrides ─────────────────────────────────────────────────────────────────────────────────────
def test_no_override_leaves_the_platform_defaults():
    resolved, problems = quota.DEFAULT.with_overrides(None)
    assert resolved == quota.DEFAULT
    assert problems == []


def test_a_tenant_may_be_given_more_and_less():
    resolved, problems = quota.DEFAULT.with_overrides(
        {"requests_per_minute": 5000, "concurrent_scans": 2})

    assert resolved.requests_per_minute == 5000
    assert resolved.concurrent_scans == 2
    assert resolved.max_page_size == quota.DEFAULT.max_page_size  # untouched
    assert problems == []


@pytest.mark.parametrize("value", [0, -1, "600", 12.5, None, True, [600]])
def test_an_unreadable_override_falls_back_to_the_default_and_says_so(value):
    """Never to "unlimited": a typo must not be the thing that removes a limit."""
    resolved, problems = quota.DEFAULT.with_overrides({"requests_per_minute": value})

    assert resolved.requests_per_minute == quota.DEFAULT.requests_per_minute
    assert problems
    assert "requests_per_minute" in problems[0]


def test_an_override_that_is_not_an_object_is_refused():
    resolved, problems = quota.DEFAULT.with_overrides("unlimited")
    assert resolved == quota.DEFAULT
    assert problems


def test_a_tenant_cannot_raise_its_page_size_above_the_platform_ceiling():
    """Otherwise the per-tenant override is a way to ask for the unbounded response back."""
    resolved, problems = quota.DEFAULT.with_overrides({"max_page_size": 100_000})

    assert resolved.max_page_size == quota.HARD_MAX_PAGE_SIZE
    assert any("ceiling" in problem for problem in problems)


def test_one_bad_field_does_not_discard_the_good_ones():
    resolved, problems = quota.DEFAULT.with_overrides(
        {"concurrent_scans": 25, "requests_per_minute": -3})

    assert resolved.concurrent_scans == 25
    assert resolved.requests_per_minute == quota.DEFAULT.requests_per_minute
    assert len(problems) == 1


# ── page size ─────────────────────────────────────────────────────────────────────────────────────
def test_an_unspecified_page_size_gets_the_default_within_the_ceiling():
    assert quota.page_size(None, maximum=200, default=50) == 50
    assert quota.page_size(None, maximum=20, default=50) == 20


def test_a_page_size_is_clamped_not_honoured():
    assert quota.page_size(10_000, maximum=200) == 200
    assert quota.page_size(25, maximum=200) == 25


@pytest.mark.parametrize("requested", [0, -1, -100])
def test_a_request_for_every_row_is_refused_rather_than_quietly_paged(requested):
    with pytest.raises(quota.InvalidPageSize) as exc:
        quota.page_size(requested, maximum=200)
    assert "page" in str(exc.value)


# ── scan admission ────────────────────────────────────────────────────────────────────────────────
def test_a_scan_is_admitted_below_the_limit():
    assert quota.admit_scan(active=3, limit=10).allowed is True


def test_a_scan_is_refused_at_the_limit_with_the_numbers_and_a_retry_time():
    decision = quota.admit_scan(active=10, limit=10)

    assert decision.allowed is False
    assert "10" in decision.reason
    assert decision.retry_after > 0


def test_a_tenant_over_its_limit_is_still_refused():
    """Recovering from a raised-then-lowered limit must not admit work."""
    assert quota.admit_scan(active=40, limit=10).allowed is False


def test_a_zero_limit_refuses_rather_than_meaning_unlimited():
    decision = quota.admit_scan(active=0, limit=0)
    assert decision.allowed is False
    assert "disabled" in decision.reason


# ── rate refusal ──────────────────────────────────────────────────────────────────────────────────
def test_a_rate_refusal_always_carries_a_retry_time():
    """A 429 with `Retry-After: 0` teaches clients to retry immediately, which turns a rate limit
    into an amplifier."""
    assert quota.rate_refusal(0.0, limit=600).retry_after >= 1
    assert quota.rate_refusal(0.2, limit=600).retry_after >= 1


def test_a_fractional_wait_rounds_up():
    assert quota.rate_refusal(12.4, limit=600).retry_after == 13
    assert quota.rate_refusal(12.0, limit=600).retry_after == 12


def test_the_refusal_names_the_limit_that_was_hit():
    assert "600" in quota.rate_refusal(5, limit=600).reason


# ── truncation ────────────────────────────────────────────────────────────────────────────────────
def test_nothing_is_said_when_nothing_was_left_out():
    assert quota.truncation_note(shown=40, total=40) == ""
    assert quota.truncation_note(shown=40, total=12) == ""


def test_a_truncated_result_says_how_much_it_left_out_and_that_it_exists():
    note = quota.truncation_note(shown=2000, total=51_234)

    assert "2,000" in note
    assert "51,234" in note
    assert "49,234" in note
    # The distinction the reader has to be able to make.
    assert "not absent" in note


# ── the limiter the API applies these with ────────────────────────────────────────────────────────
def test_two_callers_with_different_ceilings_share_one_window():
    """The ceiling is passed per call rather than stored on the limiter: a limit mutated on a shared
    object is a race between two tenants' requests."""
    from guardian_api.ratelimit import SlidingWindowLimiter

    clock = iter([0.0] * 20)
    limiter = SlidingWindowLimiter(0, 60.0, clock=lambda: next(clock))

    assert limiter.hit("tenant:a", max_hits=2)[0] is True
    assert limiter.hit("tenant:a", max_hits=2)[0] is True
    assert limiter.hit("tenant:a", max_hits=2)[0] is False
    # b has its own budget and its own ceiling.
    assert limiter.hit("tenant:b", max_hits=5)[0] is True


def test_a_refused_caller_is_told_how_long_the_window_has_left():
    from guardian_api.ratelimit import SlidingWindowLimiter

    times = [0.0, 10.0, 10.0]
    limiter = SlidingWindowLimiter(0, 60.0, clock=lambda: times.pop(0))
    limiter.hit("k", max_hits=1)

    allowed, retry_after = limiter.hit("k", max_hits=1)
    assert allowed is False
    assert 49 < retry_after <= 50  # 60s window, first hit 10s ago


def test_the_window_slides():
    from guardian_api.ratelimit import SlidingWindowLimiter

    times = [0.0, 61.0]
    limiter = SlidingWindowLimiter(0, 60.0, clock=lambda: times.pop(0))
    limiter.hit("k", max_hits=1)

    assert limiter.hit("k", max_hits=1)[0] is True


def test_a_ceiling_of_zero_disables_the_check():
    """The only way to switch the limit off, and it has to be deliberate."""
    from guardian_api.ratelimit import hit_limited

    for _ in range(50):
        assert hit_limited("never-limited", limit=0)[0] is True
