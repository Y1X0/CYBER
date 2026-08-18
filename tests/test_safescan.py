"""Safe-scanning controls (WP-H3).

Authorization decides whether a customer's estate may be scanned. These decide whether *now* is a
time they agreed to, how hard, and whether anybody has hit the stop button — the questions whose
wrong answers turn a consented scan into the customer's incident.

Two properties recur and are worth stating once: the conservative option is always the default, and
a refusal to scan is never silent. A skipped engine reads as a clean one, so a scan held back by
these controls is *deferred*, with a reason and a time to try again.
"""

from __future__ import annotations

import datetime as dt

import pytest
from guardian_core.safescan import (
    DEFAULT_PROFILE,
    PROFILES,
    Policy,
    SafeScanRefusal,
    Window,
    check,
    next_open,
    parse_policy,
)

# A Tuesday at 14:00 UTC.
NOW = dt.datetime(2026, 8, 18, 14, 0, tzinfo=dt.UTC)


# ── blackout windows ──────────────────────────────────────────────────────────────────────────────
def test_a_scan_inside_a_blackout_window_is_deferred_not_skipped():
    """A skipped engine reads as a clean one. The distinction is the whole reason for the state."""
    window = Window(days=("mon", "tue", "wed", "thu", "fri"), start_hour=9, end_hour=18,
                    label="trading hours")
    verdict = check(Policy(windows=(window,)), now=NOW)

    assert verdict.allowed is False
    assert verdict.action == "defer"
    assert "trading hours" in verdict.reason
    assert verdict.retry_after is not None and verdict.retry_after > NOW


def test_a_scan_outside_the_window_runs():
    window = Window(days=("mon", "tue"), start_hour=9, end_hour=12)
    assert check(Policy(windows=(window,)), now=NOW).allowed is True


def test_a_window_on_another_day_does_not_apply():
    window = Window(days=("sat", "sun"), start_hour=0, end_hour=23)
    assert check(Policy(windows=(window,)), now=NOW).allowed is True


def test_a_window_that_wraps_midnight_is_handled():
    """22:00–06:00 is two intervals, and the naive comparison matches neither."""
    window = Window(days=(), start_hour=22, end_hour=6)

    assert window.contains(dt.datetime(2026, 8, 18, 23, 0, tzinfo=dt.UTC)) is True
    assert window.contains(dt.datetime(2026, 8, 19, 3, 0, tzinfo=dt.UTC)) is True
    assert window.contains(dt.datetime(2026, 8, 19, 12, 0, tzinfo=dt.UTC)) is False


def test_a_window_is_evaluated_in_the_customers_own_offset():
    """09:00 means 09:00 where the customer is. Evaluating it in UTC is being wrong by the size of
    their timezone, every day."""
    window = Window(days=("tue",), start_hour=9, end_hour=18, utc_offset_hours=9)  # Tokyo

    # 14:00 UTC is 23:00 in Tokyo — outside their working day.
    assert window.contains(NOW) is False
    # 01:00 UTC is 10:00 in Tokyo — inside it.
    assert window.contains(dt.datetime(2026, 8, 18, 1, 0, tzinfo=dt.UTC)) is True


def test_the_retry_time_is_after_the_window_closes():
    window = Window(days=("tue",), start_hour=9, end_hour=18)
    reopens = next_open((window,), NOW)
    assert window.contains(reopens) is False


# ── the kill switch ───────────────────────────────────────────────────────────────────────────────
def test_a_platform_pause_stops_everything():
    verdict = check(Policy(), now=NOW, platform_paused=True)
    assert verdict.allowed is False
    assert verdict.action == "refuse"


def test_a_customer_pause_stops_that_customer_and_says_why():
    policy = Policy(paused=True, pause_reason="incident response in progress")
    verdict = check(policy, now=NOW)

    assert verdict.allowed is False
    assert "incident response in progress" in verdict.reason


def test_an_unreadable_stop_switch_fails_closed():
    """A stop button that only works when the rest of the system is healthy is not a stop button,
    and an unreadable switch is exactly the moment somebody is reaching for it."""
    verdict = check(Policy(), now=NOW, switch_readable=False)

    assert verdict.allowed is False
    assert verdict.action == "refuse"
    assert "could not be read" in verdict.reason


def test_the_stop_switch_is_checked_before_anything_else():
    """Nothing else gets a say. A paused platform inside an open window still refuses."""
    verdict = check(Policy(windows=()), now=NOW, platform_paused=True, switch_readable=False)
    assert "could not be read" in verdict.reason


# ── concurrency ───────────────────────────────────────────────────────────────────────────────────
def test_a_second_scan_of_the_same_asset_is_deferred():
    """Every engine has its own budget, and two scanners on one host produce twice the traffic the
    customer agreed to. Budgets that only hold individually are not budgets."""
    verdict = check(Policy(), now=NOW, active_scans_on_asset=1)

    assert verdict.allowed is False
    assert verdict.action == "defer"
    assert "already running" in verdict.reason


def test_the_concurrency_limit_is_configurable_upwards():
    policy = Policy(max_concurrent_scans_per_asset=3)
    assert check(policy, now=NOW, active_scans_on_asset=2).allowed is True
    assert check(policy, now=NOW, active_scans_on_asset=3).allowed is False


# ── intensity ─────────────────────────────────────────────────────────────────────────────────────
def test_the_default_profile_is_the_conservative_one():
    """The setting somebody never opens should be the one that cannot hurt them."""
    assert DEFAULT_PROFILE == "safe"
    assert PROFILES["safe"]["max_requests"] < PROFILES["standard"]["max_requests"]
    assert PROFILES["safe"]["rate_per_second"] < PROFILES["standard"]["rate_per_second"]


def test_an_allowed_verdict_carries_the_limits_the_engines_must_obey():
    verdict = check(Policy(profile="standard"), now=NOW)
    assert verdict.allowed is True
    assert verdict.limits == PROFILES["standard"]


# ── parsing customer settings ─────────────────────────────────────────────────────────────────────
def test_a_customers_settings_are_read_into_a_policy():
    policy = parse_policy({"safe_scanning": {
        "profile": "thorough",
        "paused": True,
        "pause_reason": "change freeze",
        "max_concurrent_scans_per_asset": 2,
        "blackout_windows": [{"days": ["mon"], "start_hour": 9, "end_hour": 17,
                              "utc_offset_hours": -5, "label": "US business hours"}],
    }})

    assert policy.profile == "thorough"
    assert policy.paused is True
    assert policy.max_concurrent_scans_per_asset == 2
    assert policy.windows[0].label == "US business hours"


def test_no_settings_at_all_is_the_safe_profile():
    assert parse_policy(None).profile == "safe"
    assert parse_policy({}).windows == ()


def test_an_unrecognized_profile_falls_back_to_safe_rather_than_fastest():
    """A typo must not silently select the most aggressive setting."""
    assert parse_policy({"safe_scanning": {"profile": "aggressive"}}).profile == "safe"


def test_a_malformed_blackout_window_refuses_rather_than_disappears():
    """A window the customer meant to have is not the same as no window, and dropping it means
    scanning through exactly the hours they asked you not to."""
    with pytest.raises(SafeScanRefusal, match="malformed"):
        parse_policy({"safe_scanning": {
            "blackout_windows": [{"days": ["mon"], "start_hour": "nine", "end_hour": 17}]}})


def test_a_zero_concurrency_setting_is_clamped_rather_than_blocking_everything():
    assert parse_policy(
        {"safe_scanning": {"max_concurrent_scans_per_asset": 0}}
    ).max_concurrent_scans_per_asset == 1
