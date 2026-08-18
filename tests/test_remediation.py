"""The fix lifecycle (WP-F5).

One rule matters more than everything else here, and most of these tests exist to hold it in place:

**a person cannot mark their own fix verified.**

A remediation workflow where the assignee under deadline pressure certifies the work is a to-do
list, and a to-do list is what security teams already have and already do not trust. `verified` is
reachable only from a scan that ran the engine which found the issue, saw it complete cleanly, and
did not report it again.
"""

from __future__ import annotations

import datetime as dt

import pytest
from guardian_core.remediation import (
    ACTIVE,
    FIXED,
    IN_PROGRESS,
    OPEN,
    REOPENED,
    RISK_ACCEPTED,
    SLA_DAYS,
    STATUSES,
    VERIFIED,
    WONT_FIX,
    InvalidTransition,
    due_at,
    is_overdue,
    summarize,
    ticket_payload,
    validate_transition,
)

NOW = dt.datetime(2026, 8, 18, tzinfo=dt.UTC)


# ── the rule ──────────────────────────────────────────────────────────────────────────────────────
def test_a_person_cannot_mark_an_item_verified():
    """The single most important assertion in this package."""
    with pytest.raises(InvalidTransition, match="verifying scan"):
        validate_transition(FIXED, VERIFIED, by_scan=False)


def test_a_scan_can():
    validate_transition(FIXED, VERIFIED, by_scan=True)


def test_a_person_cannot_reopen_either():
    """Reopening is the scanner saying the issue came back. A human who disagrees with a closure
    files it again as a finding."""
    with pytest.raises(InvalidTransition):
        validate_transition(VERIFIED, REOPENED, by_scan=False)


def test_a_person_can_say_fixed():
    """Claiming a fix is legitimate — it is the claim the next scan checks."""
    validate_transition(IN_PROGRESS, FIXED)


@pytest.mark.parametrize("target", [RISK_ACCEPTED, WONT_FIX])
def test_declining_to_fix_requires_a_reason(target):
    """Somebody is deciding, on the customer's behalf, that this stays broken."""
    with pytest.raises(InvalidTransition, match="justification"):
        validate_transition(OPEN, target)
    validate_transition(OPEN, target, justification="compensating control in place")


def test_an_unknown_status_is_refused():
    with pytest.raises(InvalidTransition):
        validate_transition(OPEN, "done")


def test_a_no_op_transition_is_allowed():
    validate_transition(OPEN, OPEN)


def test_a_verified_item_is_not_reopened_by_hand():
    with pytest.raises(InvalidTransition, match="a scan reopens it"):
        validate_transition(VERIFIED, IN_PROGRESS)


# ── due dates ─────────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("severity", list(SLA_DAYS))
def test_every_severity_has_a_deterministic_window(severity):
    first = due_at(severity, opened_at=NOW)
    second = due_at(severity, opened_at=NOW)
    assert first == second
    assert first > NOW


def test_a_worse_finding_gets_less_time():
    assert due_at("critical", opened_at=NOW) < due_at("high", opened_at=NOW)
    assert due_at("high", opened_at=NOW) < due_at("medium", opened_at=NOW)


def test_an_internet_facing_asset_halves_the_clock():
    """The population able to reach it is everybody."""
    public = due_at("high", exposure="public", opened_at=NOW)
    internal = due_at("high", exposure="internal", opened_at=NOW)
    assert public < internal


def test_an_unknown_severity_falls_back_rather_than_failing():
    assert due_at("catastrophic", opened_at=NOW) == due_at("medium", opened_at=NOW)


# ── overdue ───────────────────────────────────────────────────────────────────────────────────────
def test_an_outstanding_item_past_its_date_is_overdue():
    assert is_overdue(OPEN, NOW - dt.timedelta(days=1), now=NOW) is True


def test_an_item_within_its_window_is_not():
    assert is_overdue(OPEN, NOW + dt.timedelta(days=1), now=NOW) is False


def test_a_verified_item_is_never_overdue():
    """However late the fix was, it is done. Counting it forever makes the metric useless."""
    assert is_overdue(VERIFIED, NOW - dt.timedelta(days=400), now=NOW) is False


def test_an_accepted_risk_is_not_overdue():
    """Somebody decided, on the record, not to fix it. That is a decision, not a missed deadline."""
    assert is_overdue(RISK_ACCEPTED, NOW - dt.timedelta(days=400), now=NOW) is False


def test_a_claimed_fix_still_runs_its_clock():
    """`fixed` is a claim awaiting a scan. Until the scan agrees, the issue is still open in
    reality, and the clock is about reality."""
    assert is_overdue(FIXED, NOW - dt.timedelta(days=1), now=NOW) is True


# ── SLA summary ───────────────────────────────────────────────────────────────────────────────────
def _item(status, days, severity="high"):
    return {"status": status, "due_at": NOW + dt.timedelta(days=days), "severity": severity}


def test_the_summary_counts_what_matters():
    items = [_item(OPEN, -5), _item(IN_PROGRESS, 5), _item(VERIFIED, -50),
             _item(RISK_ACCEPTED, -100, "low")]
    summary = summarize(items, now=NOW)

    assert summary.total == 4
    assert summary.active == 2
    assert summary.overdue == 1
    assert summary.verified == 1
    assert summary.accepted == 1
    assert summary.by_severity == {"high": 3, "low": 1}


def test_accepting_a_stale_backlog_does_not_improve_the_on_time_rate():
    """Otherwise the fastest way to a green metric is to accept every overdue risk."""
    overdue = [_item(OPEN, -10) for _ in range(4)]
    before = summarize(overdue, now=NOW).on_time_rate
    after = summarize(overdue + [_item(RISK_ACCEPTED, -10) for _ in range(20)],
                      now=NOW).on_time_rate
    assert after <= before


def test_an_empty_backlog_is_on_time():
    assert summarize([], now=NOW).on_time_rate == 100


# ── ticket payload ────────────────────────────────────────────────────────────────────────────────
def test_a_ticket_carries_what_an_engineer_needs_to_act():
    payload = ticket_payload(
        finding_title="SQL injection in /search", severity="critical", risk_score=95,
        asset="storefront", description="The parameter reaches the database.",
        remediation="Use parameterized queries.", cwe_id="CWE-89", owasp_ref="A03:2021",
        cve_ids=(), evidence_summary="GET /search?q=' → sqlite3.OperationalError",
        due=NOW + dt.timedelta(days=7), finding_url="/findings/abc",
    )
    assert payload.title.startswith("[CRITICAL]")
    assert "Use parameterized queries." in payload.body
    assert "CWE-89" in payload.body
    assert "sqlite3.OperationalError" in payload.body
    assert "/findings/abc" in payload.body
    assert "severity:critical" in payload.labels


def test_a_ticket_says_verification_is_automatic():
    """The assignee should not go looking for a "mark done" button that deliberately does not
    exist."""
    payload = ticket_payload(finding_title="t", severity="high", risk_score=70, asset="a")
    assert "closes when a scan" in payload.body


def test_a_grouped_issue_produces_one_ticket_that_says_so():
    """Three engines finding the same credential is one thing to fix, and three tickets for it is
    how a remediation backlog stops being believed."""
    payload = ticket_payload(finding_title="Hardcoded credential", severity="high", risk_score=80,
                             asset="app", duplicate_count=2)
    assert "Reported by 3 findings" in payload.body
    assert "resolves all of them" in payload.body


def test_a_ticket_title_is_bounded():
    payload = ticket_payload(finding_title="x" * 500, severity="low", risk_score=10, asset="a")
    assert len(payload.title) <= 250


def test_the_statuses_are_a_closed_set():
    assert set(ACTIVE) <= set(STATUSES)
    assert VERIFIED in STATUSES
