"""Workbench query mechanics (WP-F2), tested without a database.

The cursor is the interesting part. Keyset paging replaced OFFSET because OFFSET skips and repeats
rows when a scan is writing while an analyst scrolls — and because the previous list endpoint sorted
in Python *after* the database had already discarded everything past row 1000, so "worst first"
silently meant "worst of an arbitrary thousand".
"""

from __future__ import annotations

import datetime as dt
import uuid

import pytest
from guardian_api.workbench import (
    DEFAULT_PAGE,
    MAX_PAGE,
    SEVERITY_RANK,
    STATUSES,
    Cursor,
    InvalidCursor,
    decode_cursor,
    encode_cursor,
    page_size,
    triage_requires_note,
    validate_transition,
)


class _Row:
    """The three fields the cursor is made of."""

    def __init__(self, severity="high", risk=70, created_at=None, id=None):  # noqa: A002
        self.severity = severity
        self.risk_score = risk
        self.created_at = created_at or dt.datetime(2026, 8, 18, 12, 0, tzinfo=dt.UTC)
        self.id = id or uuid.uuid4()


# ── ordering ──────────────────────────────────────────────────────────────────────────────────────
def test_severity_ranks_worst_first():
    assert sorted(SEVERITY_RANK, key=SEVERITY_RANK.get) == [
        "critical", "high", "medium", "low", "info",
    ]


# ── the cursor ────────────────────────────────────────────────────────────────────────────────────
def test_a_cursor_round_trips():
    row = _Row(severity="critical", risk=93)
    cursor = decode_cursor(encode_cursor(row))
    assert cursor == Cursor(rank=0, risk=93, created_at=row.created_at, id=row.id)


def test_a_cursor_carries_the_whole_sort_key():
    """Anything less is not a total order, and two findings sharing severity, score and timestamp
    would straddle a page boundary with one of them skipped."""
    row = _Row()
    cursor = decode_cursor(encode_cursor(row))
    assert cursor.rank is not None
    assert cursor.risk == row.risk_score
    assert cursor.created_at == row.created_at
    assert cursor.id == row.id


@pytest.mark.parametrize(
    "raw", ["", "not-base64!!", "eyJ9", "YWJj", "e30", "eyJyIjoxfQ"],
)
def test_a_malformed_cursor_is_refused_rather_than_ignored(raw):
    """Silently restarting at page 1 would show the caller the top of the list while they believed
    they were reading page 40 — which reads as 'no more findings'."""
    with pytest.raises(InvalidCursor):
        decode_cursor(raw)


def test_an_unknown_severity_sorts_last_not_first():
    """A finding with a severity nobody recognizes must not be promoted to the top of the queue."""
    row = _Row(severity="catastrophic")
    assert decode_cursor(encode_cursor(row)).rank > SEVERITY_RANK["info"]


# ── paging bounds ─────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("asked", "expected"), [
    (None, DEFAULT_PAGE), (0, DEFAULT_PAGE), (-5, DEFAULT_PAGE),
    (10, 10), (MAX_PAGE, MAX_PAGE), (10_000, MAX_PAGE),
])
def test_a_page_is_bounded(asked, expected):
    """An unbounded page is a way to make the API read the whole table on one request."""
    assert page_size(asked) == expected


# ── triage rules ──────────────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize("target", ["false_positive", "accepted_risk", "resolved"])
def test_silencing_a_finding_requires_a_justification(target):
    """Each of these says the customer need not act. Somebody has to own that claim on the record."""
    assert triage_requires_note(status=target, severity_override=None) is True


@pytest.mark.parametrize("target", ["open", "triaged", "confirmed", None])
def test_escalating_or_acknowledging_does_not(target):
    assert triage_requires_note(status=target, severity_override=None) is False


def test_a_severity_override_always_requires_a_justification():
    """Overriding the deterministic score is the one action that makes the risk engine's output
    disagree with what the customer is shown."""
    assert triage_requires_note(status=None, severity_override="low") is True


@pytest.mark.parametrize("target", STATUSES)
def test_every_documented_status_is_reachable(target):
    assert validate_transition("open", target) is None


def test_a_status_outside_the_vocabulary_is_refused():
    """It would create a state no filter, no gate and no report understands — a finding that has
    quietly left the workflow."""
    assert validate_transition("open", "wontfix") is not None
    assert validate_transition("open", "closed") is not None


def test_reopening_is_allowed():
    """WP-E2 reopens findings automatically when they come back; an analyst may do the same."""
    assert validate_transition("resolved", "open") is None
    assert validate_transition("accepted_risk", "confirmed") is None


def test_a_no_op_transition_is_not_an_error():
    assert validate_transition("open", "open") is None
    assert validate_transition("open", None) is None
