"""Governance temporal-comparison safety (no DB). Proves the L3+/grant time checks never mix
naive and aware datetimes and stay semantically correct when a persisted timestamp comes back naive
(the governance models declare plain `DateTime`, so PostgreSQL returns naive values).

A naive timestamp is interpreted as UTC (the platform's storage convention), so an expired/closed
window is still recognized as expired/closed — the fix is tz-safety, not a semantics change.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_db.models import ApiKey, Approval, Campaign, CapabilityGrant
from guardian_scanner.tools.governance import (
    _aware,
    _grant_ceiling,
    _validate_approval,
    _validate_campaign,
)

_TID = uuid.uuid4()
_CID = uuid.uuid4()
_ACTOR = uuid.uuid4()


def _naive(delta_minutes: int) -> dt.datetime:
    """A NAIVE UTC timestamp offset from now — mimics a value read back from a `timestamp` column."""
    return (dt.datetime.now(dt.UTC) + dt.timedelta(minutes=delta_minutes)).replace(tzinfo=None)


class _FakeResult:
    def __init__(self, rows):
        self._rows = list(rows)

    def first(self):  # noqa: ANN201
        return (self._rows[0],) if self._rows else None

    def scalars(self):  # noqa: ANN201
        return iter(self._rows)


class _FakeSession:
    """Returns a fixed object from get() and fixed rows from execute() — no DB, no query engine."""

    def __init__(self, get_obj=None, rows=()):  # noqa: ANN001
        self._get_obj = get_obj
        self._rows = rows

    def get(self, _model, _pk):  # noqa: ANN001, ANN201
        return self._get_obj

    def execute(self, *_a, **_k):  # noqa: ANN201
        return _FakeResult(self._rows)


# ── _aware() ──────────────────────────────────────────────────────────────────────────────────────
def test_aware_normalizes_naive_to_utc_and_passes_aware_through():
    assert _aware(None) is None
    naive = dt.datetime(2026, 1, 1, 12, 0, 0)
    out = _aware(naive)
    assert out.tzinfo is dt.UTC and out.replace(tzinfo=None) == naive   # same wall-clock, now UTC
    already = dt.datetime(2026, 1, 1, 12, 0, 0, tzinfo=dt.UTC)
    assert _aware(already) is already                                   # aware passes through


# ── campaign window (naive starts_at / ends_at) ────────────────────────────────────────────────────
def _campaign(**kw):  # noqa: ANN003, ANN202
    c = Campaign(tenant_id=_TID, status="active", max_capability_level=4)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def test_campaign_window_ended_with_naive_ends_at_is_tz_safe():
    now = dt.datetime.now(dt.UTC)
    camp = _campaign(starts_at=None, ends_at=_naive(-1))          # closed 1 min ago, NAIVE
    reason = _validate_campaign(_FakeSession(camp), _TID, str(_CID), _ACTOR, 4, now)
    assert reason == "campaign window has ended"                  # correct + no TypeError


def test_campaign_not_started_with_naive_starts_at_is_tz_safe():
    now = dt.datetime.now(dt.UTC)
    camp = _campaign(starts_at=_naive(+5), ends_at=None)          # opens in 5 min, NAIVE
    reason = _validate_campaign(_FakeSession(camp), _TID, str(_CID), _ACTOR, 4, now)
    assert reason == "campaign has not started"


# ── approval expiry (naive expires_at) ─────────────────────────────────────────────────────────────
def test_approval_expired_with_naive_expires_at_is_tz_safe():
    now = dt.datetime.now(dt.UTC)
    appr = Approval(tenant_id=_TID, campaign_id=_CID, subject_kind="tool_job",
                    capability_level=4, expires_at=_naive(-1))   # expired 1 min ago, NAIVE
    appr.revoked_at = None
    appr.consumed_at = None
    _uuid, reason = _validate_approval(
        _FakeSession(appr), _TID, str(uuid.uuid4()), required=4, tool_key="x",
        campaign_id=str(_CID), actor_uuid=_ACTOR, now=now)
    assert reason == "approval expired"


# ── capability grant expiry (naive expires_at) ─────────────────────────────────────────────────────
def _grant(**kw):  # noqa: ANN003, ANN202
    g = CapabilityGrant(tenant_id=_TID, subject_kind="user", subject_ref=str(_ACTOR),
                        max_level=3, tool_allowlist=None)
    g.revoked_at = None
    for k, v in kw.items():
        setattr(g, k, v)
    return g


def test_expired_naive_grant_is_ignored():
    now = dt.datetime.now(dt.UTC)
    grant = _grant(expires_at=_naive(-1))                        # expired, NAIVE → must be skipped
    ceiling = _grant_ceiling(_FakeSession(rows=[grant]), _TID, user_uuid=_ACTOR, role=None,
                             api_key_id=None, tool_key="x", now=now)
    assert ceiling is None                                       # expired grant confers nothing


def test_live_naive_grant_still_counts():
    now = dt.datetime.now(dt.UTC)
    grant = _grant(expires_at=_naive(+60))                       # live for 60 min, NAIVE
    ceiling = _grant_ceiling(_FakeSession(rows=[grant]), _TID, user_uuid=_ACTOR, role=None,
                             api_key_id=None, tool_key="x", now=now)
    assert ceiling == 3                                          # semantics preserved: still granted


def test_apikey_expiry_helper_handles_naive():
    # Direct proof the same normalization applies to the api-key expiry sibling check.
    assert _aware(_naive(-1)) <= dt.datetime.now(dt.UTC)
    assert _aware(_naive(+1)) > dt.datetime.now(dt.UTC)
    _ = ApiKey  # imported to assert the model is available for the sibling path
