"""Deterministic security score (0–100) for a set of findings.

Like severity, this is a transparent, reproducible function — the AI reports it, never sets it.
Starts at 100 and deducts weighted penalties per open finding, saturating so a handful of criticals
can't wrap around. Resolved / false-positive / accepted-risk findings don't count against the score.
"""

from __future__ import annotations

from collections.abc import Iterable

_WEIGHTS = {"critical": 25, "high": 12, "medium": 5, "low": 1, "info": 0}
_OPEN_STATES = {"open", "triaged", "confirmed"}


def security_score(findings: Iterable) -> int:
    """Compute the 0–100 posture score from finding objects (need .severity and .status)."""
    penalty = 0.0
    for f in findings:
        status = getattr(f, "status", "open")
        if status not in _OPEN_STATES:
            continue
        penalty += _WEIGHTS.get(getattr(f, "severity", "info"), 0)
    # Diminishing returns: never below 0, and each additional finding hurts a little less.
    score = 100.0 - min(100.0, penalty)
    return int(round(max(0.0, score)))
