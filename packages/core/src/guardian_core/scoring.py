"""Deterministic, transparent risk scoring.

Severity is a reproducible function of exploitability + impact signals; the AI analyst may
*explain* it but never silently overrides it (doc 01 §5). Keeping this pure and dependency-free
makes it unit-testable and identical everywhere it runs.
"""

from __future__ import annotations

from dataclasses import dataclass

from guardian_core.enums import Severity


@dataclass(frozen=True)
class ScoreInputs:
    """Signals fed into the scorer. All optional except the base band."""

    base_severity: Severity  # engine's raw assessment (fallback / floor)
    cvss_base: float | None = None  # 0.0–10.0
    epss_score: float | None = None  # 0.0–1.0 exploit probability
    kev: bool = False  # CISA Known-Exploited flag
    exposure: str = "internal"  # "public" | "internal" | "unknown"
    asset_criticality: str = "medium"  # low | medium | high | critical


_CVSS_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)

_CRIT_BUMP = {"critical": 2, "high": 1, "medium": 0, "low": 0}


def _from_cvss(cvss: float) -> Severity:
    for threshold, sev in _CVSS_BANDS:
        if cvss >= threshold:
            return sev
    return Severity.INFO


def _bump(sev: Severity, steps: int) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    idx = min(len(order) - 1, max(0, order.index(sev) + steps))
    return order[idx]


def score_severity(inp: ScoreInputs) -> Severity:
    """Combine signals into a final severity.

    Rules (deterministic, documented):
      1. Start from CVSS band if present, else the engine's base severity.
      2. KEV (actively exploited) → floor at HIGH, and bump one step.
      3. High EPSS (>=0.5) → bump one step.
      4. Public exposure + high/critical asset criticality → bump one step.
    Bumps are capped at CRITICAL.
    """
    sev = _from_cvss(inp.cvss_base) if inp.cvss_base is not None else inp.base_severity

    if inp.kev:
        sev = _bump(sev, 1)
        if sev.rank < Severity.HIGH.rank:
            sev = Severity.HIGH

    if inp.epss_score is not None and inp.epss_score >= 0.5:
        sev = _bump(sev, 1)

    if inp.exposure == "public":
        sev = _bump(sev, _CRIT_BUMP.get(inp.asset_criticality, 0))

    return sev
