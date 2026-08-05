"""Deterministic, transparent risk scoring (the Risk Engine).

Severity and the 0–100 risk score are reproducible functions of exploitability + impact signals;
the AI analyst may *explain* them but never silently overrides them (doc 01 §5). Keeping this pure
and dependency-free makes it unit-testable and identical everywhere it runs.

Two outputs, one model:
  - `score_severity(inp)` → the Critical/High/Medium/Low band (backward-compatible).
  - `assess(inp)`         → a `RiskAssessment` with the band, a 0–100 score, and a human-readable
                            rationale listing exactly which signals moved the number.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from guardian_core.enums import Severity

_CVSS_BANDS: tuple[tuple[float, Severity], ...] = (
    (9.0, Severity.CRITICAL),
    (7.0, Severity.HIGH),
    (4.0, Severity.MEDIUM),
    (0.1, Severity.LOW),
)

_CRIT_BUMP = {"critical": 2, "high": 1, "medium": 0, "low": 0}

# Base score anchored to the starting severity band, then adjusted by signals.
_SEVERITY_BASE_SCORE = {
    Severity.CRITICAL: 90,
    Severity.HIGH: 72,
    Severity.MEDIUM: 50,
    Severity.LOW: 25,
    Severity.INFO: 5,
}

_CRITICALITY_WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 0}
_BUSINESS_IMPACT_WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 0, "none": 0}


@dataclass(frozen=True)
class ScoreInputs:
    """Signals fed into the scorer. All optional except the base band."""

    base_severity: Severity  # engine's raw assessment (fallback / floor)
    cvss_base: float | None = None  # 0.0–10.0
    epss_score: float | None = None  # 0.0–1.0 exploit probability
    kev: bool = False  # CISA Known-Exploited flag
    exposure: str = "internal"  # "public" | "internal" | "unknown"
    asset_criticality: str = "medium"  # low | medium | high | critical
    # Business context: how damaging exploitation would be to the business (data, revenue, trust).
    business_impact: str = "medium"  # none | low | medium | high | critical


@dataclass(frozen=True)
class RiskAssessment:
    """The Risk Engine's verdict: band + 0–100 score + transparent rationale."""

    severity: Severity
    score: int  # 0–100
    rationale: list[str] = field(default_factory=list)


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
    """Combine signals into a final severity band (deterministic).

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


def assess(inp: ScoreInputs) -> RiskAssessment:
    """Full risk assessment: the band plus an auditable 0–100 score and rationale.

    Risk = f(severity band, EPSS, KEV, exposure, asset criticality, business impact).
    Every adjustment is recorded in `rationale` so the number is never a black box — this is the
    core of turning a CVSS figure into a *business* risk (doc 07 §1, user's Risk Engine idea).
    """
    severity = score_severity(inp)
    rationale: list[str] = []

    score = _SEVERITY_BASE_SCORE[severity]
    rationale.append(f"Base {score} from {severity.value} severity band")

    if inp.kev:
        score += 8
        rationale.append("+8 CISA KEV — actively exploited in the wild")

    if inp.epss_score is not None:
        if inp.epss_score >= 0.5:
            score += 6
            rationale.append(f"+6 high EPSS ({inp.epss_score:.2f} exploit probability)")
        elif inp.epss_score >= 0.1:
            score += 3
            rationale.append(f"+3 moderate EPSS ({inp.epss_score:.2f})")

    if inp.exposure == "public":
        score += 6
        rationale.append("+6 publicly exposed asset")
    elif inp.exposure == "unknown":
        score += 2
        rationale.append("+2 exposure unknown (conservative)")

    crit_w = _CRITICALITY_WEIGHT.get(inp.asset_criticality, 0)
    if crit_w:
        score += crit_w
        rationale.append(f"+{crit_w} asset criticality: {inp.asset_criticality}")

    bi_w = _BUSINESS_IMPACT_WEIGHT.get(inp.business_impact, 0)
    if bi_w:
        score += bi_w
        rationale.append(f"+{bi_w} business impact: {inp.business_impact}")

    score = max(0, min(100, score))
    return RiskAssessment(severity=severity, score=score, rationale=rationale)
