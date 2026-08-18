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

# Exploit code maturity, on the CVSS temporal scale (WP-C4). This is the signal a remediation
# queue is actually ordered by: a 9.8 nobody has written an exploit for and a 7.5 with a working
# Metasploit module are not the same morning's work.
_MATURITY_WEIGHT = {"high": 10, "functional": 6, "poc": 2, "unproven": 0}
# The most any finding can earn from signals: KEV + ransomware + weaponized exploit + high EPSS +
# public exposure + critical asset + critical business impact.
_MAX_SIGNAL_POINTS = 8 + 8 + 10 + 6 + 6 + 12 + 12
_MATURITY_BUMP = {"high": 1, "functional": 1}

_CRITICALITY_WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 0}
_BUSINESS_IMPACT_WEIGHT = {"critical": 12, "high": 8, "medium": 4, "low": 0, "none": 0}


@dataclass(frozen=True)
class ScoreInputs:
    """Signals fed into the scorer. All optional except the base band."""

    base_severity: Severity  # engine's raw assessment (fallback / floor)
    cvss_base: float | None = None  # 0.0–10.0
    epss_score: float | None = None  # 0.0–1.0 exploit probability
    kev: bool = False  # CISA Known-Exploited flag
    # "high" | "functional" | "poc" | "unproven" — how available working exploit code is (WP-C4).
    exploit_maturity: str | None = None
    # CISA records this separately from KEV membership: a vulnerability used in ransomware
    # campaigns has a different response deadline from one merely seen being exploited.
    ransomware: bool = False
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
      4. Working exploit code (functional or better) → bump one step.
      5. Public exposure + high/critical asset criticality → bump one step.
    Bumps are capped at CRITICAL.
    """
    sev = _from_cvss(inp.cvss_base) if inp.cvss_base is not None else inp.base_severity

    if inp.kev:
        sev = _bump(sev, 1)
        if sev.rank < Severity.HIGH.rank:
            sev = Severity.HIGH

    if inp.epss_score is not None and inp.epss_score >= 0.5:
        sev = _bump(sev, 1)

    # A proof of concept does not bump: it says someone demonstrated the bug, not that it is
    # usable. Treating a PoC like a working exploit is how every advisory becomes critical.
    sev = _bump(sev, _MATURITY_BUMP.get(inp.exploit_maturity or "", 0))

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
    signals: list[tuple[int, str]] = []

    if inp.kev:
        signals.append((8, "CISA KEV — actively exploited in the wild"))

    if inp.ransomware:
        signals.append((8, "used in known ransomware campaigns"))

    maturity_w = _MATURITY_WEIGHT.get(inp.exploit_maturity or "", 0)
    if maturity_w:
        signals.append((maturity_w, {
            "high": "weaponized, reliable exploit code is public",
            "functional": "working exploit code is public",
            "poc": "a proof of concept is public",
        }[inp.exploit_maturity]))

    if inp.epss_score is not None:
        if inp.epss_score >= 0.5:
            signals.append((6, f"high EPSS ({inp.epss_score:.2f} exploit probability)"))
        elif inp.epss_score >= 0.1:
            signals.append((3, f"moderate EPSS ({inp.epss_score:.2f})"))

    if inp.exposure == "public":
        signals.append((6, "publicly exposed asset"))
    elif inp.exposure == "unknown":
        signals.append((2, "exposure unknown (conservative)"))

    crit_w = _CRITICALITY_WEIGHT.get(inp.asset_criticality, 0)
    if crit_w:
        signals.append((crit_w, f"asset criticality: {inp.asset_criticality}"))

    bi_w = _BUSINESS_IMPACT_WEIGHT.get(inp.business_impact, 0)
    if bi_w:
        signals.append((bi_w, f"business impact: {inp.business_impact}"))

    # Signals are scaled into the headroom above the band's floor rather than added raw.
    #
    # Added raw, an ordinary public finding on a high-criticality asset already exceeded 100 — the
    # weights sum to 62 above a critical floor of 90 — so it saturated before any exploit signal
    # applied, and a weaponized critical scored exactly the same as a theoretical one. A scale whose
    # top is reached by the common case cannot rank anything, which is the opposite of what a
    # remediation queue needs.
    floor = _SEVERITY_BASE_SCORE[severity]
    earned = sum(weight for weight, _ in signals)
    headroom = 100 - floor
    bonus = round(headroom * min(earned, _MAX_SIGNAL_POINTS) / _MAX_SIGNAL_POINTS)

    rationale = [f"Base {floor} from {severity.value} severity band"]
    rationale += [f"signal +{weight}: {text}" for weight, text in signals]
    rationale.append(
        f"Signals {earned}/{_MAX_SIGNAL_POINTS} of maximum → +{bonus} of {headroom} available "
        f"above the {severity.value} floor"
    )

    score = max(0, min(100, floor + bonus))
    score = max(0, min(100, score))
    return RiskAssessment(severity=severity, score=score, rationale=rationale)
