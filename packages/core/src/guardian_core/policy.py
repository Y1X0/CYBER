"""Deployment-gate policy engine (deterministic).

A policy is a set of `fail_on` rules; the gate fails if any OPEN finding matches any rule. Like
scoring, this is transparent and reproducible — the AI never decides whether a build is blocked.

Rule keys (all optional, ANDed within a rule):
  severity   : exact severity match ("critical" | "high" | ...)
  risk_gte   : risk_score >= N
  epss_gt    : epss_score > x
  kev        : true → finding is CISA Known-Exploited
Example rules: {"fail_on": [{"severity": "critical"}, {"kev": true}]}
"""

from __future__ import annotations

from dataclasses import dataclass, field

# Sensible built-in gate used when a project has no policy configured.
DEFAULT_RULES = {
    "fail_on": [{"severity": "critical"}, {"severity": "high", "epss_gt": 0.5}, {"kev": True}]
}

_OPEN_STATES = {"open", "triaged", "confirmed"}


@dataclass
class GateResult:
    passed: bool
    blocking: list[dict] = field(default_factory=list)  # findings that tripped the gate
    rule_hits: list[str] = field(default_factory=list)  # human-readable reasons


def _matches(finding, rule: dict) -> bool:  # noqa: ANN001
    if "severity" in rule and getattr(finding, "severity", None) != rule["severity"]:
        return False
    if "risk_gte" in rule and (getattr(finding, "risk_score", 0) or 0) < rule["risk_gte"]:
        return False
    if "epss_gt" in rule:
        epss = getattr(finding, "epss_score", None)
        if epss is None or float(epss) <= rule["epss_gt"]:
            return False
    if rule.get("kev") and not getattr(finding, "kev", False):
        return False
    return True


def evaluate_gate(findings, rules: dict | None = None) -> GateResult:  # noqa: ANN001
    """Return the gate decision for a set of findings against `rules` (or DEFAULT_RULES)."""
    fail_on = (rules or DEFAULT_RULES).get("fail_on", [])
    blocking: list[dict] = []
    hits: list[str] = []
    for finding in findings:
        if getattr(finding, "status", "open") not in _OPEN_STATES:
            continue
        for rule in fail_on:
            if _matches(finding, rule):
                blocking.append(
                    {
                        "id": str(getattr(finding, "id", "")),
                        "title": getattr(finding, "title", ""),
                        "severity": getattr(finding, "severity", ""),
                        "rule": rule,
                    }
                )
                hits.append(f"{getattr(finding, 'severity', '')}:{getattr(finding, 'title', '')}")
                break
    return GateResult(passed=not blocking, blocking=blocking, rule_hits=hits)
