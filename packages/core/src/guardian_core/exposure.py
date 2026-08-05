"""Deterministic exposure scoring (the Exposure Engine) — Phase 6.

Exposure answers "how reachable / attackable is this asset from the outside?" and is kept **separate
from vulnerability risk** on purpose (a hardened but internet-facing host is highly exposed yet may
carry low risk; a critical bug on an unreachable internal box is high risk yet low exposure). Mixing
them hides both signals.

Like the Risk Engine this is pure, dependency-free, and fully transparent: the 0–100 score is a
reproducible function of reachability signals and every point is explained in the rationale. The AI
never sets it. Downstream priority is a *derived* product, not stored here:

    priority ≈ risk_score × exposure_score × asset_criticality   (computed at read time)
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class ExposureInputs:
    """Reachability signals for one asset/graph node. All optional; absence means 'not observed'."""

    internet_reachable: bool = False       # resolves + routable from the public internet
    public_dns: bool = False               # has a public DNS record
    open_ports: int = 0                    # count of open, reachable services
    sensitive_ports: bool = False          # SSH/RDP/DB exposed to the internet
    missing_tls: bool = False              # a web/API service without TLS
    cloud_public: bool = False             # a cloud resource with public access (bucket/SG)
    unknown_ownership: bool = False        # ownership unconfirmed — shadow-asset signal
    dangling_dns: bool = False             # CNAME/record pointing at an unclaimed target (takeover)


@dataclass(frozen=True)
class ExposureAssessment:
    score: int  # 0–100
    rationale: list[str] = field(default_factory=list)


def assess_exposure(inp: ExposureInputs) -> ExposureAssessment:
    """Compute a transparent 0–100 exposure score from reachability signals."""
    score = 0
    rationale: list[str] = []

    if inp.internet_reachable:
        score += 30
        rationale.append("+30 reachable from the public internet")
    if inp.public_dns:
        score += 10
        rationale.append("+10 has a public DNS record")
    if inp.open_ports:
        pts = min(20, inp.open_ports * 5)
        score += pts
        rationale.append(f"+{pts} {inp.open_ports} open service(s)")
    if inp.sensitive_ports:
        score += 15
        rationale.append("+15 sensitive port (SSH/RDP/DB) exposed")
    if inp.missing_tls:
        score += 10
        rationale.append("+10 service without TLS")
    if inp.cloud_public:
        score += 20
        rationale.append("+20 cloud resource is publicly accessible")
    if inp.dangling_dns:
        score += 20
        rationale.append("+20 dangling DNS record (subdomain-takeover risk)")
    if inp.unknown_ownership:
        score += 10
        rationale.append("+10 ownership unconfirmed (possible shadow asset)")

    score = max(0, min(100, score))
    return ExposureAssessment(score=score, rationale=rationale)
