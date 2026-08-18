"""Normalize raw engine findings → persisted Finding rows (dedup + standards + scoring).

This is the engine-agnostic seam described in doc 01 §5: every engine's output flows through the
same mapping, so scoring and dedup are identical regardless of which tool produced the finding.
"""

from __future__ import annotations

import uuid

from guardian_core.findings import RawFinding
from guardian_core.scoring import ScoreInputs, assess
from guardian_db.models import Finding


def to_finding(
    raw: RawFinding,
    *,
    tenant_id: uuid.UUID,
    customer_id: uuid.UUID,
    scan_id: uuid.UUID,
    engine_run_id: uuid.UUID,
    asset_id: uuid.UUID,
    exposure: str,
    asset_criticality: str,
    business_impact: str = "medium",
) -> Finding:
    # Risk Engine: deterministic severity band + 0–100 score + auditable rationale.
    risk = assess(
        ScoreInputs(
            base_severity=raw.base_severity,
            cvss_base=raw.cvss_base,
            epss_score=raw.epss_score,
            kev=raw.kev,
            exploit_maturity=raw.exploit_maturity,
            ransomware=raw.ransomware,
            exposure=exposure,
            asset_criticality=asset_criticality,
            business_impact=business_impact,
        )
    )
    return Finding(
        tenant_id=tenant_id,
        customer_id=customer_id,
        scan_id=scan_id,
        engine_run_id=engine_run_id,
        asset_id=asset_id,
        fingerprint=raw.fingerprint(),
        title=raw.title,
        description=raw.description,
        category=raw.category,
        cwe_id=raw.cwe_id,
        owasp_ref=raw.owasp_ref,
        cve_ids=list(raw.cve_ids),
        cvss_base=raw.cvss_base,
        epss_score=raw.epss_score,
        kev=raw.kev,
        exploit_maturity=raw.exploit_maturity,
        ransomware=raw.ransomware,
        severity=risk.severity.value,
        risk_score=risk.score,
        risk_rationale=risk.rationale,
        confidence=raw.confidence,
        status="open",
        source="automated",
        location=raw.location,
        evidence=raw.evidence,
        references=raw.references,
    )


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts
