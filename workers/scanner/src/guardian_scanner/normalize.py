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


# Fields a rescan re-observes and may therefore overwrite. Deliberately excludes everything a human
# owns — `status`, `justification`, `reopened_count` — and everything about the finding's history.
# A scan reports what it sees; it does not overturn a triage decision.
_OBSERVED_FIELDS = (
    "title", "description", "category", "cwe_id", "owasp_ref", "cve_ids", "cvss_base",
    "epss_score", "kev", "exploit_maturity", "ransomware", "severity", "risk_score",
    "risk_rationale", "confidence", "location", "evidence", "references",
)


def merge_sighting(existing: Finding, fresh: Finding, *, scan_id, engine_run_id) -> Finding:  # noqa: ANN001
    """Fold a fresh sighting into the finding that already represents this issue.

    One row per `(asset, fingerprint)` is what `verification._apply` has always assumed — its own
    comment says a returning issue is handled by "reopening the original rather than filing a new
    finding … otherwise 'fixed twice' is invisible". The scan path never implemented that half and
    inserted unconditionally, so every rescan added a row and the customer's open count grew while
    nothing got worse.

    `scan_id` and `engine_run_id` move to the observing scan, which is what makes
    `reconcile_scan` able to tell what this scan saw from what it did not. Status is untouched here:
    reconciliation owns every status transition, so there is still exactly one place that decides
    whether a finding is resolved, still present, or unchecked.
    """
    for field in _OBSERVED_FIELDS:
        setattr(existing, field, getattr(fresh, field))
    existing.scan_id = scan_id
    existing.engine_run_id = engine_run_id
    return existing


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    counts["total"] = len(findings)
    return counts
