"""AI-analysis task: enrich a scan's findings with grounded explanations + remediation.

Runs after a scan (on demand or triggered). Uses the configured LLM provider — the deterministic
stub when no API key is set — so it always completes, offline included. Severity/risk are untouched.
"""

from __future__ import annotations

import uuid

from guardian_ai.analyst import explain_finding
from guardian_ai.providers import get_provider
from guardian_common.logging import get_logger
from guardian_db.audit import record_audit
from guardian_db.models import Finding, Scan
from guardian_db.session import session_scope

from guardian_scanner.celery_app import celery_app

log = get_logger("guardian.analysis")


@celery_app.task(name="guardian.analyze_scan")
def analyze_scan(scan_id: str) -> dict:
    """Populate ai_explanation + remediation for each finding in the scan."""
    provider = get_provider()
    analyzed = 0
    with session_scope() as session:
        scan = session.get(Scan, uuid.UUID(scan_id))
        if scan is None:
            return {"scan_id": scan_id, "status": "not_found"}
        findings = session.query(Finding).filter(Finding.scan_id == scan.id).all()
        for finding in findings:
            try:
                out = explain_finding(session, finding, provider)
            except Exception as exc:  # noqa: BLE001 - one finding must not fail the batch
                log.error("analysis_failed", finding_id=str(finding.id), error=str(exc))
                continue
            finding.ai_explanation = out.get("explanation")
            finding.remediation = {
                "summary": (out.get("remediation") or "")[:280],
                "remediation": out.get("remediation"),
                "impact": out.get("impact"),
                "attack_scenario": out.get("attack_scenario"),
                "references": out.get("references", []),
            }
            analyzed += 1
        record_audit(
            session,
            action="scan.analyzed",
            tenant_id=scan.tenant_id,
            customer_id=scan.customer_id,
            entity_type="scan",
            entity_id=str(scan.id),
            metadata={"analyzed": analyzed, "provider": provider.name},
        )
        return {
            "scan_id": scan_id,
            "status": "completed",
            "analyzed": analyzed,
            "provider": provider.name,
        }
