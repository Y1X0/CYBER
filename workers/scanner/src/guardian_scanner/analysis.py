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
        failed: list[str] = []
        guarded = 0
        for finding in findings:
            try:
                out = explain_finding(session, finding, provider)
            except Exception as exc:  # noqa: BLE001 - one finding must not fail the batch
                # Counted and returned, not merely logged: a run where the provider failed on every
                # finding currently reports `completed` with `analyzed: 0`, which reads as "the
                # findings needed no explanation" rather than "the analyst never ran".
                failed.append(f"{finding.id}: {type(exc).__name__}: {exc}"[:200])
                log.error("analysis_failed", finding_id=str(finding.id), error=str(exc))
                continue
            guard = out.get("_guard") or {}
            if any(guard.values()):
                guarded += 1
            finding.ai_explanation = out.get("explanation")
            finding.remediation = {
                "summary": (out.get("remediation") or "")[:280],
                "remediation": out.get("remediation"),
                "impact": out.get("impact"),
                "attack_scenario": out.get("attack_scenario"),
                "references": out.get("references", []),
                # What the guard did to this explanation, kept with it: a reader who sees an
                # explanation that was altered on the way in or out should be able to find that out.
                "guard": guard,
            }
            analyzed += 1
        record_audit(
            session,
            action="scan.analyzed",
            tenant_id=scan.tenant_id,
            customer_id=scan.customer_id,
            entity_type="scan",
            entity_id=str(scan.id),
            metadata={"analyzed": analyzed, "provider": provider.name,
                      "failed": len(failed), "guarded": guarded},
        )
        return {
            "scan_id": scan_id,
            # `partial` when some findings could not be explained: the difference between "every
            # finding has an explanation" and "some do" is one a customer can act on.
            "status": "completed" if not failed else ("failed" if analyzed == 0 else "partial"),
            "analyzed": analyzed,
            "failed": len(failed),
            "errors": failed[:10],
            "guarded": guarded,
            "provider": provider.name,
        }
