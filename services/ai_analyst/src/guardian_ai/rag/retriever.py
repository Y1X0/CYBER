"""Retrieval-Augmented grounding for the analyst.

Phase 3 retrieves deterministically by standards mapping (CWE / OWASP / tags / CVE) — no embeddings
required, fully testable offline. `kb_entries.embedding` + pgvector similarity is a later upgrade
behind this same function, so callers don't change.
"""

from __future__ import annotations

from guardian_db.models import KbEntry, Vulnerability, Weakness
from sqlalchemy import or_, select
from sqlalchemy.orm import Session


def retrieve_for_finding(session: Session, finding) -> dict:  # noqa: ANN001
    """Gather KB context relevant to a finding: weakness (CWE), advisories (CVE), best-practices."""
    ctx: dict = {"kb": [], "weakness": None, "vulnerabilities": []}

    if finding.cwe_id:
        weakness = (
            session.execute(select(Weakness).where(Weakness.external_id == finding.cwe_id))
            .scalars()
            .first()
        )
        if weakness:
            ctx["weakness"] = {
                "id": weakness.external_id,
                "name": weakness.name,
                "description": weakness.description,
            }

    # KB entries whose standards mention this CWE/OWASP, or whose tags match the category.
    conditions = []
    if finding.cwe_id:
        conditions.append(KbEntry.standards["cwe"].astext == finding.cwe_id)
    if finding.owasp_ref:
        conditions.append(KbEntry.standards["owasp"].astext == finding.owasp_ref)
    conditions.append(KbEntry.tags.contains([finding.category]))
    kb_rows = session.execute(select(KbEntry).where(or_(*conditions)).limit(5)).scalars().all()
    ctx["kb"] = [{"title": e.title, "body": e.body, "standards": e.standards} for e in kb_rows]

    for cve in finding.cve_ids or []:
        vuln = (
            session.execute(select(Vulnerability).where(Vulnerability.external_id == cve))
            .scalars()
            .first()
        )
        if vuln:
            ctx["vulnerabilities"].append(
                {
                    "id": vuln.external_id,
                    "summary": vuln.summary,
                    "cvss_base": float(vuln.cvss_base) if vuln.cvss_base is not None else None,
                    "kev": vuln.kev,
                }
            )
    return ctx
