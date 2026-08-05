"""Vulnerability matchers — bridge the SCA engine to a data source.

`KbVulnMatcher` matches dependencies against the local knowledge base (offline, fast, testable).
A live-feed matcher (OSV) can be swapped in without touching the engine, since both satisfy the
`VulnMatcher` protocol.
"""

from __future__ import annotations

from guardian_core.enums import Severity
from guardian_db.models import Vulnerability
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_scanner.engines.base import VulnMatch


def _severity_from_cvss(cvss: float | None) -> Severity:
    if cvss is None:
        return Severity.MEDIUM
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW


def _version_affected(entry: dict, version: str) -> bool:
    versions = entry.get("versions")
    if versions:
        return version in versions
    if "version" in entry:
        return entry["version"] == version
    return True  # package-level advisory with no version pinning → assume affected


class KbVulnMatcher:
    """Matches against `vulnerabilities.affected` in the local KB."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def match(self, *, name: str, version: str, ecosystem: str) -> list[VulnMatch]:
        name_l, eco_l = name.lower(), ecosystem.lower()
        # JSONB containment on package narrows candidates; version is checked in Python.
        stmt = select(Vulnerability).where(
            Vulnerability.affected.contains([{"package": name_l, "ecosystem": eco_l}])
        )
        out: list[VulnMatch] = []
        for vuln in self._session.execute(stmt).scalars():
            affected_here = [
                e
                for e in vuln.affected
                if e.get("package", "").lower() == name_l
                and e.get("ecosystem", "").lower() == eco_l
                and _version_affected(e, version)
            ]
            if not affected_here:
                continue
            out.append(
                VulnMatch(
                    external_id=vuln.external_id,
                    summary=vuln.summary,
                    severity=_severity_from_cvss(
                        float(vuln.cvss_base) if vuln.cvss_base is not None else None
                    ),
                    cvss_base=float(vuln.cvss_base) if vuln.cvss_base is not None else None,
                    epss_score=float(vuln.epss_score) if vuln.epss_score is not None else None,
                    kev=vuln.kev,
                    cwe_ids=list(vuln.cwe_ids or []),
                    references=list(vuln.references or []),
                )
            )
        return out
