"""Vulnerability matchers — bridge the SCA engine to a data source.

`KbVulnMatcher` matches dependencies against the local knowledge base (offline, fast, testable).
A live-feed matcher (OSV) can be swapped in without touching the engine, since both satisfy the
`VulnMatcher` protocol.
"""

from __future__ import annotations

from guardian_common.logging import get_logger
from guardian_core.cvss import base_score
from guardian_core.enums import Severity
from guardian_core.versioning import version_affected
from guardian_db.models import Vulnerability
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_scanner.engines.base import VulnMatch

log = get_logger("guardian.vuln_match")


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
    """Delegate to the ecosystem-aware evaluator.

    This used to be `version in versions` — exact string membership. Advisories publish ranges
    ("fixed in 1.4.2"), so a customer running the vulnerable 1.4.1 matched nothing and was told
    they were unaffected. Range semantics, ordering and per-ecosystem rules now live in
    `guardian_core.versioning`, where they are testable against each specification's own examples.
    """
    return version_affected(entry, version)


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


class OsvVulnMatcher:
    """Matches against OSV.dev — the corpus the local KB cannot be, aggregating GHSA, PyPA,
    RustSec, Go and OSS-Fuzz with correct affected-version ranges.

    The client for this already existed and was wired to nothing, so dependency scanning ran
    against six hand-seeded advisories. Behind the same `VulnMatcher` protocol the engine already
    consumes, so no engine changes.

    Fails soft by design: a feed outage yields no matches rather than an exception, because a scan
    that dies on a third party's downtime is worse than a scan that reports what it could see. The
    caller pairs this with the KB matcher so an outage degrades rather than blinds.
    """

    def __init__(self, client=None) -> None:  # noqa: ANN001
        self._client = client

    def _osv(self):  # noqa: ANN202
        if self._client is None:
            from guardian_clients.feeds.osv import OsvClient  # noqa: PLC0415

            self._client = OsvClient()
        return self._client

    def match(self, *, name: str, version: str, ecosystem: str) -> list[VulnMatch]:
        try:
            found = self._osv().query_package(name=name, version=version, ecosystem=ecosystem)
        except Exception as exc:  # noqa: BLE001 - a feed outage must never fail a scan
            log.warning("osv_query_failed", package=name, ecosystem=ecosystem,
                        error=type(exc).__name__)
            return []

        out: list[VulnMatch] = []
        for nv in found:
            # Feeds publish a vector, not a number. Without evaluating it every advisory lands on
            # the default band and ranks below the seeded rows it is meant to replace.
            base = nv.cvss_base if nv.cvss_base is not None else base_score(nv.cvss_vector or "")
            out.append(
                VulnMatch(
                    external_id=nv.external_id,
                    summary=nv.summary or nv.details[:300],
                    severity=_severity_from_cvss(base),
                    cvss_base=base,
                    epss_score=nv.epss_score,
                    kev=nv.kev,
                    cwe_ids=list(nv.cwe_ids or []),
                    references=list(nv.references or []),
                )
            )
        return out


class CompositeVulnMatcher:
    """Queries several sources and merges by advisory id, keeping the richest record.

    Two sources reporting the same CVE is corroboration, not duplication: the local KB may carry
    KEV and EPSS enrichment that OSV does not, while OSV has the coverage the KB never will. The
    merge keeps whichever value is present rather than letting source order decide.
    """

    def __init__(self, *matchers) -> None:  # noqa: ANN002
        self._matchers = [m for m in matchers if m is not None]

    def match(self, *, name: str, version: str, ecosystem: str) -> list[VulnMatch]:
        merged: dict[str, VulnMatch] = {}
        for matcher in self._matchers:
            for found in matcher.match(name=name, version=version, ecosystem=ecosystem):
                key = (found.external_id or "").upper()
                if not key:
                    continue
                existing = merged.get(key)
                merged[key] = found if existing is None else _merge(existing, found)
        return list(merged.values())


def _merge(a: VulnMatch, b: VulnMatch) -> VulnMatch:
    """Prefer present values over absent ones, and the more severe assessment over the milder."""
    cvss = a.cvss_base if a.cvss_base is not None else b.cvss_base
    if a.cvss_base is not None and b.cvss_base is not None:
        cvss = max(a.cvss_base, b.cvss_base)
    return VulnMatch(
        external_id=a.external_id,
        summary=a.summary or b.summary,
        severity=_severity_from_cvss(cvss) if cvss is not None else a.severity,
        cvss_base=cvss,
        epss_score=a.epss_score if a.epss_score is not None else b.epss_score,
        kev=a.kev or b.kev,
        cwe_ids=sorted(set(a.cwe_ids) | set(b.cwe_ids)),
        references=list(dict.fromkeys([*a.references, *b.references])),
    )
