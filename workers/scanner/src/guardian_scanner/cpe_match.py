"""Match a running service version to the advisories that apply to it (WP-C3).

WP-B2 and WP-B3 turn an open port into `OpenSSH 8.9p1` or `nginx 1.24.0` and a CPE string. WP-C1
ingests NVD's CPE applicability — the statement of which product versions each CVE covers. This
module is the join, and it is the only path by which a host that has no lockfile gets a
vulnerability finding at all.

The discipline here is the same one that governs the rest of the platform, and it matters more here
than anywhere else because the input is a guess made from a banner:

**No product, no match.** A service identified only by its port number has no CPE, and matching on
the port alone would attribute someone else's CVEs to whatever is actually listening.

**No version, no version-specific match.** A product known without a release matches only advisories
whose applicability has no lower or upper bound — which is almost none. Reporting every OpenSSH CVE
ever published against a host whose version is unknown is not a finding, it is a denial of service
against the person reading the report.

**A bound is evaluated, never assumed.** `versionEndExcluding: 9.3.2` means exactly that, and
`8.9p1 < 9.3.2` has to be decided by a version comparator rather than by string order, which puts
`8.9p1` after `9.3.2`.
"""

from __future__ import annotations

from dataclasses import dataclass

from guardian_common.logging import get_logger
from guardian_core.cvss import base_score
from guardian_core.enums import Severity
from guardian_core.versioning import Ecosystem, compare
from guardian_db.models import Vulnerability
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_scanner.engines.base import VulnMatch

log = get_logger("guardian.cpe_match")

MAX_CANDIDATES = 500


@dataclass(frozen=True)
class ServiceIdentity:
    """What a fingerprint concluded about one service."""

    vendor: str
    product: str
    version: str = ""

    @property
    def identified(self) -> bool:
        return bool(self.vendor and self.product)


def parse_cpe(cpe: str) -> ServiceIdentity | None:
    """(vendor, product, version) from a CPE 2.3 string, or None if it is not one."""
    parts = (cpe or "").split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    version = parts[5]
    return ServiceIdentity(
        vendor=parts[3].lower(),
        product=parts[4].lower(),
        version="" if version in {"*", "-", ""} else version,
    )


def applies(row: dict, version: str) -> bool:
    """Whether one CPE applicability row covers `version`.

    An unbounded row — no start, no end, and a wildcard version — covers every release of the
    product. That is a real thing NVD publishes, and it is also what an over-eager match looks
    like, so the caller decides whether to accept one when the running version is unknown.
    """
    exact = str(row.get("version") or "")
    if exact and exact not in {"*", "-"}:
        return bool(version) and compare(version, exact, Ecosystem.GENERIC) == 0

    if not version:
        return False       # bounds cannot be evaluated without a version

    start_including = row.get("version_start_including")
    start_excluding = row.get("version_start_excluding")
    end_including = row.get("version_end_including")
    end_excluding = row.get("version_end_excluding")

    if start_including and compare(version, str(start_including), Ecosystem.GENERIC) < 0:
        return False
    if start_excluding and compare(version, str(start_excluding), Ecosystem.GENERIC) <= 0:
        return False
    if end_including and compare(version, str(end_including), Ecosystem.GENERIC) > 0:
        return False
    if end_excluding and compare(version, str(end_excluding), Ecosystem.GENERIC) >= 0:
        return False

    return any((start_including, start_excluding, end_including, end_excluding))


def unbounded(row: dict) -> bool:
    """A row that names a product with no version constraint at all."""
    exact = str(row.get("version") or "")
    if exact and exact not in {"*", "-"}:
        return False
    return not any((
        row.get("version_start_including"), row.get("version_start_excluding"),
        row.get("version_end_including"), row.get("version_end_excluding"),
    ))


class CpeVulnMatcher:
    """Advisories affecting a product at a version, from the ingested CPE applicability."""

    def __init__(self, session: Session) -> None:
        self._session = session

    def match_identity(self, identity: ServiceIdentity) -> list[VulnMatch]:
        if not identity.identified:
            # A port number is not a product. Matching on it would attribute an advisory to
            # whatever happens to be listening.
            return []

        candidates = self._session.execute(
            select(Vulnerability)
            .where(Vulnerability.cpe_configurations.contains(
                [{"vendor": identity.vendor, "product": identity.product}]
            ))
            .limit(MAX_CANDIDATES)
        ).scalars().all()

        matches: list[VulnMatch] = []
        for vulnerability in candidates:
            rows = [
                row for row in (vulnerability.cpe_configurations or [])
                if isinstance(row, dict)
                and str(row.get("vendor", "")).lower() == identity.vendor
                and str(row.get("product", "")).lower() == identity.product
            ]
            if not any(applies(row, identity.version) for row in rows):
                continue
            matches.append(self._to_match(vulnerability))
        return sorted(matches, key=lambda m: (-(m.cvss_base or 0.0), m.external_id))

    def match_cpe(self, cpe: str) -> list[VulnMatch]:
        identity = parse_cpe(cpe)
        return self.match_identity(identity) if identity else []

    def match(self, *, name: str, version: str, ecosystem: str) -> list[VulnMatch]:
        """`VulnMatcher`-shaped entry point, so this can be injected wherever the protocol is used.

        `ecosystem` carries the CPE vendor here — a service has no package ecosystem, and inventing
        one would make the argument meaningless in a different way.
        """
        return self.match_identity(
            ServiceIdentity(vendor=ecosystem.lower(), product=name.lower(), version=version)
        )

    def _to_match(self, vulnerability: Vulnerability) -> VulnMatch:
        cvss = (
            float(vulnerability.cvss_base) if vulnerability.cvss_base is not None
            else base_score(vulnerability.cvss_vector or "")
        )
        return VulnMatch(
            external_id=vulnerability.external_id,
            summary=vulnerability.summary or vulnerability.details[:300],
            severity=_severity(cvss, vulnerability.severity),
            cvss_base=cvss,
            epss_score=(
                float(vulnerability.epss_score) if vulnerability.epss_score is not None else None
            ),
            kev=bool(vulnerability.kev),
            cwe_ids=list(vulnerability.cwe_ids or []),
            references=list(vulnerability.references or []),
        )


def _severity(cvss: float | None, published: str | None) -> Severity:
    """The feed's own severity word when it published one, otherwise derived from the score.

    Preferring the published word matters because NVD's banding and a naive cutoff disagree at the
    edges, and a customer comparing Guardian's output to the NVD page should not find them
    contradicting each other over the same CVE.
    """
    if published:
        try:
            return Severity(published.lower())
        except ValueError:
            pass
    if cvss is None:
        return Severity.MEDIUM
    if cvss >= 9.0:
        return Severity.CRITICAL
    if cvss >= 7.0:
        return Severity.HIGH
    if cvss >= 4.0:
        return Severity.MEDIUM
    return Severity.LOW
