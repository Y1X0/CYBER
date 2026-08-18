"""Turn discovered service versions into vulnerability findings (WP-C3).

This closes the loop the discovery packages opened. WP-B2/B3 record what is running on an exposed
port — `OpenSSH 8.9p1`, `nginx 1.24.0` — as a CPE on a SERVICE graph node. WP-C1 ingests NVD's
statement of which product versions each CVE covers. This task joins them and writes findings, which
is the only way a host with no repository and no lockfile produces one.

The evidence attached to each finding is the whole chain: which port, what the service said about
itself, which fingerprint concluded the product and version, and which applicability row in the
advisory matched. A version-inference finding is exactly the kind a customer will dispute — "we
patched that" — and the answer has to be in the finding rather than in someone's memory of how the
scanner works.

Findings are per (service, CVE) and idempotent: a re-run updates rather than duplicating, because a
weekly scan of an unpatched host must not produce a growing pile of the same finding.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, NodeType, Severity
from guardian_core.evidence import Evidence, EvidenceKind
from guardian_core.findings import RawFinding
from guardian_db.models import Asset, Finding, GraphNode, Scan, ScanEngineRun
from guardian_db.session import session_scope
from sqlalchemy import select

from guardian_scanner.celery_app import celery_app
from guardian_scanner.cpe_match import CpeVulnMatcher, ServiceIdentity, parse_cpe
from guardian_scanner.normalize import to_finding

log = get_logger("guardian.service_cve")

MAX_SERVICES = 2_000
MAX_FINDINGS_PER_SERVICE = 50


def identity_for(node: GraphNode) -> ServiceIdentity | None:
    """What a SERVICE node claims to be running, or None when it never established a product.

    Only the CPE is read. The `product`/`version` attributes are the fingerprint's own words and are
    kept for display; the CPE exists precisely because it is the normalized identity a feed is
    indexed by, and re-deriving one here would let the two disagree.
    """
    attributes = node.metadata_ if isinstance(node.metadata_, dict) else {}
    cpe = attributes.get("cpe")
    if isinstance(cpe, str) and cpe:
        return parse_cpe(cpe)
    return None


def _raw_finding(
    node_key: str, identity: ServiceIdentity, match, attributes: dict
) -> RawFinding:
    port = attributes.get("port")
    service = attributes.get("service") or identity.product
    banner = str(attributes.get("banner") or "")[:200]
    evidence_source = attributes.get("evidence") or "banner"

    description = (
        f"{identity.product} {identity.version} is running on {node_key} and is affected by "
        f"{match.external_id}. "
        f"{match.summary or ''}"
    ).strip()
    description += (
        "\n\nHow this was determined: the service was identified as "
        f"{identity.product} {identity.version} from its {evidence_source}, and the advisory's "
        "applicability lists that product at that version. Confirm the running build before "
        "treating it as patched — a backported fix can leave the reported version unchanged."
    )

    evidence = Evidence(
        kind=EvidenceKind.CONFIG,
        summary=f"{node_key} — {identity.product} {identity.version}",
        location={"service": node_key, "port": port, "protocol": service},
        detail={
            "product": identity.product,
            "vendor": identity.vendor,
            "version": identity.version,
            "cpe": attributes.get("cpe"),
            "identified_from": evidence_source,
            "banner": banner,
            "advisory": match.external_id,
        },
    ).to_dict()

    return RawFinding(
        engine=EngineKey.SCA,
        title=f"{identity.product} {identity.version} — {match.external_id}",
        category="vuln-service",
        description=description,
        base_severity=match.severity or Severity.MEDIUM,
        # The advisory is certain; the *version inference* is not, and a banner can be edited or
        # a fix backported. Saying "high" here would overstate what a banner can prove.
        confidence="medium" if evidence_source == "banner" else "low",
        cwe_id=match.cwe_ids[0] if match.cwe_ids else None,
        cve_ids=[match.external_id] if match.external_id.startswith("CVE-") else [],
        cvss_base=match.cvss_base,
        epss_score=match.epss_score,
        kev=match.kev,
        location={"service": node_key, "port": port, "product": identity.product,
                  "version": identity.version, "rule": f"service-cve-{match.external_id}"},
        evidence=evidence,
        references={"advisory": match.external_id, "refs": list(match.references or [])},
    )


@celery_app.task(name="guardian.match_service_versions")
def match_service_versions(tenant_id: str, customer_id: str | None = None) -> dict:
    """Match every discovered service with a known product+version against the knowledge base."""
    tenant = uuid.UUID(tenant_id)
    stats = {"services": 0, "identified": 0, "unversioned": 0, "matched": 0,
             "created": 0, "updated": 0}

    with session_scope() as session:
        query = select(GraphNode).where(
            GraphNode.tenant_id == tenant,
            GraphNode.node_type == NodeType.SERVICE.value,
        ).limit(MAX_SERVICES)
        if customer_id:
            query = query.where(GraphNode.customer_id == uuid.UUID(customer_id))

        matcher = CpeVulnMatcher(session)
        scans: dict[uuid.UUID, tuple[Scan, ScanEngineRun]] = {}
        for node in session.execute(query).scalars():
            stats["services"] += 1
            attributes = dict(node.metadata_ or {})
            identity = identity_for(node)
            if identity is None or not identity.identified:
                continue
            stats["identified"] += 1
            if not identity.version:
                # A product without a release matches only unbounded advisories, which would mean
                # reporting every CVE the product ever had. Counted so the gap is visible.
                stats["unversioned"] += 1
                continue

            matches = matcher.match_identity(identity)[:MAX_FINDINGS_PER_SERVICE]
            if not matches:
                continue
            stats["matched"] += len(matches)

            asset = _asset_for(session, node)
            if asset is None:
                # Nothing to attach a finding to. Recorded rather than dropped: a service the graph
                # knows about but no asset owns is a gap in onboarding, not an absence of risk.
                log.warning("service_cve_unattached", service=node.canonical_key,
                            matches=len(matches))
                continue

            scan, engine_run = _scan_for(session, scans, tenant, asset)
            for match in matches:
                created = _persist(session, tenant, asset, scan, engine_run, node, identity,
                                   match, attributes)
                stats["created" if created else "updated"] += 1

        _finish(scans)

    log.info("service_cve_complete", tenant=tenant_id, **stats)
    return stats


def _scan_for(  # noqa: ANN001
    session, cache: dict, tenant: uuid.UUID, asset: Asset
) -> tuple[Scan, ScanEngineRun]:
    """The scan these findings belong to.

    A finding without a scan cannot exist in this schema, and that is the right constraint rather
    than something to work around: matching a discovered version against the knowledge base *is* a
    scan of that asset, and recording it as one means the result shows up in scan history, carries
    a timestamp, and can be compared with the run before it.
    """
    if asset.id in cache:
        return cache[asset.id]

    now = dt.datetime.now(dt.UTC)
    scan = Scan(
        tenant_id=tenant, customer_id=asset.customer_id, asset_id=asset.id,
        trigger="discovery", status="running", requested_engines=["service_cve"],
        stats={}, started_at=now,
    )
    session.add(scan)
    session.flush()
    engine_run = ScanEngineRun(scan_id=scan.id, engine="service_cve", status="running")
    session.add(engine_run)
    session.flush()
    cache[asset.id] = (scan, engine_run)
    return scan, engine_run


def _finish(cache: dict) -> None:
    """Close every scan this run opened, so none is left reporting `running` forever."""
    now = dt.datetime.now(dt.UTC)
    for scan, engine_run in cache.values():
        scan.status = "completed"
        scan.finished_at = now
        engine_run.status = "completed"


def _asset_for(session, node: GraphNode) -> Asset | None:  # noqa: ANN001
    """The asset a service finding belongs to.

    A SERVICE node is `host:port`; the asset is whatever the tenant registered for that host. No
    fuzzy matching — an exact identifier or nothing, because attaching a finding to the wrong asset
    puts it in the wrong customer's report.
    """
    if node.asset_id is not None:
        return session.get(Asset, node.asset_id)
    host = (node.canonical_key or "").rsplit(":", 1)[0]
    if not host:
        return None
    return session.execute(
        select(Asset).where(
            Asset.tenant_id == node.tenant_id,
            Asset.identifier.in_([host, f"https://{host}", f"http://{host}"]),
        ).limit(1)
    ).scalars().first()


def _persist(  # noqa: PLR0913
    session, tenant: uuid.UUID, asset: Asset, scan: Scan,  # noqa: ANN001
    engine_run: ScanEngineRun, node: GraphNode, identity: ServiceIdentity, match,
    attributes: dict,
) -> bool:
    """Create or refresh one finding. Returns True when it was created."""
    raw = _raw_finding(node.canonical_key, identity, match, attributes)
    fingerprint = raw.fingerprint()

    existing = session.execute(
        select(Finding).where(
            Finding.tenant_id == tenant,
            Finding.asset_id == asset.id,
            Finding.fingerprint == fingerprint,
        )
    ).scalars().first()

    if existing is not None:
        # A weekly scan of an unpatched host must not grow a pile of the same finding. The score
        # is refreshed because EPSS and KEV move, which is the whole point of re-running.
        existing.cvss_base = raw.cvss_base
        existing.epss_score = raw.epss_score
        existing.kev = raw.kev
        existing.evidence = raw.evidence
        existing.scan_id = scan.id
        existing.engine_run_id = engine_run.id
        return False

    finding = to_finding(
        raw,
        tenant_id=tenant,
        customer_id=asset.customer_id,
        scan_id=scan.id,
        engine_run_id=engine_run.id,
        asset_id=asset.id,
        exposure=asset.exposure or "unknown",
        asset_criticality="high",
    )
    session.add(finding)
    return True
