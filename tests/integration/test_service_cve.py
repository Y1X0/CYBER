"""Discovered service version → advisory → finding (WP-C3).

This is the product loop for an asset that has no repository: a port answers, WP-B2 identifies
`OpenSSH 8.9p1` from the banner and records a CPE, WP-C1 has ingested the applicability NVD
publishes, and this produces a finding a customer can act on — with the whole chain of reasoning
attached, because a version-inference finding is exactly the kind that gets disputed.

The claims worth testing are the negative ones. A banner names a version; it does not prove one. So
the engine must not fire when the product is unknown, must not fire when the release is unknown, and
must not silently drop a match it cannot attach to an asset.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


@pytest.fixture
def marker():
    return uuid.uuid4().hex[:8]


def _product(marker: str) -> str:
    """A product name unique to one test.

    The knowledge base is global reference data — an advisory is not any tenant's secret — so an
    advisory ingested by one test is visible to every other. That is correct behaviour and makes
    the *tests* interfere unless each one owns its product name.
    """
    return f"openssh-{marker}"


def cpe_for(marker: str, version: str = "8.9p1") -> str:
    return f"cpe:2.3:a:openbsd:{_product(marker)}:{version}:*:*:*:*:*:*:*"


def _advisory(marker, *, cve=None, start="5.5", end="9.3.2", vendor="openbsd", product=None):
    """An ingested advisory with NVD-style CPE applicability."""
    from guardian_clients.feeds import NormalizedVuln
    from guardian_scanner import intel

    product = product or _product(marker)
    cve = cve or f"CVE-2099-{marker[:6]}"
    record = NormalizedVuln(external_id=cve, source="nvd",
                            summary="ssh-agent PKCS#11 remote code execution")
    record.cvss_base = 9.8
    record.severity = "critical"
    record.cwe_ids = ["CWE-428"]
    record.cpe_configurations = [{
        "cpe": f"cpe:2.3:a:{vendor}:{product}:*:*:*:*:*:*:*:*",
        "vendor": vendor, "product": product, "version": "*",
        "version_start_including": start, "version_end_excluding": end,
    }]
    intel.run_source(f"nvd-{marker}", lambda _s, _u: [record])
    return cve


def _tenant_with_service(marker, *, cpe=..., host=None, attach_asset=True):
    """A tenant with an asset and a discovered SERVICE graph node."""
    if cpe is ...:
        cpe = cpe_for(marker)
    from guardian_core.enums import NodeType
    from guardian_db.models import Asset, Customer, GraphNode, Tenant
    from guardian_db.session import session_scope

    host = host or f"host-{marker}.example.com"
    slug = f"c3-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="high")
        db.add(customer)
        db.flush()

        asset_id = None
        if attach_asset:
            asset = Asset(tenant_id=tenant.id, customer_id=customer.id, name=host,
                          kind="web", identifier=host, exposure="public", config={})
            db.add(asset)
            db.flush()
            asset_id = asset.id

        metadata = {"port": 22, "service": "ssh", "evidence": "banner",
                    "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.4",
                    "product": _product(marker), "version": "8.9p1"}
        if cpe:
            metadata["cpe"] = cpe
        node = GraphNode(
            tenant_id=tenant.id, customer_id=customer.id, node_type=NodeType.SERVICE.value,
            canonical_key=f"{host}:22", asset_id=asset_id, metadata_=metadata,
            confidence=95, ownership_confidence=90, exposure_score=0, state="active",
            first_seen_at=dt.datetime.now(dt.UTC), last_seen_at=dt.datetime.now(dt.UTC),
        )
        db.add(node)
        db.flush()
        return str(tenant.id), str(customer.id), host


def _findings(tenant_id):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope

    with session_scope() as db:
        return db.query(Finding).filter(Finding.tenant_id == uuid.UUID(tenant_id)).all()


# ── the loop ──────────────────────────────────────────────────────────────────────────────────────
def test_a_discovered_version_produces_a_finding_with_its_reasoning(marker):
    from guardian_scanner.service_cve import match_service_versions

    cve = _advisory(marker)
    tenant_id, _customer_id, host = _tenant_with_service(marker)

    stats = match_service_versions(tenant_id)
    assert stats["identified"] == 1
    assert stats["matched"] == 1
    assert stats["created"] == 1

    findings = _findings(tenant_id)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.cve_ids == [cve]
    assert finding.severity == "critical"
    assert finding.category == "vuln-service"
    assert finding.location["service"] == f"{host}:22"
    assert finding.location["version"] == "8.9p1"

    # The chain of reasoning: which banner, which fingerprint, which advisory.
    detail = finding.evidence["detail"]
    assert detail["product"] == _product(marker)
    assert detail["version"] == "8.9p1"
    assert detail["identified_from"] == "banner"
    assert "OpenSSH_8.9p1" in detail["banner"]
    assert detail["advisory"] == cve
    assert "backported fix" in finding.description


def test_a_finding_belongs_to_a_scan_that_completed(marker):
    """A finding with no scan cannot exist in this schema, and recording the match as a scan is
    what puts it in the asset's history rather than appearing from nowhere."""
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker)
    match_service_versions(tenant_id)

    with session_scope() as db:
        scans = db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tenant_id)).all()
    assert len(scans) == 1
    assert scans[0].status == "completed"
    assert scans[0].finished_at is not None
    assert scans[0].requested_engines == ["service_cve"]
    assert scans[0].trigger == "discovery"


def test_a_patched_version_produces_nothing(marker):
    """The bound is `< 9.3.2`. A host on 9.4 is not affected and must not be told it is."""
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker, cpe=cpe_for(marker, "9.4p1"))
    stats = match_service_versions(tenant_id)
    assert stats["identified"] == 1
    assert stats["matched"] == 0
    assert _findings(tenant_id) == []


def test_a_version_below_the_lower_bound_produces_nothing(marker):
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker, start="5.5")
    tenant_id, _customer_id, _host = _tenant_with_service(marker, cpe=cpe_for(marker, "4.3"))
    assert match_service_versions(tenant_id)["matched"] == 0


def test_a_different_product_is_not_matched(marker):
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker, vendor="nginx", product=f"nginx-{marker}")
    tenant_id, _customer_id, _host = _tenant_with_service(marker)   # the OpenSSH product
    assert match_service_versions(tenant_id)["matched"] == 0


# ── what must stay quiet ──────────────────────────────────────────────────────────────────────────
def test_a_service_with_no_cpe_is_not_matched(marker):
    """A port number is not a product."""
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker, cpe=None)
    stats = match_service_versions(tenant_id)
    assert stats["services"] == 1
    assert stats["identified"] == 0
    assert _findings(tenant_id) == []


def test_a_product_without_a_version_is_counted_not_matched(marker):
    """Matching every OpenSSH CVE against a host whose release is unknown is not a finding, it is
    a denial of service against whoever reads the report. The gap is counted so it is visible."""
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker, cpe=cpe_for(marker, "*"))
    stats = match_service_versions(tenant_id)
    assert stats["identified"] == 1
    assert stats["unversioned"] == 1
    assert stats["matched"] == 0
    assert _findings(tenant_id) == []


def test_a_match_that_cannot_be_attached_is_reported_not_dropped(marker, caplog):
    """A service the graph knows about but no asset owns is a gap in onboarding, not an absence
    of risk, and it must not vanish silently."""
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker, attach_asset=False)
    stats = match_service_versions(tenant_id)
    assert stats["matched"] == 1
    assert stats["created"] == 0
    assert _findings(tenant_id) == []


# ── idempotence ───────────────────────────────────────────────────────────────────────────────────
def test_re_running_updates_rather_than_duplicating(marker):
    """A weekly scan of an unpatched host must not grow a pile of the same finding."""
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker)

    first = match_service_versions(tenant_id)
    second = match_service_versions(tenant_id)

    assert first["created"] == 1
    assert second["created"] == 0
    assert second["updated"] == 1
    assert len(_findings(tenant_id)) == 1


def test_a_rerun_refreshes_the_exploit_signals(marker):
    """EPSS and KEV move; refreshing them is most of the point of scanning again."""
    from guardian_db.session import session_scope
    from guardian_scanner import intel
    from guardian_scanner.service_cve import match_service_versions

    cve = _advisory(marker)
    tenant_id, _customer_id, _host = _tenant_with_service(marker)
    match_service_versions(tenant_id)
    assert _findings(tenant_id)[0].kev is False

    from guardian_clients.feeds import KevRecord

    with session_scope() as db:
        intel.apply_kev(db, [KevRecord(cve_id=cve, ransomware=True)])
        intel.apply_epss(db, {cve: 0.87})

    match_service_versions(tenant_id)
    finding = _findings(tenant_id)[0]
    assert finding.kev is True
    assert float(finding.epss_score) == pytest.approx(0.87)


def test_findings_from_two_advisories_on_one_service_are_separate(marker):
    from guardian_scanner.service_cve import match_service_versions

    first = _advisory(marker, cve=f"CVE-2099-{marker[:5]}A")
    second = _advisory(marker, cve=f"CVE-2099-{marker[:5]}B")
    tenant_id, _customer_id, _host = _tenant_with_service(marker)

    match_service_versions(tenant_id)
    findings = _findings(tenant_id)
    assert len(findings) == 2
    assert {f.cve_ids[0] for f in findings} == {first, second}
    assert len({f.fingerprint for f in findings}) == 2


def test_another_tenants_service_is_untouched(marker):
    from guardian_scanner.service_cve import match_service_versions

    _advisory(marker)
    mine, _c, _h = _tenant_with_service(marker)
    # Same product, different tenant: the advisory applies to both, so only scoping keeps them apart.
    theirs, _c2, _h2 = _tenant_with_service(marker, host=f"other-{marker}.example.com")

    match_service_versions(mine)
    assert len(_findings(mine)) == 1
    assert _findings(theirs) == []
