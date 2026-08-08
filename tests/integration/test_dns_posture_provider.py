"""DNS/email-security posture provider, end-to-end (Framework — Provider #3). GUARDIAN_RUN_DB_TESTS=1.

Proves the posture branch on the governed rail and the locked semantic contract (ADR-0019):

  * authorized domain → offline snapshot → DB-less sandbox (no network) → Evidence-first hash chain →
    findings bound to the web/api asset by exact canonical host → 6E enrich (asset→finding);
  * authorization is REQUIRED — an unauthorized domain is denied, nothing executes;
  * a clean domain yields evidence but NO finding AND NO Scan (evidence-only, strict contract);
  * a malformed snapshot fails closed (evidence, no finding);
  * zero / multiple matching assets ⇒ Evidence-only; the provider never creates an asset;
  * evidence is tenant-isolated and the hash chain verifies.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_WEAK = {"spf": "v=spf1 +all", "dmarc": "v=DMARC1; p=none", "caa": [], "dnssec": False,
         "mx": ["10 mail.app.example.com"]}
_CLEAN = {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject", "caa": ["0 issue \"le\""],
          "dnssec": True, "mx": ["10 mail.app.example.com"]}


def _tenant():
    from guardian_db.models import Authorization, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        t = Tenant(name=f"dp-{m}", slug=f"dp-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"dp-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role="pentester"))
        db.add(Authorization(
            tenant_id=t.id, customer_id=c.id, asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": "app.example.com"}],
            method="active_recon", authorized_by=u.id,
            valid_from=now - dt.timedelta(hours=1), valid_until=now + dt.timedelta(hours=1),
        ))
        return str(t.id), str(c.id)


def _asset(tid, cid, *, kind="web", identifier="https://app.example.com"):
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        a = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="a",
                  kind=kind, identifier=identifier, exposure="public")
        db.add(a)
        db.flush()
        return str(a.id)


def _evidence_rows(tid):
    from guardian_db.models import EvidenceItem
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()


def _findings(tid):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(Finding).filter(Finding.tenant_id == uuid.UUID(tid)).all()


def _scans(tid):
    from guardian_db.models import Scan
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(Scan).filter(Scan.tenant_id == uuid.UUID(tid)).all()


def _staff_actor(tid):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    with session_scope() as db:
        m = db.query(TenantMembership).filter(
            TenantMembership.tenant_id == uuid.UUID(tid)).first()
        return str(m.user_id)


def _dispatch(tid, domain, snapshot):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "dns_posture", [domain], _staff_actor(tid), False, {"snapshot": snapshot}]
    ).get()


def test_full_pipeline_evidence_findings_and_graph():
    tid, cid = _tenant()
    _asset(tid, cid)
    res = _dispatch(tid, "app.example.com", {"app.example.com": _WEAK})
    assert res["status"] == "completed"
    # weak domain: SPF +all, DMARC p=none, CAA missing, DNSSEC missing = 4 findings.
    assert res["findings"] == 4 and res["assets_bound"] == 1

    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain
    ev = _evidence_rows(tid)
    assert any(e.kind == "dns_records" for e in ev)              # chain-of-custody evidence present
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True

    from guardian_db.models import ScanEngineRun
    titles = {f.title for f in _findings(tid)}
    assert "SPF policy is permissive (+all)" in titles
    assert "DMARC policy is monitor-only (p=none)" in titles
    with session_scope() as db:
        run = db.query(ScanEngineRun).join(ScanEngineRun.scan).filter_by(
            tenant_id=uuid.UUID(tid)).one()
        assert run.engine == "dns_posture"

    from guardian_db.models import GraphEdge
    with session_scope() as db:
        exposes = db.query(GraphEdge).filter(GraphEdge.tenant_id == uuid.UUID(tid),
                                             GraphEdge.relation == "exposes").all()
    assert len(exposes) == 4 and all(e.src_type == "asset" and e.dst_type == "finding"
                                     for e in exposes)


def test_authorization_is_required():
    tid, cid = _tenant()
    _asset(tid, cid, identifier="https://evil.example.com")
    res = _dispatch(tid, "evil.example.com", {"evil.example.com": _WEAK})  # not authorized
    assert res["status"] == "denied"
    assert _evidence_rows(tid) == [] and _findings(tid) == []


def test_clean_domain_is_evidence_only_no_finding_no_scan():
    tid, cid = _tenant()
    _asset(tid, cid)
    res = _dispatch(tid, "app.example.com", {"app.example.com": _CLEAN})
    assert res["status"] == "completed" and res["findings"] == 0
    assert len(_evidence_rows(tid)) == 1                          # evidence persists (primary truth)
    assert _findings(tid) == []
    assert _scans(tid) == []                                      # strict contract: no empty Scan


def test_malformed_snapshot_is_evidence_only_fail_closed():
    tid, cid = _tenant()
    _asset(tid, cid)
    res = _dispatch(tid, "app.example.com", {"app.example.com": "garbage"})
    assert res["status"] == "completed" and res["findings"] == 0
    rows = _evidence_rows(tid)
    assert len(rows) == 1 and rows[0].detail["data"]["status"] == "failed"
    assert _findings(tid) == [] and _scans(tid) == []


def test_no_matching_asset_is_evidence_only():
    tid, _ = _tenant()                                            # authorized, but NO asset created
    res = _dispatch(tid, "app.example.com", {"app.example.com": _WEAK})
    assert res["status"] == "completed" and res["findings"] == 0
    assert len(_evidence_rows(tid)) >= 1                          # evidence persists
    assert _findings(tid) == [] and _scans(tid) == []


def test_two_matching_assets_is_evidence_only():
    tid, cid = _tenant()
    _asset(tid, cid, kind="web", identifier="https://app.example.com")
    _asset(tid, cid, kind="api", identifier="https://app.example.com")  # same host, ambiguous
    res = _dispatch(tid, "app.example.com", {"app.example.com": _WEAK})
    assert res["status"] == "completed" and res["findings"] == 0
    assert _findings(tid) == [] and _scans(tid) == []


def test_evidence_is_tenant_isolated():
    from guardian_db.session import get_app_session, set_tenant
    from sqlalchemy import text
    a_tid, a_cid = _tenant()
    _asset(a_tid, a_cid)
    b_tid, b_cid = _tenant()
    _asset(b_tid, b_cid)
    _dispatch(a_tid, "app.example.com", {"app.example.com": _WEAK})
    _dispatch(b_tid, "app.example.com", {"app.example.com": _WEAK})

    s = get_app_session()
    try:
        row = s.execute(
            text("SELECT rolbypassrls, rolsuper FROM pg_roles WHERE rolname = current_user")
        ).one()
        if row.rolbypassrls or row.rolsuper:
            pytest.skip("app session is not RLS-enforced")
        set_tenant(s, a_tid)
        seen = s.execute(
            text("SELECT DISTINCT tenant_id::text FROM evidence_items")).scalars().all()
        assert seen == [a_tid]
    finally:
        s.close()
