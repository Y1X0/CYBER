"""Nmap provider, end-to-end (Framework — first active external-binary tool). GUARDIAN_RUN_DB_TESTS=1.

Hermetic: offline XML snapshot, no real nmap, no network. Proves the L2 governance path
(authorization + human approval), scope enforcement, evidence-first persistence, conservative
findings bound to the authorized asset (never new IP/Service nodes), and tenant isolation.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_IP = "10.0.0.5"
_XML = (
    '<?xml version="1.0"?><nmaprun>'
    f'<host><address addr="{_IP}" addrtype="ipv4"/><ports>'
    '<port protocol="tcp" portid="23"><state state="open"/><service name="telnet"/></port>'
    '<port protocol="tcp" portid="22"><state state="open"/><service name="ssh"/></port>'
    '</ports></host></nmaprun>'
)


def _tenant():
    from guardian_db.models import Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"nm-{m}", slug=f"nm-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"nm-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role="pentester"))
        return str(t.id), str(c.id), str(u.id)


def _asset(tid, cid):
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        a = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="host",
                  kind="web", identifier=f"https://{_IP}", exposure="public")
        db.add(a)
        db.flush()
        return str(a.id)


def _authorize(tid, cid, uid, *, ip=_IP, asset_id=None):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid),
            asset_id=uuid.UUID(asset_id) if asset_id else None, scope="s",
            authorized_targets=[{"type": "ip", "value": ip}], method="active_recon",
            authorized_by=uuid.UUID(uid), valid_from=now - dt.timedelta(hours=1),
            valid_until=now + dt.timedelta(hours=1)))


def _evidence(tid):
    from guardian_db.models import EvidenceItem
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()


def _findings(tid):
    from guardian_db.models import Finding
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(Finding).filter(Finding.tenant_id == uuid.UUID(tid)).all()


def _dispatch(tid, actor, targets=(_IP,), *, approved=True):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "nmap", list(targets), actor, approved, {"allow_live": False, "xml": _XML}]
    ).get()


def test_full_pipeline_authorization_approval_finding_and_graph():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize(tid, cid, uid, asset_id=aid)

    res = _dispatch(tid, uid, approved=True)
    assert res["status"] == "completed" and res["findings"] == 1   # telnet only; ssh is not

    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain
    ev = _evidence(tid)
    assert any(e.kind == "nmap_scan" for e in ev) and any(e.kind == "nmap_service" for e in ev)
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True

    from guardian_db.models import ScanEngineRun
    findings = _findings(tid)
    assert len(findings) == 1 and findings[0].title == "Sensitive service exposed: Telnet"
    assert findings[0].asset_id == uuid.UUID(aid)
    with session_scope() as db:
        run = db.query(ScanEngineRun).join(ScanEngineRun.scan).filter_by(
            tenant_id=uuid.UUID(tid)).one()
        assert run.engine == "nmap"

    from guardian_db.models import GraphEdge
    with session_scope() as db:
        exposes = db.query(GraphEdge).filter(GraphEdge.tenant_id == uuid.UUID(tid),
                                             GraphEdge.relation == "exposes").all()
    assert len(exposes) == 1 and exposes[0].dst_type == "finding"


def test_active_scan_requires_human_approval():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize(tid, cid, uid, asset_id=aid)
    res = _dispatch(tid, uid, approved=False)                      # L2 needs approval
    assert res["status"] == "denied" and res["requires_human_approval"] is True
    assert _evidence(tid) == []


def test_authorization_required_and_scope_enforced():
    tid, cid, uid = _tenant()
    _asset(tid, cid)
    _authorize(tid, cid, uid, ip=_IP, asset_id=None)              # authorized for _IP only
    res = _dispatch(tid, uid, targets=["10.0.0.99"], approved=True)  # not authorized
    assert res["status"] == "denied"
    assert _evidence(tid) == []


def test_scope_based_authz_is_evidence_only_no_finding():
    tid, cid, uid = _tenant()
    _asset(tid, cid)
    _authorize(tid, cid, uid, asset_id=None)                      # no asset binding
    res = _dispatch(tid, uid, approved=True)
    assert res["status"] == "completed" and res["findings"] == 0
    assert len(_evidence(tid)) >= 1                                # evidence persists
    assert _findings(tid) == []                                   # but no finding (unbound)


def test_no_ip_or_service_graph_nodes_created():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize(tid, cid, uid, asset_id=aid)
    _dispatch(tid, uid, approved=True)
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    with session_scope() as db:
        kinds = {n.node_type for n in db.query(GraphNode).filter(
            GraphNode.tenant_id == uuid.UUID(tid)).all()}
    assert "ip_address" not in kinds and "service" not in kinds   # nmap never invents topology


def test_analyst_cannot_run_l2_nmap():
    from guardian_db.models import TenantMembership, User
    from guardian_db.session import session_scope
    tid, cid, _ = _tenant()
    aid = _asset(tid, cid)
    with session_scope() as db:
        u = User(email=f"an-{uuid.uuid4().hex[:8]}@x.com", name="A", password_hash="x",
                 status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=uuid.UUID(tid), role="analyst"))
        analyst = str(u.id)
    _authorize(tid, cid, analyst, asset_id=aid)
    res = _dispatch(tid, analyst, approved=True)                  # analyst ceiling is L0
    assert res["status"] == "forbidden"


def test_evidence_is_tenant_isolated():
    from guardian_db.session import get_app_session, set_tenant
    from sqlalchemy import text
    a_tid, a_cid, a_uid = _tenant()
    _authorize(a_tid, a_cid, a_uid, asset_id=_asset(a_tid, a_cid))
    b_tid, b_cid, b_uid = _tenant()
    _authorize(b_tid, b_cid, b_uid, asset_id=_asset(b_tid, b_cid))
    _dispatch(a_tid, a_uid, approved=True)
    _dispatch(b_tid, b_uid, approved=True)

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
