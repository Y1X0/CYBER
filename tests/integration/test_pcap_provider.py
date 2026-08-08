"""Artifact/PCAP provider, end-to-end (Framework — Provider #2). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the untrusted-artifact branch of the governed rail and the asset-anchored contract:

  * asset-anchored authorization → DB-less sandboxed parse (no network) → Evidence-first hash chain
    (artifact sha256 = root) → findings bound to the anchored asset → 6E enrich (asset→finding);
  * authorization is REQUIRED — an unauthorized/unowned/missing asset is DENIED, nothing executes;
  * a 2 MB+ artifact is rejected fail-closed before execution;
  * a benign capture yields evidence but NO finding (Evidence-only);
  * the provider never creates assets for endpoints observed inside the capture;
  * evidence is tenant-isolated and the hash chain verifies.
"""

from __future__ import annotations

import base64
import datetime as dt
import os
import socket
import struct
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


# ── pcap builders (classic little-endian, LINKTYPE_ETHERNET) ──
def _eth_ipv4_tcp(src, dst, sport, dport):
    ip = bytearray(20)
    ip[0] = 0x45
    ip[9] = 6
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    return b"\x00" * 12 + b"\x08\x00" + bytes(ip) + struct.pack(">HH", sport, dport) + b"\x00" * 16


def _pcap(records):
    out = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
    for ts, pkt in records:
        out += struct.pack("<IIII", ts, 0, len(pkt), len(pkt)) + pkt
    return out


_HTTP_PCAP = _pcap([(1000, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50000, 80)),
                    (1001, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50000, 80))])
_BENIGN_PCAP = _pcap([(1000, _eth_ipv4_tcp("10.0.0.5", "10.0.0.9", 50000, 443))])


def _b64(raw):
    return base64.b64encode(raw).decode()


def _tenant():
    from guardian_db.models import Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"pc-{m}", slug=f"pc-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"pc-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role="pentester"))
        db.flush()
        return str(t.id), str(c.id), str(u.id)


def _asset(tid, cid, *, kind="web", identifier="https://cap.example.com"):
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        a = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="a",
                  kind=kind, identifier=identifier, exposure="internal")
        db.add(a)
        db.flush()
        return str(a.id)


def _authorize_asset(tid, cid, uid, aid):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=uuid.UUID(aid),
            scope="artifact", authorized_targets=[], method="written_consent",
            authorized_by=uuid.UUID(uid),
            valid_from=now - dt.timedelta(hours=1), valid_until=now + dt.timedelta(hours=1),
        ))


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


def _assets(tid):
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(Asset).filter(Asset.tenant_id == uuid.UUID(tid)).all()


def _staff_actor(tid):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    with session_scope() as db:
        m = db.query(TenantMembership).filter(
            TenantMembership.tenant_id == uuid.UUID(tid)).first()
        return str(m.user_id)


def _dispatch(tid, aid, raw):
    from guardian_scanner.tools.tasks import dispatch_artifact_job
    return dispatch_artifact_job.apply(
        args=[tid, "pcap_meta", aid, _b64(raw), _staff_actor(tid)]).get()


def test_full_pipeline_evidence_binding_finding_and_graph():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize_asset(tid, cid, uid, aid)

    res = _dispatch(tid, aid, _HTTP_PCAP)
    assert res["status"] == "completed" and res["findings"] == 1
    assert res["evidence"] >= 2                                  # artifact root + cleartext flow

    # Evidence-first: artifact sha256 is the ROOT of a verifiable hash chain.
    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain
    ev = _evidence_rows(tid)
    root = next(e for e in ev if e.kind == "artifact")
    import hashlib
    assert root.detail["data"]["sha256"] == hashlib.sha256(_HTTP_PCAP).hexdigest()
    assert root.prev_hash is None                                # genuinely first in the chain
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True

    # A Finding was DERIVED, bound to the anchored asset, via ScanEngineRun(engine=pcap_meta).
    from guardian_db.models import Finding, ScanEngineRun
    findings = _findings(tid)
    assert len(findings) == 1 and findings[0].title == "Cleartext HTTP traffic observed"
    assert findings[0].asset_id == uuid.UUID(aid)               # bound to the anchor
    with session_scope() as db:
        run = db.query(ScanEngineRun).join(ScanEngineRun.scan).filter_by(
            tenant_id=uuid.UUID(tid)).one()
        assert run.engine == "pcap_meta"
        assert db.query(Finding).filter_by(tenant_id=uuid.UUID(tid)).one().evidence[
            "artifact_sha256"] == root.detail["data"]["sha256"]  # Finding ← Evidence ← Artifact

    # 6E: asset --exposes--> finding exists in the graph.
    from guardian_db.models import GraphEdge
    with session_scope() as db:
        exposes = db.query(GraphEdge).filter(GraphEdge.tenant_id == uuid.UUID(tid),
                                             GraphEdge.relation == "exposes").all()
    assert len(exposes) == 1 and exposes[0].src_type == "asset" and exposes[0].dst_type == "finding"


def test_authorization_is_required():
    tid, cid, _ = _tenant()
    aid = _asset(tid, cid)                                       # asset exists but NO authorization
    res = _dispatch(tid, aid, _HTTP_PCAP)
    assert res["status"] == "denied"
    assert _evidence_rows(tid) == [] and _findings(tid) == []   # nothing executed


def test_unauthorized_asset_id_does_not_execute():
    tid, _, _ = _tenant()
    ghost = str(uuid.uuid4())                                    # asset that does not exist
    res = _dispatch(tid, ghost, _HTTP_PCAP)
    assert res["status"] == "denied"
    assert _evidence_rows(tid) == []


def test_asset_from_another_tenant_is_denied():
    a_tid, a_cid, a_uid = _tenant()
    b_tid, b_cid, _ = _tenant()
    a_aid = _asset(a_tid, a_cid)
    _authorize_asset(a_tid, a_cid, a_uid, a_aid)
    # tenant B tries to analyze tenant A's (authorized-for-A) asset → denied, nothing runs.
    res = _dispatch(b_tid, a_aid, _HTTP_PCAP)
    assert res["status"] == "denied"
    assert _evidence_rows(b_tid) == []


def test_oversized_artifact_rejected_before_execution():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize_asset(tid, cid, uid, aid)
    big = b"\xd4\xc3\xb2\xa1" + b"\x00" * (2 * 1024 * 1024 + 1)  # > 2 MB
    from guardian_scanner.tools.tasks import dispatch_artifact_job
    res = dispatch_artifact_job.apply(
        args=[tid, "pcap_meta", aid, _b64(big), _staff_actor(tid)]).get()
    assert res["status"] == "rejected" and res["reason"] == "artifact_exceeds_2mb"
    assert _evidence_rows(tid) == []                             # fail-closed, nothing ran


def test_benign_capture_is_evidence_only_no_finding():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize_asset(tid, cid, uid, aid)
    res = _dispatch(tid, aid, _BENIGN_PCAP)
    assert res["status"] == "completed" and res["findings"] == 0
    assert len(_evidence_rows(tid)) >= 1                         # evidence persists (primary truth)
    assert _findings(tid) == []                                  # but no finding derived


def test_observed_endpoints_do_not_become_assets():
    tid, cid, uid = _tenant()
    aid = _asset(tid, cid)
    _authorize_asset(tid, cid, uid, aid)
    before = {str(a.id) for a in _assets(tid)}
    _dispatch(tid, aid, _HTTP_PCAP)                              # capture mentions 10.0.0.5/10.0.0.9
    after = {str(a.id) for a in _assets(tid)}
    assert after == before == {aid}                             # no asset invented for endpoints


def test_evidence_is_tenant_isolated():
    from guardian_db.session import get_app_session, set_tenant
    from sqlalchemy import text
    a_tid, a_cid, a_uid = _tenant()
    a_aid = _asset(a_tid, a_cid)
    _authorize_asset(a_tid, a_cid, a_uid, a_aid)
    b_tid, b_cid, b_uid = _tenant()
    b_aid = _asset(b_tid, b_cid)
    _authorize_asset(b_tid, b_cid, b_uid, b_aid)
    _dispatch(a_tid, a_aid, _HTTP_PCAP)
    _dispatch(b_tid, b_aid, _HTTP_PCAP)

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
