"""Web/TLS read-only provider, end-to-end (Framework — first provider). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the full governed rail for a real tool and the Evidence-first + exact-binding contract:

  * authorized → scope → human-approval → DB-less sandbox → evidence → EXACT binding →
    Scan/ScanEngineRun(web_tls) → Finding → 6E enrich → a real internet→…→finding attack path;
  * an unauthorized target is DENIED — the provider never executes, nothing persists;
  * authorized but NO matching asset → Evidence persists, but NO Finding (Evidence-only);
  * authorized but TWO matching assets → Evidence persists, but NO Finding (ambiguous ⇒ Evidence-only).

Hermetic: the provider runs offline from a snapshot (no socket), so results are deterministic.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_EXPIRED_TLS = {"tls": {"port": 443, "tls_version": "TLSv1.2", "subject": {"commonName": "x"},
                        "issuer": {"commonName": "CA"}, "san": ["app.example.com"],
                        "not_after": "Jan  1 00:00:00 2000 GMT", "expired": True,
                        "hostname_verified": True, "resolved_ip": "203.0.113.7"}}


def _tenant():
    from guardian_db.models import Authorization, Customer, Tenant, TenantMembership, User
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"wt-{m}", slug=f"wt-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        u = User(email=f"wt-{m}@x.com", name="U", password_hash="x", status="active")
        db.add(u)
        db.flush()
        db.add(TenantMembership(user_id=u.id, tenant_id=t.id, role="pentester"))
        db.add(Authorization(
            tenant_id=t.id, customer_id=c.id, asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": "app.example.com"}],
            method="active_recon", authorized_by=u.id,
            valid_from=dt.datetime.now(dt.UTC) - dt.timedelta(hours=1),
            valid_until=dt.datetime.now(dt.UTC) + dt.timedelta(hours=1),
        ))
        return str(t.id), str(c.id), str(u.id)


def _asset(tid, cid, *, kind, identifier):
    from guardian_db.models import Asset
    from guardian_db.session import session_scope
    with session_scope() as db:
        a = Asset(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="a",
                  kind=kind, identifier=identifier, exposure="public")
        db.add(a)
        db.flush()
        return str(a.id)


def _gnode(tid, node_type, key, *, internet=False):
    from guardian_db.models import GraphNode
    from guardian_db.session import session_scope
    with session_scope() as db:
        n = GraphNode(tenant_id=uuid.UUID(tid), node_type=node_type, canonical_key=key,
                      metadata_={"internet_reachable": internet}, confidence=90,
                      ownership_confidence=90)
        db.add(n)
        db.flush()
        return str(n.id)


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


def _staff_actor(tid):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    with session_scope() as db:
        m = db.query(TenantMembership).filter(
            TenantMembership.tenant_id == uuid.UUID(tid)).first()
        return str(m.user_id)


def _dispatch(tid, targets, *, approved=True, snapshot=None):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    settings = {"snapshot": snapshot or {}}
    return dispatch_tool_job.apply(
        args=[tid, "web_tls", targets, _staff_actor(tid), approved, settings]
    ).get()


def test_full_pipeline_evidence_binding_finding_and_attack_path():
    tid, cid, _ = _tenant()
    _asset(tid, cid, kind="web", identifier="https://app.example.com")
    _gnode(tid, "subdomain", "app.example.com", internet=True)  # internet-facing topology entry

    res = _dispatch(tid, ["app.example.com"], approved=True,
                    snapshot={"app.example.com": _EXPIRED_TLS})
    assert res["status"] == "completed"
    assert res["evidence"] == 1 and res["assets_bound"] == 1 and res["findings"] == 1

    # Evidence is the primary truth — persisted, hash-chained, tenant-scoped.
    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain
    ev = _evidence_rows(tid)
    assert len(ev) == 1 and ev[0].kind == "tls"
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True

    # A Finding was DERIVED from evidence, via a reused Scan/ScanEngineRun(engine=web_tls).
    from guardian_db.models import ScanEngineRun
    findings = _findings(tid)
    assert len(findings) == 1 and findings[0].title == "TLS certificate expired"
    with session_scope() as db:
        run = db.query(ScanEngineRun).join(
            ScanEngineRun.scan).filter_by(tenant_id=uuid.UUID(tid)).one()
        assert run.engine == "web_tls"

    # 6E enrichment ran → a real internet → serves → asset → exposes → finding attack path.
    from guardian_db.graph_read import DbGraphProjector
    with session_scope() as db:
        paths = DbGraphProjector(db).attack_paths(tenant_id=tid)["paths"]
    assert paths, "expected an internet→…→finding attack path"
    kinds = [n["node_type"] for n in paths[0]]
    assert kinds[0] == "subdomain" and kinds[-1] == "finding"
    assert "asset" in kinds


def test_unauthorized_target_is_denied_and_never_executes():
    tid, _, _ = _tenant()
    res = _dispatch(tid, ["evil.example.com"], approved=True,
                    snapshot={"evil.example.com": _EXPIRED_TLS})
    assert res["status"] == "denied"          # outside authorization
    assert _evidence_rows(tid) == []           # provider never ran, nothing persisted
    assert _findings(tid) == []


def test_active_tool_requires_human_approval():
    tid, cid, _ = _tenant()
    _asset(tid, cid, kind="web", identifier="https://app.example.com")
    denied = _dispatch(tid, ["app.example.com"], approved=False,
                       snapshot={"app.example.com": _EXPIRED_TLS})
    assert denied["status"] == "denied" and denied["requires_human_approval"] is True
    assert _evidence_rows(tid) == []


def test_authorized_but_no_asset_is_evidence_only():
    tid, _, _ = _tenant()  # authorized for app.example.com but NO asset created
    res = _dispatch(tid, ["app.example.com"], approved=True,
                    snapshot={"app.example.com": _EXPIRED_TLS})
    assert res["status"] == "completed"
    assert res["evidence"] == 1 and res["assets_bound"] == 0 and res["findings"] == 0
    assert len(_evidence_rows(tid)) == 1       # evidence persists (primary truth)
    assert _findings(tid) == []                # but NO finding — nothing to bind to


def test_authorized_but_two_assets_is_evidence_only():
    tid, cid, _ = _tenant()
    # Two web/api assets share the exact host → ambiguous → Evidence-only, never a guessed binding.
    _asset(tid, cid, kind="web", identifier="https://app.example.com")
    _asset(tid, cid, kind="api", identifier="https://app.example.com")
    res = _dispatch(tid, ["app.example.com"], approved=True,
                    snapshot={"app.example.com": _EXPIRED_TLS})
    assert res["status"] == "completed"
    assert res["evidence"] == 1 and res["assets_bound"] == 0 and res["findings"] == 0
    assert len(_evidence_rows(tid)) == 1
    assert _findings(tid) == []
