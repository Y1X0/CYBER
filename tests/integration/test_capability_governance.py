"""Capability governance, end-to-end (Phase A). Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves the Control-Plane enforcement point refuses a tool execution based on WHO is asking, before
anything runs — reusing existing identity (TenantMembership.role, ApiKey.scopes, platform-owner
allowlist), with no new tables. Covers the locked matrix: platform owner, tenant confinement,
no self-escalation, ungranted capability, anonymous Celery, audit actor, service-account allowlist,
provider cannot self-authorize, no cross-tenant execution.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_DOMAIN = "app.example.com"
_CLEAN_DNS = {_DOMAIN: {"spf": "v=spf1 -all", "dmarc": "v=DMARC1; p=reject",
                        "caa": ["0 issue \"le\""], "dnssec": True, "mx": ["10 mail"]}}


def _tenant():
    from guardian_db.models import Customer, Tenant
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"gv-{m}", slug=f"gv-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        return str(t.id), str(c.id)


def _user(email_tag):
    from guardian_db.models import User
    from guardian_db.session import session_scope
    with session_scope() as db:
        u = User(email=f"{email_tag}-{uuid.uuid4().hex[:8]}@x.com", name="U",
                 password_hash="x", status="active")
        db.add(u)
        db.flush()
        return str(u.id)


def _member(tid, role):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    uid = _user(role)
    with session_scope() as db:
        db.add(TenantMembership(user_id=uuid.UUID(uid), tenant_id=uuid.UUID(tid), role=role))
    return uid


def _apikey(tid, scopes):
    from guardian_db.models import ApiKey
    from guardian_db.session import session_scope
    with session_scope() as db:
        k = ApiKey(tenant_id=uuid.UUID(tid), name="svc", key_hash=uuid.uuid4().hex, scopes=scopes)
        db.add(k)
        db.flush()
        return str(k.id)


def _authorize(tid, cid, domain=_DOMAIN):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope
    uid = _user("authz")
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": domain}], method="active_recon",
            authorized_by=uuid.UUID(uid), valid_from=now - dt.timedelta(hours=1),
            valid_until=now + dt.timedelta(hours=1)))


def _evidence(tid):
    from guardian_db.models import EvidenceItem
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()


def _run_l2(tid, actor, approved=True):
    """web_tls is L2 (ACTIVE_RECON); offline snapshot so nothing touches the network."""
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "web_tls", [_DOMAIN], actor, approved, {"snapshot": {}}]).get()


def _run_l0(tid, actor):
    """dns_posture is L0 (PASSIVE_ANALYSIS)."""
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "dns_posture", [_DOMAIN], actor, False, {"snapshot": _CLEAN_DNS}]).get()


# ── the matrix ──
def test_platform_owner_may_run_globally(monkeypatch):
    tid, cid = _tenant()
    owner = _user("plat-owner")                                 # NO tenant membership
    monkeypatch.setattr("guardian_scanner.tools.governance._platform_owner_ids",
                        lambda: {owner})
    _authorize(tid, cid)
    res = _run_l2(tid, owner, approved=True)
    assert res["status"] == "completed"                         # allowed without any membership


def test_tenant_member_cannot_act_in_another_tenant():
    a_tid, a_cid = _tenant()
    b_tid, _ = _tenant()
    owner_of_a = _member(a_tid, "owner")                        # owner of A only
    res = _run_l0(b_tid, owner_of_a)                            # tries to act in B
    assert res["status"] == "forbidden"
    assert "no valid identity in this tenant" in " ".join(res["reasons"])
    assert _evidence(b_tid) == []


def test_normal_user_cannot_escalate_to_higher_level():
    tid, cid = _tenant()
    analyst = _member(tid, "analyst")                           # L0 ceiling
    _authorize(tid, cid)
    res = _run_l2(tid, analyst)                                 # L2 tool
    assert res["status"] == "forbidden" and res["level"] == 2
    assert "capped at level 0" in " ".join(res["reasons"])
    assert _evidence(tid) == []


def test_reviewer_may_not_execute_tools():
    tid, cid = _tenant()
    reviewer = _member(tid, "reviewer")                         # no-execute role
    _authorize(tid, cid)
    res = _run_l0(tid, reviewer)
    assert res["status"] == "forbidden"
    assert "may not execute" in " ".join(res["reasons"])


def test_celery_cannot_run_without_identity():
    tid, cid = _tenant()
    _authorize(tid, cid)
    from guardian_scanner.tools.tasks import dispatch_tool_job
    res = dispatch_tool_job.apply(
        args=[tid, "dns_posture", [_DOMAIN], None, False, {"snapshot": _CLEAN_DNS}]).get()
    assert res["status"] == "forbidden"
    assert "missing actor identity" in " ".join(res["reasons"])
    assert _evidence(tid) == []


def test_actor_id_recorded_in_audit():
    tid, cid = _tenant()
    pentester = _member(tid, "pentester")
    _authorize(tid, cid)
    _run_l0(tid, pentester)
    from guardian_db.models import AuditLog
    from guardian_db.session import session_scope
    with session_scope() as db:
        rows = db.query(AuditLog).filter(
            AuditLog.tenant_id == uuid.UUID(tid),
            AuditLog.action == "tool.capability.decision").all()
    assert rows and str(rows[0].actor_id) == pentester          # who ran it is on the record


def test_service_account_cannot_exceed_scope_allowlist():
    tid, cid = _tenant()
    _authorize(tid, cid)
    key_l0 = _apikey(tid, ["cap:0"])                            # passive-only service account
    assert _run_l0(tid, key_l0)["status"] == "completed"        # L0 allowed
    over = _run_l2(tid, key_l0)                                 # L2 beyond its scope
    assert over["status"] == "forbidden" and "capped at level 0" in " ".join(over["reasons"])


def test_provider_cannot_self_authorize():
    from guardian_scanner.tools.providers.web_tls_provider import WebTlsProvider
    # The contract has no authorize(); authorization/capability is decided in the Control Plane.
    assert not hasattr(WebTlsProvider(), "authorize")
    tid, cid = _tenant()
    analyst = _member(tid, "analyst")
    _authorize(tid, cid)
    assert _run_l2(tid, analyst)["status"] == "forbidden"       # denied before the provider runs
    assert _evidence(tid) == []


def test_no_cross_tenant_execution_for_staff():
    a_tid, a_cid = _tenant()
    b_tid, b_cid = _tenant()
    pentester_a = _member(a_tid, "pentester")
    _authorize(b_tid, b_cid)
    res = _run_l0(b_tid, pentester_a)                           # A's staff acting in B
    assert res["status"] == "forbidden"
    assert _evidence(b_tid) == []
