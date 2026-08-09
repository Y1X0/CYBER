"""Phase B governance, end-to-end. Gated by GUARDIAN_RUN_DB_TESTS=1.

Proves persistent authorization: platform roles, capability grants, tool catalog enablement, the
service-account L2 ceiling, and the L3+ campaign + approval machinery (recognized-not-forbidden made
executable). Uses monkeypatched fake providers for L3+ (no real L3+ provider ships).
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest
from guardian_core.tool import RawEvidence, ToolCapabilities

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


# ── a minimal fake provider whose level we control via capabilities ──
class _FakeProvider:
    key, name, version = "fake", "fake", "1"

    def __init__(self, caps):
        self._caps = caps

    @property
    def capabilities(self):  # noqa: ANN201
        return self._caps

    def validate(self, job):  # noqa: ANN001, ANN201
        return None

    def execute(self, job):  # noqa: ANN001, ANN201
        for t in job.scope.targets:
            yield RawEvidence(tool="fake", execution_id=job.job_id, target=t, kind="fake",
                              data={"ok": True})

    def normalize(self, evidence):  # noqa: ANN001, ANN201
        return None


def _install(monkeypatch, key, caps):
    from guardian_scanner.tools import registry
    prov = _FakeProvider(caps)
    prov.key = key
    monkeypatch.setattr(registry, "tool_for", lambda k: prov if k == key else None)
    monkeypatch.setattr(registry, "capabilities_for",
                        lambda k: prov.capabilities if k == key else None)


_L4_CAPS = ToolCapabilities(category="exploit", network=True, active=True,
                            requires_authorization=True)  # ⇒ EXPLOIT_VALIDATION (L4)
_L0_CAPS = ToolCapabilities(category="x", network=False, active=False)


def _tenant():
    from guardian_db.models import Customer, Tenant
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"pb-{m}", slug=f"pb-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        return str(t.id), str(c.id)


def _user(tag="u"):
    from guardian_db.models import User
    from guardian_db.session import session_scope
    with session_scope() as db:
        u = User(email=f"{tag}-{uuid.uuid4().hex[:8]}@x.com", name="U", password_hash="x",
                 status="active")
        db.add(u)
        db.flush()
        return str(u.id)


def _member(tid, role, uid=None):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    uid = uid or _user(role)
    with session_scope() as db:
        db.add(TenantMembership(user_id=uuid.UUID(uid), tenant_id=uuid.UUID(tid), role=role))
    return uid


def _authorize(tid, cid, domain="t.example.com"):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": domain}], method="active_recon",
            authorized_by=uuid.UUID(_user("authz")), valid_from=now - dt.timedelta(hours=1),
            valid_until=now + dt.timedelta(hours=1)))


def _grant(tid, subject_kind, subject_ref, max_level, granter, *, tools=None,
           expires_at=None, revoked=False):
    from guardian_db.models import CapabilityGrant
    from guardian_db.session import session_scope
    with session_scope() as db:
        g = CapabilityGrant(
            tenant_id=uuid.UUID(tid), subject_kind=subject_kind, subject_ref=subject_ref,
            max_level=max_level, tool_allowlist=tools, granted_by=uuid.UUID(granter),
            expires_at=expires_at, revoked_at=dt.datetime.now(dt.UTC) if revoked else None)
        db.add(g)


def _campaign(tid, cid, creator, *, status="active", max_level=4,
              starts=None, ends=None, operators=()):
    from guardian_db.models import Campaign, CampaignMember
    from guardian_db.session import session_scope
    with session_scope() as db:
        camp = Campaign(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="c",
                        status=status, max_capability_level=max_level, starts_at=starts, ends_at=ends,
                        created_by=uuid.UUID(creator))
        db.add(camp)
        db.flush()
        for op_uid in operators:
            db.add(CampaignMember(campaign_id=camp.id, user_id=uuid.UUID(op_uid),
                                  role_in_campaign="operator"))
        return str(camp.id)


def _approval(tid, campaign_id, *, level, provider, requester, approver,
              expires=None, revoked=False, consumed=False):
    from guardian_db.models import Approval
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        a = Approval(
            tenant_id=uuid.UUID(tid), campaign_id=uuid.UUID(campaign_id), subject_kind="tool_job",
            provider_key=provider, capability_level=level, requested_by=uuid.UUID(requester),
            approver_id=uuid.UUID(approver), reason="ok", granted_at=now,
            expires_at=expires, revoked_at=now if revoked else None,
            consumed_at=now if consumed else None)
        db.add(a)
        db.flush()
        return str(a.id)


def _apikey(tid, scopes):
    from guardian_db.models import ApiKey
    from guardian_db.session import session_scope
    with session_scope() as db:
        k = ApiKey(tenant_id=uuid.UUID(tid), name="svc", key_hash=uuid.uuid4().hex, scopes=scopes)
        db.add(k)
        db.flush()
        return str(k.id)


def _run(tid, actor, *, tool="fake", campaign=None, approval=None):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, tool, ["t.example.com"], actor, True, {"snapshot": {}}, None, campaign, approval]
    ).get()


# ── platform roles ──
def test_platform_grant_row_grants_platform_authority(monkeypatch):
    from guardian_db.models import PlatformGrant
    from guardian_db.session import session_scope
    _install(monkeypatch, "fake", _L0_CAPS)
    tid, cid = _tenant()
    owner = _user("plat")
    with session_scope() as db:  # a real DB platform grant, not the config allowlist
        db.add(PlatformGrant(user_id=uuid.UUID(owner), role="platform_owner"))
    _authorize(tid, cid)
    assert _run(tid, owner)["status"] == "completed"   # platform owner runs without membership


def test_tenant_owner_is_not_platform_owner(monkeypatch):
    _install(monkeypatch, "fake", _L0_CAPS)
    a_tid, a_cid = _tenant()
    b_tid, _ = _tenant()
    owner_a = _member(a_tid, "owner")
    assert _run(b_tid, owner_a)["status"] == "forbidden"   # tenant owner has no cross-tenant reach


# ── capability grants ──
def test_capability_grant_raises_analyst_ceiling(monkeypatch):
    _install(monkeypatch, "fake", ToolCapabilities(category="x", network=True, active=True))  # L2
    tid, cid = _tenant()
    analyst = _member(tid, "analyst")            # L0 by role
    admin = _member(tid, "admin")
    _authorize(tid, cid)
    assert _run(tid, analyst)["status"] == "forbidden"          # L2 > L0 ceiling
    _grant(tid, "user", analyst, 2, admin)                       # explicit grant to L2
    assert _run(tid, analyst)["status"] == "completed"


def test_revoked_and_expired_grants_are_ignored(monkeypatch):
    _install(monkeypatch, "fake", ToolCapabilities(category="x", network=True, active=True))
    tid, cid = _tenant()
    analyst = _member(tid, "analyst")
    admin = _member(tid, "admin")
    _authorize(tid, cid)
    _grant(tid, "user", analyst, 2, admin, revoked=True)
    assert _run(tid, analyst)["status"] == "forbidden"
    _grant(tid, "user", analyst, 2, admin,
           expires_at=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
    assert _run(tid, analyst)["status"] == "forbidden"


def test_role_grant_applies_to_all_of_that_role(monkeypatch):
    _install(monkeypatch, "fake", ToolCapabilities(category="x", network=True, active=True))
    tid, cid = _tenant()
    analyst = _member(tid, "analyst")
    admin = _member(tid, "admin")
    _authorize(tid, cid)
    _grant(tid, "role", "analyst", 2, admin)
    assert _run(tid, analyst)["status"] == "completed"


# ── tool catalog ──
def test_disabled_tool_in_catalog_is_denied(monkeypatch):
    from guardian_db.models import ToolCatalog
    from guardian_db.session import session_scope
    _install(monkeypatch, "disabled_tool", _L0_CAPS)
    tid, cid = _tenant()
    pentester = _member(tid, "pentester")
    _authorize(tid, cid)
    with session_scope() as db:
        db.merge(ToolCatalog(provider_key="disabled_tool", version="1", enabled=False))
    res = _run(tid, pentester, tool="disabled_tool")
    assert res["status"] == "forbidden" and "disabled" in " ".join(res["reasons"])


def test_unregistered_sensitive_provider_denied_by_default(monkeypatch):
    # A unique key never inserted into the catalog ⇒ genuinely unregistered.
    _install(monkeypatch, "unreg_sensitive", _L4_CAPS)          # L4, no catalog row
    tid, cid = _tenant()
    owner = _user("plat")
    from guardian_db.models import PlatformGrant
    from guardian_db.session import session_scope
    with session_scope() as db:
        db.add(PlatformGrant(user_id=uuid.UUID(owner), role="platform_owner"))
    _authorize(tid, cid)
    res = _run(tid, owner, tool="unreg_sensitive")             # even a platform owner
    assert res["status"] == "forbidden"
    assert "not registered in the tool catalog" in " ".join(res["reasons"])


# ── service accounts ──
def test_service_account_capped_at_l2(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)                      # L4
    tid, cid = _tenant()
    _authorize(tid, cid)
    _enable_fake_l4()                                            # "fake" enabled in catalog
    key = _apikey(tid, ["cap:5"])                                # even a broad scope
    res = _run(tid, key)
    assert res["status"] == "forbidden" and "capped at level 2" in " ".join(res["reasons"])


# ── L3+ campaign + approval ──
def _enable_fake_l4():
    from guardian_db.models import ToolCatalog
    from guardian_db.session import session_scope
    with session_scope() as db:
        db.merge(ToolCatalog(provider_key="fake", version="1", enabled=True))


def test_l4_requires_campaign_and_approval_full_path(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)                     # operator granted L4
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, max_level=4, operators=[operator])
    appr = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin)
    res = _run(tid, operator, campaign=camp, approval=appr)
    assert res["status"] == "completed"


def test_l4_denied_without_campaign(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    appr_camp = _campaign(tid, cid, admin, operators=[operator])
    appr = _approval(tid, appr_camp, level=4, provider="fake", requester=operator, approver=admin)
    res = _run(tid, operator, campaign=None, approval=appr)
    assert res["status"] == "forbidden" and "requires a campaign" in " ".join(res["reasons"])


def test_l4_self_approval_denied(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, operators=[operator])
    # operator approves their own request → DB check + control-plane both forbid.
    import sqlalchemy
    from guardian_db.models import Approval
    from guardian_db.session import session_scope
    with pytest.raises(sqlalchemy.exc.IntegrityError):
        with session_scope() as db:
            db.add(Approval(tenant_id=uuid.UUID(tid), campaign_id=uuid.UUID(camp),
                            subject_kind="tool_job", provider_key="fake", capability_level=4,
                            requested_by=uuid.UUID(operator), approver_id=uuid.UUID(operator),
                            reason="x", granted_at=dt.datetime.now(dt.UTC)))


def test_expired_revoked_consumed_and_mismatch_approvals_denied(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, operators=[operator])

    expired = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin,
                        expires=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
    assert "expired" in " ".join(_run(tid, operator, campaign=camp, approval=expired)["reasons"])

    revoked = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin,
                        revoked=True)
    assert "revoked" in " ".join(_run(tid, operator, campaign=camp, approval=revoked)["reasons"])

    consumed = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin,
                         consumed=True)
    assert "consumed" in " ".join(_run(tid, operator, campaign=camp, approval=consumed)["reasons"])

    mism = _approval(tid, camp, level=4, provider="other", requester=operator, approver=admin)
    assert "provider mismatch" in " ".join(_run(tid, operator, campaign=camp, approval=mism)["reasons"])


def test_consumed_approval_cannot_replay(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, max_level=4, operators=[operator])
    appr = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin)
    assert _run(tid, operator, campaign=camp, approval=appr)["status"] == "completed"
    replay = _run(tid, operator, campaign=camp, approval=appr)      # same approval again
    assert replay["status"] == "forbidden" and "consumed" in " ".join(replay["reasons"])


def test_suspended_campaign_denied(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, status="suspended", operators=[operator])
    appr = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin)
    res = _run(tid, operator, campaign=camp, approval=appr)
    assert res["status"] == "forbidden" and "not active" in " ".join(res["reasons"])


def test_expired_campaign_window_denied(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", operator, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, operators=[operator],
                     ends=dt.datetime.now(dt.UTC) - dt.timedelta(minutes=1))
    appr = _approval(tid, camp, level=4, provider="fake", requester=operator, approver=admin)
    assert "window has ended" in " ".join(
        _run(tid, operator, campaign=camp, approval=appr)["reasons"])


def test_non_operator_cannot_run_campaign(monkeypatch):
    _install(monkeypatch, "fake", _L4_CAPS)
    _enable_fake_l4()
    tid, cid = _tenant()
    operator = _member(tid, "pentester")
    outsider = _member(tid, "pentester")
    admin = _member(tid, "admin")
    _grant(tid, "user", outsider, 4, admin)
    _authorize(tid, cid)
    camp = _campaign(tid, cid, admin, operators=[operator])       # outsider is NOT a member
    appr = _approval(tid, camp, level=4, provider="fake", requester=outsider, approver=admin)
    res = _run(tid, outsider, campaign=camp, approval=appr)
    assert res["status"] == "forbidden" and "not an operator" in " ".join(res["reasons"])


# ── audit immutability ──
def test_audit_log_is_immutable():
    import sqlalchemy
    from guardian_db.models import AuditLog, Tenant
    from guardian_db.session import session_scope
    with session_scope() as db:
        t = Tenant(name=f"au-{uuid.uuid4().hex[:8]}", slug=f"au-{uuid.uuid4().hex[:8]}",
                   mode="hybrid")
        db.add(t)
        db.flush()
        row = AuditLog(tenant_id=t.id, action="x", created_at=dt.datetime.now(dt.UTC))
        db.add(row)
        db.flush()
        rid = row.id
    with pytest.raises(sqlalchemy.exc.DatabaseError):        # DELETE blocked by trigger
        with session_scope() as db:
            db.query(AuditLog).filter(AuditLog.id == rid).delete()
    with pytest.raises(sqlalchemy.exc.DatabaseError):        # UPDATE blocked by trigger
        with session_scope() as db:
            db.query(AuditLog).filter(AuditLog.id == rid).update({"action": "y"})
