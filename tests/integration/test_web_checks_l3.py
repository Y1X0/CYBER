"""web_checks L3 end-to-end (Provider #6) — the first REAL provider through the L3 machinery.

Gated by GUARDIAN_RUN_DB_TESTS=1. Proves the genuinely-new leg no shipped provider exercised before:
Campaign → single-use Approval → signed job → provider → Evidence. A capability grant raises the
actor above the L2 staff ceiling; an active campaign (actor = operator) + a matching single-use
approval are BOTH required; a missing campaign, a missing approval, and a re-used approval are denied.
"""

from __future__ import annotations

import datetime as dt
import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)

_DOMAIN = "t.example.com"
_SNAP = {_DOMAIN: {"/.git/config": {"status": 200, "body": "[core]\n\trepositoryformatversion = 0"}}}


def _user(tag="u"):
    from guardian_db.models import User
    from guardian_db.session import session_scope
    with session_scope() as db:
        u = User(email=f"{tag}-{uuid.uuid4().hex[:8]}@x.com", name="U", password_hash="x",
                 status="active")
        db.add(u)
        db.flush()
        return str(u.id)


def _tenant_customer():
    from guardian_db.models import Customer, Tenant
    from guardian_db.session import session_scope
    m = uuid.uuid4().hex[:8]
    with session_scope() as db:
        t = Tenant(name=f"wc-{m}", slug=f"wc-{m}", mode="hybrid")
        db.add(t)
        db.flush()
        c = Customer(tenant_id=t.id, name="C", criticality="high")
        db.add(c)
        db.flush()
        return str(t.id), str(c.id)


def _member(tid, role, uid):
    from guardian_db.models import TenantMembership
    from guardian_db.session import session_scope
    with session_scope() as db:
        db.add(TenantMembership(user_id=uuid.UUID(uid), tenant_id=uuid.UUID(tid), role=role))


def _authorize(tid, cid, granter):
    from guardian_db.models import Authorization
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        db.add(Authorization(
            tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), asset_id=None, scope="s",
            authorized_targets=[{"type": "domain", "value": _DOMAIN}], method="active_recon",
            authorized_by=uuid.UUID(granter), valid_from=now - dt.timedelta(hours=1),
            valid_until=now + dt.timedelta(hours=1)))


def _grant_l3(tid, uid, granter):
    from guardian_db.models import CapabilityGrant
    from guardian_db.session import session_scope
    with session_scope() as db:
        db.add(CapabilityGrant(
            tenant_id=uuid.UUID(tid), subject_kind="user", subject_ref=uid, max_level=3,
            tool_allowlist=None, granted_by=uuid.UUID(granter)))


def _campaign(tid, cid, creator, operator):
    from guardian_db.models import Campaign, CampaignMember
    from guardian_db.session import session_scope
    with session_scope() as db:
        camp = Campaign(tenant_id=uuid.UUID(tid), customer_id=uuid.UUID(cid), name="c",
                        status="active", max_capability_level=3, created_by=uuid.UUID(creator))
        db.add(camp)
        db.flush()
        db.add(CampaignMember(campaign_id=camp.id, user_id=uuid.UUID(operator),
                              role_in_campaign="operator"))
        return str(camp.id)


def _approval(tid, campaign_id, actor):
    from guardian_db.models import Approval
    from guardian_db.session import session_scope
    now = dt.datetime.now(dt.UTC)
    with session_scope() as db:
        a = Approval(
            tenant_id=uuid.UUID(tid), campaign_id=uuid.UUID(campaign_id), subject_kind="tool_job",
            provider_key="web_checks", capability_level=3, requested_by=uuid.UUID(actor),
            approver_id=uuid.UUID(actor), reason="ok", granted_at=now,
            expires_at=now + dt.timedelta(hours=1))
        db.add(a)
        db.flush()
        return str(a.id)


def _full_setup():
    tid, cid = _tenant_customer()
    actor = _user("op")
    _member(tid, "pentester", actor)          # staff ceiling L2 …
    _grant_l3(tid, actor, actor)              # … raised to L3 by a capability grant
    _authorize(tid, cid, actor)
    camp = _campaign(tid, cid, actor, actor)
    return tid, cid, actor, camp


def _dispatch(tid, actor, *, campaign_id=None, approval_id=None):
    from guardian_scanner.tools.tasks import dispatch_tool_job
    return dispatch_tool_job.apply(
        args=[tid, "web_checks", [_DOMAIN], actor, True],
        kwargs={"settings": {"snapshot": _SNAP}, "campaign_id": campaign_id,
                "approval_id": approval_id}).get()


def _evidence(tid):
    from guardian_db.models import EvidenceItem
    from guardian_db.session import session_scope
    with session_scope() as db:
        return db.query(EvidenceItem).filter(EvidenceItem.tenant_id == uuid.UUID(tid)).all()


def test_l3_web_checks_runs_with_campaign_and_approval_and_consumes_it():
    from guardian_db.models import Approval
    from guardian_db.session import session_scope
    from guardian_scanner.tools.evidence import verify_chain

    tid, _cid, actor, camp = _full_setup()
    appr = _approval(tid, camp, actor)
    res = _dispatch(tid, actor, campaign_id=camp, approval_id=appr)
    assert res["status"] == "completed"

    kinds = {e.kind for e in _evidence(tid)}
    assert "web_check" in kinds and "web_checks_scan" in kinds        # detection reached Evidence
    with session_scope() as db:
        assert verify_chain(db, uuid.UUID(tid)) is True
        assert db.get(Approval, uuid.UUID(appr)).consumed_at is not None   # single-use consumed


def test_l3_denied_without_campaign():
    tid, _cid, actor, _camp = _full_setup()
    res = _dispatch(tid, actor)                                       # no campaign/approval
    assert res["status"] == "forbidden"
    assert any("campaign" in r for r in res["reasons"])
    assert _evidence(tid) == []                                      # nothing ran


def test_l3_denied_without_approval():
    tid, _cid, actor, camp = _full_setup()
    res = _dispatch(tid, actor, campaign_id=camp)                    # campaign but no approval
    assert res["status"] == "forbidden"
    assert any("approval" in r for r in res["reasons"])
    assert _evidence(tid) == []


def test_l3_approval_is_single_use():
    tid, _cid, actor, camp = _full_setup()
    appr = _approval(tid, camp, actor)
    assert _dispatch(tid, actor, campaign_id=camp, approval_id=appr)["status"] == "completed"
    second = _dispatch(tid, actor, campaign_id=camp, approval_id=appr)   # re-use the same approval
    assert second["status"] == "forbidden"
    assert any("consumed" in r for r in second["reasons"])
