"""Capability governance resolver — the Control-Plane enforcement point.

Refuses a tool execution BEFORE it runs, based on WHO is asking, reusing the persisted identity /
authority substrate:

  * platform authority — the config allowlist OR a `platform_grants` row (Phase B);
  * tenant staff — `TenantMembership.role` with a role ceiling, raised by `capability_grants`;
  * service accounts — `ApiKey.scopes`, capped at L2, further narrowed by grants;
  * tool enablement — `tool_catalog` (a disabled tool is refused; an unregistered SENSITIVE/L3+
    provider is refused by default; unregistered L0–L2 keeps working);
  * L3+ (SENSITIVE/EXPLOIT/DESTRUCTIVE) — additionally require an ACTIVE `campaign` the actor is an
    operator of, and a valid, unconsumed, scope/provider/campaign-matching `approval` whose approver
    is independent for L4/L5. The approval id is returned to be consumed only once the full gate
    passes.

The provider is never consulted and never sees identity, role, grant, campaign, or approval.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from guardian_common.config import get_settings
from guardian_core.capability import CapabilityLevel, derive_capability_level
from guardian_core.rbac import role_ceiling
from guardian_core.tool import ToolCapabilities
from guardian_db.models import (
    ApiKey,
    Approval,
    Campaign,
    CampaignMember,
    CapabilityGrant,
    PlatformGrant,
    TenantMembership,
    ToolCatalog,
)
from sqlalchemy import select
from sqlalchemy.orm import Session

_SERVICE_MAX = int(CapabilityLevel.ACTIVE_RECON)   # service accounts are capped at L2 (Phase B)
_L3 = int(CapabilityLevel.SENSITIVE)
_L4 = int(CapabilityLevel.EXPLOIT_VALIDATION)


@dataclass(frozen=True)
class GovernanceResult:
    allowed: bool
    principal_kind: str                 # platform_owner | staff | service | none
    actor_uuid: uuid.UUID | None        # users.id for staff/owner audit; None for service/none
    required_level: int
    reasons: tuple[str, ...] = ()
    approval_id: uuid.UUID | None = None  # consume only after the full gate passes (L3+)


def _deny(kind, actor, level, reason) -> GovernanceResult:  # noqa: ANN001
    return GovernanceResult(False, kind, actor, level, (reason,))


def _platform_owner_ids() -> set[str]:
    raw = get_settings().platform_owner_ids or ""
    return {x.strip() for x in raw.split(",") if x.strip()}


def _as_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None


def _aware(ts: dt.datetime | None) -> dt.datetime | None:
    """Normalize a datetime to timezone-aware UTC for comparison against `now`.

    Some persisted governance timestamps come back naive (the models declare plain `DateTime`, i.e.
    `timestamp without time zone`), and the platform writes every timestamp in UTC. Interpreting a
    naive value as UTC keeps temporal checks correct while never mixing naive/aware operands, so an
    expiry/window comparison can never raise "can't compare offset-naive and offset-aware".
    Already-aware values pass through unchanged, so governance semantics are preserved exactly.
    """
    if ts is not None and ts.tzinfo is None:
        return ts.replace(tzinfo=dt.UTC)
    return ts


def _is_platform_owner(session: Session, aid: str, actor_uuid: uuid.UUID | None) -> bool:
    if aid in _platform_owner_ids():
        return True
    if actor_uuid is None:
        return False
    row = session.execute(
        select(PlatformGrant).where(
            PlatformGrant.user_id == actor_uuid, PlatformGrant.revoked_at.is_(None))
    ).first()
    return row is not None


def _service_scope_level(scopes: list[str] | None) -> int | None:
    best: int | None = None
    for s in scopes or []:
        token = str(s)
        if token.startswith("cap:"):
            try:
                lvl = int(token.split(":", 1)[1])
            except ValueError:
                continue
            best = lvl if best is None else max(best, lvl)
    return best


def _grant_ceiling(session, tenant_id, *, user_uuid, role, api_key_id, tool_key, now):  # noqa: ANN001
    """The highest level any live, tool-matching capability_grant confers on this subject."""
    best: int | None = None
    rows = session.execute(
        select(CapabilityGrant).where(
            CapabilityGrant.tenant_id == tenant_id, CapabilityGrant.revoked_at.is_(None))
    ).scalars()
    for g in rows:
        if g.expires_at is not None and _aware(g.expires_at) <= now:
            continue
        matches = (
            (g.subject_kind == "user" and user_uuid is not None
             and g.subject_ref == str(user_uuid))
            or (g.subject_kind == "role" and role is not None and g.subject_ref == role)
            or (g.subject_kind == "api_key" and api_key_id is not None
                and g.subject_ref == str(api_key_id))
        )
        if not matches:
            continue
        if g.tool_allowlist is not None and tool_key not in g.tool_allowlist:
            continue
        best = g.max_level if best is None else max(best, g.max_level)
    return best


def _catalog_block(session, tool_key, required) -> str | None:  # noqa: ANN001
    """Tool-catalog enablement. Returns a deny reason or None. Primitives stay in code."""
    if not tool_key:
        return None
    cat = session.get(ToolCatalog, tool_key)
    if cat is not None and not cat.enabled:
        return "tool is disabled in the catalog"
    if cat is None and required >= _L3:
        return "sensitive provider is not registered in the tool catalog"
    return None


def _validate_campaign(session, tenant_id, campaign_id, actor_uuid, required, now):  # noqa: ANN001
    """An active, in-window campaign that authorizes `required` and lists the actor as operator."""
    if not campaign_id:
        return "L3+ execution requires a campaign"
    cid = _as_uuid(str(campaign_id))
    camp = session.get(Campaign, cid) if cid else None
    if camp is None or camp.tenant_id != tenant_id:
        return "campaign not found in tenant"
    if camp.status != "active":
        return f"campaign is {camp.status}, not active"
    if camp.starts_at is not None and _aware(camp.starts_at) > now:
        return "campaign has not started"
    if camp.ends_at is not None and _aware(camp.ends_at) <= now:
        return "campaign window has ended"
    if required > camp.max_capability_level:
        return "campaign does not authorize this capability level"
    member = session.execute(
        select(CampaignMember).where(
            CampaignMember.campaign_id == cid, CampaignMember.user_id == actor_uuid,
            CampaignMember.role_in_campaign == "operator")
    ).first()
    if member is None:
        return "actor is not an operator of this campaign"
    return None


def _validate_approval(session, tenant_id, approval_id, *, required, tool_key,  # noqa: ANN001
                       campaign_id, actor_uuid, now):
    """Return (approval_uuid, None) if valid, else (None, reason). Does NOT consume."""
    if not approval_id:
        return None, "L3+ execution requires an approval"
    aid = _as_uuid(str(approval_id))
    appr = session.get(Approval, aid) if aid else None
    if appr is None or appr.tenant_id != tenant_id:
        return None, "approval not found in tenant"
    if appr.revoked_at is not None:
        return None, "approval revoked"
    if appr.consumed_at is not None:
        return None, "approval already consumed"
    if appr.expires_at is not None and _aware(appr.expires_at) <= now:
        return None, "approval expired"
    if appr.capability_level < required:
        return None, "approval level too low"
    if appr.provider_key not in (None, tool_key):
        return None, "approval provider mismatch"
    if str(appr.campaign_id) != str(campaign_id):
        return None, "approval campaign mismatch"
    if required >= _L4 and appr.approver_id == actor_uuid:
        return None, "L4+ requires an independent approver"
    return appr.id, None


def evaluate_governance(  # noqa: PLR0911, PLR0913
    session: Session, *, tenant_id: uuid.UUID, actor_id: str | None, caps: ToolCapabilities,
    tool_key: str | None = None, campaign_id: str | None = None, approval_id: str | None = None,
) -> GovernanceResult:
    """Decide whether `actor_id` may run a tool of these capabilities in `tenant_id`."""
    required = int(derive_capability_level(caps))
    now = dt.datetime.now(dt.UTC)

    if not actor_id:
        return _deny("none", None, required, "missing actor identity")
    aid = str(actor_id)
    actor_uuid = _as_uuid(aid)

    # ── resolve principal → base ceiling. `audit_actor` is a real users.id or None (service). ──
    if _is_platform_owner(session, aid, actor_uuid):
        kind, is_service, base_ceiling, role = ("platform_owner", False,
                                                int(CapabilityLevel.DESTRUCTIVE), None)
    else:
        if actor_uuid is None:
            return _deny("none", None, required, "invalid actor id")
        membership = session.execute(
            select(TenantMembership).where(
                TenantMembership.user_id == actor_uuid,
                TenantMembership.tenant_id == tenant_id)
        ).scalar_one_or_none()
        if membership is not None:
            ceiling = role_ceiling(membership.role)
            if ceiling is None:
                return _deny("staff", actor_uuid, required,
                             f"role '{membership.role}' may not execute tools")
            kind, is_service, base_ceiling, role = "staff", False, int(ceiling), membership.role
        else:
            apikey = session.get(ApiKey, actor_uuid)
            if (apikey is None or apikey.tenant_id != tenant_id or apikey.revoked_at is not None
                    or (apikey.expires_at is not None and _aware(apikey.expires_at) <= now)):
                return _deny("none", None, required, "no valid identity in this tenant")
            scope_level = _service_scope_level(apikey.scopes)
            if scope_level is None:
                return _deny("service", None, required, "service account has no capability scope")
            kind, is_service, base_ceiling, role = ("service", True,
                                                    min(scope_level, _SERVICE_MAX), None)

    audit_actor = None if is_service else actor_uuid  # audit_log.actor_id FK ⇒ real users.id only

    catalog_reason = _catalog_block(session, tool_key, required)
    if catalog_reason is not None:
        return _deny(kind, audit_actor, required, catalog_reason)

    # ── raise ceiling by capability grants (never for platform owner, who is already L5) ──
    effective = base_ceiling
    if kind != "platform_owner":
        granted = _grant_ceiling(
            session, tenant_id, user_uuid=(None if is_service else actor_uuid), role=role,
            api_key_id=(actor_uuid if is_service else None), tool_key=tool_key, now=now)
        if granted is not None:
            effective = max(effective, granted)
        if is_service:
            effective = min(effective, _SERVICE_MAX)   # a grant can never lift a service past L2

    if is_service and required >= _L3:
        return _deny("service", None, required, "service accounts are capped at level 2")
    if required > effective:
        return _deny(kind, audit_actor, required, f"principal capped at level {effective}")

    # ── L0–L2: capability + catalog + (later) authorization/policy is enough ──
    if required < _L3:
        return GovernanceResult(True, kind, audit_actor, required)

    # ── L3+: campaign + approval (in addition to the capability check above) ──
    camp_reason = _validate_campaign(session, tenant_id, campaign_id, actor_uuid, required, now)
    if camp_reason is not None:
        return _deny(kind, audit_actor, required, camp_reason)
    appr_uuid, appr_reason = _validate_approval(
        session, tenant_id, approval_id, required=required, tool_key=tool_key,
        campaign_id=campaign_id, actor_uuid=actor_uuid, now=now)
    if appr_reason is not None:
        return _deny(kind, audit_actor, required, appr_reason)
    return GovernanceResult(True, kind, audit_actor, required, approval_id=appr_uuid)
