"""Capability governance resolver (Phase A) — the Control-Plane enforcement point.

This is where a tool execution is refused BEFORE it runs, based on WHO is asking. It resolves the
calling principal (platform owner / tenant staff / service account), derives the tool's capability
level from its declared primitives, and decides whether that principal may run that level in that
tenant. It reuses the existing identity substrate — `TenantMembership.role`, `ApiKey.scopes`, and a
config-level platform-owner allowlist — with **no new tables**.

Boundaries this enforces:
  * a request with no valid identity in the tenant is refused (Celery cannot run a job anonymously);
  * a tenant principal cannot act in another tenant (cross-tenant execution is refused);
  * a normal role cannot exceed its ceiling (no self-escalation);
  * a service account cannot exceed its scope allowlist;
  * L3+ (SENSITIVE/EXPLOIT/DESTRUCTIVE) are recognized but require the Phase-B campaign+approval
    machinery — refused for now, not forbidden.

The provider is never consulted and never sees identity — it only ever declares capabilities.
"""

from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass

from guardian_common.config import get_settings
from guardian_core.capability import (
    CapabilityLevel,
    derive_capability_level,
    level_requires_campaign,
)
from guardian_core.rbac import role_ceiling
from guardian_core.tool import ToolCapabilities
from guardian_db.models import ApiKey, TenantMembership
from sqlalchemy import select
from sqlalchemy.orm import Session


@dataclass(frozen=True)
class GovernanceResult:
    allowed: bool
    principal_kind: str                 # platform_owner | staff | service | none
    actor_uuid: uuid.UUID | None        # users.id for staff/owner audit; None for service/none
    required_level: int
    reasons: tuple[str, ...] = ()


def _platform_owner_ids() -> set[str]:
    raw = get_settings().platform_owner_ids or ""
    return {x.strip() for x in raw.split(",") if x.strip()}


def _service_max_level(scopes: list[str] | None) -> int | None:
    """The highest ``cap:<n>`` level a service account's scope allowlist grants, or None."""
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


def _campaign_block(kind: str, actor: uuid.UUID | None, required: int) -> GovernanceResult:
    return GovernanceResult(
        False, kind, actor, required,
        ("capability level requires campaign + approval governance (Phase B, not enabled)",),
    )


def evaluate_governance(
    session: Session, *, tenant_id: uuid.UUID, actor_id: str | None, caps: ToolCapabilities
) -> GovernanceResult:
    """Decide whether `actor_id` may run a tool of these capabilities in `tenant_id`."""
    required = int(derive_capability_level(caps))
    needs_campaign = level_requires_campaign(CapabilityLevel(required))

    if not actor_id:
        return GovernanceResult(False, "none", None, required, ("missing actor identity",))
    aid = str(actor_id)

    # 1) Platform owner (config allowlist) — platform-level authority, tenant-independent.
    if aid in _platform_owner_ids():
        owner_uuid = _as_uuid(aid)
        if needs_campaign:
            return _campaign_block("platform_owner", owner_uuid, required)
        return GovernanceResult(True, "platform_owner", owner_uuid, required)

    actor_uuid = _as_uuid(aid)
    if actor_uuid is None:
        return GovernanceResult(False, "none", None, required, ("invalid actor id",))

    # 2) Staff membership in THIS tenant (cross-tenant principals have no membership here).
    membership = session.execute(
        select(TenantMembership).where(
            TenantMembership.user_id == actor_uuid,
            TenantMembership.tenant_id == tenant_id,
        )
    ).scalar_one_or_none()
    if membership is not None:
        ceiling = role_ceiling(membership.role)
        if ceiling is None:
            return GovernanceResult(False, "staff", actor_uuid, required,
                                    (f"role '{membership.role}' may not execute tools",))
        if needs_campaign:
            return _campaign_block("staff", actor_uuid, required)
        if required > int(ceiling):
            return GovernanceResult(False, "staff", actor_uuid, required,
                                    (f"role '{membership.role}' capped at level {int(ceiling)}",))
        return GovernanceResult(True, "staff", actor_uuid, required)

    # 3) Service account (ApiKey) bound to THIS tenant, live, scoped by an explicit allowlist.
    apikey = session.get(ApiKey, actor_uuid)
    now = dt.datetime.now(dt.UTC)
    if (apikey is not None and apikey.tenant_id == tenant_id and apikey.revoked_at is None
            and (apikey.expires_at is None or apikey.expires_at > now)):
        max_level = _service_max_level(apikey.scopes)
        if max_level is None:
            return GovernanceResult(False, "service", None, required,
                                    ("service account has no capability scope",))
        if needs_campaign:
            return _campaign_block("service", None, required)
        if required > max_level:
            return GovernanceResult(False, "service", None, required,
                                    (f"service account capped at level {max_level}",))
        return GovernanceResult(True, "service", None, required)

    # 4) No valid identity in this tenant (covers cross-tenant and unknown principals).
    return GovernanceResult(False, "none", None, required, ("no valid identity in this tenant",))


def _as_uuid(value: str) -> uuid.UUID | None:
    try:
        return uuid.UUID(value)
    except ValueError:
        return None
