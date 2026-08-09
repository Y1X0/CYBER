"""Phase B governance persistence — platform roles, campaigns, approvals, grants, tool catalog.

All additive. Tenant-scoped tables (campaigns, approvals, capability_grants) follow the existing
`tenant_isolation` RLS pattern; `campaign_members` is a child scoped through its campaign. The
global tables (`platform_grants`, `tool_catalog`) carry no tenant and are read by the trusted worker
plane (owner session, RLS-bypassing) and managed by platform owners — never exposed to the app role.

The provider never sees any of these; they are Control-Plane policy the governance resolver reads.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class PlatformGrant(Base, TimestampMixin):
    """Platform-level authority (owner/admin), distinct from any per-tenant `owner` role. Global."""

    __tablename__ = "platform_grants"
    __table_args__ = (
        CheckConstraint("role IN ('platform_owner','platform_admin')", name="ck_platform_role"),
        Index("uq_platform_grant_active", "user_id", "role",
              unique=True, postgresql_where=text("revoked_at IS NULL")),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), nullable=False)
    granted_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)


class ToolCatalog(Base, TimestampMixin):
    """Central enablement + policy for a provider. Global. Primitives stay in code; the catalog
    controls enablement, version, and optional campaign/approval overrides only."""

    __tablename__ = "tool_catalog"

    provider_key: Mapped[str] = mapped_column(String(60), primary_key=True)
    version: Mapped[str] = mapped_column(String(20), default="", nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    # null ⇒ follow the code-derived capability level; True/False ⇒ override.
    requires_campaign: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    requires_approval: Mapped[bool | None] = mapped_column(Boolean, nullable=True)
    metadata_: Mapped[dict] = mapped_column("metadata", JSONB, default=dict, nullable=False)


class Campaign(Base, TimestampMixin):
    """A governed container for sensitive (L3+) operations, tenant-scoped and time-windowed."""

    __tablename__ = "campaigns"
    __table_args__ = (
        CheckConstraint(
            "status IN ('draft','active','suspended','completed','revoked')",
            name="ck_campaign_state"),
        Index("idx_campaigns_tenant_status", "tenant_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("customers.id"), nullable=True)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="draft", nullable=False)
    max_capability_level: Mapped[int] = mapped_column(Integer, nullable=False)
    scope: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    starts_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    ends_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    created_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)


class CampaignMember(Base, TimestampMixin):
    """A participant in a campaign, with a campaign-local role. Child of campaigns (RLS via
    the parent campaign's tenant)."""

    __tablename__ = "campaign_members"
    __table_args__ = (
        UniqueConstraint("campaign_id", "user_id", name="uq_campaign_member"),
        CheckConstraint(
            "role_in_campaign IN ('operator','approver','observer')", name="ck_campaign_member_role"
        ),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    campaign_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("campaigns.id", ondelete="CASCADE"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    role_in_campaign: Mapped[str] = mapped_column(String(20), nullable=False)


class Approval(Base, TimestampMixin):
    """A first-class, revocable, single-use approval for a sensitive (L3+) execution. Tenant-scoped.

    Replaces the ephemeral `human_approved` bool for L3+. L2 keeps the bool (unchanged).
    """

    __tablename__ = "approvals"
    __table_args__ = (
        CheckConstraint("subject_kind IN ('campaign','tool_job')", name="ck_approval_subject"),
        # L4/L5 require an independent approver (defense-in-depth beyond the Control-Plane check).
        CheckConstraint("capability_level < 4 OR approver_id <> requested_by",
                        name="ck_approval_independent_high"),
        Index("idx_approvals_tenant_campaign", "tenant_id", "campaign_id"),
        Index("idx_approvals_tenant_expires", "tenant_id", "expires_at"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    campaign_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("campaigns.id"), nullable=True)
    subject_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    provider_key: Mapped[str | None] = mapped_column(String(60), nullable=True)
    capability_level: Mapped[int] = mapped_column(Integer, nullable=False)
    scope_snapshot: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    requested_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    approver_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    reason: Mapped[str] = mapped_column(Text, default="", nullable=False)
    granted_at: Mapped[dt.datetime] = mapped_column(nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    revoked_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    consumed_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)


class CapabilityGrant(Base, TimestampMixin):
    """Grants a subject (user / role / api_key) a capability ceiling above their role default.

    Tenant-scoped. A grant can never exceed the granter's own authority (enforced in the Control
    Plane). The provider never sees grants.
    """

    __tablename__ = "capability_grants"
    __table_args__ = (
        CheckConstraint("subject_kind IN ('user','role','api_key')", name="ck_grant_subject"),
        Index("idx_capability_grants_tenant_subject", "tenant_id", "subject_ref"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    subject_kind: Mapped[str] = mapped_column(String(20), nullable=False)
    subject_ref: Mapped[str] = mapped_column(String(64), nullable=False)  # user_id / role / key id
    max_level: Mapped[int] = mapped_column(Integer, nullable=False)
    tool_allowlist: Mapped[list | None] = mapped_column(JSONB, nullable=True)  # null ⇒ all tools
    granted_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    expires_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(nullable=True)
