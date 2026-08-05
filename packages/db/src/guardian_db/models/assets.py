"""Assets, engagements, and the authorization gate (docs 07 §3 and 06 §4).

- Asset         : an inventory item under management (repo/web/api/cloud/image/manifest).
- Engagement    : a scoped assessment effort grouping scans, carrying authorized scope.
- Authorization : the safe-scanning gate — active engines cannot run without a valid record.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import DateTime, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # AssetKind value: repo | web | api | cloud_account | container_image | k8s_manifest
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    # URL / ARN / image ref / path
    identifier: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # "public" | "internal" | "unknown" — feeds the scorer.
    exposure: Mapped[str] = mapped_column(String(20), default="unknown", nullable=False)
    # Non-sensitive scan config + credential *references* (e.g. secrets-manager keys / role ARNs).
    # Raw secrets MUST NOT be stored here — use `secret_ref` (envelope-encrypted) instead.
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    # ── Phase 5 (5B) provenance seam: where this asset came from (EASM / discovery foundation).
    # "declared" (customer-registered) | "discovered" (found by EASM). No discovery logic yet.
    source: Mapped[str] = mapped_column(String(20), default="declared", nullable=False)
    # "active" | "inactive" | "shadow" — lifecycle/shadow-asset state.
    state: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    discovered_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)
    first_seen_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Envelope-encrypted credential reference (opaque ciphertext); decrypted only at use.
    secret_ref: Mapped[str | None] = mapped_column(Text, nullable=True)


class Engagement(Base, TimestampMixin):
    __tablename__ = "engagements"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    # Authorized scope descriptor (asset ids, allowed engines, constraints).
    scope: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class Authorization(Base, TimestampMixin):
    __tablename__ = "authorizations"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )
    scope: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # "ownership_verified" | "written_consent"
    method: Mapped[str] = mapped_column(String(40), nullable=False)
    authorized_by: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    valid_from: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    valid_until: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    asset: Mapped[Asset | None] = relationship()
