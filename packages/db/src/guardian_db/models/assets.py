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
    # PLAINTEXT JSONB in Phase 1 — raw secrets MUST NOT be stored here. Envelope encryption (KMS)
    # for credential references lands in Phase 4 before any real cloud credentials are handled.
    config: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


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
