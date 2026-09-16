"""SBOM store — the dependency inventory of a scanned asset, in CycloneDX form.

One row per scan that produced a dependency inventory: the CycloneDX 1.5 document (built by
`guardian_core.sbom` from the SCA engine's resolved components) plus a few counts kept in the clear
for list views. Unlike the proof vault, an SBOM is a deliverable meant to be exported — it holds no
secret and no exploit — so the document is stored as plain JSONB, isolated per tenant by Row-Level
Security like every other tenant-owned table.

This is persistence for data the scan already resolved but discarded: the SCA engine walks every
lockfile and only the *vulnerable* components became findings. The SBOM keeps the full inventory so
it survives the ephemeral scan workspace and can be downloaded later.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class SbomRecord(Base, TimestampMixin):
    __tablename__ = "sbom_documents"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("assets.id"), nullable=True)

    bom_format: Mapped[str] = mapped_column(String(20), default="CycloneDX", nullable=False)
    spec_version: Mapped[str] = mapped_column(String(10), default="1.5", nullable=False)
    component_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    vulnerable_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    # The CycloneDX document itself — a deliverable, not a secret, so stored in the clear.
    document: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
