"""Evidence-item seam (Phase 5B) — metadata + integrity foundation.

First-class evidence with a per-finding **hash chain** (`content_sha256` + `prev_hash`) so a chain
of custody can be verified later. Integrity can't be added retroactively to evidence captured
without it, so the columns land now. No capture/collaboration workflow is implemented yet — this is
the storage + integrity foundation only.
"""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class EvidenceItem(Base, TimestampMixin):
    __tablename__ = "evidence_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    finding_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("findings.id"), nullable=True)
    # code_snippet | http_exchange | config | secret | screenshot | terminal | note | manual
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    summary: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    # pointer into object storage for large artifacts (screenshots, raw output); metadata inline.
    storage_ref: Mapped[str | None] = mapped_column(Text, nullable=True)
    detail: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    # Integrity foundation: hash of this item's content + hash of the previous item in the chain.
    content_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    prev_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
