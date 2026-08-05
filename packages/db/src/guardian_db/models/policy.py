"""Deployment-gate policies (doc 01 §7). Declarative `fail_on` rules evaluated by the gate."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, Integer, String
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Policy(Base, TimestampMixin):
    __tablename__ = "policies"

    id: Mapped[uuid.UUID] = uuid_pk()
    organization_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    project_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)  # null = tenant-wide
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    # e.g. {"fail_on": [{"severity": "critical"}, {"kev": true}]}
    rules: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    version: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
