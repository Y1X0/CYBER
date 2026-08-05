"""Reports and the pentester/reviewer approval trail (doc 07 §6)."""

from __future__ import annotations

import uuid

from sqlalchemy import ForeignKey, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    scan_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("scans.id"), nullable=True)
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )
    title: Mapped[str] = mapped_column(String(300), default="", nullable=False)
    format: Mapped[str] = mapped_column(String(10), default="html", nullable=False)
    # ReportStatus: draft | in_review | approved | published | rejected | revoked
    status: Mapped[str] = mapped_column(String(20), default="draft", nullable=False)
    summary: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    artifact_uri: Mapped[str | None] = mapped_column(Text, nullable=True)

    sections: Mapped[list[ReportSection]] = relationship(back_populates="report")
    approvals: Mapped[list[ReportApproval]] = relationship(back_populates="report")


class ReportSection(Base, TimestampMixin):
    __tablename__ = "report_sections"

    id: Mapped[uuid.UUID] = uuid_pk()
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("reports.id"), nullable=False)
    # executive | findings | standards | remediation
    kind: Mapped[str] = mapped_column(String(30), nullable=False)
    title: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    ordering: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    report: Mapped[Report] = relationship(back_populates="sections")


class ReportApproval(Base, TimestampMixin):
    __tablename__ = "report_approvals"

    id: Mapped[uuid.UUID] = uuid_pk()
    report_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("reports.id"), nullable=False)
    actor_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    # "approve" | "reject" | "publish" | "revoke"
    decision: Mapped[str] = mapped_column(String(20), nullable=False)
    notes: Mapped[str] = mapped_column(Text, default="", nullable=False)

    report: Mapped[Report] = relationship(back_populates="approvals")
