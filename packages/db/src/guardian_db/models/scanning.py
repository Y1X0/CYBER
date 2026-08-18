"""Scans, engine runs, canonical findings, triage history, and remediation tracking."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Scan(Base, TimestampMixin):
    __tablename__ = "scans"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("engagements.id"), nullable=True
    )
    trigger: Mapped[str] = mapped_column(String(20), default="manual", nullable=False)
    ref: Mapped[str | None] = mapped_column(String(200), nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    requested_engines: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Denormalized severity counts for fast list views.
    stats: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)

    engine_runs: Mapped[list[ScanEngineRun]] = relationship(back_populates="scan")


class ScanEngineRun(Base, TimestampMixin):
    __tablename__ = "scan_engine_runs"
    __table_args__ = (UniqueConstraint("scan_id", "engine", name="uq_engine_run_scan_engine"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    engine: Mapped[str] = mapped_column(String(30), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="queued", nullable=False)
    tool_versions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    raw_artifact_uri: Mapped[str | None] = mapped_column(Text, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)

    scan: Mapped[Scan] = relationship(back_populates="engine_runs")


class Finding(Base, TimestampMixin):
    __tablename__ = "findings"
    __table_args__ = (
        Index("idx_findings_tenant_customer_status", "tenant_id", "customer_id", "status"),
        Index("idx_findings_scan_severity", "scan_id", "severity"),
        Index("idx_findings_fingerprint", "asset_id", "fingerprint"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    scan_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scans.id"), nullable=False)
    engine_run_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("scan_engine_runs.id"), nullable=False
    )
    asset_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("assets.id"), nullable=False)

    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    category: Mapped[str] = mapped_column(String(60), nullable=False)

    # Standards mapping
    cwe_id: Mapped[str | None] = mapped_column(String(20), nullable=True)
    owasp_ref: Mapped[str | None] = mapped_column(String(20), nullable=True)
    cve_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)

    # Exploitability signals
    cvss_base: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Exploit intelligence carried onto the finding (WP-C4), so a report ranks without re-reading
    # the KB and a finding keeps the maturity it was actually scored with.
    exploit_maturity: Mapped[str | None] = mapped_column(String(20), nullable=True)
    ransomware: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    # Risk Engine output: 0–100 business-risk score + the transparent rationale behind it.
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    risk_rationale: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    confidence: Mapped[str] = mapped_column(String(10), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    # Provenance for the human-pentester workflow (doc 07 §6).
    source: Mapped[str] = mapped_column(String(20), default="automated", nullable=False)
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    # The cross-engine group this finding belongs to, if any (WP-E1). Set, never used to hide the
    # finding: a report renders the group, and the members stay individually inspectable.
    correlation_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("finding_correlations.id"), nullable=True
    )

    location: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    evidence: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    remediation: Mapped[dict | None] = mapped_column(JSONB, nullable=True)
    ai_explanation: Mapped[str | None] = mapped_column(Text, nullable=True)
    references: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    first_seen_scan_id: Mapped[uuid.UUID | None] = mapped_column(nullable=True)


class FindingEvent(Base, TimestampMixin):
    """Immutable triage history per finding (audit of status transitions)."""

    __tablename__ = "finding_events"

    id: Mapped[uuid.UUID] = uuid_pk()
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    actor_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    from_status: Mapped[str | None] = mapped_column(String(20), nullable=True)
    to_status: Mapped[str] = mapped_column(String(20), nullable=False)
    note: Mapped[str] = mapped_column(Text, default="", nullable=False)


class RemediationItem(Base, TimestampMixin):
    """Tracked fix lifecycle per finding (doc 07 §3)."""

    __tablename__ = "remediation_items"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="open", nullable=False)
    assignee_id: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    due_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    justification: Mapped[str | None] = mapped_column(Text, nullable=True)
    approved_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    verified_by_scan_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("scans.id"), nullable=True
    )


class FindingCorrelation(Base, TimestampMixin):
    """A group of findings that describe one underlying issue (WP-E1).

    Nine engines report on the same estate and nothing joined their answers: three of them can find
    the same hardcoded credential, and a customer saw three criticals for one problem. Meanwhile the
    two findings that together mean "the credential is publicly retrievable" sat in different
    sections with nothing saying so.
    """

    __tablename__ = "finding_correlations"
    __table_args__ = (
        UniqueConstraint("tenant_id", "fingerprint", name="uq_correlation_tenant_fingerprint"),
        Index("idx_correlation_tenant_customer", "tenant_id", "customer_id"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    rule: Mapped[str] = mapped_column(String(60), nullable=False)
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    # duplicate | corroboration | chain
    kind: Mapped[str] = mapped_column(String(20), default="duplicate", nullable=False)
    severity: Mapped[str] = mapped_column(String(10), nullable=False)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    rationale: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    member_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)


class FindingCorrelationMember(Base, TimestampMixin):
    """Which findings are in a group, and in what role."""

    __tablename__ = "finding_correlation_members"
    __table_args__ = (Index("idx_correlation_member_finding", "finding_id"),)

    correlation_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("finding_correlations.id", ondelete="CASCADE"), primary_key=True
    )
    finding_id: Mapped[uuid.UUID] = mapped_column(
        ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True
    )
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    role: Mapped[str] = mapped_column(String(20), default="corroborating", nullable=False)
