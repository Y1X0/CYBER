"""Vulnerability Intelligence knowledge base (doc 03, user's Phase 2 idea #1).

Normalized store for CVEs/advisories (NVD, OSV, GHSA), the CWE catalog, curated best-practice
entries, and feed-sync bookkeeping. The SCA engine matches dependencies against `vulnerabilities`;
the AI analyst (Phase 3) will retrieve from `kb_entries`.
"""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import Boolean, DateTime, Index, Integer, Numeric, String, Text, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Vulnerability(Base, TimestampMixin):
    """A normalized advisory record (CVE / GHSA / OSV id)."""

    __tablename__ = "vulnerabilities"
    __table_args__ = (
        Index("idx_vuln_external", "external_id", unique=True),
        Index("idx_vuln_affected", "affected", postgresql_using="gin"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)  # e.g. CVE-2024-1234
    source: Mapped[str] = mapped_column(String(20), default="osv", nullable=False)  # nvd|osv|ghsa
    summary: Mapped[str] = mapped_column(Text, default="", nullable=False)
    details: Mapped[str] = mapped_column(Text, default="", nullable=False)

    cwe_ids: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    cvss_vector: Mapped[str | None] = mapped_column(String(120), nullable=True)
    cvss_base: Mapped[float | None] = mapped_column(Numeric(3, 1), nullable=True)
    epss_score: Mapped[float | None] = mapped_column(Numeric, nullable=True)
    kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    # OSV-style affected ranges: [{"ecosystem","package","ranges":[...],"versions":[...]}]
    affected: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    references: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    published_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    modified_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class Weakness(Base, TimestampMixin):
    """CWE catalog entry."""

    __tablename__ = "weaknesses"

    id: Mapped[uuid.UUID] = uuid_pk()
    external_id: Mapped[str] = mapped_column(String(20), unique=True, nullable=False)  # CWE-###
    name: Mapped[str] = mapped_column(String(300), nullable=False)
    description: Mapped[str] = mapped_column(Text, default="", nullable=False)
    relationships: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class Advisory(Base, TimestampMixin):
    """Raw source advisory payload (provenance for `vulnerabilities`)."""

    __tablename__ = "advisories"

    id: Mapped[uuid.UUID] = uuid_pk()
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    external_id: Mapped[str] = mapped_column(String(64), nullable=False)
    url: Mapped[str | None] = mapped_column(Text, nullable=True)
    payload: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    fetched_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class KbEntry(Base, TimestampMixin):
    """Curated best-practice / remediation guidance (OWASP/CIS/ASVS). Phase 3 adds embeddings."""

    __tablename__ = "kb_entries"

    id: Mapped[uuid.UUID] = uuid_pk()
    kind: Mapped[str] = mapped_column(String(40), nullable=False)  # best_practice | remediation
    title: Mapped[str] = mapped_column(String(300), nullable=False)
    body: Mapped[str] = mapped_column(Text, default="", nullable=False)
    standards: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    tags: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)


class FeedSync(Base, TimestampMixin):
    """Bookkeeping for scheduled feed updates (NVD, OSV, GHSA, EPSS, KEV)."""

    __tablename__ = "feed_syncs"
    __table_args__ = (UniqueConstraint("source", "cursor", name="uq_feedsync_source_cursor"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="pending", nullable=False)
    items_ingested: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    cursor: Mapped[str | None] = mapped_column(String(120), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
