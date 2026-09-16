"""Scan artifacts — the uploaded binary an offline engine analyses (AUD-P1-7 / AUD-P1-6).

A `mobile_app` or `ios_app` asset has nothing to scan until its `.apk` / `.ipa` is uploaded. This is
that upload, stored **in Postgres** — the same durable store the SBOM and evidence use — rather than
on the worker's local disk, which on the pilot (Render free tier) is ephemeral and lost on every
restart. Storing it here means the artifact survives to the moment a scan runs and is isolated per
tenant by Row-Level Security like every other tenant-owned table.

Why in the DB and not a filesystem path: the previous design let an asset's free-form `config` name
an arbitrary path on the worker (`apk_path` / `local_path`), so a staff user could point an engine
at `/etc/…` or another tenant's workspace (AUD-P1-6). The artifact is addressed only by its opaque
server-generated id; the worker resolves that id to bytes it wrote to a controlled temp file, and no
browser-supplied string is ever treated as a worker filesystem path.

The `content` bytes are deferred so list/metadata queries never load the blob. An artifact is a
customer's own upload — not a secret we mint — so it is stored as-is (never executed, only read
statically); the platform's existing evidence/report redaction still governs anything derived from
it.
"""

from __future__ import annotations

import uuid

from sqlalchemy import BigInteger, ForeignKey, LargeBinary, String
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class ScanArtifact(Base, TimestampMixin):
    __tablename__ = "scan_artifacts"

    id: Mapped[uuid.UUID] = uuid_pk(db_generated=True)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    # An artifact always belongs to exactly one asset; the scan reads it via that asset. ON DELETE
    # CASCADE so deleting an asset removes its artifacts (no orphaned, indefinitely-stored blob).
    asset_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="CASCADE"), nullable=False
    )
    # The artifact type the engine expects: "apk" (Android) | "ipa" (iOS). Not a MIME type and not a
    # path — a small closed vocabulary the worker matches against the asset kind.
    kind: Mapped[str] = mapped_column(String(10), nullable=False)
    # The uploader's original filename, sanitized to a bare basename. DISPLAY ONLY — never used to
    # build a storage key or a filesystem path (the id is the only address).
    filename: Mapped[str] = mapped_column(String(255), default="", nullable=False)
    content_type: Mapped[str] = mapped_column(String(100), default="", nullable=False)
    size_bytes: Mapped[int] = mapped_column(BigInteger, nullable=False)
    # Content integrity + dedupe signal; lets the worker verify what it read is what was stored.
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)
    # "stored" today; the column exists so a future scan/quarantine state has somewhere to live.
    status: Mapped[str] = mapped_column(String(20), default="stored", nullable=False,
                                        server_default="stored")
    # The raw uploaded bytes. Deferred: a list/metadata query must never pull tens of megabytes.
    content: Mapped[bytes] = mapped_column(LargeBinary, nullable=False, deferred=True)
    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
