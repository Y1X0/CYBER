"""Proof-of-Vulnerability vault — encrypted, per-tenant storage of safe reproduction evidence.

One row is the durable, auditable proof for one finding: the benign reproduction that demonstrates
the weakness and the safe check that a regression retest replays. The sensitive body is stored
ENCRYPTED (`sealed_proof`, via the credential KMS) and never in plaintext, and the row is isolated
per tenant by Row-Level Security like every other tenant-owned table.

The safety invariant lives one layer up, in `guardian_core.proof`: a row only ever exists for a
reproduction that passed the gate, so the vault cannot hold a working exploit — this table is the
encrypted *storage* for that already-safe, already-redacted proof, plus an integrity hash so
tampering with the ciphertext at rest is detectable on read.
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class ProofRecord(Base, TimestampMixin):
    __tablename__ = "proof_of_vulnerabilities"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    customer_id: Mapped[uuid.UUID | None] = mapped_column(
        ForeignKey("customers.id"), nullable=True)
    finding_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("findings.id"), nullable=False)

    # Non-sensitive metadata, safe to index/filter on.
    vuln_class: Mapped[str] = mapped_column(String(64), default="", nullable=False)
    method: Mapped[str] = mapped_column(String(40), default="", nullable=False)
    # The invariant marker: a row is only written for a reproduction that passed the safety gate.
    safe: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # The proof body — already redacted by guardian_core.proof, then ENCRYPTED at rest. Never a
    # plaintext reproduction, never a secret.
    sealed_proof: Mapped[str] = mapped_column(Text, nullable=False)
    # SHA-256 of the plaintext proof JSON, checked on read: detects tampering with the ciphertext.
    content_sha256: Mapped[str] = mapped_column(String(64), nullable=False)

    created_by: Mapped[uuid.UUID | None] = mapped_column(ForeignKey("users.id"), nullable=True)
