"""Evidence capture (Framework Phase 1) — RawEvidence → hash-chained EvidenceItem, trusted plane.

Evidence is the heart of the platform: proof of WHAT a tool observed, tamper-evident and verifiable.
Each item stores `content_sha256 = sha256(prev_hash + canonical_content)` and `prev_hash` (the prior
item's hash), so altering any earlier item breaks every later hash — a real chain of custody, over
the `evidence_items` table (no migration).

A secret is NEVER evidence: sensitive-looking keys are scrubbed from evidence content before hashing
or storage, on top of the contract that RawEvidence/ToolJob carry no credential material.
"""

from __future__ import annotations

import hashlib
import json
import uuid

from guardian_core.tool import RawEvidence, evidence_to_wire
from guardian_db.models import EvidenceItem
from sqlalchemy import select
from sqlalchemy.orm import Session

# Keys never persisted or hashed into evidence (defense in depth; a secret is not proof).
_SENSITIVE_KEYS = ("secret", "credential", "password", "passwd", "token", "api_key",
                   "apikey", "private_key", "authorization", "cookie", "session")


def _scrub(value):  # noqa: ANN001, ANN201
    """Recursively drop sensitive-looking keys so a credential can never land in evidence."""
    if isinstance(value, dict):
        return {k: _scrub(v) for k, v in value.items()
                if not any(s in str(k).lower() for s in _SENSITIVE_KEYS)}
    if isinstance(value, list):
        return [_scrub(v) for v in value]
    return value


def _canonical(evidence: RawEvidence) -> str:
    wire = evidence_to_wire(evidence)
    wire["data"] = _scrub(wire.get("data") or {})
    wire["provenance"] = _scrub(wire.get("provenance") or {})
    return json.dumps(wire, sort_keys=True, separators=(",", ":"))


def _hash(prev_hash: str, canonical: str) -> str:
    return hashlib.sha256(((prev_hash or "") + canonical).encode("utf-8")).hexdigest()


def _order_key(e: RawEvidence) -> tuple:
    return (e.occurred_at, e.execution_id, e.target, e.kind)


def _latest_hash(session: Session, tenant_id: uuid.UUID) -> str | None:
    """The most recent item hash to continue the tenant chain (deterministic by created_at,id)."""
    row = session.execute(
        select(EvidenceItem.content_sha256)
        .where(EvidenceItem.tenant_id == tenant_id)
        .order_by(EvidenceItem.created_at.desc(), EvidenceItem.id.desc())
        .limit(1)
    ).scalar_one_or_none()
    return row


def persist_evidence_chain(
    session: Session, *, tenant_id: uuid.UUID, evidences: list[RawEvidence],
    created_by: uuid.UUID | None = None,
) -> list[uuid.UUID]:
    """Persist RawEvidence as hash-chained EvidenceItems (tenant-scoped). Returns ids."""
    prev = _latest_hash(session, tenant_id)
    ids: list[uuid.UUID] = []
    for e in sorted(evidences, key=_order_key):
        canonical = _canonical(e)
        digest = _hash(prev or "", canonical)
        item = EvidenceItem(
            tenant_id=tenant_id, finding_id=None, kind=e.kind[:30] or "tool",
            summary=f"{e.tool}:{e.target}"[:300], detail=json.loads(canonical),
            content_sha256=digest, prev_hash=prev, created_by=created_by,
        )
        session.add(item)
        session.flush()
        ids.append(item.id)
        prev = digest
    return ids


def verify_chain(session: Session, tenant_id: uuid.UUID) -> bool:
    """Recompute the tenant's chain and confirm every link — tamper detection for tests/audit."""
    rows = list(session.execute(
        select(EvidenceItem)
        .where(EvidenceItem.tenant_id == tenant_id)
        .order_by(EvidenceItem.created_at.asc(), EvidenceItem.id.asc())
    ).scalars())
    prev: str | None = None
    for item in rows:
        expected = _hash(prev or "", json.dumps(item.detail, sort_keys=True, separators=(",", ":")))
        if item.prev_hash != prev or item.content_sha256 != expected:
            return False
        prev = item.content_sha256
    return True
