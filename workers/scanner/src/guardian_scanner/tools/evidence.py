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

from guardian_common.logging import get_logger
from guardian_core.redaction import scrub as _value_scrub
from guardian_core.tool import RawEvidence, evidence_to_wire
from guardian_db.models import EvidenceItem
from sqlalchemy import select
from sqlalchemy.orm import Session

log = get_logger("guardian.tools.evidence")

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


def _canonical(evidence: RawEvidence) -> tuple[str, list[str]]:
    """Return (canonical JSON, redaction hits).

    Two passes, because they catch different failures. `_scrub` drops keys whose NAME is sensitive
    (`password`, `token`, …) — the value never appears at all. But a provider can also place a
    credential in a benignly-named field: gitleaks reports the secret VALUE in `Match`, which no
    key-name check would catch, and the DB and UI read straight from this canonical content. So a
    second, value-based pass (`guardian_core.redaction.scrub`) masks anything credential-SHAPED —
    AWS keys, GitHub/Slack/Stripe tokens, JWTs, PEM private keys, `password=` assignments — wherever
    it sits. The egress scrubber already did this before anything reached the model or a webhook;
    this closes the same gap at persistence, so the raw value never lands in `evidence_items` or the
    console in the first place.

    A hit here is a provider defect (it tried to persist a raw credential), so the hits are returned
    to be logged, never silently swallowed.
    """
    wire = evidence_to_wire(evidence)
    wire["data"] = _scrub(wire.get("data") or {})
    wire["provenance"] = _scrub(wire.get("provenance") or {})
    redacted, hits = _value_scrub(wire)
    return json.dumps(redacted, sort_keys=True, separators=(",", ":")), hits


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
        canonical, hits = _canonical(e)
        if hits:
            # A credential value reached persistence in a non-sensitively-named field. It has been
            # masked, so nothing leaks — but the provider should never have emitted it, so record
            # the defect with the tool and target (never the value) for follow-up.
            log.warning("evidence_credential_redacted_at_persist",
                        tool=e.tool, target=e.target, kind=e.kind, patterns=sorted(set(hits)))
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
    """Recompute the tenant's chain and confirm every link — tamper detection for tests/audit.

    The chain is self-describing: order is reconstructed by following ``prev_hash`` (the genesis
    link has ``prev_hash IS NULL``; each successor is the item whose ``prev_hash`` equals the
    current ``content_sha256``), NOT by ``created_at``/``id``. Items persisted in one transaction
    share a ``now()`` timestamp, so timestamp ordering is ambiguous and tiebreaks on the random
    UUID — this walks the links instead. A missing/duplicate genesis link, a fork, a break in the
    middle, or a tampered item all fail closed.
    """
    rows = list(session.execute(
        select(EvidenceItem).where(EvidenceItem.tenant_id == tenant_id)
    ).scalars())
    if not rows:
        return True

    by_prev: dict[str | None, list[EvidenceItem]] = {}
    for r in rows:
        by_prev.setdefault(r.prev_hash, []).append(r)

    seen = 0
    prev: str | None = None
    nexts = by_prev.get(None, [])            # the single genesis link (prev_hash IS NULL)
    while nexts:
        if len(nexts) != 1:
            return False                     # missing or forked link ⇒ tampered/ambiguous chain
        item = nexts[0]
        canonical = json.dumps(item.detail, sort_keys=True, separators=(",", ":"))
        if item.prev_hash != prev or item.content_sha256 != _hash(prev or "", canonical):
            return False
        seen += 1
        if seen > len(rows):
            return False                     # absolute loop bound (defensive)
        prev = item.content_sha256
        nexts = by_prev.get(prev, [])
    return seen == len(rows)                  # every item must belong to the single verified chain
