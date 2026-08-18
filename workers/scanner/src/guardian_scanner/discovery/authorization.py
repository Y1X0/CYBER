"""Active-discovery authorization gate (Phase 6C) — the mandatory pre-network check.

No active probe touches a target unless a **valid, tenant-owned, in-window, non-revoked**
authorization in the DB grants it. Trust comes only from the `authorizations` table (queried by
tenant), never from caller-supplied input: a client can ask to scan anything, but only a real
authorization row lets it through. A target outside every authorization is denied *before any
socket is opened*, and the denial is recorded in the audit + event trail.

Pure matcher + DB loader are separated so the matching logic is unit-testable without a database.
"""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_core import authorization as authz
from guardian_db.audit import record_audit
from guardian_db.models import Authorization, DomainEvent
from sqlalchemy import select
from sqlalchemy.orm import Session

# Two ways a target can be cleared for active probing, and the gate honours both:
#
# * `active_recon` — an operator recorded a written engagement scope.
# * `ownership_verified` — the customer proved control of the domain itself, by publishing a token
#   only its controller could publish (WP-F1). This is the *stronger* of the two: it is machine
#   checked rather than asserted, so refusing it here would mean a proof Guardian went and read
#   with its own eyes counts for less than a checkbox somebody ticked.
#
# Anything else — `written_consent` on an artifact, say — grants nothing on the network plane.
_RECON_METHODS = ("active_recon", "ownership_verified")


def _host_of(target: str) -> str:
    """Strip a :port suffix (and IPv6 brackets) to get the host/ip used for scope matching."""
    t = target.strip()
    if t.startswith("["):  # [ipv6]:port
        return t[1:].split("]")[0]
    host, sep, port = t.rpartition(":")
    return host if sep and port.isdigit() else t


def target_matches(authorized_targets: list[dict], target: str) -> bool:
    """Pure scope test: does `target` (host or ip, optional :port) fall inside any authorized entry?

    Delegates to `guardian_core.authorization` (WP-H1) so the discovery gate and the scan gate share
    one implementation. They used to have two, which is how a domain the customer had proved they
    own could clear a discovery probe and not a scan of the same host.
    """
    return authz.target_matches(authorized_targets or [], _host_of(target))


def load_recon_authorizations(
    session: Session, *, tenant_id: uuid.UUID, customer_id: uuid.UUID | None, now: dt.datetime
) -> list[Authorization]:
    """Valid probe-granting authorizations for this tenant (+customer if given). DB-trusted only."""
    stmt = (
        select(Authorization)
        .where(Authorization.tenant_id == tenant_id)
        .where(Authorization.method.in_(_RECON_METHODS))
        .where(Authorization.revoked_at.is_(None))
        .where(Authorization.valid_from <= now)
        .where(Authorization.valid_until >= now)
    )
    if customer_id is not None:
        stmt = stmt.where(Authorization.customer_id == customer_id)
    return list(session.execute(stmt).scalars())


def authorize_targets(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    customer_id: uuid.UUID | None,
    run_id: uuid.UUID,
    candidates: list[str],
    now: dt.datetime,
) -> tuple[list[str], list[str]]:
    """Split candidates into (allowed, denied) using only DB authorizations; audit every denial.

    Denials are logged BEFORE any network access (this runs before the provider), so an
    unauthorized target leaves an audit + event trail and never reaches a socket.
    """
    auths = load_recon_authorizations(
        session, tenant_id=tenant_id, customer_id=customer_id, now=now
    )
    merged: list[dict] = []
    for a in auths:
        merged.extend(a.authorized_targets or [])

    allowed: list[str] = []
    denied: list[str] = []
    for target in candidates:
        if merged and target_matches(merged, target):
            allowed.append(target)
        else:
            denied.append(target)
            _record_block(session, tenant_id, customer_id, run_id, target)
    return allowed, denied


def _record_block(
    session: Session, tenant_id: uuid.UUID, customer_id: uuid.UUID | None,
    run_id: uuid.UUID, target: str,
) -> None:
    record_audit(
        session,
        action="discovery.target.blocked",
        tenant_id=tenant_id,
        customer_id=customer_id,
        entity_type="discovery_run",
        entity_id=str(run_id),
        metadata={"target": target, "reason": "no valid authorization in scope"},
    )
    session.add(DomainEvent(
        tenant_id=tenant_id, customer_id=customer_id, type="discovery.target.blocked",
        payload={"target": target, "run_id": str(run_id)},
        occurred_at=dt.datetime.now(dt.UTC),
    ))
