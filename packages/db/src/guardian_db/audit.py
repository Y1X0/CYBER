"""Helper to append audit-log records (used by both the API and the workers)."""

from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy.orm import Session

from guardian_db.models import AuditLog


def record_audit(
    session: Session,
    *,
    action: str,
    tenant_id: uuid.UUID | None = None,
    customer_id: uuid.UUID | None = None,
    actor_id: uuid.UUID | None = None,
    entity_type: str | None = None,
    entity_id: str | None = None,
    metadata: dict | None = None,
    ip: str | None = None,
) -> AuditLog:
    entry = AuditLog(
        action=action,
        tenant_id=tenant_id,
        customer_id=customer_id,
        actor_id=actor_id,
        entity_type=entity_type,
        entity_id=entity_id,
        metadata_=metadata or {},
        ip=ip,
        created_at=dt.datetime.now(dt.UTC),
    )
    session.add(entry)
    return entry
