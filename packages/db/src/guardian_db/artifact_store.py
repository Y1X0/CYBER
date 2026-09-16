"""Persistence for uploaded scan artifacts (.apk / .ipa).

Thin CRUD over `ScanArtifact`, kept out of the route so the worker can resolve an artifact without
importing the API. Tenant isolation is enforced one level down by Row-Level Security on the table
for the API's app-role session; the worker runs as the owner (RLS-bypassed) and therefore passes
`tenant_id` explicitly on every call here — the same discipline every other worker query follows.

Content bytes are deferred on the model, so `list_artifacts_for_asset` and `get_artifact_meta` never
load a blob; only `load_artifact_content` pulls it, and only the worker does that.
"""

from __future__ import annotations

import hashlib
import uuid

from sqlalchemy.orm import Session, undefer

from guardian_db.models import ScanArtifact


def create_artifact(
    session: Session,
    *,
    tenant_id: uuid.UUID,
    customer_id: uuid.UUID,
    asset_id: uuid.UUID,
    kind: str,
    filename: str,
    content_type: str,
    content: bytes,
    created_by: uuid.UUID | None,
) -> ScanArtifact:
    """Store an artifact's bytes and metadata. Caller has already validated size/type/ownership."""
    record = ScanArtifact(
        tenant_id=tenant_id,
        customer_id=customer_id,
        asset_id=asset_id,
        kind=kind,
        filename=filename,
        content_type=content_type,
        size_bytes=len(content),
        sha256=hashlib.sha256(content).hexdigest(),
        content=content,
        created_by=created_by,
    )
    session.add(record)
    session.flush()
    return record


def get_artifact_meta(
    session: Session, *, artifact_id: uuid.UUID, tenant_id: uuid.UUID
) -> ScanArtifact | None:
    """Metadata for one artifact (no blob), scoped to the tenant. RLS also restricts the app."""
    return (
        session.query(ScanArtifact)
        .filter(ScanArtifact.id == artifact_id, ScanArtifact.tenant_id == tenant_id)
        .first()
    )


def list_artifacts_for_asset(
    session: Session, *, asset_id: uuid.UUID, tenant_id: uuid.UUID
) -> list[ScanArtifact]:
    """All artifacts attached to an asset (no blobs), newest first."""
    return (
        session.query(ScanArtifact)
        .filter(ScanArtifact.asset_id == asset_id, ScanArtifact.tenant_id == tenant_id)
        .order_by(ScanArtifact.created_at.desc())
        .all()
    )


def load_artifact_content(
    session: Session, *, artifact_id: uuid.UUID, tenant_id: uuid.UUID, asset_id: uuid.UUID
) -> ScanArtifact | None:
    """The full artifact WITH its bytes, resolved by (id, tenant, asset).

    The worker calls this. Requiring the asset id too means a browser that smuggled some other
    artifact's id into an asset's config cannot make the worker read it: the row only returns when
    the id, the tenant, AND the owning asset all line up.
    """
    return (
        session.query(ScanArtifact)
        .options(undefer(ScanArtifact.content))
        .filter(
            ScanArtifact.id == artifact_id,
            ScanArtifact.tenant_id == tenant_id,
            ScanArtifact.asset_id == asset_id,
        )
        .first()
    )


def delete_artifact(
    session: Session, *, artifact_id: uuid.UUID, tenant_id: uuid.UUID
) -> bool:
    """Delete an artifact by id within the tenant. Returns whether a row was removed."""
    record = get_artifact_meta(session, artifact_id=artifact_id, tenant_id=tenant_id)
    if record is None:
        return False
    session.delete(record)
    return True
