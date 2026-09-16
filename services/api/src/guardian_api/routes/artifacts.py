"""Scan-artifact uploads — the real, authenticated path behind "Upload the .apk / .ipa" (AUD-P1-7).

A `mobile_app` / `ios_app` asset cannot be scanned until its binary is uploaded. These endpoints are
that path: an authenticated, tenant-scoped upload that validates the bytes statically, stores them
Postgres (the durable store), and records an opaque artifact id on the asset for the worker to
resolve. The browser never supplies a filesystem path — it uploads bytes and gets back an id.

Mounted under `/assets`, so the routes are `/assets/{asset_id}/artifact(s)`.

Security posture:
  * `require_staff_write` — same authority as creating the asset; no unauthenticated upload.
  * every lookup is filtered by `identity.tenant_id` on top of the app-role RLS session, so a tenant
    cannot upload to, read, or delete another tenant's asset by changing the id in the URL.
  * the artifact type is derived from the asset kind server-side and the bytes are validated against
    it (static zip inspection, never execution).
  * size is bounded twice — a fast Content-Length pre-check before the body is buffered, and a hard
    cap on the actual read — and the artifact id is opaque and server-generated.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, File, HTTPException, Request, UploadFile, status
from guardian_common.config import get_settings
from guardian_common.logging import get_logger
from guardian_core.artifacts import (
    ArtifactValidationError,
    artifact_kind_for_asset,
    sanitize_filename,
    validate_artifact,
)
from guardian_db.artifact_store import (
    create_artifact,
    delete_artifact,
    get_artifact_meta,
    list_artifacts_for_asset,
)
from guardian_db.audit import record_audit
from guardian_db.models import Asset
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_current_identity, get_db, require_staff_write
from guardian_api.schemas import ArtifactOut

router = APIRouter()
log = get_logger("guardian.api.artifacts")

# A small header/multipart-boundary allowance on top of the artifact byte cap, for the
# Content-Length pre-check (the multipart envelope is slightly larger than the file itself).
_ENVELOPE_ALLOWANCE = 64 * 1024


def _owned_asset(db: Session, asset_id: uuid.UUID, identity: Identity) -> Asset:
    asset = db.get(Asset, asset_id)
    if asset is None or asset.tenant_id != identity.tenant_id:
        # Same 404 whether the asset is another tenant's or does not exist — never confirm existence
        # across a tenant boundary.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")
    return asset


def _enforce_content_length(request: Request) -> None:
    """Reject an over-cap upload from its Content-Length before the body is parsed/buffered.

    Runs as a dependency, which FastAPI resolves before it parses the multipart form, so an honest
    oversized upload is refused up front rather than spooled to the worker's disk first. The
    in-handler read cap is the backstop for a client that omits or understates Content-Length.
    """
    raw = request.headers.get("content-length")
    if raw is None:
        return
    try:
        declared = int(raw)
    except ValueError:
        return
    limit = get_settings().artifact_max_bytes + _ENVELOPE_ALLOWANCE
    if declared > limit:
        mb = get_settings().artifact_max_bytes // (1024 * 1024)
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"the file is too large (limit {mb} MB)",
        )


@router.post("/{asset_id}/artifact", response_model=ArtifactOut, status_code=201)
def upload_artifact(
    asset_id: uuid.UUID,
    request: Request,
    file: UploadFile = File(...),
    identity: Identity = Depends(require_staff_write),
    _limit: None = Depends(_enforce_content_length),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> ArtifactOut:
    asset = _owned_asset(db, asset_id, identity)

    expected_kind = artifact_kind_for_asset(asset.kind)
    if expected_kind is None:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"a {asset.kind} asset is not scanned from an uploaded file",
        )

    max_bytes = get_settings().artifact_max_bytes
    # Read one byte past the cap so an over-limit upload is detected without materializing it all.
    data = file.file.read(max_bytes + 1)
    if len(data) > max_bytes:
        log.info("artifact_upload_rejected", reason="too_large", asset_id=str(asset.id),
                 tenant_id=str(identity.tenant_id))
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"the file is too large (limit {max_bytes // (1024 * 1024)} MB)",
        )

    try:
        validate_artifact(expected_kind, data)
    except ArtifactValidationError as exc:
        # Customer-safe message (no path/tenant/stack); operators see the structured log line.
        log.info("artifact_upload_rejected", reason="invalid", asset_id=str(asset.id),
                 tenant_id=str(identity.tenant_id), detail=str(exc))
        raise HTTPException(status.HTTP_415_UNSUPPORTED_MEDIA_TYPE, str(exc)) from exc

    record = create_artifact(
        db,
        tenant_id=identity.tenant_id,
        customer_id=asset.customer_id,
        asset_id=asset.id,
        kind=expected_kind,
        filename=sanitize_filename(file.filename),
        content_type=file.content_type or "",
        content=data,
        created_by=identity.user.id,
    )

    # Point the asset at the artifact server-side so a scan resolves it by opaque id. Overwrites any
    # prior pointer — re-uploading replaces which artifact the next scan reads. No path is written.
    cfg = dict(asset.config or {})
    cfg["artifact_id"] = str(record.id)
    cfg["artifact_kind"] = expected_kind
    asset.config = cfg

    record_audit(
        db, action="artifact.upload", tenant_id=identity.tenant_id,
        customer_id=asset.customer_id, actor_id=identity.user.id, entity_type="scan_artifact",
        entity_id=str(record.id), ip=ip,
        metadata={"asset_id": str(asset.id), "kind": expected_kind,
                  "size_bytes": record.size_bytes, "sha256": record.sha256},
    )
    db.commit()
    log.info("artifact_upload_accepted", artifact_id=str(record.id), asset_id=str(asset.id),
             tenant_id=str(identity.tenant_id), kind=expected_kind, size_bytes=record.size_bytes)
    return ArtifactOut.model_validate(record, from_attributes=True)


@router.get("/{asset_id}/artifacts", response_model=list[ArtifactOut])
def list_artifacts(
    asset_id: uuid.UUID,
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[ArtifactOut]:
    asset = _owned_asset(db, asset_id, identity)
    rows = list_artifacts_for_asset(db, asset_id=asset.id, tenant_id=identity.tenant_id)
    return [ArtifactOut.model_validate(r, from_attributes=True) for r in rows]


@router.delete("/{asset_id}/artifacts/{artifact_id}", status_code=204)
def remove_artifact(
    asset_id: uuid.UUID,
    artifact_id: uuid.UUID,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> None:
    asset = _owned_asset(db, asset_id, identity)
    record = get_artifact_meta(db, artifact_id=artifact_id, tenant_id=identity.tenant_id)
    if record is None or record.asset_id != asset.id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "artifact not found")
    delete_artifact(db, artifact_id=artifact_id, tenant_id=identity.tenant_id)

    # If the asset pointed at this artifact, clear the pointer so a later scan fails "needs upload"
    # rather than dangling at a deleted id.
    cfg = dict(asset.config or {})
    if cfg.get("artifact_id") == str(artifact_id):
        cfg.pop("artifact_id", None)
        cfg.pop("artifact_kind", None)
        asset.config = cfg

    record_audit(
        db, action="artifact.delete", tenant_id=identity.tenant_id,
        customer_id=asset.customer_id, actor_id=identity.user.id, entity_type="scan_artifact",
        entity_id=str(artifact_id), ip=ip, metadata={"asset_id": str(asset.id)},
    )
    db.commit()
