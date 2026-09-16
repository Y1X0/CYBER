"""Persistence for the per-scan SBOM.

The SBOM document is built by `guardian_core.sbom` from the SCA engine's resolved inventory; this
module only stores and reads it. Unlike the proof vault there is no encryption or integrity seal —
an SBOM is a deliverable meant to be exported, holds no secret, and is stored as plain JSONB. Tenant
isolation is enforced one level down by Row-Level Security on the table.

One SBOM per scan: `store_sbom` replaces any existing row for the scan so a re-run does not
accumulate stale inventories.
"""

from __future__ import annotations

import uuid

from guardian_core.sbom import Sbom

from guardian_db.models import SbomRecord


def store_sbom(
    session,  # noqa: ANN001 - SQLAlchemy Session
    *,
    tenant_id: uuid.UUID,
    customer_id: uuid.UUID | None,
    scan_id: uuid.UUID,
    asset_id: uuid.UUID | None,
    sbom: Sbom,
) -> SbomRecord:
    """Persist (or replace) the SBOM for a scan, scoped to the scan's tenant/customer."""
    existing = (
        session.query(SbomRecord)
        .filter(SbomRecord.scan_id == scan_id, SbomRecord.tenant_id == tenant_id)
        .first()
    )
    if existing is not None:
        existing.document = sbom.document
        existing.component_count = sbom.component_count
        existing.vulnerable_count = sbom.vulnerable_count
        existing.bom_format = sbom.document.get("bomFormat", "CycloneDX")
        existing.spec_version = sbom.document.get("specVersion", "1.5")
        return existing
    record = SbomRecord(
        tenant_id=tenant_id,
        customer_id=customer_id,
        scan_id=scan_id,
        asset_id=asset_id,
        bom_format=sbom.document.get("bomFormat", "CycloneDX"),
        spec_version=sbom.document.get("specVersion", "1.5"),
        component_count=sbom.component_count,
        vulnerable_count=sbom.vulnerable_count,
        document=sbom.document,
    )
    session.add(record)
    return record


def load_sbom(
    session,  # noqa: ANN001 - SQLAlchemy Session
    *,
    scan_id: uuid.UUID,
    tenant_id: uuid.UUID,
) -> SbomRecord | None:
    """The stored SBOM for a scan, or None. RLS restricts this to the caller's tenant."""
    return (
        session.query(SbomRecord)
        .filter(SbomRecord.scan_id == scan_id, SbomRecord.tenant_id == tenant_id)
        .first()
    )
