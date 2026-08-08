"""Attack-graph read-only analysis API (Phase 6D) — Control Plane only.

Exposure paths, blast radius, chokepoints, and exposure drift over the graph the discovery pipeline
already built. Every endpoint is READ-ONLY (GET), staff-only, tenant-scoped, and bounded.
It opens no socket and never runs on the recon worker — the projector reads the RLS-enforced app
session and the deterministic algorithms live in `guardian_core.attack_graph`.

Naming is honest to the data: a path is an *internet exposure path* to an exposed service/asset, not
"internet → vulnerability" — no finding nodes or `exposes` edges. Vulnerability severity is
returned as enrichment on the node, never as a hop in the path.
"""

from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Query, status
from guardian_db.graph_read import DbGraphProjector
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db
from guardian_api.schemas import (
    BlastRadiusOut,
    ChokepointsOut,
    DriftOut,
    ExposurePathsOut,
    ReachableOut,
)

router = APIRouter()


def _staff(identity: Identity = Depends(get_current_identity)) -> Identity:
    """Graph analysis is an internal-staff capability (read-only)."""
    if not identity.is_staff:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "graph analysis requires a staff role")
    return identity


@router.get("/exposure-paths", response_model=ExposurePathsOut)
def get_exposure_paths(
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    max_depth: int = Query(default=6, ge=1, le=6),
    limit: int = Query(default=100, ge=1, le=100),
) -> ExposurePathsOut:
    out = DbGraphProjector(db).exposure_paths(
        tenant_id=str(identity.tenant_id), max_depth=max_depth, limit=limit
    )
    return ExposurePathsOut.model_validate(out)


@router.get("/attack-paths", response_model=ExposurePathsOut)
def get_attack_paths(
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    max_depth: int = Query(default=6, ge=1, le=6),
    limit: int = Query(default=100, ge=1, le=100),
) -> ExposurePathsOut:
    """Real attack paths (6E): internet → ... → service → serves → asset → exposes → finding.

    Distinct from /exposure-paths (unchanged): a path ends at a real finding and exists only
    where the data's edges do — no `enables`, no invented hops.
    """
    out = DbGraphProjector(db).attack_paths(
        tenant_id=str(identity.tenant_id), max_depth=max_depth, limit=limit
    )
    return ExposurePathsOut.model_validate(out)


@router.get("/chokepoints", response_model=ChokepointsOut)
def get_chokepoints(
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    top: int = Query(default=10, ge=1, le=100),
    max_depth: int = Query(default=6, ge=1, le=6),
) -> ChokepointsOut:
    out = DbGraphProjector(db).chokepoints(
        tenant_id=str(identity.tenant_id), top=top, max_depth=max_depth
    )
    return ChokepointsOut.model_validate(out)


@router.get("/drift", response_model=DriftOut)
def get_exposure_drift(
    since: str,
    until: str,
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
) -> DriftOut:
    try:
        out = DbGraphProjector(db).exposure_drift(
            tenant_id=str(identity.tenant_id), since=since, until=until
        )
    except ValueError:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY, "since/until must be ISO-8601 timestamps"
        ) from None
    return DriftOut.model_validate(out)


@router.get("/nodes/{node_id}/blast-radius", response_model=BlastRadiusOut)
def get_blast_radius(
    node_id: uuid.UUID,
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    max_depth: int = Query(default=6, ge=1, le=6),
) -> BlastRadiusOut:
    out = DbGraphProjector(db).blast_radius(
        tenant_id=str(identity.tenant_id), node_type="", node_id=str(node_id), max_depth=max_depth
    )
    return BlastRadiusOut.model_validate(out)


@router.get("/nodes/{node_id}/paths", response_model=ExposurePathsOut)
def get_paths_to(
    node_id: uuid.UUID,
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    max_depth: int = Query(default=6, ge=1, le=6),
) -> ExposurePathsOut:
    paths = DbGraphProjector(db).paths_to(
        tenant_id=str(identity.tenant_id), target_type="", target_id=str(node_id),
        max_depth=max_depth,
    )
    return ExposurePathsOut.model_validate({"paths": paths, "truncated": False})


@router.get("/nodes/{node_id}/reachable", response_model=ReachableOut)
def get_reachable_from(
    node_id: uuid.UUID,
    identity: Identity = Depends(_staff),
    db: Session = Depends(get_db),
    max_depth: int = Query(default=6, ge=1, le=6),
) -> ReachableOut:
    nodes = DbGraphProjector(db).reachable_from(
        tenant_id=str(identity.tenant_id), src_type="", src_id=str(node_id), max_depth=max_depth
    )
    return ReachableOut.model_validate({"nodes": nodes, "from_id": str(node_id)})
