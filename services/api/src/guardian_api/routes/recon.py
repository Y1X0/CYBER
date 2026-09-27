"""Owner-direct RECON dispatch — the OWNER-ONLY entry point for governed active port scanning.

This is the exact analogue of the owner-direct branch in `scans.py`, for the network recon plane. It
is the FIRST and ONLY API path that can start an nmap port scan, and it is locked down the same way
owner-direct scanning is:

  * OWNER-ONLY, re-checked server-side from the resolved identity (never a client flag, never an API
    key, never a borrowed role). A non-owner can NEVER invoke recon — even with a verified-ownership
    authorization — and every refusal is audited.
  * OFF by default: the capability does not exist until an operator sets the enable flag.
  * A one-time, per-target LEGAL affirmation ("I affirm I have the legal right to port-scan the
    target") is required before the first scan of a target; it is stored immutably and written to
    the audit log. Subsequent scans of the same target skip the prompt.
  * Both the affirmation and the dispatch are recorded in the immutable audit log with the authority
    note, mirroring `scans.py`.

This route NEVER opens a socket and never forces isolation itself — it only decides authority and
publishes. The job then runs through the governance-gated tool path (`dispatch_tool_job` →
`run_tool`), which RE-CHECKS owner-direct server-side and runs nmap inside the MANDATORY
uid+nftables egress cage on the isolated recon plane. The DB-authorization gate and egress cage are
untouched (defense in depth).
"""

from __future__ import annotations

import datetime as dt
import ipaddress

from fastapi import APIRouter, Depends, HTTPException, Request, status
from guardian_common.config import get_settings
from guardian_core.enums import AuthorizationBasis, StaffRole
from guardian_db.audit import record_audit
from guardian_db.models import Asset, ReconAffirmation
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, client_ip, get_db, require_staff_write
from guardian_api.publisher import enqueue_owner_direct_recon

router = APIRouter()


class ReconDispatchCreate(BaseModel):
    # The recon target: an IP address literal (nmap scans IPs; a hostname is rejected so a value can
    # never smuggle a flag and so the egress cage can pin the destination). An optional :port is not
    # accepted here — ports are the tool capability's allowlist, narrowed by `ports` below.
    target: str
    # Optional asset to bind findings to (and to report under). Owner-direct recon bypasses the DB
    # authorization, so without this the run is evidence-only; with it, findings bind to this asset
    # and the Scan is labeled owner-direct-recon.
    asset_id: str | None = None
    # Optional narrowing of the port set (must be a subset of the nmap capability allowlist; the
    # tool policy narrows it deterministically and can never widen it).
    ports: list[int] | None = None
    # `affirm=true` records the owner's legal-right affirmation for this target the first time it is
    # scanned this way. It is a request to record the affirmation, never a grant of authority.
    affirm: bool = False


def _recon_target(value: str) -> str:
    """The per-target key an owner affirms once. Normalized (stripped, lowercased) so the same host
    in different casing is the same target."""
    return (value or "").strip().lower()


def _recon_affirmation_text(target: str) -> str:
    return (
        f"I affirm that I have the legal right and authority to run an active port scan against "
        f"{target}, that I have obtained any permission required to do so, and I accept "
        f"responsibility for this authorization."
    )


def _is_owner(identity: Identity) -> bool:
    """A human (never a machine key) whose resolved staff role is OWNER. `staff_role` is resolved
    server-side from the authenticated principal, and a key holds no staff role, so it can never
    satisfy this — identical to the owner check in scans.py."""
    return (not identity.is_machine) and identity.staff_role == StaffRole.OWNER.value


def _valid_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address((value or "").strip()))
    except ValueError:
        return None


@router.post("", status_code=202)
def dispatch_recon(
    body: ReconDispatchCreate,
    request: Request,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
    ip: str | None = Depends(client_ip),
) -> dict:
    """Dispatch an owner-direct nmap port scan. Owner-only, feature-flagged, per-target affirmed."""
    settings = get_settings()

    # (1) OWNER-only, re-checked here from the resolved identity — never a client flag, never a
    # borrowed/inherited role, never an API key. A non-owner is refused outright, even if they hold
    # a verified-ownership authorization for the target.
    if not _is_owner(identity):
        record_audit(
            db, action="recon.owner_direct.denied", tenant_id=identity.tenant_id,
            actor_id=identity.user.id, entity_type="recon", entity_id=_recon_target(body.target),
            ip=ip, metadata={"reason": "not_owner", "role": identity.staff_role},
        )
        db.commit()
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "owner-direct recon requires the tenant owner role",
        )

    # (6) Off by default: the capability does not exist until an operator enables it.
    if not settings.owner_direct_recon:
        raise HTTPException(
            status.HTTP_403_FORBIDDEN,
            "owner-direct recon is disabled on this deployment",
        )

    # nmap scans an IP: reject anything that is not an IP literal (so a value can never smuggle a
    # flag and so the egress cage can pin the destination).
    ip_target = _valid_ip(body.target)
    if ip_target is None:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            "recon target must be an IP address (nmap scans IPs; resolve a hostname first)",
        )

    # An asset, when given, must belong to this tenant — findings bind to it and it is reported on.
    if body.asset_id is not None:
        asset = db.get(Asset, body.asset_id)
        if asset is None or asset.tenant_id != identity.tenant_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "asset not found")

    # (4) One-time, per-target legal affirmation before the first owner-direct recon of a target.
    target = _recon_target(ip_target)
    affirmed = db.execute(
        select(ReconAffirmation).where(
            ReconAffirmation.tenant_id == identity.tenant_id,
            ReconAffirmation.target == target,
        )
    ).scalar_one_or_none()
    if affirmed is None:
        if not body.affirm:
            # Not an error to retry blindly: the client must show the affirmation and resend with
            # affirm=true. 409 carries the exact legal text and target for that prompt.
            raise HTTPException(
                status.HTTP_409_CONFLICT,
                detail={
                    "code": "recon_affirmation_required",
                    "target": target,
                    "affirmation": _recon_affirmation_text(target),
                },
            )
        db.add(ReconAffirmation(
            tenant_id=identity.tenant_id, target=target,
            affirmed_by=identity.user.id, affirmed_at=dt.datetime.now(dt.UTC),
        ))
        db.flush()
        # The affirmation itself, in the immutable audit log (accountability, not just state).
        record_audit(
            db, action="recon.affirmed", tenant_id=identity.tenant_id,
            actor_id=identity.user.id, entity_type="recon", entity_id=target, ip=ip,
            metadata={"target": target, "affirmation": _recon_affirmation_text(target)},
        )

    # (3) The owner-direct recon dispatch, recorded immutably: who, when, target, and that it ran
    # under owner-direct-recon authority. This is the accountability record, mirroring scans.py.
    record_audit(
        db, action="recon.dispatch", tenant_id=identity.tenant_id,
        actor_id=identity.user.id, entity_type="recon", entity_id=target, ip=ip,
        metadata={
            "target": target,
            "asset_id": str(body.asset_id) if body.asset_id else None,
            "basis": AuthorizationBasis.OWNER_DIRECT_RECON.value,
            "authority": "owner-direct-recon: active port scan authorized by tenant owner",
            "ports": body.ports,
        },
    )
    db.commit()

    enqueue_owner_direct_recon(
        tenant_id=str(identity.tenant_id), actor_id=str(identity.user.id),
        target=ip_target, asset_id=str(body.asset_id) if body.asset_id else None,
        ports=body.ports,
    )
    return {
        "status": "recon_queued",
        "target": target,
        "asset_id": str(body.asset_id) if body.asset_id else None,
        "authorization_basis": AuthorizationBasis.OWNER_DIRECT_RECON.value,
    }


@router.get("/preflight", response_model=dict)
def recon_preflight(
    target: str | None = None,
    identity: Identity = Depends(require_staff_write),
    db: Session = Depends(get_db),
) -> dict:
    """Can this caller run owner-direct recon, and (if a target is given) is it already affirmed?

    Read-only. Lets the UI show the recon control (and the affirmation prompt) only when it would be
    honored, instead of learning that from a failed POST. It never grants anything: the
    authoritative checks re-run on the dispatch itself, and again on the trusted dispatch plane.
    """
    settings = get_settings()
    is_owner = _is_owner(identity)
    normalized: str | None = None
    affirmed_row = None
    if target is not None:
        ip_target = _valid_ip(target)
        if ip_target is None:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY, "recon target must be an IP address")
        normalized = _recon_target(ip_target)
        affirmed_row = db.execute(
            select(ReconAffirmation).where(
                ReconAffirmation.tenant_id == identity.tenant_id,
                ReconAffirmation.target == normalized,
            )
        ).scalar_one_or_none()
    return {
        "eligible": bool(settings.owner_direct_recon and is_owner),
        "enabled": settings.owner_direct_recon,
        "is_owner": is_owner,
        "target": normalized,
        "affirmed": affirmed_row is not None,
        "affirmation_text": (_recon_affirmation_text(normalized) if normalized
                             else "I affirm that I have the legal right and authority to run an "
                                  "active port scan against this target."),
    }
