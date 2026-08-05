"""Vulnerability Intelligence read API — look up KB advisories and weaknesses.

Read-only surface over the knowledge base populated by the seed + feed-sync task. Any authenticated
principal in the tenant may read it (the KB is not tenant-specific data).
"""

from __future__ import annotations

import datetime as dt
import uuid

from fastapi import APIRouter, Depends, Query
from guardian_db.models import Vulnerability, Weakness
from pydantic import BaseModel
from sqlalchemy.orm import Session

from guardian_api.deps import Identity, get_current_identity, get_db

router = APIRouter()


class VulnerabilityOut(BaseModel):
    id: uuid.UUID
    external_id: str
    source: str
    summary: str
    cwe_ids: list[str]
    cvss_base: float | None
    epss_score: float | None
    kev: bool
    affected: list
    references: list
    modified_at: dt.datetime | None


class WeaknessOut(BaseModel):
    external_id: str
    name: str
    description: str


@router.get("/vulnerabilities", response_model=list[VulnerabilityOut])
def list_vulnerabilities(
    cve: str | None = Query(default=None),
    package: str | None = Query(default=None),
    kev_only: bool = Query(default=False),
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[VulnerabilityOut]:
    q = db.query(Vulnerability)
    if cve:
        q = q.filter(Vulnerability.external_id == cve.upper())
    if package:
        q = q.filter(Vulnerability.affected.contains([{"package": package.lower()}]))
    if kev_only:
        q = q.filter(Vulnerability.kev.is_(True))
    rows = q.limit(200).all()
    return [VulnerabilityOut.model_validate(r, from_attributes=True) for r in rows]


@router.get("/weaknesses", response_model=list[WeaknessOut])
def list_weaknesses(
    identity: Identity = Depends(get_current_identity),
    db: Session = Depends(get_db),
) -> list[WeaknessOut]:
    rows = db.query(Weakness).order_by(Weakness.external_id).limit(500).all()
    return [WeaknessOut.model_validate(r, from_attributes=True) for r in rows]
