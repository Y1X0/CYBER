"""Liveness and readiness probes."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import text
from sqlalchemy.orm import Session

from guardian_api.deps import get_db

router = APIRouter()


@router.get("/health")
def health() -> dict:
    return {"status": "ok", "service": "guardian-api"}


@router.get("/health/ready")
def ready(db: Session = Depends(get_db)) -> dict:
    db.execute(text("SELECT 1"))
    return {"status": "ready", "database": "ok"}
