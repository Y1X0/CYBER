"""Aggregate the v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from guardian_api.routes import assets, auth, customers, findings, health, scans

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])

v1 = APIRouter(prefix="/api/v1")
v1.include_router(auth.router, prefix="/auth", tags=["auth"])
v1.include_router(customers.router, prefix="/customers", tags=["customers"])
v1.include_router(assets.router, prefix="/assets", tags=["assets"])
v1.include_router(scans.router, prefix="/scans", tags=["scans"])
v1.include_router(findings.router, prefix="/findings", tags=["findings"])
api_router.include_router(v1)
