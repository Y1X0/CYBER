"""Aggregate the v1 API router."""

from __future__ import annotations

from fastapi import APIRouter

from guardian_api.routes import (
    apikeys,
    assets,
    auth,
    chat,
    compliance,
    customers,
    dashboard,
    discovery,
    findings,
    graph,
    health,
    knowledge_base,
    remediation,
    reports,
    scans,
    verifications,
    webhook_endpoints,
    webhooks,
)

api_router = APIRouter()
api_router.include_router(health.router, tags=["health"])
# Webhooks are HMAC-verified, not JWT-authenticated — mounted outside /api/v1.
api_router.include_router(webhooks.router, prefix="/webhooks", tags=["webhooks"])

v1 = APIRouter(prefix="/api/v1")
v1.include_router(auth.router, prefix="/auth", tags=["auth"])
v1.include_router(apikeys.router, prefix="/api-keys", tags=["api-keys"])
v1.include_router(customers.router, prefix="/customers", tags=["customers"])
v1.include_router(assets.router, prefix="/assets", tags=["assets"])
v1.include_router(verifications.router, prefix="/verifications", tags=["ownership"])
v1.include_router(scans.router, prefix="/scans", tags=["scans"])
v1.include_router(discovery.router, prefix="/discovery", tags=["discovery"])
v1.include_router(graph.router, prefix="/graph", tags=["graph"])
v1.include_router(findings.router, prefix="/findings", tags=["findings"])
v1.include_router(reports.router, prefix="/reports", tags=["reports"])
v1.include_router(compliance.router, prefix="/compliance", tags=["compliance"])
v1.include_router(remediation.router, prefix="/remediation", tags=["remediation"])
v1.include_router(webhook_endpoints.router, prefix="/webhook-endpoints",
                  tags=["webhooks"])
v1.include_router(knowledge_base.router, prefix="/knowledge-base", tags=["knowledge-base"])
v1.include_router(chat.router, prefix="/chat", tags=["chat"])
v1.include_router(dashboard.router, prefix="/dashboard", tags=["dashboard"])
api_router.include_router(v1)
