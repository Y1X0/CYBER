"""Request/response DTOs (Pydantic v2). Typed edges guard the API boundary (doc 01 §9)."""

from __future__ import annotations

import datetime as dt
import uuid

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Auth ──
class LoginRequest(BaseModel):
    email: EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"  # noqa: S105 - field name only, not a secret
    expires_in: int


class MembershipOut(BaseModel):
    tenant_id: uuid.UUID
    role: str


class MeResponse(BaseModel):
    id: uuid.UUID
    email: str
    name: str
    tenant_id: uuid.UUID
    staff_role: str | None
    portal_customer_id: uuid.UUID | None


# ── Customers ──
class CustomerCreate(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    criticality: str = Field(default="medium", pattern="^(low|medium|high|critical)$")


class CustomerOut(BaseModel):
    id: uuid.UUID
    name: str
    criticality: str
    status: str
    created_at: dt.datetime


# ── Assets ──
class AssetCreate(BaseModel):
    customer_id: uuid.UUID
    name: str = Field(min_length=1, max_length=200)
    kind: str = Field(pattern="^(repo|web|api|cloud_account|container_image|k8s_manifest)$")
    identifier: str = Field(default="", max_length=2048)
    exposure: str = Field(default="unknown", pattern="^(public|internal|unknown)$")
    config: dict = Field(default_factory=dict)

    @field_validator("config")
    @classmethod
    def _bound_config_size(cls, v: dict) -> dict:
        # Cap serialized config to prevent oversized-payload DoS (also bounds inline_content).
        import json

        if len(json.dumps(v)) > 262_144:  # 256 KiB
            raise ValueError("config exceeds maximum size (256 KiB)")
        return v


class AssetOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    name: str
    kind: str
    identifier: str
    exposure: str
    created_at: dt.datetime


# ── Scans ──
class ScanCreate(BaseModel):
    asset_id: uuid.UUID
    engines: list[str] = Field(default_factory=lambda: ["secrets"])
    ref: str | None = None
    trigger: str = Field(default="manual", pattern="^(manual|schedule|webhook|ci)$")


class ScanOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    asset_id: uuid.UUID
    status: str
    trigger: str
    ref: str | None
    requested_engines: list[str]
    stats: dict
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    created_at: dt.datetime


# ── Findings ──
class FindingOut(BaseModel):
    id: uuid.UUID
    scan_id: uuid.UUID
    asset_id: uuid.UUID
    title: str
    category: str
    severity: str
    risk_score: int
    risk_rationale: list
    confidence: str
    status: str
    source: str
    cwe_id: str | None
    owasp_ref: str | None
    cve_ids: list[str]
    location: dict
    evidence: dict
    references: dict
    created_at: dt.datetime


class FindingTriage(BaseModel):
    """Human-pentester triage action (workflow, doc 07 §6)."""

    status: str | None = Field(
        default=None,
        pattern="^(open|triaged|confirmed|false_positive|accepted_risk|resolved)$",
    )
    severity_override: str | None = Field(default=None, pattern="^(critical|high|medium|low|info)$")
    note: str = Field(default="", max_length=4000)


# ── Reports (pentester + reviewer approval flow) ──
class ReportCreate(BaseModel):
    scan_id: uuid.UUID
    title: str = Field(default="", max_length=300)


class ReportAction(BaseModel):
    notes: str = Field(default="", max_length=4000)


class ReportApprovalOut(BaseModel):
    actor_id: uuid.UUID
    decision: str
    notes: str
    created_at: dt.datetime


class ReportOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID
    scan_id: uuid.UUID | None
    title: str
    status: str
    summary: dict
    created_at: dt.datetime
