"""Request/response DTOs (Pydantic v2). Typed edges guard the API boundary (doc 01 §9)."""

from __future__ import annotations

import datetime as dt
import uuid

from guardian_core.enums import AssetKind
from pydantic import BaseModel, EmailStr, Field, field_validator

_ASSET_KINDS = {k.value for k in AssetKind}


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
    kind: str  # validated against AssetKind below (single source of truth — no drift)
    identifier: str = Field(default="", max_length=2048)
    exposure: str = Field(default="unknown", pattern="^(public|internal|unknown)$")
    config: dict = Field(default_factory=dict)
    # Sensitive credential material (cloud keys, DAST auth). Encrypted at rest into
    # `asset.secret_ref` and never echoed back — keep it out of `config`, which is returned/logged.
    secret: dict | None = Field(default=None)

    @field_validator("kind")
    @classmethod
    def _known_kind(cls, v: str) -> str:
        if v not in _ASSET_KINDS:
            raise ValueError(f"unknown asset kind: {v}")
        return v

    @field_validator("config", "secret")
    @classmethod
    def _bound_size(cls, v: dict | None) -> dict | None:
        # Cap serialized size to prevent oversized-payload DoS (also bounds inline_content).
        import json

        if v is not None and len(json.dumps(v)) > 262_144:  # 256 KiB
            raise ValueError("field exceeds maximum size (256 KiB)")
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


# ── Discovery (Phase 6C.1 operationalization) ──
class DiscoveryRunCreate(BaseModel):
    customer_id: uuid.UUID
    # Passive seeds (domains/hosts) and/or active_targets — active ones are only ever probed if a
    # valid authorization covers them; this DTO never grants authorization by itself.
    seeds: dict = Field(default_factory=dict)
    providers: list[str] = Field(default_factory=list)  # empty → default passive (dns, ct)
    trigger: str = Field(default="manual", pattern="^(manual|schedule|api)$")

    @field_validator("seeds")
    @classmethod
    def _bound_seeds(cls, v: dict) -> dict:
        import json

        if len(json.dumps(v)) > 262_144:  # 256 KiB cap, same posture as asset config
            raise ValueError("seeds exceed maximum size (256 KiB)")
        return v


class DiscoveryRunOut(BaseModel):
    id: uuid.UUID
    customer_id: uuid.UUID | None
    status: str
    trigger: str
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


# ── AI chat (grounded on project findings) ──
class ChatRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)
    scan_id: uuid.UUID | None = None
    customer_id: uuid.UUID | None = None


class ChatResponse(BaseModel):
    answer: str
    cited_finding_ids: list[str]


# ── Dashboard ──
class DashboardResponse(BaseModel):
    """The dashboard payload (WP-P0).

    The original four fields are unchanged so existing clients keep working; everything added has a
    default, and every value is computed from a query rather than estimated.
    """

    security_score: int
    severity_counts: dict
    total_findings: int
    recent_scans: list[ScanOut]

    # Open findings are the actionable number. Total includes resolved and accepted work, which is
    # the right figure for a trend and the wrong one for "what needs attention".
    open_severity_counts: dict = Field(default_factory=dict)
    open_findings: int = 0

    assets_total: int = 0
    assets_by_exposure: dict = Field(default_factory=dict)

    scans_by_status: dict = Field(default_factory=dict)
    scans_active: int = 0
    scans_completed: int = 0
    last_successful_scan_at: str | None = None
    # failed / skipped / deferred engine runs. Shown next to the finding counts because these are
    # exactly the states that must never be read as "clean".
    engine_runs_unresolved: dict = Field(default_factory=dict)

    remediation_by_status: dict = Field(default_factory=dict)
    remediation_overdue: int = 0

    risk_trend: list[dict] = Field(default_factory=list)
    exposure_trend: list[dict] = Field(default_factory=list)
    trend_days: int = 0


# ── Attack-graph read-only analysis (Phase 6D) ──
class GraphNodeRef(BaseModel):
    id: str
    node_type: str
    canonical_key: str


class ExposurePathsOut(BaseModel):
    paths: list[list[GraphNodeRef]]
    truncated: bool


class ReachableOut(BaseModel):
    nodes: list[GraphNodeRef]
    from_id: str


class BlastRadiusOut(BaseModel):
    root_id: str
    root_key: str
    affected_nodes: int
    sensitive_nodes: int
    exposure_paths: int
    weighted_impact: int
    truncated: bool


class ChokepointOut(BaseModel):
    node_id: str
    node_key: str
    node_type: str
    paths_cut: int
    total_paths: int
    fraction: float
    evidence_paths: list[list[GraphNodeRef]]


class ChokepointsOut(BaseModel):
    chokepoints: list[ChokepointOut]
    total_paths: int
    truncated: bool


class DriftItemOut(BaseModel):
    node_id: str
    node_key: str
    kind: str
    detail: dict
    occurred_at: str


class DriftOut(BaseModel):
    items: list[DriftItemOut]
