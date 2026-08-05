"""Canonical enumerations shared across the platform.

Kept in `guardian_core` (not the DB layer) so non-DB code — engines, scoring, schemas — can
depend on them without importing SQLAlchemy.
"""

from __future__ import annotations

from enum import Enum


class Severity(str, Enum):
    """Deterministic severity produced by the scorer (guardian_core.scoring)."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def rank(self) -> int:
        return {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}[self.value]


class EngineKey(str, Enum):
    """Stable keys for scanner engines (plugin registry, doc 07 §4)."""

    SAST = "sast"
    SECRETS = "secrets"
    SCA = "sca"
    DAST = "dast"
    API = "api"
    CSPM = "cspm"
    CONTAINER = "container"
    K8S = "k8s"


# Engines that actively probe a live target and therefore REQUIRE an authorization record
# before they may run (safe-scanning gate, doc 06 §4).
ACTIVE_ENGINES: frozenset[EngineKey] = frozenset({EngineKey.DAST, EngineKey.API, EngineKey.CSPM})


class AssetKind(str, Enum):
    REPO = "repo"
    WEB = "web"
    API = "api"
    CLOUD_ACCOUNT = "cloud_account"
    CONTAINER_IMAGE = "container_image"
    K8S_MANIFEST = "k8s_manifest"


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    PARTIAL = "partial"
    FAILED = "failed"
    CANCELED = "canceled"


class FindingStatus(str, Enum):
    OPEN = "open"
    TRIAGED = "triaged"
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    ACCEPTED_RISK = "accepted_risk"
    RESOLVED = "resolved"


class FindingSource(str, Enum):
    """Provenance — supports the human-pentester workflow (doc 07 §6)."""

    AUTOMATED = "automated"
    AI_ASSISTED = "ai_assisted"
    MANUAL = "manual"


class StaffRole(str, Enum):
    """Internal staff roles within a tenant."""

    OWNER = "owner"
    ADMIN = "admin"
    PENTESTER = "pentester"
    ANALYST = "analyst"
    REVIEWER = "reviewer"


class PortalRole(str, Enum):
    """External customer-portal roles."""

    CUSTOMER_ADMIN = "customer_admin"
    CUSTOMER_VIEWER = "customer_viewer"


class ReportStatus(str, Enum):
    DRAFT = "draft"
    IN_REVIEW = "in_review"
    APPROVED = "approved"
    PUBLISHED = "published"
    REJECTED = "rejected"
    REVOKED = "revoked"


class RemediationStatus(str, Enum):
    OPEN = "open"
    ACKNOWLEDGED = "acknowledged"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    RESOLVED = "resolved"
    RISK_ACCEPTED = "risk_accepted"
