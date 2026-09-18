"""Import every model module so `Base.metadata` is fully populated (Alembic + create_all)."""

from guardian_db.models.artifacts import ScanArtifact
from guardian_db.models.assets import (
    Asset,
    Authorization,
    DomainVerification,
    Engagement,
    OwnerDirectAffirmation,
)
from guardian_db.models.audit import ApiKey, AuditLog
from guardian_db.models.billing import Plan, PlanEntitlement, Subscription, UsageRecord
from guardian_db.models.discovery import DiscoveryRun, DiscoveryScope
from guardian_db.models.events import DomainEvent
from guardian_db.models.evidence import EvidenceItem
from guardian_db.models.governance import (
    Approval,
    Campaign,
    CampaignMember,
    CapabilityGrant,
    PlatformGrant,
    ToolCatalog,
)
from guardian_db.models.graph import GraphEdge
from guardian_db.models.graph_nodes import GraphNode
from guardian_db.models.knowledge import (
    Advisory,
    Exploit,
    FeedState,
    FeedSync,
    KbEntry,
    Vulnerability,
    Weakness,
)
from guardian_db.models.node_events import NodeEvent
from guardian_db.models.plugins import ScannerPlugin, TenantScannerConfig
from guardian_db.models.policy import Policy
from guardian_db.models.reporting import Report, ReportApproval, ReportSection
from guardian_db.models.sbom import SbomRecord
from guardian_db.models.scanning import (
    Finding,
    FindingCorrelation,
    FindingCorrelationMember,
    FindingEvent,
    FindingVerification,
    RemediationItem,
    Scan,
    ScanEngineRun,
)
from guardian_db.models.scheduling import Schedule
from guardian_db.models.tenancy import (
    Customer,
    CustomerContact,
    PasswordResetToken,
    Tenant,
    TenantMembership,
    User,
)
from guardian_db.models.vault import ProofRecord
from guardian_db.models.webhooks import WebhookDelivery, WebhookEndpoint

__all__ = [
    "Advisory",
    "ApiKey",
    "Approval",
    "Asset",
    "PasswordResetToken",
    "AuditLog",
    "Authorization",
    "CapabilityGrant",
    "Campaign",
    "CampaignMember",
    "Customer",
    "CustomerContact",
    "DiscoveryRun",
    "DiscoveryScope",
    "DomainEvent",
    "Engagement",
    "EvidenceItem",
    "ProofRecord",
    "SbomRecord",
    "DomainVerification",
    "OwnerDirectAffirmation",
    "Exploit",
    "FeedState",
    "FeedSync",
    "Finding",
    "FindingCorrelation",
    "FindingCorrelationMember",
    "FindingEvent",
    "FindingVerification",
    "GraphEdge",
    "GraphNode",
    "KbEntry",
    "NodeEvent",
    "Plan",
    "PlanEntitlement",
    "PlatformGrant",
    "Policy",
    "RemediationItem",
    "Report",
    "ScanArtifact",
    "Schedule",
    "ReportApproval",
    "ReportSection",
    "Scan",
    "ScanEngineRun",
    "ScannerPlugin",
    "Subscription",
    "Tenant",
    "TenantMembership",
    "TenantScannerConfig",
    "ToolCatalog",
    "UsageRecord",
    "User",
    "Vulnerability",
    "Weakness",
    "WebhookDelivery",
    "WebhookEndpoint",
]
