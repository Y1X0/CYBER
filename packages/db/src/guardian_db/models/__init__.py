"""Import every model module so `Base.metadata` is fully populated (Alembic + create_all)."""

from guardian_db.models.assets import Asset, Authorization, Engagement
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
from guardian_db.models.scanning import (
    Finding,
    FindingCorrelation,
    FindingCorrelationMember,
    FindingEvent,
    RemediationItem,
    Scan,
    ScanEngineRun,
)
from guardian_db.models.scheduling import Schedule
from guardian_db.models.tenancy import (
    Customer,
    CustomerContact,
    Tenant,
    TenantMembership,
    User,
)

__all__ = [
    "Advisory",
    "ApiKey",
    "Approval",
    "Asset",
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
    "Exploit",
    "FeedState",
    "FeedSync",
    "Finding",
    "FindingCorrelation",
    "FindingCorrelationMember",
    "FindingEvent",
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
]
