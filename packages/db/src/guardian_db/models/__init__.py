"""Import every model module so `Base.metadata` is fully populated (Alembic + create_all)."""

from guardian_db.models.assets import Asset, Authorization, Engagement
from guardian_db.models.audit import ApiKey, AuditLog
from guardian_db.models.billing import Plan, PlanEntitlement, Subscription, UsageRecord
from guardian_db.models.plugins import ScannerPlugin, TenantScannerConfig
from guardian_db.models.reporting import Report, ReportApproval, ReportSection
from guardian_db.models.scanning import (
    Finding,
    FindingEvent,
    RemediationItem,
    Scan,
    ScanEngineRun,
)
from guardian_db.models.tenancy import (
    Customer,
    CustomerContact,
    Tenant,
    TenantMembership,
    User,
)

__all__ = [
    "ApiKey",
    "Asset",
    "AuditLog",
    "Authorization",
    "Customer",
    "CustomerContact",
    "Engagement",
    "Finding",
    "FindingEvent",
    "Plan",
    "PlanEntitlement",
    "RemediationItem",
    "Report",
    "ReportApproval",
    "ReportSection",
    "Scan",
    "ScanEngineRun",
    "ScannerPlugin",
    "Subscription",
    "Tenant",
    "TenantMembership",
    "TenantScannerConfig",
    "UsageRecord",
    "User",
]
