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
    # Read-only Web/TLS tool provider (Security Tool Execution Framework — first provider).
    WEB_TLS = "web_tls"
    # Offline PCAP header/metadata analysis provider (Framework — second, artifact/non-network).
    PCAP_META = "pcap_meta"


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
    # Phase 6 EASM discovery kinds.
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    NETBLOCK = "netblock"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"


class NodeType(str, Enum):
    """Attack-graph node kinds. A node is identified by an internal UUID; its `canonical_key`
    (FQDN / ARN / referenced-row id) is a searchable, *mutable* natural key — so relations point at
    stable ids and survive a rename (Phase 6 design decision)."""

    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP_ADDRESS = "ip_address"
    NETBLOCK = "netblock"
    SERVICE = "service"
    CLOUD_RESOURCE = "cloud_resource"
    ASSET = "asset"        # references a managed asset row
    FINDING = "finding"    # references a finding row (for exposure/path analysis)


class EdgeRelation(str, Enum):
    """Directed relations between attack-graph nodes."""

    SUBDOMAIN_OF = "subdomain_of"
    RESOLVES_TO = "resolves_to"
    HOSTS = "hosts"
    ROUTES_TO = "routes_to"
    EXPOSES = "exposes"        # asset -> finding (evidence: findings.asset_id) — produced in 6E
    ENABLES = "enables"        # finding -> exposure/blast-radius (future seam; NOT produced yet)
    CONTAINS = "contains"      # netblock -> ip_address
    TRUSTS = "trusts"
    SERVES = "serves"          # subdomain/service -> asset (deterministic host-identity link, 6E)


class AssetState(str, Enum):
    """Discovery lifecycle for an asset/graph node (driven by last_seen_at)."""

    CANDIDATE = "candidate"
    ACTIVE = "active"
    SHADOW = "shadow"      # live but never declared by the customer — the high-value EASM signal
    INACTIVE = "inactive"


class DiscoverySource(str, Enum):
    """Where a discovered node/edge came from — carried as provenance on every observation."""

    CT_LOG = "ct_log"
    PASSIVE_DNS = "passive_dns"
    DNS_RESOLVER = "dns_resolver"
    ASN_RIR = "asn_rir"
    CLOUD_ENUM = "cloud_enum"
    PORT_SCAN = "port_scan"       # authorization-gated
    MANUAL = "manual"
    INFERRED = "inferred"


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
