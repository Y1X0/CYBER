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
    # Infrastructure-as-code: Terraform, CloudFormation, Terraform plan (WP-D9).
    IAC = "iac"
    # Read-only Web/TLS tool provider (Security Tool Execution Framework — first provider).
    WEB_TLS = "web_tls"
    # Offline PCAP header/metadata analysis provider (Framework — second, artifact/non-network).
    PCAP_META = "pcap_meta"
    # Offline DNS / email-security posture provider (Framework — third, absence-as-evidence).
    DNS_POSTURE = "dns_posture"
    # Nmap TCP-connect active network discovery provider (Framework — first active-binary, L2).
    NMAP = "nmap"
    # Templated web checks provider (Framework — first L3 SENSITIVE, in-proc curated detection).
    WEB_CHECKS = "web_checks"
    # ML-model supply-chain: unsafe operators in serialized models (Phase A, modelscan-backed).
    # The first engine whose external tool is its ONLY detector (no built-in fallback), so a
    # missing binary is genuine degradation — verification treats its silence as INCONCLUSIVE.
    ML_MODEL = "ml_model"
    # CI/CD & supply-chain security: GitHub Actions script injection, poisoned pull_request_target,
    # unpinned actions, over-privileged tokens (Phase A, self-contained built-in detector).
    CICD = "cicd"
    # AI-assisted vulnerability discovery: an LLM reads source and proposes candidate weaknesses the
    # pattern engines miss (logic/authz/complex injection). Its output is HYPOTHESES — persisted as
    # source=ai_assisted, always non-exhaustive, so its silence never resolves a finding.
    AI_DISCOVERY = "ai_discovery"
    # Mobile app static analysis: Android APK manifest/permissions/exported-components/cleartext/
    # secrets/crypto (Phase 1, offline — no emulator; dynamic analysis is a documented host need).
    MOBILE = "mobile"
    # iOS app static analysis: Info.plist (ATS, URL schemes, privacy usage), provisioning-profile
    # entitlements (get-task-allow), and Mach-O/bundle secrets/indicators (offline — no device,
    # no macOS/Xcode; FairPlay-encrypted store binaries limit string analysis, documented).
    IOS = "ios"
    # Authorized host/network posture assessed from an allowlisted local-agent submission (no
    # cloud-to-LAN scanning): home-network device/service posture and Linux server hardening.
    HOST_POSTURE = "host_posture"


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
    # An uploaded mobile app package (Android .apk) analysed statically (Phase 1).
    MOBILE_APP = "mobile_app"
    # An uploaded iOS app package (.ipa) analysed statically — Info.plist/entitlements/Mach-O.
    IOS_APP = "ios_app"
    # A device/host assessed via an authorized local agent's allowlisted posture submission
    # (home-network device or Linux server) — never scanned directly from the cloud (Phase 2/3).
    NETWORK_HOST = "network_host"
    SERVER_HOST = "server_host"


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


class CorrelationConfidence(str, Enum):
    """How strongly the *relationship* between correlated findings is supported by evidence (WP-E1).

    This is deliberately a SEPARATE concept from ``Finding.confidence``, which asks "how sure are we
    that this one finding is real?". Correlation confidence asks "how sure are we that these
    findings are meaningfully related?" — two high-confidence findings do not, by themselves,
    prove a relationship. The tier is derived from the *kind of evidence that established the
    link*, never from the members' own severity or confidence.

    * ``CONFIRMED`` — the evidence proves the relationship (e.g. two findings carry the *same*
      redacted secret value, so they are the same credential).
    * ``STRONG_EVIDENCE`` — multiple independent findings strongly support the relationship, but it
      is not proven to be the identical instance (e.g. the same CVE on the same asset from two
      engines, without proof it is the same component; or a static+dynamic agreement on a weakness
      class without proof of the same sink).
    * ``POTENTIAL`` — the relationship is plausible but the evidence only ties a weak key (e.g. the
      same customer), not the specific asset/component/repository, so it needs further validation.
    """

    CONFIRMED = "confirmed"
    STRONG_EVIDENCE = "strong_evidence"
    POTENTIAL = "potential"


class StaffRole(str, Enum):
    """Internal staff roles within a tenant."""

    OWNER = "owner"
    ADMIN = "admin"
    PENTESTER = "pentester"
    ANALYST = "analyst"
    REVIEWER = "reviewer"


class AuthorizationBasis(str, Enum):
    """On what authority a scan's active engines were allowed to run.

    Every scan carries one, so a report can state plainly WHY the target could be scanned:

    * ``VERIFIED_OWNERSHIP`` — the normal path: an ``Authorization`` row (verified ownership /
      written consent) covered the target, evaluated per-engine in the worker for every user.
    * ``OWNER_DIRECT`` — the tenant OWNER ran an active scan against an UNVERIFIED target under the
      owner-direct capability (off by default; owner role re-checked server-side at dispatch; the
      owner affirmed legal right to scan the target). The ownership gate is bypassed for that one
      scan only; it never changes the gate for any non-owner. The dispatch and the affirmation are
      written to the immutable audit log — this label is the human-readable half of that record.
    """

    VERIFIED_OWNERSHIP = "verified-ownership"
    OWNER_DIRECT = "owner-direct"


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
