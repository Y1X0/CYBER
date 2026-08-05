"""guardian_core — shared domain: canonical finding schema, severity model, scoring.

This package is the single source of truth imported by the API, workers, and AI service so
engines and services can never drift on the finding shape or severity semantics.
"""

from guardian_core.discovery import (
    DiscoveredAsset,
    DiscoveredEdge,
    DiscoveryContext,
)
from guardian_core.enums import (
    AssetKind,
    AssetState,
    DiscoverySource,
    EdgeRelation,
    EngineKey,
    FindingSource,
    FindingStatus,
    NodeType,
    PortalRole,
    ScanStatus,
    Severity,
    StaffRole,
)
from guardian_core.evidence import Evidence, EvidenceKind, code_evidence, dependency_evidence
from guardian_core.exposure import ExposureAssessment, ExposureInputs, assess_exposure
from guardian_core.findings import RawFinding
from guardian_core.policy import DEFAULT_RULES, GateResult, evaluate_gate
from guardian_core.scoring import RiskAssessment, ScoreInputs, assess, score_severity

__all__ = [
    "DEFAULT_RULES",
    "AssetKind",
    "AssetState",
    "DiscoveredAsset",
    "DiscoveredEdge",
    "DiscoveryContext",
    "DiscoverySource",
    "EdgeRelation",
    "EngineKey",
    "Evidence",
    "EvidenceKind",
    "ExposureAssessment",
    "ExposureInputs",
    "FindingSource",
    "FindingStatus",
    "GateResult",
    "NodeType",
    "PortalRole",
    "RawFinding",
    "RiskAssessment",
    "ScanStatus",
    "ScoreInputs",
    "Severity",
    "StaffRole",
    "assess",
    "assess_exposure",
    "code_evidence",
    "dependency_evidence",
    "evaluate_gate",
    "score_severity",
]
