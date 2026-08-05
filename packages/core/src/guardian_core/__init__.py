"""guardian_core — shared domain: canonical finding schema, severity model, scoring.

This package is the single source of truth imported by the API, workers, and AI service so
engines and services can never drift on the finding shape or severity semantics.
"""

from guardian_core.enums import (
    AssetKind,
    EngineKey,
    FindingSource,
    FindingStatus,
    PortalRole,
    ScanStatus,
    Severity,
    StaffRole,
)
from guardian_core.evidence import Evidence, EvidenceKind, code_evidence, dependency_evidence
from guardian_core.findings import RawFinding
from guardian_core.policy import DEFAULT_RULES, GateResult, evaluate_gate
from guardian_core.scoring import RiskAssessment, ScoreInputs, assess, score_severity

__all__ = [
    "DEFAULT_RULES",
    "AssetKind",
    "EngineKey",
    "Evidence",
    "EvidenceKind",
    "FindingSource",
    "FindingStatus",
    "GateResult",
    "PortalRole",
    "RawFinding",
    "RiskAssessment",
    "ScanStatus",
    "ScoreInputs",
    "Severity",
    "StaffRole",
    "assess",
    "code_evidence",
    "dependency_evidence",
    "evaluate_gate",
    "score_severity",
]
