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
from guardian_core.findings import RawFinding
from guardian_core.scoring import ScoreInputs, score_severity

__all__ = [
    "AssetKind",
    "EngineKey",
    "FindingSource",
    "FindingStatus",
    "PortalRole",
    "RawFinding",
    "ScanStatus",
    "ScoreInputs",
    "Severity",
    "StaffRole",
    "score_severity",
]
