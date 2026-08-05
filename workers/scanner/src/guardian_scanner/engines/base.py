"""The stable engine contract every scanner plugin implements (doc 01 §5, doc 07 §4).

The orchestrator and normalizer know only this interface — never an engine's internals — so a new
engine is purely additive.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding


@dataclass
class VulnMatch:
    """A KB/feed vulnerability matched to a dependency (consumed by the SCA engine)."""

    external_id: str  # CVE / GHSA id
    summary: str = ""
    severity: Severity = Severity.MEDIUM
    cvss_base: float | None = None
    epss_score: float | None = None
    kev: bool = False
    cwe_ids: list[str] = field(default_factory=list)
    references: list = field(default_factory=list)


@runtime_checkable
class VulnMatcher(Protocol):
    """Looks up known vulnerabilities for a dependency. Implemented DB-side or via a live feed,
    so the SCA engine never imports the database or a network client directly."""

    def match(self, *, name: str, version: str, ecosystem: str) -> list[VulnMatch]: ...


@dataclass
class ScanContext:
    """Everything an engine needs for one run. Populated by the task from the DB + workspace."""

    scan_id: str
    asset_kind: str
    asset_identifier: str
    workspace_path: str | None = None  # local path to scan (cloned repo / provided dir)
    inline_content: str | None = None  # optional inline content (tests, single-file scans)
    exposure: str = "unknown"
    settings: dict = field(default_factory=dict)
    vuln_matcher: VulnMatcher | None = None  # injected for SCA (KB or live-feed backed)
    # The asset's config blob. Carries offline snapshots for active engines (cloud_config,
    # http_snapshot, openapi_spec) so CSPM/DAST/API run without touching a live system in tests.
    asset_config: dict = field(default_factory=dict)


@dataclass
class EngineHealth:
    ok: bool
    detail: str = ""


@runtime_checkable
class ScanEngine(Protocol):
    """Contract for a scanner plugin."""

    key: EngineKey
    name: str
    version: str
    requires_authorization: bool

    def supports(self, asset_kind: str) -> bool:
        """Whether this engine can scan the given asset kind."""
        ...

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        """Execute the scan and yield canonical findings."""
        ...

    def health(self) -> EngineHealth:
        """Report readiness (e.g. required binary present)."""
        ...
