"""The stable engine contract every scanner plugin implements (doc 01 §5, doc 07 §4).

The orchestrator and normalizer know only this interface — never an engine's internals — so a new
engine is purely additive.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from typing import Protocol, runtime_checkable

from guardian_core.enums import EngineKey
from guardian_core.findings import RawFinding


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
