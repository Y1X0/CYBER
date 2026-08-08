"""Protocol-probe evidence (Phase 6C.2) — the shape a ProtocolProbe returns.

A `ProtocolProbe` talks to ONE protocol (http, tls, …) and returns `ProbeEvidence` — the
low-impact facts it observed (a TLS certificate, a banner). It is deliberately ignorant of graph
nodes, edges, assets, and discovery runs: the orchestrator turns evidence into those. This mirrors
how `RawFinding` separates an engine from persistence.

Evidence only: never an exploit or payload, nothing beyond service identification / fingerprinting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ProbeEvidence:
    protocol: str                       # "http" | "tls" (only these in 6C.2)
    port: int
    attributes: dict[str, Any] = field(default_factory=dict)  # tls / banner / missing_tls, ...
    confidence: int = 95                # a live connection is strong evidence
