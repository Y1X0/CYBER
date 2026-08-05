"""The canonical finding shape emitted by every scanner engine.

Engines produce `RawFinding`s; the normalizer maps them to persisted findings with a stable
fingerprint (for dedup/trend) and a scored severity. This dataclass is intentionally
engine-agnostic — the core never knows how a given engine found the issue.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from guardian_core.enums import EngineKey, Severity


@dataclass
class RawFinding:
    """A single issue reported by an engine, before normalization/scoring."""

    engine: EngineKey
    title: str
    category: str  # e.g. "secret", "injection", "misconfig", "vuln-dep"
    description: str = ""
    base_severity: Severity = Severity.MEDIUM
    confidence: str = "medium"  # high | medium | low

    # Standards mapping (any/all optional)
    cwe_id: str | None = None
    owasp_ref: str | None = None
    cve_ids: list[str] = field(default_factory=list)

    # Exploitability signals (optional, feed the scorer)
    cvss_base: float | None = None
    epss_score: float | None = None
    kev: bool = False

    # Where & proof (sanitized — never raw secrets)
    location: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    references: dict[str, Any] = field(default_factory=dict)

    def fingerprint(self) -> str:
        """Stable identity across scans → dedup & trend tracking.

        Based on engine + rule/category + normalized location, NOT on volatile fields like line
        content, so the same issue is recognized run-to-run.
        """
        loc = self.location
        key = {
            "engine": self.engine.value,
            "category": self.category,
            "title": self.title,
            "path": loc.get("path") or loc.get("endpoint") or loc.get("resource"),
            "rule": loc.get("rule") or self.cwe_id,
        }
        blob = json.dumps(key, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(blob.encode()).hexdigest()[:32]
