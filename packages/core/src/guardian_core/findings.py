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
    exploit_maturity: str | None = None   # "high" | "functional" | "poc" | "unproven" (WP-C4)
    ransomware: bool = False

    # Where & proof (sanitized — never raw secrets)
    location: dict[str, Any] = field(default_factory=dict)
    evidence: dict[str, Any] = field(default_factory=dict)
    references: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """A JSON-safe mapping of this finding (enums flattened to their ``.value``).

        Used to carry raw findings across the scan-plane boundary (ISSUE-3). JSON — never pickle —
        because the scan plane runs untrusted engine code and is the LOWER-trust side; a pickle
        crossing back would let a compromised scan plane execute code on the control plane that
        holds the KMS master. Every field here is a str/bool/number/list/dict, so it round-trips
        with no code execution on decode.
        """
        return {
            "engine": self.engine.value,
            "title": self.title,
            "category": self.category,
            "description": self.description,
            "base_severity": self.base_severity.value,
            "confidence": self.confidence,
            "cwe_id": self.cwe_id,
            "owasp_ref": self.owasp_ref,
            "cve_ids": list(self.cve_ids),
            "cvss_base": self.cvss_base,
            "epss_score": self.epss_score,
            "kev": self.kev,
            "exploit_maturity": self.exploit_maturity,
            "ransomware": self.ransomware,
            "location": self.location,
            "evidence": self.evidence,
            "references": self.references,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> RawFinding:
        """Rebuild a RawFinding from :meth:`to_dict`. Unknown enum values fail loudly rather than
        silently mislabelling a finding's engine or severity."""
        return cls(
            engine=EngineKey(data["engine"]),
            title=str(data["title"]),
            category=str(data["category"]),
            description=str(data.get("description", "")),
            base_severity=Severity(data.get("base_severity", Severity.MEDIUM.value)),
            confidence=str(data.get("confidence", "medium")),
            cwe_id=data.get("cwe_id"),
            owasp_ref=data.get("owasp_ref"),
            cve_ids=list(data.get("cve_ids", []) or []),
            cvss_base=data.get("cvss_base"),
            epss_score=data.get("epss_score"),
            kev=bool(data.get("kev", False)),
            exploit_maturity=data.get("exploit_maturity"),
            ransomware=bool(data.get("ransomware", False)),
            location=dict(data.get("location", {}) or {}),
            evidence=dict(data.get("evidence", {}) or {}),
            references=dict(data.get("references", {}) or {}),
        )

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
