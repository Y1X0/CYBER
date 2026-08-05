"""Structured evidence for findings (Evidence Management, user's Phase 2 idea #3).

Every finding should be a defensible mini-dossier: what/where, the proof, the affected asset, and
references. Engines and human pentesters both populate this shape. Evidence is stored as a plain
dict on the finding (JSONB) — these helpers give it a consistent, validated structure and keep raw
secrets out of what gets persisted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from enum import Enum


class EvidenceKind(str, Enum):
    CODE_SNIPPET = "code_snippet"  # SAST — file/line + redacted excerpt
    DEPENDENCY = "dependency"  # SCA — package@version + advisory
    HTTP_EXCHANGE = "http_exchange"  # DAST/API — request/response pair
    CONFIG = "config"  # CSPM/container — offending configuration
    SECRET = "secret"  # noqa: S105 - enum label, not a credential
    MANUAL = "manual"  # pentester-supplied evidence


def _truncate(value: str | None, limit: int = 4000) -> str | None:
    if value is None:
        return None
    return value if len(value) <= limit else value[:limit] + "…[truncated]"


@dataclass
class Evidence:
    """A structured, sanitized evidence record attached to a finding."""

    kind: EvidenceKind
    summary: str = ""
    # Where the issue lives (file+line / endpoint / package / resource ARN).
    location: dict = field(default_factory=dict)
    # The proof, already sanitized. For HTTP: {"request": ..., "response": ...}.
    detail: dict = field(default_factory=dict)
    # Optional pointer to an uploaded artifact (screenshot, raw output) in object storage.
    artifact_ref: str | None = None

    def to_dict(self) -> dict:
        data = asdict(self)
        data["kind"] = self.kind.value
        data["summary"] = _truncate(self.summary)
        # Defensively truncate any long string values in detail.
        data["detail"] = {
            k: _truncate(v) if isinstance(v, str) else v for k, v in self.detail.items()
        }
        return data


def code_evidence(*, path: str, line: int, redacted_excerpt: str, rule: str | None = None) -> dict:
    return Evidence(
        kind=EvidenceKind.CODE_SNIPPET,
        summary=f"{path}:{line}",
        location={"path": path, "line": line, "rule": rule},
        detail={"excerpt": redacted_excerpt},
    ).to_dict()


def dependency_evidence(*, package: str, version: str, ecosystem: str, advisory: str) -> dict:
    return Evidence(
        kind=EvidenceKind.DEPENDENCY,
        summary=f"{package}@{version} ({ecosystem})",
        location={"package": package, "version": version, "ecosystem": ecosystem},
        detail={"advisory": advisory},
    ).to_dict()
