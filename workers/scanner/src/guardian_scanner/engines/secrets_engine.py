"""Reference engine: hardcoded-secret detection (SAST/secrets family).

Self-contained (no external binary) so it works out of the box as the Phase 1 vertical-slice
engine and in CI. It walks a workspace for text files and flags likely secrets via named patterns
plus a Shannon-entropy heuristic for assignments to secret-looking identifiers.

Evidence is ALWAYS redacted — the raw secret is never persisted (doc 06 §6).
"""

from __future__ import annotations

import math
import re
from collections.abc import Iterable
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

# (name, compiled pattern, base severity)
_PATTERNS: list[tuple[str, re.Pattern[str], Severity]] = [
    ("AWS Access Key ID", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), Severity.HIGH),
    (
        "AWS Secret Access Key",
        re.compile(r"(?i)aws.{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]"),
        Severity.HIGH,
    ),
    (
        "Private Key block",
        re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
        Severity.CRITICAL,
    ),
    ("GitHub Token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36,}\b"), Severity.HIGH),
    ("Slack Token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"), Severity.HIGH),
    ("Google API Key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b"), Severity.HIGH),
    ("Stripe Secret Key", re.compile(r"\bsk_(?:live|test)_[0-9A-Za-z]{16,}\b"), Severity.HIGH),
    (
        "JWT",
        re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b"),
        Severity.MEDIUM,
    ),
    (
        "Generic secret assignment",
        re.compile(
            r"(?i)(?:password|passwd|pwd|secret|api[_-]?key|token|access[_-]?key)\s*[:=]\s*['\"][^'\"]{8,}['\"]"
        ),
        Severity.MEDIUM,
    ),
]

_SECRET_NAME = re.compile(r"(?i)\b(secret|password|passwd|pwd|api[_-]?key|token|access[_-]?key)\b")
_ASSIGN_VALUE = re.compile(r"['\"]([^'\"]{16,})['\"]")

_SKIP_DIRS = {
    ".git",
    "node_modules",
    "venv",
    ".venv",
    "dist",
    "build",
    "__pycache__",
    ".mypy_cache",
}
_MAX_FILE_BYTES = 1_000_000
_TEXT_SUFFIXES = {
    ".py",
    ".js",
    ".ts",
    ".tsx",
    ".jsx",
    ".java",
    ".go",
    ".rb",
    ".php",
    ".env",
    ".yml",
    ".yaml",
    ".json",
    ".toml",
    ".ini",
    ".cfg",
    ".sh",
    ".txt",
    ".md",
    ".xml",
    ".properties",
    ".tf",
    "",
}


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = {c: s.count(c) for c in set(s)}
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _redact(value: str) -> str:
    value = value.strip("'\"")
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:2]}{'*' * 8}{value[-2:]} (len={len(value)})"


class SecretsEngine:
    """Detects hardcoded secrets in source. Implements the ScanEngine protocol."""

    key = EngineKey.SECRETS
    name = "Guardian Secrets Scanner"
    version = "0.1.0"
    requires_authorization = False  # passive: operates on code the customer provides

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "container_image", "k8s_manifest"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="builtin, no external dependencies")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_text("<inline>", ctx.inline_content)
            return
        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        if not root.exists():
            return
        for path in self._iter_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            yield from self._scan_text(rel, text)

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            if path.suffix.lower() not in _TEXT_SUFFIXES:
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path

    def _scan_text(self, path: str, text: str) -> Iterable[RawFinding]:
        seen: set[tuple[str, int]] = set()
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4000:
                continue
            for name, pattern, sev in _PATTERNS:
                m = pattern.search(line)
                if not m:
                    continue
                dedup = (name, lineno)
                if dedup in seen:
                    continue
                seen.add(dedup)
                yield self._make_finding(name, sev, path, lineno, m.group(0), "medium")
            # Entropy heuristic: high-entropy value assigned to a secret-looking identifier.
            if _SECRET_NAME.search(line):
                for vm in _ASSIGN_VALUE.finditer(line):
                    value = vm.group(1)
                    if _shannon_entropy(value) >= 4.0 and ("entropy", lineno) not in seen:
                        seen.add(("entropy", lineno))
                        yield self._make_finding(
                            "High-entropy secret", Severity.MEDIUM, path, lineno, value, "low"
                        )

    def _make_finding(
        self, name: str, sev: Severity, path: str, lineno: int, raw: str, confidence: str
    ) -> RawFinding:
        return RawFinding(
            engine=EngineKey.SECRETS,
            title=f"Hardcoded secret: {name}",
            category="secret",
            description=(
                f"A likely hardcoded credential ({name}) was detected in source. Hardcoded secrets "
                "can be extracted from the repository or its history and used to access systems."
            ),
            base_severity=sev,
            confidence=confidence,
            cwe_id="CWE-798",
            owasp_ref="A07:2021",
            location={"path": path, "line": lineno, "rule": name},
            evidence={"match": _redact(raw)},
            references={
                "cwe": "https://cwe.mitre.org/data/definitions/798.html",
                "owasp": "https://owasp.org/Top10/A07_2021-Identification_and_Authentication_Failures/",
            },
        )
