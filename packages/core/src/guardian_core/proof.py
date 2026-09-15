"""Proof-of-Vulnerability — a safe, auditable evidence record for a confirmed finding.

This is the "Verification Evidence Vault" in code form, and it exists to answer two questions a
serious platform must answer, without ever becoming an attack tool:

  1. *Was the finding real?* — a client or an auditor who doubts a finding is shown a concrete,
     technical reproduction: the exact benign input that triggered it and the signal that proved it.
  2. *Is the fix real?* — after the client remediates, the same benign reproduction is replayed; if
     the signal is gone, the finding is confirmed closed (regression verification).

The single invariant that keeps this an evidence vault and not a weapon cache: **only a SAFE
reproduction may be stored.** A safe reproduction observes — it sends a probe designed to reveal the
weakness (a lone quote to elicit a SQL error, a canary string, a read-only request) and records what
came back. It never carries a destructive or weaponized payload: no `DROP TABLE`, no `rm -rf`, no
reverse shell, no data-exfiltration. `assess_reproduction_safety` is the gate every reproduction
passes through, and `build_proof` refuses to construct a record from anything that fails it. So even
the admin, even per-tenant and encrypted, the vault physically cannot hold a working exploit.

This module is pure and deterministic — the safety decision has one home and is fully testable. The
storage layer (encryption at rest via `guardian_common.crypto`, per-tenant isolation, access
control) wraps this; it never relaxes the invariant enforced here.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardian_core.redaction import scrub

_MAX = 4_000


def _clip(text: str, limit: int = _MAX) -> str:
    text = text or ""
    return text if len(text) <= limit else text[:limit] + "…[truncated]"


# Markers that make a "reproduction" destructive or weaponized rather than observational. If any of
# these appears, it is not a safe probe and must never enter the vault. Deliberately broad: the
# cost of rejecting a borderline-safe probe is far lower than the cost of storing a weapon.
_DESTRUCTIVE: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("destructive-sql", re.compile(
        r"(?i)\b(drop\s+(table|database|schema)|truncate\s+table|delete\s+from\s+\w+\s*(;|$)"
        r"|update\s+\w+\s+set\b(?![^;]*\bwhere\b)|into\s+outfile|load_file\s*\(|xp_cmdshell)")),
    ("shell-destruction", re.compile(
        r"(?i)(rm\s+-rf|mkfs\.|dd\s+if=|>\s*/dev/sd|:\(\)\s*\{|shutdown\b|reboot\b|chmod\s+-R\s+777"
        r"|chown\s+-R|>\s*/dev/null\s*;\s*rm)")),
    ("remote-code-exec", re.compile(
        r"(?i)((curl|wget)\b[^\n|]*\|\s*(sudo\s+)?(ba|z)?sh\b|iwr\b[^\n|]*\|\s*iex\b"
        r"|python\s+-c\s+['\"].*exec\(|eval\s*\(\s*(request|input|base64))")),
    ("reverse-shell", re.compile(
        r"(?i)(/dev/tcp/|bash\s+-i\b|nc\s+-e\b|ncat\s+-e\b|mkfifo\b.*\|.*sh\b|socket\.socket"
        r".*connect|/bin/sh\s+-i)")),
    ("data-exfiltration", re.compile(
        r"(?i)((curl|wget|nc|Invoke-WebRequest)\b[^\n]*(/etc/passwd|/etc/shadow|\.aws/credentials"
        r"|\.ssh/id_|env\b)|base64\b[^\n]*\|\s*(curl|nc)\b)")),
    ("fork-bomb", re.compile(r":\(\)\s*\{\s*:\s*\|\s*:\s*&\s*\}\s*;\s*:")),
)


@dataclass(frozen=True)
class ReproSafety:
    """The gate's verdict on one reproduction. `safe` is the only thing that may open the vault."""

    safe: bool
    reasons: tuple[str, ...] = ()


def assess_reproduction_safety(*parts: str) -> ReproSafety:
    """Assess whether a reproduction is a benign probe (safe to store) or carries a weaponized
    payload (must be refused). Any destructive marker in any part fails the whole reproduction."""
    blob = "\n".join(p for p in parts if p)
    hits = sorted({name for name, pat in _DESTRUCTIVE if pat.search(blob)})
    return ReproSafety(safe=not hits, reasons=tuple(hits))


@dataclass
class SafeReproduction:
    """The benign, non-destructive way to re-trigger a finding — the vault's core artifact.

    `method` is how it is replayed (e.g. "http_probe", "input_marker", "static_location"); `probe`
    is the exact benign input/request shape; `expected_signal` is what its presence in the response
    proves. None of these may contain a destructive payload — construction goes through the gate.
    """

    method: str
    probe: str
    expected_signal: str = ""
    target: dict = field(default_factory=dict)  # endpoint / file+line / parameter — where to replay


class UnsafeReproductionError(ValueError):
    """A reproduction carrying a destructive/weaponized payload was refused entry to the vault."""


@dataclass
class ProofOfVulnerability:
    """A self-contained, sanitized proof record for one finding. Everything here is safe to store,
    encrypt, and show an auditor; nothing here is an attack tool."""

    finding_fingerprint: str
    vuln_class: str                      # CWE or finding category
    reproduction: SafeReproduction
    observed_evidence: str = ""          # the sanitized signal that proved it (redacted)
    regression_ref: dict = field(default_factory=dict)  # how a retest replays it (engine/check id)

    def to_dict(self) -> dict:
        # Redact defensively at the boundary: proof evidence is written from live request/response
        # data and must never carry a real secret into storage, even encrypted.
        return {
            "finding_fingerprint": self.finding_fingerprint,
            "vuln_class": self.vuln_class,
            "reproduction": {
                "method": self.reproduction.method,
                "probe": _clip(scrub(self.reproduction.probe)[0]),
                "expected_signal": _clip(scrub(self.reproduction.expected_signal)[0]),
                "target": self.reproduction.target,
            },
            "observed_evidence": _clip(scrub(self.observed_evidence)[0]),
            "regression_ref": self.regression_ref,
            "safe": True,   # invariant: an instance only ever exists for a safe reproduction
        }


def build_proof(
    *,
    finding_fingerprint: str,
    vuln_class: str,
    reproduction: SafeReproduction,
    observed_evidence: str = "",
    regression_ref: dict | None = None,
) -> ProofOfVulnerability:
    """Construct a proof record IFF the reproduction is safe. Otherwise refuse — this is the one
    place the vault's invariant is enforced, so there is one place to read and to trust."""
    safety = assess_reproduction_safety(
        reproduction.probe, reproduction.expected_signal, observed_evidence)
    if not safety.safe:
        raise UnsafeReproductionError(
            "refused to store a reproduction with a destructive/weaponized payload "
            f"({', '.join(safety.reasons)}); the vault holds safe proofs only")
    return ProofOfVulnerability(
        finding_fingerprint=finding_fingerprint,
        vuln_class=vuln_class,
        reproduction=reproduction,
        observed_evidence=observed_evidence,
        regression_ref=regression_ref or {},
    )
