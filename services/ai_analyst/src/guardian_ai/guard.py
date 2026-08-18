"""What may leave for the model, and what may come back from it (WP-E3).

The analyst had the right shape — deterministic severity is authoritative, references are filtered
to the ones the finding actually carries, scanned content is delimited as untrusted data — and three
gaps that matter once a real model is configured rather than the offline stub.

**Findings are sent verbatim to a third party.** `evidence` and `location` go into the prompt as
they are. A secrets finding's evidence is redacted at write time, but an IaC parser quoting a config
file, a container layer's environment variable, or a triage note is not, and the destination is
somebody else's API. WP-F2 already wrote the scrubber for exactly this shape of problem; it runs
here too, before the request rather than after it.

**The delimiter is not a boundary.** `<scan_data>…</scan_data>` around attacker-influenced content
is a convention the content can simply close. Scanned data is what a customer's *attacker* wrote —
a page title, a filename, a commit message — so the closing tag has to be neutralized in the data
itself, not trusted to be absent.

**The model's prose is not checked against the facts.** A model that writes "this is a low-severity
informational issue" about a deterministic critical has not changed the score, but it has told the
customer to ignore it, which comes to the same thing. And a model asked for a "non-actionable attack
summary" sometimes returns a working command anyway.

Everything here is pure, so each rule is tested against the output that must be caught and the
output that must pass.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from guardian_core.redaction import scrub

MAX_FIELD_CHARS = 4_000
MAX_LIST_ITEMS = 20

# Rendered inert rather than removed: a finding whose evidence legitimately contains the literal
# text `</scan_data>` should still be explainable, and the analyst should be able to see that it
# was there.
_DELIMITERS = re.compile(r"(?i)</?\s*(?:scan_data|system|instructions?|assistant|human)\s*>")

# Phrases that only appear when content is trying to address the model rather than describe a
# finding. Neutralized in the data, and reported: an injection attempt in scanned content is itself
# worth an analyst seeing.
# No trailing `\b`: several of these end in a colon, and a colon followed by a space is not a word
# boundary — the same mistake that once made `\binteractsh\b` miss `interactsh_url`.
_INJECTION = re.compile(
    r"(?i)\b(?:ignore (?:all )?(?:previous|prior|above) (?:instructions?|prompts?)|"
    r"disregard (?:the )?(?:previous|above|system)|you are now|new instructions?:|"
    r"system prompt:|act as (?:an? )?(?:admin|root|developer mode)|"
    r"reveal (?:your )?(?:system )?prompt|print (?:your )?instructions)"
)

# Output that is operational rather than explanatory. The analyst is asked for a high-level attack
# summary; these are the shapes that mean it returned a working recipe instead.
_EXPLOIT_SHAPES: tuple[tuple[str, re.Pattern[str]], ...] = (
    # The binary *plus* an operational argument — a URL, a flag, a path, or a pipe into a shell.
    # Requiring the argument is what keeps "use curl to verify the header" out of it.
    ("shell command", re.compile(
        r"(?i)\b(?:curl|wget|nc|ncat|powershell|python[23]?|perl|ruby|msfconsole|sqlmap|hydra|"
        r"john|hashcat)\s+(?:-{1,2}\w|https?://|/\w|\d{1,3}(?:\.\d{1,3}){3})[^\n]*")),
    ("reverse shell", re.compile(
        r"(?i)(?:/dev/tcp/|nc\s+-[a-z]*e|bash\s+-i\s*>&|socat\s+exec)")),
    ("sql payload", re.compile(
        r"(?i)(?:union\s+(?:all\s+)?select\b|'\s*or\s*'?1'?\s*=\s*'?1|;\s*drop\s+table)")),
    ("script payload", re.compile(
        r"(?i)<script[^>]*>|javascript:\s*\w+\(|onerror\s*=\s*[\"']?\w+\(")),
    ("metasploit module", re.compile(r"(?i)\b(?:use\s+exploit/|set\s+(?:rhosts|lhost)\b)")),
)

# Fields the analyst is asked to keep explanatory. `remediation` is deliberately absent.
_NON_ACTIONABLE_FIELDS = frozenset({
    "explanation", "impact", "attack_scenario", "summary", "posture", "recommendation",
})

REFUSAL_NOTE = (
    "[removed: the model returned operational exploit content, which Guardian does not publish. "
    "The finding's evidence shows what was observed.]"
)


@dataclass
class Sanitized:
    """What will be sent, and what was changed to make it sendable."""

    payload: dict
    redacted: list[str] = field(default_factory=list)
    injection_attempts: int = 0
    truncated: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.redacted or self.injection_attempts or self.truncated)


def _neutralize(text: str, state: Sanitized, path: str) -> str:
    replaced = _DELIMITERS.sub(lambda m: m.group(0).replace("<", "‹").replace(">", "›"),
                               text)
    if _INJECTION.search(replaced):
        state.injection_attempts += 1
        replaced = _INJECTION.sub("[neutralized instruction-like text]", replaced)
    if len(replaced) > MAX_FIELD_CHARS:
        state.truncated.append(path)
        replaced = replaced[:MAX_FIELD_CHARS] + " …[truncated]"
    return replaced


def _walk(value, state: Sanitized, path: str = ""):  # noqa: ANN001, ANN202
    if isinstance(value, dict):
        return {k: _walk(v, state, f"{path}.{k}" if path else str(k)) for k, v in value.items()}
    if isinstance(value, list):
        if len(value) > MAX_LIST_ITEMS:
            state.truncated.append(path)
            value = value[:MAX_LIST_ITEMS]
        return [_walk(v, state, path) for v in value]
    if isinstance(value, str):
        return _neutralize(value, state, path)
    return value


def sanitize_for_model(payload: dict) -> Sanitized:
    """Everything that must happen before a finding leaves this process.

    Order matters: credentials are removed first, so a value that is both a credential and an
    injection attempt is not merely truncated with the credential intact.
    """
    scrubbed, hits = scrub(payload)
    state = Sanitized(payload={}, redacted=sorted(set(hits)))
    state.payload = _walk(scrubbed, state)
    return state


# ── output ────────────────────────────────────────────────────────────────────────────────────────
@dataclass
class Checked:
    output: dict
    dropped_references: list[str] = field(default_factory=list)
    exploit_content_removed: list[str] = field(default_factory=list)
    contradictions: list[str] = field(default_factory=list)

    @property
    def modified(self) -> bool:
        return bool(self.dropped_references or self.exploit_content_removed or self.contradictions)


_SEVERITY_WORDS = {
    "critical": ("critical",),
    "high": ("high",),
    "medium": ("medium", "moderate"),
    "low": ("low",),
    "info": ("informational", "info"),
}
_DOWNPLAY = re.compile(
    r"(?i)\b(?:not (?:a |really )?(?:a )?(?:concern|risk|issue|problem|vulnerability)|"
    r"no real (?:risk|impact)|harmless|benign|false positive|can be (?:safely )?ignored|"
    r"low[- ]risk|minimal risk|not exploitable)\b"
)


def check_output(output: dict, *, severity: str, allowed_references: set[str]) -> Checked:
    """Everything that must be true of what came back.

    Three separate jobs, and the third is the one people forget: the model cannot change the
    severity — the platform never reads it from the model — but it can tell the reader the finding
    is nothing to worry about, which has the same effect on what gets fixed.
    """
    result = Checked(output=dict(output))

    references = [r for r in (result.output.get("references") or []) if isinstance(r, str)]
    kept = [r for r in references if r in allowed_references]
    result.dropped_references = [r for r in references if r not in allowed_references]
    result.output["references"] = kept

    for key, value in list(result.output.items()):
        if not isinstance(value, str) or key not in _NON_ACTIONABLE_FIELDS:
            # `remediation` is *supposed* to carry commands — "rotate the key with `aws iam
            # update-access-key`" is the advice, not a leak. Stripping it would remove the useful
            # half of the answer to prevent the model from being helpful in the wrong field.
            continue
        for label, pattern in _EXPLOIT_SHAPES:
            if pattern.search(value):
                result.exploit_content_removed.append(f"{key}: {label}")
                result.output[key] = pattern.sub(REFUSAL_NOTE, value)
                value = result.output[key]

    severity = (severity or "").lower()
    if severity in ("critical", "high"):
        prose = " ".join(str(result.output.get(key, "")) for key in
                         ("explanation", "impact", "attack_scenario"))
        if _DOWNPLAY.search(prose):
            result.contradictions.append(
                f"the explanation downplays a finding the risk engine scored {severity}"
            )
        for other, words in _SEVERITY_WORDS.items():
            if other in ("critical", "high"):
                continue
            if any(re.search(rf"(?i)\b{word}[- ]severity\b", prose) for word in words):
                result.contradictions.append(
                    f"the explanation calls a {severity} finding {other}-severity"
                )
                break

    return result


__all__ = [
    "MAX_FIELD_CHARS",
    "REFUSAL_NOTE",
    "Checked",
    "Sanitized",
    "check_output",
    "sanitize_for_model",
]
