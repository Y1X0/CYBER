"""Reference engine: hardcoded-secret detection (SAST/secrets family).

Self-contained by default (no external binary) so it works out of the box in CI and on any host. It
walks a workspace for text files and flags likely secrets via named patterns plus a Shannon-entropy
heuristic for assignments to secret-looking identifiers. When the **gitleaks** binary is present it
is run as an ADDITIONAL backend (its maintained ruleset merged in, the same way SastEngine wraps
semgrep) — additive, never a precondition, so the engine is complete with or without it.

Evidence is ALWAYS redacted — the raw secret is never persisted (doc 06 §6).

It also scans git history, which is where secrets usually are. Removing a key in a later commit
does not remove it from the repository: anyone who can clone can still read it, and the working
tree — the only thing a scanner sees by default — shows nothing. History scanning is what turns
this engine from a linter into a credential-exposure check. It uses git itself rather than an
external tool, so it adds no binary and no licence question.
"""

from __future__ import annotations

import json
import math
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell, bounded
import tempfile
from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

# gitleaks (MIT, APPROVED in docs/TOOL_LICENSES.md) is used as an ADDITIONAL detection backend when
# the binary is present — thousands of maintained rules, merged rather than reimplemented, the
# same way SastEngine wraps semgrep. It is additive, not a precondition: the built-in patterns,
# entropy and history are a complete detector on their own, so the engine is never "degraded"
# without gitleaks (unlike SAST, where the community ruleset is coverage the built-in genuinely
# lacks). When gitleaks is present it finds more; when absent the built-in still fully checks.
# Bounded so a huge repo degrades rather than hangs.
_GITLEAKS_TIMEOUT = 300
_GITLEAKS_MAX_FINDINGS = 1000
# gitleaks reports a rule id but no severity. A private key is categorically worse than a generic
# high-entropy hit, so it is raised; everything else a secret scanner emits is HIGH by nature.
_GITLEAKS_CRITICAL_RULES = ("private-key", "rsa", "ssh", "pgp", "pkcs")

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
# History scanning is bounded on three axes so a large repository degrades rather than hangs:
# how many commits are walked, how long git may run, and how much diff output is examined.
_HISTORY_COMMITS = 1000
_HISTORY_TIMEOUT = 120
_HISTORY_MAX_LINES = 400_000
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


log = get_logger("guardian.engine.secrets")


class SecretsInputError(RuntimeError):
    """There was nothing to read (readiness audit, Phase 4)."""


class SecretsEngine:
    """Detects hardcoded secrets in source. Implements the ScanEngine protocol."""

    key = EngineKey.SECRETS
    name = "Guardian Secrets Scanner"
    version = "0.1.0"
    requires_authorization = False  # passive: operates on code the customer provides

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "container_image", "k8s_manifest"}

    def health(self) -> EngineHealth:
        # Built-in detection is complete on its own, so the engine is never degraded — gitleaks
        # only adds rules. The detail reports whether it augmented, so a scan stays legible after.
        has_gitleaks = bool(shutil.which("gitleaks"))
        return EngineHealth(
            ok=True,
            detail=("builtin patterns + entropy + git history"
                    + (" + gitleaks ruleset" if has_gitleaks else " (gitleaks absent)")),
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_text("<inline>", ctx.inline_content)
            return
        if not ctx.workspace_path:
            # Nothing to read is not nothing to find. A silent return completes the run cleanly,
            # and WP-E2 reads a clean completion as permission to resolve this asset's existing
            # secret findings — so a misconfigured asset would quietly close them all (readiness
            # audit, Phase 4).
            raise SecretsInputError(
                "no workspace and no inline content, so no file was read. An absence of input is "
                "not an absence of secrets."
            )
        root = Path(ctx.workspace_path)
        if not root.exists():
            raise SecretsInputError(
                f"the workspace path {ctx.workspace_path!r} does not exist, so no file was read"
            )
        for path in self._iter_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(path.relative_to(root))
            yield from self._scan_text(rel, text)
        yield from self._scan_history(root, ctx)
        yield from self._run_gitleaks_if_available(root)

    def _run_gitleaks_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Wrap gitleaks when installed. No-op otherwise, so CI and the built-in path are unchanged.

        gitleaks is invoked with `--redact`, so it masks the secret in its OWN output before we ever
        read it — and we mask again with `_redact` and never carry the raw `Match` into a finding.
        Two independent redactions on top of the persistence-layer value-scrub: a secret gitleaks
        found must never become a secret Guardian stored.
        """
        exe = shutil.which("gitleaks")
        if not exe:
            return
        has_git = (root / ".git").exists()
        with tempfile.NamedTemporaryFile("r+", suffix=".json", delete=True) as report:
            argv = [exe, "detect", "--source", str(root), "--report-format", "json",
                    "--report-path", report.name, "--redact", "--no-banner", "--exit-code", "0"]
            if not has_git:
                argv.append("--no-git")   # a plain directory, not a repo — scan the tree
            try:
                subprocess.run(  # noqa: S603 - fixed argv, no shell, bounded
                    argv, capture_output=True, timeout=_GITLEAKS_TIMEOUT, check=False)
                report.seek(0)
                data = json.loads(report.read() or "[]")
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                # gitleaks is installed but did not answer. The built-in detector still ran, so this
                # is reduced coverage rather than a failed scan — but it must not be silent: fewer
                # findings from a crashed tool looks exactly like a cleaner repository.
                log.warning("secrets_gitleaks_failed", error=f"{type(exc).__name__}: {exc}"[:200])
                return
        if not isinstance(data, list):
            log.warning("secrets_gitleaks_unexpected_output", kind=type(data).__name__)
            return
        emitted: set[tuple[str, str, int]] = set()
        for item in data[:_GITLEAKS_MAX_FINDINGS]:
            if not isinstance(item, dict):
                continue
            finding = self._gitleaks_finding(item)
            if finding is None:
                continue
            dedup = (finding.location.get("rule", ""), finding.location.get("path", ""),
                     int(finding.location.get("line") or 0))
            if dedup in emitted:
                continue
            emitted.add(dedup)
            yield finding

    def _gitleaks_finding(self, item: dict) -> RawFinding | None:
        rule = str(item.get("RuleID") or "").strip()
        path = str(item.get("File") or "").strip()
        if not rule or not path:
            return None
        line = item.get("StartLine")
        commit = str(item.get("Commit") or "").strip()[:12]
        # gitleaks with --redact already masked the value; mask again defensively and NEVER read the
        # raw `Match`. The redacted `Secret` field is all that reaches evidence.
        redacted = _redact(str(item.get("Secret") or ""))
        low = rule.lower()
        severity = (Severity.CRITICAL if any(k in low for k in _GITLEAKS_CRITICAL_RULES)
                    else Severity.HIGH)
        description = str(item.get("Description") or f"gitleaks rule {rule}").strip()[:400]
        location = {"path": path, "line": line, "rule": rule}
        if commit:
            location["commit"] = commit
            location["source"] = "gitleaks-history"
            description = (f"{description} Found in commit {commit}; it remains retrievable from "
                           "history even if later removed, so the credential must be rotated.")
        else:
            location["source"] = "gitleaks"
        return RawFinding(
            engine=EngineKey.SECRETS,
            title=f"Hardcoded secret: {description[:80]}" if description else f"Secret: {rule}",
            category="secret",
            description=description,
            base_severity=severity,
            confidence="high",   # gitleaks rules are precise; above the built-in entropy guess
            cwe_id="CWE-798",
            owasp_ref="A07:2021",
            location=location,
            evidence={"match": redacted, "detector": "gitleaks", "rule": rule},
            references={
                "cwe": "https://cwe.mitre.org/data/definitions/798.html",
                "gitleaks": f"https://github.com/gitleaks/gitleaks (rule: {rule})",
            },
        )

    def _scan_history(self, root: Path, ctx: ScanContext) -> Iterable[RawFinding]:
        """Scan lines ADDED by past commits.

        Only additions matter: a deletion is the secret being removed, which is not a new exposure,
        and scanning both sides would report every leak twice. A finding here means the value is
        still retrievable by anyone who can clone, regardless of the current file contents.
        """
        if not (root / ".git").exists() or not shutil.which("git"):
            return
        settings = ctx.settings or {}
        if settings.get("scan_history") is False:
            return
        depth = int(settings.get("history_commits") or _HISTORY_COMMITS)

        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, bounded
                ["git", "-C", str(root), "log", f"-n{depth}", "-p", "--no-color",  # noqa: S607
                 "--no-merges", "--unified=0", "--pretty=format:%x00commit %H"],
                capture_output=True, text=True, timeout=_HISTORY_TIMEOUT, check=False,
            )
        except (subprocess.SubprocessError, OSError) as exc:
            # History is a bonus surface and must never fail the scan — but a silent return loses
            # the fact that it was not searched at all (readiness audit, Phase 4).
            log.warning("secrets_history_unavailable", error=f"{type(exc).__name__}: {exc}"[:200])
            return
        if proc.returncode != 0:
            log.warning("secrets_history_failed", returncode=proc.returncode,
                        stderr=(proc.stderr or "")[:300])
            return

        commit = "unknown"
        path = "unknown"
        emitted: set[tuple[str, str]] = set()
        budget = _HISTORY_MAX_LINES
        for line in proc.stdout.splitlines():
            budget -= 1
            if budget <= 0:
                break
            if line.startswith("\x00commit "):
                commit = line.split(" ", 1)[1].strip()[:12]
                continue
            if line.startswith("+++ b/"):
                path = line[6:].strip()
                continue
            if not line.startswith("+") or line.startswith("+++"):
                continue
            content = line[1:]
            for finding in self._scan_text(f"{path}@{commit}", content):
                # One report per (rule, path) across history: the same key re-committed on ten
                # branches is one exposed credential, not ten.
                key = (finding.location.get("rule", ""), path)
                if key in emitted:
                    continue
                emitted.add(key)
                finding.location["commit"] = commit
                finding.location["path"] = path
                finding.location["source"] = "git-history"
                finding.description = (
                    f"{finding.description} This was found in commit {commit}; it remains "
                    "retrievable from the repository history even if later removed, so rotation "
                    "is required — deleting the file is not sufficient."
                )
                yield finding

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
