"""SAST engine — static detection of insecure code patterns.

Ships a builtin, dependency-free ruleset so it delivers value out of the box and in CI. When a
`semgrep` binary is present it is additionally invoked and its results are merged (the wrap-don't-
reinvent pattern from ADR-005) — but the engine never *requires* it.

All detection lives here in the plugin; the core knows nothing about these rules.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import code_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    owasp: str
    suffixes: tuple[str, ...]  # empty = all supported code files


_PY = (".py",)
_JS = (".js", ".ts", ".tsx", ".jsx")

_RULES: tuple[Rule, ...] = (
    Rule(
        "py-eval",
        "Use of eval()",
        re.compile(r"\beval\s*\("),
        Severity.HIGH,
        "CWE-95",
        "A03:2021",
        _PY + _JS,
    ),
    Rule(
        "py-exec",
        "Use of exec()",
        re.compile(r"\bexec\s*\("),
        Severity.HIGH,
        "CWE-95",
        "A03:2021",
        _PY,
    ),
    Rule(
        "py-shell-true",
        "subprocess with shell=True",
        re.compile(r"subprocess\.\w+\([^)]*shell\s*=\s*True"),
        Severity.HIGH,
        "CWE-78",
        "A03:2021",
        _PY,
    ),
    Rule(
        "py-os-system",
        "os.system() call",
        re.compile(r"\bos\.system\s*\("),
        Severity.HIGH,
        "CWE-78",
        "A03:2021",
        _PY,
    ),
    Rule(
        "py-yaml-load",
        "Unsafe yaml.load()",
        re.compile(r"yaml\.load\s*\((?![^)]*Safe)"),
        Severity.HIGH,
        "CWE-502",
        "A08:2021",
        _PY,
    ),
    Rule(
        "py-pickle",
        "Unsafe pickle deserialization",
        re.compile(r"\bpickle\.loads?\s*\("),
        Severity.MEDIUM,
        "CWE-502",
        "A08:2021",
        _PY,
    ),
    Rule(
        "py-weak-hash",
        "Weak hash (md5/sha1)",
        re.compile(r"hashlib\.(md5|sha1)\s*\("),
        Severity.MEDIUM,
        "CWE-327",
        "A02:2021",
        _PY,
    ),
    Rule(
        "py-tls-verify-off",
        "TLS verification disabled",
        re.compile(r"verify\s*=\s*False"),
        Severity.HIGH,
        "CWE-295",
        "A07:2021",
        _PY,
    ),
    Rule(
        "py-sql-fstring",
        "Possible SQL injection (f-string/%% in execute)",
        re.compile(r"execute\s*\(\s*(?:f['\"]|['\"].*%\s*%?\s*[a-zA-Z_(])"),
        Severity.HIGH,
        "CWE-89",
        "A03:2021",
        _PY,
    ),
    Rule(
        "js-eval",
        "Use of eval()",
        re.compile(r"\beval\s*\("),
        Severity.HIGH,
        "CWE-95",
        "A03:2021",
        _JS,
    ),
    Rule(
        "js-child-exec",
        "child_process.exec()",
        re.compile(r"child_process\.exec\s*\("),
        Severity.HIGH,
        "CWE-78",
        "A03:2021",
        _JS,
    ),
    Rule(
        "js-inner-html",
        "Assignment to innerHTML (possible XSS)",
        re.compile(r"\.innerHTML\s*="),
        Severity.MEDIUM,
        "CWE-79",
        "A03:2021",
        _JS,
    ),
    Rule(
        "js-danger-html",
        "React dangerouslySetInnerHTML",
        re.compile(r"dangerouslySetInnerHTML"),
        Severity.MEDIUM,
        "CWE-79",
        "A03:2021",
        _JS,
    ),
)

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
_ALL_SUFFIXES = _PY + _JS
_MAX_FILE_BYTES = 1_000_000


class SastEngine:
    key = EngineKey.SAST
    name = "Guardian SAST (builtin rules + optional semgrep)"
    version = "0.1.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "k8s_manifest", "container_image"}

    def health(self) -> EngineHealth:
        semgrep = "present" if shutil.which("semgrep") else "absent"
        return EngineHealth(ok=True, detail=f"builtin rules active; semgrep {semgrep}")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_text("<inline>", ctx.inline_content, _ALL_SUFFIXES)
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
            yield from self._scan_text(str(path.relative_to(root)), text, (path.suffix.lower(),))
        yield from self._run_semgrep_if_available(root)

    def _iter_files(self, root: Path) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in _ALL_SUFFIXES:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            yield path

    def _scan_text(self, path: str, text: str, suffixes: tuple[str, ...]) -> Iterable[RawFinding]:
        applicable = [r for r in _RULES if not r.suffixes or any(s in r.suffixes for s in suffixes)]
        for lineno, line in enumerate(text.splitlines(), start=1):
            if len(line) > 4000:
                continue
            for rule in applicable:
                if rule.pattern.search(line):
                    yield self._finding(rule, path, lineno, line.strip())

    def _finding(self, rule: Rule, path: str, lineno: int, line: str) -> RawFinding:
        excerpt = line if len(line) <= 200 else line[:200] + "…"
        return RawFinding(
            engine=EngineKey.SAST,
            title=rule.title,
            category="insecure-code",
            description=f"{rule.title} detected. This pattern maps to {rule.cwe}.",
            base_severity=rule.severity,
            confidence="medium",
            cwe_id=rule.cwe,
            owasp_ref=rule.owasp,
            location={"path": path, "line": lineno, "rule": rule.id},
            evidence=code_evidence(path=path, line=lineno, redacted_excerpt=excerpt, rule=rule.id),
            references={
                "cwe": f"https://cwe.mitre.org/data/definitions/{rule.cwe.split('-')[1]}.html"
            },
        )

    def _run_semgrep_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Best-effort wrap of semgrep when installed. No-op otherwise (keeps CI self-contained)."""
        if not shutil.which("semgrep"):
            return
        try:
            proc = subprocess.run(  # noqa: S603,S607 - fixed argv, no shell
                ["semgrep", "--config", "auto", "--json", "--quiet", str(root)],  # noqa: S607
                capture_output=True,
                timeout=600,
                check=False,
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, OSError, ValueError):
            return
        for res in data.get("results", []):
            extra = res.get("extra", {})
            start = res.get("start", {})
            rel = res.get("path", "")
            yield RawFinding(
                engine=EngineKey.SAST,
                title=extra.get("message", "Semgrep finding")[:300],
                category="insecure-code",
                description=extra.get("message", ""),
                base_severity=_semgrep_sev(extra.get("severity", "WARNING")),
                confidence="medium",
                location={"path": rel, "line": start.get("line"), "rule": res.get("check_id")},
                evidence=code_evidence(
                    path=rel,
                    line=start.get("line", 0),
                    redacted_excerpt=(extra.get("lines", "") or "")[:200],
                    rule=res.get("check_id"),
                ),
                references={"semgrep": res.get("check_id", "")},
            )


def _semgrep_sev(sev: str) -> Severity:
    return {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}.get(
        sev.upper(), Severity.MEDIUM
    )
