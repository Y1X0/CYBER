"""Container engine — Dockerfile security analysis (CIS Docker Benchmark).

Builtin ruleset (Hadolint-style, no external binary) so it runs out of the box. Scans Dockerfiles
in the workspace, or inline content. Passive — operates on artifacts the customer provides.
An optional Trivy image-CVE wrap can layer in later behind this same engine.
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import code_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

_SECRET_ENV = re.compile(r"(?i)\b(ENV|ARG)\s+\w*(password|secret|token|api[_-]?key)\w*\s*[= ]")
_CURL_PIPE = re.compile(r"(?i)(curl|wget)\s+[^\n|]*\|\s*(sh|bash)")


class ContainerEngine:
    key = EngineKey.CONTAINER
    name = "Guardian Container (Dockerfile CIS rules)"
    version = "0.1.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"container_image", "repo"}

    def health(self) -> EngineHealth:
        return EngineHealth(ok=True, detail="builtin Dockerfile rules")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan("Dockerfile", ctx.inline_content)
            return
        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        for path in root.rglob("*"):
            if path.is_file() and path.name.lower().startswith("dockerfile"):
                try:
                    text = path.read_text("utf-8", "ignore")
                except OSError:
                    continue
                yield from self._scan(str(path.relative_to(root)), text)

    def _scan(self, path: str, text: str) -> Iterable[RawFinding]:
        has_user = False
        for lineno, raw in enumerate(text.splitlines(), start=1):
            line = raw.strip()
            upper = line.upper()
            if upper.startswith("USER "):
                has_user = True
                if line.split()[1].lower() in {"root", "0"}:
                    yield self._f(
                        "Container runs as root (USER root)",
                        Severity.HIGH,
                        "CWE-250",
                        "CIS Docker 4.1",
                        path,
                        lineno,
                        line,
                    )
            if upper.startswith("FROM ") and (":latest" in line or ":" not in line.split()[1]):
                yield self._f(
                    "Base image uses mutable 'latest' tag",
                    Severity.MEDIUM,
                    "CWE-1357",
                    "CIS Docker 4.9",
                    path,
                    lineno,
                    line,
                )
            if _SECRET_ENV.search(line):
                yield self._f(
                    "Secret baked into image (ENV/ARG)",
                    Severity.HIGH,
                    "CWE-798",
                    "CIS Docker 4.10",
                    path,
                    lineno,
                    line,
                )
            if _CURL_PIPE.search(line):
                yield self._f(
                    "Remote script piped to shell (curl|bash)",
                    Severity.HIGH,
                    "CWE-494",
                    "CIS Docker 4.7",
                    path,
                    lineno,
                    line,
                )
            if upper.startswith("ADD ") and "http" not in line:
                yield self._f(
                    "Use COPY instead of ADD for local files",
                    Severity.LOW,
                    "CWE-669",
                    "CIS Docker 4.9",
                    path,
                    lineno,
                    line,
                )
        if not has_user:
            yield self._f(
                "No USER instruction — image runs as root by default",
                Severity.HIGH,
                "CWE-250",
                "CIS Docker 4.1",
                path,
                0,
                "(no USER directive)",
            )

    def _f(self, title, sev, cwe, cis, path, lineno, line) -> RawFinding:  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.CONTAINER,
            title=title,
            category="container-misconfig",
            description=f"{title} ({cis}).",
            base_severity=sev,
            confidence="high",
            cwe_id=cwe,
            location={"path": path, "line": lineno, "cis": cis},
            evidence=code_evidence(path=path, line=lineno, redacted_excerpt=line[:200], rule=cis),
            references={"cis": cis},
        )
