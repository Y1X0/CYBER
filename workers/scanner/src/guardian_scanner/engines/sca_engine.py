"""SCA engine — Software Composition Analysis.

Parses dependency manifests (requirements.txt, package.json) into (name, version, ecosystem) and
matches each against known vulnerabilities via the injected `VulnMatcher` (KB-backed by default,
live-feed-backed optionally). Emits one finding per vulnerable dependency with dependency evidence.

Parsing lives here; the vulnerability data source is injected — so the engine works offline against
the seeded KB and needs no network in CI.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardian_core.enums import EngineKey
from guardian_core.evidence import dependency_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import ScanContext, VulnMatch

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9_.\-]+)\s*==\s*([A-Za-z0-9_.\-]+)")
_SKIP_DIRS = {".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__"}


class ScaEngine:
    key = EngineKey.SCA
    name = "Guardian SCA (dependency analysis)"
    version = "0.1.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "container_image"}

    def health(self):  # noqa: ANN201
        from guardian_scanner.engines.base import EngineHealth

        return EngineHealth(ok=True, detail="manifest parsing; matcher injected at runtime")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.vuln_matcher is None:
            return  # no data source wired → nothing to assert
        deps = list(self._collect_dependencies(ctx))
        for name, version, ecosystem, source in deps:
            for vm in ctx.vuln_matcher.match(name=name, version=version, ecosystem=ecosystem):
                yield self._finding(name, version, ecosystem, source, vm)

    def _collect_dependencies(self, ctx: ScanContext) -> Iterator[tuple[str, str, str, str]]:
        if ctx.inline_content is not None:
            # Inline content is treated as a requirements.txt for single-file/test scans.
            yield from self._parse_requirements(ctx.inline_content, "<inline>")
            return
        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        for path in root.rglob("*"):
            if not path.is_file() or any(p in _SKIP_DIRS for p in path.parts):
                continue
            rel = str(path.relative_to(root))
            try:
                if path.name == "requirements.txt":
                    yield from self._parse_requirements(path.read_text("utf-8", "ignore"), rel)
                elif path.name == "package.json":
                    yield from self._parse_package_json(path.read_text("utf-8", "ignore"), rel)
            except OSError:
                continue

    @staticmethod
    def _parse_requirements(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
        for line in text.splitlines():
            if line.strip().startswith("#"):
                continue
            m = _REQ_LINE.match(line)
            if m:
                yield m.group(1).lower(), m.group(2), "pypi", source

    @staticmethod
    def _parse_package_json(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
        try:
            data = json.loads(text)
        except ValueError:
            return
        for section in ("dependencies", "devDependencies"):
            for name, spec in (data.get(section) or {}).items():
                version = str(spec).lstrip("^~>=< ")
                if version:
                    yield name.lower(), version, "npm", source

    def _finding(
        self, name: str, version: str, ecosystem: str, source: str, vm: VulnMatch
    ) -> RawFinding:
        return RawFinding(
            engine=EngineKey.SCA,
            title=f"Vulnerable dependency: {name}@{version} ({vm.external_id})",
            category="vuln-dep",
            description=vm.summary or f"{name}@{version} is affected by {vm.external_id}.",
            base_severity=vm.severity,
            confidence="high",
            cwe_id=vm.cwe_ids[0] if vm.cwe_ids else None,
            cve_ids=[vm.external_id] if vm.external_id.startswith("CVE-") else [],
            cvss_base=vm.cvss_base,
            epss_score=vm.epss_score,
            kev=vm.kev,
            location={"path": source, "package": name, "version": version, "ecosystem": ecosystem},
            evidence=dependency_evidence(
                package=name, version=version, ecosystem=ecosystem, advisory=vm.external_id
            ),
            references={"refs": vm.references, "advisory": vm.external_id},
        )
