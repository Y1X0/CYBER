"""SCA engine — Software Composition Analysis.

Parses dependency manifests AND lockfiles into (name, version, ecosystem) and
matches each against known vulnerabilities via the injected `VulnMatcher` (KB-backed by default,
live-feed-backed optionally). Emits one finding per vulnerable dependency with dependency evidence.

Lockfiles matter more than manifests. A manifest states what was asked for, often as a range; a
lockfile states what was actually installed, including the transitive dependencies nobody chose
deliberately — which is where most vulnerable code enters a project. Reading `package.json` alone
sees the few direct dependencies and misses the hundreds beneath them.

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
# go.sum lines are `<module path> <version> <hash>`; a module path is a dotted/slashed identifier
# and a version is semver with a leading v.
_GO_MODULE = re.compile(r"^[a-zA-Z0-9][\w.\-~]*(?:[/.][\w.\-~]+)+$")
_GO_VERSION = re.compile(r"^v\d+\.\d+\.\d+(?:[-+][\w.\-]+)?$")


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
                parser = _LOCKFILES.get(path.name)
                if parser is not None:
                    yield from parser(path.read_text("utf-8", "ignore"), rel)
                elif path.name == "requirements.txt" or path.name.startswith("requirements"):
                    yield from self._parse_requirements(path.read_text("utf-8", "ignore"), rel)
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


# ── lockfile parsers ──────────────────────────────────────────────────────────────────────────────
# Each returns (name, version, ecosystem, source). They are deliberately tolerant: a lockfile
# format that shifts between tool versions should cost coverage of that file, never a failed scan.

def _parse_package_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """npm package-lock.json — v2/v3 `packages` map, falling back to v1 `dependencies`."""
    try:
        data = json.loads(text)
    except ValueError:
        return
    packages = data.get("packages")
    if isinstance(packages, dict):
        for path, meta in packages.items():
            if not path or not isinstance(meta, dict):
                continue                       # "" is the root project, not a dependency
            name = meta.get("name") or path.rsplit("node_modules/", 1)[-1]
            version = meta.get("version")
            if name and version:
                yield str(name).lower(), str(version), "npm", source
        return
    def _walk(node, depth=0):  # noqa: ANN001, ANN202 - v1 nests transitives arbitrarily deep
        if depth > 50 or not isinstance(node, dict):
            return
        for name, meta in node.items():
            if not isinstance(meta, dict):
                continue
            if meta.get("version"):
                yield str(name).lower(), str(meta["version"]), "npm", source
            yield from _walk(meta.get("dependencies") or {}, depth + 1)
    yield from _walk(data.get("dependencies") or {})


def _parse_yarn_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """yarn.lock — classic (v1) and berry both key an entry block then state `version`."""
    current: list[str] = []
    for line in text.splitlines():
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        if not line.startswith((" ", "\t")):
            current = []
            for spec in line.rstrip(":").split(","):
                spec = spec.strip().strip('"')
                # Scoped packages keep their leading @, so split on the LAST @.
                name = spec[: spec.rfind("@")] if spec.rfind("@") > 0 else spec
                if name:
                    current.append(name.lower())
        else:
            stripped = line.strip()
            if stripped.startswith("version") and current:
                version = stripped.split(None, 1)[-1].strip().strip('"').strip("'")
                for name in current:
                    yield name, version, "npm", source
                current = []


def _parse_poetry_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """poetry.lock — TOML, read line-wise so no TOML dependency is needed."""
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
        elif stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = ") and name:
            version = stripped.split("=", 1)[1].strip().strip('"')
            yield name.lower(), version, "pypi", source
            name = None


def _parse_pipfile_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Pipfile.lock — `default` and `develop` sections with `==`-pinned versions."""
    try:
        data = json.loads(text)
    except ValueError:
        return
    for section in ("default", "develop"):
        for name, meta in (data.get(section) or {}).items():
            version = (meta or {}).get("version", "") if isinstance(meta, dict) else ""
            if version.startswith("=="):
                yield str(name).lower(), version[2:], "pypi", source


def _parse_gemfile_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Gemfile.lock — the indented entries under GEM/specs are name (version)."""
    in_specs = False
    for line in text.splitlines():
        if line.strip() == "specs:":
            in_specs = True
            continue
        if line and not line.startswith(" "):
            in_specs = False
        if in_specs:
            m = re.match(r"^\s{4,6}([A-Za-z0-9_.-]+) \(([^)<>=~ ]+)\)\s*$", line)
            if m:
                yield m.group(1).lower(), m.group(2), "rubygems", source


def _parse_go_sum(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """go.sum — module version hashes; the /go.mod lines repeat a module already listed."""
    seen: set[tuple[str, str]] = set()
    for line in text.splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[1].endswith("/go.mod"):
            continue
        # Validate the shape rather than trusting the field count: three whitespace-separated
        # tokens is also what a line of prose looks like, and an unvalidated split turns a
        # malformed file into a package named "{{{".
        if not _GO_MODULE.match(parts[0]) or not _GO_VERSION.match(parts[1]):
            continue
        name, version = parts[0].lower(), parts[1].lstrip("v")
        if (name, version) not in seen:
            seen.add((name, version))
            yield name, version, "go", source


def _parse_cargo_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Cargo.lock — TOML package blocks, read line-wise like poetry.lock."""
    name = None
    for line in text.splitlines():
        stripped = line.strip()
        if stripped == "[[package]]":
            name = None
        elif stripped.startswith("name = "):
            name = stripped.split("=", 1)[1].strip().strip('"')
        elif stripped.startswith("version = ") and name:
            yield name.lower(), stripped.split("=", 1)[1].strip().strip('"'), "cargo", source
            name = None


def _parse_composer_lock(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """composer.lock — `packages` and `packages-dev` arrays."""
    try:
        data = json.loads(text)
    except ValueError:
        return
    for section in ("packages", "packages-dev"):
        for pkg in data.get(section) or []:
            if isinstance(pkg, dict) and pkg.get("name") and pkg.get("version"):
                yield str(pkg["name"]).lower(), str(pkg["version"]).lstrip("v"), "packagist", source


def _parse_package_json_file(text: str, source: str) -> Iterator[tuple[str, str, str, str]]:
    """Direct dependencies only — kept for repositories that ship no lockfile."""
    yield from ScaEngine._parse_package_json(text, source)


_LOCKFILES = {
    "package-lock.json": _parse_package_lock,
    "npm-shrinkwrap.json": _parse_package_lock,
    "yarn.lock": _parse_yarn_lock,
    "poetry.lock": _parse_poetry_lock,
    "Pipfile.lock": _parse_pipfile_lock,
    "Gemfile.lock": _parse_gemfile_lock,
    "go.sum": _parse_go_sum,
    "Cargo.lock": _parse_cargo_lock,
    "composer.lock": _parse_composer_lock,
    "package.json": _parse_package_json_file,
}
