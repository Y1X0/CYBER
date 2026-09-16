"""SCA engine — Software Composition Analysis.

Parses dependency manifests AND lockfiles into (name, version, ecosystem) and
matches each against known vulnerabilities via the injected `VulnMatcher` (KB-backed by default,
live-feed-backed optionally). Emits one finding per vulnerable dependency with dependency evidence.

Lockfiles matter more than manifests. A manifest states what was asked for, often as a range; a
lockfile states what was actually installed, including the transitive dependencies nobody chose
deliberately — which is where most vulnerable code enters a project. Reading `package.json` alone
sees the few direct dependencies and misses the hundreds beneath them.

Parsing lives here; the vulnerability data source is injected — so the engine works offline against
the seeded KB and needs no network in CI. When the **osv-scanner** binary is present it is run as an
ADDITIONAL backend (the same way SastEngine wraps semgrep), widening lockfile coverage to ecosystems
the built-in parser skips — additive, never a precondition.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell, bounded
from collections.abc import Iterable, Iterator
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import dependency_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import ScanContext, VulnMatch

log = get_logger("guardian.engine.sca")

# osv-scanner (Apache-2.0, APPROVED) is run as an ADDITIONAL backend when present. It is genuinely
# additive rather than redundant: the built-in parser covers a fixed set of lockfiles (pip, npm,
# go), while osv-scanner reads Cargo.lock, Gemfile.lock, composer.lock, pom.xml, poetry.lock,
# Pipfile.lock, pnpm/yarn and more — vulnerable dependencies in ecosystems the built-in skips
# entirely. Same OSV data, wider format coverage. Additive, never a precondition; overlap on a
# shared lockfile collapses under the downstream fingerprint dedup. It needs files on disk, so it
# augments a workspace scan but not an inline one.
_OSV_TIMEOUT = 300
_OSV_MAX_FINDINGS = 3_000
# The SBOM inventory is bounded independently of findings: a pathological lockfile should widen the
# document, never make it unbounded. Mirrors guardian_core.sbom's own cap.
_INVENTORY_MAX = 20_000
_OSV_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, "MODERATE": Severity.MEDIUM,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
}

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

        # The built-in parser + injected matcher is complete for its ecosystems, so the engine is
        # never degraded — osv-scanner only widens format coverage.
        has_osv = bool(shutil.which("osv-scanner"))
        return EngineHealth(
            ok=True,
            detail=("manifest parsing; matcher injected at runtime"
                    + (" + osv-scanner" if has_osv else " (osv-scanner absent)")),
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.vuln_matcher is not None:
            for name, version, ecosystem, source in self._collect_dependencies(ctx):
                for vm in ctx.vuln_matcher.match(name=name, version=version, ecosystem=ecosystem):
                    yield self._finding(name, version, ecosystem, source, vm)
        # osv-scanner needs files on disk; it augments a workspace scan, not an inline one, and it
        # runs regardless of whether a matcher is wired — it carries its own data source.
        if ctx.inline_content is None and ctx.workspace_path:
            root = Path(ctx.workspace_path)
            if root.exists():
                yield from self._run_osv_scanner_if_available(root)

    def collect_inventory(self, ctx: ScanContext) -> list[tuple[str, str, str, str]]:
        """The full resolved dependency inventory — every component, not only the vulnerable ones.

        Reuses the exact manifest/lockfile parsing `run()` uses, so the SBOM lists precisely what
        the SCA engine saw. Deduped and bounded; this is the *inventory* an SBOM is built from, and
        is kept separate from `run()` (which yields findings) so neither path changes the other.
        """
        seen: dict[tuple[str, str, str], tuple[str, str, str, str]] = {}
        for name, version, ecosystem, source in self._collect_dependencies(ctx):
            if not name or not version:
                continue
            key = (name.lower(), version, (ecosystem or "").lower())
            seen.setdefault(key, (name, version, ecosystem, source))
            if len(seen) >= _INVENTORY_MAX:
                break
        return list(seen.values())

    def _run_osv_scanner_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Wrap osv-scanner when installed. No-op otherwise; CI and built-in path unchanged."""
        exe = shutil.which("osv-scanner")
        if not exe:
            return
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell, bounded
                [exe, "--format", "json", "-r", str(root)],
                capture_output=True, text=True, timeout=_OSV_TIMEOUT, check=False)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, OSError, ValueError) as exc:
            # osv-scanner is installed but did not answer (often no network to OSV.dev). The
            # built-in matcher ran, so this is reduced coverage, not a failure — never silent.
            log.warning("sca_osv_scanner_failed", error=f"{type(exc).__name__}: {exc}"[:200])
            return
        emitted = 0
        seen: set[tuple[str, str, str]] = set()
        for result in (data.get("results") or []):
            source = str((result.get("source") or {}).get("path") or "").strip()
            for pkg in (result.get("packages") or []):
                info = pkg.get("package") or {}
                name = str(info.get("name") or "").strip()
                version = str(info.get("version") or "").strip()
                ecosystem = str(info.get("ecosystem") or "").strip().lower()
                if not name or not version:
                    continue
                for vuln in (pkg.get("vulnerabilities") or []):
                    if emitted >= _OSV_MAX_FINDINGS:
                        return
                    finding = self._osv_finding(name, version, ecosystem, source, vuln)
                    if finding is None:
                        continue
                    key = (name, version, str(vuln.get("id") or ""))
                    if key in seen:
                        continue
                    seen.add(key)
                    emitted += 1
                    yield finding

    def _osv_finding(self, name: str, version: str, ecosystem: str, source: str,
                     vuln: dict) -> RawFinding | None:
        if not isinstance(vuln, dict):
            return None
        vid = str(vuln.get("id") or "").strip()
        if not vid:
            return None
        aliases = [str(a) for a in (vuln.get("aliases") or []) if str(a).startswith("CVE-")]
        db = vuln.get("database_specific") or {}
        sev = _OSV_SEVERITY.get(str(db.get("severity") or "").upper(), Severity.MEDIUM)
        summary = str(vuln.get("summary")
                      or f"{name}@{version} is affected by {vid}.").strip()[:400]
        return RawFinding(
            engine=EngineKey.SCA,
            title=f"Vulnerable dependency: {name}@{version} ({vid})"[:300],
            category="vuln-dep",
            description=summary,
            base_severity=sev,
            confidence="high",
            cve_ids=aliases,
            location={"path": source, "package": name, "version": version, "ecosystem": ecosystem},
            evidence=dependency_evidence(
                package=name, version=version, ecosystem=ecosystem, advisory=vid),
            references={"advisory": vid, "detector": "osv-scanner"},
        )

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
            exploit_maturity=vm.exploit_maturity,
            ransomware=vm.ransomware,
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
