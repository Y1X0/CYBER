"""CycloneDX SBOM builder — a Software Bill of Materials for a scanned asset.

An SBOM is the dependency inventory of the thing that was scanned: every component the SCA engine
resolved from the asset's manifests and lockfiles, in the CycloneDX 1.5 JSON format that
procurement and compliance (NTIA minimum elements, US EO 14028) ask for. It is a *view* over data
the platform already collects — not a second scanner and not a new finding type. Vulnerabilities are
cross-referenced from the scan's existing SCA findings so the SBOM and the findings never disagree.

Deliberately dependency-free (stdlib only), matching `tools/generate_sbom.py`'s self-SBOM shape so
the platform's own SBOM and a customer-asset SBOM read identically. Deterministic: components are
sorted and each carries a stable `bom-ref` (its PURL), so two SBOMs of the same inventory are byte
-identical and diffable across scans.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field

SPEC_VERSION = "1.5"
BOM_FORMAT = "CycloneDX"

# A generous cap: an SBOM is an inventory, not a finding list, but a pathological lockfile should
# never produce an unbounded document. Truncation is recorded in the metadata so a reader can tell
# "this is everything" from "this is the first N".
_MAX_COMPONENTS = 20_000

# Map the ecosystem labels the SCA engine emits to Package-URL (purl) types. An unknown ecosystem
# falls back to using its own label as the type — a stable, honest PURL rather than a wrong one.
_PURL_TYPE = {
    "pypi": "pypi",
    "npm": "npm",
    "go": "golang",
    "golang": "golang",
    "rubygems": "gem",
    "gem": "gem",
    "cargo": "cargo",
    "packagist": "composer",
    "composer": "composer",
    "maven": "maven",
    "nuget": "nuget",
    "apk": "apk",
    "deb": "deb",
    "rpm": "rpm",
}

# CycloneDX vulnerability ratings use lowercase severities; map the platform's Severity names.
_RATING = {"critical": "critical", "high": "high", "medium": "medium", "low": "low", "info": "info"}


@dataclass(frozen=True)
class Component:
    """One inventoried dependency: what the SCA engine already resolves per lockfile entry."""

    name: str
    version: str
    ecosystem: str
    source: str = ""  # the manifest/lockfile it came from (evidence, not identity)


@dataclass
class Vulnerability:
    """A vulnerability affecting one component, taken from the scan's existing SCA findings."""

    external_id: str  # CVE / advisory id
    severity: str = "medium"
    affects_name: str = ""
    affects_version: str = ""
    affects_ecosystem: str = ""
    description: str = ""


@dataclass
class Sbom:
    document: dict
    component_count: int
    vulnerable_count: int
    truncated: bool = False
    ecosystems: list[str] = field(default_factory=list)


def purl(name: str, version: str, ecosystem: str) -> str:
    """A Package-URL for a component. Also serves as its stable CycloneDX bom-ref."""
    eco = (ecosystem or "").strip().lower()
    ptype = _PURL_TYPE.get(eco, eco or "generic")
    # golang PURLs keep the module path (which contains slashes); other types keep the bare name.
    return f"pkg:{ptype}/{name.strip()}@{version.strip()}"


def _dedupe(components: Iterable[Component]) -> list[Component]:
    seen: dict[tuple[str, str, str], Component] = {}
    for c in components:
        if not c.name or not c.version:
            continue
        key = (c.name.lower(), c.version, (c.ecosystem or "").lower())
        seen.setdefault(key, c)
    return sorted(seen.values(), key=lambda c: (c.ecosystem.lower(), c.name.lower(), c.version))


def build_sbom(
    components: Iterable[Component],
    vulnerabilities: Iterable[Vulnerability] = (),
    *,
    subject_name: str,
    subject_kind: str = "application",
) -> Sbom:
    """Build a CycloneDX 1.5 SBOM from a resolved component inventory.

    `subject_name` names the scanned asset (the BOM's root component). Vulnerabilities are matched
    to components by (name, version, ecosystem); a vuln with no matching component is still listed
    (it references its own bom-ref) so nothing is silently dropped.
    """
    comps = _dedupe(components)
    truncated = len(comps) > _MAX_COMPONENTS
    if truncated:
        comps = comps[:_MAX_COMPONENTS]

    refs = {(c.name.lower(), c.version, (c.ecosystem or "").lower()): purl(c.name, c.version,
            c.ecosystem) for c in comps}

    component_objs = [
        {
            "type": "library",
            "bom-ref": refs[(c.name.lower(), c.version, (c.ecosystem or "").lower())],
            "name": c.name,
            "version": c.version,
            "purl": refs[(c.name.lower(), c.version, (c.ecosystem or "").lower())],
            **({"evidence": {"identity": {"field": "purl", "concludedValue": c.source}}}
               if c.source else {}),
        }
        for c in comps
    ]

    vuln_objs: list[dict] = []
    vulnerable_keys: set[tuple[str, str, str]] = set()
    # Group vulnerabilities by advisory id so one CVE affecting several components is one entry.
    by_id: dict[str, dict] = {}
    for v in vulnerabilities:
        vid = (v.external_id or "").strip()
        if not vid:
            continue
        key = (v.affects_name.lower(), v.affects_version, (v.affects_ecosystem or "").lower())
        ref = refs.get(key) or purl(v.affects_name or vid, v.affects_version or "0",
                                    v.affects_ecosystem)
        if key in refs:
            vulnerable_keys.add(key)
        entry = by_id.get(vid)
        if entry is None:
            entry = {
                "id": vid,
                "ratings": [{"severity": _RATING.get((v.severity or "medium").lower(), "medium")}],
                "affects": [],
            }
            if v.description:
                entry["description"] = v.description[:1000]
            by_id[vid] = entry
        if not any(a.get("ref") == ref for a in entry["affects"]):
            entry["affects"].append({"ref": ref})
    vuln_objs = [by_id[k] for k in sorted(by_id)]

    document = {
        "bomFormat": BOM_FORMAT,
        "specVersion": SPEC_VERSION,
        "version": 1,
        "metadata": {
            "component": {"type": subject_kind, "name": subject_name},
            "tools": [{"name": "guardian-sbom", "version": "1"}],
            **({"properties": [{"name": "guardian:truncated", "value": "true"}]}
               if truncated else {}),
        },
        "components": component_objs,
        **({"vulnerabilities": vuln_objs} if vuln_objs else {}),
    }
    ecosystems = sorted({(c.ecosystem or "").lower() for c in comps if c.ecosystem})
    return Sbom(
        document=document,
        component_count=len(comps),
        vulnerable_count=len(vulnerable_keys),
        truncated=truncated,
        ecosystems=ecosystems,
    )
