"""Generate a self-SBOM — an inventory of the platform's own installed dependencies (Phase 5A).

A CycloneDX-lite JSON document listing every installed distribution with its version and PURL. This
is the "know your own supply chain" foundation: the same inventory a customer would demand of a
security vendor. Emitted in CI as an artifact and consumed by the dependency self-scan (pip-audit).

Deliberately dependency-free (stdlib `importlib.metadata` only) so it can run in any environment,
including a minimal build image, without pulling in an SBOM library.

Usage:
    python tools/generate_sbom.py [output_path]      # default: sbom.json
"""

from __future__ import annotations

import json
import sys
from importlib import metadata


def _components() -> list[dict]:
    seen: dict[str, str] = {}
    for dist in metadata.distributions():
        name = (dist.metadata["Name"] or "").strip()
        if not name or name in seen:
            continue
        seen[name] = dist.version or "0"
    return [
        {
            "type": "library",
            "name": name,
            "version": version,
            "purl": f"pkg:pypi/{name.lower()}@{version}",
        }
        for name, version in sorted(seen.items(), key=lambda kv: kv[0].lower())
    ]


def build_sbom() -> dict:
    components = _components()
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "security-guardian-platform",
            },
            "tools": [{"name": "guardian-self-sbom", "version": "1"}],
        },
        "components": components,
    }


def main() -> int:
    out_path = sys.argv[1] if len(sys.argv) > 1 else "sbom.json"
    sbom = build_sbom()
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(sbom, f, indent=2, sort_keys=True)
        f.write("\n")
    print(f"wrote {out_path}: {len(sbom['components'])} components")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
