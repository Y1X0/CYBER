"""OSV.dev client — query open-source vulnerabilities by package (SCA source of truth).

OSV aggregates GHSA, PyPA, RustSec, etc. and returns CVE aliases + affected ranges, which is
exactly what the SCA engine needs to match a dependency to known vulnerabilities.
"""

from __future__ import annotations

import httpx

from guardian_clients.feeds.base import NormalizedVuln, http_client

_QUERY_URL = "https://api.osv.dev/v1/query"

# Map our ecosystem hints to OSV ecosystem names.
_ECOSYSTEM = {
    "pypi": "PyPI",
    "python": "PyPI",
    "npm": "npm",
    "node": "npm",
    "go": "Go",
    "maven": "Maven",
    "rubygems": "RubyGems",
    "cargo": "crates.io",
}


class OsvClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client
        self._owns = client is None

    def query_package(self, *, name: str, version: str, ecosystem: str) -> list[NormalizedVuln]:
        """Return known vulnerabilities affecting name@version. Empty on any failure."""
        osv_eco = _ECOSYSTEM.get(ecosystem.lower(), ecosystem)
        payload = {"package": {"name": name, "ecosystem": osv_eco}, "version": version}
        client = self._client or http_client()
        try:
            resp = client.post(_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except (httpx.HTTPError, ValueError):
            return []
        finally:
            if self._owns and self._client is None:
                client.close()
        return [self._normalize(v, name, version, osv_eco) for v in data.get("vulns", [])]

    @staticmethod
    def _normalize(v: dict, name: str, version: str, ecosystem: str) -> NormalizedVuln:
        aliases = v.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
        severity = v.get("severity", [])
        cvss_vector = severity[0]["score"] if severity else None
        return NormalizedVuln(
            external_id=cve,
            source="osv",
            summary=v.get("summary", ""),
            details=v.get("details", "")[:8000],
            cvss_vector=cvss_vector,
            affected=[{"ecosystem": ecosystem, "package": name, "version": version}],
            references=[r.get("url") for r in v.get("references", []) if r.get("url")],
        )
