"""OSV.dev client — query open-source vulnerabilities by package (SCA source of truth).

OSV aggregates GHSA, PyPA, RustSec, etc. and returns CVE aliases + affected ranges, which is
exactly what the SCA engine needs to match a dependency to known vulnerabilities.
"""

from __future__ import annotations

import httpx

from guardian_clients.feeds.base import FeedError, NormalizedVuln, http_client

_QUERY_URL = "https://api.osv.dev/v1/query"
# The whole corpus for one ecosystem, as a zip of JSON documents. This is how a knowledge base gets
# populated; the query endpoint answers one package at a time and cannot.
BULK_URL = "https://osv-vulnerabilities.storage.googleapis.com/{ecosystem}/all.zip"
MAX_BULK_RECORDS = 200_000

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
        """Known vulnerabilities affecting name@version.

        Raises `FeedError` on failure rather than returning an empty list. An empty list means the
        package is clean, and a client that says that when the feed is down hands the caller a false
        negative it cannot detect. Deciding to degrade is the caller's call — `OsvVulnMatcher` makes
        it explicitly, and logs it.
        """
        osv_eco = _ECOSYSTEM.get(ecosystem.lower(), ecosystem)
        payload = {"package": {"name": name, "ecosystem": osv_eco}, "version": version}
        client = self._client or http_client()
        try:
            resp = client.post(_QUERY_URL, json=payload)
            resp.raise_for_status()
            data = resp.json()
        except httpx.HTTPError as exc:
            raise FeedError(f"OSV query failed for {name}@{version}: {exc}") from exc
        except ValueError as exc:
            raise FeedError(f"OSV returned a body that is not JSON: {exc}") from exc
        finally:
            if self._owns and self._client is None:
                client.close()
        return [self._normalize(v, name, version, osv_eco) for v in data.get("vulns", [])]

    def fetch_ecosystem(self, ecosystem: str) -> list[NormalizedVuln]:  # pragma: no cover - network
        """Every advisory for one ecosystem, from the published bulk archive.

        Raises on failure. An empty ecosystem would mean npm has no known vulnerabilities, which is
        a claim no scanner should make on the strength of a failed download.
        """
        osv_eco = _ECOSYSTEM.get(ecosystem.lower(), ecosystem)
        client = self._client or http_client(timeout=300.0)
        try:
            response = client.get(BULK_URL.format(ecosystem=osv_eco))
            response.raise_for_status()
            raw = response.content
        except httpx.HTTPError as exc:
            raise FeedError(f"OSV bulk download failed for {osv_eco}: {exc}") from exc
        finally:
            if self._client is None:
                client.close()
        return parse_bulk_zip(raw, osv_eco)

    @staticmethod
    def _normalize(v: dict, name: str, version: str, ecosystem: str) -> NormalizedVuln:
        aliases = v.get("aliases", [])
        cve = next((a for a in aliases if a.startswith("CVE-")), v.get("id", ""))
        # Prefer a v3 vector: severity entries can carry v2, v3 and v4 side by side, and the
        # scoring arithmetic differs per version, so picking the first one blindly mis-scores.
        cvss_vector = None
        for entry in v.get("severity", []) or []:
            if not isinstance(entry, dict):
                continue
            score = entry.get("score")
            if isinstance(score, str) and score.startswith("CVSS:3"):
                cvss_vector = score
                break
            cvss_vector = cvss_vector or (score if isinstance(score, str) else None)

        # GHSA records carry CWE ids here; they are what the analyst grounds an explanation on.
        specific = v.get("database_specific") or {}
        cwe_ids = [str(c) for c in (specific.get("cwe_ids") or []) if str(c).startswith("CWE-")]

        return NormalizedVuln(
            external_id=cve,
            source="osv",
            summary=v.get("summary", ""),
            details=v.get("details", "")[:8000],
            cwe_ids=cwe_ids,
            cvss_vector=cvss_vector,
            # OSV's query endpoint returns only advisories affecting the version we asked about,
            # so the match is already established; the entry records what was asked, not a range.
            affected=[{"ecosystem": ecosystem, "package": name, "version": version}],
            references=[r.get("url") for r in v.get("references", []) if r.get("url")],
        )


def parse_bulk_zip(raw: bytes, ecosystem: str) -> list[NormalizedVuln]:
    """Parse an OSV `all.zip`: one JSON document per advisory."""
    import io
    import json
    import zipfile

    try:
        archive = zipfile.ZipFile(io.BytesIO(raw))
    except zipfile.BadZipFile as exc:
        raise FeedError(f"OSV bulk archive for {ecosystem} is not a zip: {exc}") from exc

    records: list[NormalizedVuln] = []
    for name in archive.namelist()[:MAX_BULK_RECORDS]:
        if not name.endswith(".json"):
            continue
        try:
            document = json.loads(archive.read(name))
        except (ValueError, KeyError, zipfile.BadZipFile):
            continue
        record = parse_osv_record(document, ecosystem)
        if record is not None:
            records.append(record)
    if not records:
        raise FeedError(f"OSV bulk archive for {ecosystem} yielded no advisories")
    return records


def parse_osv_record(document: dict, ecosystem: str = "") -> NormalizedVuln | None:
    """One OSV advisory document, with its affected ranges preserved.

    Unlike the query endpoint — which is asked about one version and answers yes or no — a bulk
    record carries the ranges themselves. Those are what `guardian_core.versioning` evaluates, so
    the knowledge base can answer for a version it has never been asked about before.
    """
    if not isinstance(document, dict):
        return None
    osv_id = str(document.get("id") or "")
    if not osv_id:
        return None
    aliases = [str(a) for a in (document.get("aliases") or [])]
    external_id = next((a for a in aliases if a.startswith("CVE-")), osv_id)

    cvss_vector = None
    for entry in document.get("severity") or []:
        if isinstance(entry, dict) and isinstance(entry.get("score"), str):
            score = entry["score"]
            if score.startswith("CVSS:3"):
                cvss_vector = score
                break
            cvss_vector = cvss_vector or score

    specific = document.get("database_specific") or {}
    cwe_ids = [str(c) for c in (specific.get("cwe_ids") or []) if str(c).startswith("CWE-")]

    affected: list[dict] = []
    for entry in document.get("affected") or []:
        if not isinstance(entry, dict):
            continue
        package = entry.get("package") or {}
        affected.append({
            "ecosystem": str(package.get("ecosystem") or ecosystem),
            "package": str(package.get("name") or ""),
            "ranges": entry.get("ranges") or [],
            "versions": entry.get("versions") or [],
        })

    record = NormalizedVuln(
        external_id=external_id,
        source="osv",
        summary=str(document.get("summary") or "")[:2000],
        details=str(document.get("details") or "")[:8000],
        cwe_ids=cwe_ids,
        cvss_vector=cvss_vector,
        affected=affected,
        references=[
            str(r.get("url")) for r in (document.get("references") or [])
            if isinstance(r, dict) and r.get("url")
        ][:40],
    )
    record.published_at = _osv_time(document.get("published"))
    record.modified_at = _osv_time(document.get("modified"))
    return record


def _osv_time(value):  # noqa: ANN001, ANN202
    import datetime as dt

    if not isinstance(value, str) or not value:
        return None
    try:
        parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
