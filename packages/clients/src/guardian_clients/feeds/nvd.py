"""NVD 2.0 client — the authoritative CVE record, including CPE applicability (WP-C1).

NVD is the only feed that says which *product versions* a CVE applies to in machine-readable CPE
terms. That is what turns "this host runs OpenSSH 8.9p1" into "and these four advisories apply",
which no package-manager feed can answer because a service on a port has no lockfile.

Two behaviours are deliberate and differ from the older clients in this package:

**Failures are raised, not returned as an empty list.** A feed outage that reports zero
vulnerabilities is indistinguishable from a clean scan, and the platform would happily record
"synced, 0 items" while the knowledge base silently went stale.

**Paging is explicit and resumable.** The API returns a `totalResults`, and a sync that stopped
halfway must say so rather than let the caller assume it saw everything.
"""

from __future__ import annotations

import datetime as dt
from collections.abc import Iterator
from dataclasses import dataclass, field

import httpx

from guardian_clients.feeds.base import FeedError, NormalizedVuln, http_client

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE_SIZE = 2_000          # the API's maximum
MAX_PAGES = 200            # a backstop: 400k records is more than the whole corpus
# NVD rejects a window wider than 120 days on the lastModified filter.
MAX_WINDOW_DAYS = 110


@dataclass
class FeedPage:
    records: list[NormalizedVuln] = field(default_factory=list)
    start_index: int = 0
    total: int = 0

    @property
    def next_index(self) -> int:
        return self.start_index + len(self.records)

    @property
    def exhausted(self) -> bool:
        return self.next_index >= self.total


class NvdClient:
    def __init__(self, client: httpx.Client | None = None, api_key: str | None = None) -> None:
        self._client = client
        self._api_key = api_key

    # ── network ──────────────────────────────────────────────────────────────────────────────────
    def _headers(self) -> dict[str, str]:
        # An API key raises the rate limit from 5 to 50 requests per 30 seconds. Optional: without
        # one the sync is slower, not broken, so a missing key is not an error.
        return {"apiKey": self._api_key} if self._api_key else {}

    def fetch_page(  # pragma: no cover - network
        self, *, start_index: int = 0, modified_since: dt.datetime | None = None,
        modified_until: dt.datetime | None = None,
    ) -> FeedPage:
        params: dict[str, object] = {"resultsPerPage": PAGE_SIZE, "startIndex": start_index}
        if modified_since is not None:
            until = modified_until or dt.datetime.now(dt.UTC)
            params["lastModStartDate"] = _stamp(modified_since)
            params["lastModEndDate"] = _stamp(until)

        client = self._client or http_client(timeout=60.0)
        try:
            response = client.get(API_URL, params=params, headers=self._headers())
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise FeedError(f"NVD request failed: {type(exc).__name__}: {exc}") from exc
        except ValueError as exc:
            raise FeedError(f"NVD returned a body that is not JSON: {exc}") from exc
        finally:
            if self._client is None:
                client.close()
        return parse_page(payload, start_index)

    def fetch_all(  # pragma: no cover - network
        self, *, modified_since: dt.datetime | None = None
    ) -> Iterator[NormalizedVuln]:
        """Every record in the window, page by page. Raises rather than truncating silently."""
        index = 0
        for _page_number in range(MAX_PAGES):
            page = self.fetch_page(start_index=index, modified_since=modified_since)
            yield from page.records
            if page.exhausted or not page.records:
                return
            index = page.next_index
        raise FeedError(
            f"NVD paging exceeded {MAX_PAGES} pages — refusing to continue rather than "
            "silently ingesting a partial corpus"
        )


def _stamp(when: dt.datetime) -> str:
    return when.astimezone(dt.UTC).strftime("%Y-%m-%dT%H:%M:%S.000")


def windows(
    since: dt.datetime, until: dt.datetime, *, days: int = MAX_WINDOW_DAYS
) -> list[tuple[dt.datetime, dt.datetime]]:
    """Split a range into windows NVD will accept.

    A first sync asks for everything since the epoch, and the API rejects any lastModified window
    wider than 120 days. Splitting here rather than at the call site means the caller cannot
    accidentally request a window that is refused and read the refusal as "nothing changed".
    """
    if until <= since:
        return []
    spans: list[tuple[dt.datetime, dt.datetime]] = []
    cursor = since
    step = dt.timedelta(days=days)
    while cursor < until:
        end = min(cursor + step, until)
        spans.append((cursor, end))
        cursor = end
    return spans


# ── parsing (pure) ────────────────────────────────────────────────────────────────────────────────
def parse_page(payload: dict, start_index: int = 0) -> FeedPage:
    if not isinstance(payload, dict):
        raise FeedError("NVD page is not an object")
    if "vulnerabilities" not in payload:
        raise FeedError("NVD page has no `vulnerabilities` key — the API contract changed")
    records = [
        parse_cve(item["cve"])
        for item in payload.get("vulnerabilities") or []
        if isinstance(item, dict) and isinstance(item.get("cve"), dict)
    ]
    return FeedPage(
        records=[r for r in records if r is not None],
        start_index=int(payload.get("startIndex", start_index) or 0),
        total=int(payload.get("totalResults", len(records)) or 0),
    )


def parse_cve(cve: dict) -> NormalizedVuln | None:
    cve_id = str(cve.get("id") or "")
    if not cve_id.startswith("CVE-"):
        return None

    summary = ""
    for description in cve.get("descriptions") or []:
        if isinstance(description, dict) and description.get("lang") == "en":
            summary = str(description.get("value") or "")
            break

    vector, score, severity = _best_metric(cve.get("metrics") or {})
    record = NormalizedVuln(
        external_id=cve_id,
        source="nvd",
        summary=summary[:2000],
        details=summary[:8000],
        cwe_ids=_cwes(cve.get("weaknesses") or []),
        cvss_base=score,
        cvss_vector=vector,
        references=[
            str(reference.get("url"))
            for reference in (cve.get("references") or [])
            if isinstance(reference, dict) and reference.get("url")
        ][:40],
    )
    record.severity = severity
    record.cpe_configurations = cpe_configurations(cve.get("configurations") or [])
    record.published_at = _parse_time(cve.get("published"))
    record.modified_at = _parse_time(cve.get("lastModified"))
    return record


def _best_metric(metrics: dict) -> tuple[str | None, float | None, str | None]:
    """Prefer CVSS v3.1, then v3.0, then v4, then v2.

    Version matters: the arithmetic differs, so a v2 score of 5.0 and a v3 score of 5.0 do not
    describe the same severity, and taking whichever key happens to come first mis-ranks findings.
    """
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV40", "cvssMetricV2"):
        entries = metrics.get(key)
        if not entries:
            continue
        primary = next(
            (e for e in entries if isinstance(e, dict) and e.get("type") == "Primary"),
            entries[0] if isinstance(entries[0], dict) else None,
        )
        if primary is None:
            continue
        data = primary.get("cvssData") or {}
        severity = primary.get("baseSeverity") or data.get("baseSeverity")
        score = data.get("baseScore")
        return (
            str(data.get("vectorString")) if data.get("vectorString") else None,
            float(score) if isinstance(score, int | float) else None,
            str(severity).lower() if severity else None,
        )
    return None, None, None


def _cwes(weaknesses: list) -> list[str]:
    found: list[str] = []
    for weakness in weaknesses:
        if not isinstance(weakness, dict):
            continue
        for description in weakness.get("description") or []:
            value = str((description or {}).get("value") or "")
            if value.startswith("CWE-") and value not in found:
                found.append(value)
    return found[:10]


def cpe_configurations(configurations: list) -> list[dict]:
    """Flatten NVD's nested configuration tree into applicability rows.

    NVD expresses applicability as nodes of `cpeMatch` entries with optional version bounds. The
    nesting encodes AND/OR relationships between a running product and the platform it runs on;
    that structure matters for exploitability, but for "does this advisory mention this product at
    this version" the flat list is what a lookup needs, and keeping it flat keeps the query — and
    the index behind it — simple enough to be fast.

    Only entries marked vulnerable are kept. A non-vulnerable entry names the platform the
    vulnerable product runs on, and treating it as affected would attribute the CVE to the
    operating system.
    """
    rows: list[dict] = []
    # A row is identified by its CPE plus its bounds. Deduplicated because the same product with
    # the same range legitimately appears under several nodes, and a duplicated applicability row
    # would double-count in a later match and inflate the stored document for no benefit.
    seen: set[tuple] = set()

    def walk(node: dict) -> None:
        for match in node.get("cpeMatch") or []:
            if not isinstance(match, dict) or not match.get("vulnerable"):
                continue
            criteria = str(match.get("criteria") or "")
            parsed = parse_cpe(criteria)
            if parsed is None:
                continue
            vendor, product, version = parsed
            row = {
                "cpe": criteria,
                "vendor": vendor,
                "product": product,
                "version": version,
                "version_start_including": match.get("versionStartIncluding"),
                "version_start_excluding": match.get("versionStartExcluding"),
                "version_end_including": match.get("versionEndIncluding"),
                "version_end_excluding": match.get("versionEndExcluding"),
            }
            identity = tuple(sorted((k, str(v)) for k, v in row.items()))
            if identity in seen:
                continue
            seen.add(identity)
            rows.append(row)
        for child in node.get("nodes") or []:
            if isinstance(child, dict):
                walk(child)

    for configuration in configurations:
        # `walk` descends into `nodes` itself, and also reads a `cpeMatch` sitting directly on the
        # object — so one call covers both shapes. Walking the nodes here as well would visit every
        # match twice.
        if isinstance(configuration, dict):
            walk(configuration)
    return rows[:200]


def parse_cpe(criteria: str) -> tuple[str, str, str] | None:
    """(vendor, product, version) from a CPE 2.3 string, or None if it is not one."""
    parts = criteria.split(":")
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return parts[3], parts[4], parts[5]


def _parse_time(value: object) -> dt.datetime | None:
    if not isinstance(value, str) or not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.UTC)
