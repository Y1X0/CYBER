"""EPSS client (FIRST.org) — how likely a CVE is to be exploited in the next 30 days (WP-C1).

EPSS turns "this is theoretically severe" into "this is the one that will actually be used", and it
is what stops a report from ranking 400 criticals by CVSS alone.

The per-CVE endpoint that existed before is kept for a single lookup, but it cannot be the sync
mechanism: enriching a knowledge base of a quarter of a million CVEs one HTTP request at a time is
not a pipeline. `fetch_all` reads the daily bulk CSV — every score in one gzipped download — which
is the interface FIRST publishes for exactly this.
"""

from __future__ import annotations

import csv
import gzip
import io

import httpx

from guardian_clients.feeds.base import FeedError, http_client

API_URL = "https://api.first.org/data/v1/epss"
BULK_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
MAX_ROWS = 500_000


class EpssClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def score_for(self, cve_id: str) -> float | None:  # pragma: no cover - network
        """One CVE's probability. For a single lookup; never for a sync."""
        client = self._client or http_client()
        try:
            response = client.get(API_URL, params={"cve": cve_id})
            response.raise_for_status()
            rows = response.json().get("data", [])
        except httpx.HTTPError as exc:
            raise FeedError(f"EPSS request failed: {type(exc).__name__}: {exc}") from exc
        except ValueError as exc:
            raise FeedError(f"EPSS returned a body that is not JSON: {exc}") from exc
        finally:
            if self._client is None:
                client.close()
        if not rows:
            return None
        try:
            return float(rows[0]["epss"])
        except (KeyError, TypeError, ValueError) as exc:
            raise FeedError(f"EPSS row has no usable score: {exc}") from exc

    def fetch_all(self) -> dict[str, float]:  # pragma: no cover - network
        """Every current score, from the daily bulk CSV."""
        client = self._client or http_client(timeout=120.0)
        try:
            response = client.get(BULK_URL)
            response.raise_for_status()
            raw = response.content
        except httpx.HTTPError as exc:
            raise FeedError(f"EPSS bulk download failed: {type(exc).__name__}: {exc}") from exc
        finally:
            if self._client is None:
                client.close()
        return parse_epss_csv(raw)


def parse_epss_csv(raw: bytes) -> dict[str, float]:
    """Parse the bulk CSV, gzipped or not.

    The file opens with a `#model_version` comment line before the header, so a plain `DictReader`
    reads that comment as the column names and every row comes back keyed wrongly — silently, with
    no error and no scores.
    """
    if raw[:2] == b"\x1f\x8b":
        try:
            raw = gzip.decompress(raw)
        except OSError as exc:
            raise FeedError(f"EPSS bulk file is not valid gzip: {exc}") from exc

    text = raw.decode("utf-8", "replace")
    lines = [line for line in text.splitlines() if line and not line.startswith("#")]
    if not lines:
        raise FeedError("EPSS bulk file contained no rows")

    reader = csv.DictReader(io.StringIO("\n".join(lines)))
    if not reader.fieldnames or "cve" not in reader.fieldnames or "epss" not in reader.fieldnames:
        raise FeedError(
            f"EPSS CSV header is not what was expected: {reader.fieldnames} — the feed changed"
        )

    scores: dict[str, float] = {}
    for row in reader:
        cve = (row.get("cve") or "").strip()
        if not cve.startswith("CVE-"):
            continue
        try:
            scores[cve] = float(row.get("epss") or 0.0)
        except (TypeError, ValueError):
            continue
        if len(scores) >= MAX_ROWS:
            break
    if not scores:
        raise FeedError("EPSS bulk file parsed to zero scores")
    return scores
