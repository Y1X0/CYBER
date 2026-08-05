"""EPSS client (FIRST.org) — exploit-probability enrichment for CVEs.

EPSS turns "is this theoretically bad" into "how likely is it to actually be exploited", a key
Risk Engine input.
"""

from __future__ import annotations

import httpx

from guardian_clients.feeds.base import http_client

_URL = "https://api.first.org/data/v1/epss"


class EpssClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def score_for(self, cve_id: str) -> float | None:
        """Return the EPSS probability (0–1) for a CVE, or None if unavailable."""
        client = self._client or http_client()
        try:
            resp = client.get(_URL, params={"cve": cve_id})
            resp.raise_for_status()
            rows = resp.json().get("data", [])
            if rows:
                return float(rows[0]["epss"])
            return None
        except (httpx.HTTPError, ValueError, KeyError):
            return None
        finally:
            if self._client is None:
                client.close()
