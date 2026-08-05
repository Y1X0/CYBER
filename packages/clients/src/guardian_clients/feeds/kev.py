"""CISA KEV client — the Known Exploited Vulnerabilities catalog.

A CVE appearing in KEV means it is being actively exploited; the Risk Engine treats that as a
strong escalation signal.
"""

from __future__ import annotations

import httpx

from guardian_clients.feeds.base import http_client

_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


class KevClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def fetch_kev_ids(self) -> set[str]:
        """Return the set of CVE ids currently in the KEV catalog. Empty on failure."""
        client = self._client or http_client(timeout=30.0)
        try:
            resp = client.get(_URL)
            resp.raise_for_status()
            data = resp.json()
            return {v["cveID"] for v in data.get("vulnerabilities", []) if v.get("cveID")}
        except (httpx.HTTPError, ValueError, KeyError):
            return set()
        finally:
            if self._client is None:
                client.close()
