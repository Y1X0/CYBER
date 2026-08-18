"""CISA KEV client — the catalogue of vulnerabilities known to be exploited (WP-C1).

KEV is the single highest-signal input the risk engine has. A CVE in this catalogue is not
theoretically exploitable; someone is exploiting it, which is why a CVSS 7.5 in KEV outranks a
CVSS 9.8 that is not. The record also says whether ransomware campaigns use it and when the US
federal remediation deadline falls — both worth showing a customer verbatim rather than folding
into a score.

The whole catalogue is one JSON document of a few thousand entries, so there is no paging and no
watermark: a sync replaces what it knows.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass

import httpx

from guardian_clients.feeds.base import FeedError, http_client

URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


@dataclass(frozen=True)
class KevRecord:
    cve_id: str
    vendor: str = ""
    product: str = ""
    name: str = ""
    date_added: dt.date | None = None
    due_date: dt.date | None = None
    ransomware: bool = False
    required_action: str = ""


class KevClient:
    def __init__(self, client: httpx.Client | None = None) -> None:
        self._client = client

    def fetch(self) -> list[KevRecord]:  # pragma: no cover - network
        """The full catalogue. Raises `FeedError` on failure — an empty catalogue would read as
        "nothing is being exploited right now", which has never been true."""
        client = self._client or http_client(timeout=60.0)
        try:
            response = client.get(URL)
            response.raise_for_status()
            payload = response.json()
        except httpx.HTTPError as exc:
            raise FeedError(f"KEV request failed: {type(exc).__name__}: {exc}") from exc
        except ValueError as exc:
            raise FeedError(f"KEV returned a body that is not JSON: {exc}") from exc
        finally:
            if self._client is None:
                client.close()
        return parse_kev(payload)

    def fetch_kev_ids(self) -> set[str]:  # pragma: no cover - network
        """The CVE ids alone, for callers that only need the flag."""
        return {record.cve_id for record in self.fetch()}


def parse_kev(payload: dict) -> list[KevRecord]:
    if not isinstance(payload, dict) or "vulnerabilities" not in payload:
        raise FeedError("KEV payload has no `vulnerabilities` key — the feed contract changed")
    records: list[KevRecord] = []
    for entry in payload.get("vulnerabilities") or []:
        if not isinstance(entry, dict):
            continue
        cve_id = str(entry.get("cveID") or "")
        if not cve_id.startswith("CVE-"):
            continue
        records.append(KevRecord(
            cve_id=cve_id,
            vendor=str(entry.get("vendorProject") or ""),
            product=str(entry.get("product") or ""),
            name=str(entry.get("vulnerabilityName") or "")[:300],
            date_added=_date(entry.get("dateAdded")),
            due_date=_date(entry.get("dueDate")),
            # The field is a string "Known"/"Unknown", not a boolean. Treating any truthy value as
            # yes would mark every entry as ransomware-linked.
            ransomware=(str(entry.get("knownRansomwareCampaignUse") or "").strip().lower()
                        == "known"),
            required_action=str(entry.get("requiredAction") or "")[:500],
        ))
    if not records:
        raise FeedError("KEV payload contained no usable records")
    return records


def _date(value: object) -> dt.date | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return dt.date.fromisoformat(value[:10])
    except ValueError:
        return None
