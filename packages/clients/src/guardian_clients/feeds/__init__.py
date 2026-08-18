"""Vulnerability data-feed clients: NVD, OSV, EPSS, CISA KEV.

Each client is a thin, timeout-bounded HTTP wrapper returning normalized records.

**A failure is raised, not returned as an empty result** (WP-C1). The older behaviour — degrade to
an empty list so a feed outage never breaks a scan — sounds defensive and is not: an empty feed
result is indistinguishable from a clean scan, so an outage silently became "no vulnerabilities
found" and the knowledge base went stale with nothing to show for it. Callers decide what to do
with a failure; they can no longer be unaware there was one.

Parsing is separated from fetching in every client, so what a feed's payload means is testable
without a network, and a contract change in the feed fails a test instead of a customer's scan.
"""

from guardian_clients.feeds.base import FeedError, NormalizedVuln
from guardian_clients.feeds.epss import EpssClient, parse_epss_csv
from guardian_clients.feeds.exploits import (
    ExploitDbClient,
    ExploitRecord,
    MetasploitClient,
    parse_exploitdb_csv,
    parse_metasploit_metadata,
    strongest,
)
from guardian_clients.feeds.kev import KevClient, KevRecord, parse_kev
from guardian_clients.feeds.nvd import NvdClient, parse_cve, parse_page
from guardian_clients.feeds.osv import OsvClient, parse_osv_record

__all__ = [
    "EpssClient",
    "ExploitDbClient",
    "ExploitRecord",
    "FeedError",
    "KevClient",
    "KevRecord",
    "NormalizedVuln",
    "MetasploitClient",
    "NvdClient",
    "OsvClient",
    "parse_cve",
    "parse_epss_csv",
    "parse_exploitdb_csv",
    "parse_metasploit_metadata",
    "parse_kev",
    "parse_osv_record",
    "parse_page",
    "strongest",
]
