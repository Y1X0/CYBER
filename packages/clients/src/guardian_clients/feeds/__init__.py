"""Vulnerability data-feed clients: OSV, EPSS, CISA KEV (NVD/GHSA follow the same interface).

Each client is a thin, timeout-bounded HTTP wrapper that returns normalized dicts and degrades
gracefully (empty result on failure) so a feed outage never breaks a scan. Enrichment/ingestion
into the KB is orchestrated by the feed-sync task in the worker.
"""

from guardian_clients.feeds.base import FeedError, NormalizedVuln
from guardian_clients.feeds.epss import EpssClient
from guardian_clients.feeds.kev import KevClient
from guardian_clients.feeds.osv import OsvClient

__all__ = ["EpssClient", "FeedError", "KevClient", "NormalizedVuln", "OsvClient"]
