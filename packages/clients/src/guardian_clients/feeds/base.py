"""Shared types and HTTP helper for feed clients."""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field

import httpx

DEFAULT_TIMEOUT = 15.0


class FeedError(Exception):
    """Raised for unrecoverable feed errors (callers usually degrade to empty results)."""


@dataclass
class NormalizedVuln:
    """A vulnerability normalized to the platform's KB shape."""

    external_id: str
    source: str
    summary: str = ""
    details: str = ""
    cwe_ids: list[str] = field(default_factory=list)
    cvss_base: float | None = None
    cvss_vector: str | None = None
    epss_score: float | None = None
    kev: bool = False
    severity: str | None = None
    # OSV-style package ranges — "is this dependency vulnerable".
    affected: list = field(default_factory=list)
    # CPE applicability from NVD — "is this running build vulnerable" (WP-C1/C3).
    cpe_configurations: list = field(default_factory=list)
    references: list = field(default_factory=list)
    published_at: dt.datetime | None = None
    modified_at: dt.datetime | None = None


def http_client(timeout: float = DEFAULT_TIMEOUT) -> httpx.Client:
    # Respects HTTPS_PROXY / CA bundle from the environment (sandbox egress rules apply).
    return httpx.Client(
        timeout=timeout, follow_redirects=True, headers={"User-Agent": "SecurityGuardian/0.1"}
    )
