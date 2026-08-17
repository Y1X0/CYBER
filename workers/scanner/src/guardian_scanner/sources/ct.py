"""Certificate Transparency as a discovery source (ADR-0026).

CT logs list every certificate ever issued for a domain, which makes them the highest-confidence
passive way to learn a company's subdomains: a CT record is a real certificate someone asked a CA
to sign, not a guess. Nothing is sent to the customer's own infrastructure.

The single risk is egress to a third party, so the HTTP path is treated as UNTRUSTED and confined
so this can never be turned into an SSRF pivot:

  * requests go ONLY to the fixed CT host over https — the endpoint is a constant, never wired in;
  * the target domain rides ONLY in the query string, so it can never change the host;
  * a redirect is refused rather than followed to a response-chosen location;
  * the CT host must resolve to a PUBLIC address (private/loopback/link-local/metadata → refused);
  * the response is size-bounded, and the *discovered* names are DATA — never fetched.

This module holds the one implementation. It was extracted from the CT tool provider so the
discovery pipeline could reuse it verbatim instead of growing a second copy to keep in review.
"""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from urllib.parse import quote, urlsplit

from guardian_common.logging import get_logger

log = get_logger("guardian.sources.ct")

# Fixed, code-owned CT endpoint allowlist — NEVER supplied by the wire (ADR-0026 §4).
CT_HOST = "crt.sh"
CT_HOSTS = frozenset({CT_HOST})
SCHEME = "https"
TIMEOUT = 8
MAX_BYTES = 5_000_000
MAX_ASSETS = 5000

# A target must look like a hostname before we ever build a URL from it (defense in depth).
DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class EgressBlocked(RuntimeError):
    """A network egress was refused by the SSRF guard (fail-closed)."""


def is_blocked_ip(ip: str) -> bool:
    """True for any address we must never egress to: private/loopback/link-local (incl. cloud
    metadata 169.254.169.254 / fd00:ec2::)/multicast/reserved/unspecified, or a non-literal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a literal address → cannot vouch for it → block
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def ct_url(domain: str) -> str:
    """Build the CT query URL. The domain rides ONLY in the query string (URL-encoded), so it can
    never change the host; the host is the fixed constant."""
    return f"{SCHEME}://{CT_HOST}/?q={quote(domain, safe='')}&output=json"


def assert_endpoint_allowed(url: str) -> None:
    """Refuse any URL that is not https to the fixed CT host — enforced, not by convention."""
    parts = urlsplit(url)
    if parts.scheme != SCHEME:
        raise EgressBlocked(f"scheme not allowed: {parts.scheme!r}")
    host = (parts.hostname or "").lower()
    if host not in CT_HOSTS:
        raise EgressBlocked(f"host not in CT allowlist: {host!r}")


def ensure_not_redirect(status_code: int) -> None:
    """Refuse a redirect — we never follow to a response-chosen location (SSRF guard)."""
    if 300 <= status_code < 400:
        raise EgressBlocked(f"redirect refused: {status_code}")


def assert_ct_host_public() -> None:
    """Resolve the fixed CT host and refuse if ANY address is non-public (DNS-rebinding/SSRF)."""
    infos = socket.getaddrinfo(CT_HOST, 443, proto=socket.IPPROTO_TCP)
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise EgressBlocked(f"no address for {CT_HOST!r}")
    for ip in ips:
        if is_blocked_ip(ip):
            raise EgressBlocked(f"{CT_HOST!r} resolves to non-public {ip}")


def under_domain(host: str, domain: str) -> bool:
    """Scope hygiene: only assets AT/under the authorized domain (a cert may list foreign SANs)."""
    return host == domain or host.endswith("." + domain)


def parse_ct_names(raw: bytes) -> list[str]:
    """Extract hostnames from a CT JSON response; wildcards flattened, deduped, sorted. Never dumps
    the raw payload — only sanitized names leave this function."""
    try:
        rows = json.loads(raw)
    except (ValueError, TypeError):
        return []
    names: set[str] = set()
    if isinstance(rows, list):
        for row in rows:
            if not isinstance(row, dict):
                continue
            value = row.get("name_value") or row.get("common_name") or ""
            for line in str(value).splitlines():
                host = line.strip().lower().lstrip("*.").rstrip(".")
                if host:
                    names.add(host)
    return sorted(names)


def fetch_ct_live(domain: str) -> list[str]:  # pragma: no cover - network
    """Hardened live CT fetch: fixed host, no redirects, public-only resolution, bounded size."""
    import httpx  # noqa: PLC0415 - kept local so importing this module needs no HTTP stack

    url = ct_url(domain)
    assert_endpoint_allowed(url)
    assert_ct_host_public()
    with httpx.Client(follow_redirects=False, timeout=TIMEOUT) as client:
        resp = client.get(url, headers={"user-agent": "guardian-surface-discovery"})
        ensure_not_redirect(resp.status_code)
        if resp.status_code != 200:
            return []
        raw = resp.content[:MAX_BYTES]
    return parse_ct_names(raw)


def hosts_for_domain(domain: str, *, allow_live: bool, snapshot: dict | None) -> list[str]:
    """Every host CT knows about for `domain`, scoped to the domain and deduplicated.

    Offline by default so CI and tests open no socket. `allow_live` is the only switch that opens
    the network, and a refused egress yields an empty list rather than an exception — the caller
    treats "no observation" as unknown, never as a finding.
    """
    domain = domain.strip().lower().rstrip(".")
    if not DOMAIN_RE.match(domain):
        return []                                   # never build a URL from a bad target
    if allow_live:
        # A blocked egress and a domain with genuinely no certificates both produce an empty list,
        # and an operator cannot tell those apart from the result alone. Log the reason so "we
        # could not look" is never read as "there is nothing there".
        try:
            raw_hosts = fetch_ct_live(domain)
        except EgressBlocked as exc:
            log.warning("ct_egress_blocked", domain=domain, reason=str(exc)[:200])
            return []                               # fail-closed: refuse egress, emit none
        except Exception as exc:  # noqa: BLE001 - a CT outage must never fail a discovery run
            log.warning("ct_fetch_failed", domain=domain, error=type(exc).__name__,
                        detail=str(exc)[:200])
            return []
    else:
        entry = (snapshot or {}).get(domain)
        raw_hosts = [str(h) for h in entry] if isinstance(entry, list) else []

    hosts = {
        host
        for host in (str(h).strip().lower().lstrip("*.").rstrip(".") for h in raw_hosts)
        if host and under_domain(host, domain)
    }
    return sorted(hosts)[:MAX_ASSETS]
