"""CT-log passive attack-surface discovery provider (Framework — Provider #4, L1).

Locked by ADR-0026. It discovers the attack surface of an *authorized* domain from Certificate
Transparency logs — the subdomains/hosts a certificate was ever issued for — WITHOUT touching the
customer's target (`active=False`). It opens the network only to a fixed, code-owned CT endpoint and
returns `discovered_asset` evidence; the assets feed the World Model / netblock graph, which then
feeds Nmap and Web/TLS. It is NOT a finding source — an asset is inventory, not a vulnerability.

Governance: derived level is **L1 PASSIVE_NETWORK** (network=True, active=False) — no campaign, no
approval. In-process (no external binary → in-proc sandbox, never uid_nft).

The one new risk is data egress to a third party, so v1 is scoped hard (CT logs only, no API key, no
new dependency) and the HTTP path is treated as UNTRUSTED network: *L1 passive ≠ trusted network
access*. Every egress is confined so the provider can never be turned into an SSRF pivot:
  * requests may go ONLY to the fixed CT host over https (the endpoint is a constant, never wired);
  * the target domain rides ONLY in the query string — it can never change the host;
  * a redirect is refused (never followed to a response-chosen location);
  * the CT host must resolve to a PUBLIC address (private/loopback/link-local/metadata → refused);
  * the *discovered* names are DATA, never fetched.

Offline-first & hermetic: without `allow_live` it reads a snapshot from `settings["ct"]`
({domain: [hosts]}) so CI is deterministic and opens no socket. Live work runs only behind
`allow_live` and only through the hardened fetch below.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from urllib.parse import quote, urlsplit

from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

# Fixed, code-owned CT endpoint allowlist — NEVER supplied by the wire (ADR-0026 §4).
_CT_HOST = "crt.sh"
_CT_HOSTS = frozenset({_CT_HOST})
_SCHEME = "https"
_TIMEOUT = 8
_MAX_BYTES = 5_000_000
_MAX_ASSETS = 5000

# A target must look like a hostname before we ever build a URL from it (defense in depth).
_DOMAIN_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")


class EgressBlocked(RuntimeError):
    """A network egress was refused by the passive provider's SSRF guard (fail-closed)."""


def _is_blocked_ip(ip: str) -> bool:
    """True for any address we must never egress to: private/loopback/link-local (incl. cloud
    metadata 169.254.169.254 / fd00:ec2::)/multicast/reserved/unspecified, or a non-literal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True  # not a literal address → cannot vouch for it → block
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _ct_url(domain: str) -> str:
    """Build the CT query URL. The domain rides ONLY in the query string (URL-encoded), so it can
    never change the host; the host is the fixed constant."""
    return f"{_SCHEME}://{_CT_HOST}/?q={quote(domain, safe='')}&output=json"


def _assert_endpoint_allowed(url: str) -> None:
    """Refuse any URL that is not https to the fixed CT host — enforced, not by convention."""
    parts = urlsplit(url)
    if parts.scheme != _SCHEME:
        raise EgressBlocked(f"scheme not allowed: {parts.scheme!r}")
    host = (parts.hostname or "").lower()
    if host not in _CT_HOSTS:
        raise EgressBlocked(f"host not in CT allowlist: {host!r}")


def _ensure_not_redirect(status_code: int) -> None:
    """Refuse a redirect — we never follow to a response-chosen location (SSRF guard)."""
    if 300 <= status_code < 400:
        raise EgressBlocked(f"redirect refused: {status_code}")


def _assert_ct_host_public() -> None:
    """Resolve the fixed CT host and refuse if ANY address is non-public (DNS-rebinding/SSRF)."""
    infos = socket.getaddrinfo(_CT_HOST, 443, proto=socket.IPPROTO_TCP)
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise EgressBlocked(f"no address for {_CT_HOST!r}")
    for ip in ips:
        if _is_blocked_ip(ip):
            raise EgressBlocked(f"{_CT_HOST!r} resolves to non-public {ip}")


def _under_domain(host: str, domain: str) -> bool:
    """Scope hygiene: only assets AT/under the authorized domain (a cert may list foreign SANs)."""
    return host == domain or host.endswith("." + domain)


def _parse_ct_names(raw: bytes) -> list[str]:
    """Extract hostnames from a CT JSON response; wildcards flattened, deduped, sorted. Never dumps
    the raw payload — only sanitized names leave this function."""
    import json

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


def _fetch_ct_live(domain: str) -> list[str]:  # pragma: no cover - network
    """Hardened live CT fetch: fixed host, no redirects, public-only resolution, bounded size."""
    import httpx

    url = _ct_url(domain)
    _assert_endpoint_allowed(url)
    _assert_ct_host_public()
    with httpx.Client(follow_redirects=False, timeout=_TIMEOUT) as client:
        resp = client.get(url, headers={"user-agent": "guardian-surface-discovery"})
        _ensure_not_redirect(resp.status_code)
        if resp.status_code != 200:
            return []
        raw = resp.content[:_MAX_BYTES]
    return _parse_ct_names(raw)


class CtSurfaceProvider:
    """A governed, passive (L1) attack-surface discoverer. It declares itself; never self-grants."""

    key = "ct_surface"
    name = "CT Passive Attack-Surface Discovery"
    version = "1"

    @property
    def capabilities(self) -> ToolCapabilities:
        # network + non-active ⇒ derived L1 PASSIVE_NETWORK; no approval, no campaign. It never
        # touches the target, so it declares NO target ports/protocols.
        return ToolCapabilities(
            category="surface_discovery", network=True, active=False, destructive=False,
            requires_authorization=True, requires_human_approval=False,
            supported_targets=("domain", "subdomain"), ports=(), protocols=(),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane gate already ran."""
        if not job.scope.targets:
            raise ValueError("ct_surface: no in-scope target")

    def _hosts_for(self, job: ToolJob, domain: str) -> list[str]:
        settings = job.settings or {}
        if settings.get("allow_live"):
            try:
                return _fetch_ct_live(domain)
            except EgressBlocked:
                return []                                  # fail-closed: refuse egress, emit none
        snapshot = settings.get("ct") or settings.get("snapshot") or {}
        entry = snapshot.get(domain) if isinstance(snapshot, dict) else None
        return [str(h) for h in entry] if isinstance(entry, list) else []

    def execute(self, job: ToolJob):  # noqa: ANN201
        """Discover assets for each in-scope, authorized domain. Only assets AT/under an authorized
        domain are emitted; the target comes ONLY from the effective scope."""
        mode = "live" if (job.settings or {}).get("allow_live") else "offline"
        for raw_target in job.scope.targets:
            domain = str(raw_target).strip().lower().rstrip(".")
            if not _DOMAIN_RE.match(domain):
                continue                                   # never build a URL from a bad target
            hosts: set[str] = set()
            for raw_host in self._hosts_for(job, domain):
                host = str(raw_host).strip().lower().lstrip("*.").rstrip(".")
                if host and _under_domain(host, domain):       # dedup + scope hygiene
                    hosts.add(host)
            # Sorted → deterministic, source-independent order (offline snapshot or live parse).
            for host in sorted(hosts)[:_MAX_ASSETS]:
                yield RawEvidence(
                    tool=self.key, execution_id=job.job_id, target=host, kind="discovered_asset",
                    data={"host": host, "parent_domain": domain, "source": "ct_log",
                          "asset_type": "domain" if host == domain else "subdomain"},
                    provenance={"mode": mode, "source": "ct_log"},
                )

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:  # noqa: ARG002
        """A discovered asset is inventory, not a vulnerability — it feeds the World Model graph,
        not the findings table. So there is deterministically no finding here."""
        return None
