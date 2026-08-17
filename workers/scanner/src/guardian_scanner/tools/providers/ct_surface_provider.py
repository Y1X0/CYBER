"""CT-log passive attack-surface discovery provider (Framework — Provider #4, L1).

Locked by ADR-0026. It discovers the attack surface of an *authorized* domain from Certificate
Transparency logs — the subdomains/hosts a certificate was ever issued for — WITHOUT touching the
customer's target (`active=False`). It returns `discovered_asset` evidence; the assets feed the
World Model / netblock graph, which then feeds Nmap and Web/TLS. It is NOT a finding source — an
asset is inventory, not a vulnerability.

Governance: derived level is **L1 PASSIVE_NETWORK** (network=True, active=False) — no campaign, no
approval. In-process (no external binary → in-proc sandbox, never uid_nft).

The hardened CT fetch itself now lives in `guardian_scanner.sources.ct`, shared with the discovery
pipeline. The SSRF confinement it carries — fixed host, query-string-only target, no redirects,
public-address enforcement, bounded response — is reviewed in one place rather than two. The names
below are re-exported because they are this module's tested surface.
"""

from __future__ import annotations

from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

from guardian_scanner.sources.ct import (
    DOMAIN_RE as _DOMAIN_RE,
)
from guardian_scanner.sources.ct import (
    MAX_ASSETS as _MAX_ASSETS,
)
from guardian_scanner.sources.ct import (
    EgressBlocked,
    assert_ct_host_public,
    assert_endpoint_allowed,
    ct_url,
    ensure_not_redirect,
    fetch_ct_live,
    is_blocked_ip,
    parse_ct_names,
    under_domain,
)

# Backwards-compatible private aliases: the unit tests monkeypatch these module attributes.
_is_blocked_ip = is_blocked_ip
_ct_url = ct_url
_assert_endpoint_allowed = assert_endpoint_allowed
_ensure_not_redirect = ensure_not_redirect
_assert_ct_host_public = assert_ct_host_public
_under_domain = under_domain
_parse_ct_names = parse_ct_names
_fetch_ct_live = fetch_ct_live

__all__ = ["CtSurfaceProvider", "EgressBlocked"]


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
