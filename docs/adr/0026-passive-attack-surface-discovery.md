# ADR-026 — Provider #4: Passive Attack-Surface Discovery (CT logs, L1, no secrets)

- **Status:** Accepted (design lock — not yet implemented)
- **Date:** 2026-08-09
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

The platform can *assess* known targets (Web/TLS, DNS posture, PCAP) and *actively discover* ports
on a known IP (Nmap L2), but it has no way to **discover the attack surface itself** — the
subdomains/hosts that belong to an authorized domain. The evidence funnel starts too late: something
must produce the assets that Nmap and Web/TLS then consume.

Provider #4 fills that gap and, deliberately, fills the **one empty low governance level (L1
PASSIVE_NETWORK)** — proving the capability-level model across L0 → L1 → L2. It is the safest possible
next step: it opens the network but **never touches the customer's target** (`active=False`).

The one genuinely new concern is **data egress to a third party**: enumerating a domain means asking
an external service about it. v1 is scoped hard to remove every avoidable form of that risk.

## Decision (CTO-locked, v1 — CT logs only)

1. **Capability = L1 PASSIVE_NETWORK.** Primitives: `category="surface_discovery"`, `network=True`,
   `active=False`, `destructive=False`, `requires_authorization=True`,
   `requires_human_approval=False`. The level is *derived* (ADR-021), never declared. **No campaign,
   no approval** (L1 < L3).
2. **Source = Certificate Transparency logs only.** Passive-DNS providers are **out of scope for v1**
   (they would need an API key / account). **No new API keys, no new secrets, no new infrastructure,
   no new binary.** In-process via `httpx` (already a dependency).
3. **Backend = in-process sandbox, NOT uid_nft.** It is not an external binary and never connects to
   the target, so kernel egress-pinning (ADR-024, built around *target* scope) does not apply. **But
   L1 passive ≠ trusted network access** — see the egress rules below; in-process is not a licence to
   reach the whole internet.
4. **Fixed, code/config-owned CT endpoints — never from the wire.** The CT endpoint(s) are a
   hard-coded/config allowlist. The job wire may carry the *target domain* (from `EffectiveScope`)
   and nothing else network-relevant. A wire can never name the endpoint we call (Phase C P0-2
   lesson: no security-relevant destination is wire-controlled).
5. **The target comes ONLY from `EffectiveScope`.** Any domain not in the authorized scope → **DENY**.
   The scope narrows *which domains* may be enumerated; `ports`/`protocols` are empty (no target port
   is touched); `network_allowed=True`, `read_only=True`.
6. **Anti-SSRF egress discipline (the core safety property).** The HTTP client is constrained so a
   passive provider can never be turned into an SSRF pivot:
   - Requests may go **only** to the fixed CT endpoint host(s) — enforced, not by convention.
   - **Redirects are not followed to source-controlled locations.** No auto-follow to a Location the
     response chooses; a redirect off the allowlisted host is refused.
   - **DNS/URL resolution is restricted:** the connection target must resolve to the CT service, and
     resolution to private/loopback/link-local/metadata ranges is refused. The *discovered* asset
     names are DATA, never fetched.
   - Bounded timeouts, response-size caps, and no arbitrary-URL input from the wire.
7. **No extra privileges.** No root, no `NET_ADMIN`, no raw sockets, no new capabilities.
8. **Evidence = discovered assets only.** `RawEvidence(kind="discovered_asset")`: the subdomain/host,
   `source="ct_log"`, the issuing/seen context, and a resolved IP only if the CT record carries one.
   **No raw CT API responses are dumped into evidence; no secrets ever.** Findings are informational
   surface-expansion (asset inventory), not "misconfig". Assets feed the World Model / netblock graph
   (ADR-015), which then feeds Nmap and Web/TLS.

### Evidence funnel this unlocks

```
CT logs → Discovered assets → World Model / netblock graph → Nmap L2 → ip:port → Web/TLS L2 → assessment
```

## Security requirements (to be proven by tests at execution time — no DB, no live network)

- Scope narrowing: a domain outside the authorization is never enumerated (DENY).
- Egress confinement: the client refuses any host other than the fixed CT endpoint(s).
- Wire cannot inject a target or an endpoint (endpoint is code/config; target is scope-only).
- Anti-SSRF: off-allowlist redirect refused; resolution to private/loopback/link-local/metadata
  refused; no auto-follow to a response-chosen Location.
- Evidence carries no secret and no raw third-party payload; `normalize` is deterministic.
- Level derivation yields exactly L1; policy gate requires no approval/campaign.

## Alternatives considered

- **Include passive-DNS (API-key) sources in v1.** Deferred: needs a secret + external account →
  its own secrets-handling and approval discussion. CT-logs-only gives real coverage with zero
  secrets.
- **Run under uid_nft.** Unnecessary: uid_nft isolates a *target* egress allowlist for external
  binaries; this is in-process and never touches the target. The in-process egress allowlist +
  anti-SSRF discipline is the right control here.
- **Make it active (resolve/probe discovered hosts).** That would raise it to L2 and change the risk
  class; kept out — discovery stays passive, probing stays with Nmap/Web/TLS.

## Consequences

- The platform gains attack-surface discovery and fills L1, widening the funnel instead of deepening
  one branch. No new dependency, no new secret, no migration; DB head stays `0010_phase_b_governance`.
- 6C.4/6D/6E/6F, Providers #1/#2/#3, Nmap, Phase A/B, Evidence chain, RLS, uid_nft — all unchanged.

### Residual / deferred

- **Third-party data egress is inherent to CT lookups** (the target domain is sent to a public CT
  API). Bounded to CT endpoints; documented as accepted for v1.
- **Passive-DNS / API-key sources, active resolution of discovered hosts** — deferred to a later
  provider or a v2 of this one, each with its own lock.
- **Candidate B (service/version ID, L2) and Candidate C (templated web checks, L3)** remain
  unstarted. C is explicitly sequenced later as the first real end-to-end test of
  Campaign → Approval → Grant → Authorization → forced backend → kernel isolation → provider; it is
  not mixed into this phase.
