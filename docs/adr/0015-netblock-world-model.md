# ADR-015 — Phase 6F: netblock world-model completion (authorized enrichment + passive ASN/RIR)

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

A read of the code established that `NodeType.NETBLOCK/CLOUD_RESOURCE` and `EdgeRelation.CONTAINS/
ROUTES_TO/TRUSTS` and `DiscoverySource.ASN_RIR/CLOUD_ENUM` exist only as definitions — no producer
emits them. Unlike 6E (pure enrichment over data already present), completing the network world model
needs a data *source*: netblocks come either from operator-declared CIDRs or from RIR registry data.
`cloud_resource` needs an auth-gated cloud API; `routes_to` needs active routing probes; `trusts` has
no source. Only the netblock slice is buildable now without inventing relationships or adding active
capability.

## Decision

**Complete the netblock portion of the world model with two convergent, honest sources; defer the
rest.** (Decisions locked by the CTO: 6F-a + 6F-b, limited scope.)

- **6F-a — authorized-netblock enrichment (trusted plane, no network).** From
  `Authorization.authorized_targets` entries of type `netblock` (tenant/customer scoped; **not**
  `DiscoveryScope.seeds`), create `netblock` nodes and `netblock --contains--> ip` edges to existing
  `ip_address` nodes by **exact CIDR containment** only — no fuzzy/reverse inference. Runs in the
  discovery persist phase (the IP nodes exist by then). Idempotent, tenant-isolated.
- **6F-b — passive ASN/RIR provider (recon plane, 6C.4 result-return).** A new passive discovery
  provider (`asn`) maps each already-discovered IP to its registering netblock. **Offline-first and
  deterministic** (snapshot in `ctx.settings["asn"]`); a live RDAP lookup is behind an explicit
  `allow_live` flag (best-effort, fail-safe, untested) — mirroring DNS/CT. Passive public data only:
  no active probing, traceroute, ICMP, port scan, new ports/protocols, or credentials. The IP set
  comes from discovered `ip_address` nodes, supplied by the trusted orchestrator in the recon payload
  (bounded + de-duplicated), never from raw user seeds. It flows through the unchanged 6C.4 pipeline
  (recon_collect, no DB → result-return → persist via the ingestor).
- **Convergence + provenance.** Both sources canonicalize a CIDR to the same key, so they dedupe onto
  **one** `netblock` node per tenant and idempotent `contains` edges. Provenance stays
  distinguishable: 6F-a `contains` edges carry `source="inferred"` + `meta.link="cidr_containment"`
  and their node `metadata.source="authorized"`; 6F-b carries `source="asn_rir"` and an `asn` node
  attribute (RIR-derived).
- **`contains` is grouping ONLY.** It is deliberately excluded from `REACHABILITY_RELATIONS` and
  `ATTACK_RELATIONS`, so 6D exposure paths and 6E attack paths are byte-identical — a netblock node
  never becomes a traversal hop. Proven by regression tests.
- **No migration.** `netblock` node type and `contains` relation are existing string values;
  `DiscoverySource.ASN_RIR` already exists. DB head stays `0009_phase6c_recon`.

## Alternatives considered

- **6F-a or 6F-b alone.** 6F-a alone ignores the RIR data that would discover netblocks for IPs
  outside declared ranges; 6F-b alone leaves declared authorization CIDRs unused. C (both) gives the
  better world model at minimal scope.
- **`cloud_resource` in 6F.** Rejected: needs a cloud-provider integration + credential store + auth —
  a separate, larger phase, not a netblock slice.
- **`routes_to` / `trusts`.** Rejected: `routes_to` needs an active routing probe (violates the recon
  posture); `trusts` has no data source. Deferred until real evidence exists.
- **Live ASN as the primary path.** Rejected: offline-first keeps tests hermetic and avoids shipping
  a network dependency; live RDAP stays a flagged, best-effort seam like DNS/CT.

## Consequences

- The world model now expresses network grouping (`netblock --contains--> ip`) from two convergent,
  evidence-backed sources, without any active capability or migration.
- 6C.4 recon isolation is preserved: the ASN provider is passive and DB-less, flowing through the
  existing result-return; the recon plane still holds no DB credentials.
- 6D and 6E are untouched: `contains` is not a path hop, so exposure and attack paths are unchanged.
- ASN coverage is incremental: a run maps the IPs discovered *before* it; this run's new IPs are
  mapped on the next run (standard EASM cadence).

### Deferred / technical debt (documented, not in 6F)

- **`cloud_resource`** (auth-gated cloud enumeration) — a separate phase with a credential store.
- **`routes_to` / `trusts`** — until there is non-inferred evidence (routing data / trust records).
- **Live ASN/RIR** hardening (a real RDAP/RIR client with bootstrap, caching, rate limits).
- Everything already deferred by ADR-011/012/013/014.
- The **Security Tool Execution Framework** (Nmap/PCAP/Web as providers behind
  Authorization→Scope→Sandbox→Evidence→Finding→Graph) is a **separate Discovery**, explicitly NOT
  started here.
