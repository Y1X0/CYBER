# ADR-014 — Phase 6E: graph enrichment (finding/asset nodes, exposes/serves) + attack paths

- **Status:** Accepted
- **Date:** 2026-08-08
- **Deciders:** CTO, Chief Security Architect, Platform Engineering

## Context

The graph was topology-only (`domain/subdomain/ip_address/service` over `resolves_to/hosts/
subdomain_of`); vulnerabilities appeared in 6D solely as a read-only enrichment. A read of the code
established two facts that shaped this phase:

1. The only evidence-backed link between vulnerabilities and the rest of the model is
   `findings.asset_id → assets.id`. There is **no** data linking a discovered *service* to a *finding*
   directly, and **no** producer ever set `graph_nodes.asset_id`, so the topology and the
   asset/finding world were disconnected — 6D's finding read-join was effectively dormant on real data.
2. `NodeType.FINDING/ASSET` and `EdgeRelation.EXPOSES/ENABLES` already exist, and graph nodes/edges are
   polymorphic string types, so representing them needs **no schema migration**.

## Decision

**Project managed assets and findings into the graph, honestly, and add a distinct read-only
attack-path analysis — reusing existing scoring, inventing no relationships.**

- **Finding nodes:** `node_type="finding"`, `canonical_key=str(finding.id)`, `asset_id=finding.asset_id`,
  `state=Finding.status`, `exposure_score=0` (exposure ≠ risk), metadata copied from existing fields.
  No AI, no re-scoring.
- **`asset --exposes--> finding`:** the one vulnerability edge, backed by `findings.asset_id`. An asset
  node is created only if it would carry an edge (has findings or a topology match) — no orphans.
- **`enables` is NOT produced.** There is no evidence for what a finding enables beyond its own asset;
  `EdgeRelation.ENABLES` stays a future seam.
- **Topology ↔ asset via `serves` (Conn-B), exact host identity only.** A new
  `EdgeRelation.SERVES` links `subdomain/service --serves--> asset` **only** when a web/api asset's URL
  host, canonicalized, exactly equals a discovered topology node's canonical host. No fuzzy matching,
  no brand/name matching, no IP-literal matching, no guessing; a non-host-derivable identifier or no
  match yields no edge. Conn-A (populating `graph_nodes.asset_id` on topology nodes) was rejected
  because it would silently activate 6D's enrichment and change existing exposure semantics as a side
  effect; `serves` is explicit and side-effect-free.
- **Attack paths (read-only):** a new `attack_paths` analysis over `ATTACK_RELATIONS =
  {resolves_to, hosts, serves, exposes}` — an internet-facing entry → a `finding`. It is **distinct
  from** `exposure_paths` (which is unchanged and still traverses only `{resolves_to, hosts}`), never
  uses `enables`, and inherits the same deterministic, bounded machinery (max_depth/paths/nodes,
  truncation, cycle protection, stable ordering). Exposed at `GET /api/v1/graph/attack-paths`
  (read-only, staff-only, tenant-scoped).
- **Trigger:** the enricher runs automatically after a scan completes (completed/partial), on the
  trusted/default plane only, fire-and-forget and idempotent (dedupe on node/edge identity). It never
  runs on the recon worker and opens no socket.
- **No migration** (head stays `0009_phase6c_recon`); `SERVES` is a new enum value on an existing
  string column.

## Alternatives considered

- **Conn-A (populate `graph_nodes.asset_id`).** Rejected: it reuses an existing column but activates
  6D's read-join enrichment as a side effect, changing exposure-path sensitivity implicitly.
- **`service --exposes--> finding` (the enum's literal note).** Rejected: no data links a discovered
  service to a finding; findings attach to assets. Modeling it would invent a relationship.
- **Producing `enables`.** Rejected: no evidence for post-asset movement; would be fabricated.
- **Fuzzy / IP host matching for `serves`.** Rejected: risks mis-attributing a vulnerability to the
  wrong service; only exact canonical-host identity is used.
- **Folding attack paths into `exposure_paths`.** Rejected: would change 6D semantics; kept separate.

## Consequences

- For the first time the graph expresses a real, data-backed path: **internet → subdomain → ip →
  service → serves → asset → exposes → finding**, queryable and deterministic, with the finding as the
  endpoint — no invented "internet → vulnerability" story.
- 6D is untouched: `exposure_paths/blast_radius/chokepoints/drift` traverse the same relation set and
  return the same results; finding/asset nodes are not reachable over reachability edges and never
  appear in exposure paths.
- `serves` covers only web/api assets with a host identifier and a matching topology node; other
  assets (repo/cloud/ARN, or no discovered host) simply have no `serves` edge — honest and expected.
- Enrichment runs on the trusted plane, preserving 6C.4 recon isolation (no network, no recon, no DB
  on the recon worker).

### Deferred / technical debt (documented, not in 6E)

- **`enables` edges** once there is evidence for post-asset movement (lateral/trust).
- **Finding-node lifecycle** (pruning/stale-marking resolved findings) — today re-enrichment refreshes
  `state` in place but does not remove nodes for findings that disappeared.
- **IP-identity `serves`** and non-URL asset linkage, if a deterministic identity is established.
- Everything already deferred by ADR-011/012/013 (netblock/cloud nodes, node-event enrichment,
  historical snapshots, graph-loader scalability, non-blocking recon orchestration, seccomp).
